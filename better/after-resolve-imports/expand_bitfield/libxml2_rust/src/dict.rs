use ::libc;
extern "C" {
    
    
    fn rand_r(__seed: *mut u32) -> i32;
    fn time(__timer: *mut time_t) -> time_t;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: i32,
        _: u64,
    ) -> *mut libc::c_void;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> i32;
    fn strlen(_: *const i8) -> u64;
    
    
    
    
    
    
}
pub use crate::src::threads::xmlFreeMutex;
pub use crate::src::threads::xmlMutexLock;
pub use crate::src::threads::xmlMutexUnlock;
pub use crate::src::threads::xmlNewMutex;
pub use crate::src::xmlstring::xmlStrQEqual;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub use crate::src::threads::_xmlMutex;
pub type xmlChar = crate::src::HTMLparser::xmlChar;
pub type size_t = crate::src::HTMLparser::size_t;
pub type __uint32_t = u32;
pub type __time_t = crate::src::catalog::__time_t;
pub type xmlMutexPtr = *mut xmlMutex;
pub type xmlMutex = _xmlMutex;
pub type time_t = __time_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDict {
    pub ref_counter: i32,
    pub dict: *mut _xmlDictEntry,
    pub size: size_t,
    pub nbElems: u32,
    pub strings: xmlDictStringsPtr,
    pub subdict: *mut _xmlDict,
    pub seed: i32,
    pub limit: size_t,
}
pub type xmlDictStringsPtr = *mut xmlDictStrings;
pub type xmlDictStrings = _xmlDictStrings;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDictStrings {
    pub next: xmlDictStringsPtr,
    pub free: *mut xmlChar,
    pub end: *mut xmlChar,
    pub size: size_t,
    pub nbStrings: size_t,
    pub array: [xmlChar; 1],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDictEntry {
    pub next: *mut _xmlDictEntry,
    pub name: *const xmlChar,
    pub len: u32,
    pub valid: i32,
    pub okey: u64,
}
pub type xmlDictPtr = crate::src::HTMLparser::xmlDictPtr;
pub type xmlDict = crate::src::HTMLparser::xmlDict;
pub type xmlFreeFunc = crate::src::HTMLparser::xmlFreeFunc;
pub type xmlDictEntry = _xmlDictEntry;
pub type xmlMallocFunc = crate::src::HTMLparser::xmlMallocFunc;
pub type xmlDictEntryPtr = *mut xmlDictEntry;
static mut xmlDictMutex: xmlMutexPtr = 0 as *const xmlMutex as xmlMutexPtr;
static mut xmlDictInitialized: i32 = 0 as i32;
static mut rand_seed: u32 = 0 as i32 as u32;
#[no_mangle]
pub extern "C" fn xmlInitializeDict() -> i32 {
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlInitializeDict() -> i32 {
    if xmlDictInitialized != 0 {
        return 1 as i32;
    }
    xmlDictMutex = xmlNewMutex();
    if xmlDictMutex.is_null() {
        return 0 as i32;
    }
    xmlMutexLock(xmlDictMutex);
    rand_seed = time(0 as *mut time_t) as u32;
    rand_r(&mut rand_seed);
    xmlDictInitialized = 1 as i32;
    xmlMutexUnlock(xmlDictMutex);
    return 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn __xmlRandom() -> i32 {
    let mut ret: i32 = 0;
    if xmlDictInitialized == 0 as i32 {
        __xmlInitializeDict();
    }
    xmlMutexLock(xmlDictMutex);
    ret = rand_r(&mut rand_seed);
    xmlMutexUnlock(xmlDictMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDictCleanup() {
    if xmlDictInitialized == 0 {
        return;
    }
    xmlFreeMutex(xmlDictMutex);
    xmlDictInitialized = 0 as i32;
}
unsafe extern "C" fn xmlDictAddString(
    mut dict: xmlDictPtr,
    mut name: *const xmlChar,
    mut namelen: u32,
) -> *const xmlChar {
    let mut current_block: u64;
    let mut pool: xmlDictStringsPtr = 0 as *mut xmlDictStrings;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    let mut size: size_t = 0 as i32 as size_t;
    let mut limit: size_t = 0 as i32 as size_t;
    pool = (*dict).strings;
    loop {
        if pool.is_null() {
            current_block = 13183875560443969876;
            break;
        }
        if ((*pool).end).offset_from((*pool).free) as i64 as size_t
            > namelen as u64
        {
            current_block = 16549717771175460023;
            break;
        }
        if (*pool).size > size {
            size = (*pool).size;
        }
        limit = (limit as u64).wrapping_add((*pool).size) as size_t as size_t;
        pool = (*pool).next;
    }
    match current_block {
        13183875560443969876 => {
            if pool.is_null() {
                if (*dict).limit > 0 as i32 as u64
                    && limit > (*dict).limit
                {
                    return 0 as *const xmlChar;
                }
                if size == 0 as i32 as u64 {
                    size = 1000 as i32 as size_t;
                } else {
                    size = (size as u64)
                        .wrapping_mul(4 as i32 as u64) as size_t
                        as size_t;
                }
                if size
                    < (4 as i32 as u32).wrapping_mul(namelen)
                        as u64
                {
                    size = (4 as i32 as u32).wrapping_mul(namelen)
                        as size_t;
                }
                pool = xmlMalloc
                    .expect(
                        "non-null function pointer",
                    )(
                    (::std::mem::size_of::<xmlDictStrings>() as u64)
                        .wrapping_add(size),
                ) as xmlDictStringsPtr;
                if pool.is_null() {
                    return 0 as *const xmlChar;
                }
                (*pool).size = size;
                (*pool).nbStrings = 0 as i32 as size_t;
                let fresh0 = &mut ((*pool).free);
                *fresh0 = &mut *((*pool).array)
                    .as_mut_ptr()
                    .offset(0 as i32 as isize) as *mut xmlChar;
                let fresh1 = &mut ((*pool).end);
                *fresh1 = &mut *((*pool).array).as_mut_ptr().offset(size as isize)
                    as *mut xmlChar;
                let fresh2 = &mut ((*pool).next);
                *fresh2 = (*dict).strings;
                let fresh3 = &mut ((*dict).strings);
                *fresh3 = pool;
            }
        }
        _ => {}
    }
    ret = (*pool).free;
    memcpy(
        (*pool).free as *mut libc::c_void,
        name as *const libc::c_void,
        namelen as u64,
    );
    let fresh4 = &mut ((*pool).free);
    *fresh4 = (*fresh4).offset(namelen as isize);
    let fresh5 = &mut ((*pool).free);
    let fresh6 = *fresh5;
    *fresh5 = (*fresh5).offset(1);
    *fresh6 = 0 as i32 as xmlChar;
    let fresh7 = &mut ((*pool).nbStrings);
    *fresh7 = (*fresh7).wrapping_add(1);
    return ret;
}
unsafe extern "C" fn xmlDictAddQString(
    mut dict: xmlDictPtr,
    mut prefix: *const xmlChar,
    mut plen: u32,
    mut name: *const xmlChar,
    mut namelen: u32,
) -> *const xmlChar {
    let mut current_block: u64;
    let mut pool: xmlDictStringsPtr = 0 as *mut xmlDictStrings;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    let mut size: size_t = 0 as i32 as size_t;
    let mut limit: size_t = 0 as i32 as size_t;
    if prefix.is_null() {
        return xmlDictAddString(dict, name, namelen);
    }
    pool = (*dict).strings;
    loop {
        if pool.is_null() {
            current_block = 13536709405535804910;
            break;
        }
        if ((*pool).end).offset_from((*pool).free) as i64 as size_t
            > namelen.wrapping_add(plen).wrapping_add(1 as i32 as u32)
                as u64
        {
            current_block = 7192883661880266812;
            break;
        }
        if (*pool).size > size {
            size = (*pool).size;
        }
        limit = (limit as u64).wrapping_add((*pool).size) as size_t as size_t;
        pool = (*pool).next;
    }
    match current_block {
        13536709405535804910 => {
            if pool.is_null() {
                if (*dict).limit > 0 as i32 as u64
                    && limit > (*dict).limit
                {
                    return 0 as *const xmlChar;
                }
                if size == 0 as i32 as u64 {
                    size = 1000 as i32 as size_t;
                } else {
                    size = (size as u64)
                        .wrapping_mul(4 as i32 as u64) as size_t
                        as size_t;
                }
                if size
                    < (4 as i32 as u32)
                        .wrapping_mul(
                            namelen
                                .wrapping_add(plen)
                                .wrapping_add(1 as i32 as u32),
                        ) as u64
                {
                    size = (4 as i32 as u32)
                        .wrapping_mul(
                            namelen
                                .wrapping_add(plen)
                                .wrapping_add(1 as i32 as u32),
                        ) as size_t;
                }
                pool = xmlMalloc
                    .expect(
                        "non-null function pointer",
                    )(
                    (::std::mem::size_of::<xmlDictStrings>() as u64)
                        .wrapping_add(size),
                ) as xmlDictStringsPtr;
                if pool.is_null() {
                    return 0 as *const xmlChar;
                }
                (*pool).size = size;
                (*pool).nbStrings = 0 as i32 as size_t;
                let fresh8 = &mut ((*pool).free);
                *fresh8 = &mut *((*pool).array)
                    .as_mut_ptr()
                    .offset(0 as i32 as isize) as *mut xmlChar;
                let fresh9 = &mut ((*pool).end);
                *fresh9 = &mut *((*pool).array).as_mut_ptr().offset(size as isize)
                    as *mut xmlChar;
                let fresh10 = &mut ((*pool).next);
                *fresh10 = (*dict).strings;
                let fresh11 = &mut ((*dict).strings);
                *fresh11 = pool;
            }
        }
        _ => {}
    }
    ret = (*pool).free;
    memcpy(
        (*pool).free as *mut libc::c_void,
        prefix as *const libc::c_void,
        plen as u64,
    );
    let fresh12 = &mut ((*pool).free);
    *fresh12 = (*fresh12).offset(plen as isize);
    let fresh13 = &mut ((*pool).free);
    let fresh14 = *fresh13;
    *fresh13 = (*fresh13).offset(1);
    *fresh14 = ':' as i32 as xmlChar;
    memcpy(
        (*pool).free as *mut libc::c_void,
        name as *const libc::c_void,
        namelen as u64,
    );
    let fresh15 = &mut ((*pool).free);
    *fresh15 = (*fresh15).offset(namelen as isize);
    let fresh16 = &mut ((*pool).free);
    let fresh17 = *fresh16;
    *fresh16 = (*fresh16).offset(1);
    *fresh17 = 0 as i32 as xmlChar;
    let fresh18 = &mut ((*pool).nbStrings);
    *fresh18 = (*fresh18).wrapping_add(1);
    return ret;
}
unsafe extern "C" fn xmlDictComputeBigKey(
    mut data: *const xmlChar,
    mut namelen: i32,
    mut seed: i32,
) -> uint32_t {
    let mut hash: uint32_t = 0;
    let mut i: i32 = 0;
    if namelen <= 0 as i32 || data.is_null() {
        return 0 as i32 as uint32_t;
    }
    hash = seed as uint32_t;
    i = 0 as i32;
    while i < namelen {
        hash = (hash as u32)
            .wrapping_add(*data.offset(i as isize) as u32) as uint32_t
            as uint32_t;
        hash = (hash as u32).wrapping_add(hash << 10 as i32) as uint32_t
            as uint32_t;
        hash ^= hash >> 6 as i32;
        i += 1;
    }
    hash = (hash as u32).wrapping_add(hash << 3 as i32) as uint32_t
        as uint32_t;
    hash ^= hash >> 11 as i32;
    hash = (hash as u32).wrapping_add(hash << 15 as i32) as uint32_t
        as uint32_t;
    return hash;
}
unsafe extern "C" fn xmlDictComputeBigQKey(
    mut prefix: *const xmlChar,
    mut plen: i32,
    mut name: *const xmlChar,
    mut len: i32,
    mut seed: i32,
) -> u64 {
    let mut hash: uint32_t = 0;
    let mut i: i32 = 0;
    hash = seed as uint32_t;
    i = 0 as i32;
    while i < plen {
        hash = (hash as u32)
            .wrapping_add(*prefix.offset(i as isize) as u32) as uint32_t
            as uint32_t;
        hash = (hash as u32).wrapping_add(hash << 10 as i32) as uint32_t
            as uint32_t;
        hash ^= hash >> 6 as i32;
        i += 1;
    }
    hash = (hash as u32).wrapping_add(':' as i32 as u32) as uint32_t
        as uint32_t;
    hash = (hash as u32).wrapping_add(hash << 10 as i32) as uint32_t
        as uint32_t;
    hash ^= hash >> 6 as i32;
    i = 0 as i32;
    while i < len {
        hash = (hash as u32)
            .wrapping_add(*name.offset(i as isize) as u32) as uint32_t
            as uint32_t;
        hash = (hash as u32).wrapping_add(hash << 10 as i32) as uint32_t
            as uint32_t;
        hash ^= hash >> 6 as i32;
        i += 1;
    }
    hash = (hash as u32).wrapping_add(hash << 3 as i32) as uint32_t
        as uint32_t;
    hash ^= hash >> 11 as i32;
    hash = (hash as u32).wrapping_add(hash << 15 as i32) as uint32_t
        as uint32_t;
    return hash as u64;
}
unsafe extern "C" fn xmlDictComputeFastKey(
    mut name: *const xmlChar,
    mut namelen: i32,
    mut seed: i32,
) -> u64 {
    let mut value: u64 = seed as u64;
    if name.is_null() {
        return 0 as i32 as u64;
    }
    value = value.wrapping_add(*name as u64);
    value <<= 5 as i32;
    if namelen > 10 as i32 {
        value = value
            .wrapping_add(
                *name.offset((namelen - 1 as i32) as isize) as u64,
            );
        namelen = 10 as i32;
    }
    let mut current_block_16: u64;
    match namelen {
        10 => {
            value = value
                .wrapping_add(*name.offset(9 as i32 as isize) as u64);
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
            value = value
                .wrapping_add(*name.offset(8 as i32 as isize) as u64);
            current_block_16 = 7244956010693875373;
        }
        _ => {}
    }
    match current_block_16 {
        7244956010693875373 => {
            value = value
                .wrapping_add(*name.offset(7 as i32 as isize) as u64);
            current_block_16 = 17573653595028029515;
        }
        _ => {}
    }
    match current_block_16 {
        17573653595028029515 => {
            value = value
                .wrapping_add(*name.offset(6 as i32 as isize) as u64);
            current_block_16 = 11089524544337135140;
        }
        _ => {}
    }
    match current_block_16 {
        11089524544337135140 => {
            value = value
                .wrapping_add(*name.offset(5 as i32 as isize) as u64);
            current_block_16 = 18235174393473213413;
        }
        _ => {}
    }
    match current_block_16 {
        18235174393473213413 => {
            value = value
                .wrapping_add(*name.offset(4 as i32 as isize) as u64);
            current_block_16 = 16104263797903159467;
        }
        _ => {}
    }
    match current_block_16 {
        16104263797903159467 => {
            value = value
                .wrapping_add(*name.offset(3 as i32 as isize) as u64);
            current_block_16 = 11324303184752563449;
        }
        _ => {}
    }
    match current_block_16 {
        11324303184752563449 => {
            value = value
                .wrapping_add(*name.offset(2 as i32 as isize) as u64);
            current_block_16 = 1900231684298568950;
        }
        _ => {}
    }
    match current_block_16 {
        1900231684298568950 => {
            value = value
                .wrapping_add(*name.offset(1 as i32 as isize) as u64);
        }
        _ => {}
    }
    return value;
}
unsafe extern "C" fn xmlDictComputeFastQKey(
    mut prefix: *const xmlChar,
    mut plen: i32,
    mut name: *const xmlChar,
    mut len: i32,
    mut seed: i32,
) -> u64 {
    let mut value: u64 = seed as u64;
    if plen == 0 as i32 {
        value = value
            .wrapping_add(
                (30 as i32 as u64)
                    .wrapping_mul(':' as i32 as u64),
            );
    } else {
        value = value
            .wrapping_add((30 as i32 * *prefix as i32) as u64);
    }
    if len > 10 as i32 {
        let mut offset: i32 = len - (plen + 1 as i32 + 1 as i32);
        if offset < 0 as i32 {
            offset = len - (10 as i32 + 1 as i32);
        }
        value = value.wrapping_add(*name.offset(offset as isize) as u64);
        len = 10 as i32;
        if plen > 10 as i32 {
            plen = 10 as i32;
        }
    }
    let mut current_block_20: u64;
    match plen {
        10 => {
            value = value
                .wrapping_add(
                    *prefix.offset(9 as i32 as isize) as u64,
                );
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
            value = value
                .wrapping_add(
                    *prefix.offset(8 as i32 as isize) as u64,
                );
            current_block_20 = 7038770548287051377;
        }
        _ => {}
    }
    match current_block_20 {
        7038770548287051377 => {
            value = value
                .wrapping_add(
                    *prefix.offset(7 as i32 as isize) as u64,
                );
            current_block_20 = 10770133212036609160;
        }
        _ => {}
    }
    match current_block_20 {
        10770133212036609160 => {
            value = value
                .wrapping_add(
                    *prefix.offset(6 as i32 as isize) as u64,
                );
            current_block_20 = 12600003426392199789;
        }
        _ => {}
    }
    match current_block_20 {
        12600003426392199789 => {
            value = value
                .wrapping_add(
                    *prefix.offset(5 as i32 as isize) as u64,
                );
            current_block_20 = 16012330138488115495;
        }
        _ => {}
    }
    match current_block_20 {
        16012330138488115495 => {
            value = value
                .wrapping_add(
                    *prefix.offset(4 as i32 as isize) as u64,
                );
            current_block_20 = 1411058975029915551;
        }
        _ => {}
    }
    match current_block_20 {
        1411058975029915551 => {
            value = value
                .wrapping_add(
                    *prefix.offset(3 as i32 as isize) as u64,
                );
            current_block_20 = 8768901130990501272;
        }
        _ => {}
    }
    match current_block_20 {
        8768901130990501272 => {
            value = value
                .wrapping_add(
                    *prefix.offset(2 as i32 as isize) as u64,
                );
            current_block_20 = 8280968883510158391;
        }
        _ => {}
    }
    match current_block_20 {
        8280968883510158391 => {
            value = value
                .wrapping_add(
                    *prefix.offset(1 as i32 as isize) as u64,
                );
            current_block_20 = 14259685586177370419;
        }
        _ => {}
    }
    match current_block_20 {
        14259685586177370419 => {
            value = value
                .wrapping_add(
                    *prefix.offset(0 as i32 as isize) as u64,
                );
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
            value = value
                .wrapping_add(*name.offset(9 as i32 as isize) as u64);
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
            value = value
                .wrapping_add(*name.offset(8 as i32 as isize) as u64);
            current_block_36 = 17869296276999015210;
        }
        _ => {}
    }
    match current_block_36 {
        17869296276999015210 => {
            value = value
                .wrapping_add(*name.offset(7 as i32 as isize) as u64);
            current_block_36 = 5309407416788998794;
        }
        _ => {}
    }
    match current_block_36 {
        5309407416788998794 => {
            value = value
                .wrapping_add(*name.offset(6 as i32 as isize) as u64);
            current_block_36 = 7515937090034470222;
        }
        _ => {}
    }
    match current_block_36 {
        7515937090034470222 => {
            value = value
                .wrapping_add(*name.offset(5 as i32 as isize) as u64);
            current_block_36 = 4953035719795365622;
        }
        _ => {}
    }
    match current_block_36 {
        4953035719795365622 => {
            value = value
                .wrapping_add(*name.offset(4 as i32 as isize) as u64);
            current_block_36 = 16676005767965041358;
        }
        _ => {}
    }
    match current_block_36 {
        16676005767965041358 => {
            value = value
                .wrapping_add(*name.offset(3 as i32 as isize) as u64);
            current_block_36 = 8784458375054248129;
        }
        _ => {}
    }
    match current_block_36 {
        8784458375054248129 => {
            value = value
                .wrapping_add(*name.offset(2 as i32 as isize) as u64);
            current_block_36 = 563573333189432338;
        }
        _ => {}
    }
    match current_block_36 {
        563573333189432338 => {
            value = value
                .wrapping_add(*name.offset(1 as i32 as isize) as u64);
            current_block_36 = 8480119504522294706;
        }
        _ => {}
    }
    match current_block_36 {
        8480119504522294706 => {
            value = value
                .wrapping_add(*name.offset(0 as i32 as isize) as u64);
        }
        _ => {}
    }
    return value;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDictCreate() -> xmlDictPtr {
    let mut dict: xmlDictPtr = 0 as *mut xmlDict;
    if xmlDictInitialized == 0 {
        if __xmlInitializeDict() == 0 {
            return 0 as xmlDictPtr;
        }
    }
    dict = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlDict>() as u64) as xmlDictPtr;
    if !dict.is_null() {
        (*dict).ref_counter = 1 as i32;
        (*dict).limit = 0 as i32 as size_t;
        (*dict).size = 128 as i32 as size_t;
        (*dict).nbElems = 0 as i32 as u32;
        let fresh19 = &mut ((*dict).dict);
        *fresh19 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            (128 as i32 as u64)
                .wrapping_mul(::std::mem::size_of::<xmlDictEntry>() as u64),
        ) as *mut _xmlDictEntry;
        let fresh20 = &mut ((*dict).strings);
        *fresh20 = 0 as xmlDictStringsPtr;
        let fresh21 = &mut ((*dict).subdict);
        *fresh21 = 0 as *mut _xmlDict;
        if !((*dict).dict).is_null() {
            memset(
                (*dict).dict as *mut libc::c_void,
                0 as i32,
                (128 as i32 as u64)
                    .wrapping_mul(::std::mem::size_of::<xmlDictEntry>() as u64),
            );
            (*dict).seed = __xmlRandom();
            return dict;
        }
        xmlFree.expect("non-null function pointer")(dict as *mut libc::c_void);
    }
    return 0 as xmlDictPtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDictCreateSub(mut sub: xmlDictPtr) -> xmlDictPtr {
    let mut dict: xmlDictPtr = xmlDictCreate();
    if !dict.is_null() && !sub.is_null() {
        (*dict).seed = (*sub).seed;
        let fresh22 = &mut ((*dict).subdict);
        *fresh22 = sub;
        xmlDictReference((*dict).subdict);
    }
    return dict;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDictReference(mut dict: xmlDictPtr) -> i32 {
    if xmlDictInitialized == 0 {
        if __xmlInitializeDict() == 0 {
            return -(1 as i32);
        }
    }
    if dict.is_null() {
        return -(1 as i32);
    }
    xmlMutexLock(xmlDictMutex);
    let fresh23 = &mut ((*dict).ref_counter);
    *fresh23 += 1;
    xmlMutexUnlock(xmlDictMutex);
    return 0 as i32;
}
unsafe extern "C" fn xmlDictGrow(mut dict: xmlDictPtr, mut size: size_t) -> i32 {
    let mut key: u64 = 0;
    let mut okey: u64 = 0;
    let mut oldsize: size_t = 0;
    let mut i: size_t = 0;
    let mut iter: xmlDictEntryPtr = 0 as *mut xmlDictEntry;
    let mut next: xmlDictEntryPtr = 0 as *mut xmlDictEntry;
    let mut olddict: *mut _xmlDictEntry = 0 as *mut _xmlDictEntry;
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
    oldsize = (*dict).size;
    olddict = (*dict).dict;
    if olddict.is_null() {
        return -(1 as i32);
    }
    if oldsize == 128 as i32 as u64 {
        keep_keys = 0 as i32;
    }
    let fresh24 = &mut ((*dict).dict);
    *fresh24 = xmlMalloc
        .expect(
            "non-null function pointer",
        )(size.wrapping_mul(::std::mem::size_of::<xmlDictEntry>() as u64))
        as *mut _xmlDictEntry;
    if ((*dict).dict).is_null() {
        let fresh25 = &mut ((*dict).dict);
        *fresh25 = olddict;
        return -(1 as i32);
    }
    memset(
        (*dict).dict as *mut libc::c_void,
        0 as i32,
        size.wrapping_mul(::std::mem::size_of::<xmlDictEntry>() as u64),
    );
    (*dict).size = size;
    i = 0 as i32 as size_t;
    while i < oldsize {
        if !((*olddict.offset(i as isize)).valid == 0 as i32) {
            if keep_keys != 0 {
                okey = (*olddict.offset(i as isize)).okey;
            } else {
                okey = if (*dict).size == 128 as i32 as u64 {
                    xmlDictComputeFastKey(
                        (*olddict.offset(i as isize)).name,
                        (*olddict.offset(i as isize)).len as i32,
                        (*dict).seed,
                    )
                } else {
                    xmlDictComputeBigKey(
                        (*olddict.offset(i as isize)).name,
                        (*olddict.offset(i as isize)).len as i32,
                        (*dict).seed,
                    ) as u64
                };
            }
            key = okey.wrapping_rem((*dict).size);
            if (*((*dict).dict).offset(key as isize)).valid == 0 as i32 {
                memcpy(
                    &mut *((*dict).dict).offset(key as isize) as *mut _xmlDictEntry
                        as *mut libc::c_void,
                    &mut *olddict.offset(i as isize) as *mut _xmlDictEntry
                        as *const libc::c_void,
                    ::std::mem::size_of::<xmlDictEntry>() as u64,
                );
                let fresh26 = &mut ((*((*dict).dict).offset(key as isize)).next);
                *fresh26 = 0 as *mut _xmlDictEntry;
                (*((*dict).dict).offset(key as isize)).okey = okey;
            } else {
                let mut entry: xmlDictEntryPtr = 0 as *mut xmlDictEntry;
                entry = xmlMalloc
                    .expect(
                        "non-null function pointer",
                    )(::std::mem::size_of::<xmlDictEntry>() as u64)
                    as xmlDictEntryPtr;
                if !entry.is_null() {
                    let fresh27 = &mut ((*entry).name);
                    *fresh27 = (*olddict.offset(i as isize)).name;
                    (*entry).len = (*olddict.offset(i as isize)).len;
                    (*entry).okey = okey;
                    let fresh28 = &mut ((*entry).next);
                    *fresh28 = (*((*dict).dict).offset(key as isize)).next;
                    (*entry).valid = 1 as i32;
                    let fresh29 = &mut ((*((*dict).dict).offset(key as isize)).next);
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
        iter = (*olddict.offset(i as isize)).next;
        while !iter.is_null() {
            next = (*iter).next;
            if keep_keys != 0 {
                okey = (*iter).okey;
            } else {
                okey = if (*dict).size == 128 as i32 as u64 {
                    xmlDictComputeFastKey(
                        (*iter).name,
                        (*iter).len as i32,
                        (*dict).seed,
                    )
                } else {
                    xmlDictComputeBigKey(
                        (*iter).name,
                        (*iter).len as i32,
                        (*dict).seed,
                    ) as u64
                };
            }
            key = okey.wrapping_rem((*dict).size);
            if (*((*dict).dict).offset(key as isize)).valid == 0 as i32 {
                memcpy(
                    &mut *((*dict).dict).offset(key as isize) as *mut _xmlDictEntry
                        as *mut libc::c_void,
                    iter as *const libc::c_void,
                    ::std::mem::size_of::<xmlDictEntry>() as u64,
                );
                let fresh30 = &mut ((*((*dict).dict).offset(key as isize)).next);
                *fresh30 = 0 as *mut _xmlDictEntry;
                (*((*dict).dict).offset(key as isize)).valid = 1 as i32;
                (*((*dict).dict).offset(key as isize)).okey = okey;
                xmlFree.expect("non-null function pointer")(iter as *mut libc::c_void);
            } else {
                let fresh31 = &mut ((*iter).next);
                *fresh31 = (*((*dict).dict).offset(key as isize)).next;
                (*iter).okey = okey;
                let fresh32 = &mut ((*((*dict).dict).offset(key as isize)).next);
                *fresh32 = iter;
            }
            iter = next;
        }
        i = i.wrapping_add(1);
    }
    xmlFree.expect("non-null function pointer")(olddict as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDictFree(mut dict: xmlDictPtr) {
    let mut i: size_t = 0;
    let mut iter: xmlDictEntryPtr = 0 as *mut xmlDictEntry;
    let mut next: xmlDictEntryPtr = 0 as *mut xmlDictEntry;
    let mut inside_dict: i32 = 0 as i32;
    let mut pool: xmlDictStringsPtr = 0 as *mut xmlDictStrings;
    let mut nextp: xmlDictStringsPtr = 0 as *mut xmlDictStrings;
    if dict.is_null() {
        return;
    }
    if xmlDictInitialized == 0 {
        if __xmlInitializeDict() == 0 {
            return;
        }
    }
    xmlMutexLock(xmlDictMutex);
    let fresh33 = &mut ((*dict).ref_counter);
    *fresh33 -= 1;
    if (*dict).ref_counter > 0 as i32 {
        xmlMutexUnlock(xmlDictMutex);
        return;
    }
    xmlMutexUnlock(xmlDictMutex);
    if !((*dict).subdict).is_null() {
        xmlDictFree((*dict).subdict);
    }
    if !((*dict).dict).is_null() {
        i = 0 as i32 as size_t;
        while i < (*dict).size && (*dict).nbElems > 0 as i32 as u32 {
            iter = &mut *((*dict).dict).offset(i as isize) as *mut _xmlDictEntry;
            if !((*iter).valid == 0 as i32) {
                inside_dict = 1 as i32;
                while !iter.is_null() {
                    next = (*iter).next;
                    if inside_dict == 0 {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(iter as *mut libc::c_void);
                    }
                    let fresh34 = &mut ((*dict).nbElems);
                    *fresh34 = (*fresh34).wrapping_sub(1);
                    inside_dict = 0 as i32;
                    iter = next;
                }
            }
            i = i.wrapping_add(1);
        }
        xmlFree.expect("non-null function pointer")((*dict).dict as *mut libc::c_void);
    }
    pool = (*dict).strings;
    while !pool.is_null() {
        nextp = (*pool).next;
        xmlFree.expect("non-null function pointer")(pool as *mut libc::c_void);
        pool = nextp;
    }
    xmlFree.expect("non-null function pointer")(dict as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDictLookup(
    mut dict: xmlDictPtr,
    mut name: *const xmlChar,
    mut len: i32,
) -> *const xmlChar {
    let mut key: u64 = 0;
    let mut okey: u64 = 0;
    let mut nbi: u64 = 0 as i32 as u64;
    let mut entry: xmlDictEntryPtr = 0 as *mut xmlDictEntry;
    let mut insert: xmlDictEntryPtr = 0 as *mut xmlDictEntry;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    let mut l: u32 = 0;
    if dict.is_null() || name.is_null() {
        return 0 as *const xmlChar;
    }
    if len < 0 as i32 {
        l = strlen(name as *const i8) as u32;
    } else {
        l = len as u32;
    }
    if (*dict).limit > 0 as i32 as u64
        && l as u64 >= (*dict).limit
        || l > (2147483647 as i32 / 2 as i32) as u32
    {
        return 0 as *const xmlChar;
    }
    okey = if (*dict).size == 128 as i32 as u64 {
        xmlDictComputeFastKey(name, l as i32, (*dict).seed)
    } else {
        xmlDictComputeBigKey(name, l as i32, (*dict).seed) as u64
    };
    key = okey.wrapping_rem((*dict).size);
    if (*((*dict).dict).offset(key as isize)).valid == 0 as i32 {
        insert = 0 as xmlDictEntryPtr;
    } else {
        insert = &mut *((*dict).dict).offset(key as isize) as *mut _xmlDictEntry;
        while !((*insert).next).is_null() {
            if (*insert).okey == okey && (*insert).len == l {
                if memcmp(
                    (*insert).name as *const libc::c_void,
                    name as *const libc::c_void,
                    l as u64,
                ) == 0
                {
                    return (*insert).name;
                }
            }
            nbi = nbi.wrapping_add(1);
            insert = (*insert).next;
        }
        if (*insert).okey == okey && (*insert).len == l {
            if memcmp(
                (*insert).name as *const libc::c_void,
                name as *const libc::c_void,
                l as u64,
            ) == 0
            {
                return (*insert).name;
            }
        }
    }
    if !((*dict).subdict).is_null() {
        let mut skey: u64 = 0;
        if (*dict).size == 128 as i32 as u64
            && (*(*dict).subdict).size != 128 as i32 as u64
            || (*dict).size != 128 as i32 as u64
                && (*(*dict).subdict).size == 128 as i32 as u64
        {
            skey = if (*(*dict).subdict).size == 128 as i32 as u64 {
                xmlDictComputeFastKey(name, l as i32, (*(*dict).subdict).seed)
            } else {
                xmlDictComputeBigKey(name, l as i32, (*(*dict).subdict).seed)
                    as u64
            };
        } else {
            skey = okey;
        }
        key = skey.wrapping_rem((*(*dict).subdict).size);
        if (*((*(*dict).subdict).dict).offset(key as isize)).valid != 0 as i32 {
            let mut tmp: xmlDictEntryPtr = 0 as *mut xmlDictEntry;
            tmp = &mut *((*(*dict).subdict).dict).offset(key as isize)
                as *mut _xmlDictEntry;
            while !((*tmp).next).is_null() {
                if (*tmp).okey == skey && (*tmp).len == l {
                    if memcmp(
                        (*tmp).name as *const libc::c_void,
                        name as *const libc::c_void,
                        l as u64,
                    ) == 0
                    {
                        return (*tmp).name;
                    }
                }
                nbi = nbi.wrapping_add(1);
                tmp = (*tmp).next;
            }
            if (*tmp).okey == skey && (*tmp).len == l {
                if memcmp(
                    (*tmp).name as *const libc::c_void,
                    name as *const libc::c_void,
                    l as u64,
                ) == 0
                {
                    return (*tmp).name;
                }
            }
        }
        key = okey.wrapping_rem((*dict).size);
    }
    ret = xmlDictAddString(dict, name, l);
    if ret.is_null() {
        return 0 as *const xmlChar;
    }
    if insert.is_null() {
        entry = &mut *((*dict).dict).offset(key as isize) as *mut _xmlDictEntry;
    } else {
        entry = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlDictEntry>() as u64) as xmlDictEntryPtr;
        if entry.is_null() {
            return 0 as *const xmlChar;
        }
    }
    let fresh35 = &mut ((*entry).name);
    *fresh35 = ret;
    (*entry).len = l;
    let fresh36 = &mut ((*entry).next);
    *fresh36 = 0 as *mut _xmlDictEntry;
    (*entry).valid = 1 as i32;
    (*entry).okey = okey;
    if !insert.is_null() {
        let fresh37 = &mut ((*insert).next);
        *fresh37 = entry;
    }
    let fresh38 = &mut ((*dict).nbElems);
    *fresh38 = (*fresh38).wrapping_add(1);
    if nbi > 3 as i32 as u64
        && (*dict).size
            <= (8 as i32 * 2048 as i32 / 2 as i32
                / 3 as i32) as u64
    {
        if xmlDictGrow(
            dict,
            ((3 as i32 * 2 as i32) as u64)
                .wrapping_mul((*dict).size),
        ) != 0 as i32
        {
            return 0 as *const xmlChar;
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDictExists(
    mut dict: xmlDictPtr,
    mut name: *const xmlChar,
    mut len: i32,
) -> *const xmlChar {
    let mut key: u64 = 0;
    let mut okey: u64 = 0;
    let mut nbi: u64 = 0 as i32 as u64;
    let mut insert: xmlDictEntryPtr = 0 as *mut xmlDictEntry;
    let mut l: u32 = 0;
    if dict.is_null() || name.is_null() {
        return 0 as *const xmlChar;
    }
    if len < 0 as i32 {
        l = strlen(name as *const i8) as u32;
    } else {
        l = len as u32;
    }
    if (*dict).limit > 0 as i32 as u64
        && l as u64 >= (*dict).limit
        || l > (2147483647 as i32 / 2 as i32) as u32
    {
        return 0 as *const xmlChar;
    }
    okey = if (*dict).size == 128 as i32 as u64 {
        xmlDictComputeFastKey(name, l as i32, (*dict).seed)
    } else {
        xmlDictComputeBigKey(name, l as i32, (*dict).seed) as u64
    };
    key = okey.wrapping_rem((*dict).size);
    if (*((*dict).dict).offset(key as isize)).valid == 0 as i32 {
        insert = 0 as xmlDictEntryPtr;
    } else {
        insert = &mut *((*dict).dict).offset(key as isize) as *mut _xmlDictEntry;
        while !((*insert).next).is_null() {
            if (*insert).okey == okey && (*insert).len == l {
                if memcmp(
                    (*insert).name as *const libc::c_void,
                    name as *const libc::c_void,
                    l as u64,
                ) == 0
                {
                    return (*insert).name;
                }
            }
            nbi = nbi.wrapping_add(1);
            insert = (*insert).next;
        }
        if (*insert).okey == okey && (*insert).len == l {
            if memcmp(
                (*insert).name as *const libc::c_void,
                name as *const libc::c_void,
                l as u64,
            ) == 0
            {
                return (*insert).name;
            }
        }
    }
    if !((*dict).subdict).is_null() {
        let mut skey: u64 = 0;
        if (*dict).size == 128 as i32 as u64
            && (*(*dict).subdict).size != 128 as i32 as u64
            || (*dict).size != 128 as i32 as u64
                && (*(*dict).subdict).size == 128 as i32 as u64
        {
            skey = if (*(*dict).subdict).size == 128 as i32 as u64 {
                xmlDictComputeFastKey(name, l as i32, (*(*dict).subdict).seed)
            } else {
                xmlDictComputeBigKey(name, l as i32, (*(*dict).subdict).seed)
                    as u64
            };
        } else {
            skey = okey;
        }
        key = skey.wrapping_rem((*(*dict).subdict).size);
        if (*((*(*dict).subdict).dict).offset(key as isize)).valid != 0 as i32 {
            let mut tmp: xmlDictEntryPtr = 0 as *mut xmlDictEntry;
            tmp = &mut *((*(*dict).subdict).dict).offset(key as isize)
                as *mut _xmlDictEntry;
            while !((*tmp).next).is_null() {
                if (*tmp).okey == skey && (*tmp).len == l {
                    if memcmp(
                        (*tmp).name as *const libc::c_void,
                        name as *const libc::c_void,
                        l as u64,
                    ) == 0
                    {
                        return (*tmp).name;
                    }
                }
                nbi = nbi.wrapping_add(1);
                tmp = (*tmp).next;
            }
            if (*tmp).okey == skey && (*tmp).len == l {
                if memcmp(
                    (*tmp).name as *const libc::c_void,
                    name as *const libc::c_void,
                    l as u64,
                ) == 0
                {
                    return (*tmp).name;
                }
            }
        }
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDictQLookup(
    mut dict: xmlDictPtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
) -> *const xmlChar {
    let mut okey: u64 = 0;
    let mut key: u64 = 0;
    let mut nbi: u64 = 0 as i32 as u64;
    let mut entry: xmlDictEntryPtr = 0 as *mut xmlDictEntry;
    let mut insert: xmlDictEntryPtr = 0 as *mut xmlDictEntry;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    let mut len: u32 = 0;
    let mut plen: u32 = 0;
    let mut l: u32 = 0;
    if dict.is_null() || name.is_null() {
        return 0 as *const xmlChar;
    }
    if prefix.is_null() {
        return xmlDictLookup(dict, name, -(1 as i32));
    }
    len = strlen(name as *const i8) as u32;
    l = len;
    plen = strlen(prefix as *const i8) as u32;
    len = len.wrapping_add((1 as i32 as u32).wrapping_add(plen));
    okey = if prefix.is_null() {
        if (*dict).size == 128 as i32 as u64 {
            xmlDictComputeFastKey(name, l as i32, (*dict).seed)
        } else {
            xmlDictComputeBigKey(name, l as i32, (*dict).seed) as u64
        }
    } else if (*dict).size == 128 as i32 as u64 {
        xmlDictComputeFastQKey(
            prefix,
            plen as i32,
            name,
            l as i32,
            (*dict).seed,
        )
    } else {
        xmlDictComputeBigQKey(
            prefix,
            plen as i32,
            name,
            l as i32,
            (*dict).seed,
        )
    };
    key = okey.wrapping_rem((*dict).size);
    if (*((*dict).dict).offset(key as isize)).valid == 0 as i32 {
        insert = 0 as xmlDictEntryPtr;
    } else {
        insert = &mut *((*dict).dict).offset(key as isize) as *mut _xmlDictEntry;
        while !((*insert).next).is_null() {
            if (*insert).okey == okey && (*insert).len == len
                && xmlStrQEqual(prefix, name, (*insert).name) != 0
            {
                return (*insert).name;
            }
            nbi = nbi.wrapping_add(1);
            insert = (*insert).next;
        }
        if (*insert).okey == okey && (*insert).len == len
            && xmlStrQEqual(prefix, name, (*insert).name) != 0
        {
            return (*insert).name;
        }
    }
    if !((*dict).subdict).is_null() {
        let mut skey: u64 = 0;
        if (*dict).size == 128 as i32 as u64
            && (*(*dict).subdict).size != 128 as i32 as u64
            || (*dict).size != 128 as i32 as u64
                && (*(*dict).subdict).size == 128 as i32 as u64
        {
            skey = if prefix.is_null() {
                if (*(*dict).subdict).size == 128 as i32 as u64 {
                    xmlDictComputeFastKey(
                        name,
                        l as i32,
                        (*(*dict).subdict).seed,
                    )
                } else {
                    xmlDictComputeBigKey(name, l as i32, (*(*dict).subdict).seed)
                        as u64
                }
            } else if (*(*dict).subdict).size == 128 as i32 as u64 {
                xmlDictComputeFastQKey(
                    prefix,
                    plen as i32,
                    name,
                    l as i32,
                    (*(*dict).subdict).seed,
                )
            } else {
                xmlDictComputeBigQKey(
                    prefix,
                    plen as i32,
                    name,
                    l as i32,
                    (*(*dict).subdict).seed,
                )
            };
        } else {
            skey = okey;
        }
        key = skey.wrapping_rem((*(*dict).subdict).size);
        if (*((*(*dict).subdict).dict).offset(key as isize)).valid != 0 as i32 {
            let mut tmp: xmlDictEntryPtr = 0 as *mut xmlDictEntry;
            tmp = &mut *((*(*dict).subdict).dict).offset(key as isize)
                as *mut _xmlDictEntry;
            while !((*tmp).next).is_null() {
                if (*tmp).okey == skey && (*tmp).len == len
                    && xmlStrQEqual(prefix, name, (*tmp).name) != 0
                {
                    return (*tmp).name;
                }
                nbi = nbi.wrapping_add(1);
                tmp = (*tmp).next;
            }
            if (*tmp).okey == skey && (*tmp).len == len
                && xmlStrQEqual(prefix, name, (*tmp).name) != 0
            {
                return (*tmp).name;
            }
        }
        key = okey.wrapping_rem((*dict).size);
    }
    ret = xmlDictAddQString(dict, prefix, plen, name, l);
    if ret.is_null() {
        return 0 as *const xmlChar;
    }
    if insert.is_null() {
        entry = &mut *((*dict).dict).offset(key as isize) as *mut _xmlDictEntry;
    } else {
        entry = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlDictEntry>() as u64) as xmlDictEntryPtr;
        if entry.is_null() {
            return 0 as *const xmlChar;
        }
    }
    let fresh39 = &mut ((*entry).name);
    *fresh39 = ret;
    (*entry).len = len;
    let fresh40 = &mut ((*entry).next);
    *fresh40 = 0 as *mut _xmlDictEntry;
    (*entry).valid = 1 as i32;
    (*entry).okey = okey;
    if !insert.is_null() {
        let fresh41 = &mut ((*insert).next);
        *fresh41 = entry;
    }
    let fresh42 = &mut ((*dict).nbElems);
    *fresh42 = (*fresh42).wrapping_add(1);
    if nbi > 3 as i32 as u64
        && (*dict).size
            <= (8 as i32 * 2048 as i32 / 2 as i32
                / 3 as i32) as u64
    {
        xmlDictGrow(
            dict,
            ((3 as i32 * 2 as i32) as u64)
                .wrapping_mul((*dict).size),
        );
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDictOwns(
    mut dict: xmlDictPtr,
    mut str: *const xmlChar,
) -> i32 {
    let mut pool: xmlDictStringsPtr = 0 as *mut xmlDictStrings;
    if dict.is_null() || str.is_null() {
        return -(1 as i32);
    }
    pool = (*dict).strings;
    while !pool.is_null() {
        if str
            >= &mut *((*pool).array).as_mut_ptr().offset(0 as i32 as isize)
                as *mut xmlChar as *const xmlChar
            && str <= (*pool).free as *const xmlChar
        {
            return 1 as i32;
        }
        pool = (*pool).next;
    }
    if !((*dict).subdict).is_null() {
        return xmlDictOwns((*dict).subdict, str);
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDictSize(mut dict: xmlDictPtr) -> i32 {
    if dict.is_null() {
        return -(1 as i32);
    }
    if !((*dict).subdict).is_null() {
        return ((*dict).nbElems).wrapping_add((*(*dict).subdict).nbElems) as i32;
    }
    return (*dict).nbElems as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDictSetLimit(
    mut dict: xmlDictPtr,
    mut limit: size_t,
) -> size_t {
    let mut ret: size_t = 0;
    if dict.is_null() {
        return 0 as i32 as size_t;
    }
    ret = (*dict).limit;
    (*dict).limit = limit;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDictGetUsage(mut dict: xmlDictPtr) -> size_t {
    let mut pool: xmlDictStringsPtr = 0 as *mut xmlDictStrings;
    let mut limit: size_t = 0 as i32 as size_t;
    if dict.is_null() {
        return 0 as i32 as size_t;
    }
    pool = (*dict).strings;
    while !pool.is_null() {
        limit = (limit as u64).wrapping_add((*pool).size) as size_t as size_t;
        pool = (*pool).next;
    }
    return limit;
}
