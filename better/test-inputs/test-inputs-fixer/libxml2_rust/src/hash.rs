use :: libc;
extern "C" {
    pub type _xmlDict;
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrQEqual(pref: *const xmlChar, name: *const xmlChar, str: *const xmlChar) -> i32;
    fn __xmlRandom() -> i32;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn xmlDictReference(dict: xmlDictPtr) -> i32;
    fn xmlDictFree(dict: xmlDictPtr);
    fn xmlDictLookup(dict: xmlDictPtr, name: *const xmlChar, len: i32) -> *const xmlChar;
    fn xmlDictOwns(dict: xmlDictPtr, str: *const xmlChar) -> i32;
    static mut xmlFree: xmlFreeFunc;
    static mut xmlMalloc: xmlMallocFunc;
}
pub type xmlChar = u8;
pub type size_t = u64;
pub type xmlHashTablePtr = *mut xmlHashTable;
pub type xmlHashTable = _xmlHashTable;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlHashTable {
    pub table: *mut _xmlHashEntry,
    pub size: i32,
    pub nbElems: i32,
    pub dict: xmlDictPtr,
    pub random_seed: i32,
}
pub type xmlDictPtr = *mut xmlDict;
pub type xmlDict = _xmlDict;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlHashEntry {
    pub next: *mut _xmlHashEntry,
    pub name: *mut xmlChar,
    pub name2: *mut xmlChar,
    pub name3: *mut xmlChar,
    pub payload: *mut libc::c_void,
    pub valid: i32,
}
pub type xmlHashDeallocator = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type xmlHashCopier =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> *mut libc::c_void>;
pub type xmlHashScanner =
    Option<unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void, *const xmlChar) -> ()>;
pub type xmlHashScannerFull = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type xmlHashEntry = _xmlHashEntry;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type xmlHashEntryPtr = *mut xmlHashEntry;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stubData {
    pub hashscanner: xmlHashScanner,
    pub data: *mut libc::c_void,
}
extern "C" fn xmlHashComputeKey(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
) -> u64 {
    let mut value: u64 = 0 as i64 as u64;
    let mut ch: u64 = 0;
    value = (unsafe { (*table).random_seed }) as u64;
    if !name.is_null() {
        value = value.wrapping_add((30 as i32 * (unsafe { *name }) as i32) as u64);
        loop {
            let fresh0 = name;
            name = unsafe { name.offset(1) };
            ch = (unsafe { *fresh0 }) as u64;
            if !(ch != 0 as i32 as u64) {
                break;
            }
            value = value
                ^ (value << 5 as i32)
                    .wrapping_add(value >> 3 as i32)
                    .wrapping_add(ch);
        }
    }
    value = value ^ (value << 5 as i32).wrapping_add(value >> 3 as i32);
    if !name2.is_null() {
        loop {
            let fresh1 = name2;
            name2 = unsafe { name2.offset(1) };
            ch = (unsafe { *fresh1 }) as u64;
            if !(ch != 0 as i32 as u64) {
                break;
            }
            value = value
                ^ (value << 5 as i32)
                    .wrapping_add(value >> 3 as i32)
                    .wrapping_add(ch);
        }
    }
    value = value ^ (value << 5 as i32).wrapping_add(value >> 3 as i32);
    if !name3.is_null() {
        loop {
            let fresh2 = name3;
            name3 = unsafe { name3.offset(1) };
            ch = (unsafe { *fresh2 }) as u64;
            if !(ch != 0 as i32 as u64) {
                break;
            }
            value = value
                ^ (value << 5 as i32)
                    .wrapping_add(value >> 3 as i32)
                    .wrapping_add(ch);
        }
    }
    return value.wrapping_rem((unsafe { (*table).size }) as u64);
}
extern "C" fn xmlHashComputeQKey(
    mut table: xmlHashTablePtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
    mut prefix2: *const xmlChar,
    mut name2: *const xmlChar,
    mut prefix3: *const xmlChar,
    mut name3: *const xmlChar,
) -> u64 {
    let mut value: u64 = 0 as i64 as u64;
    let mut ch: u64 = 0;
    value = (unsafe { (*table).random_seed }) as u64;
    if !prefix.is_null() {
        value = value.wrapping_add((30 as i32 * (unsafe { *prefix }) as i32) as u64);
    } else {
        value = value.wrapping_add((30 as i32 * (unsafe { *name }) as i32) as u64);
    }
    if !prefix.is_null() {
        loop {
            let fresh3 = prefix;
            prefix = unsafe { prefix.offset(1) };
            ch = (unsafe { *fresh3 }) as u64;
            if !(ch != 0 as i32 as u64) {
                break;
            }
            value = value
                ^ (value << 5 as i32)
                    .wrapping_add(value >> 3 as i32)
                    .wrapping_add(ch);
        }
        value = value
            ^ (value << 5 as i32)
                .wrapping_add(value >> 3 as i32)
                .wrapping_add(':' as i32 as u64);
    }
    if !name.is_null() {
        loop {
            let fresh4 = name;
            name = unsafe { name.offset(1) };
            ch = (unsafe { *fresh4 }) as u64;
            if !(ch != 0 as i32 as u64) {
                break;
            }
            value = value
                ^ (value << 5 as i32)
                    .wrapping_add(value >> 3 as i32)
                    .wrapping_add(ch);
        }
    }
    value = value ^ (value << 5 as i32).wrapping_add(value >> 3 as i32);
    if !prefix2.is_null() {
        loop {
            let fresh5 = prefix2;
            prefix2 = unsafe { prefix2.offset(1) };
            ch = (unsafe { *fresh5 }) as u64;
            if !(ch != 0 as i32 as u64) {
                break;
            }
            value = value
                ^ (value << 5 as i32)
                    .wrapping_add(value >> 3 as i32)
                    .wrapping_add(ch);
        }
        value = value
            ^ (value << 5 as i32)
                .wrapping_add(value >> 3 as i32)
                .wrapping_add(':' as i32 as u64);
    }
    if !name2.is_null() {
        loop {
            let fresh6 = name2;
            name2 = unsafe { name2.offset(1) };
            ch = (unsafe { *fresh6 }) as u64;
            if !(ch != 0 as i32 as u64) {
                break;
            }
            value = value
                ^ (value << 5 as i32)
                    .wrapping_add(value >> 3 as i32)
                    .wrapping_add(ch);
        }
    }
    value = value ^ (value << 5 as i32).wrapping_add(value >> 3 as i32);
    if !prefix3.is_null() {
        loop {
            let fresh7 = prefix3;
            prefix3 = unsafe { prefix3.offset(1) };
            ch = (unsafe { *fresh7 }) as u64;
            if !(ch != 0 as i32 as u64) {
                break;
            }
            value = value
                ^ (value << 5 as i32)
                    .wrapping_add(value >> 3 as i32)
                    .wrapping_add(ch);
        }
        value = value
            ^ (value << 5 as i32)
                .wrapping_add(value >> 3 as i32)
                .wrapping_add(':' as i32 as u64);
    }
    if !name3.is_null() {
        loop {
            let fresh8 = name3;
            name3 = unsafe { name3.offset(1) };
            ch = (unsafe { *fresh8 }) as u64;
            if !(ch != 0 as i32 as u64) {
                break;
            }
            value = value
                ^ (value << 5 as i32)
                    .wrapping_add(value >> 3 as i32)
                    .wrapping_add(ch);
        }
    }
    return value.wrapping_rem((unsafe { (*table).size }) as u64);
}
#[no_mangle]
pub extern "C" fn xmlHashCreate(mut size: i32) -> xmlHashTablePtr {
    let mut table: xmlHashTablePtr = 0 as *mut xmlHashTable;
    if size <= 0 as i32 {
        size = 256 as i32;
    }
    table =
        (unsafe { xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlHashTable>() as u64) })
            as xmlHashTablePtr;
    if !table.is_null() {
        let fresh9 = unsafe { &mut ((*table).dict) };
        *fresh9 = 0 as xmlDictPtr;
        (unsafe { (*table).size = size });
        (unsafe { (*table).nbElems = 0 as i32 });
        let fresh10 = unsafe { &mut ((*table).table) };
        *fresh10 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            (size as u64).wrapping_mul(::std::mem::size_of::<xmlHashEntry>() as u64),
        ) }) as *mut _xmlHashEntry;
        if !(unsafe { (*table).table }).is_null() {
            (unsafe { memset(
                (*table).table as *mut libc::c_void,
                0 as i32,
                (size as u64).wrapping_mul(::std::mem::size_of::<xmlHashEntry>() as u64),
            ) });
            (unsafe { (*table).random_seed = __xmlRandom() });
            return table;
        }
        (unsafe { xmlFree.expect("non-null function pointer")(table as *mut libc::c_void) });
    }
    return 0 as xmlHashTablePtr;
}
#[no_mangle]
pub extern "C" fn xmlHashCreateDict(mut size: i32, mut dict: xmlDictPtr) -> xmlHashTablePtr {
    let mut table: xmlHashTablePtr = 0 as *mut xmlHashTable;
    table = xmlHashCreate(size);
    if !table.is_null() {
        let fresh11 = unsafe { &mut ((*table).dict) };
        *fresh11 = dict;
        (unsafe { xmlDictReference(dict) });
    }
    return table;
}
extern "C" fn xmlHashGrow(mut table: xmlHashTablePtr, mut size: i32) -> i32 {
    let mut key: u64 = 0;
    let mut oldsize: i32 = 0;
    let mut i: i32 = 0;
    let mut iter: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut next: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut oldtable: *mut _xmlHashEntry = 0 as *mut _xmlHashEntry;
    if table.is_null() {
        return -(1 as i32);
    }
    if size < 8 as i32 {
        return -(1 as i32);
    }
    if size > 8 as i32 * 2048 as i32 {
        return -(1 as i32);
    }
    oldsize = unsafe { (*table).size };
    oldtable = unsafe { (*table).table };
    if oldtable.is_null() {
        return -(1 as i32);
    }
    let fresh12 = unsafe { &mut ((*table).table) };
    *fresh12 = (unsafe { xmlMalloc.expect("non-null function pointer")(
        (size as u64).wrapping_mul(::std::mem::size_of::<xmlHashEntry>() as u64),
    ) }) as *mut _xmlHashEntry;
    if (unsafe { (*table).table }).is_null() {
        let fresh13 = unsafe { &mut ((*table).table) };
        *fresh13 = oldtable;
        return -(1 as i32);
    }
    (unsafe { memset(
        (*table).table as *mut libc::c_void,
        0 as i32,
        (size as u64).wrapping_mul(::std::mem::size_of::<xmlHashEntry>() as u64),
    ) });
    (unsafe { (*table).size = size });
    i = 0 as i32;
    while i < oldsize {
        if !((unsafe { (*oldtable.offset(i as isize)).valid }) == 0 as i32) {
            key = xmlHashComputeKey(
                table,
                unsafe { (*oldtable.offset(i as isize)).name },
                unsafe { (*oldtable.offset(i as isize)).name2 },
                unsafe { (*oldtable.offset(i as isize)).name3 },
            );
            (unsafe { memcpy(
                &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry
                    as *mut libc::c_void,
                &mut *oldtable.offset(i as isize) as *mut _xmlHashEntry as *const libc::c_void,
                ::std::mem::size_of::<xmlHashEntry>() as u64,
            ) });
            let fresh14 = unsafe { &mut ((*((*table).table).offset(key as isize)).next) };
            *fresh14 = 0 as *mut _xmlHashEntry;
        }
        i += 1;
    }
    i = 0 as i32;
    while i < oldsize {
        iter = unsafe { (*oldtable.offset(i as isize)).next };
        while !iter.is_null() {
            next = unsafe { (*iter).next };
            key = xmlHashComputeKey(table, unsafe { (*iter).name }, unsafe { (*iter).name2 }, unsafe { (*iter).name3 });
            if (unsafe { (*((*table).table).offset(key as isize)).valid }) == 0 as i32 {
                (unsafe { memcpy(
                    &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry
                        as *mut libc::c_void,
                    iter as *const libc::c_void,
                    ::std::mem::size_of::<xmlHashEntry>() as u64,
                ) });
                let fresh15 = unsafe { &mut ((*((*table).table).offset(key as isize)).next) };
                *fresh15 = 0 as *mut _xmlHashEntry;
                (unsafe { xmlFree.expect("non-null function pointer")(iter as *mut libc::c_void) });
            } else {
                let fresh16 = unsafe { &mut ((*iter).next) };
                *fresh16 = unsafe { (*((*table).table).offset(key as isize)).next };
                let fresh17 = unsafe { &mut ((*((*table).table).offset(key as isize)).next) };
                *fresh17 = iter;
            }
            iter = next;
        }
        i += 1;
    }
    (unsafe { xmlFree.expect("non-null function pointer")(oldtable as *mut libc::c_void) });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlHashFree(mut table: xmlHashTablePtr, mut f: xmlHashDeallocator) {
    let mut i: i32 = 0;
    let mut iter: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut next: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut inside_table: i32 = 0 as i32;
    let mut nbElems: i32 = 0;
    if table.is_null() {
        return;
    }
    if !(unsafe { (*table).table }).is_null() {
        nbElems = unsafe { (*table).nbElems };
        i = 0 as i32;
        while i < (unsafe { (*table).size }) && nbElems > 0 as i32 {
            iter = (unsafe { &mut *((*table).table).offset(i as isize) }) as *mut _xmlHashEntry;
            if !((unsafe { (*iter).valid }) == 0 as i32) {
                inside_table = 1 as i32;
                while !iter.is_null() {
                    next = unsafe { (*iter).next };
                    if f.is_some() && !(unsafe { (*iter).payload }).is_null() {
                        (unsafe { f.expect("non-null function pointer")((*iter).payload, (*iter).name) });
                    }
                    if (unsafe { (*table).dict }).is_null() {
                        if !(unsafe { (*iter).name }).is_null() {
                            (unsafe { xmlFree.expect("non-null function pointer")(
                                (*iter).name as *mut libc::c_void,
                            ) });
                        }
                        if !(unsafe { (*iter).name2 }).is_null() {
                            (unsafe { xmlFree.expect("non-null function pointer")(
                                (*iter).name2 as *mut libc::c_void,
                            ) });
                        }
                        if !(unsafe { (*iter).name3 }).is_null() {
                            (unsafe { xmlFree.expect("non-null function pointer")(
                                (*iter).name3 as *mut libc::c_void,
                            ) });
                        }
                    }
                    let fresh18 = unsafe { &mut ((*iter).payload) };
                    *fresh18 = 0 as *mut libc::c_void;
                    if inside_table == 0 {
                        (unsafe { xmlFree.expect("non-null function pointer")(iter as *mut libc::c_void) });
                    }
                    nbElems -= 1;
                    inside_table = 0 as i32;
                    iter = next;
                }
            }
            i += 1;
        }
        (unsafe { xmlFree.expect("non-null function pointer")((*table).table as *mut libc::c_void) });
    }
    if !(unsafe { (*table).dict }).is_null() {
        (unsafe { xmlDictFree((*table).dict) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(table as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlHashDefaultDeallocator(
    mut entry: *mut libc::c_void,
    mut _name: *const xmlChar,
) {
    (unsafe { xmlFree.expect("non-null function pointer")(entry) });
}
#[no_mangle]
pub extern "C" fn xmlHashAddEntry(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut userdata: *mut libc::c_void,
) -> i32 {
    return xmlHashAddEntry3(
        table,
        name,
        0 as *const xmlChar,
        0 as *const xmlChar,
        userdata,
    );
}
#[no_mangle]
pub extern "C" fn xmlHashAddEntry2(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut userdata: *mut libc::c_void,
) -> i32 {
    return xmlHashAddEntry3(table, name, name2, 0 as *const xmlChar, userdata);
}
#[no_mangle]
pub extern "C" fn xmlHashUpdateEntry(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut userdata: *mut libc::c_void,
    mut f: xmlHashDeallocator,
) -> i32 {
    return xmlHashUpdateEntry3(
        table,
        name,
        0 as *const xmlChar,
        0 as *const xmlChar,
        userdata,
        f,
    );
}
#[no_mangle]
pub extern "C" fn xmlHashUpdateEntry2(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut userdata: *mut libc::c_void,
    mut f: xmlHashDeallocator,
) -> i32 {
    return xmlHashUpdateEntry3(table, name, name2, 0 as *const xmlChar, userdata, f);
}
#[no_mangle]
pub extern "C" fn xmlHashLookup(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
) -> *mut libc::c_void {
    return xmlHashLookup3(table, name, 0 as *const xmlChar, 0 as *const xmlChar);
}
#[no_mangle]
pub extern "C" fn xmlHashLookup2(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
) -> *mut libc::c_void {
    return xmlHashLookup3(table, name, name2, 0 as *const xmlChar);
}
#[no_mangle]
pub extern "C" fn xmlHashQLookup(
    mut table: xmlHashTablePtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
) -> *mut libc::c_void {
    return xmlHashQLookup3(
        table,
        prefix,
        name,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
    );
}
#[no_mangle]
pub extern "C" fn xmlHashQLookup2(
    mut table: xmlHashTablePtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
    mut prefix2: *const xmlChar,
    mut name2: *const xmlChar,
) -> *mut libc::c_void {
    return xmlHashQLookup3(
        table,
        prefix,
        name,
        prefix2,
        name2,
        0 as *const xmlChar,
        0 as *const xmlChar,
    );
}
#[no_mangle]
pub extern "C" fn xmlHashAddEntry3(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
    mut userdata: *mut libc::c_void,
) -> i32 {
    let mut key: u64 = 0;
    let mut len: u64 = 0 as i32 as u64;
    let mut entry: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut insert: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    if table.is_null() || name.is_null() {
        return -(1 as i32);
    }
    if !(unsafe { (*table).dict }).is_null() {
        if (unsafe { xmlDictOwns((*table).dict, name) }) == 0 {
            name = unsafe { xmlDictLookup((*table).dict, name, -(1 as i32)) };
            if name.is_null() {
                return -(1 as i32);
            }
        }
        if !name2.is_null() && (unsafe { xmlDictOwns((*table).dict, name2) }) == 0 {
            name2 = unsafe { xmlDictLookup((*table).dict, name2, -(1 as i32)) };
            if name2.is_null() {
                return -(1 as i32);
            }
        }
        if !name3.is_null() && (unsafe { xmlDictOwns((*table).dict, name3) }) == 0 {
            name3 = unsafe { xmlDictLookup((*table).dict, name3, -(1 as i32)) };
            if name3.is_null() {
                return -(1 as i32);
            }
        }
    }
    key = xmlHashComputeKey(table, name, name2, name3);
    if (unsafe { (*((*table).table).offset(key as isize)).valid }) == 0 as i32 {
        insert = 0 as xmlHashEntryPtr;
    } else if !(unsafe { (*table).dict }).is_null() {
        insert = (unsafe { &mut *((*table).table).offset(key as isize) }) as *mut _xmlHashEntry;
        while !(unsafe { (*insert).next }).is_null() {
            if (unsafe { (*insert).name }) == name as *mut xmlChar
                && (unsafe { (*insert).name2 }) == name2 as *mut xmlChar
                && (unsafe { (*insert).name3 }) == name3 as *mut xmlChar
            {
                return -(1 as i32);
            }
            len = len.wrapping_add(1);
            insert = unsafe { (*insert).next };
        }
        if (unsafe { (*insert).name }) == name as *mut xmlChar
            && (unsafe { (*insert).name2 }) == name2 as *mut xmlChar
            && (unsafe { (*insert).name3 }) == name3 as *mut xmlChar
        {
            return -(1 as i32);
        }
    } else {
        insert = (unsafe { &mut *((*table).table).offset(key as isize) }) as *mut _xmlHashEntry;
        while !(unsafe { (*insert).next }).is_null() {
            if (unsafe { xmlStrEqual((*insert).name, name) }) != 0
                && (unsafe { xmlStrEqual((*insert).name2, name2) }) != 0
                && (unsafe { xmlStrEqual((*insert).name3, name3) }) != 0
            {
                return -(1 as i32);
            }
            len = len.wrapping_add(1);
            insert = unsafe { (*insert).next };
        }
        if (unsafe { xmlStrEqual((*insert).name, name) }) != 0
            && (unsafe { xmlStrEqual((*insert).name2, name2) }) != 0
            && (unsafe { xmlStrEqual((*insert).name3, name3) }) != 0
        {
            return -(1 as i32);
        }
    }
    if insert.is_null() {
        entry = (unsafe { &mut *((*table).table).offset(key as isize) }) as *mut _xmlHashEntry;
    } else {
        entry = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlHashEntry>() as u64
        ) }) as xmlHashEntryPtr;
        if entry.is_null() {
            return -(1 as i32);
        }
    }
    if !(unsafe { (*table).dict }).is_null() {
        let fresh19 = unsafe { &mut ((*entry).name) };
        *fresh19 = name as *mut xmlChar;
        let fresh20 = unsafe { &mut ((*entry).name2) };
        *fresh20 = name2 as *mut xmlChar;
        let fresh21 = unsafe { &mut ((*entry).name3) };
        *fresh21 = name3 as *mut xmlChar;
    } else {
        let fresh22 = unsafe { &mut ((*entry).name) };
        *fresh22 = unsafe { xmlStrdup(name) };
        let fresh23 = unsafe { &mut ((*entry).name2) };
        *fresh23 = unsafe { xmlStrdup(name2) };
        let fresh24 = unsafe { &mut ((*entry).name3) };
        *fresh24 = unsafe { xmlStrdup(name3) };
    }
    let fresh25 = unsafe { &mut ((*entry).payload) };
    *fresh25 = userdata;
    let fresh26 = unsafe { &mut ((*entry).next) };
    *fresh26 = 0 as *mut _xmlHashEntry;
    (unsafe { (*entry).valid = 1 as i32 });
    if !insert.is_null() {
        let fresh27 = unsafe { &mut ((*insert).next) };
        *fresh27 = entry;
    }
    let fresh28 = unsafe { &mut ((*table).nbElems) };
    *fresh28 += 1;
    if len > 8 as i32 as u64 {
        xmlHashGrow(table, 8 as i32 * (unsafe { (*table).size }));
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlHashUpdateEntry3(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
    mut userdata: *mut libc::c_void,
    mut f: xmlHashDeallocator,
) -> i32 {
    let mut key: u64 = 0;
    let mut entry: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut insert: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    if table.is_null() || name.is_null() {
        return -(1 as i32);
    }
    if !(unsafe { (*table).dict }).is_null() {
        if (unsafe { xmlDictOwns((*table).dict, name) }) == 0 {
            name = unsafe { xmlDictLookup((*table).dict, name, -(1 as i32)) };
            if name.is_null() {
                return -(1 as i32);
            }
        }
        if !name2.is_null() && (unsafe { xmlDictOwns((*table).dict, name2) }) == 0 {
            name2 = unsafe { xmlDictLookup((*table).dict, name2, -(1 as i32)) };
            if name2.is_null() {
                return -(1 as i32);
            }
        }
        if !name3.is_null() && (unsafe { xmlDictOwns((*table).dict, name3) }) == 0 {
            name3 = unsafe { xmlDictLookup((*table).dict, name3, -(1 as i32)) };
            if name3.is_null() {
                return -(1 as i32);
            }
        }
    }
    key = xmlHashComputeKey(table, name, name2, name3);
    if (unsafe { (*((*table).table).offset(key as isize)).valid }) == 0 as i32 {
        insert = 0 as xmlHashEntryPtr;
    } else if !(unsafe { (*table).dict }).is_null() {
        insert = (unsafe { &mut *((*table).table).offset(key as isize) }) as *mut _xmlHashEntry;
        while !(unsafe { (*insert).next }).is_null() {
            if (unsafe { (*insert).name }) == name as *mut xmlChar
                && (unsafe { (*insert).name2 }) == name2 as *mut xmlChar
                && (unsafe { (*insert).name3 }) == name3 as *mut xmlChar
            {
                if f.is_some() {
                    (unsafe { f.expect("non-null function pointer")((*insert).payload, (*insert).name) });
                }
                let fresh29 = unsafe { &mut ((*insert).payload) };
                *fresh29 = userdata;
                return 0 as i32;
            }
            insert = unsafe { (*insert).next };
        }
        if (unsafe { (*insert).name }) == name as *mut xmlChar
            && (unsafe { (*insert).name2 }) == name2 as *mut xmlChar
            && (unsafe { (*insert).name3 }) == name3 as *mut xmlChar
        {
            if f.is_some() {
                (unsafe { f.expect("non-null function pointer")((*insert).payload, (*insert).name) });
            }
            let fresh30 = unsafe { &mut ((*insert).payload) };
            *fresh30 = userdata;
            return 0 as i32;
        }
    } else {
        insert = (unsafe { &mut *((*table).table).offset(key as isize) }) as *mut _xmlHashEntry;
        while !(unsafe { (*insert).next }).is_null() {
            if (unsafe { xmlStrEqual((*insert).name, name) }) != 0
                && (unsafe { xmlStrEqual((*insert).name2, name2) }) != 0
                && (unsafe { xmlStrEqual((*insert).name3, name3) }) != 0
            {
                if f.is_some() {
                    (unsafe { f.expect("non-null function pointer")((*insert).payload, (*insert).name) });
                }
                let fresh31 = unsafe { &mut ((*insert).payload) };
                *fresh31 = userdata;
                return 0 as i32;
            }
            insert = unsafe { (*insert).next };
        }
        if (unsafe { xmlStrEqual((*insert).name, name) }) != 0
            && (unsafe { xmlStrEqual((*insert).name2, name2) }) != 0
            && (unsafe { xmlStrEqual((*insert).name3, name3) }) != 0
        {
            if f.is_some() {
                (unsafe { f.expect("non-null function pointer")((*insert).payload, (*insert).name) });
            }
            let fresh32 = unsafe { &mut ((*insert).payload) };
            *fresh32 = userdata;
            return 0 as i32;
        }
    }
    if insert.is_null() {
        entry = (unsafe { &mut *((*table).table).offset(key as isize) }) as *mut _xmlHashEntry;
    } else {
        entry = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlHashEntry>() as u64
        ) }) as xmlHashEntryPtr;
        if entry.is_null() {
            return -(1 as i32);
        }
    }
    if !(unsafe { (*table).dict }).is_null() {
        let fresh33 = unsafe { &mut ((*entry).name) };
        *fresh33 = name as *mut xmlChar;
        let fresh34 = unsafe { &mut ((*entry).name2) };
        *fresh34 = name2 as *mut xmlChar;
        let fresh35 = unsafe { &mut ((*entry).name3) };
        *fresh35 = name3 as *mut xmlChar;
    } else {
        let fresh36 = unsafe { &mut ((*entry).name) };
        *fresh36 = unsafe { xmlStrdup(name) };
        let fresh37 = unsafe { &mut ((*entry).name2) };
        *fresh37 = unsafe { xmlStrdup(name2) };
        let fresh38 = unsafe { &mut ((*entry).name3) };
        *fresh38 = unsafe { xmlStrdup(name3) };
    }
    let fresh39 = unsafe { &mut ((*entry).payload) };
    *fresh39 = userdata;
    let fresh40 = unsafe { &mut ((*entry).next) };
    *fresh40 = 0 as *mut _xmlHashEntry;
    (unsafe { (*entry).valid = 1 as i32 });
    let fresh41 = unsafe { &mut ((*table).nbElems) };
    *fresh41 += 1;
    if !insert.is_null() {
        let fresh42 = unsafe { &mut ((*insert).next) };
        *fresh42 = entry;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlHashLookup3(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
) -> *mut libc::c_void {
    let mut key: u64 = 0;
    let mut entry: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    if table.is_null() {
        return 0 as *mut libc::c_void;
    }
    if name.is_null() {
        return 0 as *mut libc::c_void;
    }
    key = xmlHashComputeKey(table, name, name2, name3);
    if (unsafe { (*((*table).table).offset(key as isize)).valid }) == 0 as i32 {
        return 0 as *mut libc::c_void;
    }
    if !(unsafe { (*table).dict }).is_null() {
        entry = (unsafe { &mut *((*table).table).offset(key as isize) }) as *mut _xmlHashEntry;
        while !entry.is_null() {
            if (unsafe { (*entry).name }) == name as *mut xmlChar
                && (unsafe { (*entry).name2 }) == name2 as *mut xmlChar
                && (unsafe { (*entry).name3 }) == name3 as *mut xmlChar
            {
                return unsafe { (*entry).payload };
            }
            entry = unsafe { (*entry).next };
        }
    }
    entry = (unsafe { &mut *((*table).table).offset(key as isize) }) as *mut _xmlHashEntry;
    while !entry.is_null() {
        if (unsafe { xmlStrEqual((*entry).name, name) }) != 0
            && (unsafe { xmlStrEqual((*entry).name2, name2) }) != 0
            && (unsafe { xmlStrEqual((*entry).name3, name3) }) != 0
        {
            return unsafe { (*entry).payload };
        }
        entry = unsafe { (*entry).next };
    }
    return 0 as *mut libc::c_void;
}
#[no_mangle]
pub extern "C" fn xmlHashQLookup3(
    mut table: xmlHashTablePtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
    mut prefix2: *const xmlChar,
    mut name2: *const xmlChar,
    mut prefix3: *const xmlChar,
    mut name3: *const xmlChar,
) -> *mut libc::c_void {
    let mut key: u64 = 0;
    let mut entry: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    if table.is_null() {
        return 0 as *mut libc::c_void;
    }
    if name.is_null() {
        return 0 as *mut libc::c_void;
    }
    key = xmlHashComputeQKey(table, prefix, name, prefix2, name2, prefix3, name3);
    if (unsafe { (*((*table).table).offset(key as isize)).valid }) == 0 as i32 {
        return 0 as *mut libc::c_void;
    }
    entry = (unsafe { &mut *((*table).table).offset(key as isize) }) as *mut _xmlHashEntry;
    while !entry.is_null() {
        if (unsafe { xmlStrQEqual(prefix, name, (*entry).name) }) != 0
            && (unsafe { xmlStrQEqual(prefix2, name2, (*entry).name2) }) != 0
            && (unsafe { xmlStrQEqual(prefix3, name3, (*entry).name3) }) != 0
        {
            return unsafe { (*entry).payload };
        }
        entry = unsafe { (*entry).next };
    }
    return 0 as *mut libc::c_void;
}
extern "C" fn stubHashScannerFull(
    mut payload: *mut libc::c_void,
    mut data: *mut libc::c_void,
    mut name: *const xmlChar,
    mut _name2: *const xmlChar,
    mut _name3: *const xmlChar,
) {
    let mut stubdata: *mut stubData = data as *mut stubData;
    (unsafe { ((*stubdata).hashscanner).expect("non-null function pointer")(
        payload,
        (*stubdata).data,
        name as *mut xmlChar,
    ) });
}
#[no_mangle]
pub extern "C" fn xmlHashScan(
    mut table: xmlHashTablePtr,
    mut f: xmlHashScanner,
    mut data: *mut libc::c_void,
) {
    let mut stubdata: stubData = stubData {
        hashscanner: None,
        data: 0 as *mut libc::c_void,
    };
    stubdata.data = data;
    stubdata.hashscanner = f;
    xmlHashScanFull(
        table,
        Some(
            stubHashScannerFull
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_void,
                    *const xmlChar,
                    *const xmlChar,
                    *const xmlChar,
                ) -> (),
        ),
        &mut stubdata as *mut stubData as *mut libc::c_void,
    );
}
#[no_mangle]
pub extern "C" fn xmlHashScanFull(
    mut table: xmlHashTablePtr,
    mut f: xmlHashScannerFull,
    mut data: *mut libc::c_void,
) {
    let mut i: i32 = 0;
    let mut nb: i32 = 0;
    let mut iter: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut next: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    if table.is_null() {
        return;
    }
    if f.is_none() {
        return;
    }
    if !(unsafe { (*table).table }).is_null() {
        i = 0 as i32;
        while i < (unsafe { (*table).size }) {
            if !((unsafe { (*((*table).table).offset(i as isize)).valid }) == 0 as i32) {
                iter = (unsafe { &mut *((*table).table).offset(i as isize) }) as *mut _xmlHashEntry;
                while !iter.is_null() {
                    next = unsafe { (*iter).next };
                    nb = unsafe { (*table).nbElems };
                    if f.is_some() && !(unsafe { (*iter).payload }).is_null() {
                        (unsafe { f.expect("non-null function pointer")(
                            (*iter).payload,
                            data,
                            (*iter).name,
                            (*iter).name2,
                            (*iter).name3,
                        ) });
                    }
                    if nb != (unsafe { (*table).nbElems }) {
                        if iter == (unsafe { &mut *((*table).table).offset(i as isize) }) as *mut _xmlHashEntry {
                            if (unsafe { (*((*table).table).offset(i as isize)).valid }) == 0 as i32 {
                                iter = 0 as xmlHashEntryPtr;
                            }
                            if (unsafe { (*((*table).table).offset(i as isize)).next }) != next {
                                iter =
                                    (unsafe { &mut *((*table).table).offset(i as isize) }) as *mut _xmlHashEntry;
                            }
                        } else {
                            iter = next;
                        }
                    } else {
                        iter = next;
                    }
                }
            }
            i += 1;
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlHashScan3(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
    mut f: xmlHashScanner,
    mut data: *mut libc::c_void,
) {
    let mut stubdata: stubData = stubData {
        hashscanner: None,
        data: 0 as *mut libc::c_void,
    };
    stubdata.data = data;
    stubdata.hashscanner = f;
    xmlHashScanFull3(
        table,
        name,
        name2,
        name3,
        Some(
            stubHashScannerFull
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_void,
                    *const xmlChar,
                    *const xmlChar,
                    *const xmlChar,
                ) -> (),
        ),
        &mut stubdata as *mut stubData as *mut libc::c_void,
    );
}
#[no_mangle]
pub extern "C" fn xmlHashScanFull3(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
    mut f: xmlHashScannerFull,
    mut data: *mut libc::c_void,
) {
    let mut i: i32 = 0;
    let mut iter: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut next: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    if table.is_null() {
        return;
    }
    if f.is_none() {
        return;
    }
    if !(unsafe { (*table).table }).is_null() {
        i = 0 as i32;
        while i < (unsafe { (*table).size }) {
            if !((unsafe { (*((*table).table).offset(i as isize)).valid }) == 0 as i32) {
                iter = (unsafe { &mut *((*table).table).offset(i as isize) }) as *mut _xmlHashEntry;
                while !iter.is_null() {
                    next = unsafe { (*iter).next };
                    if (name.is_null() || (unsafe { xmlStrEqual(name, (*iter).name) }) != 0)
                        && (name2.is_null() || (unsafe { xmlStrEqual(name2, (*iter).name2) }) != 0)
                        && (name3.is_null() || (unsafe { xmlStrEqual(name3, (*iter).name3) }) != 0)
                        && !(unsafe { (*iter).payload }).is_null()
                    {
                        (unsafe { f.expect("non-null function pointer")(
                            (*iter).payload,
                            data,
                            (*iter).name,
                            (*iter).name2,
                            (*iter).name3,
                        ) });
                    }
                    iter = next;
                }
            }
            i += 1;
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlHashCopy(mut table: xmlHashTablePtr, mut f: xmlHashCopier) -> xmlHashTablePtr {
    let mut i: i32 = 0;
    let mut iter: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut next: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut ret: xmlHashTablePtr = 0 as *mut xmlHashTable;
    if table.is_null() {
        return 0 as xmlHashTablePtr;
    }
    if f.is_none() {
        return 0 as xmlHashTablePtr;
    }
    ret = xmlHashCreate(unsafe { (*table).size });
    if ret.is_null() {
        return 0 as xmlHashTablePtr;
    }
    if !(unsafe { (*table).table }).is_null() {
        i = 0 as i32;
        while i < (unsafe { (*table).size }) {
            if !((unsafe { (*((*table).table).offset(i as isize)).valid }) == 0 as i32) {
                iter = (unsafe { &mut *((*table).table).offset(i as isize) }) as *mut _xmlHashEntry;
                while !iter.is_null() {
                    next = unsafe { (*iter).next };
                    xmlHashAddEntry3(
                        ret,
                        unsafe { (*iter).name },
                        unsafe { (*iter).name2 },
                        unsafe { (*iter).name3 },
                        unsafe { f.expect("non-null function pointer")((*iter).payload, (*iter).name) },
                    );
                    iter = next;
                }
            }
            i += 1;
        }
    }
    (unsafe { (*ret).nbElems = (*table).nbElems });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlHashSize(mut table: xmlHashTablePtr) -> i32 {
    if table.is_null() {
        return -(1 as i32);
    }
    return unsafe { (*table).nbElems };
}
#[no_mangle]
pub extern "C" fn xmlHashRemoveEntry(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut f: xmlHashDeallocator,
) -> i32 {
    return xmlHashRemoveEntry3(table, name, 0 as *const xmlChar, 0 as *const xmlChar, f);
}
#[no_mangle]
pub extern "C" fn xmlHashRemoveEntry2(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut f: xmlHashDeallocator,
) -> i32 {
    return xmlHashRemoveEntry3(table, name, name2, 0 as *const xmlChar, f);
}
#[no_mangle]
pub extern "C" fn xmlHashRemoveEntry3(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
    mut f: xmlHashDeallocator,
) -> i32 {
    let mut key: u64 = 0;
    let mut entry: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut prev: xmlHashEntryPtr = 0 as xmlHashEntryPtr;
    if table.is_null() || name.is_null() {
        return -(1 as i32);
    }
    key = xmlHashComputeKey(table, name, name2, name3);
    if (unsafe { (*((*table).table).offset(key as isize)).valid }) == 0 as i32 {
        return -(1 as i32);
    } else {
        entry = (unsafe { &mut *((*table).table).offset(key as isize) }) as *mut _xmlHashEntry;
        while !entry.is_null() {
            if (unsafe { xmlStrEqual((*entry).name, name) }) != 0
                && (unsafe { xmlStrEqual((*entry).name2, name2) }) != 0
                && (unsafe { xmlStrEqual((*entry).name3, name3) }) != 0
            {
                if f.is_some() && !(unsafe { (*entry).payload }).is_null() {
                    (unsafe { f.expect("non-null function pointer")((*entry).payload, (*entry).name) });
                }
                let fresh43 = unsafe { &mut ((*entry).payload) };
                *fresh43 = 0 as *mut libc::c_void;
                if (unsafe { (*table).dict }).is_null() {
                    if !(unsafe { (*entry).name }).is_null() {
                        (unsafe { xmlFree.expect("non-null function pointer")(
                            (*entry).name as *mut libc::c_void,
                        ) });
                    }
                    if !(unsafe { (*entry).name2 }).is_null() {
                        (unsafe { xmlFree.expect("non-null function pointer")(
                            (*entry).name2 as *mut libc::c_void,
                        ) });
                    }
                    if !(unsafe { (*entry).name3 }).is_null() {
                        (unsafe { xmlFree.expect("non-null function pointer")(
                            (*entry).name3 as *mut libc::c_void,
                        ) });
                    }
                }
                if !prev.is_null() {
                    let fresh44 = unsafe { &mut ((*prev).next) };
                    *fresh44 = unsafe { (*entry).next };
                    (unsafe { xmlFree.expect("non-null function pointer")(entry as *mut libc::c_void) });
                } else if (unsafe { (*entry).next }).is_null() {
                    (unsafe { (*entry).valid = 0 as i32 });
                } else {
                    entry = unsafe { (*entry).next };
                    (unsafe { memcpy(
                        &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry
                            as *mut libc::c_void,
                        entry as *const libc::c_void,
                        ::std::mem::size_of::<xmlHashEntry>() as u64,
                    ) });
                    (unsafe { xmlFree.expect("non-null function pointer")(entry as *mut libc::c_void) });
                }
                let fresh45 = unsafe { &mut ((*table).nbElems) };
                *fresh45 -= 1;
                return 0 as i32;
            }
            prev = entry;
            entry = unsafe { (*entry).next };
        }
        return -(1 as i32);
    };
}
