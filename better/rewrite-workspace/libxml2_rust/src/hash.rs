use ::libc;
extern "C" {
    
    
    
    
    
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    
    
    
    
    static mut xmlFree: xmlFreeFunc;
    static mut xmlMalloc: xmlMallocFunc;
}
pub use crate::src::dict::__xmlRandom;
pub use crate::src::dict::xmlDictFree;
pub use crate::src::dict::xmlDictLookup;
pub use crate::src::dict::xmlDictOwns;
pub use crate::src::dict::xmlDictReference;
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrQEqual;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::dict::_xmlDict;
pub use crate::src::HTMLparser::xmlChar;
pub use crate::src::HTMLparser::size_t;
pub use crate::src::HTMLparser::xmlHashTablePtr;
pub use crate::src::HTMLparser::xmlHashTable;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlHashTable {
    pub table: *mut _xmlHashEntry,
    pub size: libc::c_int,
    pub nbElems: libc::c_int,
    pub dict: xmlDictPtr,
    pub random_seed: libc::c_int,
}
pub use crate::src::HTMLparser::xmlDictPtr;
pub use crate::src::HTMLparser::xmlDict;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlHashEntry {
    pub next: *mut _xmlHashEntry,
    pub name: *mut xmlChar,
    pub name2: *mut xmlChar,
    pub name3: *mut xmlChar,
    pub payload: *mut libc::c_void,
    pub valid: libc::c_int,
}
pub use crate::src::HTMLparser::xmlHashDeallocator;
pub use crate::src::entities::xmlHashCopier;
pub use crate::src::catalog::xmlHashScanner;
pub type xmlHashScannerFull = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub use crate::src::HTMLparser::xmlFreeFunc;
pub type xmlHashEntry = _xmlHashEntry;
pub use crate::src::HTMLparser::xmlMallocFunc;
pub type xmlHashEntryPtr = *mut xmlHashEntry;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stubData {
    pub hashscanner: xmlHashScanner,
    pub data: *mut libc::c_void,
}
unsafe extern "C" fn xmlHashComputeKey(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
) -> libc::c_ulong {
    let mut value: libc::c_ulong = 0 as libc::c_long as libc::c_ulong;
    let mut ch: libc::c_ulong = 0;
    value = (*table).random_seed as libc::c_ulong;
    if !name.is_null() {
        value = value
            .wrapping_add((30 as libc::c_int * *name as libc::c_int) as libc::c_ulong);
        loop {
            let fresh0 = name;
            name = name.offset(1);
            ch = *fresh0 as libc::c_ulong;
            if !(ch != 0 as libc::c_int as libc::c_ulong) {
                break;
            }
            value = value
                ^ (value << 5 as libc::c_int)
                    .wrapping_add(value >> 3 as libc::c_int)
                    .wrapping_add(ch);
        }
    }
    value = value ^ (value << 5 as libc::c_int).wrapping_add(value >> 3 as libc::c_int);
    if !name2.is_null() {
        loop {
            let fresh1 = name2;
            name2 = name2.offset(1);
            ch = *fresh1 as libc::c_ulong;
            if !(ch != 0 as libc::c_int as libc::c_ulong) {
                break;
            }
            value = value
                ^ (value << 5 as libc::c_int)
                    .wrapping_add(value >> 3 as libc::c_int)
                    .wrapping_add(ch);
        }
    }
    value = value ^ (value << 5 as libc::c_int).wrapping_add(value >> 3 as libc::c_int);
    if !name3.is_null() {
        loop {
            let fresh2 = name3;
            name3 = name3.offset(1);
            ch = *fresh2 as libc::c_ulong;
            if !(ch != 0 as libc::c_int as libc::c_ulong) {
                break;
            }
            value = value
                ^ (value << 5 as libc::c_int)
                    .wrapping_add(value >> 3 as libc::c_int)
                    .wrapping_add(ch);
        }
    }
    return value.wrapping_rem((*table).size as libc::c_ulong);
}
unsafe extern "C" fn xmlHashComputeQKey(
    mut table: xmlHashTablePtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
    mut prefix2: *const xmlChar,
    mut name2: *const xmlChar,
    mut prefix3: *const xmlChar,
    mut name3: *const xmlChar,
) -> libc::c_ulong {
    let mut value: libc::c_ulong = 0 as libc::c_long as libc::c_ulong;
    let mut ch: libc::c_ulong = 0;
    value = (*table).random_seed as libc::c_ulong;
    if !prefix.is_null() {
        value = value
            .wrapping_add((30 as libc::c_int * *prefix as libc::c_int) as libc::c_ulong);
    } else {
        value = value
            .wrapping_add((30 as libc::c_int * *name as libc::c_int) as libc::c_ulong);
    }
    if !prefix.is_null() {
        loop {
            let fresh3 = prefix;
            prefix = prefix.offset(1);
            ch = *fresh3 as libc::c_ulong;
            if !(ch != 0 as libc::c_int as libc::c_ulong) {
                break;
            }
            value = value
                ^ (value << 5 as libc::c_int)
                    .wrapping_add(value >> 3 as libc::c_int)
                    .wrapping_add(ch);
        }
        value = value
            ^ (value << 5 as libc::c_int)
                .wrapping_add(value >> 3 as libc::c_int)
                .wrapping_add(':' as i32 as libc::c_ulong);
    }
    if !name.is_null() {
        loop {
            let fresh4 = name;
            name = name.offset(1);
            ch = *fresh4 as libc::c_ulong;
            if !(ch != 0 as libc::c_int as libc::c_ulong) {
                break;
            }
            value = value
                ^ (value << 5 as libc::c_int)
                    .wrapping_add(value >> 3 as libc::c_int)
                    .wrapping_add(ch);
        }
    }
    value = value ^ (value << 5 as libc::c_int).wrapping_add(value >> 3 as libc::c_int);
    if !prefix2.is_null() {
        loop {
            let fresh5 = prefix2;
            prefix2 = prefix2.offset(1);
            ch = *fresh5 as libc::c_ulong;
            if !(ch != 0 as libc::c_int as libc::c_ulong) {
                break;
            }
            value = value
                ^ (value << 5 as libc::c_int)
                    .wrapping_add(value >> 3 as libc::c_int)
                    .wrapping_add(ch);
        }
        value = value
            ^ (value << 5 as libc::c_int)
                .wrapping_add(value >> 3 as libc::c_int)
                .wrapping_add(':' as i32 as libc::c_ulong);
    }
    if !name2.is_null() {
        loop {
            let fresh6 = name2;
            name2 = name2.offset(1);
            ch = *fresh6 as libc::c_ulong;
            if !(ch != 0 as libc::c_int as libc::c_ulong) {
                break;
            }
            value = value
                ^ (value << 5 as libc::c_int)
                    .wrapping_add(value >> 3 as libc::c_int)
                    .wrapping_add(ch);
        }
    }
    value = value ^ (value << 5 as libc::c_int).wrapping_add(value >> 3 as libc::c_int);
    if !prefix3.is_null() {
        loop {
            let fresh7 = prefix3;
            prefix3 = prefix3.offset(1);
            ch = *fresh7 as libc::c_ulong;
            if !(ch != 0 as libc::c_int as libc::c_ulong) {
                break;
            }
            value = value
                ^ (value << 5 as libc::c_int)
                    .wrapping_add(value >> 3 as libc::c_int)
                    .wrapping_add(ch);
        }
        value = value
            ^ (value << 5 as libc::c_int)
                .wrapping_add(value >> 3 as libc::c_int)
                .wrapping_add(':' as i32 as libc::c_ulong);
    }
    if !name3.is_null() {
        loop {
            let fresh8 = name3;
            name3 = name3.offset(1);
            ch = *fresh8 as libc::c_ulong;
            if !(ch != 0 as libc::c_int as libc::c_ulong) {
                break;
            }
            value = value
                ^ (value << 5 as libc::c_int)
                    .wrapping_add(value >> 3 as libc::c_int)
                    .wrapping_add(ch);
        }
    }
    return value.wrapping_rem((*table).size as libc::c_ulong);
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashCreate(mut size: libc::c_int) -> xmlHashTablePtr {
    let mut table: xmlHashTablePtr = 0 as *mut xmlHashTable;
    if size <= 0 as libc::c_int {
        size = 256 as libc::c_int;
    }
    table = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlHashTable>() as libc::c_ulong) as xmlHashTablePtr;
    if !table.is_null() {
        let ref mut fresh9 = (*table).dict;
        *fresh9 = 0 as xmlDictPtr;
        (*table).size = size;
        (*table).nbElems = 0 as libc::c_int;
        let ref mut fresh10 = (*table).table;
        *fresh10 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            (size as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlHashEntry>() as libc::c_ulong),
        ) as *mut _xmlHashEntry;
        if !((*table).table).is_null() {
            memset(
                (*table).table as *mut libc::c_void,
                0 as libc::c_int,
                (size as libc::c_ulong)
                    .wrapping_mul(::std::mem::size_of::<xmlHashEntry>() as libc::c_ulong),
            );
            (*table).random_seed = __xmlRandom();
            return table;
        }
        xmlFree.expect("non-null function pointer")(table as *mut libc::c_void);
    }
    return 0 as xmlHashTablePtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashCreateDict(
    mut size: libc::c_int,
    mut dict: xmlDictPtr,
) -> xmlHashTablePtr {
    let mut table: xmlHashTablePtr = 0 as *mut xmlHashTable;
    table = xmlHashCreate(size);
    if !table.is_null() {
        let ref mut fresh11 = (*table).dict;
        *fresh11 = dict;
        xmlDictReference(dict);
    }
    return table;
}
unsafe extern "C" fn xmlHashGrow(
    mut table: xmlHashTablePtr,
    mut size: libc::c_int,
) -> libc::c_int {
    let mut key: libc::c_ulong = 0;
    let mut oldsize: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut iter: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut next: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut oldtable: *mut _xmlHashEntry = 0 as *mut _xmlHashEntry;
    if table.is_null() {
        return -(1 as libc::c_int);
    }
    if size < 8 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if size > 8 as libc::c_int * 2048 as libc::c_int {
        return -(1 as libc::c_int);
    }
    oldsize = (*table).size;
    oldtable = (*table).table;
    if oldtable.is_null() {
        return -(1 as libc::c_int);
    }
    let ref mut fresh12 = (*table).table;
    *fresh12 = xmlMalloc
        .expect(
            "non-null function pointer",
        )(
        (size as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlHashEntry>() as libc::c_ulong),
    ) as *mut _xmlHashEntry;
    if ((*table).table).is_null() {
        let ref mut fresh13 = (*table).table;
        *fresh13 = oldtable;
        return -(1 as libc::c_int);
    }
    memset(
        (*table).table as *mut libc::c_void,
        0 as libc::c_int,
        (size as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlHashEntry>() as libc::c_ulong),
    );
    (*table).size = size;
    i = 0 as libc::c_int;
    while i < oldsize {
        if !((*oldtable.offset(i as isize)).valid == 0 as libc::c_int) {
            key = xmlHashComputeKey(
                table,
                (*oldtable.offset(i as isize)).name,
                (*oldtable.offset(i as isize)).name2,
                (*oldtable.offset(i as isize)).name3,
            );
            memcpy(
                &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry
                    as *mut libc::c_void,
                &mut *oldtable.offset(i as isize) as *mut _xmlHashEntry
                    as *const libc::c_void,
                ::std::mem::size_of::<xmlHashEntry>() as libc::c_ulong,
            );
            let ref mut fresh14 = (*((*table).table).offset(key as isize)).next;
            *fresh14 = 0 as *mut _xmlHashEntry;
        }
        i += 1;
    }
    i = 0 as libc::c_int;
    while i < oldsize {
        iter = (*oldtable.offset(i as isize)).next;
        while !iter.is_null() {
            next = (*iter).next;
            key = xmlHashComputeKey(table, (*iter).name, (*iter).name2, (*iter).name3);
            if (*((*table).table).offset(key as isize)).valid == 0 as libc::c_int {
                memcpy(
                    &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry
                        as *mut libc::c_void,
                    iter as *const libc::c_void,
                    ::std::mem::size_of::<xmlHashEntry>() as libc::c_ulong,
                );
                let ref mut fresh15 = (*((*table).table).offset(key as isize)).next;
                *fresh15 = 0 as *mut _xmlHashEntry;
                xmlFree.expect("non-null function pointer")(iter as *mut libc::c_void);
            } else {
                let ref mut fresh16 = (*iter).next;
                *fresh16 = (*((*table).table).offset(key as isize)).next;
                let ref mut fresh17 = (*((*table).table).offset(key as isize)).next;
                *fresh17 = iter;
            }
            iter = next;
        }
        i += 1;
    }
    xmlFree.expect("non-null function pointer")(oldtable as *mut libc::c_void);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashFree(
    mut table: xmlHashTablePtr,
    mut f: xmlHashDeallocator,
) {
    let mut i: libc::c_int = 0;
    let mut iter: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut next: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut inside_table: libc::c_int = 0 as libc::c_int;
    let mut nbElems: libc::c_int = 0;
    if table.is_null() {
        return;
    }
    if !((*table).table).is_null() {
        nbElems = (*table).nbElems;
        i = 0 as libc::c_int;
        while i < (*table).size && nbElems > 0 as libc::c_int {
            iter = &mut *((*table).table).offset(i as isize) as *mut _xmlHashEntry;
            if !((*iter).valid == 0 as libc::c_int) {
                inside_table = 1 as libc::c_int;
                while !iter.is_null() {
                    next = (*iter).next;
                    if f.is_some() && !((*iter).payload).is_null() {
                        f
                            .expect(
                                "non-null function pointer",
                            )((*iter).payload, (*iter).name);
                    }
                    if ((*table).dict).is_null() {
                        if !((*iter).name).is_null() {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )((*iter).name as *mut libc::c_void);
                        }
                        if !((*iter).name2).is_null() {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )((*iter).name2 as *mut libc::c_void);
                        }
                        if !((*iter).name3).is_null() {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )((*iter).name3 as *mut libc::c_void);
                        }
                    }
                    let ref mut fresh18 = (*iter).payload;
                    *fresh18 = 0 as *mut libc::c_void;
                    if inside_table == 0 {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(iter as *mut libc::c_void);
                    }
                    nbElems -= 1;
                    inside_table = 0 as libc::c_int;
                    iter = next;
                }
            }
            i += 1;
        }
        xmlFree.expect("non-null function pointer")((*table).table as *mut libc::c_void);
    }
    if !((*table).dict).is_null() {
        xmlDictFree((*table).dict);
    }
    xmlFree.expect("non-null function pointer")(table as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashDefaultDeallocator(
    mut entry: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    xmlFree.expect("non-null function pointer")(entry);
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashAddEntry(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut userdata: *mut libc::c_void,
) -> libc::c_int {
    return xmlHashAddEntry3(
        table,
        name,
        0 as *const xmlChar,
        0 as *const xmlChar,
        userdata,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashAddEntry2(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut userdata: *mut libc::c_void,
) -> libc::c_int {
    return xmlHashAddEntry3(table, name, name2, 0 as *const xmlChar, userdata);
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashUpdateEntry(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut userdata: *mut libc::c_void,
    mut f: xmlHashDeallocator,
) -> libc::c_int {
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
pub unsafe extern "C" fn xmlHashUpdateEntry2(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut userdata: *mut libc::c_void,
    mut f: xmlHashDeallocator,
) -> libc::c_int {
    return xmlHashUpdateEntry3(table, name, name2, 0 as *const xmlChar, userdata, f);
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashLookup(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
) -> *mut libc::c_void {
    return xmlHashLookup3(table, name, 0 as *const xmlChar, 0 as *const xmlChar);
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashLookup2(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
) -> *mut libc::c_void {
    return xmlHashLookup3(table, name, name2, 0 as *const xmlChar);
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashQLookup(
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
pub unsafe extern "C" fn xmlHashQLookup2(
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
pub unsafe extern "C" fn xmlHashAddEntry3(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
    mut userdata: *mut libc::c_void,
) -> libc::c_int {
    let mut key: libc::c_ulong = 0;
    let mut len: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
    let mut entry: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut insert: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    if table.is_null() || name.is_null() {
        return -(1 as libc::c_int);
    }
    if !((*table).dict).is_null() {
        if xmlDictOwns((*table).dict, name) == 0 {
            name = xmlDictLookup((*table).dict, name, -(1 as libc::c_int));
            if name.is_null() {
                return -(1 as libc::c_int);
            }
        }
        if !name2.is_null() && xmlDictOwns((*table).dict, name2) == 0 {
            name2 = xmlDictLookup((*table).dict, name2, -(1 as libc::c_int));
            if name2.is_null() {
                return -(1 as libc::c_int);
            }
        }
        if !name3.is_null() && xmlDictOwns((*table).dict, name3) == 0 {
            name3 = xmlDictLookup((*table).dict, name3, -(1 as libc::c_int));
            if name3.is_null() {
                return -(1 as libc::c_int);
            }
        }
    }
    key = xmlHashComputeKey(table, name, name2, name3);
    if (*((*table).table).offset(key as isize)).valid == 0 as libc::c_int {
        insert = 0 as xmlHashEntryPtr;
    } else if !((*table).dict).is_null() {
        insert = &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry;
        while !((*insert).next).is_null() {
            if (*insert).name == name as *mut xmlChar
                && (*insert).name2 == name2 as *mut xmlChar
                && (*insert).name3 == name3 as *mut xmlChar
            {
                return -(1 as libc::c_int);
            }
            len = len.wrapping_add(1);
            insert = (*insert).next;
        }
        if (*insert).name == name as *mut xmlChar
            && (*insert).name2 == name2 as *mut xmlChar
            && (*insert).name3 == name3 as *mut xmlChar
        {
            return -(1 as libc::c_int);
        }
    } else {
        insert = &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry;
        while !((*insert).next).is_null() {
            if xmlStrEqual((*insert).name, name) != 0
                && xmlStrEqual((*insert).name2, name2) != 0
                && xmlStrEqual((*insert).name3, name3) != 0
            {
                return -(1 as libc::c_int);
            }
            len = len.wrapping_add(1);
            insert = (*insert).next;
        }
        if xmlStrEqual((*insert).name, name) != 0
            && xmlStrEqual((*insert).name2, name2) != 0
            && xmlStrEqual((*insert).name3, name3) != 0
        {
            return -(1 as libc::c_int);
        }
    }
    if insert.is_null() {
        entry = &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry;
    } else {
        entry = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlHashEntry>() as libc::c_ulong) as xmlHashEntryPtr;
        if entry.is_null() {
            return -(1 as libc::c_int);
        }
    }
    if !((*table).dict).is_null() {
        let ref mut fresh19 = (*entry).name;
        *fresh19 = name as *mut xmlChar;
        let ref mut fresh20 = (*entry).name2;
        *fresh20 = name2 as *mut xmlChar;
        let ref mut fresh21 = (*entry).name3;
        *fresh21 = name3 as *mut xmlChar;
    } else {
        let ref mut fresh22 = (*entry).name;
        *fresh22 = xmlStrdup(name);
        let ref mut fresh23 = (*entry).name2;
        *fresh23 = xmlStrdup(name2);
        let ref mut fresh24 = (*entry).name3;
        *fresh24 = xmlStrdup(name3);
    }
    let ref mut fresh25 = (*entry).payload;
    *fresh25 = userdata;
    let ref mut fresh26 = (*entry).next;
    *fresh26 = 0 as *mut _xmlHashEntry;
    (*entry).valid = 1 as libc::c_int;
    if !insert.is_null() {
        let ref mut fresh27 = (*insert).next;
        *fresh27 = entry;
    }
    let ref mut fresh28 = (*table).nbElems;
    *fresh28 += 1;
    if len > 8 as libc::c_int as libc::c_ulong {
        xmlHashGrow(table, 8 as libc::c_int * (*table).size);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashUpdateEntry3(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
    mut userdata: *mut libc::c_void,
    mut f: xmlHashDeallocator,
) -> libc::c_int {
    let mut key: libc::c_ulong = 0;
    let mut entry: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut insert: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    if table.is_null() || name.is_null() {
        return -(1 as libc::c_int);
    }
    if !((*table).dict).is_null() {
        if xmlDictOwns((*table).dict, name) == 0 {
            name = xmlDictLookup((*table).dict, name, -(1 as libc::c_int));
            if name.is_null() {
                return -(1 as libc::c_int);
            }
        }
        if !name2.is_null() && xmlDictOwns((*table).dict, name2) == 0 {
            name2 = xmlDictLookup((*table).dict, name2, -(1 as libc::c_int));
            if name2.is_null() {
                return -(1 as libc::c_int);
            }
        }
        if !name3.is_null() && xmlDictOwns((*table).dict, name3) == 0 {
            name3 = xmlDictLookup((*table).dict, name3, -(1 as libc::c_int));
            if name3.is_null() {
                return -(1 as libc::c_int);
            }
        }
    }
    key = xmlHashComputeKey(table, name, name2, name3);
    if (*((*table).table).offset(key as isize)).valid == 0 as libc::c_int {
        insert = 0 as xmlHashEntryPtr;
    } else if !((*table).dict).is_null() {
        insert = &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry;
        while !((*insert).next).is_null() {
            if (*insert).name == name as *mut xmlChar
                && (*insert).name2 == name2 as *mut xmlChar
                && (*insert).name3 == name3 as *mut xmlChar
            {
                if f.is_some() {
                    f
                        .expect(
                            "non-null function pointer",
                        )((*insert).payload, (*insert).name);
                }
                let ref mut fresh29 = (*insert).payload;
                *fresh29 = userdata;
                return 0 as libc::c_int;
            }
            insert = (*insert).next;
        }
        if (*insert).name == name as *mut xmlChar
            && (*insert).name2 == name2 as *mut xmlChar
            && (*insert).name3 == name3 as *mut xmlChar
        {
            if f.is_some() {
                f.expect("non-null function pointer")((*insert).payload, (*insert).name);
            }
            let ref mut fresh30 = (*insert).payload;
            *fresh30 = userdata;
            return 0 as libc::c_int;
        }
    } else {
        insert = &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry;
        while !((*insert).next).is_null() {
            if xmlStrEqual((*insert).name, name) != 0
                && xmlStrEqual((*insert).name2, name2) != 0
                && xmlStrEqual((*insert).name3, name3) != 0
            {
                if f.is_some() {
                    f
                        .expect(
                            "non-null function pointer",
                        )((*insert).payload, (*insert).name);
                }
                let ref mut fresh31 = (*insert).payload;
                *fresh31 = userdata;
                return 0 as libc::c_int;
            }
            insert = (*insert).next;
        }
        if xmlStrEqual((*insert).name, name) != 0
            && xmlStrEqual((*insert).name2, name2) != 0
            && xmlStrEqual((*insert).name3, name3) != 0
        {
            if f.is_some() {
                f.expect("non-null function pointer")((*insert).payload, (*insert).name);
            }
            let ref mut fresh32 = (*insert).payload;
            *fresh32 = userdata;
            return 0 as libc::c_int;
        }
    }
    if insert.is_null() {
        entry = &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry;
    } else {
        entry = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlHashEntry>() as libc::c_ulong) as xmlHashEntryPtr;
        if entry.is_null() {
            return -(1 as libc::c_int);
        }
    }
    if !((*table).dict).is_null() {
        let ref mut fresh33 = (*entry).name;
        *fresh33 = name as *mut xmlChar;
        let ref mut fresh34 = (*entry).name2;
        *fresh34 = name2 as *mut xmlChar;
        let ref mut fresh35 = (*entry).name3;
        *fresh35 = name3 as *mut xmlChar;
    } else {
        let ref mut fresh36 = (*entry).name;
        *fresh36 = xmlStrdup(name);
        let ref mut fresh37 = (*entry).name2;
        *fresh37 = xmlStrdup(name2);
        let ref mut fresh38 = (*entry).name3;
        *fresh38 = xmlStrdup(name3);
    }
    let ref mut fresh39 = (*entry).payload;
    *fresh39 = userdata;
    let ref mut fresh40 = (*entry).next;
    *fresh40 = 0 as *mut _xmlHashEntry;
    (*entry).valid = 1 as libc::c_int;
    let ref mut fresh41 = (*table).nbElems;
    *fresh41 += 1;
    if !insert.is_null() {
        let ref mut fresh42 = (*insert).next;
        *fresh42 = entry;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashLookup3(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
) -> *mut libc::c_void {
    let mut key: libc::c_ulong = 0;
    let mut entry: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    if table.is_null() {
        return 0 as *mut libc::c_void;
    }
    if name.is_null() {
        return 0 as *mut libc::c_void;
    }
    key = xmlHashComputeKey(table, name, name2, name3);
    if (*((*table).table).offset(key as isize)).valid == 0 as libc::c_int {
        return 0 as *mut libc::c_void;
    }
    if !((*table).dict).is_null() {
        entry = &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry;
        while !entry.is_null() {
            if (*entry).name == name as *mut xmlChar
                && (*entry).name2 == name2 as *mut xmlChar
                && (*entry).name3 == name3 as *mut xmlChar
            {
                return (*entry).payload;
            }
            entry = (*entry).next;
        }
    }
    entry = &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry;
    while !entry.is_null() {
        if xmlStrEqual((*entry).name, name) != 0
            && xmlStrEqual((*entry).name2, name2) != 0
            && xmlStrEqual((*entry).name3, name3) != 0
        {
            return (*entry).payload;
        }
        entry = (*entry).next;
    }
    return 0 as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashQLookup3(
    mut table: xmlHashTablePtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
    mut prefix2: *const xmlChar,
    mut name2: *const xmlChar,
    mut prefix3: *const xmlChar,
    mut name3: *const xmlChar,
) -> *mut libc::c_void {
    let mut key: libc::c_ulong = 0;
    let mut entry: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    if table.is_null() {
        return 0 as *mut libc::c_void;
    }
    if name.is_null() {
        return 0 as *mut libc::c_void;
    }
    key = xmlHashComputeQKey(table, prefix, name, prefix2, name2, prefix3, name3);
    if (*((*table).table).offset(key as isize)).valid == 0 as libc::c_int {
        return 0 as *mut libc::c_void;
    }
    entry = &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry;
    while !entry.is_null() {
        if xmlStrQEqual(prefix, name, (*entry).name) != 0
            && xmlStrQEqual(prefix2, name2, (*entry).name2) != 0
            && xmlStrQEqual(prefix3, name3, (*entry).name3) != 0
        {
            return (*entry).payload;
        }
        entry = (*entry).next;
    }
    return 0 as *mut libc::c_void;
}
unsafe extern "C" fn stubHashScannerFull(
    mut payload: *mut libc::c_void,
    mut data: *mut libc::c_void,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
) {
    let mut stubdata: *mut stubData = data as *mut stubData;
    ((*stubdata).hashscanner)
        .expect(
            "non-null function pointer",
        )(payload, (*stubdata).data, name as *mut xmlChar);
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashScan(
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
pub unsafe extern "C" fn xmlHashScanFull(
    mut table: xmlHashTablePtr,
    mut f: xmlHashScannerFull,
    mut data: *mut libc::c_void,
) {
    let mut i: libc::c_int = 0;
    let mut nb: libc::c_int = 0;
    let mut iter: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut next: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    if table.is_null() {
        return;
    }
    if f.is_none() {
        return;
    }
    if !((*table).table).is_null() {
        i = 0 as libc::c_int;
        while i < (*table).size {
            if !((*((*table).table).offset(i as isize)).valid == 0 as libc::c_int) {
                iter = &mut *((*table).table).offset(i as isize) as *mut _xmlHashEntry;
                while !iter.is_null() {
                    next = (*iter).next;
                    nb = (*table).nbElems;
                    if f.is_some() && !((*iter).payload).is_null() {
                        f
                            .expect(
                                "non-null function pointer",
                            )(
                            (*iter).payload,
                            data,
                            (*iter).name,
                            (*iter).name2,
                            (*iter).name3,
                        );
                    }
                    if nb != (*table).nbElems {
                        if iter
                            == &mut *((*table).table).offset(i as isize)
                                as *mut _xmlHashEntry
                        {
                            if (*((*table).table).offset(i as isize)).valid
                                == 0 as libc::c_int
                            {
                                iter = 0 as xmlHashEntryPtr;
                            }
                            if (*((*table).table).offset(i as isize)).next != next {
                                iter = &mut *((*table).table).offset(i as isize)
                                    as *mut _xmlHashEntry;
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
pub unsafe extern "C" fn xmlHashScan3(
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
pub unsafe extern "C" fn xmlHashScanFull3(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
    mut f: xmlHashScannerFull,
    mut data: *mut libc::c_void,
) {
    let mut i: libc::c_int = 0;
    let mut iter: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut next: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    if table.is_null() {
        return;
    }
    if f.is_none() {
        return;
    }
    if !((*table).table).is_null() {
        i = 0 as libc::c_int;
        while i < (*table).size {
            if !((*((*table).table).offset(i as isize)).valid == 0 as libc::c_int) {
                iter = &mut *((*table).table).offset(i as isize) as *mut _xmlHashEntry;
                while !iter.is_null() {
                    next = (*iter).next;
                    if (name.is_null() || xmlStrEqual(name, (*iter).name) != 0)
                        && (name2.is_null() || xmlStrEqual(name2, (*iter).name2) != 0)
                        && (name3.is_null() || xmlStrEqual(name3, (*iter).name3) != 0)
                        && !((*iter).payload).is_null()
                    {
                        f
                            .expect(
                                "non-null function pointer",
                            )(
                            (*iter).payload,
                            data,
                            (*iter).name,
                            (*iter).name2,
                            (*iter).name3,
                        );
                    }
                    iter = next;
                }
            }
            i += 1;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashCopy(
    mut table: xmlHashTablePtr,
    mut f: xmlHashCopier,
) -> xmlHashTablePtr {
    let mut i: libc::c_int = 0;
    let mut iter: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut next: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut ret: xmlHashTablePtr = 0 as *mut xmlHashTable;
    if table.is_null() {
        return 0 as xmlHashTablePtr;
    }
    if f.is_none() {
        return 0 as xmlHashTablePtr;
    }
    ret = xmlHashCreate((*table).size);
    if ret.is_null() {
        return 0 as xmlHashTablePtr;
    }
    if !((*table).table).is_null() {
        i = 0 as libc::c_int;
        while i < (*table).size {
            if !((*((*table).table).offset(i as isize)).valid == 0 as libc::c_int) {
                iter = &mut *((*table).table).offset(i as isize) as *mut _xmlHashEntry;
                while !iter.is_null() {
                    next = (*iter).next;
                    xmlHashAddEntry3(
                        ret,
                        (*iter).name,
                        (*iter).name2,
                        (*iter).name3,
                        f
                            .expect(
                                "non-null function pointer",
                            )((*iter).payload, (*iter).name),
                    );
                    iter = next;
                }
            }
            i += 1;
        }
    }
    (*ret).nbElems = (*table).nbElems;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashSize(mut table: xmlHashTablePtr) -> libc::c_int {
    if table.is_null() {
        return -(1 as libc::c_int);
    }
    return (*table).nbElems;
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashRemoveEntry(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut f: xmlHashDeallocator,
) -> libc::c_int {
    return xmlHashRemoveEntry3(table, name, 0 as *const xmlChar, 0 as *const xmlChar, f);
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashRemoveEntry2(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut f: xmlHashDeallocator,
) -> libc::c_int {
    return xmlHashRemoveEntry3(table, name, name2, 0 as *const xmlChar, f);
}
#[no_mangle]
pub unsafe extern "C" fn xmlHashRemoveEntry3(
    mut table: xmlHashTablePtr,
    mut name: *const xmlChar,
    mut name2: *const xmlChar,
    mut name3: *const xmlChar,
    mut f: xmlHashDeallocator,
) -> libc::c_int {
    let mut key: libc::c_ulong = 0;
    let mut entry: xmlHashEntryPtr = 0 as *mut xmlHashEntry;
    let mut prev: xmlHashEntryPtr = 0 as xmlHashEntryPtr;
    if table.is_null() || name.is_null() {
        return -(1 as libc::c_int);
    }
    key = xmlHashComputeKey(table, name, name2, name3);
    if (*((*table).table).offset(key as isize)).valid == 0 as libc::c_int {
        return -(1 as libc::c_int)
    } else {
        entry = &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry;
        while !entry.is_null() {
            if xmlStrEqual((*entry).name, name) != 0
                && xmlStrEqual((*entry).name2, name2) != 0
                && xmlStrEqual((*entry).name3, name3) != 0
            {
                if f.is_some() && !((*entry).payload).is_null() {
                    f
                        .expect(
                            "non-null function pointer",
                        )((*entry).payload, (*entry).name);
                }
                let ref mut fresh43 = (*entry).payload;
                *fresh43 = 0 as *mut libc::c_void;
                if ((*table).dict).is_null() {
                    if !((*entry).name).is_null() {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )((*entry).name as *mut libc::c_void);
                    }
                    if !((*entry).name2).is_null() {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )((*entry).name2 as *mut libc::c_void);
                    }
                    if !((*entry).name3).is_null() {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )((*entry).name3 as *mut libc::c_void);
                    }
                }
                if !prev.is_null() {
                    let ref mut fresh44 = (*prev).next;
                    *fresh44 = (*entry).next;
                    xmlFree
                        .expect("non-null function pointer")(entry as *mut libc::c_void);
                } else if ((*entry).next).is_null() {
                    (*entry).valid = 0 as libc::c_int;
                } else {
                    entry = (*entry).next;
                    memcpy(
                        &mut *((*table).table).offset(key as isize) as *mut _xmlHashEntry
                            as *mut libc::c_void,
                        entry as *const libc::c_void,
                        ::std::mem::size_of::<xmlHashEntry>() as libc::c_ulong,
                    );
                    xmlFree
                        .expect("non-null function pointer")(entry as *mut libc::c_void);
                }
                let ref mut fresh45 = (*table).nbElems;
                *fresh45 -= 1;
                return 0 as libc::c_int;
            }
            prev = entry;
            entry = (*entry).next;
        }
        return -(1 as libc::c_int);
    };
}
