use :: libc;
extern "C" {
    pub type json_object;
    fn json_object_put(obj: *mut json_object) -> i32;
    fn json_object_is_type(obj: *const json_object, type_0: json_type) -> i32;
    fn json_object_object_add(obj: *mut json_object, key: *const i8, val: *mut json_object) -> i32;
    fn json_object_object_get_ex(
        obj: *const json_object,
        key: *const i8,
        value: *mut *mut json_object,
    ) -> json_bool;
    fn json_object_array_length(obj: *const json_object) -> size_t;
    fn json_object_array_add(obj: *mut json_object, val: *mut json_object) -> i32;
    fn json_object_array_put_idx(obj: *mut json_object, idx: size_t, val: *mut json_object) -> i32;
    fn json_object_array_get_idx(obj: *const json_object, idx: size_t) -> *mut json_object;
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn __errno_location() -> *mut i32;
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strrchr(_: *const i8, _: i32) -> *mut i8;
    fn strstr(_: *const i8, _: *const i8) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn strdup(_: *const i8) -> *mut i8;
    fn vasprintf(__ptr: *mut *mut i8, __f: *const i8, __arg: ::std::ffi::VaList) -> i32;
    fn strtol(_: *const i8, _: *mut *mut i8, _: i32) -> i64;
    fn free(__ptr: *mut libc::c_void);
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: u32,
    pub fp_offset: u32,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type json_bool = i32;
pub type json_type = u32;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
pub type size_t = u64;
pub type va_list = __builtin_va_list;
extern "C" fn string_replace_all_occurrences_with_char(
    mut s: *mut i8,
    mut occur: *const i8,
    mut repl_char: i8,
) {
    let mut slen: size_t = unsafe { strlen(s) };
    let mut skip: size_t = (unsafe { strlen(occur) }).wrapping_sub(1 as i32 as u64);
    let mut p: *mut i8 = s;
    loop {
        p = unsafe { strstr(p, occur) };
        if p.is_null() {
            break;
        }
        (unsafe { *p = repl_char });
        p = unsafe { p.offset(1) };
        slen = (slen as u64).wrapping_sub(skip) as size_t as size_t;
        (unsafe { memmove(
            p as *mut libc::c_void,
            p.offset(skip as isize) as *const libc::c_void,
            slen.wrapping_sub(p.offset_from(s) as i64 as u64)
                .wrapping_add(1 as i32 as u64),
        ) });
    }
}
extern "C" fn is_valid_index(
    mut jo: *mut json_object,
    mut path: *const i8,
    mut idx: *mut size_t,
) -> i32 {
    let mut i: size_t = 0;
    let mut len: size_t = unsafe { strlen(path) };
    let mut idx_val: i64 = -(1 as i32) as i64;
    if len == 1 as i32 as u64 {
        if (unsafe { *path.offset(0 as i32 as isize) }) as i32 >= '0' as i32
            && (unsafe { *path.offset(0 as i32 as isize) }) as i32 <= '9' as i32
        {
            (unsafe { *idx = (*path.offset(0 as i32 as isize) as i32 - '0' as i32) as size_t });
        } else {
            (unsafe { *__errno_location() = 22 as i32 });
            return 0 as i32;
        }
    } else {
        if (unsafe { *path.offset(0 as i32 as isize) }) as i32 == '0' as i32 {
            (unsafe { *__errno_location() = 22 as i32 });
            return 0 as i32;
        }
        i = 0 as i32 as size_t;
        while i < len {
            if !((unsafe { *path.offset(i as isize) }) as i32 >= '0' as i32
                && (unsafe { *path.offset(i as isize) }) as i32 <= '9' as i32)
            {
                (unsafe { *__errno_location() = 22 as i32 });
                return 0 as i32;
            }
            i = i.wrapping_add(1);
        }
        idx_val = unsafe { strtol(path, 0 as *mut *mut i8, 10 as i32) };
        if idx_val < 0 as i32 as i64 {
            (unsafe { *__errno_location() = 22 as i32 });
            return 0 as i32;
        }
        (unsafe { *idx = idx_val as size_t });
    }
    len = unsafe { json_object_array_length(jo) };
    if (unsafe { *idx }) >= len {
        (unsafe { *__errno_location() = 2 as i32 });
        return 0 as i32;
    }
    return 1 as i32;
}
extern "C" fn json_pointer_get_single_path(
    mut obj: *mut json_object,
    mut path: *mut i8,
    mut value: *mut *mut json_object,
) -> i32 {
    if (unsafe { json_object_is_type(obj, json_type_array) }) != 0 {
        let mut idx: size_t = 0;
        if is_valid_index(obj, path, &mut idx) == 0 {
            return -(1 as i32);
        }
        obj = unsafe { json_object_array_get_idx(obj, idx) };
        if !obj.is_null() {
            if !value.is_null() {
                (unsafe { *value = obj });
            }
            return 0 as i32;
        }
        (unsafe { *__errno_location() = 2 as i32 });
        return -(1 as i32);
    }
    string_replace_all_occurrences_with_char(
        path,
        b"~1\0" as *const u8 as *const i8,
        '/' as i32 as i8,
    );
    string_replace_all_occurrences_with_char(
        path,
        b"~0\0" as *const u8 as *const i8,
        '~' as i32 as i8,
    );
    if (unsafe { json_object_object_get_ex(obj, path, value) }) == 0 {
        (unsafe { *__errno_location() = 2 as i32 });
        return -(1 as i32);
    }
    return 0 as i32;
}
extern "C" fn json_pointer_set_single_path(
    mut parent: *mut json_object,
    mut path: *const i8,
    mut value: *mut json_object,
) -> i32 {
    if (unsafe { json_object_is_type(parent, json_type_array) }) != 0 {
        let mut idx: size_t = 0;
        if (unsafe { *path.offset(0 as i32 as isize) }) as i32 == '-' as i32
            && (unsafe { *path.offset(1 as i32 as isize) }) as i32 == '\u{0}' as i32
        {
            return unsafe { json_object_array_add(parent, value) };
        }
        if is_valid_index(parent, path, &mut idx) == 0 {
            return -(1 as i32);
        }
        return unsafe { json_object_array_put_idx(parent, idx, value) };
    }
    if (unsafe { json_object_is_type(parent, json_type_object) }) != 0 {
        return unsafe { json_object_object_add(parent, path, value) };
    }
    (unsafe { *__errno_location() = 2 as i32 });
    return -(1 as i32);
}
extern "C" fn json_pointer_get_recursive(
    mut obj: *mut json_object,
    mut path: *mut i8,
    mut value: *mut *mut json_object,
) -> i32 {
    let mut endp: *mut i8 = 0 as *mut i8;
    let mut rc: i32 = 0;
    if (unsafe { *path.offset(0 as i32 as isize) }) as i32 != '/' as i32 {
        (unsafe { *__errno_location() = 22 as i32 });
        return -(1 as i32);
    }
    path = unsafe { path.offset(1) };
    endp = unsafe { strchr(path, '/' as i32) };
    if !endp.is_null() {
        (unsafe { *endp = '\u{0}' as i32 as i8 });
    }
    rc = json_pointer_get_single_path(obj, path, &mut obj);
    if rc != 0 {
        return rc;
    }
    if !endp.is_null() {
        (unsafe { *endp = '/' as i32 as i8 });
        return json_pointer_get_recursive(obj, endp, value);
    }
    if !value.is_null() {
        (unsafe { *value = obj });
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn json_pointer_get(
    mut obj: *mut json_object,
    mut path: *const i8,
    mut res: *mut *mut json_object,
) -> i32 {
    let mut path_copy: *mut i8 = 0 as *mut i8;
    let mut rc: i32 = 0;
    if obj.is_null() || path.is_null() {
        (unsafe { *__errno_location() = 22 as i32 });
        return -(1 as i32);
    }
    if (unsafe { *path.offset(0 as i32 as isize) }) as i32 == '\u{0}' as i32 {
        if !res.is_null() {
            (unsafe { *res = obj });
        }
        return 0 as i32;
    }
    path_copy = unsafe { strdup(path) };
    if path_copy.is_null() {
        (unsafe { *__errno_location() = 12 as i32 });
        return -(1 as i32);
    }
    rc = json_pointer_get_recursive(obj, path_copy, res);
    (unsafe { free(path_copy as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn json_pointer_getf(
    mut obj: *mut json_object,
    mut res: *mut *mut json_object,
    mut path_fmt: *const i8,
    mut args: ...
) -> i32 {
    let mut path_copy: *mut i8 = 0 as *mut i8;
    let mut rc: i32 = 0 as i32;
    let mut args_0: ::std::ffi::VaListImpl;
    if obj.is_null() || path_fmt.is_null() {
        *__errno_location() = 22 as i32;
        return -(1 as i32);
    }
    args_0 = args.clone();
    rc = vasprintf(&mut path_copy, path_fmt, args_0.as_va_list());
    if rc < 0 as i32 {
        return rc;
    }
    if *path_copy.offset(0 as i32 as isize) as i32 == '\u{0}' as i32 {
        if !res.is_null() {
            *res = obj;
        }
    } else {
        rc = json_pointer_get_recursive(obj, path_copy, res);
    }
    free(path_copy as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub extern "C" fn json_pointer_set(
    mut obj: *mut *mut json_object,
    mut path: *const i8,
    mut value: *mut json_object,
) -> i32 {
    let mut endp: *const i8 = 0 as *const i8;
    let mut path_copy: *mut i8 = 0 as *mut i8;
    let mut set: *mut json_object = 0 as *mut json_object;
    let mut rc: i32 = 0;
    if obj.is_null() || path.is_null() {
        (unsafe { *__errno_location() = 22 as i32 });
        return -(1 as i32);
    }
    if (unsafe { *path.offset(0 as i32 as isize) }) as i32 == '\u{0}' as i32 {
        (unsafe { json_object_put(*obj) });
        (unsafe { *obj = value });
        return 0 as i32;
    }
    if (unsafe { *path.offset(0 as i32 as isize) }) as i32 != '/' as i32 {
        (unsafe { *__errno_location() = 22 as i32 });
        return -(1 as i32);
    }
    endp = unsafe { strrchr(path, '/' as i32) };
    if endp == path {
        path = unsafe { path.offset(1) };
        return json_pointer_set_single_path(unsafe { *obj }, path, value);
    }
    path_copy = unsafe { strdup(path) };
    if path_copy.is_null() {
        (unsafe { *__errno_location() = 12 as i32 });
        return -(1 as i32);
    }
    (unsafe { *path_copy.offset(endp.offset_from(path) as i64 as isize) = '\u{0}' as i32 as i8 });
    rc = json_pointer_get_recursive(unsafe { *obj }, path_copy, &mut set);
    (unsafe { free(path_copy as *mut libc::c_void) });
    if rc != 0 {
        return rc;
    }
    endp = unsafe { endp.offset(1) };
    return json_pointer_set_single_path(set, endp, value);
}
#[no_mangle]
pub unsafe extern "C" fn json_pointer_setf(
    mut obj: *mut *mut json_object,
    mut value: *mut json_object,
    mut path_fmt: *const i8,
    mut args: ...
) -> i32 {
    let mut current_block: u64;
    let mut endp: *mut i8 = 0 as *mut i8;
    let mut path_copy: *mut i8 = 0 as *mut i8;
    let mut set: *mut json_object = 0 as *mut json_object;
    let mut args_0: ::std::ffi::VaListImpl;
    let mut rc: i32 = 0 as i32;
    if obj.is_null() || path_fmt.is_null() {
        *__errno_location() = 22 as i32;
        return -(1 as i32);
    }
    args_0 = args.clone();
    rc = vasprintf(&mut path_copy, path_fmt, args_0.as_va_list());
    if rc < 0 as i32 {
        return rc;
    }
    if *path_copy.offset(0 as i32 as isize) as i32 == '\u{0}' as i32 {
        json_object_put(*obj);
        *obj = value;
    } else if *path_copy.offset(0 as i32 as isize) as i32 != '/' as i32 {
        *__errno_location() = 22 as i32;
        rc = -(1 as i32);
    } else {
        endp = strrchr(path_copy, '/' as i32);
        if endp == path_copy {
            set = *obj;
            current_block = 1863480813282067938;
        } else {
            *endp = '\u{0}' as i32 as i8;
            rc = json_pointer_get_recursive(*obj, path_copy, &mut set);
            if rc != 0 {
                current_block = 14315698657705028467;
            } else {
                current_block = 1863480813282067938;
            }
        }
        match current_block {
            14315698657705028467 => {}
            _ => {
                endp = endp.offset(1);
                rc = json_pointer_set_single_path(set, endp, value);
            }
        }
    }
    free(path_copy as *mut libc::c_void);
    return rc;
}
