use ::libc;
extern "C" {
    pub type __locale_data;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn __errno_location() -> *mut libc::c_int;
    fn strtod(_: *const libc::c_char, _: *mut *mut libc::c_char) -> libc::c_double;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strncasecmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn newlocale(
        __category_mask: libc::c_int,
        __locale: *const libc::c_char,
        __base: locale_t,
    ) -> locale_t;
    fn freelocale(__dataset: locale_t);
    fn duplocale(__dataset: locale_t) -> locale_t;
    fn uselocale(__dataset: locale_t) -> locale_t;
}
pub use crate::debug::mc_debug;
pub use crate::json_object::json_object_array_add;
pub use crate::json_object::json_object_array_shrink;
pub use crate::json_object::json_object_get;
pub use crate::json_object::json_object_new_array;
pub use crate::json_object::json_object_new_boolean;
pub use crate::json_object::json_object_new_double;
pub use crate::json_object::json_object_new_double_s;
pub use crate::json_object::json_object_new_int64;
pub use crate::json_object::json_object_new_object;
pub use crate::json_object::json_object_new_string_len;
pub use crate::json_object::json_object_new_uint64;
pub use crate::json_object::json_object_object_add;
pub use crate::json_object::json_object_put;
pub use crate::json_util::json_parse_int64;
pub use crate::json_util::json_parse_uint64;
pub use crate::printbuf::printbuf_free;
pub use crate::printbuf::printbuf_memappend;
pub use crate::printbuf::printbuf_new;
pub use crate::printbuf::printbuf_reset;
pub use crate::json_object::__uint32_t;
pub use crate::json_object::__int64_t;
pub use crate::json_object::__uint64_t;
pub use crate::apps::json_parse::size_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __locale_struct {
    pub __locales: [*mut __locale_data; 13],
    pub __ctype_b: *const libc::c_ushort,
    pub __ctype_tolower: *const libc::c_int,
    pub __ctype_toupper: *const libc::c_int,
    pub __names: [*const libc::c_char; 13],
}
pub type __locale_t = *mut __locale_struct;
pub type locale_t = __locale_t;
pub use crate::json_object::int64_t;
pub use crate::json_object::uint32_t;
pub use crate::json_object::uint64_t;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::printbuf;
// #[derive(Copy, Clone)]

pub use crate::json_object::json_object;
pub use crate::json_object::json_object_delete_fn;
pub use crate::json_object::json_object_to_json_string_fn;
pub use crate::json_object::json_type;
pub const json_type_string: json_type = 6;
pub const json_type_array: json_type = 5;
pub const json_type_object: json_type = 4;
pub const json_type_int: json_type = 3;
pub const json_type_double: json_type = 2;
pub const json_type_boolean: json_type = 1;
pub const json_type_null: json_type = 0;
pub use crate::json_object::json_bool;
pub use crate::apps::json_parse::json_tokener_error;
pub const json_tokener_error_size: json_tokener_error = 15;
pub const json_tokener_error_parse_utf8_string: json_tokener_error = 14;
pub const json_tokener_error_parse_comment: json_tokener_error = 13;
pub const json_tokener_error_parse_string: json_tokener_error = 12;
pub const json_tokener_error_parse_object_value_sep: json_tokener_error = 11;
pub const json_tokener_error_parse_object_key_sep: json_tokener_error = 10;
pub const json_tokener_error_parse_object_key_name: json_tokener_error = 9;
pub const json_tokener_error_parse_array: json_tokener_error = 8;
pub const json_tokener_error_parse_number: json_tokener_error = 7;
pub const json_tokener_error_parse_boolean: json_tokener_error = 6;
pub const json_tokener_error_parse_null: json_tokener_error = 5;
pub const json_tokener_error_parse_unexpected: json_tokener_error = 4;
pub const json_tokener_error_parse_eof: json_tokener_error = 3;
pub const json_tokener_error_depth: json_tokener_error = 2;
pub const json_tokener_continue: json_tokener_error = 1;
pub const json_tokener_success: json_tokener_error = 0;
pub use crate::apps::json_parse::json_tokener_state;
pub const json_tokener_state_inf: json_tokener_state = 26;
pub const json_tokener_state_object_field_start_after_sep: json_tokener_state = 25;
pub const json_tokener_state_array_after_sep: json_tokener_state = 24;
pub const json_tokener_state_object_sep: json_tokener_state = 23;
pub const json_tokener_state_object_value_add: json_tokener_state = 22;
pub const json_tokener_state_object_value: json_tokener_state = 21;
pub const json_tokener_state_object_field_end: json_tokener_state = 20;
pub const json_tokener_state_object_field: json_tokener_state = 19;
pub const json_tokener_state_object_field_start: json_tokener_state = 18;
pub const json_tokener_state_array_sep: json_tokener_state = 17;
pub const json_tokener_state_array_add: json_tokener_state = 16;
pub const json_tokener_state_array: json_tokener_state = 15;
pub const json_tokener_state_number: json_tokener_state = 14;
pub const json_tokener_state_boolean: json_tokener_state = 13;
pub const json_tokener_state_escape_unicode_need_u: json_tokener_state = 12;
pub const json_tokener_state_escape_unicode_need_escape: json_tokener_state = 11;
pub const json_tokener_state_escape_unicode: json_tokener_state = 10;
pub const json_tokener_state_string_escape: json_tokener_state = 9;
pub const json_tokener_state_string: json_tokener_state = 8;
pub const json_tokener_state_comment_end: json_tokener_state = 7;
pub const json_tokener_state_comment_eol: json_tokener_state = 6;
pub const json_tokener_state_comment: json_tokener_state = 5;
pub const json_tokener_state_comment_start: json_tokener_state = 4;
pub const json_tokener_state_null: json_tokener_state = 3;
pub const json_tokener_state_finish: json_tokener_state = 2;
pub const json_tokener_state_start: json_tokener_state = 1;
pub const json_tokener_state_eatws: json_tokener_state = 0;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::json_tokener_srec;
// #[derive(Copy, Clone)]

pub use crate::apps::json_parse::json_tokener;
#[inline]
 extern "C" fn is_ws_char(mut c: libc::c_char) -> libc::c_int {
    return (c as libc::c_int == ' ' as i32 || c as libc::c_int == '\t' as i32
        || c as libc::c_int == '\n' as i32 || c as libc::c_int == '\r' as i32)
        as libc::c_int;
}
#[inline]
 extern "C" fn is_hex_char(mut c: libc::c_char) -> libc::c_int {
    return (c as libc::c_int >= '0' as i32 && c as libc::c_int <= '9' as i32
        || c as libc::c_int >= 'A' as i32 && c as libc::c_int <= 'F' as i32
        || c as libc::c_int >= 'a' as i32 && c as libc::c_int <= 'f' as i32)
        as libc::c_int;
}
static mut json_null_str: [libc::c_char; 5] = unsafe {
    *::std::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"null\0")
};
static mut json_null_str_len: libc::c_int = 0;
static mut json_inf_str: [libc::c_char; 9] = unsafe {
    *::std::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"Infinity\0")
};
static mut json_inf_str_invert: [libc::c_char; 9] = unsafe {
    *::std::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"iNFINITY\0")
};
static mut json_inf_str_len: libc::c_uint = 0;
static mut json_nan_str: [libc::c_char; 4] = unsafe {
    *::std::mem::transmute::<&[u8; 4], &[libc::c_char; 4]>(b"NaN\0")
};
static mut json_nan_str_len: libc::c_int = 0;
static mut json_true_str: [libc::c_char; 5] = unsafe {
    *::std::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"true\0")
};
static mut json_true_str_len: libc::c_int = 0;
static mut json_false_str: [libc::c_char; 6] = unsafe {
    *::std::mem::transmute::<&[u8; 6], &[libc::c_char; 6]>(b"false\0")
};
static mut json_false_str_len: libc::c_int = 0;
static mut json_tokener_errors: [*const libc::c_char; 16] = [
    b"success\0" as *const u8 as *const libc::c_char,
    b"continue\0" as *const u8 as *const libc::c_char,
    b"nesting too deep\0" as *const u8 as *const libc::c_char,
    b"unexpected end of data\0" as *const u8 as *const libc::c_char,
    b"unexpected character\0" as *const u8 as *const libc::c_char,
    b"null expected\0" as *const u8 as *const libc::c_char,
    b"boolean expected\0" as *const u8 as *const libc::c_char,
    b"number expected\0" as *const u8 as *const libc::c_char,
    b"array value separator ',' expected\0" as *const u8 as *const libc::c_char,
    b"quoted object property name expected\0" as *const u8 as *const libc::c_char,
    b"object property name separator ':' expected\0" as *const u8 as *const libc::c_char,
    b"object value separator ',' expected\0" as *const u8 as *const libc::c_char,
    b"invalid string sequence\0" as *const u8 as *const libc::c_char,
    b"expected comment\0" as *const u8 as *const libc::c_char,
    b"invalid utf-8 string\0" as *const u8 as *const libc::c_char,
    b"buffer size overflow\0" as *const u8 as *const libc::c_char,
];
#[no_mangle]
pub unsafe extern "C" fn json_tokener_error_desc(
    mut jerr: json_tokener_error,
) -> *const libc::c_char {
    let mut jerr_int: libc::c_int = jerr as libc::c_int;
    if jerr_int < 0 as libc::c_int
        || jerr_int
            >= (::std::mem::size_of::<[*const libc::c_char; 16]>() as libc::c_ulong)
                .wrapping_div(
                    ::std::mem::size_of::<*const libc::c_char>() as libc::c_ulong,
                ) as libc::c_int
    {
        return b"Unknown error, invalid json_tokener_error value passed to json_tokener_error_desc()\0"
            as *const u8 as *const libc::c_char;
    }
    return json_tokener_errors[jerr as usize];
}
#[no_mangle]
pub unsafe extern "C" fn json_tokener_get_error(
    mut tok: *mut json_tokener,
) -> json_tokener_error {
    return (*tok).err;
}
static mut utf8_replacement_char: [libc::c_uchar; 3] = [
    0xef as libc::c_int as libc::c_uchar,
    0xbf as libc::c_int as libc::c_uchar,
    0xbd as libc::c_int as libc::c_uchar,
];
#[no_mangle]
pub unsafe extern "C" fn json_tokener_new_ex(
    mut depth: libc::c_int,
) -> *mut json_tokener {
    let mut tok: *mut json_tokener = 0 as *mut json_tokener;
    tok = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::std::mem::size_of::<json_tokener>() as libc::c_ulong,
    ) as *mut json_tokener;
    if tok.is_null() {
        return 0 as *mut json_tokener;
    }
    let ref mut fresh0 = (*tok).stack;
    *fresh0 = calloc(
        depth as libc::c_ulong,
        ::std::mem::size_of::<json_tokener_srec>() as libc::c_ulong,
    ) as *mut json_tokener_srec;
    if ((*tok).stack).is_null() {
        free(tok as *mut libc::c_void);
        return 0 as *mut json_tokener;
    }
    let ref mut fresh1 = (*tok).pb;
    *fresh1 = printbuf_new();
    if ((*tok).pb).is_null() {
        free((*tok).stack as *mut libc::c_void);
        free(tok as *mut libc::c_void);
        return 0 as *mut json_tokener;
    }
    (*tok).max_depth = depth;
    json_tokener_reset(tok);
    return tok;
}
#[no_mangle]
pub unsafe extern "C" fn json_tokener_new() -> *mut json_tokener {
    return json_tokener_new_ex(32 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn json_tokener_free(mut tok: *mut json_tokener) {
    json_tokener_reset(tok);
    if !((*tok).pb).is_null() {
        printbuf_free((*tok).pb);
    }
    free((*tok).stack as *mut libc::c_void);
    free(tok as *mut libc::c_void);
}
unsafe extern "C" fn json_tokener_reset_level(
    mut tok: *mut json_tokener,
    mut depth: libc::c_int,
) {
    (*((*tok).stack).offset(depth as isize)).state = json_tokener_state_eatws;
    (*((*tok).stack).offset(depth as isize)).saved_state = json_tokener_state_start;
    json_object_put((*((*tok).stack).offset(depth as isize)).current);
    let ref mut fresh2 = (*((*tok).stack).offset(depth as isize)).current;
    *fresh2 = 0 as *mut json_object;
    free((*((*tok).stack).offset(depth as isize)).obj_field_name as *mut libc::c_void);
    let ref mut fresh3 = (*((*tok).stack).offset(depth as isize)).obj_field_name;
    *fresh3 = 0 as *mut libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn json_tokener_reset(mut tok: *mut json_tokener) {
    let mut i: libc::c_int = 0;
    if tok.is_null() {
        return;
    }
    i = (*tok).depth;
    while i >= 0 as libc::c_int {
        json_tokener_reset_level(tok, i);
        i -= 1;
    }
    (*tok).depth = 0 as libc::c_int;
    (*tok).err = json_tokener_success;
}
#[no_mangle]
pub unsafe extern "C" fn json_tokener_parse(
    mut str: *const libc::c_char,
) -> *mut json_object {
    let mut jerr_ignored: json_tokener_error = json_tokener_success;
    let mut obj: *mut json_object = 0 as *mut json_object;
    obj = json_tokener_parse_verbose(str, &mut jerr_ignored);
    return obj;
}
#[no_mangle]
pub unsafe extern "C" fn json_tokener_parse_verbose(
    mut str: *const libc::c_char,
    mut error: *mut json_tokener_error,
) -> *mut json_object {
    let mut tok: *mut json_tokener = 0 as *mut json_tokener;
    let mut obj: *mut json_object = 0 as *mut json_object;
    tok = json_tokener_new();
    if tok.is_null() {
        return 0 as *mut json_object;
    }
    obj = json_tokener_parse_ex(tok, str, -(1 as libc::c_int));
    *error = (*tok).err;
    if (*tok).err as libc::c_uint != json_tokener_success as libc::c_int as libc::c_uint
    {
        if !obj.is_null() {
            json_object_put(obj);
        }
        obj = 0 as *mut json_object;
    }
    json_tokener_free(tok);
    return obj;
}
#[no_mangle]
pub unsafe extern "C" fn json_tokener_parse_ex(
    mut tok: *mut json_tokener,
    mut str: *const libc::c_char,
    mut len: libc::c_int,
) -> *mut json_object {
    let mut case_start_3: *const libc::c_char = 0 as *const libc::c_char;
    let mut case_start_1: *const libc::c_char = 0 as *const libc::c_char;
    let mut case_start_0: *const libc::c_char = 0 as *const libc::c_char;
    let mut case_start: *const libc::c_char = 0 as *const libc::c_char;
    let mut size: libc::c_int = 0;
    let mut size_nan: libc::c_int = 0;
    let mut size1: libc::c_int = 0;
    let mut size2: libc::c_int = 0;
    let mut current_block: u64;
    let mut obj: *mut json_object = 0 as *mut json_object;
    let mut c: libc::c_char = '\u{1}' as i32 as libc::c_char;
    let mut nBytes: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut nBytesp: *mut libc::c_uint = &mut nBytes;
    let mut oldlocale: locale_t = uselocale(0 as locale_t);
    let mut newloc: locale_t = 0 as *mut __locale_struct;
    (*tok).char_offset = 0 as libc::c_int;
    (*tok).err = json_tokener_success;
    if len < -(1 as libc::c_int)
        || len == -(1 as libc::c_int)
            && strlen(str) > 2147483647 as libc::c_int as libc::c_ulong
    {
        (*tok).err = json_tokener_error_size;
        return 0 as *mut json_object;
    }
    let mut duploc: locale_t = duplocale(oldlocale);
    newloc = newlocale(
        (1 as libc::c_int) << 1 as libc::c_int,
        b"C\0" as *const u8 as *const libc::c_char,
        duploc,
    );
    if newloc.is_null() {
        freelocale(duploc);
        return 0 as *mut json_object;
    }
    uselocale(newloc);
    's_76: while if (*tok).char_offset == len {
        if (*tok).depth == 0 as libc::c_int
            && (*((*tok).stack).offset((*tok).depth as isize)).state as libc::c_uint
                == json_tokener_state_eatws as libc::c_int as libc::c_uint
            && (*((*tok).stack).offset((*tok).depth as isize)).saved_state
                as libc::c_uint
                == json_tokener_state_finish as libc::c_int as libc::c_uint
        {
            (*tok).err = json_tokener_success;
            0 as libc::c_int
        } else {
            (*tok).err = json_tokener_continue;
            0 as libc::c_int
        }
    } else if (*tok).flags & 0x10 as libc::c_int != 0
            && json_tokener_validate_utf8(*str, nBytesp) == 0
        {
        (*tok).err = json_tokener_error_parse_utf8_string;
        0 as libc::c_int
    } else {
        c = *str;
        1 as libc::c_int
    } != 0
    {
        loop {
            match (*((*tok).stack).offset((*tok).depth as isize)).state as libc::c_uint {
                0 => {
                    while is_ws_char(c) != 0 {
                        str = str.offset(1);
                        let ref mut fresh4 = (*tok).char_offset;
                        *fresh4 += 1;
                        if c == 0
                            || (if (*tok).char_offset == len {
                                (if (*tok).depth == 0 as libc::c_int
                                    && (*((*tok).stack).offset((*tok).depth as isize)).state
                                        as libc::c_uint
                                        == json_tokener_state_eatws as libc::c_int as libc::c_uint
                                    && (*((*tok).stack).offset((*tok).depth as isize))
                                        .saved_state as libc::c_uint
                                        == json_tokener_state_finish as libc::c_int as libc::c_uint
                                {
                                    (*tok).err = json_tokener_success;
                                    0 as libc::c_int
                                } else {
                                    (*tok).err = json_tokener_continue;
                                    0 as libc::c_int
                                })
                            } else {
                                (if (*tok).flags & 0x10 as libc::c_int != 0
                                    && json_tokener_validate_utf8(*str, nBytesp) == 0
                                {
                                    (*tok).err = json_tokener_error_parse_utf8_string;
                                    0 as libc::c_int
                                } else {
                                    c = *str;
                                    1 as libc::c_int
                                })
                            }) == 0
                        {
                            break 's_76;
                        }
                    }
                    if c as libc::c_int == '/' as i32
                        && (*tok).flags & 0x1 as libc::c_int == 0
                    {
                        printbuf_reset((*tok).pb);
                        if (*(*tok).pb).size - (*(*tok).pb).bpos > 1 as libc::c_int {
                            memcpy(
                                ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                    as *mut libc::c_void,
                                &mut c as *mut libc::c_char as *const libc::c_void,
                                1 as libc::c_int as libc::c_ulong,
                            );
                            (*(*tok).pb).bpos += 1 as libc::c_int;
                            *((*(*tok).pb).buf)
                                .offset(
                                    (*(*tok).pb).bpos as isize,
                                ) = '\u{0}' as i32 as libc::c_char;
                        } else {
                            printbuf_memappend((*tok).pb, &mut c, 1 as libc::c_int);
                        }
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_comment_start;
                        current_block = 14910428593596980134;
                        break;
                    } else {
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = (*((*tok).stack).offset((*tok).depth as isize))
                            .saved_state;
                    }
                }
                1 => {
                    match c as libc::c_int {
                        123 => {
                            (*((*tok).stack).offset((*tok).depth as isize))
                                .state = json_tokener_state_eatws;
                            (*((*tok).stack).offset((*tok).depth as isize))
                                .saved_state = json_tokener_state_object_field_start;
                            let ref mut fresh5 = (*((*tok).stack)
                                .offset((*tok).depth as isize))
                                .current;
                            *fresh5 = json_object_new_object();
                            if ((*((*tok).stack).offset((*tok).depth as isize)).current)
                                .is_null()
                            {
                                break 's_76;
                            } else {
                                current_block = 14910428593596980134;
                                break;
                            }
                        }
                        91 => {
                            (*((*tok).stack).offset((*tok).depth as isize))
                                .state = json_tokener_state_eatws;
                            (*((*tok).stack).offset((*tok).depth as isize))
                                .saved_state = json_tokener_state_array;
                            let ref mut fresh6 = (*((*tok).stack)
                                .offset((*tok).depth as isize))
                                .current;
                            *fresh6 = json_object_new_array();
                            if ((*((*tok).stack).offset((*tok).depth as isize)).current)
                                .is_null()
                            {
                                break 's_76;
                            } else {
                                current_block = 14910428593596980134;
                                break;
                            }
                        }
                        73 | 105 => {
                            (*((*tok).stack).offset((*tok).depth as isize))
                                .state = json_tokener_state_inf;
                            printbuf_reset((*tok).pb);
                            (*tok).st_pos = 0 as libc::c_int;
                        }
                        78 | 110 => {
                            (*((*tok).stack).offset((*tok).depth as isize))
                                .state = json_tokener_state_null;
                            printbuf_reset((*tok).pb);
                            (*tok).st_pos = 0 as libc::c_int;
                        }
                        39 => {
                            if (*tok).flags & 0x1 as libc::c_int != 0 {
                                current_block = 7990025728955927862;
                                break;
                            } else {
                                current_block = 5965298418754406754;
                                break;
                            }
                        }
                        34 => {
                            current_block = 5965298418754406754;
                            break;
                        }
                        84 | 116 | 70 | 102 => {
                            (*((*tok).stack).offset((*tok).depth as isize))
                                .state = json_tokener_state_boolean;
                            printbuf_reset((*tok).pb);
                            (*tok).st_pos = 0 as libc::c_int;
                        }
                        48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 | 45 => {
                            (*((*tok).stack).offset((*tok).depth as isize))
                                .state = json_tokener_state_number;
                            printbuf_reset((*tok).pb);
                            (*tok).is_double = 0 as libc::c_int;
                        }
                        _ => {
                            (*tok).err = json_tokener_error_parse_unexpected;
                            break 's_76;
                        }
                    }
                }
                2 => {
                    if (*tok).depth == 0 as libc::c_int {
                        break 's_76;
                    }
                    obj = json_object_get(
                        (*((*tok).stack).offset((*tok).depth as isize)).current,
                    );
                    json_tokener_reset_level(tok, (*tok).depth);
                    let ref mut fresh7 = (*tok).depth;
                    *fresh7 -= 1;
                }
                26 => {
                    let mut is_negative: libc::c_int = 0 as libc::c_int;
                    while (*tok).st_pos < json_inf_str_len as libc::c_int {
                        let mut inf_char: libc::c_char = *str;
                        if inf_char as libc::c_int
                            != json_inf_str[(*tok).st_pos as usize] as libc::c_int
                            && ((*tok).flags & 0x1 as libc::c_int != 0
                                || inf_char as libc::c_int
                                    != json_inf_str_invert[(*tok).st_pos as usize]
                                        as libc::c_int)
                        {
                            (*tok).err = json_tokener_error_parse_unexpected;
                            break 's_76;
                        } else {
                            let ref mut fresh8 = (*tok).st_pos;
                            *fresh8 += 1;
                            str = str.offset(1);
                            let ref mut fresh9 = (*tok).char_offset;
                            *fresh9 += 1;
                            if !(if (*tok).char_offset == len {
                                if (*tok).depth == 0 as libc::c_int
                                    && (*((*tok).stack).offset((*tok).depth as isize)).state
                                        as libc::c_uint
                                        == json_tokener_state_eatws as libc::c_int as libc::c_uint
                                    && (*((*tok).stack).offset((*tok).depth as isize))
                                        .saved_state as libc::c_uint
                                        == json_tokener_state_finish as libc::c_int as libc::c_uint
                                {
                                    (*tok).err = json_tokener_success;
                                    0 as libc::c_int
                                } else {
                                    (*tok).err = json_tokener_continue;
                                    0 as libc::c_int
                                }
                            } else if (*tok).flags & 0x10 as libc::c_int != 0
                                    && json_tokener_validate_utf8(*str, nBytesp) == 0
                                {
                                (*tok).err = json_tokener_error_parse_utf8_string;
                                0 as libc::c_int
                            } else {
                                c = *str;
                                1 as libc::c_int
                            } == 0)
                            {
                                continue;
                            }
                            break 's_76;
                        }
                    }
                    if (*(*tok).pb).bpos > 0 as libc::c_int
                        && *(*(*tok).pb).buf as libc::c_int == '-' as i32
                    {
                        is_negative = 1 as libc::c_int;
                    }
                    let ref mut fresh10 = (*((*tok).stack).offset((*tok).depth as isize))
                        .current;
                    *fresh10 = json_object_new_double(
                        (if is_negative != 0 {
                            -::std::f32::INFINITY
                        } else {
                            ::std::f32::INFINITY
                        }) as libc::c_double,
                    );
                    if ((*((*tok).stack).offset((*tok).depth as isize)).current)
                        .is_null()
                    {
                        break 's_76;
                    }
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .saved_state = json_tokener_state_finish;
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .state = json_tokener_state_eatws;
                }
                3 => {
                    size = 0;
                    size_nan = 0;
                    if (*(*tok).pb).size - (*(*tok).pb).bpos > 1 as libc::c_int {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            &mut c as *mut libc::c_char as *const libc::c_void,
                            1 as libc::c_int as libc::c_ulong,
                        );
                        (*(*tok).pb).bpos += 1 as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend((*tok).pb, &mut c, 1 as libc::c_int);
                    }
                    size = if ((*tok).st_pos + 1 as libc::c_int) < json_null_str_len {
                        (*tok).st_pos + 1 as libc::c_int
                    } else {
                        json_null_str_len
                    };
                    size_nan = if ((*tok).st_pos + 1 as libc::c_int) < json_nan_str_len {
                        (*tok).st_pos + 1 as libc::c_int
                    } else {
                        json_nan_str_len
                    };
                    if (*tok).flags & 0x1 as libc::c_int == 0
                        && strncasecmp(
                            json_null_str.as_ptr(),
                            (*(*tok).pb).buf,
                            size as libc::c_ulong,
                        ) == 0 as libc::c_int
                        || strncmp(
                            json_null_str.as_ptr(),
                            (*(*tok).pb).buf,
                            size as libc::c_ulong,
                        ) == 0 as libc::c_int
                    {
                        if !((*tok).st_pos == json_null_str_len) {
                            current_block = 13823707972521062695;
                            break;
                        }
                        let ref mut fresh11 = (*((*tok).stack)
                            .offset((*tok).depth as isize))
                            .current;
                        *fresh11 = 0 as *mut json_object;
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .saved_state = json_tokener_state_finish;
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_eatws;
                    } else if (*tok).flags & 0x1 as libc::c_int == 0
                            && strncasecmp(
                                json_nan_str.as_ptr(),
                                (*(*tok).pb).buf,
                                size_nan as libc::c_ulong,
                            ) == 0 as libc::c_int
                            || strncmp(
                                json_nan_str.as_ptr(),
                                (*(*tok).pb).buf,
                                size_nan as libc::c_ulong,
                            ) == 0 as libc::c_int
                        {
                        if !((*tok).st_pos == json_nan_str_len) {
                            current_block = 13823707972521062695;
                            break;
                        }
                        let ref mut fresh12 = (*((*tok).stack)
                            .offset((*tok).depth as isize))
                            .current;
                        *fresh12 = json_object_new_double(
                            ::std::f32::NAN as libc::c_double,
                        );
                        if ((*((*tok).stack).offset((*tok).depth as isize)).current)
                            .is_null()
                        {
                            break 's_76;
                        }
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .saved_state = json_tokener_state_finish;
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_eatws;
                    } else {
                        (*tok).err = json_tokener_error_parse_null;
                        break 's_76;
                    }
                }
                4 => {
                    if c as libc::c_int == '*' as i32 {
                        current_block = 11162283542402356847;
                        break;
                    } else {
                        current_block = 17917672080766325409;
                        break;
                    }
                }
                5 => {
                    case_start = str;
                    current_block = 18221534353613080499;
                    break;
                }
                6 => {
                    case_start_0 = str;
                    current_block = 6662862405959679103;
                    break;
                }
                7 => {
                    if (*(*tok).pb).size - (*(*tok).pb).bpos > 1 as libc::c_int {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            &mut c as *mut libc::c_char as *const libc::c_void,
                            1 as libc::c_int as libc::c_ulong,
                        );
                        (*(*tok).pb).bpos += 1 as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend((*tok).pb, &mut c, 1 as libc::c_int);
                    }
                    if c as libc::c_int == '/' as i32 {
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_eatws;
                    } else {
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_comment;
                    }
                    current_block = 14910428593596980134;
                    break;
                }
                8 => {
                    case_start_1 = str;
                    current_block = 13526015532137226550;
                    break;
                }
                9 => {
                    match c as libc::c_int {
                        34 | 92 | 47 => {
                            current_block = 5851233167266824712;
                            break;
                        }
                        98 | 110 | 114 | 116 | 102 => {
                            current_block = 902433882565356955;
                            break;
                        }
                        117 => {
                            current_block = 17501499944854094182;
                            break;
                        }
                        _ => {
                            current_block = 15463013039495622015;
                            break;
                        }
                    }
                }
                10 => {
                    current_block = 5600328731811258759;
                    break;
                }
                11 => {
                    if c == 0 || c as libc::c_int != '\\' as i32 {
                        if (*(*tok).pb).size - (*(*tok).pb).bpos > 3 as libc::c_int {
                            memcpy(
                                ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                    as *mut libc::c_void,
                                utf8_replacement_char.as_mut_ptr() as *mut libc::c_char
                                    as *const libc::c_void,
                                3 as libc::c_int as libc::c_ulong,
                            );
                            (*(*tok).pb).bpos += 3 as libc::c_int;
                            *((*(*tok).pb).buf)
                                .offset(
                                    (*(*tok).pb).bpos as isize,
                                ) = '\u{0}' as i32 as libc::c_char;
                        } else {
                            printbuf_memappend(
                                (*tok).pb,
                                utf8_replacement_char.as_mut_ptr() as *mut libc::c_char,
                                3 as libc::c_int,
                            );
                        }
                        (*tok).high_surrogate = 0 as libc::c_int as libc::c_uint;
                        (*tok).ucs_char = 0 as libc::c_int as libc::c_uint;
                        (*tok).st_pos = 0 as libc::c_int;
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = (*((*tok).stack).offset((*tok).depth as isize))
                            .saved_state;
                    } else {
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_escape_unicode_need_u;
                        current_block = 14910428593596980134;
                        break;
                    }
                }
                12 => {
                    if c == 0 || c as libc::c_int != 'u' as i32 {
                        if (*(*tok).pb).size - (*(*tok).pb).bpos > 3 as libc::c_int {
                            memcpy(
                                ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                    as *mut libc::c_void,
                                utf8_replacement_char.as_mut_ptr() as *mut libc::c_char
                                    as *const libc::c_void,
                                3 as libc::c_int as libc::c_ulong,
                            );
                            (*(*tok).pb).bpos += 3 as libc::c_int;
                            *((*(*tok).pb).buf)
                                .offset(
                                    (*(*tok).pb).bpos as isize,
                                ) = '\u{0}' as i32 as libc::c_char;
                        } else {
                            printbuf_memappend(
                                (*tok).pb,
                                utf8_replacement_char.as_mut_ptr() as *mut libc::c_char,
                                3 as libc::c_int,
                            );
                        }
                        (*tok).high_surrogate = 0 as libc::c_int as libc::c_uint;
                        (*tok).ucs_char = 0 as libc::c_int as libc::c_uint;
                        (*tok).st_pos = 0 as libc::c_int;
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_string_escape;
                    } else {
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_escape_unicode;
                        current_block = 14910428593596980134;
                        break;
                    }
                }
                13 => {
                    size1 = 0;
                    size2 = 0;
                    if (*(*tok).pb).size - (*(*tok).pb).bpos > 1 as libc::c_int {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            &mut c as *mut libc::c_char as *const libc::c_void,
                            1 as libc::c_int as libc::c_ulong,
                        );
                        (*(*tok).pb).bpos += 1 as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend((*tok).pb, &mut c, 1 as libc::c_int);
                    }
                    size1 = if ((*tok).st_pos + 1 as libc::c_int) < json_true_str_len {
                        (*tok).st_pos + 1 as libc::c_int
                    } else {
                        json_true_str_len
                    };
                    size2 = if ((*tok).st_pos + 1 as libc::c_int) < json_false_str_len {
                        (*tok).st_pos + 1 as libc::c_int
                    } else {
                        json_false_str_len
                    };
                    if (*tok).flags & 0x1 as libc::c_int == 0
                        && strncasecmp(
                            json_true_str.as_ptr(),
                            (*(*tok).pb).buf,
                            size1 as libc::c_ulong,
                        ) == 0 as libc::c_int
                        || strncmp(
                            json_true_str.as_ptr(),
                            (*(*tok).pb).buf,
                            size1 as libc::c_ulong,
                        ) == 0 as libc::c_int
                    {
                        if !((*tok).st_pos == json_true_str_len) {
                            current_block = 6015864261243718670;
                            break;
                        }
                        let ref mut fresh27 = (*((*tok).stack)
                            .offset((*tok).depth as isize))
                            .current;
                        *fresh27 = json_object_new_boolean(1 as libc::c_int);
                        if ((*((*tok).stack).offset((*tok).depth as isize)).current)
                            .is_null()
                        {
                            break 's_76;
                        }
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .saved_state = json_tokener_state_finish;
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_eatws;
                    } else if (*tok).flags & 0x1 as libc::c_int == 0
                            && strncasecmp(
                                json_false_str.as_ptr(),
                                (*(*tok).pb).buf,
                                size2 as libc::c_ulong,
                            ) == 0 as libc::c_int
                            || strncmp(
                                json_false_str.as_ptr(),
                                (*(*tok).pb).buf,
                                size2 as libc::c_ulong,
                            ) == 0 as libc::c_int
                        {
                        if !((*tok).st_pos == json_false_str_len) {
                            current_block = 6015864261243718670;
                            break;
                        }
                        let ref mut fresh28 = (*((*tok).stack)
                            .offset((*tok).depth as isize))
                            .current;
                        *fresh28 = json_object_new_boolean(0 as libc::c_int);
                        if ((*((*tok).stack).offset((*tok).depth as isize)).current)
                            .is_null()
                        {
                            break 's_76;
                        }
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .saved_state = json_tokener_state_finish;
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_eatws;
                    } else {
                        (*tok).err = json_tokener_error_parse_boolean;
                        break 's_76;
                    }
                }
                14 => {
                    let mut case_start_2: *const libc::c_char = str;
                    let mut case_len: libc::c_int = 0 as libc::c_int;
                    let mut is_exponent: libc::c_int = 0 as libc::c_int;
                    let mut neg_sign_ok: libc::c_int = 1 as libc::c_int;
                    let mut pos_sign_ok: libc::c_int = 0 as libc::c_int;
                    if (*(*tok).pb).bpos > 0 as libc::c_int {
                        let mut e_loc: *mut libc::c_char = strchr(
                            (*(*tok).pb).buf,
                            'e' as i32,
                        );
                        if e_loc.is_null() {
                            e_loc = strchr((*(*tok).pb).buf, 'E' as i32);
                        }
                        if !e_loc.is_null() {
                            let mut last_saved_char: *mut libc::c_char = &mut *((*(*tok)
                                .pb)
                                .buf)
                                .offset(((*(*tok).pb).bpos - 1 as libc::c_int) as isize)
                                as *mut libc::c_char;
                            is_exponent = 1 as libc::c_int;
                            neg_sign_ok = 1 as libc::c_int;
                            pos_sign_ok = neg_sign_ok;
                            if e_loc != last_saved_char {
                                neg_sign_ok = 0 as libc::c_int;
                                pos_sign_ok = 0 as libc::c_int;
                            }
                        }
                    }
                    while c as libc::c_int != 0
                        && (c as libc::c_int >= '0' as i32
                            && c as libc::c_int <= '9' as i32
                            || is_exponent == 0
                                && (c as libc::c_int == 'e' as i32
                                    || c as libc::c_int == 'E' as i32)
                            || neg_sign_ok != 0 && c as libc::c_int == '-' as i32
                            || pos_sign_ok != 0 && c as libc::c_int == '+' as i32
                            || (*tok).is_double == 0 && c as libc::c_int == '.' as i32)
                    {
                        neg_sign_ok = 0 as libc::c_int;
                        pos_sign_ok = neg_sign_ok;
                        case_len += 1;
                        match c as libc::c_int {
                            46 => {
                                (*tok).is_double = 1 as libc::c_int;
                                pos_sign_ok = 1 as libc::c_int;
                                neg_sign_ok = 1 as libc::c_int;
                            }
                            101 | 69 => {
                                is_exponent = 1 as libc::c_int;
                                (*tok).is_double = 1 as libc::c_int;
                                neg_sign_ok = 1 as libc::c_int;
                                pos_sign_ok = neg_sign_ok;
                            }
                            _ => {}
                        }
                        str = str.offset(1);
                        let ref mut fresh30 = (*tok).char_offset;
                        *fresh30 += 1;
                        if !(c == 0
                            || (if (*tok).char_offset == len {
                                (if (*tok).depth == 0 as libc::c_int
                                    && (*((*tok).stack).offset((*tok).depth as isize)).state
                                        as libc::c_uint
                                        == json_tokener_state_eatws as libc::c_int as libc::c_uint
                                    && (*((*tok).stack).offset((*tok).depth as isize))
                                        .saved_state as libc::c_uint
                                        == json_tokener_state_finish as libc::c_int as libc::c_uint
                                {
                                    (*tok).err = json_tokener_success;
                                    0 as libc::c_int
                                } else {
                                    (*tok).err = json_tokener_continue;
                                    0 as libc::c_int
                                })
                            } else {
                                (if (*tok).flags & 0x10 as libc::c_int != 0
                                    && json_tokener_validate_utf8(*str, nBytesp) == 0
                                {
                                    (*tok).err = json_tokener_error_parse_utf8_string;
                                    0 as libc::c_int
                                } else {
                                    c = *str;
                                    1 as libc::c_int
                                })
                            }) == 0)
                        {
                            continue;
                        }
                        if (*(*tok).pb).size - (*(*tok).pb).bpos > case_len {
                            memcpy(
                                ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                    as *mut libc::c_void,
                                case_start_2 as *const libc::c_void,
                                case_len as libc::c_ulong,
                            );
                            (*(*tok).pb).bpos += case_len;
                            *((*(*tok).pb).buf)
                                .offset(
                                    (*(*tok).pb).bpos as isize,
                                ) = '\u{0}' as i32 as libc::c_char;
                        } else {
                            printbuf_memappend((*tok).pb, case_start_2, case_len);
                        }
                        break 's_76;
                    }
                    if (*tok).depth > 0 as libc::c_int && c as libc::c_int != ',' as i32
                        && c as libc::c_int != ']' as i32
                        && c as libc::c_int != '}' as i32
                        && c as libc::c_int != '/' as i32
                        && c as libc::c_int != 'I' as i32
                        && c as libc::c_int != 'i' as i32 && is_ws_char(c) == 0
                    {
                        (*tok).err = json_tokener_error_parse_number;
                        break 's_76;
                    } else {
                        if case_len > 0 as libc::c_int {
                            if (*(*tok).pb).size - (*(*tok).pb).bpos > case_len {
                                memcpy(
                                    ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                        as *mut libc::c_void,
                                    case_start_2 as *const libc::c_void,
                                    case_len as libc::c_ulong,
                                );
                                (*(*tok).pb).bpos += case_len;
                                *((*(*tok).pb).buf)
                                    .offset(
                                        (*(*tok).pb).bpos as isize,
                                    ) = '\u{0}' as i32 as libc::c_char;
                            } else {
                                printbuf_memappend((*tok).pb, case_start_2, case_len);
                            }
                        }
                        if *((*(*tok).pb).buf).offset(0 as libc::c_int as isize)
                            as libc::c_int == '-' as i32 && case_len <= 1 as libc::c_int
                            && (c as libc::c_int == 'i' as i32
                                || c as libc::c_int == 'I' as i32)
                        {
                            (*((*tok).stack).offset((*tok).depth as isize))
                                .state = json_tokener_state_inf;
                            (*tok).st_pos = 0 as libc::c_int;
                        } else {
                            if (*tok).is_double != 0
                                && (*tok).flags & 0x1 as libc::c_int == 0
                            {
                                while (*(*tok).pb).bpos > 1 as libc::c_int {
                                    let mut last_char: libc::c_char = *((*(*tok).pb).buf)
                                        .offset(((*(*tok).pb).bpos - 1 as libc::c_int) as isize);
                                    if last_char as libc::c_int != 'e' as i32
                                        && last_char as libc::c_int != 'E' as i32
                                        && last_char as libc::c_int != '-' as i32
                                        && last_char as libc::c_int != '+' as i32
                                    {
                                        break;
                                    }
                                    *((*(*tok).pb).buf)
                                        .offset(
                                            ((*(*tok).pb).bpos - 1 as libc::c_int) as isize,
                                        ) = '\u{0}' as i32 as libc::c_char;
                                    let ref mut fresh31 = (*(*tok).pb).bpos;
                                    *fresh31 -= 1;
                                }
                            }
                            let mut num64: int64_t = 0;
                            let mut numuint64: uint64_t = 0;
                            let mut numd: libc::c_double = 0.;
                            if (*tok).is_double == 0
                                && *((*(*tok).pb).buf).offset(0 as libc::c_int as isize)
                                    as libc::c_int == '-' as i32
                                && json_parse_int64((*(*tok).pb).buf, &mut num64)
                                    == 0 as libc::c_int
                            {
                                if *__errno_location() == 34 as libc::c_int
                                    && (*tok).flags & 0x1 as libc::c_int != 0
                                {
                                    (*tok).err = json_tokener_error_parse_number;
                                    break 's_76;
                                } else {
                                    let ref mut fresh32 = (*((*tok).stack)
                                        .offset((*tok).depth as isize))
                                        .current;
                                    *fresh32 = json_object_new_int64(num64);
                                    if ((*((*tok).stack).offset((*tok).depth as isize)).current)
                                        .is_null()
                                    {
                                        break 's_76;
                                    }
                                }
                            } else if (*tok).is_double == 0
                                    && *((*(*tok).pb).buf).offset(0 as libc::c_int as isize)
                                        as libc::c_int != '-' as i32
                                    && json_parse_uint64((*(*tok).pb).buf, &mut numuint64)
                                        == 0 as libc::c_int
                                {
                                if *__errno_location() == 34 as libc::c_int
                                    && (*tok).flags & 0x1 as libc::c_int != 0
                                {
                                    (*tok).err = json_tokener_error_parse_number;
                                    break 's_76;
                                } else if numuint64 != 0
                                        && *((*(*tok).pb).buf).offset(0 as libc::c_int as isize)
                                            as libc::c_int == '0' as i32
                                        && (*tok).flags & 0x1 as libc::c_int != 0
                                    {
                                    (*tok).err = json_tokener_error_parse_number;
                                    break 's_76;
                                } else if numuint64
                                        <= 9223372036854775807 as libc::c_long as libc::c_ulong
                                    {
                                    num64 = numuint64 as int64_t;
                                    let ref mut fresh33 = (*((*tok).stack)
                                        .offset((*tok).depth as isize))
                                        .current;
                                    *fresh33 = json_object_new_int64(num64);
                                    if ((*((*tok).stack).offset((*tok).depth as isize)).current)
                                        .is_null()
                                    {
                                        break 's_76;
                                    }
                                } else {
                                    let ref mut fresh34 = (*((*tok).stack)
                                        .offset((*tok).depth as isize))
                                        .current;
                                    *fresh34 = json_object_new_uint64(numuint64);
                                    if ((*((*tok).stack).offset((*tok).depth as isize)).current)
                                        .is_null()
                                    {
                                        break 's_76;
                                    }
                                }
                            } else if (*tok).is_double != 0
                                    && json_tokener_parse_double(
                                        (*(*tok).pb).buf,
                                        (*(*tok).pb).bpos,
                                        &mut numd,
                                    ) == 0 as libc::c_int
                                {
                                let ref mut fresh35 = (*((*tok).stack)
                                    .offset((*tok).depth as isize))
                                    .current;
                                *fresh35 = json_object_new_double_s(numd, (*(*tok).pb).buf);
                                if ((*((*tok).stack).offset((*tok).depth as isize)).current)
                                    .is_null()
                                {
                                    break 's_76;
                                }
                            } else {
                                (*tok).err = json_tokener_error_parse_number;
                                break 's_76;
                            }
                            (*((*tok).stack).offset((*tok).depth as isize))
                                .saved_state = json_tokener_state_finish;
                            (*((*tok).stack).offset((*tok).depth as isize))
                                .state = json_tokener_state_eatws;
                        }
                    }
                }
                24 | 15 => {
                    if c as libc::c_int == ']' as i32 {
                        json_object_array_shrink(
                            (*((*tok).stack).offset((*tok).depth as isize)).current,
                            0 as libc::c_int,
                        );
                        if (*((*tok).stack).offset((*tok).depth as isize)).state
                            as libc::c_uint
                            == json_tokener_state_array_after_sep as libc::c_int
                                as libc::c_uint && (*tok).flags & 0x1 as libc::c_int != 0
                        {
                            current_block = 5524635047616071233;
                            break;
                        } else {
                            current_block = 955764296456093747;
                            break;
                        }
                    } else if (*tok).depth >= (*tok).max_depth - 1 as libc::c_int {
                        (*tok).err = json_tokener_error_depth;
                        break 's_76;
                    } else {
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_array_add;
                        let ref mut fresh36 = (*tok).depth;
                        *fresh36 += 1;
                        json_tokener_reset_level(tok, (*tok).depth);
                    }
                }
                16 => {
                    if json_object_array_add(
                        (*((*tok).stack).offset((*tok).depth as isize)).current,
                        obj,
                    ) != 0 as libc::c_int
                    {
                        break 's_76;
                    }
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .saved_state = json_tokener_state_array_sep;
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .state = json_tokener_state_eatws;
                }
                17 => {
                    if c as libc::c_int == ']' as i32 {
                        current_block = 17927085222977126794;
                        break;
                    } else {
                        current_block = 9898910953550671049;
                        break;
                    }
                }
                18 | 25 => {
                    if c as libc::c_int == '}' as i32 {
                        current_block = 9952967170209510081;
                        break;
                    } else {
                        current_block = 8644614806574383103;
                        break;
                    }
                }
                19 => {
                    case_start_3 = str;
                    current_block = 16251542583832361733;
                    break;
                }
                20 => {
                    if c as libc::c_int == ':' as i32 {
                        current_block = 14575203612169622940;
                        break;
                    } else {
                        current_block = 5151117443143562747;
                        break;
                    }
                }
                21 => {
                    if (*tok).depth >= (*tok).max_depth - 1 as libc::c_int {
                        (*tok).err = json_tokener_error_depth;
                        break 's_76;
                    } else {
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_object_value_add;
                        let ref mut fresh42 = (*tok).depth;
                        *fresh42 += 1;
                        json_tokener_reset_level(tok, (*tok).depth);
                    }
                }
                22 => {
                    json_object_object_add(
                        (*((*tok).stack).offset((*tok).depth as isize)).current,
                        (*((*tok).stack).offset((*tok).depth as isize)).obj_field_name,
                        obj,
                    );
                    free(
                        (*((*tok).stack).offset((*tok).depth as isize)).obj_field_name
                            as *mut libc::c_void,
                    );
                    let ref mut fresh43 = (*((*tok).stack).offset((*tok).depth as isize))
                        .obj_field_name;
                    *fresh43 = 0 as *mut libc::c_char;
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .saved_state = json_tokener_state_object_sep;
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .state = json_tokener_state_eatws;
                }
                23 => {
                    if c as libc::c_int == '}' as i32 {
                        current_block = 10945600426047866894;
                        break;
                    } else {
                        current_block = 16760829112842239754;
                        break;
                    }
                }
                _ => {
                    current_block = 14910428593596980134;
                    break;
                }
            }
        }
        match current_block {
            16251542583832361733 => {
                loop {
                    if c as libc::c_int == (*tok).quote_char as libc::c_int {
                        if ((*(*tok).pb).size - (*(*tok).pb).bpos) as libc::c_long
                            > str.offset_from(case_start_3) as libc::c_long
                        {
                            memcpy(
                                ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                    as *mut libc::c_void,
                                case_start_3 as *const libc::c_void,
                                str.offset_from(case_start_3) as libc::c_long
                                    as libc::c_ulong,
                            );
                            let ref mut fresh37 = (*(*tok).pb).bpos;
                            *fresh37 = (*fresh37 as libc::c_long
                                + str.offset_from(case_start_3) as libc::c_long)
                                as libc::c_int;
                            *((*(*tok).pb).buf)
                                .offset(
                                    (*(*tok).pb).bpos as isize,
                                ) = '\u{0}' as i32 as libc::c_char;
                        } else {
                            printbuf_memappend(
                                (*tok).pb,
                                case_start_3,
                                str.offset_from(case_start_3) as libc::c_long as libc::c_int,
                            );
                        }
                        let ref mut fresh38 = (*((*tok).stack)
                            .offset((*tok).depth as isize))
                            .obj_field_name;
                        *fresh38 = strdup((*(*tok).pb).buf);
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .saved_state = json_tokener_state_object_field_end;
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_eatws;
                        break;
                    } else if c as libc::c_int == '\\' as i32 {
                        if ((*(*tok).pb).size - (*(*tok).pb).bpos) as libc::c_long
                            > str.offset_from(case_start_3) as libc::c_long
                        {
                            memcpy(
                                ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                    as *mut libc::c_void,
                                case_start_3 as *const libc::c_void,
                                str.offset_from(case_start_3) as libc::c_long
                                    as libc::c_ulong,
                            );
                            let ref mut fresh39 = (*(*tok).pb).bpos;
                            *fresh39 = (*fresh39 as libc::c_long
                                + str.offset_from(case_start_3) as libc::c_long)
                                as libc::c_int;
                            *((*(*tok).pb).buf)
                                .offset(
                                    (*(*tok).pb).bpos as isize,
                                ) = '\u{0}' as i32 as libc::c_char;
                        } else {
                            printbuf_memappend(
                                (*tok).pb,
                                case_start_3,
                                str.offset_from(case_start_3) as libc::c_long as libc::c_int,
                            );
                        }
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .saved_state = json_tokener_state_object_field;
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_string_escape;
                        break;
                    } else {
                        str = str.offset(1);
                        let ref mut fresh40 = (*tok).char_offset;
                        *fresh40 += 1;
                        if !(c == 0
                            || (if (*tok).char_offset == len {
                                (if (*tok).depth == 0 as libc::c_int
                                    && (*((*tok).stack).offset((*tok).depth as isize)).state
                                        as libc::c_uint
                                        == json_tokener_state_eatws as libc::c_int as libc::c_uint
                                    && (*((*tok).stack).offset((*tok).depth as isize))
                                        .saved_state as libc::c_uint
                                        == json_tokener_state_finish as libc::c_int as libc::c_uint
                                {
                                    (*tok).err = json_tokener_success;
                                    0 as libc::c_int
                                } else {
                                    (*tok).err = json_tokener_continue;
                                    0 as libc::c_int
                                })
                            } else {
                                (if (*tok).flags & 0x10 as libc::c_int != 0
                                    && json_tokener_validate_utf8(*str, nBytesp) == 0
                                {
                                    (*tok).err = json_tokener_error_parse_utf8_string;
                                    0 as libc::c_int
                                } else {
                                    c = *str;
                                    1 as libc::c_int
                                })
                            }) == 0)
                        {
                            continue;
                        }
                        if ((*(*tok).pb).size - (*(*tok).pb).bpos) as libc::c_long
                            > str.offset_from(case_start_3) as libc::c_long
                        {
                            memcpy(
                                ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                    as *mut libc::c_void,
                                case_start_3 as *const libc::c_void,
                                str.offset_from(case_start_3) as libc::c_long
                                    as libc::c_ulong,
                            );
                            let ref mut fresh41 = (*(*tok).pb).bpos;
                            *fresh41 = (*fresh41 as libc::c_long
                                + str.offset_from(case_start_3) as libc::c_long)
                                as libc::c_int;
                            *((*(*tok).pb).buf)
                                .offset(
                                    (*(*tok).pb).bpos as isize,
                                ) = '\u{0}' as i32 as libc::c_char;
                        } else {
                            printbuf_memappend(
                                (*tok).pb,
                                case_start_3,
                                str.offset_from(case_start_3) as libc::c_long as libc::c_int,
                            );
                        }
                        break 's_76;
                    }
                }
                current_block = 14910428593596980134;
            }
            8644614806574383103 => {
                if c as libc::c_int == '"' as i32 || c as libc::c_int == '\'' as i32 {
                    (*tok).quote_char = c;
                    printbuf_reset((*tok).pb);
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .state = json_tokener_state_object_field;
                } else {
                    (*tok).err = json_tokener_error_parse_object_key_name;
                    break;
                }
                current_block = 14910428593596980134;
            }
            9952967170209510081 => {
                if (*((*tok).stack).offset((*tok).depth as isize)).state as libc::c_uint
                    == json_tokener_state_object_field_start_after_sep as libc::c_int
                        as libc::c_uint && (*tok).flags & 0x1 as libc::c_int != 0
                {
                    (*tok).err = json_tokener_error_parse_unexpected;
                    break;
                } else {
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .saved_state = json_tokener_state_finish;
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .state = json_tokener_state_eatws;
                }
                current_block = 14910428593596980134;
            }
            9898910953550671049 => {
                if c as libc::c_int == ',' as i32 {
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .saved_state = json_tokener_state_array_after_sep;
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .state = json_tokener_state_eatws;
                } else {
                    (*tok).err = json_tokener_error_parse_array;
                    break;
                }
                current_block = 14910428593596980134;
            }
            955764296456093747 => {
                (*((*tok).stack).offset((*tok).depth as isize))
                    .saved_state = json_tokener_state_finish;
                (*((*tok).stack).offset((*tok).depth as isize))
                    .state = json_tokener_state_eatws;
                current_block = 14910428593596980134;
            }
            16760829112842239754 => {
                if c as libc::c_int == ',' as i32 {
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .saved_state = json_tokener_state_object_field_start_after_sep;
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .state = json_tokener_state_eatws;
                } else {
                    (*tok).err = json_tokener_error_parse_object_value_sep;
                    break;
                }
                current_block = 14910428593596980134;
            }
            5600328731811258759 => {
                loop {
                    if c == 0 || is_hex_char(c) == 0 {
                        (*tok).err = json_tokener_error_parse_string;
                        break 's_76;
                    } else {
                        (*tok).ucs_char
                            |= ((if c as libc::c_int <= '9' as i32 {
                                c as libc::c_int - '0' as i32
                            } else {
                                (c as libc::c_int & 7 as libc::c_int) + 9 as libc::c_int
                            }) as libc::c_uint)
                                << (3 as libc::c_int - (*tok).st_pos) * 4 as libc::c_int;
                        let ref mut fresh25 = (*tok).st_pos;
                        *fresh25 += 1;
                        if (*tok).st_pos >= 4 as libc::c_int {
                            break;
                        }
                        str = str.offset(1);
                        let ref mut fresh26 = (*tok).char_offset;
                        *fresh26 += 1;
                        if !(if (*tok).char_offset == len {
                            if (*tok).depth == 0 as libc::c_int
                                && (*((*tok).stack).offset((*tok).depth as isize)).state
                                    as libc::c_uint
                                    == json_tokener_state_eatws as libc::c_int as libc::c_uint
                                && (*((*tok).stack).offset((*tok).depth as isize))
                                    .saved_state as libc::c_uint
                                    == json_tokener_state_finish as libc::c_int as libc::c_uint
                            {
                                (*tok).err = json_tokener_success;
                                0 as libc::c_int
                            } else {
                                (*tok).err = json_tokener_continue;
                                0 as libc::c_int
                            }
                        } else if (*tok).flags & 0x10 as libc::c_int != 0
                                && json_tokener_validate_utf8(*str, nBytesp) == 0
                            {
                            (*tok).err = json_tokener_error_parse_utf8_string;
                            0 as libc::c_int
                        } else {
                            c = *str;
                            1 as libc::c_int
                        } == 0)
                        {
                            continue;
                        }
                        break 's_76;
                    }
                }
                (*tok).st_pos = 0 as libc::c_int;
                if (*tok).high_surrogate != 0 {
                    if (*tok).ucs_char & 0xfc00 as libc::c_int as libc::c_uint
                        == 0xdc00 as libc::c_int as libc::c_uint
                    {
                        (*tok)
                            .ucs_char = (((*tok).high_surrogate
                            & 0x3ff as libc::c_int as libc::c_uint) << 10 as libc::c_int)
                            .wrapping_add(
                                (*tok).ucs_char & 0x3ff as libc::c_int as libc::c_uint,
                            )
                            .wrapping_add(0x10000 as libc::c_int as libc::c_uint);
                    } else if (*(*tok).pb).size - (*(*tok).pb).bpos > 3 as libc::c_int {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            utf8_replacement_char.as_mut_ptr() as *mut libc::c_char
                                as *const libc::c_void,
                            3 as libc::c_int as libc::c_ulong,
                        );
                        (*(*tok).pb).bpos += 3 as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend(
                            (*tok).pb,
                            utf8_replacement_char.as_mut_ptr() as *mut libc::c_char,
                            3 as libc::c_int,
                        );
                    }
                    (*tok).high_surrogate = 0 as libc::c_int as libc::c_uint;
                }
                if (*tok).ucs_char < 0x80 as libc::c_int as libc::c_uint {
                    let mut unescaped_utf: [libc::c_uchar; 1] = [0; 1];
                    unescaped_utf[0 as libc::c_int
                        as usize] = (*tok).ucs_char as libc::c_uchar;
                    if (*(*tok).pb).size - (*(*tok).pb).bpos > 1 as libc::c_int {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            unescaped_utf.as_mut_ptr() as *mut libc::c_char
                                as *const libc::c_void,
                            1 as libc::c_int as libc::c_ulong,
                        );
                        (*(*tok).pb).bpos += 1 as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend(
                            (*tok).pb,
                            unescaped_utf.as_mut_ptr() as *mut libc::c_char,
                            1 as libc::c_int,
                        );
                    }
                    current_block = 16438646162350502520;
                } else if (*tok).ucs_char < 0x800 as libc::c_int as libc::c_uint {
                    let mut unescaped_utf_0: [libc::c_uchar; 2] = [0; 2];
                    unescaped_utf_0[0 as libc::c_int
                        as usize] = (0xc0 as libc::c_int as libc::c_uint
                        | (*tok).ucs_char >> 6 as libc::c_int) as libc::c_uchar;
                    unescaped_utf_0[1 as libc::c_int
                        as usize] = (0x80 as libc::c_int as libc::c_uint
                        | (*tok).ucs_char & 0x3f as libc::c_int as libc::c_uint)
                        as libc::c_uchar;
                    if (*(*tok).pb).size - (*(*tok).pb).bpos > 2 as libc::c_int {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            unescaped_utf_0.as_mut_ptr() as *mut libc::c_char
                                as *const libc::c_void,
                            2 as libc::c_int as libc::c_ulong,
                        );
                        (*(*tok).pb).bpos += 2 as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend(
                            (*tok).pb,
                            unescaped_utf_0.as_mut_ptr() as *mut libc::c_char,
                            2 as libc::c_int,
                        );
                    }
                    current_block = 16438646162350502520;
                } else if (*tok).ucs_char & 0xfc00 as libc::c_int as libc::c_uint
                        == 0xd800 as libc::c_int as libc::c_uint
                    {
                    (*tok).high_surrogate = (*tok).ucs_char;
                    (*tok).ucs_char = 0 as libc::c_int as libc::c_uint;
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .state = json_tokener_state_escape_unicode_need_escape;
                    current_block = 14910428593596980134;
                } else {
                    if (*tok).ucs_char & 0xfc00 as libc::c_int as libc::c_uint
                        == 0xdc00 as libc::c_int as libc::c_uint
                    {
                        if (*(*tok).pb).size - (*(*tok).pb).bpos > 3 as libc::c_int {
                            memcpy(
                                ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                    as *mut libc::c_void,
                                utf8_replacement_char.as_mut_ptr() as *mut libc::c_char
                                    as *const libc::c_void,
                                3 as libc::c_int as libc::c_ulong,
                            );
                            (*(*tok).pb).bpos += 3 as libc::c_int;
                            *((*(*tok).pb).buf)
                                .offset(
                                    (*(*tok).pb).bpos as isize,
                                ) = '\u{0}' as i32 as libc::c_char;
                        } else {
                            printbuf_memappend(
                                (*tok).pb,
                                utf8_replacement_char.as_mut_ptr() as *mut libc::c_char,
                                3 as libc::c_int,
                            );
                        }
                    } else if (*tok).ucs_char < 0x10000 as libc::c_int as libc::c_uint {
                        let mut unescaped_utf_1: [libc::c_uchar; 3] = [0; 3];
                        unescaped_utf_1[0 as libc::c_int
                            as usize] = (0xe0 as libc::c_int as libc::c_uint
                            | (*tok).ucs_char >> 12 as libc::c_int) as libc::c_uchar;
                        unescaped_utf_1[1 as libc::c_int
                            as usize] = (0x80 as libc::c_int as libc::c_uint
                            | (*tok).ucs_char >> 6 as libc::c_int
                                & 0x3f as libc::c_int as libc::c_uint) as libc::c_uchar;
                        unescaped_utf_1[2 as libc::c_int
                            as usize] = (0x80 as libc::c_int as libc::c_uint
                            | (*tok).ucs_char & 0x3f as libc::c_int as libc::c_uint)
                            as libc::c_uchar;
                        if (*(*tok).pb).size - (*(*tok).pb).bpos > 3 as libc::c_int {
                            memcpy(
                                ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                    as *mut libc::c_void,
                                unescaped_utf_1.as_mut_ptr() as *mut libc::c_char
                                    as *const libc::c_void,
                                3 as libc::c_int as libc::c_ulong,
                            );
                            (*(*tok).pb).bpos += 3 as libc::c_int;
                            *((*(*tok).pb).buf)
                                .offset(
                                    (*(*tok).pb).bpos as isize,
                                ) = '\u{0}' as i32 as libc::c_char;
                        } else {
                            printbuf_memappend(
                                (*tok).pb,
                                unescaped_utf_1.as_mut_ptr() as *mut libc::c_char,
                                3 as libc::c_int,
                            );
                        }
                    } else if (*tok).ucs_char < 0x110000 as libc::c_int as libc::c_uint {
                        let mut unescaped_utf_2: [libc::c_uchar; 4] = [0; 4];
                        unescaped_utf_2[0 as libc::c_int
                            as usize] = (0xf0 as libc::c_int as libc::c_uint
                            | (*tok).ucs_char >> 18 as libc::c_int
                                & 0x7 as libc::c_int as libc::c_uint) as libc::c_uchar;
                        unescaped_utf_2[1 as libc::c_int
                            as usize] = (0x80 as libc::c_int as libc::c_uint
                            | (*tok).ucs_char >> 12 as libc::c_int
                                & 0x3f as libc::c_int as libc::c_uint) as libc::c_uchar;
                        unescaped_utf_2[2 as libc::c_int
                            as usize] = (0x80 as libc::c_int as libc::c_uint
                            | (*tok).ucs_char >> 6 as libc::c_int
                                & 0x3f as libc::c_int as libc::c_uint) as libc::c_uchar;
                        unescaped_utf_2[3 as libc::c_int
                            as usize] = (0x80 as libc::c_int as libc::c_uint
                            | (*tok).ucs_char & 0x3f as libc::c_int as libc::c_uint)
                            as libc::c_uchar;
                        if (*(*tok).pb).size - (*(*tok).pb).bpos > 4 as libc::c_int {
                            memcpy(
                                ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                    as *mut libc::c_void,
                                unescaped_utf_2.as_mut_ptr() as *mut libc::c_char
                                    as *const libc::c_void,
                                4 as libc::c_int as libc::c_ulong,
                            );
                            (*(*tok).pb).bpos += 4 as libc::c_int;
                            *((*(*tok).pb).buf)
                                .offset(
                                    (*(*tok).pb).bpos as isize,
                                ) = '\u{0}' as i32 as libc::c_char;
                        } else {
                            printbuf_memappend(
                                (*tok).pb,
                                unescaped_utf_2.as_mut_ptr() as *mut libc::c_char,
                                4 as libc::c_int,
                            );
                        }
                    } else if (*(*tok).pb).size - (*(*tok).pb).bpos > 3 as libc::c_int {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            utf8_replacement_char.as_mut_ptr() as *mut libc::c_char
                                as *const libc::c_void,
                            3 as libc::c_int as libc::c_ulong,
                        );
                        (*(*tok).pb).bpos += 3 as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend(
                            (*tok).pb,
                            utf8_replacement_char.as_mut_ptr() as *mut libc::c_char,
                            3 as libc::c_int,
                        );
                    }
                    current_block = 16438646162350502520;
                }
                match current_block {
                    14910428593596980134 => {}
                    _ => {
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = (*((*tok).stack).offset((*tok).depth as isize))
                            .saved_state;
                        current_block = 14910428593596980134;
                    }
                }
            }
            17501499944854094182 => {
                (*tok).ucs_char = 0 as libc::c_int as libc::c_uint;
                (*tok).st_pos = 0 as libc::c_int;
                (*((*tok).stack).offset((*tok).depth as isize))
                    .state = json_tokener_state_escape_unicode;
                current_block = 14910428593596980134;
            }
            902433882565356955 => {
                if c as libc::c_int == 'b' as i32 {
                    if (*(*tok).pb).size - (*(*tok).pb).bpos > 1 as libc::c_int {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            b"\x08\0" as *const u8 as *const libc::c_char
                                as *const libc::c_void,
                            1 as libc::c_int as libc::c_ulong,
                        );
                        (*(*tok).pb).bpos += 1 as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend(
                            (*tok).pb,
                            b"\x08\0" as *const u8 as *const libc::c_char,
                            1 as libc::c_int,
                        );
                    }
                } else if c as libc::c_int == 'n' as i32 {
                    if (*(*tok).pb).size - (*(*tok).pb).bpos > 1 as libc::c_int {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            b"\n\0" as *const u8 as *const libc::c_char
                                as *const libc::c_void,
                            1 as libc::c_int as libc::c_ulong,
                        );
                        (*(*tok).pb).bpos += 1 as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend(
                            (*tok).pb,
                            b"\n\0" as *const u8 as *const libc::c_char,
                            1 as libc::c_int,
                        );
                    }
                } else if c as libc::c_int == 'r' as i32 {
                    if (*(*tok).pb).size - (*(*tok).pb).bpos > 1 as libc::c_int {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            b"\r\0" as *const u8 as *const libc::c_char
                                as *const libc::c_void,
                            1 as libc::c_int as libc::c_ulong,
                        );
                        (*(*tok).pb).bpos += 1 as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend(
                            (*tok).pb,
                            b"\r\0" as *const u8 as *const libc::c_char,
                            1 as libc::c_int,
                        );
                    }
                } else if c as libc::c_int == 't' as i32 {
                    if (*(*tok).pb).size - (*(*tok).pb).bpos > 1 as libc::c_int {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            b"\t\0" as *const u8 as *const libc::c_char
                                as *const libc::c_void,
                            1 as libc::c_int as libc::c_ulong,
                        );
                        (*(*tok).pb).bpos += 1 as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend(
                            (*tok).pb,
                            b"\t\0" as *const u8 as *const libc::c_char,
                            1 as libc::c_int,
                        );
                    }
                } else if c as libc::c_int == 'f' as i32 {
                    if (*(*tok).pb).size - (*(*tok).pb).bpos > 1 as libc::c_int {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            b"\x0C\0" as *const u8 as *const libc::c_char
                                as *const libc::c_void,
                            1 as libc::c_int as libc::c_ulong,
                        );
                        (*(*tok).pb).bpos += 1 as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend(
                            (*tok).pb,
                            b"\x0C\0" as *const u8 as *const libc::c_char,
                            1 as libc::c_int,
                        );
                    }
                }
                (*((*tok).stack).offset((*tok).depth as isize))
                    .state = (*((*tok).stack).offset((*tok).depth as isize)).saved_state;
                current_block = 14910428593596980134;
            }
            5851233167266824712 => {
                if (*(*tok).pb).size - (*(*tok).pb).bpos > 1 as libc::c_int {
                    memcpy(
                        ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                            as *mut libc::c_void,
                        &mut c as *mut libc::c_char as *const libc::c_void,
                        1 as libc::c_int as libc::c_ulong,
                    );
                    (*(*tok).pb).bpos += 1 as libc::c_int;
                    *((*(*tok).pb).buf)
                        .offset(
                            (*(*tok).pb).bpos as isize,
                        ) = '\u{0}' as i32 as libc::c_char;
                } else {
                    printbuf_memappend((*tok).pb, &mut c, 1 as libc::c_int);
                }
                (*((*tok).stack).offset((*tok).depth as isize))
                    .state = (*((*tok).stack).offset((*tok).depth as isize)).saved_state;
                current_block = 14910428593596980134;
            }
            13526015532137226550 => {
                loop {
                    if c as libc::c_int == (*tok).quote_char as libc::c_int {
                        if ((*(*tok).pb).size - (*(*tok).pb).bpos) as libc::c_long
                            > str.offset_from(case_start_1) as libc::c_long
                        {
                            memcpy(
                                ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                    as *mut libc::c_void,
                                case_start_1 as *const libc::c_void,
                                str.offset_from(case_start_1) as libc::c_long
                                    as libc::c_ulong,
                            );
                            let ref mut fresh20 = (*(*tok).pb).bpos;
                            *fresh20 = (*fresh20 as libc::c_long
                                + str.offset_from(case_start_1) as libc::c_long)
                                as libc::c_int;
                            *((*(*tok).pb).buf)
                                .offset(
                                    (*(*tok).pb).bpos as isize,
                                ) = '\u{0}' as i32 as libc::c_char;
                        } else {
                            printbuf_memappend(
                                (*tok).pb,
                                case_start_1,
                                str.offset_from(case_start_1) as libc::c_long as libc::c_int,
                            );
                        }
                        let ref mut fresh21 = (*((*tok).stack)
                            .offset((*tok).depth as isize))
                            .current;
                        *fresh21 = json_object_new_string_len(
                            (*(*tok).pb).buf,
                            (*(*tok).pb).bpos,
                        );
                        if ((*((*tok).stack).offset((*tok).depth as isize)).current)
                            .is_null()
                        {
                            break 's_76;
                        }
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .saved_state = json_tokener_state_finish;
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_eatws;
                        break;
                    } else if c as libc::c_int == '\\' as i32 {
                        if ((*(*tok).pb).size - (*(*tok).pb).bpos) as libc::c_long
                            > str.offset_from(case_start_1) as libc::c_long
                        {
                            memcpy(
                                ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                    as *mut libc::c_void,
                                case_start_1 as *const libc::c_void,
                                str.offset_from(case_start_1) as libc::c_long
                                    as libc::c_ulong,
                            );
                            let ref mut fresh22 = (*(*tok).pb).bpos;
                            *fresh22 = (*fresh22 as libc::c_long
                                + str.offset_from(case_start_1) as libc::c_long)
                                as libc::c_int;
                            *((*(*tok).pb).buf)
                                .offset(
                                    (*(*tok).pb).bpos as isize,
                                ) = '\u{0}' as i32 as libc::c_char;
                        } else {
                            printbuf_memappend(
                                (*tok).pb,
                                case_start_1,
                                str.offset_from(case_start_1) as libc::c_long as libc::c_int,
                            );
                        }
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .saved_state = json_tokener_state_string;
                        (*((*tok).stack).offset((*tok).depth as isize))
                            .state = json_tokener_state_string_escape;
                        break;
                    } else {
                        str = str.offset(1);
                        let ref mut fresh23 = (*tok).char_offset;
                        *fresh23 += 1;
                        if !(c == 0
                            || (if (*tok).char_offset == len {
                                (if (*tok).depth == 0 as libc::c_int
                                    && (*((*tok).stack).offset((*tok).depth as isize)).state
                                        as libc::c_uint
                                        == json_tokener_state_eatws as libc::c_int as libc::c_uint
                                    && (*((*tok).stack).offset((*tok).depth as isize))
                                        .saved_state as libc::c_uint
                                        == json_tokener_state_finish as libc::c_int as libc::c_uint
                                {
                                    (*tok).err = json_tokener_success;
                                    0 as libc::c_int
                                } else {
                                    (*tok).err = json_tokener_continue;
                                    0 as libc::c_int
                                })
                            } else {
                                (if (*tok).flags & 0x10 as libc::c_int != 0
                                    && json_tokener_validate_utf8(*str, nBytesp) == 0
                                {
                                    (*tok).err = json_tokener_error_parse_utf8_string;
                                    0 as libc::c_int
                                } else {
                                    c = *str;
                                    1 as libc::c_int
                                })
                            }) == 0)
                        {
                            continue;
                        }
                        if ((*(*tok).pb).size - (*(*tok).pb).bpos) as libc::c_long
                            > str.offset_from(case_start_1) as libc::c_long
                        {
                            memcpy(
                                ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                    as *mut libc::c_void,
                                case_start_1 as *const libc::c_void,
                                str.offset_from(case_start_1) as libc::c_long
                                    as libc::c_ulong,
                            );
                            let ref mut fresh24 = (*(*tok).pb).bpos;
                            *fresh24 = (*fresh24 as libc::c_long
                                + str.offset_from(case_start_1) as libc::c_long)
                                as libc::c_int;
                            *((*(*tok).pb).buf)
                                .offset(
                                    (*(*tok).pb).bpos as isize,
                                ) = '\u{0}' as i32 as libc::c_char;
                        } else {
                            printbuf_memappend(
                                (*tok).pb,
                                case_start_1,
                                str.offset_from(case_start_1) as libc::c_long as libc::c_int,
                            );
                        }
                        break 's_76;
                    }
                }
                current_block = 14910428593596980134;
            }
            6662862405959679103 => {
                while c as libc::c_int != '\n' as i32 {
                    str = str.offset(1);
                    let ref mut fresh17 = (*tok).char_offset;
                    *fresh17 += 1;
                    if !(c == 0
                        || (if (*tok).char_offset == len {
                            (if (*tok).depth == 0 as libc::c_int
                                && (*((*tok).stack).offset((*tok).depth as isize)).state
                                    as libc::c_uint
                                    == json_tokener_state_eatws as libc::c_int as libc::c_uint
                                && (*((*tok).stack).offset((*tok).depth as isize))
                                    .saved_state as libc::c_uint
                                    == json_tokener_state_finish as libc::c_int as libc::c_uint
                            {
                                (*tok).err = json_tokener_success;
                                0 as libc::c_int
                            } else {
                                (*tok).err = json_tokener_continue;
                                0 as libc::c_int
                            })
                        } else {
                            (if (*tok).flags & 0x10 as libc::c_int != 0
                                && json_tokener_validate_utf8(*str, nBytesp) == 0
                            {
                                (*tok).err = json_tokener_error_parse_utf8_string;
                                0 as libc::c_int
                            } else {
                                c = *str;
                                1 as libc::c_int
                            })
                        }) == 0)
                    {
                        continue;
                    }
                    if ((*(*tok).pb).size - (*(*tok).pb).bpos) as libc::c_long
                        > str.offset_from(case_start_0) as libc::c_long
                    {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            case_start_0 as *const libc::c_void,
                            str.offset_from(case_start_0) as libc::c_long
                                as libc::c_ulong,
                        );
                        let ref mut fresh18 = (*(*tok).pb).bpos;
                        *fresh18 = (*fresh18 as libc::c_long
                            + str.offset_from(case_start_0) as libc::c_long)
                            as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend(
                            (*tok).pb,
                            case_start_0,
                            str.offset_from(case_start_0) as libc::c_long as libc::c_int,
                        );
                    }
                    break 's_76;
                }
                if ((*(*tok).pb).size - (*(*tok).pb).bpos) as libc::c_long
                    > str.offset_from(case_start_0) as libc::c_long
                {
                    memcpy(
                        ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                            as *mut libc::c_void,
                        case_start_0 as *const libc::c_void,
                        str.offset_from(case_start_0) as libc::c_long as libc::c_ulong,
                    );
                    let ref mut fresh19 = (*(*tok).pb).bpos;
                    *fresh19 = (*fresh19 as libc::c_long
                        + str.offset_from(case_start_0) as libc::c_long) as libc::c_int;
                    *((*(*tok).pb).buf)
                        .offset(
                            (*(*tok).pb).bpos as isize,
                        ) = '\u{0}' as i32 as libc::c_char;
                } else {
                    printbuf_memappend(
                        (*tok).pb,
                        case_start_0,
                        str.offset_from(case_start_0) as libc::c_long as libc::c_int,
                    );
                }
                (*((*tok).stack).offset((*tok).depth as isize))
                    .state = json_tokener_state_eatws;
                current_block = 14910428593596980134;
            }
            18221534353613080499 => {
                while c as libc::c_int != '*' as i32 {
                    str = str.offset(1);
                    let ref mut fresh14 = (*tok).char_offset;
                    *fresh14 += 1;
                    if !(c == 0
                        || (if (*tok).char_offset == len {
                            (if (*tok).depth == 0 as libc::c_int
                                && (*((*tok).stack).offset((*tok).depth as isize)).state
                                    as libc::c_uint
                                    == json_tokener_state_eatws as libc::c_int as libc::c_uint
                                && (*((*tok).stack).offset((*tok).depth as isize))
                                    .saved_state as libc::c_uint
                                    == json_tokener_state_finish as libc::c_int as libc::c_uint
                            {
                                (*tok).err = json_tokener_success;
                                0 as libc::c_int
                            } else {
                                (*tok).err = json_tokener_continue;
                                0 as libc::c_int
                            })
                        } else {
                            (if (*tok).flags & 0x10 as libc::c_int != 0
                                && json_tokener_validate_utf8(*str, nBytesp) == 0
                            {
                                (*tok).err = json_tokener_error_parse_utf8_string;
                                0 as libc::c_int
                            } else {
                                c = *str;
                                1 as libc::c_int
                            })
                        }) == 0)
                    {
                        continue;
                    }
                    if ((*(*tok).pb).size - (*(*tok).pb).bpos) as libc::c_long
                        > str.offset_from(case_start) as libc::c_long
                    {
                        memcpy(
                            ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                                as *mut libc::c_void,
                            case_start as *const libc::c_void,
                            str.offset_from(case_start) as libc::c_long as libc::c_ulong,
                        );
                        let ref mut fresh15 = (*(*tok).pb).bpos;
                        *fresh15 = (*fresh15 as libc::c_long
                            + str.offset_from(case_start) as libc::c_long)
                            as libc::c_int;
                        *((*(*tok).pb).buf)
                            .offset(
                                (*(*tok).pb).bpos as isize,
                            ) = '\u{0}' as i32 as libc::c_char;
                    } else {
                        printbuf_memappend(
                            (*tok).pb,
                            case_start,
                            str.offset_from(case_start) as libc::c_long as libc::c_int,
                        );
                    }
                    break 's_76;
                }
                if ((*(*tok).pb).size - (*(*tok).pb).bpos) as libc::c_long
                    > str.offset(1 as libc::c_int as isize).offset_from(case_start)
                        as libc::c_long
                {
                    memcpy(
                        ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                            as *mut libc::c_void,
                        case_start as *const libc::c_void,
                        str.offset(1 as libc::c_int as isize).offset_from(case_start)
                            as libc::c_long as libc::c_ulong,
                    );
                    let ref mut fresh16 = (*(*tok).pb).bpos;
                    *fresh16 = (*fresh16 as libc::c_long
                        + str.offset(1 as libc::c_int as isize).offset_from(case_start)
                            as libc::c_long) as libc::c_int;
                    *((*(*tok).pb).buf)
                        .offset(
                            (*(*tok).pb).bpos as isize,
                        ) = '\u{0}' as i32 as libc::c_char;
                } else {
                    printbuf_memappend(
                        (*tok).pb,
                        case_start,
                        str.offset(1 as libc::c_int as isize).offset_from(case_start)
                            as libc::c_long as libc::c_int,
                    );
                }
                (*((*tok).stack).offset((*tok).depth as isize))
                    .state = json_tokener_state_comment_end;
                current_block = 14910428593596980134;
            }
            17917672080766325409 => {
                if c as libc::c_int == '/' as i32 {
                    (*((*tok).stack).offset((*tok).depth as isize))
                        .state = json_tokener_state_comment_eol;
                } else {
                    (*tok).err = json_tokener_error_parse_comment;
                    break;
                }
                current_block = 6988365858197790817;
            }
            5965298418754406754 => {
                (*((*tok).stack).offset((*tok).depth as isize))
                    .state = json_tokener_state_string;
                printbuf_reset((*tok).pb);
                (*tok).quote_char = c;
                current_block = 14910428593596980134;
            }
            5524635047616071233 => {
                (*tok).err = json_tokener_error_parse_unexpected;
                break;
            }
            11162283542402356847 => {
                (*((*tok).stack).offset((*tok).depth as isize))
                    .state = json_tokener_state_comment;
                current_block = 6988365858197790817;
            }
            15463013039495622015 => {
                (*tok).err = json_tokener_error_parse_string;
                break;
            }
            5151117443143562747 => {
                (*tok).err = json_tokener_error_parse_object_key_sep;
                break;
            }
            10945600426047866894 => {
                (*((*tok).stack).offset((*tok).depth as isize))
                    .saved_state = json_tokener_state_finish;
                (*((*tok).stack).offset((*tok).depth as isize))
                    .state = json_tokener_state_eatws;
                current_block = 14910428593596980134;
            }
            14575203612169622940 => {
                (*((*tok).stack).offset((*tok).depth as isize))
                    .saved_state = json_tokener_state_object_value;
                (*((*tok).stack).offset((*tok).depth as isize))
                    .state = json_tokener_state_eatws;
                current_block = 14910428593596980134;
            }
            7990025728955927862 => {
                (*tok).err = json_tokener_error_parse_unexpected;
                break;
            }
            17927085222977126794 => {
                json_object_array_shrink(
                    (*((*tok).stack).offset((*tok).depth as isize)).current,
                    0 as libc::c_int,
                );
                (*((*tok).stack).offset((*tok).depth as isize))
                    .saved_state = json_tokener_state_finish;
                (*((*tok).stack).offset((*tok).depth as isize))
                    .state = json_tokener_state_eatws;
                current_block = 14910428593596980134;
            }
            13823707972521062695 => {
                let ref mut fresh13 = (*tok).st_pos;
                *fresh13 += 1;
                current_block = 14910428593596980134;
            }
            6015864261243718670 => {
                let ref mut fresh29 = (*tok).st_pos;
                *fresh29 += 1;
                current_block = 14910428593596980134;
            }
            _ => {}
        }
        match current_block {
            6988365858197790817 => {
                if (*(*tok).pb).size - (*(*tok).pb).bpos > 1 as libc::c_int {
                    memcpy(
                        ((*(*tok).pb).buf).offset((*(*tok).pb).bpos as isize)
                            as *mut libc::c_void,
                        &mut c as *mut libc::c_char as *const libc::c_void,
                        1 as libc::c_int as libc::c_ulong,
                    );
                    (*(*tok).pb).bpos += 1 as libc::c_int;
                    *((*(*tok).pb).buf)
                        .offset(
                            (*(*tok).pb).bpos as isize,
                        ) = '\u{0}' as i32 as libc::c_char;
                } else {
                    printbuf_memappend((*tok).pb, &mut c, 1 as libc::c_int);
                }
            }
            _ => {}
        }
        str = str.offset(1);
        let ref mut fresh44 = (*tok).char_offset;
        *fresh44 += 1;
        if c == 0 {
            break;
        }
    }
    if (*tok).flags & 0x10 as libc::c_int != 0
        && nBytes != 0 as libc::c_int as libc::c_uint
    {
        (*tok).err = json_tokener_error_parse_utf8_string;
    }
    if c as libc::c_int != 0
        && (*((*tok).stack).offset((*tok).depth as isize)).state as libc::c_uint
            == json_tokener_state_finish as libc::c_int as libc::c_uint
        && (*tok).depth == 0 as libc::c_int
        && (*tok).flags & (0x1 as libc::c_int | 0x2 as libc::c_int) == 0x1 as libc::c_int
    {
        (*tok).err = json_tokener_error_parse_unexpected;
    }
    if c == 0 {
        if (*((*tok).stack).offset((*tok).depth as isize)).state as libc::c_uint
            != json_tokener_state_finish as libc::c_int as libc::c_uint
            && (*((*tok).stack).offset((*tok).depth as isize)).saved_state
                as libc::c_uint
                != json_tokener_state_finish as libc::c_int as libc::c_uint
        {
            (*tok).err = json_tokener_error_parse_eof;
        }
    }
    uselocale(oldlocale);
    freelocale(newloc);
    if (*tok).err as libc::c_uint == json_tokener_success as libc::c_int as libc::c_uint
    {
        let mut ret: *mut json_object = json_object_get(
            (*((*tok).stack).offset((*tok).depth as isize)).current,
        );
        let mut ii: libc::c_int = 0;
        ii = (*tok).depth;
        while ii >= 0 as libc::c_int {
            json_tokener_reset_level(tok, ii);
            ii -= 1;
        }
        return ret;
    }
    return 0 as *mut json_object;
}
unsafe extern "C" fn json_tokener_validate_utf8(
    c: libc::c_char,
    mut nBytes: *mut libc::c_uint,
) -> json_bool {
    let mut chr: libc::c_uchar = c as libc::c_uchar;
    if *nBytes == 0 as libc::c_int as libc::c_uint {
        if chr as libc::c_int >= 0x80 as libc::c_int {
            if chr as libc::c_int & 0xe0 as libc::c_int == 0xc0 as libc::c_int {
                *nBytes = 1 as libc::c_int as libc::c_uint;
            } else if chr as libc::c_int & 0xf0 as libc::c_int == 0xe0 as libc::c_int {
                *nBytes = 2 as libc::c_int as libc::c_uint;
            } else if chr as libc::c_int & 0xf8 as libc::c_int == 0xf0 as libc::c_int {
                *nBytes = 3 as libc::c_int as libc::c_uint;
            } else {
                return 0 as libc::c_int
            }
        }
    } else {
        if chr as libc::c_int & 0xc0 as libc::c_int != 0x80 as libc::c_int {
            return 0 as libc::c_int;
        }
        *nBytes = (*nBytes).wrapping_sub(1);
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn json_tokener_set_flags(
    mut tok: *mut json_tokener,
    mut flags: libc::c_int,
) {
    (*tok).flags = flags;
}
#[no_mangle]
pub unsafe extern "C" fn json_tokener_get_parse_end(
    mut tok: *mut json_tokener,
) -> size_t {
    if (*tok).char_offset >= 0 as libc::c_int {} else {
        __assert_fail(
            b"tok->char_offset >= 0\0" as *const u8 as *const libc::c_char,
            b"/home/xial/json-c/json_tokener.c\0" as *const u8 as *const libc::c_char,
            1300 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 57],
                &[libc::c_char; 57],
            >(b"size_t json_tokener_get_parse_end(struct json_tokener *)\0"))
                .as_ptr(),
        );
    }
    return (*tok).char_offset as size_t;
}
unsafe extern "C" fn json_tokener_parse_double(
    mut buf: *const libc::c_char,
    mut len: libc::c_int,
    mut retval: *mut libc::c_double,
) -> libc::c_int {
    let mut end: *mut libc::c_char = 0 as *mut libc::c_char;
    *retval = strtod(buf, &mut end);
    if buf.offset(len as isize) == end as *const libc::c_char {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn run_static_initializers() {
    json_null_str_len = (::std::mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int;
    json_inf_str_len = (::std::mem::size_of::<[libc::c_char; 9]>() as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_uint;
    json_nan_str_len = (::std::mem::size_of::<[libc::c_char; 4]>() as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int;
    json_true_str_len = (::std::mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int;
    json_false_str_len = (::std::mem::size_of::<[libc::c_char; 6]>() as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int;
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
