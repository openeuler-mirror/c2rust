use ::libc;
extern "C" {
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn strcmp(_: * const i8, _: * const i8) -> i32;
    fn strncmp(
        _: * const i8,
        _: * const i8,
        _: u64,
    ) -> i32;
    fn strchr(_: * const i8, _: i32) -> * mut i8;
    fn strlen(_: * const i8) -> u64;
    
    
    
}
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::easy::Curl_cstrdup;
pub type size_t = u64;
pub type curl_malloc_callback<'a1> = Option<unsafe extern "C"  fn(_: u64,) -> Option<&'a1 mut core::ffi::c_void>>;
pub type curl_free_callback<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
pub type curl_strdup_callback<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 i8>,) -> Option<&'a2 mut i8>>;
#[no_mangle]
pub unsafe extern "C" fn Curl_dedotdotify(
    mut input: * const i8,
) -> * mut i8 {
    let mut inlen: u64 = strlen(input);
    let mut clone: * mut i8 = 0 as *mut i8;
    let mut clen: u64 = inlen;
    let mut out: * mut i8 = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(inlen.wrapping_add(1 as i32 as u64)) as *mut i8;
    let mut outptr: * mut i8 = 0 as *mut i8;
    let mut orgclone: * mut i8 = 0 as *mut i8;
    let mut queryp: * mut i8 = 0 as *mut i8;
    if out.is_null() {
        return 0 as *mut i8;
    }
    *out = 0 as i32 as i8;
    clone = Curl_cstrdup.expect("non-null function pointer")(input);
    if clone.is_null() {
        Curl_cfree.expect("non-null function pointer")(out as *mut libc::c_void);
        return 0 as *mut i8;
    }
    orgclone = clone;
    outptr = out;
    if *clone == 0 {
        Curl_cfree.expect("non-null function pointer")(out as *mut libc::c_void);
        return clone;
    }
    queryp = strchr(clone, '?' as i32);
    if !queryp.is_null() {
        *queryp = 0 as i32 as i8;
    }
    loop {
        if strncmp(
            b"./\0" as *const u8 as *const i8,
            clone,
            2 as i32 as u64,
        ) == 0
        {
            clone = clone.offset(2 as i32 as isize);
            clen = (clen as u64)
                .wrapping_sub(2 as i32 as u64) as size_t as size_t;
        } else if strncmp(
                b"../\0" as *const u8 as *const i8,
                clone,
                3 as i32 as u64,
            ) == 0
            {
            clone = clone.offset(3 as i32 as isize);
            clen = (clen as u64)
                .wrapping_sub(3 as i32 as u64) as size_t as size_t;
        } else if strncmp(
                b"/./\0" as *const u8 as *const i8,
                clone,
                3 as i32 as u64,
            ) == 0
            {
            clone = clone.offset(2 as i32 as isize);
            clen = (clen as u64)
                .wrapping_sub(2 as i32 as u64) as size_t as size_t;
        } else if strcmp(b"/.\0" as *const u8 as *const i8, clone) == 0 {
            *clone.offset(1 as i32 as isize) = '/' as i32 as i8;
            clone = clone.offset(1);
            clen = (clen as u64)
                .wrapping_sub(1 as i32 as u64) as size_t as size_t;
        } else if strncmp(
                b"/../\0" as *const u8 as *const i8,
                clone,
                4 as i32 as u64,
            ) == 0
            {
            clone = clone.offset(3 as i32 as isize);
            clen = (clen as u64)
                .wrapping_sub(3 as i32 as u64) as size_t as size_t;
            while outptr > out {
                outptr = outptr.offset(-1);
                if *outptr as i32 == '/' as i32 {
                    break;
                }
            }
            *outptr = 0 as i32 as i8;
        } else if strcmp(b"/..\0" as *const u8 as *const i8, clone) == 0 {
            *clone.offset(2 as i32 as isize) = '/' as i32 as i8;
            clone = clone.offset(2 as i32 as isize);
            clen = (clen as u64)
                .wrapping_sub(2 as i32 as u64) as size_t as size_t;
            while outptr > out {
                outptr = outptr.offset(-1);
                if *outptr as i32 == '/' as i32 {
                    break;
                }
            }
            *outptr = 0 as i32 as i8;
        } else if strcmp(b".\0" as *const u8 as *const i8, clone) == 0
                || strcmp(b"..\0" as *const u8 as *const i8, clone) == 0
            {
            *clone = 0 as i32 as i8;
            *out = 0 as i32 as i8;
        } else {
            loop {
                let mut fresh0 = clone;
                clone = clone.offset(1);
                let mut fresh1 = outptr;
                outptr = outptr.offset(1);
                *fresh1 = *fresh0;
                clen = clen.wrapping_sub(1);
                if !(*clone as i32 != 0 && *clone as i32 != '/' as i32) {
                    break;
                }
            }
            *outptr = 0 as i32 as i8;
        }
        if !(*clone != 0) {
            break;
        }
    }
    if !queryp.is_null() {
        let mut qlen: u64 = 0;
        let mut oindex: u64 = queryp.offset_from(orgclone) as i64 as size_t;
        qlen = strlen(&*input.offset(oindex as isize));
        memcpy(
            outptr as *mut libc::c_void,
            &*input.offset(oindex as isize) as *const i8
                as *const libc::c_void,
            qlen.wrapping_add(1 as i32 as u64),
        );
    }
    Curl_cfree.expect("non-null function pointer")(orgclone as *mut libc::c_void);
    return out;
}
use crate::laertes_rt::*;
