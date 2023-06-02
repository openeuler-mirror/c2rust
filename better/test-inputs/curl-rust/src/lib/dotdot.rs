use ::libc;
extern "C" {
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
}
pub type size_t = libc::c_ulong;
pub type curl_malloc_callback = Option::<
    unsafe extern "C" fn(size_t) -> *mut libc::c_void,
>;
pub type curl_free_callback = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_strdup_callback = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
>;
#[no_mangle]
pub unsafe extern "C" fn Curl_dedotdotify(
    mut input: *const libc::c_char,
) -> *mut libc::c_char {
    let mut inlen: size_t = strlen(input);
    let mut clone: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut clen: size_t = inlen;
    let mut out: *mut libc::c_char = Curl_cmalloc
        .expect(
            "non-null function pointer",
        )(inlen.wrapping_add(1 as libc::c_int as libc::c_ulong)) as *mut libc::c_char;
    let mut outptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut orgclone: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut queryp: *mut libc::c_char = 0 as *mut libc::c_char;
    if out.is_null() {
        return 0 as *mut libc::c_char;
    }
    *out = 0 as libc::c_int as libc::c_char;
    clone = Curl_cstrdup.expect("non-null function pointer")(input);
    if clone.is_null() {
        Curl_cfree.expect("non-null function pointer")(out as *mut libc::c_void);
        return 0 as *mut libc::c_char;
    }
    orgclone = clone;
    outptr = out;
    if *clone == 0 {
        Curl_cfree.expect("non-null function pointer")(out as *mut libc::c_void);
        return clone;
    }
    queryp = strchr(clone, '?' as i32);
    if !queryp.is_null() {
        *queryp = 0 as libc::c_int as libc::c_char;
    }
    loop {
        if strncmp(
            b"./\0" as *const u8 as *const libc::c_char,
            clone,
            2 as libc::c_int as libc::c_ulong,
        ) == 0
        {
            clone = clone.offset(2 as libc::c_int as isize);
            clen = (clen as libc::c_ulong)
                .wrapping_sub(2 as libc::c_int as libc::c_ulong) as size_t as size_t;
        } else if strncmp(
                b"../\0" as *const u8 as *const libc::c_char,
                clone,
                3 as libc::c_int as libc::c_ulong,
            ) == 0
            {
            clone = clone.offset(3 as libc::c_int as isize);
            clen = (clen as libc::c_ulong)
                .wrapping_sub(3 as libc::c_int as libc::c_ulong) as size_t as size_t;
        } else if strncmp(
                b"/./\0" as *const u8 as *const libc::c_char,
                clone,
                3 as libc::c_int as libc::c_ulong,
            ) == 0
            {
            clone = clone.offset(2 as libc::c_int as isize);
            clen = (clen as libc::c_ulong)
                .wrapping_sub(2 as libc::c_int as libc::c_ulong) as size_t as size_t;
        } else if strcmp(b"/.\0" as *const u8 as *const libc::c_char, clone) == 0 {
            *clone.offset(1 as libc::c_int as isize) = '/' as i32 as libc::c_char;
            clone = clone.offset(1);
            clen = (clen as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as size_t as size_t;
        } else if strncmp(
                b"/../\0" as *const u8 as *const libc::c_char,
                clone,
                4 as libc::c_int as libc::c_ulong,
            ) == 0
            {
            clone = clone.offset(3 as libc::c_int as isize);
            clen = (clen as libc::c_ulong)
                .wrapping_sub(3 as libc::c_int as libc::c_ulong) as size_t as size_t;
            while outptr > out {
                outptr = outptr.offset(-1);
                if *outptr as libc::c_int == '/' as i32 {
                    break;
                }
            }
            *outptr = 0 as libc::c_int as libc::c_char;
        } else if strcmp(b"/..\0" as *const u8 as *const libc::c_char, clone) == 0 {
            *clone.offset(2 as libc::c_int as isize) = '/' as i32 as libc::c_char;
            clone = clone.offset(2 as libc::c_int as isize);
            clen = (clen as libc::c_ulong)
                .wrapping_sub(2 as libc::c_int as libc::c_ulong) as size_t as size_t;
            while outptr > out {
                outptr = outptr.offset(-1);
                if *outptr as libc::c_int == '/' as i32 {
                    break;
                }
            }
            *outptr = 0 as libc::c_int as libc::c_char;
        } else if strcmp(b".\0" as *const u8 as *const libc::c_char, clone) == 0
                || strcmp(b"..\0" as *const u8 as *const libc::c_char, clone) == 0
            {
            *clone = 0 as libc::c_int as libc::c_char;
            *out = 0 as libc::c_int as libc::c_char;
        } else {
            loop {
                let fresh0 = clone;
                clone = clone.offset(1);
                let fresh1 = outptr;
                outptr = outptr.offset(1);
                *fresh1 = *fresh0;
                clen = clen.wrapping_sub(1);
                if !(*clone as libc::c_int != 0 && *clone as libc::c_int != '/' as i32) {
                    break;
                }
            }
            *outptr = 0 as libc::c_int as libc::c_char;
        }
        if !(*clone != 0) {
            break;
        }
    }
    if !queryp.is_null() {
        let mut qlen: size_t = 0;
        let mut oindex: size_t = queryp.offset_from(orgclone) as libc::c_long as size_t;
        qlen = strlen(&*input.offset(oindex as isize));
        memcpy(
            outptr as *mut libc::c_void,
            &*input.offset(oindex as isize) as *const libc::c_char
                as *const libc::c_void,
            qlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
        );
    }
    Curl_cfree.expect("non-null function pointer")(orgclone as *mut libc::c_void);
    return out;
}
