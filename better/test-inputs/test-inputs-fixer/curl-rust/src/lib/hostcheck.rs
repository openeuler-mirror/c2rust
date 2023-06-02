use :: libc;
extern "C" {
    fn strchr(_: *const i8, _: i32) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn Curl_strcasecompare(first: *const i8, second: *const i8) -> i32;
    fn Curl_strncasecompare(first: *const i8, second: *const i8, max: size_t) -> i32;
    fn Curl_host_is_ipnum(hostname: *const i8) -> bool;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
}
pub type size_t = u64;
pub type curl_free_callback = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_strdup_callback = Option<unsafe extern "C" fn(*const i8) -> *mut i8>;
extern "C" fn hostmatch(mut hostname: *mut i8, mut pattern: *mut i8) -> i32 {
    let mut pattern_label_end: *const i8 = 0 as *const i8;
    let mut pattern_wildcard: *const i8 = 0 as *const i8;
    let mut hostname_label_end: *const i8 = 0 as *const i8;
    let mut wildcard_enabled: i32 = 0;
    let mut prefixlen: size_t = 0;
    let mut suffixlen: size_t = 0;
    let mut len: size_t = unsafe { strlen(hostname) };
    if (unsafe { *hostname.offset(len.wrapping_sub(1 as i32 as u64) as isize) }) as i32 == '.' as i32 {
        (unsafe { *hostname.offset(len.wrapping_sub(1 as i32 as u64) as isize) = 0 as i32 as i8 });
    }
    len = unsafe { strlen(pattern) };
    if (unsafe { *pattern.offset(len.wrapping_sub(1 as i32 as u64) as isize) }) as i32 == '.' as i32 {
        (unsafe { *pattern.offset(len.wrapping_sub(1 as i32 as u64) as isize) = 0 as i32 as i8 });
    }
    pattern_wildcard = unsafe { strchr(pattern, '*' as i32) };
    if pattern_wildcard.is_null() {
        return if (unsafe { Curl_strcasecompare(pattern, hostname) }) != 0 {
            1 as i32
        } else {
            0 as i32
        };
    }
    if unsafe { Curl_host_is_ipnum(hostname) } {
        return 0 as i32;
    }
    wildcard_enabled = 1 as i32;
    pattern_label_end = unsafe { strchr(pattern, '.' as i32) };
    if pattern_label_end.is_null()
        || (unsafe { strchr(pattern_label_end.offset(1 as i32 as isize), '.' as i32) }).is_null()
        || pattern_wildcard > pattern_label_end
        || (unsafe { Curl_strncasecompare(
            pattern,
            b"xn--\0" as *const u8 as *const i8,
            4 as i32 as size_t,
        ) }) != 0
    {
        wildcard_enabled = 0 as i32;
    }
    if wildcard_enabled == 0 {
        return if (unsafe { Curl_strcasecompare(pattern, hostname) }) != 0 {
            1 as i32
        } else {
            0 as i32
        };
    }
    hostname_label_end = unsafe { strchr(hostname, '.' as i32) };
    if hostname_label_end.is_null()
        || (unsafe { Curl_strcasecompare(pattern_label_end, hostname_label_end) }) == 0
    {
        return 0 as i32;
    }
    if ((unsafe { hostname_label_end.offset_from(hostname) }) as i64)
        < (unsafe { pattern_label_end.offset_from(pattern) }) as i64
    {
        return 0 as i32;
    }
    prefixlen = (unsafe { pattern_wildcard.offset_from(pattern) }) as i64 as size_t;
    suffixlen =
        (unsafe { pattern_label_end.offset_from(pattern_wildcard.offset(1 as i32 as isize)) }) as i64 as size_t;
    return if (unsafe { Curl_strncasecompare(pattern, hostname, prefixlen) }) != 0
        && (unsafe { Curl_strncasecompare(
            pattern_wildcard.offset(1 as i32 as isize),
            hostname_label_end.offset(-(suffixlen as isize)),
            suffixlen,
        ) }) != 0
    {
        1 as i32
    } else {
        0 as i32
    };
}
#[no_mangle]
pub extern "C" fn Curl_cert_hostcheck(
    mut match_pattern: *const i8,
    mut hostname: *const i8,
) -> i32 {
    let mut res: i32 = 0 as i32;
    if !(match_pattern.is_null() || (unsafe { *match_pattern }) == 0 || hostname.is_null() || (unsafe { *hostname }) == 0) {
        let mut matchp: *mut i8 = unsafe { Curl_cstrdup.expect("non-null function pointer")(match_pattern) };
        if !matchp.is_null() {
            let mut hostp: *mut i8 = unsafe { Curl_cstrdup.expect("non-null function pointer")(hostname) };
            if !hostp.is_null() {
                if hostmatch(hostp, matchp) == 1 as i32 {
                    res = 1 as i32;
                }
                (unsafe { Curl_cfree.expect("non-null function pointer")(hostp as *mut libc::c_void) });
            }
            (unsafe { Curl_cfree.expect("non-null function pointer")(matchp as *mut libc::c_void) });
        }
    }
    return res;
}
