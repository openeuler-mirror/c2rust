use ::libc;
extern "C" {
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn Curl_strcasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
    ) -> libc::c_int;
    fn Curl_strncasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
        max: size_t,
    ) -> libc::c_int;
    fn Curl_host_is_ipnum(hostname: *const libc::c_char) -> bool;
    static mut Curl_cfree: curl_free_callback;
    static mut Curl_cstrdup: curl_strdup_callback;
}
pub type size_t = libc::c_ulong;
pub type curl_free_callback = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_strdup_callback = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
>;
unsafe extern "C" fn hostmatch(
    mut hostname: *mut libc::c_char,
    mut pattern: *mut libc::c_char,
) -> libc::c_int {
    let mut pattern_label_end: *const libc::c_char = 0 as *const libc::c_char;
    let mut pattern_wildcard: *const libc::c_char = 0 as *const libc::c_char;
    let mut hostname_label_end: *const libc::c_char = 0 as *const libc::c_char;
    let mut wildcard_enabled: libc::c_int = 0;
    let mut prefixlen: size_t = 0;
    let mut suffixlen: size_t = 0;
    let mut len: size_t = strlen(hostname);
    if *hostname.offset(len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
        as libc::c_int == '.' as i32
    {
        *hostname
            .offset(
                len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
            ) = 0 as libc::c_int as libc::c_char;
    }
    len = strlen(pattern);
    if *pattern.offset(len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
        as libc::c_int == '.' as i32
    {
        *pattern
            .offset(
                len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
            ) = 0 as libc::c_int as libc::c_char;
    }
    pattern_wildcard = strchr(pattern, '*' as i32);
    if pattern_wildcard.is_null() {
        return if Curl_strcasecompare(pattern, hostname) != 0 {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        };
    }
    if Curl_host_is_ipnum(hostname) {
        return 0 as libc::c_int;
    }
    wildcard_enabled = 1 as libc::c_int;
    pattern_label_end = strchr(pattern, '.' as i32);
    if pattern_label_end.is_null()
        || (strchr(pattern_label_end.offset(1 as libc::c_int as isize), '.' as i32))
            .is_null() || pattern_wildcard > pattern_label_end
        || Curl_strncasecompare(
            pattern,
            b"xn--\0" as *const u8 as *const libc::c_char,
            4 as libc::c_int as size_t,
        ) != 0
    {
        wildcard_enabled = 0 as libc::c_int;
    }
    if wildcard_enabled == 0 {
        return if Curl_strcasecompare(pattern, hostname) != 0 {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        };
    }
    hostname_label_end = strchr(hostname, '.' as i32);
    if hostname_label_end.is_null()
        || Curl_strcasecompare(pattern_label_end, hostname_label_end) == 0
    {
        return 0 as libc::c_int;
    }
    if (hostname_label_end.offset_from(hostname) as libc::c_long)
        < pattern_label_end.offset_from(pattern) as libc::c_long
    {
        return 0 as libc::c_int;
    }
    prefixlen = pattern_wildcard.offset_from(pattern) as libc::c_long as size_t;
    suffixlen = pattern_label_end
        .offset_from(pattern_wildcard.offset(1 as libc::c_int as isize)) as libc::c_long
        as size_t;
    return if Curl_strncasecompare(pattern, hostname, prefixlen) != 0
        && Curl_strncasecompare(
            pattern_wildcard.offset(1 as libc::c_int as isize),
            hostname_label_end.offset(-(suffixlen as isize)),
            suffixlen,
        ) != 0
    {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn Curl_cert_hostcheck(
    mut match_pattern: *const libc::c_char,
    mut hostname: *const libc::c_char,
) -> libc::c_int {
    let mut res: libc::c_int = 0 as libc::c_int;
    if !(match_pattern.is_null() || *match_pattern == 0 || hostname.is_null()
        || *hostname == 0)
    {
        let mut matchp: *mut libc::c_char = Curl_cstrdup
            .expect("non-null function pointer")(match_pattern);
        if !matchp.is_null() {
            let mut hostp: *mut libc::c_char = Curl_cstrdup
                .expect("non-null function pointer")(hostname);
            if !hostp.is_null() {
                if hostmatch(hostp, matchp) == 1 as libc::c_int {
                    res = 1 as libc::c_int;
                }
                Curl_cfree
                    .expect("non-null function pointer")(hostp as *mut libc::c_void);
            }
            Curl_cfree.expect("non-null function pointer")(matchp as *mut libc::c_void);
        }
    }
    return res;
}
