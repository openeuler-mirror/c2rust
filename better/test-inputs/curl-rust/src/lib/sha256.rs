use ::libc;
extern "C" {
    fn curlx_uztoui(uznum: size_t) -> libc::c_uint;
    fn SHA256_Init(c: *mut SHA256_CTX) -> libc::c_int;
    fn SHA256_Update(
        c: *mut SHA256_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA256_Final(md: *mut libc::c_uchar, c: *mut SHA256_CTX) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type HMAC_hinit_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type HMAC_hupdate_func = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_uchar, libc::c_uint) -> (),
>;
pub type HMAC_hfinal_func = Option::<
    unsafe extern "C" fn(*mut libc::c_uchar, *mut libc::c_void) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HMAC_params {
    pub hmac_hinit: HMAC_hinit_func,
    pub hmac_hupdate: HMAC_hupdate_func,
    pub hmac_hfinal: HMAC_hfinal_func,
    pub hmac_ctxtsize: libc::c_uint,
    pub hmac_maxkeylen: libc::c_uint,
    pub hmac_resultlen: libc::c_uint,
}
pub type SHA256_CTX = SHA256state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SHA256state_st {
    pub h: [libc::c_uint; 8],
    pub Nl: libc::c_uint,
    pub Nh: libc::c_uint,
    pub data: [libc::c_uint; 16],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
#[no_mangle]
pub unsafe extern "C" fn Curl_sha256it(
    mut output: *mut libc::c_uchar,
    mut input: *const libc::c_uchar,
    length: size_t,
) {
    let mut ctx: SHA256_CTX = SHA256_CTX {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        data: [0; 16],
        num: 0,
        md_len: 0,
    };
    SHA256_Init(&mut ctx);
    SHA256_Update(
        &mut ctx,
        input as *const libc::c_void,
        curlx_uztoui(length) as size_t,
    );
    SHA256_Final(output, &mut ctx);
}
#[no_mangle]
pub static mut Curl_HMAC_SHA256: [HMAC_params; 1] = unsafe {
    [
        {
            let mut init = HMAC_params {
                hmac_hinit: ::std::mem::transmute::<
                    Option::<unsafe extern "C" fn() -> ()>,
                    HMAC_hinit_func,
                >(
                    ::std::mem::transmute::<
                        Option::<unsafe extern "C" fn(*mut SHA256_CTX) -> libc::c_int>,
                        Option::<unsafe extern "C" fn() -> ()>,
                    >(
                        Some(
                            SHA256_Init
                                as unsafe extern "C" fn(*mut SHA256_CTX) -> libc::c_int,
                        ),
                    ),
                ),
                hmac_hupdate: ::std::mem::transmute::<
                    Option::<unsafe extern "C" fn() -> ()>,
                    HMAC_hupdate_func,
                >(
                    ::std::mem::transmute::<
                        Option::<
                            unsafe extern "C" fn(
                                *mut SHA256_CTX,
                                *const libc::c_void,
                                size_t,
                            ) -> libc::c_int,
                        >,
                        Option::<unsafe extern "C" fn() -> ()>,
                    >(
                        Some(
                            SHA256_Update
                                as unsafe extern "C" fn(
                                    *mut SHA256_CTX,
                                    *const libc::c_void,
                                    size_t,
                                ) -> libc::c_int,
                        ),
                    ),
                ),
                hmac_hfinal: ::std::mem::transmute::<
                    Option::<unsafe extern "C" fn() -> ()>,
                    HMAC_hfinal_func,
                >(
                    ::std::mem::transmute::<
                        Option::<
                            unsafe extern "C" fn(
                                *mut libc::c_uchar,
                                *mut SHA256_CTX,
                            ) -> libc::c_int,
                        >,
                        Option::<unsafe extern "C" fn() -> ()>,
                    >(
                        Some(
                            SHA256_Final
                                as unsafe extern "C" fn(
                                    *mut libc::c_uchar,
                                    *mut SHA256_CTX,
                                ) -> libc::c_int,
                        ),
                    ),
                ),
                hmac_ctxtsize: ::std::mem::size_of::<SHA256_CTX>() as libc::c_ulong
                    as libc::c_uint,
                hmac_maxkeylen: 64 as libc::c_int as libc::c_uint,
                hmac_resultlen: 32 as libc::c_int as libc::c_uint,
            };
            init
        },
    ]
};
