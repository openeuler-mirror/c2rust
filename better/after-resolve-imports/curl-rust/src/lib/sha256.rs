use ::libc;
extern "C" {
    
    fn SHA256_Init(c: *mut SHA256_CTX) -> i32;
    fn SHA256_Update(
        c: *mut SHA256_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> i32;
    fn SHA256_Final(md: *mut u8, c: *mut SHA256_CTX) -> i32;
}
pub use crate::src::lib::warnless::curlx_uztoui;
pub type size_t = crate::src::lib::altsvc::size_t;
pub type HMAC_hinit_func = crate::src::lib::curl_ntlm_core::HMAC_hinit_func;
pub type HMAC_hupdate_func = crate::src::lib::curl_ntlm_core::HMAC_hupdate_func;
pub type HMAC_hfinal_func = crate::src::lib::curl_ntlm_core::HMAC_hfinal_func;
// #[derive(Copy, Clone)]

pub type HMAC_params = crate::src::lib::curl_ntlm_core::HMAC_params;
pub type SHA256_CTX = SHA256state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SHA256state_st {
    pub h: [u32; 8],
    pub Nl: u32,
    pub Nh: u32,
    pub data: [u32; 16],
    pub num: u32,
    pub md_len: u32,
}
#[no_mangle]
pub unsafe extern "C" fn Curl_sha256it(
    mut output: *mut u8,
    mut input: *const u8,
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
                        Option::<unsafe extern "C" fn(*mut SHA256_CTX) -> i32>,
                        Option::<unsafe extern "C" fn() -> ()>,
                    >(
                        Some(
                            SHA256_Init
                                as unsafe extern "C" fn(*mut SHA256_CTX) -> i32,
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
                            ) -> i32,
                        >,
                        Option::<unsafe extern "C" fn() -> ()>,
                    >(
                        Some(
                            SHA256_Update
                                as unsafe extern "C" fn(
                                    *mut SHA256_CTX,
                                    *const libc::c_void,
                                    size_t,
                                ) -> i32,
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
                                *mut u8,
                                *mut SHA256_CTX,
                            ) -> i32,
                        >,
                        Option::<unsafe extern "C" fn() -> ()>,
                    >(
                        Some(
                            SHA256_Final
                                as unsafe extern "C" fn(
                                    *mut u8,
                                    *mut SHA256_CTX,
                                ) -> i32,
                        ),
                    ),
                ),
                hmac_ctxtsize: ::std::mem::size_of::<SHA256_CTX>() as u64
                    as u32,
                hmac_maxkeylen: 64 as i32 as u32,
                hmac_resultlen: 32 as i32 as u32,
            };
            init
        },
    ]
};
