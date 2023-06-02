use ::libc;
extern "C" {
    
    fn SHA256_Init(c: * mut crate::src::lib::sha256::SHA256state_st) -> i32;
    fn SHA256_Update(
        c: * mut crate::src::lib::sha256::SHA256state_st,
        data: * const core::ffi::c_void,
        len: u64,
    ) -> i32;
    fn SHA256_Final(md: * mut u8, c: * mut crate::src::lib::sha256::SHA256state_st) -> i32;
}
pub use crate::src::lib::warnless::curlx_uztoui;
pub type size_t = u64;
pub type HMAC_hinit_func<'a1> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,) -> ()>;
pub type HMAC_hupdate_func<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut core::ffi::c_void>,_: Option<&'a2 u8>,_: u32,) -> ()>;
pub type HMAC_hfinal_func<'a1, 'a2> = Option<unsafe extern "C"  fn(_: Option<&'a1 mut u8>,_: Option<&'a2 mut core::ffi::c_void>,) -> ()>;
// #[derive(Copy, Clone)]

pub type HMAC_params = crate::src::lib::curl_ntlm_core::HMAC_params;
pub type SHA256_CTX = crate::src::lib::sha256::SHA256state_st;
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
impl SHA256state_st {
    pub const fn new() -> Self {
        SHA256state_st {
        h: [0,0,0,0,0,0,0,0,],
        Nl: 0,
        Nh: 0,
        data: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,],
        num: 0,
        md_len: 0
        }
    }
}

impl std::default::Default for SHA256state_st {
    fn default() -> Self { SHA256state_st::new() }
}

#[no_mangle]
pub unsafe extern "C" fn Curl_sha256it(
    mut output: * mut u8,
    mut input: * const u8,
    length: u64,
) {
    let mut ctx: crate::src::lib::sha256::SHA256state_st = SHA256_CTX {
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
pub static mut Curl_HMAC_SHA256: [crate::src::lib::curl_ntlm_core::HMAC_params; 1] = unsafe {
    [
        {
            let mut init = HMAC_params {
                hmac_hinit: core::intrinsics::transmute::<Option<unsafe extern "C"  fn() -> ()>, Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>>(
                    core::intrinsics::transmute::<Option<unsafe extern "C"  fn(_: * mut crate::src::lib::sha256::SHA256state_st,) -> i32>, Option<unsafe extern "C"  fn() -> ()>>(
                        Some(
                            SHA256_Init,
                        ),
                    ),
                ),
                hmac_hupdate: core::intrinsics::transmute::<Option<unsafe extern "C"  fn() -> ()>, Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: u32,) -> ()>>(
                    core::intrinsics::transmute::<Option<unsafe extern "C"  fn(_: * mut crate::src::lib::sha256::SHA256state_st,_: * const core::ffi::c_void,_: u64,) -> i32>, Option<unsafe extern "C"  fn() -> ()>>(
                        Some(
                            SHA256_Update,
                        ),
                    ),
                ),
                hmac_hfinal: core::intrinsics::transmute::<Option<unsafe extern "C"  fn() -> ()>, Option<unsafe extern "C"  fn(_: * mut u8,_: * mut core::ffi::c_void,) -> ()>>(
                    core::intrinsics::transmute::<Option<unsafe extern "C"  fn(_: * mut u8,_: * mut crate::src::lib::sha256::SHA256state_st,) -> i32>, Option<unsafe extern "C"  fn() -> ()>>(
                        Some(
                            SHA256_Final,
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
use crate::laertes_rt::*;
