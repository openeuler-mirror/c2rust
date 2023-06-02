use ::libc;
extern "C" {
    
    fn MD4_Final(md: *mut u8, c: *mut MD4_CTX) -> i32;
    fn MD4_Update(
        c: *mut MD4_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> i32;
    fn MD4_Init(c: *mut MD4_CTX) -> i32;
}
pub use crate::src::lib::warnless::curlx_uztoui;
pub type size_t = crate::src::lib::altsvc::size_t;
pub type MD4_CTX = MD4state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct MD4state_st {
    pub A: u32,
    pub B: u32,
    pub C: u32,
    pub D: u32,
    pub Nl: u32,
    pub Nh: u32,
    pub data: [u32; 16],
    pub num: u32,
}
#[no_mangle]
pub unsafe extern "C" fn Curl_md4it(
    mut output: *mut u8,
    mut input: *const u8,
    len: size_t,
) {
    let mut ctx: MD4_CTX = MD4_CTX {
        A: 0,
        B: 0,
        C: 0,
        D: 0,
        Nl: 0,
        Nh: 0,
        data: [0; 16],
        num: 0,
    };
    MD4_Init(&mut ctx);
    MD4_Update(&mut ctx, input as *const libc::c_void, curlx_uztoui(len) as size_t);
    MD4_Final(output, &mut ctx);
}
