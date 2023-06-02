use :: libc;
extern "C" {
    fn MD4_Final(md: *mut u8, c: *mut crate::src::lib::md4::MD4state_st) -> i32;
    fn MD4_Update(
        c: *mut crate::src::lib::md4::MD4state_st,
        data: *const core::ffi::c_void,
        len: u64,
    ) -> i32;
    fn MD4_Init(c: *mut crate::src::lib::md4::MD4state_st) -> i32;
}
pub use crate::src::lib::warnless::curlx_uztoui;
pub type size_t = u64;
pub type MD4_CTX = crate::src::lib::md4::MD4state_st;
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
impl MD4state_st {
    pub const fn new() -> Self {
        MD4state_st {
            A: 0,
            B: 0,
            C: 0,
            D: 0,
            Nl: 0,
            Nh: 0,
            data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            num: 0,
        }
    }
}
impl std::default::Default for MD4state_st {
    fn default() -> Self {
        MD4state_st::new()
    }
}
#[no_mangle]
pub extern "C" fn Curl_md4it(mut output: *mut u8, mut input: *const u8, len: u64) {
    let mut ctx: crate::src::lib::md4::MD4state_st = MD4_CTX {
        A: 0,
        B: 0,
        C: 0,
        D: 0,
        Nl: 0,
        Nh: 0,
        data: [0; 16],
        num: 0,
    };
    (unsafe { MD4_Init(&mut ctx) });
    (unsafe { MD4_Update(
        &mut ctx,
        input as *const libc::c_void,
        curlx_uztoui(len) as size_t,
    ) });
    (unsafe { MD4_Final(output, &mut ctx) });
}

