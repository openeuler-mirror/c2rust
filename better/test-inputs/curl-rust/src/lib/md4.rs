use ::libc;
extern "C" {
    fn curlx_uztoui(uznum: size_t) -> libc::c_uint;
    fn MD4_Final(md: *mut libc::c_uchar, c: *mut MD4_CTX) -> libc::c_int;
    fn MD4_Update(
        c: *mut MD4_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn MD4_Init(c: *mut MD4_CTX) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type MD4_CTX = MD4state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct MD4state_st {
    pub A: libc::c_uint,
    pub B: libc::c_uint,
    pub C: libc::c_uint,
    pub D: libc::c_uint,
    pub Nl: libc::c_uint,
    pub Nh: libc::c_uint,
    pub data: [libc::c_uint; 16],
    pub num: libc::c_uint,
}
#[no_mangle]
pub unsafe extern "C" fn Curl_md4it(
    mut output: *mut libc::c_uchar,
    mut input: *const libc::c_uchar,
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
