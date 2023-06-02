use ::libc;
extern "C" {
    
    
    
    
    fn utimes(__file: *const i8, __tvp: *const timeval) -> i32;
    fn strerror(_: i32) -> *mut i8;
    fn __errno_location() -> *mut i32;
    fn __xstat(
        __ver: i32,
        __filename: *const i8,
        __stat_buf: *mut stat,
    ) -> i32;
    
}
pub use crate::src::src::tool_msgs::warnf;
pub use crate::src::lib::http2::curl_mime;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
pub type __dev_t = crate::src::lib::file::__dev_t;
pub type __uid_t = crate::src::lib::conncache::__uid_t;
pub type __gid_t = crate::src::lib::curl_ntlm_wb::__gid_t;
pub type __ino_t = crate::src::lib::file::__ino_t;
pub type __mode_t = crate::src::lib::file::__mode_t;
pub type __nlink_t = crate::src::lib::file::__nlink_t;
pub type __off_t = crate::src::lib::http2::__off_t;
pub type __off64_t = crate::src::lib::http2::__off64_t;
pub type __time_t = crate::src::lib::http2::__time_t;
pub type __suseconds_t = crate::src::lib::openldap::__suseconds_t;
pub type __blksize_t = crate::src::lib::file::__blksize_t;
pub type __blkcnt_t = crate::src::lib::file::__blkcnt_t;
pub type __syscall_slong_t = crate::src::lib::file::__syscall_slong_t;
pub type time_t = crate::src::lib::http2::time_t;
pub type size_t = crate::src::lib::http2::size_t;
// #[derive(Copy, Clone)]

pub type timeval = crate::src::lib::openldap::timeval;
// #[derive(Copy, Clone)]

pub type timespec = crate::src::lib::file::timespec;
pub type curl_off_t = crate::src::lib::http2::curl_off_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = crate::src::lib::http2::_IO_lock_t;
pub type FILE = crate::src::lib::http2::FILE;
// #[derive(Copy, Clone)]

pub type curl_slist = crate::src::lib::http2::curl_slist;
pub type curl_TimeCond = crate::src::lib::http2::curl_TimeCond;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
// #[derive(Copy, Clone)]

pub type stat = crate::src::lib::file::stat;
// #[derive(Copy, Clone)]

pub type GlobalConfig = crate::src::src::tool_cb_dbg::GlobalConfig;
// #[derive(Copy, Clone)]

pub type OperationConfig = crate::src::src::tool_cb_dbg::OperationConfig;
// #[derive(Copy, Clone)]

pub type State = crate::src::src::tool_cb_dbg::State;
// #[derive(Copy, Clone)]

pub type URLGlob = crate::src::src::tool_cb_dbg::URLGlob;
// #[derive(Copy, Clone)]

pub type URLPattern = crate::src::src::tool_cb_dbg::URLPattern;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed = crate::src::src::tool_cb_dbg::C2RustUnnamed;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_0 = crate::src::src::tool_cb_dbg::C2RustUnnamed_0;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_1 = crate::src::src::tool_cb_dbg::C2RustUnnamed_1;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_2 = crate::src::src::tool_cb_dbg::C2RustUnnamed_2;
pub type URLPatternType = crate::src::src::tool_cb_dbg::URLPatternType;
pub const UPTNumRange: URLPatternType = 3;
pub const UPTCharRange: URLPatternType = 2;
pub const UPTSet: URLPatternType = 1;
// #[derive(Copy, Clone)]

pub type getout = crate::src::src::tool_cb_dbg::getout;
pub type curl_error = crate::src::src::tool_cb_dbg::curl_error;
pub const ERR_LAST: curl_error = 2;
pub const ERR_BINARY_TERMINAL: curl_error = 1;
pub const ERR_NONE: curl_error = 0;
pub type HttpReq = crate::src::src::tool_cb_dbg::HttpReq;
pub const HTTPREQ_SIMPLEPOST: HttpReq = 4;
pub const HTTPREQ_MIMEPOST: HttpReq = 3;
pub const HTTPREQ_HEAD: HttpReq = 2;
pub const HTTPREQ_GET: HttpReq = 1;
pub const HTTPREQ_UNSPEC: HttpReq = 0;
// #[derive(Copy, Clone)]

pub type tool_mime = crate::src::src::tool_cb_dbg::tool_mime;
pub type toolmimekind = crate::src::src::tool_cb_dbg::toolmimekind;
pub const TOOLMIME_STDINDATA: toolmimekind = 6;
pub const TOOLMIME_STDIN: toolmimekind = 5;
pub const TOOLMIME_FILEDATA: toolmimekind = 4;
pub const TOOLMIME_FILE: toolmimekind = 3;
pub const TOOLMIME_DATA: toolmimekind = 2;
pub const TOOLMIME_PARTS: toolmimekind = 1;
pub const TOOLMIME_NONE: toolmimekind = 0;
pub type trace = crate::src::src::tool_cb_dbg::trace;
pub const TRACE_PLAIN: trace = 3;
pub const TRACE_ASCII: trace = 2;
pub const TRACE_BIN: trace = 1;
pub const TRACE_NONE: trace = 0;
#[inline]
unsafe extern "C" fn stat(
    mut __path: *const i8,
    mut __statbuf: *mut stat,
) -> i32 {
    return __xstat(1 as i32, __path, __statbuf);
}
#[no_mangle]
pub unsafe extern "C" fn getfiletime(
    mut filename: *const i8,
    mut global: *mut GlobalConfig,
) -> curl_off_t {
    let mut result: curl_off_t = -(1 as i32) as curl_off_t;
    let mut statbuf: stat = stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atim: timespec { tv_sec: 0, tv_nsec: 0 },
        st_mtim: timespec { tv_sec: 0, tv_nsec: 0 },
        st_ctim: timespec { tv_sec: 0, tv_nsec: 0 },
        __glibc_reserved: [0; 3],
    };
    if -(1 as i32) != stat(filename, &mut statbuf) {
        result = statbuf.st_mtim.tv_sec;
    } else if *__errno_location() != 2 as i32 {
        warnf(
            global,
            b"Failed to get filetime: %s\n\0" as *const u8 as *const i8,
            strerror(*__errno_location()),
        );
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn setfiletime(
    mut filetime: curl_off_t,
    mut filename: *const i8,
    mut global: *mut GlobalConfig,
) {
    if filetime >= 0 as i32 as i64 {
        let mut times: [timeval; 2] = [timeval { tv_sec: 0, tv_usec: 0 }; 2];
        times[1 as i32 as usize].tv_sec = filetime;
        times[0 as i32 as usize]
            .tv_sec = times[1 as i32 as usize].tv_sec;
        times[1 as i32 as usize].tv_usec = 0 as i32 as __suseconds_t;
        times[0 as i32 as usize]
            .tv_usec = times[1 as i32 as usize].tv_usec;
        if utimes(filename, times.as_mut_ptr() as *const timeval) != 0 {
            warnf(
                global,
                b"Failed to set filetime %ld on '%s': %s\n\0" as *const u8
                    as *const i8,
                filetime,
                filename,
                strerror(*__errno_location()),
            );
        }
    }
}
