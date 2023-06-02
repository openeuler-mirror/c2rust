use :: libc;
extern "C" {
    fn __xmlInitializeDict() -> i32;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn malloc(_: u64) -> *mut core::ffi::c_void;
    fn free(__ptr: *mut core::ffi::c_void);
    fn xmlResetError(err: *mut crate::src::threads::_xmlError);
    fn xmlInitializeGlobalState(gs: *mut crate::src::threads::_xmlGlobalState);
    fn __xmlGenericError(
    ) -> *mut Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
    fn __xmlGenericErrorContext() -> *mut *mut core::ffi::c_void;
    fn pthread_self() -> u64;
    fn pthread_mutex_lock(__mutex: *mut crate::src::threads::pthread_mutex_t) -> i32;
    fn pthread_mutex_unlock(__mutex: *mut crate::src::threads::pthread_mutex_t) -> i32;
    fn pthread_cond_init(
        __cond: *mut crate::src::threads::pthread_cond_t,
        __cond_attr: *const crate::src::threads::pthread_condattr_t,
    ) -> i32;
    fn pthread_cond_wait(
        __cond: *mut crate::src::threads::pthread_cond_t,
        __mutex: *mut crate::src::threads::pthread_mutex_t,
    ) -> i32;
    fn pthread_cond_signal(__cond: *mut crate::src::threads::pthread_cond_t) -> i32;
    fn pthread_mutex_init(
        __mutex: *mut crate::src::threads::pthread_mutex_t,
        __mutexattr: *const crate::src::threads::pthread_mutexattr_t,
    ) -> i32;
    fn pthread_cond_destroy(__cond: *mut crate::src::threads::pthread_cond_t) -> i32;
    fn pthread_mutex_destroy(__mutex: *mut crate::src::threads::pthread_mutex_t) -> i32;
    fn pthread_key_delete(__key: u32) -> i32;
    fn pthread_once(
        __once_control: *mut i32,
        __init_routine: Option<unsafe extern "C" fn() -> ()>,
    ) -> i32;
    fn pthread_getspecific(__key: u32) -> *mut core::ffi::c_void;
    fn pthread_setspecific(__key: u32, __pointer: *const core::ffi::c_void) -> i32;
    fn pthread_key_create(
        __key: *mut u32,
        __destr_function: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
    ) -> i32;
}
pub use crate::src::xmlstring::_xmlBuf;
pub use crate::src::xpointer::_xmlDict;
pub type xmlChar = u8;
pub type size_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutex_t {
    pub __data: __pthread_mutex_s,
    pub __size: [i8; 40],
    pub __align: i64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_mutex_s {
    pub __lock: i32,
    pub __count: u32,
    pub __owner: i32,
    pub __nusers: u32,
    pub __kind: i32,
    pub __spins: i16,
    pub __elision: i16,
    pub __list: crate::src::threads::__pthread_internal_list,
}
impl __pthread_mutex_s {
    pub const fn new() -> Self {
        __pthread_mutex_s {
            __lock: 0,
            __count: 0,
            __owner: 0,
            __nusers: 0,
            __kind: 0,
            __spins: 0,
            __elision: 0,
            __list: crate::src::threads::__pthread_internal_list::new(),
        }
    }
}
impl std::default::Default for __pthread_mutex_s {
    fn default() -> Self {
        __pthread_mutex_s::new()
    }
}
pub type __pthread_list_t = crate::src::threads::__pthread_internal_list;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_internal_list {
    pub __prev: *mut crate::src::threads::__pthread_internal_list,
    pub __next: *mut crate::src::threads::__pthread_internal_list,
}
impl __pthread_internal_list {
    pub const fn new() -> Self {
        __pthread_internal_list {
            __prev: (0 as *mut crate::src::threads::__pthread_internal_list),
            __next: (0 as *mut crate::src::threads::__pthread_internal_list),
        }
    }
}
impl std::default::Default for __pthread_internal_list {
    fn default() -> Self {
        __pthread_internal_list::new()
    }
}
pub const PTHREAD_MUTEX_TIMED_NP: C2RustUnnamed_3 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_cond_s {
    pub c2rust_unnamed: crate::src::threads::C2RustUnnamed_1,
    pub c2rust_unnamed_0: crate::src::threads::C2RustUnnamed,
    pub __g_refs: [u32; 2],
    pub __g_size: [u32; 2],
    pub __g1_orig_size: u32,
    pub __wrefs: u32,
    pub __g_signals: [u32; 2],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub __g1_start: u64,
    pub __g1_start32: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub __low: u32,
    pub __high: u32,
}
impl C2RustUnnamed_0 {
    pub const fn new() -> Self {
        C2RustUnnamed_0 {
            __low: 0,
            __high: 0,
        }
    }
}
impl std::default::Default for C2RustUnnamed_0 {
    fn default() -> Self {
        C2RustUnnamed_0::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub __wseq: u64,
    pub __wseq32: C2RustUnnamed_2,
}
pub type C2RustUnnamed_2 = crate::src::threads::C2RustUnnamed_0;
pub type pthread_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutexattr_t {
    pub __size: [i8; 4],
    pub __align: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_condattr_t {
    pub __size: [i8; 4],
    pub __align: i32,
}
pub type pthread_key_t = u32;
pub type pthread_once_t = i32;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_cond_t {
    pub __data: __pthread_cond_s,
    pub __size: [i8; 48],
    pub __align: i64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlMutex {
    pub lock: crate::src::threads::pthread_mutex_t,
}
pub type xmlMutex = crate::src::threads::_xmlMutex;
pub type xmlMutexPtr = *mut crate::src::threads::_xmlMutex;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlRMutex {
    pub lock: crate::src::threads::pthread_mutex_t,
    pub held: u32,
    pub waiters: u32,
    pub tid: u64,
    pub cv: crate::src::threads::pthread_cond_t,
}
pub type xmlRMutex = crate::src::threads::_xmlRMutex;
pub type xmlRMutexPtr = *mut crate::src::threads::_xmlRMutex;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInputBuffer {
    pub context: *mut core::ffi::c_void,
    pub readcallback:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut i8, _: i32) -> i32>,
    pub closecallback: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>,
    pub encoder: *mut crate::src::threads::_xmlCharEncodingHandler,
    pub buffer: *mut crate::src::xmlstring::_xmlBuf,
    pub raw: *mut crate::src::xmlstring::_xmlBuf,
    pub compressed: i32,
    pub error: i32,
    pub rawconsumed: u64,
}
impl _xmlParserInputBuffer {
    pub const fn new() -> Self {
        _xmlParserInputBuffer {
            context: (0 as *mut core::ffi::c_void),
            readcallback: None,
            closecallback: None,
            encoder: (0 as *mut crate::src::threads::_xmlCharEncodingHandler),
            buffer: (0 as *mut crate::src::xmlstring::_xmlBuf),
            raw: (0 as *mut crate::src::xmlstring::_xmlBuf),
            compressed: 0,
            error: 0,
            rawconsumed: 0,
        }
    }
}
impl std::default::Default for _xmlParserInputBuffer {
    fn default() -> Self {
        _xmlParserInputBuffer::new()
    }
}
pub type xmlBufPtr = *mut crate::src::xmlstring::_xmlBuf;
pub type xmlBuf = crate::src::xmlstring::_xmlBuf;
pub type xmlCharEncodingHandlerPtr = *mut crate::src::threads::_xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = crate::src::threads::_xmlCharEncodingHandler;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlCharEncodingHandler {
    pub name: *mut i8,
    pub input:
        Option<unsafe extern "C" fn(_: *mut u8, _: *mut i32, _: *const u8, _: *mut i32) -> i32>,
    pub output:
        Option<unsafe extern "C" fn(_: *mut u8, _: *mut i32, _: *const u8, _: *mut i32) -> i32>,
    pub iconv_in: *mut core::ffi::c_void,
    pub iconv_out: *mut core::ffi::c_void,
}
impl _xmlCharEncodingHandler {
    pub const fn new() -> Self {
        _xmlCharEncodingHandler {
            name: (0 as *mut i8),
            input: None,
            output: None,
            iconv_in: (0 as *mut core::ffi::c_void),
            iconv_out: (0 as *mut core::ffi::c_void),
        }
    }
}
impl std::default::Default for _xmlCharEncodingHandler {
    fn default() -> Self {
        _xmlCharEncodingHandler::new()
    }
}
pub type iconv_t = *mut core::ffi::c_void;
pub type xmlCharEncodingOutputFunc =
    Option<unsafe extern "C" fn(_: *mut u8, _: *mut i32, _: *const u8, _: *mut i32) -> i32>;
pub type xmlCharEncodingInputFunc =
    Option<unsafe extern "C" fn(_: *mut u8, _: *mut i32, _: *const u8, _: *mut i32) -> i32>;
pub type xmlInputCloseCallback = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type xmlInputReadCallback =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut i8, _: i32) -> i32>;
pub type xmlParserInputBuffer = crate::src::threads::_xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = *mut crate::src::threads::_xmlParserInputBuffer;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlOutputBuffer {
    pub context: *mut core::ffi::c_void,
    pub writecallback:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, _: i32) -> i32>,
    pub closecallback: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>,
    pub encoder: *mut crate::src::threads::_xmlCharEncodingHandler,
    pub buffer: *mut crate::src::xmlstring::_xmlBuf,
    pub conv: *mut crate::src::xmlstring::_xmlBuf,
    pub written: i32,
    pub error: i32,
}
impl _xmlOutputBuffer {
    pub const fn new() -> Self {
        _xmlOutputBuffer {
            context: (0 as *mut core::ffi::c_void),
            writecallback: None,
            closecallback: None,
            encoder: (0 as *mut crate::src::threads::_xmlCharEncodingHandler),
            buffer: (0 as *mut crate::src::xmlstring::_xmlBuf),
            conv: (0 as *mut crate::src::xmlstring::_xmlBuf),
            written: 0,
            error: 0,
        }
    }
}
impl std::default::Default for _xmlOutputBuffer {
    fn default() -> Self {
        _xmlOutputBuffer::new()
    }
}
pub type xmlOutputCloseCallback = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type xmlOutputWriteCallback =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, _: i32) -> i32>;
pub type xmlOutputBuffer = crate::src::threads::_xmlOutputBuffer;
pub type xmlOutputBufferPtr = *mut crate::src::threads::_xmlOutputBuffer;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInput {
    pub buf: *mut crate::src::threads::_xmlParserInputBuffer,
    pub filename: *const i8,
    pub directory: *const i8,
    pub base: *const u8,
    pub cur: *const u8,
    pub end: *const u8,
    pub length: i32,
    pub line: i32,
    pub col: i32,
    pub consumed: u64,
    pub free: Option<unsafe extern "C" fn(_: *mut u8) -> ()>,
    pub encoding: *const u8,
    pub version: *const u8,
    pub standalone: i32,
    pub id: i32,
}
impl _xmlParserInput {
    pub const fn new() -> Self {
        _xmlParserInput {
            buf: (0 as *mut crate::src::threads::_xmlParserInputBuffer),
            filename: (0 as *const i8),
            directory: (0 as *const i8),
            base: (0 as *const u8),
            cur: (0 as *const u8),
            end: (0 as *const u8),
            length: 0,
            line: 0,
            col: 0,
            consumed: 0,
            free: None,
            encoding: (0 as *const u8),
            version: (0 as *const u8),
            standalone: 0,
            id: 0,
        }
    }
}
impl std::default::Default for _xmlParserInput {
    fn default() -> Self {
        _xmlParserInput::new()
    }
}
pub type xmlParserInputDeallocate = Option<unsafe extern "C" fn(_: *mut u8) -> ()>;
pub type xmlParserInput = crate::src::threads::_xmlParserInput;
pub type xmlParserInputPtr = *mut crate::src::threads::_xmlParserInput;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNode {
    pub _private: *mut core::ffi::c_void,
    pub type_0: u32,
    pub name: *const u8,
    pub children: *mut crate::src::threads::_xmlNode,
    pub last: *mut crate::src::threads::_xmlNode,
    pub parent: *mut crate::src::threads::_xmlNode,
    pub next: *mut crate::src::threads::_xmlNode,
    pub prev: *mut crate::src::threads::_xmlNode,
    pub doc: *mut crate::src::threads::_xmlDoc,
    pub ns: *mut crate::src::threads::_xmlNs,
    pub content: *mut u8,
    pub properties: *mut crate::src::threads::_xmlAttr,
    pub nsDef: *mut crate::src::threads::_xmlNs,
    pub psvi: *mut core::ffi::c_void,
    pub line: u16,
    pub extra: u16,
}
impl _xmlNode {
    pub const fn new() -> Self {
        _xmlNode {
            _private: (0 as *mut core::ffi::c_void),
            type_0: 0,
            name: (0 as *const u8),
            children: (0 as *mut crate::src::threads::_xmlNode),
            last: (0 as *mut crate::src::threads::_xmlNode),
            parent: (0 as *mut crate::src::threads::_xmlNode),
            next: (0 as *mut crate::src::threads::_xmlNode),
            prev: (0 as *mut crate::src::threads::_xmlNode),
            doc: (0 as *mut crate::src::threads::_xmlDoc),
            ns: (0 as *mut crate::src::threads::_xmlNs),
            content: (0 as *mut u8),
            properties: (0 as *mut crate::src::threads::_xmlAttr),
            nsDef: (0 as *mut crate::src::threads::_xmlNs),
            psvi: (0 as *mut core::ffi::c_void),
            line: 0,
            extra: 0,
        }
    }
}
impl std::default::Default for _xmlNode {
    fn default() -> Self {
        _xmlNode::new()
    }
}
pub type xmlNs = crate::src::threads::_xmlNs;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNs {
    pub next: *mut crate::src::threads::_xmlNs,
    pub type_0: u32,
    pub href: *const u8,
    pub prefix: *const u8,
    pub _private: *mut core::ffi::c_void,
    pub context: *mut crate::src::threads::_xmlDoc,
}
impl _xmlNs {
    pub const fn new() -> Self {
        _xmlNs {
            next: (0 as *mut crate::src::threads::_xmlNs),
            type_0: 0,
            href: (0 as *const u8),
            prefix: (0 as *const u8),
            _private: (0 as *mut core::ffi::c_void),
            context: (0 as *mut crate::src::threads::_xmlDoc),
        }
    }
}
impl std::default::Default for _xmlNs {
    fn default() -> Self {
        _xmlNs::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDoc {
    pub _private: *mut core::ffi::c_void,
    pub type_0: u32,
    pub name: *mut i8,
    pub children: *mut crate::src::threads::_xmlNode,
    pub last: *mut crate::src::threads::_xmlNode,
    pub parent: *mut crate::src::threads::_xmlNode,
    pub next: *mut crate::src::threads::_xmlNode,
    pub prev: *mut crate::src::threads::_xmlNode,
    pub doc: *mut crate::src::threads::_xmlDoc,
    pub compression: i32,
    pub standalone: i32,
    pub intSubset: *mut crate::src::threads::_xmlDtd,
    pub extSubset: *mut crate::src::threads::_xmlDtd,
    pub oldNs: *mut crate::src::threads::_xmlNs,
    pub version: *const u8,
    pub encoding: *const u8,
    pub ids: *mut core::ffi::c_void,
    pub refs: *mut core::ffi::c_void,
    pub URL: *const u8,
    pub charset: i32,
    pub dict: *mut crate::src::xpointer::_xmlDict,
    pub psvi: *mut core::ffi::c_void,
    pub parseFlags: i32,
    pub properties: i32,
}
impl _xmlDoc {
    pub const fn new() -> Self {
        _xmlDoc {
            _private: (0 as *mut core::ffi::c_void),
            type_0: 0,
            name: (0 as *mut i8),
            children: (0 as *mut crate::src::threads::_xmlNode),
            last: (0 as *mut crate::src::threads::_xmlNode),
            parent: (0 as *mut crate::src::threads::_xmlNode),
            next: (0 as *mut crate::src::threads::_xmlNode),
            prev: (0 as *mut crate::src::threads::_xmlNode),
            doc: (0 as *mut crate::src::threads::_xmlDoc),
            compression: 0,
            standalone: 0,
            intSubset: (0 as *mut crate::src::threads::_xmlDtd),
            extSubset: (0 as *mut crate::src::threads::_xmlDtd),
            oldNs: (0 as *mut crate::src::threads::_xmlNs),
            version: (0 as *const u8),
            encoding: (0 as *const u8),
            ids: (0 as *mut core::ffi::c_void),
            refs: (0 as *mut core::ffi::c_void),
            URL: (0 as *const u8),
            charset: 0,
            dict: (0 as *mut crate::src::xpointer::_xmlDict),
            psvi: (0 as *mut core::ffi::c_void),
            parseFlags: 0,
            properties: 0,
        }
    }
}
impl std::default::Default for _xmlDoc {
    fn default() -> Self {
        _xmlDoc::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDtd {
    pub _private: *mut core::ffi::c_void,
    pub type_0: u32,
    pub name: *const u8,
    pub children: *mut crate::src::threads::_xmlNode,
    pub last: *mut crate::src::threads::_xmlNode,
    pub parent: *mut crate::src::threads::_xmlDoc,
    pub next: *mut crate::src::threads::_xmlNode,
    pub prev: *mut crate::src::threads::_xmlNode,
    pub doc: *mut crate::src::threads::_xmlDoc,
    pub notations: *mut core::ffi::c_void,
    pub elements: *mut core::ffi::c_void,
    pub attributes: *mut core::ffi::c_void,
    pub entities: *mut core::ffi::c_void,
    pub ExternalID: *const u8,
    pub SystemID: *const u8,
    pub pentities: *mut core::ffi::c_void,
}
impl _xmlDtd {
    pub const fn new() -> Self {
        _xmlDtd {
            _private: (0 as *mut core::ffi::c_void),
            type_0: 0,
            name: (0 as *const u8),
            children: (0 as *mut crate::src::threads::_xmlNode),
            last: (0 as *mut crate::src::threads::_xmlNode),
            parent: (0 as *mut crate::src::threads::_xmlDoc),
            next: (0 as *mut crate::src::threads::_xmlNode),
            prev: (0 as *mut crate::src::threads::_xmlNode),
            doc: (0 as *mut crate::src::threads::_xmlDoc),
            notations: (0 as *mut core::ffi::c_void),
            elements: (0 as *mut core::ffi::c_void),
            attributes: (0 as *mut core::ffi::c_void),
            entities: (0 as *mut core::ffi::c_void),
            ExternalID: (0 as *const u8),
            SystemID: (0 as *const u8),
            pentities: (0 as *mut core::ffi::c_void),
        }
    }
}
impl std::default::Default for _xmlDtd {
    fn default() -> Self {
        _xmlDtd::new()
    }
}
pub type xmlElementType = u32;
pub const XML_XINCLUDE_END: xmlElementType = 20;
pub const XML_XINCLUDE_START: xmlElementType = 19;
pub const XML_NAMESPACE_DECL: xmlElementType = 18;
pub const XML_ENTITY_DECL: xmlElementType = 17;
pub const XML_ATTRIBUTE_DECL: xmlElementType = 16;
pub const XML_ELEMENT_DECL: xmlElementType = 15;
pub const XML_DTD_NODE: xmlElementType = 14;
pub const XML_HTML_DOCUMENT_NODE: xmlElementType = 13;
pub const XML_NOTATION_NODE: xmlElementType = 12;
pub const XML_DOCUMENT_FRAG_NODE: xmlElementType = 11;
pub const XML_DOCUMENT_TYPE_NODE: xmlElementType = 10;
pub const XML_DOCUMENT_NODE: xmlElementType = 9;
pub const XML_COMMENT_NODE: xmlElementType = 8;
pub const XML_PI_NODE: xmlElementType = 7;
pub const XML_ENTITY_NODE: xmlElementType = 6;
pub const XML_ENTITY_REF_NODE: xmlElementType = 5;
pub const XML_CDATA_SECTION_NODE: xmlElementType = 4;
pub const XML_TEXT_NODE: xmlElementType = 3;
pub const XML_ATTRIBUTE_NODE: xmlElementType = 2;
pub const XML_ELEMENT_NODE: xmlElementType = 1;
pub type xmlNsType = u32;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlAttr {
    pub _private: *mut core::ffi::c_void,
    pub type_0: u32,
    pub name: *const u8,
    pub children: *mut crate::src::threads::_xmlNode,
    pub last: *mut crate::src::threads::_xmlNode,
    pub parent: *mut crate::src::threads::_xmlNode,
    pub next: *mut crate::src::threads::_xmlAttr,
    pub prev: *mut crate::src::threads::_xmlAttr,
    pub doc: *mut crate::src::threads::_xmlDoc,
    pub ns: *mut crate::src::threads::_xmlNs,
    pub atype: u32,
    pub psvi: *mut core::ffi::c_void,
}
impl _xmlAttr {
    pub const fn new() -> Self {
        _xmlAttr {
            _private: (0 as *mut core::ffi::c_void),
            type_0: 0,
            name: (0 as *const u8),
            children: (0 as *mut crate::src::threads::_xmlNode),
            last: (0 as *mut crate::src::threads::_xmlNode),
            parent: (0 as *mut crate::src::threads::_xmlNode),
            next: (0 as *mut crate::src::threads::_xmlAttr),
            prev: (0 as *mut crate::src::threads::_xmlAttr),
            doc: (0 as *mut crate::src::threads::_xmlDoc),
            ns: (0 as *mut crate::src::threads::_xmlNs),
            atype: 0,
            psvi: (0 as *mut core::ffi::c_void),
        }
    }
}
impl std::default::Default for _xmlAttr {
    fn default() -> Self {
        _xmlAttr::new()
    }
}
pub type xmlAttributeType = u32;
pub const XML_ATTRIBUTE_NOTATION: xmlAttributeType = 10;
pub const XML_ATTRIBUTE_ENUMERATION: xmlAttributeType = 9;
pub const XML_ATTRIBUTE_NMTOKENS: xmlAttributeType = 8;
pub const XML_ATTRIBUTE_NMTOKEN: xmlAttributeType = 7;
pub const XML_ATTRIBUTE_ENTITIES: xmlAttributeType = 6;
pub const XML_ATTRIBUTE_ENTITY: xmlAttributeType = 5;
pub const XML_ATTRIBUTE_IDREFS: xmlAttributeType = 4;
pub const XML_ATTRIBUTE_IDREF: xmlAttributeType = 3;
pub const XML_ATTRIBUTE_ID: xmlAttributeType = 2;
pub const XML_ATTRIBUTE_CDATA: xmlAttributeType = 1;
pub type xmlError = crate::src::threads::_xmlError;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlError {
    pub domain: i32,
    pub code: i32,
    pub message: *mut i8,
    pub level: u32,
    pub file: *mut i8,
    pub line: i32,
    pub str1: *mut i8,
    pub str2: *mut i8,
    pub str3: *mut i8,
    pub int1: i32,
    pub int2: i32,
    pub ctxt: *mut core::ffi::c_void,
    pub node: *mut core::ffi::c_void,
}
impl _xmlError {
    pub const fn new() -> Self {
        _xmlError {
            domain: 0,
            code: 0,
            message: (0 as *mut i8),
            level: 0,
            file: (0 as *mut i8),
            line: 0,
            str1: (0 as *mut i8),
            str2: (0 as *mut i8),
            str3: (0 as *mut i8),
            int1: 0,
            int2: 0,
            ctxt: (0 as *mut core::ffi::c_void),
            node: (0 as *mut core::ffi::c_void),
        }
    }
}
impl std::default::Default for _xmlError {
    fn default() -> Self {
        _xmlError::new()
    }
}
pub type xmlErrorLevel = u32;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlNodePtr = *mut crate::src::threads::_xmlNode;
pub type xmlNode = crate::src::threads::_xmlNode;
pub type xmlStructuredErrorFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut crate::src::threads::_xmlError) -> (),
>;
pub type xmlErrorPtr = *mut crate::src::threads::_xmlError;
pub type externalSubsetSAXFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type cdataBlockSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>;
pub type getParameterEntitySAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
    ) -> *mut crate::src::threads::_xmlEntity,
>;
pub type xmlEntityPtr = *mut crate::src::threads::_xmlEntity;
pub type xmlEntity = crate::src::threads::_xmlEntity;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlEntity {
    pub _private: *mut core::ffi::c_void,
    pub type_0: u32,
    pub name: *const u8,
    pub children: *mut crate::src::threads::_xmlNode,
    pub last: *mut crate::src::threads::_xmlNode,
    pub parent: *mut crate::src::threads::_xmlDtd,
    pub next: *mut crate::src::threads::_xmlNode,
    pub prev: *mut crate::src::threads::_xmlNode,
    pub doc: *mut crate::src::threads::_xmlDoc,
    pub orig: *mut u8,
    pub content: *mut u8,
    pub length: i32,
    pub etype: u32,
    pub ExternalID: *const u8,
    pub SystemID: *const u8,
    pub nexte: *mut crate::src::threads::_xmlEntity,
    pub URI: *const u8,
    pub owner: i32,
    pub checked: i32,
}
impl _xmlEntity {
    pub const fn new() -> Self {
        _xmlEntity {
            _private: (0 as *mut core::ffi::c_void),
            type_0: 0,
            name: (0 as *const u8),
            children: (0 as *mut crate::src::threads::_xmlNode),
            last: (0 as *mut crate::src::threads::_xmlNode),
            parent: (0 as *mut crate::src::threads::_xmlDtd),
            next: (0 as *mut crate::src::threads::_xmlNode),
            prev: (0 as *mut crate::src::threads::_xmlNode),
            doc: (0 as *mut crate::src::threads::_xmlDoc),
            orig: (0 as *mut u8),
            content: (0 as *mut u8),
            length: 0,
            etype: 0,
            ExternalID: (0 as *const u8),
            SystemID: (0 as *const u8),
            nexte: (0 as *mut crate::src::threads::_xmlEntity),
            URI: (0 as *const u8),
            owner: 0,
            checked: 0,
        }
    }
}
impl std::default::Default for _xmlEntity {
    fn default() -> Self {
        _xmlEntity::new()
    }
}
pub type xmlEntityType = u32;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type errorSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type warningSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type commentSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>;
pub type processingInstructionSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8) -> ()>;
pub type ignorableWhitespaceSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>;
pub type charactersSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>;
pub type referenceSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>;
pub type endElementSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>;
pub type startElementSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *mut *const u8) -> ()>;
pub type endDocumentSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type startDocumentSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type setDocumentLocatorSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *mut crate::src::threads::_xmlSAXLocator,
    ) -> (),
>;
pub type xmlSAXLocatorPtr = *mut crate::src::threads::_xmlSAXLocator;
pub type xmlSAXLocator = crate::src::threads::_xmlSAXLocator;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXLocator {
    pub getPublicId: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> *const u8>,
    pub getSystemId: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> *const u8>,
    pub getLineNumber: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>,
    pub getColumnNumber: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>,
}
impl _xmlSAXLocator {
    pub const fn new() -> Self {
        _xmlSAXLocator {
            getPublicId: None,
            getSystemId: None,
            getLineNumber: None,
            getColumnNumber: None,
        }
    }
}
impl std::default::Default for _xmlSAXLocator {
    fn default() -> Self {
        _xmlSAXLocator::new()
    }
}
pub type unparsedEntityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
        _: *const u8,
        _: *const u8,
    ) -> (),
>;
pub type elementDeclSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: i32,
        _: *mut crate::src::threads::_xmlElementContent,
    ) -> (),
>;
pub type xmlElementContentPtr = *mut crate::src::threads::_xmlElementContent;
pub type xmlElementContent = crate::src::threads::_xmlElementContent;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlElementContent {
    pub type_0: u32,
    pub ocur: u32,
    pub name: *const u8,
    pub c1: *mut crate::src::threads::_xmlElementContent,
    pub c2: *mut crate::src::threads::_xmlElementContent,
    pub parent: *mut crate::src::threads::_xmlElementContent,
    pub prefix: *const u8,
}
impl _xmlElementContent {
    pub const fn new() -> Self {
        _xmlElementContent {
            type_0: 0,
            ocur: 0,
            name: (0 as *const u8),
            c1: (0 as *mut crate::src::threads::_xmlElementContent),
            c2: (0 as *mut crate::src::threads::_xmlElementContent),
            parent: (0 as *mut crate::src::threads::_xmlElementContent),
            prefix: (0 as *const u8),
        }
    }
}
impl std::default::Default for _xmlElementContent {
    fn default() -> Self {
        _xmlElementContent::new()
    }
}
pub type xmlElementContentOccur = u32;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub type xmlElementContentType = u32;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub type attributeDeclSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
        _: i32,
        _: i32,
        _: *const u8,
        _: *mut crate::src::threads::_xmlEnumeration,
    ) -> (),
>;
pub type xmlEnumerationPtr = *mut crate::src::threads::_xmlEnumeration;
pub type xmlEnumeration = crate::src::threads::_xmlEnumeration;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlEnumeration {
    pub next: *mut crate::src::threads::_xmlEnumeration,
    pub name: *const u8,
}
impl _xmlEnumeration {
    pub const fn new() -> Self {
        _xmlEnumeration {
            next: (0 as *mut crate::src::threads::_xmlEnumeration),
            name: (0 as *const u8),
        }
    }
}
impl std::default::Default for _xmlEnumeration {
    fn default() -> Self {
        _xmlEnumeration::new()
    }
}
pub type notationDeclSAXFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type entityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: i32,
        _: *const u8,
        _: *const u8,
        _: *mut u8,
    ) -> (),
>;
pub type getEntitySAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
    ) -> *mut crate::src::threads::_xmlEntity,
>;
pub type resolveEntitySAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
    ) -> *mut crate::src::threads::_xmlParserInput,
>;
pub type hasExternalSubsetSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type hasInternalSubsetSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type isStandaloneSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type internalSubsetSAXFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type xmlBufferAllocationScheme = u32;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
pub type xmlGenericErrorFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXHandlerV1 {
    pub internalSubset: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: *const u8,
            _: *const u8,
        ) -> (),
    >,
    pub isStandalone: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>,
    pub hasInternalSubset: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>,
    pub hasExternalSubset: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>,
    pub resolveEntity: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: *const u8,
        ) -> *mut crate::src::threads::_xmlParserInput,
    >,
    pub getEntity: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
        ) -> *mut crate::src::threads::_xmlEntity,
    >,
    pub entityDecl: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: i32,
            _: *const u8,
            _: *const u8,
            _: *mut u8,
        ) -> (),
    >,
    pub notationDecl: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: *const u8,
            _: *const u8,
        ) -> (),
    >,
    pub attributeDecl: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: *const u8,
            _: i32,
            _: i32,
            _: *const u8,
            _: *mut crate::src::threads::_xmlEnumeration,
        ) -> (),
    >,
    pub elementDecl: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: i32,
            _: *mut crate::src::threads::_xmlElementContent,
        ) -> (),
    >,
    pub unparsedEntityDecl: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: *const u8,
            _: *const u8,
            _: *const u8,
        ) -> (),
    >,
    pub setDocumentLocator: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *mut crate::src::threads::_xmlSAXLocator,
        ) -> (),
    >,
    pub startDocument: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
    pub endDocument: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
    pub startElement: Option<
        unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *mut *const u8) -> (),
    >,
    pub endElement: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>,
    pub reference: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>,
    pub characters:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>,
    pub ignorableWhitespace:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>,
    pub processingInstruction:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8) -> ()>,
    pub comment: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>,
    pub warning: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
    pub error: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
    pub fatalError:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
    pub getParameterEntity: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
        ) -> *mut crate::src::threads::_xmlEntity,
    >,
    pub cdataBlock:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>,
    pub externalSubset: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: *const u8,
            _: *const u8,
        ) -> (),
    >,
    pub initialized: u32,
}
impl _xmlSAXHandlerV1 {
    pub const fn new() -> Self {
        _xmlSAXHandlerV1 {
            internalSubset: None,
            isStandalone: None,
            hasInternalSubset: None,
            hasExternalSubset: None,
            resolveEntity: None,
            getEntity: None,
            entityDecl: None,
            notationDecl: None,
            attributeDecl: None,
            elementDecl: None,
            unparsedEntityDecl: None,
            setDocumentLocator: None,
            startDocument: None,
            endDocument: None,
            startElement: None,
            endElement: None,
            reference: None,
            characters: None,
            ignorableWhitespace: None,
            processingInstruction: None,
            comment: None,
            warning: None,
            error: None,
            fatalError: None,
            getParameterEntity: None,
            cdataBlock: None,
            externalSubset: None,
            initialized: 0,
        }
    }
}
impl std::default::Default for _xmlSAXHandlerV1 {
    fn default() -> Self {
        _xmlSAXHandlerV1::new()
    }
}
pub type xmlSAXHandlerV1 = crate::src::threads::_xmlSAXHandlerV1;
pub type xmlCharEncoding = i32;
pub const XML_CHAR_ENCODING_ASCII: xmlCharEncoding = 22;
pub const XML_CHAR_ENCODING_EUC_JP: xmlCharEncoding = 21;
pub const XML_CHAR_ENCODING_SHIFT_JIS: xmlCharEncoding = 20;
pub const XML_CHAR_ENCODING_2022_JP: xmlCharEncoding = 19;
pub const XML_CHAR_ENCODING_8859_9: xmlCharEncoding = 18;
pub const XML_CHAR_ENCODING_8859_8: xmlCharEncoding = 17;
pub const XML_CHAR_ENCODING_8859_7: xmlCharEncoding = 16;
pub const XML_CHAR_ENCODING_8859_6: xmlCharEncoding = 15;
pub const XML_CHAR_ENCODING_8859_5: xmlCharEncoding = 14;
pub const XML_CHAR_ENCODING_8859_4: xmlCharEncoding = 13;
pub const XML_CHAR_ENCODING_8859_3: xmlCharEncoding = 12;
pub const XML_CHAR_ENCODING_8859_2: xmlCharEncoding = 11;
pub const XML_CHAR_ENCODING_8859_1: xmlCharEncoding = 10;
pub const XML_CHAR_ENCODING_UCS2: xmlCharEncoding = 9;
pub const XML_CHAR_ENCODING_UCS4_3412: xmlCharEncoding = 8;
pub const XML_CHAR_ENCODING_UCS4_2143: xmlCharEncoding = 7;
pub const XML_CHAR_ENCODING_EBCDIC: xmlCharEncoding = 6;
pub const XML_CHAR_ENCODING_UCS4BE: xmlCharEncoding = 5;
pub const XML_CHAR_ENCODING_UCS4LE: xmlCharEncoding = 4;
pub const XML_CHAR_ENCODING_UTF16BE: xmlCharEncoding = 3;
pub const XML_CHAR_ENCODING_UTF16LE: xmlCharEncoding = 2;
pub const XML_CHAR_ENCODING_UTF8: xmlCharEncoding = 1;
pub const XML_CHAR_ENCODING_NONE: xmlCharEncoding = 0;
pub const XML_CHAR_ENCODING_ERROR: xmlCharEncoding = -1;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
pub type xmlReallocFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void>;
pub type xmlStrdupFunc = Option<unsafe extern "C" fn(_: *const i8) -> *mut i8>;
pub type xmlParserInputBufferCreateFilenameFunc = Option<
    unsafe extern "C" fn(_: *const i8, _: i32) -> *mut crate::src::threads::_xmlParserInputBuffer,
>;
pub type xmlOutputBufferCreateFilenameFunc = Option<
    unsafe extern "C" fn(
        _: *const i8,
        _: *mut crate::src::threads::_xmlCharEncodingHandler,
        _: i32,
    ) -> *mut crate::src::threads::_xmlOutputBuffer,
>;
pub type xmlRegisterNodeFunc =
    Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>;
pub type xmlDeregisterNodeFunc =
    Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlGlobalState {
    pub xmlParserVersion: *const i8,
    pub xmlDefaultSAXLocator: crate::src::threads::_xmlSAXLocator,
    pub xmlDefaultSAXHandler: crate::src::threads::_xmlSAXHandlerV1,
    pub docbDefaultSAXHandler: crate::src::threads::_xmlSAXHandlerV1,
    pub htmlDefaultSAXHandler: crate::src::threads::_xmlSAXHandlerV1,
    pub xmlFree: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
    pub xmlMalloc: Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>,
    pub xmlMemStrdup: Option<unsafe extern "C" fn(_: *const i8) -> *mut i8>,
    pub xmlRealloc:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void>,
    pub xmlGenericError:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
    pub xmlStructuredError: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *mut crate::src::threads::_xmlError,
        ) -> (),
    >,
    pub xmlGenericErrorContext: *mut core::ffi::c_void,
    pub oldXMLWDcompatibility: i32,
    pub xmlBufferAllocScheme: u32,
    pub xmlDefaultBufferSize: i32,
    pub xmlSubstituteEntitiesDefaultValue: i32,
    pub xmlDoValidityCheckingDefaultValue: i32,
    pub xmlGetWarningsDefaultValue: i32,
    pub xmlKeepBlanksDefaultValue: i32,
    pub xmlLineNumbersDefaultValue: i32,
    pub xmlLoadExtDtdDefaultValue: i32,
    pub xmlParserDebugEntities: i32,
    pub xmlPedanticParserDefaultValue: i32,
    pub xmlSaveNoEmptyTags: i32,
    pub xmlIndentTreeOutput: i32,
    pub xmlTreeIndentString: *const i8,
    pub xmlRegisterNodeDefaultValue:
        Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>,
    pub xmlDeregisterNodeDefaultValue:
        Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>,
    pub xmlMallocAtomic: Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>,
    pub xmlLastError: crate::src::threads::_xmlError,
    pub xmlParserInputBufferCreateFilenameValue: Option<
        unsafe extern "C" fn(
            _: *const i8,
            _: i32,
        ) -> *mut crate::src::threads::_xmlParserInputBuffer,
    >,
    pub xmlOutputBufferCreateFilenameValue: Option<
        unsafe extern "C" fn(
            _: *const i8,
            _: *mut crate::src::threads::_xmlCharEncodingHandler,
            _: i32,
        ) -> *mut crate::src::threads::_xmlOutputBuffer,
    >,
    pub xmlStructuredErrorContext: *mut core::ffi::c_void,
}
impl _xmlGlobalState {
    pub const fn new() -> Self {
        _xmlGlobalState {
            xmlParserVersion: (0 as *const i8),
            xmlDefaultSAXLocator: crate::src::threads::_xmlSAXLocator::new(),
            xmlDefaultSAXHandler: crate::src::threads::_xmlSAXHandlerV1::new(),
            docbDefaultSAXHandler: crate::src::threads::_xmlSAXHandlerV1::new(),
            htmlDefaultSAXHandler: crate::src::threads::_xmlSAXHandlerV1::new(),
            xmlFree: None,
            xmlMalloc: None,
            xmlMemStrdup: None,
            xmlRealloc: None,
            xmlGenericError: None,
            xmlStructuredError: None,
            xmlGenericErrorContext: (0 as *mut core::ffi::c_void),
            oldXMLWDcompatibility: 0,
            xmlBufferAllocScheme: 0,
            xmlDefaultBufferSize: 0,
            xmlSubstituteEntitiesDefaultValue: 0,
            xmlDoValidityCheckingDefaultValue: 0,
            xmlGetWarningsDefaultValue: 0,
            xmlKeepBlanksDefaultValue: 0,
            xmlLineNumbersDefaultValue: 0,
            xmlLoadExtDtdDefaultValue: 0,
            xmlParserDebugEntities: 0,
            xmlPedanticParserDefaultValue: 0,
            xmlSaveNoEmptyTags: 0,
            xmlIndentTreeOutput: 0,
            xmlTreeIndentString: (0 as *const i8),
            xmlRegisterNodeDefaultValue: None,
            xmlDeregisterNodeDefaultValue: None,
            xmlMallocAtomic: None,
            xmlLastError: crate::src::threads::_xmlError::new(),
            xmlParserInputBufferCreateFilenameValue: None,
            xmlOutputBufferCreateFilenameValue: None,
            xmlStructuredErrorContext: (0 as *mut core::ffi::c_void),
        }
    }
}
impl std::default::Default for _xmlGlobalState {
    fn default() -> Self {
        _xmlGlobalState::new()
    }
}
pub type xmlGlobalState = crate::src::threads::_xmlGlobalState;
pub type xmlGlobalStatePtr = *mut crate::src::threads::_xmlGlobalState;
pub type C2RustUnnamed_3 = u32;
pub const PTHREAD_MUTEX_DEFAULT: C2RustUnnamed_3 = 0;
pub const PTHREAD_MUTEX_ERRORCHECK: C2RustUnnamed_3 = 2;
pub const PTHREAD_MUTEX_RECURSIVE: C2RustUnnamed_3 = 1;
pub const PTHREAD_MUTEX_NORMAL: C2RustUnnamed_3 = 0;
pub const PTHREAD_MUTEX_ADAPTIVE_NP: C2RustUnnamed_3 = 3;
pub const PTHREAD_MUTEX_ERRORCHECK_NP: C2RustUnnamed_3 = 2;
pub const PTHREAD_MUTEX_RECURSIVE_NP: C2RustUnnamed_3 = 1;
#[inline]
extern "C" fn pthread_equal(mut __thread1: u64, mut __thread2: u64) -> i32 {
    return (__thread1 == __thread2) as i32;
}
static mut libxml_is_threaded: i32 = -(1 as i32);
static mut globalkey: u32 = 0;
static mut mainthread: u64 = 0;
static mut once_control: i32 = 0 as i32;
static mut once_control_init: i32 = 0 as i32;
static mut global_init_lock: crate::src::threads::pthread_mutex_t = pthread_mutex_t {
    __data: {
        let mut init = __pthread_mutex_s {
            __lock: 0 as i32,
            __count: 0 as i32 as u32,
            __owner: 0 as i32,
            __nusers: 0 as i32 as u32,
            __kind: PTHREAD_MUTEX_TIMED_NP as i32,
            __spins: 0 as i32 as i16,
            __elision: 0 as i32 as i16,
            __list: {
                let mut init = __pthread_internal_list {
                    __prev: 0 as *const __pthread_internal_list as *mut __pthread_internal_list,
                    __next: 0 as *const __pthread_internal_list as *mut __pthread_internal_list,
                };
                init
            },
        };
        init
    },
};
static mut xmlLibraryLock: *mut crate::src::threads::_xmlRMutex =
    0 as *mut crate::src::threads::_xmlRMutex;
#[no_mangle]
pub extern "C" fn xmlNewMutex() -> *mut crate::src::threads::_xmlMutex {
    let mut tok: *mut crate::src::threads::_xmlMutex = 0 as *mut xmlMutex;
    tok = (unsafe { malloc(::std::mem::size_of::<xmlMutex>() as u64) }) as xmlMutexPtr;
    if tok.is_null() {
        return 0 as *mut libc::c_void as xmlMutexPtr;
    }
    if (unsafe { libxml_is_threaded }) != 0 as i32 {
        (unsafe { pthread_mutex_init(&mut (*tok).lock, 0 as *const pthread_mutexattr_t) });
    }
    return tok;
}
#[no_mangle]
pub extern "C" fn xmlFreeMutex(mut tok: *mut crate::src::threads::_xmlMutex) {
    if tok.is_null() {
        return;
    }
    if (unsafe { libxml_is_threaded }) != 0 as i32 {
        (unsafe { pthread_mutex_destroy(&mut (*tok).lock) });
    }
    (unsafe { free(tok as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlMutexLock(mut tok: *mut crate::src::threads::_xmlMutex) {
    if tok.is_null() {
        return;
    }
    if (unsafe { libxml_is_threaded }) != 0 as i32 {
        (unsafe { pthread_mutex_lock(&mut (*tok).lock) });
    }
}
#[no_mangle]
pub extern "C" fn xmlMutexUnlock(mut tok: *mut crate::src::threads::_xmlMutex) {
    if tok.is_null() {
        return;
    }
    if (unsafe { libxml_is_threaded }) != 0 as i32 {
        (unsafe { pthread_mutex_unlock(&mut (*tok).lock) });
    }
}
#[no_mangle]
pub extern "C" fn xmlNewRMutex() -> *mut crate::src::threads::_xmlRMutex {
    let mut tok: *mut crate::src::threads::_xmlRMutex = 0 as *mut crate::src::threads::_xmlRMutex;
    tok = (unsafe { malloc(::std::mem::size_of::<xmlRMutex>() as u64) }) as xmlRMutexPtr;
    if tok.is_null() {
        return 0 as *mut crate::src::threads::_xmlRMutex;
    }
    if (unsafe { libxml_is_threaded }) != 0 as i32 {
        (unsafe { pthread_mutex_init(&mut (*tok).lock, 0 as *const pthread_mutexattr_t) });
        (unsafe { (*tok).held = 0 as i32 as u32 });
        (unsafe { (*tok).waiters = 0 as i32 as u32 });
        (unsafe { pthread_cond_init(&mut (*tok).cv, 0 as *const pthread_condattr_t) });
    }
    return tok;
}
#[no_mangle]
pub extern "C" fn xmlFreeRMutex(mut tok: *mut crate::src::threads::_xmlRMutex) {
    if tok.is_null() {
        return;
    }
    if (unsafe { libxml_is_threaded }) != 0 as i32 {
        (unsafe { pthread_mutex_destroy(&mut (*tok).lock) });
        (unsafe { pthread_cond_destroy(&mut (*tok).cv) });
    }
    (unsafe { free(tok as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlRMutexLock(mut tok: *mut crate::src::threads::_xmlRMutex) {
    if tok.is_null() {
        return;
    }
    if (unsafe { libxml_is_threaded }) == 0 as i32 {
        return;
    }
    (unsafe { pthread_mutex_lock(&mut (*tok).lock) });
    if (unsafe { (*tok).held }) != 0 {
        if pthread_equal(unsafe { (*tok).tid }, unsafe { pthread_self() }) != 0 {
            let fresh0 = unsafe { &mut ((*tok).held) };
            *fresh0 = (*fresh0).wrapping_add(1);
            (unsafe { pthread_mutex_unlock(&mut (*tok).lock) });
            return;
        } else {
            let fresh1 = unsafe { &mut ((*tok).waiters) };
            *fresh1 = (*fresh1).wrapping_add(1);
            while (unsafe { (*tok).held }) != 0 {
                (unsafe { pthread_cond_wait(&mut (*tok).cv, &mut (*tok).lock) });
            }
            let fresh2 = unsafe { &mut ((*tok).waiters) };
            *fresh2 = (*fresh2).wrapping_sub(1);
        }
    }
    (unsafe { (*tok).tid = pthread_self() });
    (unsafe { (*tok).held = 1 as i32 as u32 });
    (unsafe { pthread_mutex_unlock(&mut (*tok).lock) });
}
#[no_mangle]
pub extern "C" fn xmlRMutexUnlock(mut tok: *mut crate::src::threads::_xmlRMutex) {
    if tok.is_null() {
        return;
    }
    if (unsafe { libxml_is_threaded }) == 0 as i32 {
        return;
    }
    (unsafe { pthread_mutex_lock(&mut (*tok).lock) });
    let fresh3 = unsafe { &mut ((*tok).held) };
    *fresh3 = (*fresh3).wrapping_sub(1);
    if (unsafe { (*tok).held }) == 0 as i32 as u32 {
        if (unsafe { (*tok).waiters }) != 0 {
            (unsafe { pthread_cond_signal(&mut (*tok).cv) });
        }
        (unsafe {
            memset(
                &mut (*tok).tid as *mut pthread_t as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<pthread_t>() as u64,
            )
        });
    }
    (unsafe { pthread_mutex_unlock(&mut (*tok).lock) });
}
#[no_mangle]
pub extern "C" fn __xmlGlobalInitMutexLock() {
    if (Some(pthread_mutex_lock)).is_none() {
        return;
    }
    (unsafe { pthread_mutex_lock(&mut global_init_lock) });
}
#[no_mangle]
pub extern "C" fn __xmlGlobalInitMutexUnlock() {
    if (Some(pthread_mutex_unlock)).is_none() {
        return;
    }
    (unsafe { pthread_mutex_unlock(&mut global_init_lock) });
}
#[no_mangle]
pub extern "C" fn __xmlGlobalInitMutexDestroy() {}
extern "C" fn xmlFreeGlobalState(mut state: *mut core::ffi::c_void) {
    let mut gs: *mut crate::src::threads::_xmlGlobalState = state as *mut xmlGlobalState;
    (unsafe { xmlResetError(&mut (*gs).xmlLastError) });
    (unsafe { free(state) });
}
extern "C" fn xmlNewGlobalState() -> *mut crate::src::threads::_xmlGlobalState {
    let mut gs: *mut crate::src::threads::_xmlGlobalState = 0 as *mut xmlGlobalState;
    gs = (unsafe { malloc(::std::mem::size_of::<xmlGlobalState>() as u64) }) as *mut xmlGlobalState;
    if gs.is_null() {
        (unsafe {
            (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlGetGlobalState: out of memory\n\0" as *const u8 as *const i8,
            )
        });
        return 0 as xmlGlobalStatePtr;
    }
    (unsafe {
        memset(
            gs as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlGlobalState>() as u64,
        )
    });
    (unsafe { xmlInitializeGlobalState(gs) });
    return gs;
}
#[no_mangle]
pub extern "C" fn xmlGetGlobalState() -> *mut crate::src::threads::_xmlGlobalState {
    let mut globalval: *mut crate::src::threads::_xmlGlobalState = 0 as *mut xmlGlobalState;
    if (unsafe { libxml_is_threaded }) == 0 as i32 {
        return 0 as xmlGlobalStatePtr;
    }
    (unsafe { pthread_once(&mut once_control, Some(xmlOnceInit)) });
    globalval = (unsafe { pthread_getspecific(globalkey) }) as *mut xmlGlobalState;
    if globalval.is_null() {
        let mut tsd: *mut crate::src::threads::_xmlGlobalState = xmlNewGlobalState();
        if tsd.is_null() {
            return 0 as xmlGlobalStatePtr;
        }
        (unsafe { pthread_setspecific(globalkey, tsd as *const libc::c_void) });
        return tsd;
    }
    return globalval;
}
#[no_mangle]
pub extern "C" fn xmlGetThreadId() -> i32 {
    let mut id: u64 = 0;
    let mut ret: i32 = 0;
    if (unsafe { libxml_is_threaded }) == 0 as i32 {
        return 0 as i32;
    }
    id = unsafe { pthread_self() };
    (unsafe {
        memcpy(
            &mut ret as *mut i32 as *mut libc::c_void,
            &mut id as *mut pthread_t as *const libc::c_void,
            ::std::mem::size_of::<i32>() as u64,
        )
    });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlIsMainThread() -> i32 {
    if (unsafe { libxml_is_threaded }) == -(1 as i32) {
        xmlInitThreads();
    }
    if (unsafe { libxml_is_threaded }) == 0 as i32 {
        return 1 as i32;
    }
    (unsafe { pthread_once(&mut once_control, Some(xmlOnceInit)) });
    return pthread_equal(unsafe { mainthread }, unsafe { pthread_self() });
}
#[no_mangle]
pub extern "C" fn xmlLockLibrary() {
    xmlRMutexLock(unsafe { xmlLibraryLock });
}
#[no_mangle]
pub extern "C" fn xmlUnlockLibrary() {
    xmlRMutexUnlock(unsafe { xmlLibraryLock });
}
#[no_mangle]
pub extern "C" fn xmlInitThreads() {
    if (unsafe { libxml_is_threaded }) == -(1 as i32) {
        if (Some(pthread_once)).is_some()
            && (Some(pthread_getspecific)).is_some()
            && (Some(pthread_setspecific)).is_some()
            && (Some(pthread_key_create)).is_some()
            && (Some(pthread_key_delete)).is_some()
            && (Some(pthread_mutex_init)).is_some()
            && (Some(pthread_mutex_destroy)).is_some()
            && (Some(pthread_mutex_lock)).is_some()
            && (Some(pthread_mutex_unlock)).is_some()
            && (Some(pthread_cond_init)).is_some()
            && (Some(pthread_cond_destroy)).is_some()
            && (Some(pthread_cond_wait)).is_some()
            && (Some(pthread_equal)).is_some()
            && (Some(pthread_self)).is_some()
            && (Some(pthread_cond_signal)).is_some()
        {
            (unsafe { libxml_is_threaded = 1 as i32 });
        } else {
            (unsafe { libxml_is_threaded = 0 as i32 });
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlCleanupThreads() {
    if (unsafe { libxml_is_threaded }) != 0 as i32 {
        (unsafe { pthread_key_delete(globalkey) });
    }
    (unsafe { once_control = once_control_init });
}
extern "C" fn xmlOnceInit() {
    (unsafe { pthread_key_create(&mut globalkey, Some(xmlFreeGlobalState)) });
    (unsafe { mainthread = pthread_self() });
    (unsafe { __xmlInitializeDict() });
}

