use ::libc;
extern "C" {
    
    
    
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    
    
    
    
    fn pthread_self() -> pthread_t;
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    fn pthread_cond_init(
        __cond: *mut pthread_cond_t,
        __cond_attr: *const pthread_condattr_t,
    ) -> libc::c_int;
    fn pthread_cond_wait(
        __cond: *mut pthread_cond_t,
        __mutex: *mut pthread_mutex_t,
    ) -> libc::c_int;
    fn pthread_cond_signal(__cond: *mut pthread_cond_t) -> libc::c_int;
    fn pthread_mutex_init(
        __mutex: *mut pthread_mutex_t,
        __mutexattr: *const pthread_mutexattr_t,
    ) -> libc::c_int;
    fn pthread_cond_destroy(__cond: *mut pthread_cond_t) -> libc::c_int;
    fn pthread_mutex_destroy(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    fn pthread_key_delete(__key: pthread_key_t) -> libc::c_int;
    fn pthread_once(
        __once_control: *mut pthread_once_t,
        __init_routine: Option::<unsafe extern "C" fn() -> ()>,
    ) -> libc::c_int;
    fn pthread_getspecific(__key: pthread_key_t) -> *mut libc::c_void;
    fn pthread_setspecific(
        __key: pthread_key_t,
        __pointer: *const libc::c_void,
    ) -> libc::c_int;
    fn pthread_key_create(
        __key: *mut pthread_key_t,
        __destr_function: Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    ) -> libc::c_int;
}
pub use crate::src::dict::__xmlInitializeDict;
pub use crate::src::error::xmlResetError;
pub use crate::src::globals::__xmlGenericError;
pub use crate::src::globals::__xmlGenericErrorContext;
pub use crate::src::globals::xmlInitializeGlobalState;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub use crate::src::HTMLparser::xmlChar;
pub use crate::src::HTMLparser::size_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutex_t {
    pub __data: __pthread_mutex_s,
    pub __size: [libc::c_char; 40],
    pub __align: libc::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_mutex_s {
    pub __lock: libc::c_int,
    pub __count: libc::c_uint,
    pub __owner: libc::c_int,
    pub __nusers: libc::c_uint,
    pub __kind: libc::c_int,
    pub __spins: libc::c_short,
    pub __elision: libc::c_short,
    pub __list: __pthread_list_t,
}
pub type __pthread_list_t = __pthread_internal_list;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_internal_list {
    pub __prev: *mut __pthread_internal_list,
    pub __next: *mut __pthread_internal_list,
}
pub const PTHREAD_MUTEX_TIMED_NP: C2RustUnnamed_3 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_cond_s {
    pub c2rust_unnamed: C2RustUnnamed_1,
    pub c2rust_unnamed_0: C2RustUnnamed,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_2,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}
pub type pthread_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutexattr_t {
    pub __size: [libc::c_char; 4],
    pub __align: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_condattr_t {
    pub __size: [libc::c_char; 4],
    pub __align: libc::c_int,
}
pub type pthread_key_t = libc::c_uint;
pub type pthread_once_t = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_cond_t {
    pub __data: __pthread_cond_s,
    pub __size: [libc::c_char; 48],
    pub __align: libc::c_longlong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlMutex {
    pub lock: pthread_mutex_t,
}
pub use crate::src::dict::xmlMutex;
pub use crate::src::dict::xmlMutexPtr;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlRMutex {
    pub lock: pthread_mutex_t,
    pub held: libc::c_uint,
    pub waiters: libc::c_uint,
    pub tid: pthread_t,
    pub cv: pthread_cond_t,
}
pub use crate::src::catalog::xmlRMutex;
pub use crate::src::catalog::xmlRMutexPtr;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserInputBuffer;
pub use crate::src::HTMLparser::xmlBufPtr;
pub use crate::src::HTMLparser::xmlBuf;
pub use crate::src::HTMLparser::xmlCharEncodingHandlerPtr;
pub use crate::src::HTMLparser::xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlCharEncodingHandler;
pub use crate::src::HTMLparser::iconv_t;
pub use crate::src::HTMLparser::xmlCharEncodingOutputFunc;
pub use crate::src::HTMLparser::xmlCharEncodingInputFunc;
pub use crate::src::HTMLparser::xmlInputCloseCallback;
pub use crate::src::HTMLparser::xmlInputReadCallback;
pub use crate::src::HTMLparser::xmlParserInputBuffer;
pub use crate::src::HTMLparser::xmlParserInputBufferPtr;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLtree::_xmlOutputBuffer;
pub use crate::src::HTMLtree::xmlOutputCloseCallback;
pub use crate::src::HTMLtree::xmlOutputWriteCallback;
pub use crate::src::HTMLtree::xmlOutputBuffer;
pub use crate::src::HTMLtree::xmlOutputBufferPtr;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserInput;
pub use crate::src::HTMLparser::xmlParserInputDeallocate;
pub use crate::src::HTMLparser::xmlParserInput;
pub use crate::src::HTMLparser::xmlParserInputPtr;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlNode;
pub use crate::src::HTMLparser::xmlNs;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlNs;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlDoc;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlDtd;
pub use crate::src::HTMLparser::xmlElementType;
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
pub use crate::src::HTMLparser::xmlNsType;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlAttr;
pub use crate::src::HTMLparser::xmlAttributeType;
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
pub use crate::src::HTMLparser::xmlError;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlError;
pub use crate::src::HTMLparser::xmlErrorLevel;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub use crate::src::HTMLparser::xmlNodePtr;
pub use crate::src::HTMLparser::xmlNode;
pub use crate::src::HTMLparser::xmlStructuredErrorFunc;
pub use crate::src::HTMLparser::xmlErrorPtr;
pub use crate::src::HTMLparser::externalSubsetSAXFunc;
pub use crate::src::HTMLparser::cdataBlockSAXFunc;
pub use crate::src::HTMLparser::getParameterEntitySAXFunc;
pub use crate::src::HTMLparser::xmlEntityPtr;
pub use crate::src::HTMLparser::xmlEntity;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlEntity;
pub use crate::src::HTMLparser::xmlEntityType;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub use crate::src::HTMLparser::fatalErrorSAXFunc;
pub use crate::src::HTMLparser::errorSAXFunc;
pub use crate::src::HTMLparser::warningSAXFunc;
pub use crate::src::HTMLparser::commentSAXFunc;
pub use crate::src::HTMLparser::processingInstructionSAXFunc;
pub use crate::src::HTMLparser::ignorableWhitespaceSAXFunc;
pub use crate::src::HTMLparser::charactersSAXFunc;
pub use crate::src::HTMLparser::referenceSAXFunc;
pub use crate::src::HTMLparser::endElementSAXFunc;
pub use crate::src::HTMLparser::startElementSAXFunc;
pub use crate::src::HTMLparser::endDocumentSAXFunc;
pub use crate::src::HTMLparser::startDocumentSAXFunc;
pub use crate::src::HTMLparser::setDocumentLocatorSAXFunc;
pub use crate::src::HTMLparser::xmlSAXLocatorPtr;
pub use crate::src::HTMLparser::xmlSAXLocator;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlSAXLocator;
pub use crate::src::HTMLparser::unparsedEntityDeclSAXFunc;
pub use crate::src::HTMLparser::elementDeclSAXFunc;
pub use crate::src::HTMLparser::xmlElementContentPtr;
pub use crate::src::HTMLparser::xmlElementContent;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlElementContent;
pub use crate::src::HTMLparser::xmlElementContentOccur;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub use crate::src::HTMLparser::xmlElementContentType;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub use crate::src::HTMLparser::attributeDeclSAXFunc;
pub use crate::src::HTMLparser::xmlEnumerationPtr;
pub use crate::src::HTMLparser::xmlEnumeration;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlEnumeration;
pub use crate::src::HTMLparser::notationDeclSAXFunc;
pub use crate::src::HTMLparser::entityDeclSAXFunc;
pub use crate::src::HTMLparser::getEntitySAXFunc;
pub use crate::src::HTMLparser::resolveEntitySAXFunc;
pub use crate::src::HTMLparser::hasExternalSubsetSAXFunc;
pub use crate::src::HTMLparser::hasInternalSubsetSAXFunc;
pub use crate::src::HTMLparser::isStandaloneSAXFunc;
pub use crate::src::HTMLparser::internalSubsetSAXFunc;
pub use crate::src::HTMLtree::xmlBufferAllocationScheme;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
pub use crate::src::HTMLparser::xmlGenericErrorFunc;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlSAXHandlerV1;
pub use crate::src::HTMLparser::xmlSAXHandlerV1;
pub use crate::src::HTMLparser::xmlCharEncoding;
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
pub use crate::src::HTMLparser::xmlFreeFunc;
pub use crate::src::HTMLparser::xmlMallocFunc;
pub use crate::src::HTMLparser::xmlReallocFunc;
pub use crate::src::encoding::xmlStrdupFunc;
pub use crate::src::globals::xmlParserInputBufferCreateFilenameFunc;
pub use crate::src::globals::xmlOutputBufferCreateFilenameFunc;
pub use crate::src::HTMLparser::xmlRegisterNodeFunc;
pub use crate::src::globals::xmlDeregisterNodeFunc;
// #[derive(Copy, Clone)]

pub use crate::src::globals::_xmlGlobalState;
pub use crate::src::globals::xmlGlobalState;
pub use crate::src::globals::xmlGlobalStatePtr;
pub type C2RustUnnamed_3 = libc::c_uint;
pub const PTHREAD_MUTEX_DEFAULT: C2RustUnnamed_3 = 0;
pub const PTHREAD_MUTEX_ERRORCHECK: C2RustUnnamed_3 = 2;
pub const PTHREAD_MUTEX_RECURSIVE: C2RustUnnamed_3 = 1;
pub const PTHREAD_MUTEX_NORMAL: C2RustUnnamed_3 = 0;
pub const PTHREAD_MUTEX_ADAPTIVE_NP: C2RustUnnamed_3 = 3;
pub const PTHREAD_MUTEX_ERRORCHECK_NP: C2RustUnnamed_3 = 2;
pub const PTHREAD_MUTEX_RECURSIVE_NP: C2RustUnnamed_3 = 1;
#[inline]
unsafe extern "C" fn pthread_equal(
    mut __thread1: pthread_t,
    mut __thread2: pthread_t,
) -> libc::c_int {
    return (__thread1 == __thread2) as libc::c_int;
}
static mut libxml_is_threaded: libc::c_int = -(1 as libc::c_int);
static mut globalkey: pthread_key_t = 0;
static mut mainthread: pthread_t = 0;
static mut once_control: pthread_once_t = 0 as libc::c_int;
static mut once_control_init: pthread_once_t = 0 as libc::c_int;
static mut global_init_lock: pthread_mutex_t = pthread_mutex_t {
    __data: {
        let mut init = __pthread_mutex_s {
            __lock: 0 as libc::c_int,
            __count: 0 as libc::c_int as libc::c_uint,
            __owner: 0 as libc::c_int,
            __nusers: 0 as libc::c_int as libc::c_uint,
            __kind: PTHREAD_MUTEX_TIMED_NP as libc::c_int,
            __spins: 0 as libc::c_int as libc::c_short,
            __elision: 0 as libc::c_int as libc::c_short,
            __list: {
                let mut init = __pthread_internal_list {
                    __prev: 0 as *const __pthread_internal_list
                        as *mut __pthread_internal_list,
                    __next: 0 as *const __pthread_internal_list
                        as *mut __pthread_internal_list,
                };
                init
            },
        };
        init
    },
};
static mut xmlLibraryLock: xmlRMutexPtr = 0 as *const xmlRMutex as xmlRMutexPtr;
#[no_mangle]
pub unsafe extern "C" fn xmlNewMutex() -> xmlMutexPtr {
    let mut tok: xmlMutexPtr = 0 as *mut xmlMutex;
    tok = malloc(::std::mem::size_of::<xmlMutex>() as libc::c_ulong) as xmlMutexPtr;
    if tok.is_null() {
        return 0 as xmlMutexPtr;
    }
    if libxml_is_threaded != 0 as libc::c_int {
        pthread_mutex_init(&mut (*tok).lock, 0 as *const pthread_mutexattr_t);
    }
    return tok;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeMutex(mut tok: xmlMutexPtr) {
    if tok.is_null() {
        return;
    }
    if libxml_is_threaded != 0 as libc::c_int {
        pthread_mutex_destroy(&mut (*tok).lock);
    }
    free(tok as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlMutexLock(mut tok: xmlMutexPtr) {
    if tok.is_null() {
        return;
    }
    if libxml_is_threaded != 0 as libc::c_int {
        pthread_mutex_lock(&mut (*tok).lock);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlMutexUnlock(mut tok: xmlMutexPtr) {
    if tok.is_null() {
        return;
    }
    if libxml_is_threaded != 0 as libc::c_int {
        pthread_mutex_unlock(&mut (*tok).lock);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewRMutex() -> xmlRMutexPtr {
    let mut tok: xmlRMutexPtr = 0 as *mut xmlRMutex;
    tok = malloc(::std::mem::size_of::<xmlRMutex>() as libc::c_ulong) as xmlRMutexPtr;
    if tok.is_null() {
        return 0 as xmlRMutexPtr;
    }
    if libxml_is_threaded != 0 as libc::c_int {
        pthread_mutex_init(&mut (*tok).lock, 0 as *const pthread_mutexattr_t);
        (*tok).held = 0 as libc::c_int as libc::c_uint;
        (*tok).waiters = 0 as libc::c_int as libc::c_uint;
        pthread_cond_init(&mut (*tok).cv, 0 as *const pthread_condattr_t);
    }
    return tok;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeRMutex(mut tok: xmlRMutexPtr) {
    if tok.is_null() {
        return;
    }
    if libxml_is_threaded != 0 as libc::c_int {
        pthread_mutex_destroy(&mut (*tok).lock);
        pthread_cond_destroy(&mut (*tok).cv);
    }
    free(tok as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlRMutexLock(mut tok: xmlRMutexPtr) {
    if tok.is_null() {
        return;
    }
    if libxml_is_threaded == 0 as libc::c_int {
        return;
    }
    pthread_mutex_lock(&mut (*tok).lock);
    if (*tok).held != 0 {
        if pthread_equal((*tok).tid, pthread_self()) != 0 {
            let ref mut fresh0 = (*tok).held;
            *fresh0 = (*fresh0).wrapping_add(1);
            pthread_mutex_unlock(&mut (*tok).lock);
            return;
        } else {
            let ref mut fresh1 = (*tok).waiters;
            *fresh1 = (*fresh1).wrapping_add(1);
            while (*tok).held != 0 {
                pthread_cond_wait(&mut (*tok).cv, &mut (*tok).lock);
            }
            let ref mut fresh2 = (*tok).waiters;
            *fresh2 = (*fresh2).wrapping_sub(1);
        }
    }
    (*tok).tid = pthread_self();
    (*tok).held = 1 as libc::c_int as libc::c_uint;
    pthread_mutex_unlock(&mut (*tok).lock);
}
#[no_mangle]
pub unsafe extern "C" fn xmlRMutexUnlock(mut tok: xmlRMutexPtr) {
    if tok.is_null() {
        return;
    }
    if libxml_is_threaded == 0 as libc::c_int {
        return;
    }
    pthread_mutex_lock(&mut (*tok).lock);
    let ref mut fresh3 = (*tok).held;
    *fresh3 = (*fresh3).wrapping_sub(1);
    if (*tok).held == 0 as libc::c_int as libc::c_uint {
        if (*tok).waiters != 0 {
            pthread_cond_signal(&mut (*tok).cv);
        }
        memset(
            &mut (*tok).tid as *mut pthread_t as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<pthread_t>() as libc::c_ulong,
        );
    }
    pthread_mutex_unlock(&mut (*tok).lock);
}
#[no_mangle]
pub unsafe extern "C" fn __xmlGlobalInitMutexLock() {
    if (Some(
        pthread_mutex_lock as unsafe extern "C" fn(*mut pthread_mutex_t) -> libc::c_int,
    ))
        .is_none()
    {
        return;
    }
    pthread_mutex_lock(&mut global_init_lock);
}
#[no_mangle]
pub unsafe extern "C" fn __xmlGlobalInitMutexUnlock() {
    if (Some(
        pthread_mutex_unlock as unsafe extern "C" fn(*mut pthread_mutex_t) -> libc::c_int,
    ))
        .is_none()
    {
        return;
    }
    pthread_mutex_unlock(&mut global_init_lock);
}
#[no_mangle]
pub unsafe extern "C" fn __xmlGlobalInitMutexDestroy() {}
unsafe extern "C" fn xmlFreeGlobalState(mut state: *mut libc::c_void) {
    let mut gs: *mut xmlGlobalState = state as *mut xmlGlobalState;
    xmlResetError(&mut (*gs).xmlLastError);
    free(state);
}
unsafe extern "C" fn xmlNewGlobalState() -> xmlGlobalStatePtr {
    let mut gs: *mut xmlGlobalState = 0 as *mut xmlGlobalState;
    gs = malloc(::std::mem::size_of::<xmlGlobalState>() as libc::c_ulong)
        as *mut xmlGlobalState;
    if gs.is_null() {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlGetGlobalState: out of memory\n\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlGlobalStatePtr;
    }
    memset(
        gs as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlGlobalState>() as libc::c_ulong,
    );
    xmlInitializeGlobalState(gs);
    return gs;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetGlobalState() -> xmlGlobalStatePtr {
    let mut globalval: *mut xmlGlobalState = 0 as *mut xmlGlobalState;
    if libxml_is_threaded == 0 as libc::c_int {
        return 0 as xmlGlobalStatePtr;
    }
    pthread_once(&mut once_control, Some(xmlOnceInit as unsafe extern "C" fn() -> ()));
    globalval = pthread_getspecific(globalkey) as *mut xmlGlobalState;
    if globalval.is_null() {
        let mut tsd: *mut xmlGlobalState = xmlNewGlobalState();
        if tsd.is_null() {
            return 0 as xmlGlobalStatePtr;
        }
        pthread_setspecific(globalkey, tsd as *const libc::c_void);
        return tsd;
    }
    return globalval;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetThreadId() -> libc::c_int {
    let mut id: pthread_t = 0;
    let mut ret: libc::c_int = 0;
    if libxml_is_threaded == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    id = pthread_self();
    memcpy(
        &mut ret as *mut libc::c_int as *mut libc::c_void,
        &mut id as *mut pthread_t as *const libc::c_void,
        ::std::mem::size_of::<libc::c_int>() as libc::c_ulong,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsMainThread() -> libc::c_int {
    if libxml_is_threaded == -(1 as libc::c_int) {
        xmlInitThreads();
    }
    if libxml_is_threaded == 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    pthread_once(&mut once_control, Some(xmlOnceInit as unsafe extern "C" fn() -> ()));
    return pthread_equal(mainthread, pthread_self());
}
#[no_mangle]
pub unsafe extern "C" fn xmlLockLibrary() {
    xmlRMutexLock(xmlLibraryLock);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUnlockLibrary() {
    xmlRMutexUnlock(xmlLibraryLock);
}
#[no_mangle]
pub unsafe extern "C" fn xmlInitThreads() {
    if libxml_is_threaded == -(1 as libc::c_int) {
        if (Some(
            pthread_once
                as unsafe extern "C" fn(
                    *mut pthread_once_t,
                    Option::<unsafe extern "C" fn() -> ()>,
                ) -> libc::c_int,
        ))
            .is_some()
            && (Some(
                pthread_getspecific
                    as unsafe extern "C" fn(pthread_key_t) -> *mut libc::c_void,
            ))
                .is_some()
            && (Some(
                pthread_setspecific
                    as unsafe extern "C" fn(
                        pthread_key_t,
                        *const libc::c_void,
                    ) -> libc::c_int,
            ))
                .is_some()
            && (Some(
                pthread_key_create
                    as unsafe extern "C" fn(
                        *mut pthread_key_t,
                        Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
                    ) -> libc::c_int,
            ))
                .is_some()
            && (Some(
                pthread_key_delete as unsafe extern "C" fn(pthread_key_t) -> libc::c_int,
            ))
                .is_some()
            && (Some(
                pthread_mutex_init
                    as unsafe extern "C" fn(
                        *mut pthread_mutex_t,
                        *const pthread_mutexattr_t,
                    ) -> libc::c_int,
            ))
                .is_some()
            && (Some(
                pthread_mutex_destroy
                    as unsafe extern "C" fn(*mut pthread_mutex_t) -> libc::c_int,
            ))
                .is_some()
            && (Some(
                pthread_mutex_lock
                    as unsafe extern "C" fn(*mut pthread_mutex_t) -> libc::c_int,
            ))
                .is_some()
            && (Some(
                pthread_mutex_unlock
                    as unsafe extern "C" fn(*mut pthread_mutex_t) -> libc::c_int,
            ))
                .is_some()
            && (Some(
                pthread_cond_init
                    as unsafe extern "C" fn(
                        *mut pthread_cond_t,
                        *const pthread_condattr_t,
                    ) -> libc::c_int,
            ))
                .is_some()
            && (Some(
                pthread_cond_destroy
                    as unsafe extern "C" fn(*mut pthread_cond_t) -> libc::c_int,
            ))
                .is_some()
            && (Some(
                pthread_cond_wait
                    as unsafe extern "C" fn(
                        *mut pthread_cond_t,
                        *mut pthread_mutex_t,
                    ) -> libc::c_int,
            ))
                .is_some()
            && (Some(
                pthread_equal
                    as unsafe extern "C" fn(pthread_t, pthread_t) -> libc::c_int,
            ))
                .is_some()
            && (Some(pthread_self as unsafe extern "C" fn() -> pthread_t)).is_some()
            && (Some(
                pthread_cond_signal
                    as unsafe extern "C" fn(*mut pthread_cond_t) -> libc::c_int,
            ))
                .is_some()
        {
            libxml_is_threaded = 1 as libc::c_int;
        } else {
            libxml_is_threaded = 0 as libc::c_int;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlCleanupThreads() {
    if libxml_is_threaded != 0 as libc::c_int {
        pthread_key_delete(globalkey);
    }
    once_control = once_control_init;
}
unsafe extern "C" fn xmlOnceInit() {
    pthread_key_create(
        &mut globalkey,
        Some(xmlFreeGlobalState as unsafe extern "C" fn(*mut libc::c_void) -> ()),
    );
    mainthread = pthread_self();
    __xmlInitializeDict();
}
