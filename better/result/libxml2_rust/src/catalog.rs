use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _xmlRMutex;
    pub type _xmlAutomata;
    fn xmlStrncmp(str1: *const u8, str2: *const u8, len: i32) -> i32;
    fn xmlStrEqual(str1: *const u8, str2: *const u8) -> i32;
    fn xmlStrlen(str: *const u8) -> i32;
    fn xmlStrcat(cur: *mut u8, add: *const u8) -> *mut u8;
    fn xmlStrdup(cur: *const u8) -> *mut u8;
    fn xmlStrndup(cur: *const u8, len: i32) -> *mut u8;
    fn fprintf(_: *mut crate::src::HTMLtree::_IO_FILE, _: *const i8, _: ...) -> i32;
    fn snprintf(_: *mut i8, _: u64, _: *const i8, _: ...) -> i32;
    fn getenv(__name: *const i8) -> *mut i8;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn __xstat(
        __ver: i32,
        __filename: *const i8,
        __stat_buf: *mut crate::src::catalog::stat,
    ) -> i32;
    fn close(__fd: i32) -> i32;
    fn read(__fd: i32, __buf: *mut core::ffi::c_void, __nbytes: u64) -> i64;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    fn xmlNewDtd(
        doc: *mut crate::src::HTMLparser::_xmlDoc,
        name: *const u8,
        ExternalID: *const u8,
        SystemID: *const u8,
    ) -> *mut crate::src::HTMLparser::_xmlDtd;
    fn xmlNewNs(
        node: *mut crate::src::HTMLparser::_xmlNode,
        href: *const u8,
        prefix: *const u8,
    ) -> *mut crate::src::HTMLparser::_xmlNs;
    fn xmlFreeNs(cur: *mut crate::src::HTMLparser::_xmlNs);
    fn xmlNewDoc(version: *const u8) -> *mut crate::src::HTMLparser::_xmlDoc;
    fn xmlFreeDoc(cur: *mut crate::src::HTMLparser::_xmlDoc);
    fn xmlNewDocNode(
        doc: *mut crate::src::HTMLparser::_xmlDoc,
        ns: *mut crate::src::HTMLparser::_xmlNs,
        name: *const u8,
        content: *const u8,
    ) -> *mut crate::src::HTMLparser::_xmlNode;
    fn xmlDocGetRootElement(
        doc: *const crate::src::HTMLparser::_xmlDoc,
    ) -> *mut crate::src::HTMLparser::_xmlNode;
    fn xmlAddChild(
        parent: *mut crate::src::HTMLparser::_xmlNode,
        cur: *mut crate::src::HTMLparser::_xmlNode,
    ) -> *mut crate::src::HTMLparser::_xmlNode;
    fn xmlSearchNsByHref(
        doc: *mut crate::src::HTMLparser::_xmlDoc,
        node: *mut crate::src::HTMLparser::_xmlNode,
        href: *const u8,
    ) -> *mut crate::src::HTMLparser::_xmlNs;
    fn xmlSetProp(
        node: *mut crate::src::HTMLparser::_xmlNode,
        name: *const u8,
        value: *const u8,
    ) -> *mut crate::src::HTMLparser::_xmlAttr;
    fn xmlSetNsProp(
        node: *mut crate::src::HTMLparser::_xmlNode,
        ns: *mut crate::src::HTMLparser::_xmlNs,
        name: *const u8,
        value: *const u8,
    ) -> *mut crate::src::HTMLparser::_xmlAttr;
    fn xmlGetProp(node: *const crate::src::HTMLparser::_xmlNode, name: *const u8) -> *mut u8;
    fn xmlGetNsProp(
        node: *const crate::src::HTMLparser::_xmlNode,
        name: *const u8,
        nameSpace: *const u8,
    ) -> *mut u8;
    fn xmlNodeGetBase(
        doc: *const crate::src::HTMLparser::_xmlDoc,
        cur: *const crate::src::HTMLparser::_xmlNode,
    ) -> *mut u8;
    fn xmlSaveFormatFileTo(
        buf: *mut crate::src::HTMLtree::_xmlOutputBuffer,
        cur: *mut crate::src::HTMLparser::_xmlDoc,
        encoding: *const i8,
        format: i32,
    ) -> i32;
    fn xmlParserInputBufferCreateFilename(
        URI: *const i8,
        enc: i32,
    ) -> *mut crate::src::HTMLparser::_xmlParserInputBuffer;
    fn xmlFreeParserInputBuffer(in_0: *mut crate::src::HTMLparser::_xmlParserInputBuffer);
    fn xmlParserGetDirectory(filename: *const i8) -> *mut i8;
    fn xmlOutputBufferCreateFile(
        file: *mut crate::src::HTMLtree::_IO_FILE,
        encoder: *mut crate::src::HTMLparser::_xmlCharEncodingHandler,
    ) -> *mut crate::src::HTMLtree::_xmlOutputBuffer;
    fn xmlGetThreadId() -> i32;
    fn xmlFreeRMutex(tok: *mut crate::src::catalog::_xmlRMutex);
    fn xmlRMutexUnlock(tok: *mut crate::src::catalog::_xmlRMutex);
    fn xmlRMutexLock(tok: *mut crate::src::catalog::_xmlRMutex);
    fn xmlNewRMutex() -> *mut crate::src::catalog::_xmlRMutex;
    fn xmlBuildURI(URI: *const u8, base: *const u8) -> *mut u8;
    fn xmlCanonicPath(path: *const u8) -> *mut u8;
}
pub use crate::src::buf::_xmlBuf;
pub use crate::src::buf::xmlBufResetInput;
pub use crate::src::chvalid::xmlCharInRange;
pub use crate::src::chvalid::xmlIsBaseCharGroup;
pub use crate::src::chvalid::xmlIsDigitGroup;
pub use crate::src::chvalid::xmlIsPubidChar_tab;
pub use crate::src::debugXML::_xmlValidState;
pub use crate::src::dict::_xmlDict;
pub use crate::src::encoding::_xmlAutomataState;
pub use crate::src::error::__xmlRaiseError;
pub use crate::src::globals::__xmlDefaultSAXHandler;
pub use crate::src::globals::__xmlGenericError;
pub use crate::src::globals::__xmlGenericErrorContext;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub use crate::src::globals::xmlMallocAtomic;
pub use crate::src::globals::xmlRealloc;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::hash::xmlHashAddEntry;
pub use crate::src::hash::xmlHashCreate;
pub use crate::src::hash::xmlHashFree;
pub use crate::src::hash::xmlHashLookup;
pub use crate::src::hash::xmlHashRemoveEntry;
pub use crate::src::hash::xmlHashScan;
pub use crate::src::hash::xmlHashSize;
pub use crate::src::parser::_xmlStartTag;
pub use crate::src::parser::inputPush;
pub use crate::src::parser::xmlParseDocument;
pub use crate::src::parserInternals::xmlFreeParserCtxt;
pub use crate::src::parserInternals::xmlNewInputStream;
pub use crate::src::parserInternals::xmlNewParserCtxt;
pub use crate::src::relaxng::_IO_codecvt;
pub use crate::src::HTMLtree::_IO_marker;
pub type xmlChar = u8;
pub type size_t = u64;
pub type __dev_t = u64;
pub type __uid_t = u32;
pub type __gid_t = u32;
pub type __ino_t = u64;
pub type __mode_t = u32;
pub type __nlink_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __time_t = i64;
pub type __blksize_t = i64;
pub type __blkcnt_t = i64;
pub type __ssize_t = i64;
pub type __syscall_slong_t = i64;
pub type _IO_FILE = crate::src::HTMLtree::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::HTMLtree::_IO_FILE;
pub type ssize_t = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}
impl timespec {
    pub const fn new() -> Self {
        timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }
}
impl std::default::Default for timespec {
    fn default() -> Self {
        timespec::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: i32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atim: crate::src::catalog::timespec,
    pub st_mtim: crate::src::catalog::timespec,
    pub st_ctim: crate::src::catalog::timespec,
    pub __glibc_reserved: [i64; 3],
}
impl stat {
    pub const fn new() -> Self {
        stat {
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
            st_atim: crate::src::catalog::timespec::new(),
            st_mtim: crate::src::catalog::timespec::new(),
            st_ctim: crate::src::catalog::timespec::new(),
            __glibc_reserved: [0, 0, 0],
        }
    }
}
impl std::default::Default for stat {
    fn default() -> Self {
        stat::new()
    }
}
pub type xmlFreeFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
pub type xmlReallocFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void>;
pub type xmlRMutex = crate::src::catalog::_xmlRMutex;
pub type xmlRMutexPtr = *mut crate::src::catalog::_xmlRMutex;
pub type _xmlParserInputBuffer = crate::src::HTMLparser::_xmlParserInputBuffer;
pub type xmlBufPtr = *mut crate::src::buf::_xmlBuf;
pub type xmlBuf = crate::src::buf::_xmlBuf;
pub type xmlCharEncodingHandlerPtr = *mut crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type _xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type iconv_t = *mut core::ffi::c_void;
pub type xmlCharEncodingOutputFunc =
    Option<unsafe extern "C" fn(_: *mut u8, _: *mut i32, _: *const u8, _: *mut i32) -> i32>;
pub type xmlCharEncodingInputFunc =
    Option<unsafe extern "C" fn(_: *mut u8, _: *mut i32, _: *const u8, _: *mut i32) -> i32>;
pub type xmlInputCloseCallback = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type xmlInputReadCallback =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut i8, _: i32) -> i32>;
pub type xmlParserInputBuffer = crate::src::HTMLparser::_xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = *mut crate::src::HTMLparser::_xmlParserInputBuffer;
pub type _xmlOutputBuffer = crate::src::HTMLtree::_xmlOutputBuffer;
pub type xmlOutputCloseCallback = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type xmlOutputWriteCallback =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, _: i32) -> i32>;
pub type xmlOutputBuffer = crate::src::HTMLtree::_xmlOutputBuffer;
pub type xmlOutputBufferPtr = *mut crate::src::HTMLtree::_xmlOutputBuffer;
pub type _xmlParserInput = crate::src::HTMLparser::_xmlParserInput;
pub type xmlParserInputDeallocate = Option<unsafe extern "C" fn(_: *mut u8) -> ()>;
pub type xmlParserInput = crate::src::HTMLparser::_xmlParserInput;
pub type xmlParserInputPtr = *mut crate::src::HTMLparser::_xmlParserInput;
pub type _xmlParserCtxt = crate::src::HTMLparser::_xmlParserCtxt;
pub type xmlParserNodeInfo = crate::src::HTMLparser::_xmlParserNodeInfo;
pub type _xmlParserNodeInfo = crate::src::HTMLparser::_xmlParserNodeInfo;
pub type _xmlNode = crate::src::HTMLparser::_xmlNode;
pub type xmlNs = crate::src::HTMLparser::_xmlNs;
pub type _xmlNs = crate::src::HTMLparser::_xmlNs;
pub type _xmlDoc = crate::src::HTMLparser::_xmlDoc;
pub type _xmlDtd = crate::src::HTMLparser::_xmlDtd;
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
pub type _xmlAttr = crate::src::HTMLparser::_xmlAttr;
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
pub type xmlParserMode = u32;
pub const XML_PARSE_READER: xmlParserMode = 5;
pub const XML_PARSE_PUSH_SAX: xmlParserMode = 4;
pub const XML_PARSE_PUSH_DOM: xmlParserMode = 3;
pub const XML_PARSE_SAX: xmlParserMode = 2;
pub const XML_PARSE_DOM: xmlParserMode = 1;
pub const XML_PARSE_UNKNOWN: xmlParserMode = 0;
pub type xmlError = crate::src::HTMLparser::_xmlError;
pub type _xmlError = crate::src::HTMLparser::_xmlError;
pub type xmlErrorLevel = u32;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlAttrPtr = *mut crate::src::HTMLparser::_xmlAttr;
pub type xmlAttr = crate::src::HTMLparser::_xmlAttr;
pub type xmlNodePtr = *mut crate::src::HTMLparser::_xmlNode;
pub type xmlNode = crate::src::HTMLparser::_xmlNode;
pub type xmlHashTablePtr = *mut crate::src::hash::_xmlHashTable;
pub type xmlHashTable = crate::src::hash::_xmlHashTable;
pub type xmlStartTag = crate::src::parser::_xmlStartTag;
pub type xmlDictPtr = *mut crate::src::dict::_xmlDict;
pub type xmlDict = crate::src::dict::_xmlDict;
pub type xmlParserInputState = i32;
pub const XML_PARSER_PUBLIC_LITERAL: xmlParserInputState = 16;
pub const XML_PARSER_IGNORE: xmlParserInputState = 15;
pub const XML_PARSER_EPILOG: xmlParserInputState = 14;
pub const XML_PARSER_SYSTEM_LITERAL: xmlParserInputState = 13;
pub const XML_PARSER_ATTRIBUTE_VALUE: xmlParserInputState = 12;
pub const XML_PARSER_ENTITY_VALUE: xmlParserInputState = 11;
pub const XML_PARSER_ENTITY_DECL: xmlParserInputState = 10;
pub const XML_PARSER_END_TAG: xmlParserInputState = 9;
pub const XML_PARSER_CDATA_SECTION: xmlParserInputState = 8;
pub const XML_PARSER_CONTENT: xmlParserInputState = 7;
pub const XML_PARSER_START_TAG: xmlParserInputState = 6;
pub const XML_PARSER_COMMENT: xmlParserInputState = 5;
pub const XML_PARSER_PROLOG: xmlParserInputState = 4;
pub const XML_PARSER_DTD: xmlParserInputState = 3;
pub const XML_PARSER_PI: xmlParserInputState = 2;
pub const XML_PARSER_MISC: xmlParserInputState = 1;
pub const XML_PARSER_START: xmlParserInputState = 0;
pub const XML_PARSER_EOF: xmlParserInputState = -1;
pub type xmlValidCtxt = crate::src::HTMLparser::_xmlValidCtxt;
pub type _xmlValidCtxt = crate::src::HTMLparser::_xmlValidCtxt;
pub type xmlAutomataStatePtr = *mut crate::src::encoding::_xmlAutomataState;
pub type xmlAutomataState = crate::src::encoding::_xmlAutomataState;
pub type xmlAutomataPtr = *mut crate::src::catalog::_xmlAutomata;
pub type xmlAutomata = crate::src::catalog::_xmlAutomata;
pub type xmlValidState = crate::src::debugXML::_xmlValidState;
pub type xmlDocPtr = *mut crate::src::HTMLparser::_xmlDoc;
pub type xmlDoc = crate::src::HTMLparser::_xmlDoc;
pub type xmlValidityWarningFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type xmlValidityErrorFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type xmlParserNodeInfoSeq = crate::src::HTMLparser::_xmlParserNodeInfoSeq;
pub type _xmlParserNodeInfoSeq = crate::src::HTMLparser::_xmlParserNodeInfoSeq;
pub type _xmlSAXHandler = crate::src::HTMLparser::_xmlSAXHandler;
pub type xmlStructuredErrorFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *mut crate::src::HTMLparser::_xmlError,
    ) -> (),
>;
pub type xmlErrorPtr = *mut crate::src::HTMLparser::_xmlError;
pub type endElementNsSAX2Func = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type startElementNsSAX2Func = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
        _: *const u8,
        _: i32,
        _: *mut *const u8,
        _: i32,
        _: i32,
        _: *mut *const u8,
    ) -> (),
>;
pub type externalSubsetSAXFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type cdataBlockSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>;
pub type getParameterEntitySAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
    ) -> *mut crate::src::HTMLparser::_xmlEntity,
>;
pub type xmlEntityPtr = *mut crate::src::HTMLparser::_xmlEntity;
pub type xmlEntity = crate::src::HTMLparser::_xmlEntity;
pub type _xmlEntity = crate::src::HTMLparser::_xmlEntity;
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
        _: *mut crate::src::HTMLparser::_xmlSAXLocator,
    ) -> (),
>;
pub type xmlSAXLocatorPtr = *mut crate::src::HTMLparser::_xmlSAXLocator;
pub type xmlSAXLocator = crate::src::HTMLparser::_xmlSAXLocator;
pub type _xmlSAXLocator = crate::src::HTMLparser::_xmlSAXLocator;
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
        _: *mut crate::src::HTMLparser::_xmlElementContent,
    ) -> (),
>;
pub type xmlElementContentPtr = *mut crate::src::HTMLparser::_xmlElementContent;
pub type xmlElementContent = crate::src::HTMLparser::_xmlElementContent;
pub type _xmlElementContent = crate::src::HTMLparser::_xmlElementContent;
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
        _: *mut crate::src::HTMLparser::_xmlEnumeration,
    ) -> (),
>;
pub type xmlEnumerationPtr = *mut crate::src::HTMLparser::_xmlEnumeration;
pub type xmlEnumeration = crate::src::HTMLparser::_xmlEnumeration;
pub type _xmlEnumeration = crate::src::HTMLparser::_xmlEnumeration;
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
    ) -> *mut crate::src::HTMLparser::_xmlEntity,
>;
pub type resolveEntitySAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
    ) -> *mut crate::src::HTMLparser::_xmlParserInput,
>;
pub type hasExternalSubsetSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type hasInternalSubsetSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type isStandaloneSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type internalSubsetSAXFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type xmlParserCtxt = crate::src::HTMLparser::_xmlParserCtxt;
pub type xmlParserCtxtPtr = *mut crate::src::HTMLparser::_xmlParserCtxt;
pub type xmlNsPtr = *mut crate::src::HTMLparser::_xmlNs;
pub type xmlDtd = crate::src::HTMLparser::_xmlDtd;
pub type xmlDtdPtr = *mut crate::src::HTMLparser::_xmlDtd;
pub type xmlHashDeallocator =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>;
pub type xmlHashScanner = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut core::ffi::c_void, _: *const u8) -> (),
>;
pub type C2RustUnnamed = u32;
pub const XML_FROM_URI: C2RustUnnamed = 30;
pub const XML_FROM_BUFFER: C2RustUnnamed = 29;
pub const XML_FROM_SCHEMATRONV: C2RustUnnamed = 28;
pub const XML_FROM_I18N: C2RustUnnamed = 27;
pub const XML_FROM_MODULE: C2RustUnnamed = 26;
pub const XML_FROM_WRITER: C2RustUnnamed = 25;
pub const XML_FROM_CHECK: C2RustUnnamed = 24;
pub const XML_FROM_VALID: C2RustUnnamed = 23;
pub const XML_FROM_XSLT: C2RustUnnamed = 22;
pub const XML_FROM_C14N: C2RustUnnamed = 21;
pub const XML_FROM_CATALOG: C2RustUnnamed = 20;
pub const XML_FROM_RELAXNGV: C2RustUnnamed = 19;
pub const XML_FROM_RELAXNGP: C2RustUnnamed = 18;
pub const XML_FROM_SCHEMASV: C2RustUnnamed = 17;
pub const XML_FROM_SCHEMASP: C2RustUnnamed = 16;
pub const XML_FROM_DATATYPE: C2RustUnnamed = 15;
pub const XML_FROM_REGEXP: C2RustUnnamed = 14;
pub const XML_FROM_XPOINTER: C2RustUnnamed = 13;
pub const XML_FROM_XPATH: C2RustUnnamed = 12;
pub const XML_FROM_XINCLUDE: C2RustUnnamed = 11;
pub const XML_FROM_HTTP: C2RustUnnamed = 10;
pub const XML_FROM_FTP: C2RustUnnamed = 9;
pub const XML_FROM_IO: C2RustUnnamed = 8;
pub const XML_FROM_OUTPUT: C2RustUnnamed = 7;
pub const XML_FROM_MEMORY: C2RustUnnamed = 6;
pub const XML_FROM_HTML: C2RustUnnamed = 5;
pub const XML_FROM_DTD: C2RustUnnamed = 4;
pub const XML_FROM_NAMESPACE: C2RustUnnamed = 3;
pub const XML_FROM_TREE: C2RustUnnamed = 2;
pub const XML_FROM_PARSER: C2RustUnnamed = 1;
pub const XML_FROM_NONE: C2RustUnnamed = 0;
pub type C2RustUnnamed_0 = u32;
pub const XML_BUF_OVERFLOW: C2RustUnnamed_0 = 7000;
pub const XML_I18N_NO_OUTPUT: C2RustUnnamed_0 = 6004;
pub const XML_I18N_CONV_FAILED: C2RustUnnamed_0 = 6003;
pub const XML_I18N_EXCESS_HANDLER: C2RustUnnamed_0 = 6002;
pub const XML_I18N_NO_HANDLER: C2RustUnnamed_0 = 6001;
pub const XML_I18N_NO_NAME: C2RustUnnamed_0 = 6000;
pub const XML_CHECK_NAME_NOT_NULL: C2RustUnnamed_0 = 5037;
pub const XML_CHECK_WRONG_NAME: C2RustUnnamed_0 = 5036;
pub const XML_CHECK_OUTSIDE_DICT: C2RustUnnamed_0 = 5035;
pub const XML_CHECK_NOT_NCNAME: C2RustUnnamed_0 = 5034;
pub const XML_CHECK_NO_DICT: C2RustUnnamed_0 = 5033;
pub const XML_CHECK_NOT_UTF8: C2RustUnnamed_0 = 5032;
pub const XML_CHECK_NS_ANCESTOR: C2RustUnnamed_0 = 5031;
pub const XML_CHECK_NS_SCOPE: C2RustUnnamed_0 = 5030;
pub const XML_CHECK_WRONG_PARENT: C2RustUnnamed_0 = 5029;
pub const XML_CHECK_NO_HREF: C2RustUnnamed_0 = 5028;
pub const XML_CHECK_NOT_NS_DECL: C2RustUnnamed_0 = 5027;
pub const XML_CHECK_NOT_ENTITY_DECL: C2RustUnnamed_0 = 5026;
pub const XML_CHECK_NOT_ELEM_DECL: C2RustUnnamed_0 = 5025;
pub const XML_CHECK_NOT_ATTR_DECL: C2RustUnnamed_0 = 5024;
pub const XML_CHECK_NOT_ATTR: C2RustUnnamed_0 = 5023;
pub const XML_CHECK_NOT_DTD: C2RustUnnamed_0 = 5022;
pub const XML_CHECK_WRONG_NEXT: C2RustUnnamed_0 = 5021;
pub const XML_CHECK_NO_NEXT: C2RustUnnamed_0 = 5020;
pub const XML_CHECK_WRONG_PREV: C2RustUnnamed_0 = 5019;
pub const XML_CHECK_NO_PREV: C2RustUnnamed_0 = 5018;
pub const XML_CHECK_WRONG_DOC: C2RustUnnamed_0 = 5017;
pub const XML_CHECK_NO_ELEM: C2RustUnnamed_0 = 5016;
pub const XML_CHECK_NO_NAME: C2RustUnnamed_0 = 5015;
pub const XML_CHECK_NO_DOC: C2RustUnnamed_0 = 5014;
pub const XML_CHECK_NO_PARENT: C2RustUnnamed_0 = 5013;
pub const XML_CHECK_ENTITY_TYPE: C2RustUnnamed_0 = 5012;
pub const XML_CHECK_UNKNOWN_NODE: C2RustUnnamed_0 = 5011;
pub const XML_CHECK_FOUND_NOTATION: C2RustUnnamed_0 = 5010;
pub const XML_CHECK_FOUND_FRAGMENT: C2RustUnnamed_0 = 5009;
pub const XML_CHECK_FOUND_DOCTYPE: C2RustUnnamed_0 = 5008;
pub const XML_CHECK_FOUND_COMMENT: C2RustUnnamed_0 = 5007;
pub const XML_CHECK_FOUND_PI: C2RustUnnamed_0 = 5006;
pub const XML_CHECK_FOUND_ENTITY: C2RustUnnamed_0 = 5005;
pub const XML_CHECK_FOUND_ENTITYREF: C2RustUnnamed_0 = 5004;
pub const XML_CHECK_FOUND_CDATA: C2RustUnnamed_0 = 5003;
pub const XML_CHECK_FOUND_TEXT: C2RustUnnamed_0 = 5002;
pub const XML_CHECK_FOUND_ATTRIBUTE: C2RustUnnamed_0 = 5001;
pub const XML_CHECK_FOUND_ELEMENT: C2RustUnnamed_0 = 5000;
pub const XML_MODULE_CLOSE: C2RustUnnamed_0 = 4901;
pub const XML_MODULE_OPEN: C2RustUnnamed_0 = 4900;
pub const XML_SCHEMATRONV_REPORT: C2RustUnnamed_0 = 4001;
pub const XML_SCHEMATRONV_ASSERT: C2RustUnnamed_0 = 4000;
pub const XML_SCHEMAP_COS_ALL_LIMITED: C2RustUnnamed_0 = 3091;
pub const XML_SCHEMAP_A_PROPS_CORRECT_3: C2RustUnnamed_0 = 3090;
pub const XML_SCHEMAP_AU_PROPS_CORRECT: C2RustUnnamed_0 = 3089;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_2: C2RustUnnamed_0 = 3088;
pub const XML_SCHEMAP_AG_PROPS_CORRECT: C2RustUnnamed_0 = 3087;
pub const XML_SCHEMAP_WARN_ATTR_POINTLESS_PROH: C2RustUnnamed_0 = 3086;
pub const XML_SCHEMAP_WARN_ATTR_REDECL_PROH: C2RustUnnamed_0 = 3085;
pub const XML_SCHEMAP_WARN_UNLOCATED_SCHEMA: C2RustUnnamed_0 = 3084;
pub const XML_SCHEMAP_WARN_SKIP_SCHEMA: C2RustUnnamed_0 = 3083;
pub const XML_SCHEMAP_SRC_IMPORT: C2RustUnnamed_0 = 3082;
pub const XML_SCHEMAP_SRC_REDEFINE: C2RustUnnamed_0 = 3081;
pub const XML_SCHEMAP_C_PROPS_CORRECT: C2RustUnnamed_0 = 3080;
pub const XML_SCHEMAP_A_PROPS_CORRECT_2: C2RustUnnamed_0 = 3079;
pub const XML_SCHEMAP_AU_PROPS_CORRECT_2: C2RustUnnamed_0 = 3078;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_3: C2RustUnnamed_0 = 3077;
pub const XML_SCHEMAP_SRC_CT_1: C2RustUnnamed_0 = 3076;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_2: C2RustUnnamed_0 = 3075;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_1: C2RustUnnamed_0 = 3074;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_3: C2RustUnnamed_0 = 3073;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_2: C2RustUnnamed_0 = 3072;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_1: C2RustUnnamed_0 = 3071;
pub const XML_SCHEMAP_NOT_DETERMINISTIC: C2RustUnnamed_0 = 3070;
pub const XML_SCHEMAP_INTERNAL: C2RustUnnamed_0 = 3069;
pub const XML_SCHEMAP_SRC_IMPORT_2_2: C2RustUnnamed_0 = 3068;
pub const XML_SCHEMAP_SRC_IMPORT_2_1: C2RustUnnamed_0 = 3067;
pub const XML_SCHEMAP_SRC_IMPORT_2: C2RustUnnamed_0 = 3066;
pub const XML_SCHEMAP_SRC_IMPORT_1_2: C2RustUnnamed_0 = 3065;
pub const XML_SCHEMAP_SRC_IMPORT_1_1: C2RustUnnamed_0 = 3064;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_1: C2RustUnnamed_0 = 3063;
pub const XML_SCHEMAP_CVC_SIMPLE_TYPE: C2RustUnnamed_0 = 3062;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_2: C2RustUnnamed_0 = 3061;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_1: C2RustUnnamed_0 = 3060;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_1: C2RustUnnamed_0 = 3059;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_1: C2RustUnnamed_0 = 3058;
pub const XML_SCHEMAP_NO_XSI: C2RustUnnamed_0 = 3057;
pub const XML_SCHEMAP_NO_XMLNS: C2RustUnnamed_0 = 3056;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_4: C2RustUnnamed_0 = 3055;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_2: C2RustUnnamed_0 = 3054;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_1: C2RustUnnamed_0 = 3053;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_2: C2RustUnnamed_0 = 3052;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_1: C2RustUnnamed_0 = 3051;
pub const XML_SCHEMAP_SRC_INCLUDE: C2RustUnnamed_0 = 3050;
pub const XML_SCHEMAP_E_PROPS_CORRECT_6: C2RustUnnamed_0 = 3049;
pub const XML_SCHEMAP_E_PROPS_CORRECT_5: C2RustUnnamed_0 = 3048;
pub const XML_SCHEMAP_E_PROPS_CORRECT_4: C2RustUnnamed_0 = 3047;
pub const XML_SCHEMAP_E_PROPS_CORRECT_3: C2RustUnnamed_0 = 3046;
pub const XML_SCHEMAP_E_PROPS_CORRECT_2: C2RustUnnamed_0 = 3045;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_2: C2RustUnnamed_0 = 3044;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_1: C2RustUnnamed_0 = 3043;
pub const XML_SCHEMAP_P_PROPS_CORRECT_1: C2RustUnnamed_0 = 3042;
pub const XML_SCHEMAP_SRC_ELEMENT_3: C2RustUnnamed_0 = 3041;
pub const XML_SCHEMAP_SRC_ELEMENT_2_2: C2RustUnnamed_0 = 3040;
pub const XML_SCHEMAP_SRC_ELEMENT_2_1: C2RustUnnamed_0 = 3039;
pub const XML_SCHEMAP_SRC_ELEMENT_1: C2RustUnnamed_0 = 3038;
pub const XML_SCHEMAP_S4S_ATTR_INVALID_VALUE: C2RustUnnamed_0 = 3037;
pub const XML_SCHEMAP_S4S_ATTR_MISSING: C2RustUnnamed_0 = 3036;
pub const XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED: C2RustUnnamed_0 = 3035;
pub const XML_SCHEMAP_S4S_ELEM_MISSING: C2RustUnnamed_0 = 3034;
pub const XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED: C2RustUnnamed_0 = 3033;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_2: C2RustUnnamed_0 = 3032;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_1: C2RustUnnamed_0 = 3031;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_5: C2RustUnnamed_0 = 3030;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_4: C2RustUnnamed_0 = 3029;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_3: C2RustUnnamed_0 = 3028;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_1: C2RustUnnamed_0 = 3027;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_2: C2RustUnnamed_0 = 3026;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1_2: C2RustUnnamed_0 = 3025;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1: C2RustUnnamed_0 = 3024;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_1: C2RustUnnamed_0 = 3023;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_5: C2RustUnnamed_0 = 3022;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_4: C2RustUnnamed_0 = 3021;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_3: C2RustUnnamed_0 = 3020;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_2: C2RustUnnamed_0 = 3019;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_1: C2RustUnnamed_0 = 3018;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_2: C2RustUnnamed_0 = 3017;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_1: C2RustUnnamed_0 = 3016;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_1: C2RustUnnamed_0 = 3015;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_2: C2RustUnnamed_0 = 3014;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_1: C2RustUnnamed_0 = 3013;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_2: C2RustUnnamed_0 = 3012;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_1: C2RustUnnamed_0 = 3011;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_3: C2RustUnnamed_0 = 3010;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_2: C2RustUnnamed_0 = 3009;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_1: C2RustUnnamed_0 = 3008;
pub const XML_SCHEMAP_SRC_UNION_MEMBERTYPES_OR_SIMPLETYPES: C2RustUnnamed_0 = 3007;
pub const XML_SCHEMAP_SRC_LIST_ITEMTYPE_OR_SIMPLETYPE: C2RustUnnamed_0 = 3006;
pub const XML_SCHEMAP_SRC_RESTRICTION_BASE_OR_SIMPLETYPE: C2RustUnnamed_0 = 3005;
pub const XML_SCHEMAP_SRC_RESOLVE: C2RustUnnamed_0 = 3004;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_4: C2RustUnnamed_0 = 3003;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_3: C2RustUnnamed_0 = 3002;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_2: C2RustUnnamed_0 = 3001;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_1: C2RustUnnamed_0 = 3000;
pub const XML_HTTP_UNKNOWN_HOST: C2RustUnnamed_0 = 2022;
pub const XML_HTTP_USE_IP: C2RustUnnamed_0 = 2021;
pub const XML_HTTP_URL_SYNTAX: C2RustUnnamed_0 = 2020;
pub const XML_FTP_URL_SYNTAX: C2RustUnnamed_0 = 2003;
pub const XML_FTP_ACCNT: C2RustUnnamed_0 = 2002;
pub const XML_FTP_EPSV_ANSWER: C2RustUnnamed_0 = 2001;
pub const XML_FTP_PASV_ANSWER: C2RustUnnamed_0 = 2000;
pub const XML_C14N_RELATIVE_NAMESPACE: C2RustUnnamed_0 = 1955;
pub const XML_C14N_UNKNOW_NODE: C2RustUnnamed_0 = 1954;
pub const XML_C14N_INVALID_NODE: C2RustUnnamed_0 = 1953;
pub const XML_C14N_CREATE_STACK: C2RustUnnamed_0 = 1952;
pub const XML_C14N_REQUIRES_UTF8: C2RustUnnamed_0 = 1951;
pub const XML_C14N_CREATE_CTXT: C2RustUnnamed_0 = 1950;
pub const XML_XPTR_EXTRA_OBJECTS: C2RustUnnamed_0 = 1903;
pub const XML_XPTR_EVAL_FAILED: C2RustUnnamed_0 = 1902;
pub const XML_XPTR_CHILDSEQ_START: C2RustUnnamed_0 = 1901;
pub const XML_XPTR_UNKNOWN_SCHEME: C2RustUnnamed_0 = 1900;
pub const XML_SCHEMAV_MISC: C2RustUnnamed_0 = 1879;
pub const XML_SCHEMAV_CVC_WILDCARD: C2RustUnnamed_0 = 1878;
pub const XML_SCHEMAV_CVC_IDC: C2RustUnnamed_0 = 1877;
pub const XML_SCHEMAV_CVC_TYPE_2: C2RustUnnamed_0 = 1876;
pub const XML_SCHEMAV_CVC_TYPE_1: C2RustUnnamed_0 = 1875;
pub const XML_SCHEMAV_CVC_AU: C2RustUnnamed_0 = 1874;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_1: C2RustUnnamed_0 = 1873;
pub const XML_SCHEMAV_DOCUMENT_ELEMENT_MISSING: C2RustUnnamed_0 = 1872;
pub const XML_SCHEMAV_ELEMENT_CONTENT: C2RustUnnamed_0 = 1871;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_2: C2RustUnnamed_0 = 1870;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_1: C2RustUnnamed_0 = 1869;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_4: C2RustUnnamed_0 = 1868;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_2: C2RustUnnamed_0 = 1867;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_1: C2RustUnnamed_0 = 1866;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_1: C2RustUnnamed_0 = 1865;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_4: C2RustUnnamed_0 = 1864;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_3: C2RustUnnamed_0 = 1863;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_2: C2RustUnnamed_0 = 1862;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_1: C2RustUnnamed_0 = 1861;
pub const XML_SCHEMAV_CVC_ELT_7: C2RustUnnamed_0 = 1860;
pub const XML_SCHEMAV_CVC_ELT_6: C2RustUnnamed_0 = 1859;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_2: C2RustUnnamed_0 = 1858;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_1: C2RustUnnamed_0 = 1857;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_1: C2RustUnnamed_0 = 1856;
pub const XML_SCHEMAV_CVC_ELT_5_2_1: C2RustUnnamed_0 = 1855;
pub const XML_SCHEMAV_CVC_ELT_5_1_2: C2RustUnnamed_0 = 1854;
pub const XML_SCHEMAV_CVC_ELT_5_1_1: C2RustUnnamed_0 = 1853;
pub const XML_SCHEMAV_CVC_ELT_4_3: C2RustUnnamed_0 = 1852;
pub const XML_SCHEMAV_CVC_ELT_4_2: C2RustUnnamed_0 = 1851;
pub const XML_SCHEMAV_CVC_ELT_4_1: C2RustUnnamed_0 = 1850;
pub const XML_SCHEMAV_CVC_ELT_3_2_2: C2RustUnnamed_0 = 1849;
pub const XML_SCHEMAV_CVC_ELT_3_2_1: C2RustUnnamed_0 = 1848;
pub const XML_SCHEMAV_CVC_ELT_3_1: C2RustUnnamed_0 = 1847;
pub const XML_SCHEMAV_CVC_ELT_2: C2RustUnnamed_0 = 1846;
pub const XML_SCHEMAV_CVC_ELT_1: C2RustUnnamed_0 = 1845;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_4: C2RustUnnamed_0 = 1844;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_3: C2RustUnnamed_0 = 1843;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2: C2RustUnnamed_0 = 1842;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_1: C2RustUnnamed_0 = 1841;
pub const XML_SCHEMAV_CVC_ENUMERATION_VALID: C2RustUnnamed_0 = 1840;
pub const XML_SCHEMAV_CVC_PATTERN_VALID: C2RustUnnamed_0 = 1839;
pub const XML_SCHEMAV_CVC_FRACTIONDIGITS_VALID: C2RustUnnamed_0 = 1838;
pub const XML_SCHEMAV_CVC_TOTALDIGITS_VALID: C2RustUnnamed_0 = 1837;
pub const XML_SCHEMAV_CVC_MAXEXCLUSIVE_VALID: C2RustUnnamed_0 = 1836;
pub const XML_SCHEMAV_CVC_MINEXCLUSIVE_VALID: C2RustUnnamed_0 = 1835;
pub const XML_SCHEMAV_CVC_MAXINCLUSIVE_VALID: C2RustUnnamed_0 = 1834;
pub const XML_SCHEMAV_CVC_MININCLUSIVE_VALID: C2RustUnnamed_0 = 1833;
pub const XML_SCHEMAV_CVC_MAXLENGTH_VALID: C2RustUnnamed_0 = 1832;
pub const XML_SCHEMAV_CVC_MINLENGTH_VALID: C2RustUnnamed_0 = 1831;
pub const XML_SCHEMAV_CVC_LENGTH_VALID: C2RustUnnamed_0 = 1830;
pub const XML_SCHEMAV_CVC_FACET_VALID: C2RustUnnamed_0 = 1829;
pub const XML_SCHEMAV_CVC_TYPE_3_1_2: C2RustUnnamed_0 = 1828;
pub const XML_SCHEMAV_CVC_TYPE_3_1_1: C2RustUnnamed_0 = 1827;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_3: C2RustUnnamed_0 = 1826;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2: C2RustUnnamed_0 = 1825;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1: C2RustUnnamed_0 = 1824;
pub const XML_SCHEMAV_FACET: C2RustUnnamed_0 = 1823;
pub const XML_SCHEMAV_VALUE: C2RustUnnamed_0 = 1822;
pub const XML_SCHEMAV_ATTRINVALID: C2RustUnnamed_0 = 1821;
pub const XML_SCHEMAV_ATTRUNKNOWN: C2RustUnnamed_0 = 1820;
pub const XML_SCHEMAV_NOTSIMPLE: C2RustUnnamed_0 = 1819;
pub const XML_SCHEMAV_INTERNAL: C2RustUnnamed_0 = 1818;
pub const XML_SCHEMAV_CONSTRUCT: C2RustUnnamed_0 = 1817;
pub const XML_SCHEMAV_NOTDETERMINIST: C2RustUnnamed_0 = 1816;
pub const XML_SCHEMAV_INVALIDELEM: C2RustUnnamed_0 = 1815;
pub const XML_SCHEMAV_INVALIDATTR: C2RustUnnamed_0 = 1814;
pub const XML_SCHEMAV_EXTRACONTENT: C2RustUnnamed_0 = 1813;
pub const XML_SCHEMAV_NOTNILLABLE: C2RustUnnamed_0 = 1812;
pub const XML_SCHEMAV_HAVEDEFAULT: C2RustUnnamed_0 = 1811;
pub const XML_SCHEMAV_ELEMCONT: C2RustUnnamed_0 = 1810;
pub const XML_SCHEMAV_NOTEMPTY: C2RustUnnamed_0 = 1809;
pub const XML_SCHEMAV_ISABSTRACT: C2RustUnnamed_0 = 1808;
pub const XML_SCHEMAV_NOROLLBACK: C2RustUnnamed_0 = 1807;
pub const XML_SCHEMAV_NOTYPE: C2RustUnnamed_0 = 1806;
pub const XML_SCHEMAV_WRONGELEM: C2RustUnnamed_0 = 1805;
pub const XML_SCHEMAV_MISSING: C2RustUnnamed_0 = 1804;
pub const XML_SCHEMAV_NOTTOPLEVEL: C2RustUnnamed_0 = 1803;
pub const XML_SCHEMAV_UNDECLAREDELEM: C2RustUnnamed_0 = 1802;
pub const XML_SCHEMAV_NOROOT: C2RustUnnamed_0 = 1801;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_3: C2RustUnnamed_0 = 1800;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_3: C2RustUnnamed_0 = 1799;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_2: C2RustUnnamed_0 = 1798;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_1: C2RustUnnamed_0 = 1797;
pub const XML_SCHEMAP_SRC_IMPORT_3_2: C2RustUnnamed_0 = 1796;
pub const XML_SCHEMAP_SRC_IMPORT_3_1: C2RustUnnamed_0 = 1795;
pub const XML_SCHEMAP_UNION_NOT_EXPRESSIBLE: C2RustUnnamed_0 = 1794;
pub const XML_SCHEMAP_INTERSECTION_NOT_EXPRESSIBLE: C2RustUnnamed_0 = 1793;
pub const XML_SCHEMAP_WILDCARD_INVALID_NS_MEMBER: C2RustUnnamed_0 = 1792;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_3: C2RustUnnamed_0 = 1791;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_2: C2RustUnnamed_0 = 1790;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_2: C2RustUnnamed_0 = 1789;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_1: C2RustUnnamed_0 = 1788;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_1: C2RustUnnamed_0 = 1787;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_5: C2RustUnnamed_0 = 1786;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_4: C2RustUnnamed_0 = 1785;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_3: C2RustUnnamed_0 = 1784;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_2: C2RustUnnamed_0 = 1783;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_1: C2RustUnnamed_0 = 1782;
pub const XML_SCHEMAP_REF_AND_CONTENT: C2RustUnnamed_0 = 1781;
pub const XML_SCHEMAP_INVALID_ATTR_NAME: C2RustUnnamed_0 = 1780;
pub const XML_SCHEMAP_MISSING_SIMPLETYPE_CHILD: C2RustUnnamed_0 = 1779;
pub const XML_SCHEMAP_INVALID_ATTR_INLINE_COMBINATION: C2RustUnnamed_0 = 1778;
pub const XML_SCHEMAP_INVALID_ATTR_COMBINATION: C2RustUnnamed_0 = 1777;
pub const XML_SCHEMAP_SUPERNUMEROUS_LIST_ITEM_TYPE: C2RustUnnamed_0 = 1776;
pub const XML_SCHEMAP_RECURSIVE: C2RustUnnamed_0 = 1775;
pub const XML_SCHEMAP_INVALID_ATTR_USE: C2RustUnnamed_0 = 1774;
pub const XML_SCHEMAP_UNKNOWN_MEMBER_TYPE: C2RustUnnamed_0 = 1773;
pub const XML_SCHEMAP_NOT_SCHEMA: C2RustUnnamed_0 = 1772;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NO_URI: C2RustUnnamed_0 = 1771;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NOT_URI: C2RustUnnamed_0 = 1770;
pub const XML_SCHEMAP_UNKNOWN_INCLUDE_CHILD: C2RustUnnamed_0 = 1769;
pub const XML_SCHEMAP_DEF_AND_PREFIX: C2RustUnnamed_0 = 1768;
pub const XML_SCHEMAP_UNKNOWN_PREFIX: C2RustUnnamed_0 = 1767;
pub const XML_SCHEMAP_FAILED_PARSE: C2RustUnnamed_0 = 1766;
pub const XML_SCHEMAP_REDEFINED_NOTATION: C2RustUnnamed_0 = 1765;
pub const XML_SCHEMAP_REDEFINED_ATTR: C2RustUnnamed_0 = 1764;
pub const XML_SCHEMAP_REDEFINED_ATTRGROUP: C2RustUnnamed_0 = 1763;
pub const XML_SCHEMAP_REDEFINED_ELEMENT: C2RustUnnamed_0 = 1762;
pub const XML_SCHEMAP_REDEFINED_TYPE: C2RustUnnamed_0 = 1761;
pub const XML_SCHEMAP_REDEFINED_GROUP: C2RustUnnamed_0 = 1760;
pub const XML_SCHEMAP_NOROOT: C2RustUnnamed_0 = 1759;
pub const XML_SCHEMAP_NOTHING_TO_PARSE: C2RustUnnamed_0 = 1758;
pub const XML_SCHEMAP_FAILED_LOAD: C2RustUnnamed_0 = 1757;
pub const XML_SCHEMAP_REGEXP_INVALID: C2RustUnnamed_0 = 1756;
pub const XML_SCHEMAP_ELEM_DEFAULT_FIXED: C2RustUnnamed_0 = 1755;
pub const XML_SCHEMAP_UNKNOWN_UNION_CHILD: C2RustUnnamed_0 = 1754;
pub const XML_SCHEMAP_UNKNOWN_TYPE: C2RustUnnamed_0 = 1753;
pub const XML_SCHEMAP_UNKNOWN_SIMPLETYPE_CHILD: C2RustUnnamed_0 = 1752;
pub const XML_SCHEMAP_UNKNOWN_SIMPLECONTENT_CHILD: C2RustUnnamed_0 = 1751;
pub const XML_SCHEMAP_UNKNOWN_SEQUENCE_CHILD: C2RustUnnamed_0 = 1750;
pub const XML_SCHEMAP_UNKNOWN_SCHEMAS_CHILD: C2RustUnnamed_0 = 1749;
pub const XML_SCHEMAP_UNKNOWN_RESTRICTION_CHILD: C2RustUnnamed_0 = 1748;
pub const XML_SCHEMAP_UNKNOWN_REF: C2RustUnnamed_0 = 1747;
pub const XML_SCHEMAP_UNKNOWN_PROCESSCONTENT_CHILD: C2RustUnnamed_0 = 1746;
pub const XML_SCHEMAP_UNKNOWN_NOTATION_CHILD: C2RustUnnamed_0 = 1745;
pub const XML_SCHEMAP_UNKNOWN_LIST_CHILD: C2RustUnnamed_0 = 1744;
pub const XML_SCHEMAP_UNKNOWN_IMPORT_CHILD: C2RustUnnamed_0 = 1743;
pub const XML_SCHEMAP_UNKNOWN_GROUP_CHILD: C2RustUnnamed_0 = 1742;
pub const XML_SCHEMAP_UNKNOWN_FACET_TYPE: C2RustUnnamed_0 = 1741;
pub const XML_SCHEMAP_UNKNOWN_FACET_CHILD: C2RustUnnamed_0 = 1740;
pub const XML_SCHEMAP_UNKNOWN_EXTENSION_CHILD: C2RustUnnamed_0 = 1739;
pub const XML_SCHEMAP_UNKNOWN_ELEM_CHILD: C2RustUnnamed_0 = 1738;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXTYPE_CHILD: C2RustUnnamed_0 = 1737;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXCONTENT_CHILD: C2RustUnnamed_0 = 1736;
pub const XML_SCHEMAP_UNKNOWN_CHOICE_CHILD: C2RustUnnamed_0 = 1735;
pub const XML_SCHEMAP_UNKNOWN_BASE_TYPE: C2RustUnnamed_0 = 1734;
pub const XML_SCHEMAP_UNKNOWN_ATTRIBUTE_GROUP: C2RustUnnamed_0 = 1733;
pub const XML_SCHEMAP_UNKNOWN_ATTRGRP_CHILD: C2RustUnnamed_0 = 1732;
pub const XML_SCHEMAP_UNKNOWN_ATTR_CHILD: C2RustUnnamed_0 = 1731;
pub const XML_SCHEMAP_UNKNOWN_ANYATTRIBUTE_CHILD: C2RustUnnamed_0 = 1730;
pub const XML_SCHEMAP_UNKNOWN_ALL_CHILD: C2RustUnnamed_0 = 1729;
pub const XML_SCHEMAP_TYPE_AND_SUBTYPE: C2RustUnnamed_0 = 1728;
pub const XML_SCHEMAP_SIMPLETYPE_NONAME: C2RustUnnamed_0 = 1727;
pub const XML_SCHEMAP_RESTRICTION_NONAME_NOREF: C2RustUnnamed_0 = 1726;
pub const XML_SCHEMAP_REF_AND_SUBTYPE: C2RustUnnamed_0 = 1725;
pub const XML_SCHEMAP_NOTYPE_NOREF: C2RustUnnamed_0 = 1724;
pub const XML_SCHEMAP_NOTATION_NO_NAME: C2RustUnnamed_0 = 1723;
pub const XML_SCHEMAP_NOATTR_NOREF: C2RustUnnamed_0 = 1722;
pub const XML_SCHEMAP_INVALID_WHITE_SPACE: C2RustUnnamed_0 = 1721;
pub const XML_SCHEMAP_INVALID_REF_AND_SUBTYPE: C2RustUnnamed_0 = 1720;
pub const XML_SCHEMAP_INVALID_MINOCCURS: C2RustUnnamed_0 = 1719;
pub const XML_SCHEMAP_INVALID_MAXOCCURS: C2RustUnnamed_0 = 1718;
pub const XML_SCHEMAP_INVALID_FACET_VALUE: C2RustUnnamed_0 = 1717;
pub const XML_SCHEMAP_INVALID_FACET: C2RustUnnamed_0 = 1716;
pub const XML_SCHEMAP_INVALID_ENUM: C2RustUnnamed_0 = 1715;
pub const XML_SCHEMAP_INVALID_BOOLEAN: C2RustUnnamed_0 = 1714;
pub const XML_SCHEMAP_IMPORT_SCHEMA_NOT_URI: C2RustUnnamed_0 = 1713;
pub const XML_SCHEMAP_IMPORT_REDEFINE_NSNAME: C2RustUnnamed_0 = 1712;
pub const XML_SCHEMAP_IMPORT_NAMESPACE_NOT_URI: C2RustUnnamed_0 = 1711;
pub const XML_SCHEMAP_GROUP_NONAME_NOREF: C2RustUnnamed_0 = 1710;
pub const XML_SCHEMAP_FAILED_BUILD_IMPORT: C2RustUnnamed_0 = 1709;
pub const XML_SCHEMAP_FACET_NO_VALUE: C2RustUnnamed_0 = 1708;
pub const XML_SCHEMAP_EXTENSION_NO_BASE: C2RustUnnamed_0 = 1707;
pub const XML_SCHEMAP_ELEM_NONAME_NOREF: C2RustUnnamed_0 = 1706;
pub const XML_SCHEMAP_ELEMFORMDEFAULT_VALUE: C2RustUnnamed_0 = 1705;
pub const XML_SCHEMAP_COMPLEXTYPE_NONAME_NOREF: C2RustUnnamed_0 = 1704;
pub const XML_SCHEMAP_ATTR_NONAME_NOREF: C2RustUnnamed_0 = 1703;
pub const XML_SCHEMAP_ATTRGRP_NONAME_NOREF: C2RustUnnamed_0 = 1702;
pub const XML_SCHEMAP_ATTRFORMDEFAULT_VALUE: C2RustUnnamed_0 = 1701;
pub const XML_SCHEMAP_PREFIX_UNDEFINED: C2RustUnnamed_0 = 1700;
pub const XML_CATALOG_RECURSION: C2RustUnnamed_0 = 1654;
pub const XML_CATALOG_NOT_CATALOG: C2RustUnnamed_0 = 1653;
pub const XML_CATALOG_PREFER_VALUE: C2RustUnnamed_0 = 1652;
pub const XML_CATALOG_ENTRY_BROKEN: C2RustUnnamed_0 = 1651;
pub const XML_CATALOG_MISSING_ATTR: C2RustUnnamed_0 = 1650;
pub const XML_XINCLUDE_FRAGMENT_ID: C2RustUnnamed_0 = 1618;
pub const XML_XINCLUDE_DEPRECATED_NS: C2RustUnnamed_0 = 1617;
pub const XML_XINCLUDE_FALLBACK_NOT_IN_INCLUDE: C2RustUnnamed_0 = 1616;
pub const XML_XINCLUDE_FALLBACKS_IN_INCLUDE: C2RustUnnamed_0 = 1615;
pub const XML_XINCLUDE_INCLUDE_IN_INCLUDE: C2RustUnnamed_0 = 1614;
pub const XML_XINCLUDE_XPTR_RESULT: C2RustUnnamed_0 = 1613;
pub const XML_XINCLUDE_XPTR_FAILED: C2RustUnnamed_0 = 1612;
pub const XML_XINCLUDE_MULTIPLE_ROOT: C2RustUnnamed_0 = 1611;
pub const XML_XINCLUDE_UNKNOWN_ENCODING: C2RustUnnamed_0 = 1610;
pub const XML_XINCLUDE_BUILD_FAILED: C2RustUnnamed_0 = 1609;
pub const XML_XINCLUDE_INVALID_CHAR: C2RustUnnamed_0 = 1608;
pub const XML_XINCLUDE_TEXT_DOCUMENT: C2RustUnnamed_0 = 1607;
pub const XML_XINCLUDE_TEXT_FRAGMENT: C2RustUnnamed_0 = 1606;
pub const XML_XINCLUDE_HREF_URI: C2RustUnnamed_0 = 1605;
pub const XML_XINCLUDE_NO_FALLBACK: C2RustUnnamed_0 = 1604;
pub const XML_XINCLUDE_NO_HREF: C2RustUnnamed_0 = 1603;
pub const XML_XINCLUDE_ENTITY_DEF_MISMATCH: C2RustUnnamed_0 = 1602;
pub const XML_XINCLUDE_PARSE_VALUE: C2RustUnnamed_0 = 1601;
pub const XML_XINCLUDE_RECURSION: C2RustUnnamed_0 = 1600;
pub const XML_IO_EAFNOSUPPORT: C2RustUnnamed_0 = 1556;
pub const XML_IO_EALREADY: C2RustUnnamed_0 = 1555;
pub const XML_IO_EADDRINUSE: C2RustUnnamed_0 = 1554;
pub const XML_IO_ENETUNREACH: C2RustUnnamed_0 = 1553;
pub const XML_IO_ECONNREFUSED: C2RustUnnamed_0 = 1552;
pub const XML_IO_EISCONN: C2RustUnnamed_0 = 1551;
pub const XML_IO_ENOTSOCK: C2RustUnnamed_0 = 1550;
pub const XML_IO_LOAD_ERROR: C2RustUnnamed_0 = 1549;
pub const XML_IO_BUFFER_FULL: C2RustUnnamed_0 = 1548;
pub const XML_IO_NO_INPUT: C2RustUnnamed_0 = 1547;
pub const XML_IO_WRITE: C2RustUnnamed_0 = 1546;
pub const XML_IO_FLUSH: C2RustUnnamed_0 = 1545;
pub const XML_IO_ENCODER: C2RustUnnamed_0 = 1544;
pub const XML_IO_NETWORK_ATTEMPT: C2RustUnnamed_0 = 1543;
pub const XML_IO_EXDEV: C2RustUnnamed_0 = 1542;
pub const XML_IO_ETIMEDOUT: C2RustUnnamed_0 = 1541;
pub const XML_IO_ESRCH: C2RustUnnamed_0 = 1540;
pub const XML_IO_ESPIPE: C2RustUnnamed_0 = 1539;
pub const XML_IO_EROFS: C2RustUnnamed_0 = 1538;
pub const XML_IO_ERANGE: C2RustUnnamed_0 = 1537;
pub const XML_IO_EPIPE: C2RustUnnamed_0 = 1536;
pub const XML_IO_EPERM: C2RustUnnamed_0 = 1535;
pub const XML_IO_ENXIO: C2RustUnnamed_0 = 1534;
pub const XML_IO_ENOTTY: C2RustUnnamed_0 = 1533;
pub const XML_IO_ENOTSUP: C2RustUnnamed_0 = 1532;
pub const XML_IO_ENOTEMPTY: C2RustUnnamed_0 = 1531;
pub const XML_IO_ENOTDIR: C2RustUnnamed_0 = 1530;
pub const XML_IO_ENOSYS: C2RustUnnamed_0 = 1529;
pub const XML_IO_ENOSPC: C2RustUnnamed_0 = 1528;
pub const XML_IO_ENOMEM: C2RustUnnamed_0 = 1527;
pub const XML_IO_ENOLCK: C2RustUnnamed_0 = 1526;
pub const XML_IO_ENOEXEC: C2RustUnnamed_0 = 1525;
pub const XML_IO_ENOENT: C2RustUnnamed_0 = 1524;
pub const XML_IO_ENODEV: C2RustUnnamed_0 = 1523;
pub const XML_IO_ENFILE: C2RustUnnamed_0 = 1522;
pub const XML_IO_ENAMETOOLONG: C2RustUnnamed_0 = 1521;
pub const XML_IO_EMSGSIZE: C2RustUnnamed_0 = 1520;
pub const XML_IO_EMLINK: C2RustUnnamed_0 = 1519;
pub const XML_IO_EMFILE: C2RustUnnamed_0 = 1518;
pub const XML_IO_EISDIR: C2RustUnnamed_0 = 1517;
pub const XML_IO_EIO: C2RustUnnamed_0 = 1516;
pub const XML_IO_EINVAL: C2RustUnnamed_0 = 1515;
pub const XML_IO_EINTR: C2RustUnnamed_0 = 1514;
pub const XML_IO_EINPROGRESS: C2RustUnnamed_0 = 1513;
pub const XML_IO_EFBIG: C2RustUnnamed_0 = 1512;
pub const XML_IO_EFAULT: C2RustUnnamed_0 = 1511;
pub const XML_IO_EEXIST: C2RustUnnamed_0 = 1510;
pub const XML_IO_EDOM: C2RustUnnamed_0 = 1509;
pub const XML_IO_EDEADLK: C2RustUnnamed_0 = 1508;
pub const XML_IO_ECHILD: C2RustUnnamed_0 = 1507;
pub const XML_IO_ECANCELED: C2RustUnnamed_0 = 1506;
pub const XML_IO_EBUSY: C2RustUnnamed_0 = 1505;
pub const XML_IO_EBADMSG: C2RustUnnamed_0 = 1504;
pub const XML_IO_EBADF: C2RustUnnamed_0 = 1503;
pub const XML_IO_EAGAIN: C2RustUnnamed_0 = 1502;
pub const XML_IO_EACCES: C2RustUnnamed_0 = 1501;
pub const XML_IO_UNKNOWN: C2RustUnnamed_0 = 1500;
pub const XML_REGEXP_COMPILE_ERROR: C2RustUnnamed_0 = 1450;
pub const XML_SAVE_UNKNOWN_ENCODING: C2RustUnnamed_0 = 1403;
pub const XML_SAVE_NO_DOCTYPE: C2RustUnnamed_0 = 1402;
pub const XML_SAVE_CHAR_INVALID: C2RustUnnamed_0 = 1401;
pub const XML_SAVE_NOT_UTF8: C2RustUnnamed_0 = 1400;
pub const XML_TREE_NOT_UTF8: C2RustUnnamed_0 = 1303;
pub const XML_TREE_UNTERMINATED_ENTITY: C2RustUnnamed_0 = 1302;
pub const XML_TREE_INVALID_DEC: C2RustUnnamed_0 = 1301;
pub const XML_TREE_INVALID_HEX: C2RustUnnamed_0 = 1300;
pub const XML_XPATH_INVALID_CHAR_ERROR: C2RustUnnamed_0 = 1221;
pub const XML_XPATH_ENCODING_ERROR: C2RustUnnamed_0 = 1220;
pub const XML_XPATH_UNDEF_PREFIX_ERROR: C2RustUnnamed_0 = 1219;
pub const XML_XPTR_SUB_RESOURCE_ERROR: C2RustUnnamed_0 = 1218;
pub const XML_XPTR_RESOURCE_ERROR: C2RustUnnamed_0 = 1217;
pub const XML_XPTR_SYNTAX_ERROR: C2RustUnnamed_0 = 1216;
pub const XML_XPATH_MEMORY_ERROR: C2RustUnnamed_0 = 1215;
pub const XML_XPATH_INVALID_CTXT_POSITION: C2RustUnnamed_0 = 1214;
pub const XML_XPATH_INVALID_CTXT_SIZE: C2RustUnnamed_0 = 1213;
pub const XML_XPATH_INVALID_ARITY: C2RustUnnamed_0 = 1212;
pub const XML_XPATH_INVALID_TYPE: C2RustUnnamed_0 = 1211;
pub const XML_XPATH_INVALID_OPERAND: C2RustUnnamed_0 = 1210;
pub const XML_XPATH_UNKNOWN_FUNC_ERROR: C2RustUnnamed_0 = 1209;
pub const XML_XPATH_UNCLOSED_ERROR: C2RustUnnamed_0 = 1208;
pub const XML_XPATH_EXPR_ERROR: C2RustUnnamed_0 = 1207;
pub const XML_XPATH_INVALID_PREDICATE_ERROR: C2RustUnnamed_0 = 1206;
pub const XML_XPATH_UNDEF_VARIABLE_ERROR: C2RustUnnamed_0 = 1205;
pub const XML_XPATH_VARIABLE_REF_ERROR: C2RustUnnamed_0 = 1204;
pub const XML_XPATH_START_LITERAL_ERROR: C2RustUnnamed_0 = 1203;
pub const XML_XPATH_UNFINISHED_LITERAL_ERROR: C2RustUnnamed_0 = 1202;
pub const XML_XPATH_NUMBER_ERROR: C2RustUnnamed_0 = 1201;
pub const XML_XPATH_EXPRESSION_OK: C2RustUnnamed_0 = 1200;
pub const XML_RNGP_XML_NS: C2RustUnnamed_0 = 1122;
pub const XML_RNGP_XMLNS_NAME: C2RustUnnamed_0 = 1121;
pub const XML_RNGP_VALUE_NO_CONTENT: C2RustUnnamed_0 = 1120;
pub const XML_RNGP_VALUE_EMPTY: C2RustUnnamed_0 = 1119;
pub const XML_RNGP_URI_NOT_ABSOLUTE: C2RustUnnamed_0 = 1118;
pub const XML_RNGP_URI_FRAGMENT: C2RustUnnamed_0 = 1117;
pub const XML_RNGP_UNKNOWN_TYPE_LIB: C2RustUnnamed_0 = 1116;
pub const XML_RNGP_UNKNOWN_CONSTRUCT: C2RustUnnamed_0 = 1115;
pub const XML_RNGP_UNKNOWN_COMBINE: C2RustUnnamed_0 = 1114;
pub const XML_RNGP_UNKNOWN_ATTRIBUTE: C2RustUnnamed_0 = 1113;
pub const XML_RNGP_TYPE_VALUE: C2RustUnnamed_0 = 1112;
pub const XML_RNGP_TYPE_NOT_FOUND: C2RustUnnamed_0 = 1111;
pub const XML_RNGP_TYPE_MISSING: C2RustUnnamed_0 = 1110;
pub const XML_RNGP_TEXT_HAS_CHILD: C2RustUnnamed_0 = 1109;
pub const XML_RNGP_TEXT_EXPECTED: C2RustUnnamed_0 = 1108;
pub const XML_RNGP_START_MISSING: C2RustUnnamed_0 = 1107;
pub const XML_RNGP_START_EMPTY: C2RustUnnamed_0 = 1106;
pub const XML_RNGP_START_CONTENT: C2RustUnnamed_0 = 1105;
pub const XML_RNGP_START_CHOICE_AND_INTERLEAVE: C2RustUnnamed_0 = 1104;
pub const XML_RNGP_REF_NOT_EMPTY: C2RustUnnamed_0 = 1103;
pub const XML_RNGP_REF_NO_NAME: C2RustUnnamed_0 = 1102;
pub const XML_RNGP_REF_NO_DEF: C2RustUnnamed_0 = 1101;
pub const XML_RNGP_REF_NAME_INVALID: C2RustUnnamed_0 = 1100;
pub const XML_RNGP_REF_CYCLE: C2RustUnnamed_0 = 1099;
pub const XML_RNGP_REF_CREATE_FAILED: C2RustUnnamed_0 = 1098;
pub const XML_RNGP_PREFIX_UNDEFINED: C2RustUnnamed_0 = 1097;
pub const XML_RNGP_PAT_START_VALUE: C2RustUnnamed_0 = 1096;
pub const XML_RNGP_PAT_START_TEXT: C2RustUnnamed_0 = 1095;
pub const XML_RNGP_PAT_START_ONEMORE: C2RustUnnamed_0 = 1094;
pub const XML_RNGP_PAT_START_LIST: C2RustUnnamed_0 = 1093;
pub const XML_RNGP_PAT_START_INTERLEAVE: C2RustUnnamed_0 = 1092;
pub const XML_RNGP_PAT_START_GROUP: C2RustUnnamed_0 = 1091;
pub const XML_RNGP_PAT_START_EMPTY: C2RustUnnamed_0 = 1090;
pub const XML_RNGP_PAT_START_DATA: C2RustUnnamed_0 = 1089;
pub const XML_RNGP_PAT_START_ATTR: C2RustUnnamed_0 = 1088;
pub const XML_RNGP_PAT_ONEMORE_INTERLEAVE_ATTR: C2RustUnnamed_0 = 1087;
pub const XML_RNGP_PAT_ONEMORE_GROUP_ATTR: C2RustUnnamed_0 = 1086;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_NSNAME: C2RustUnnamed_0 = 1085;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_ANYNAME: C2RustUnnamed_0 = 1084;
pub const XML_RNGP_PAT_LIST_TEXT: C2RustUnnamed_0 = 1083;
pub const XML_RNGP_PAT_LIST_REF: C2RustUnnamed_0 = 1082;
pub const XML_RNGP_PAT_LIST_LIST: C2RustUnnamed_0 = 1081;
pub const XML_RNGP_PAT_LIST_INTERLEAVE: C2RustUnnamed_0 = 1080;
pub const XML_RNGP_PAT_LIST_ELEM: C2RustUnnamed_0 = 1079;
pub const XML_RNGP_PAT_LIST_ATTR: C2RustUnnamed_0 = 1078;
pub const XML_RNGP_PAT_DATA_EXCEPT_TEXT: C2RustUnnamed_0 = 1077;
pub const XML_RNGP_PAT_DATA_EXCEPT_REF: C2RustUnnamed_0 = 1076;
pub const XML_RNGP_PAT_DATA_EXCEPT_ONEMORE: C2RustUnnamed_0 = 1075;
pub const XML_RNGP_PAT_DATA_EXCEPT_LIST: C2RustUnnamed_0 = 1074;
pub const XML_RNGP_PAT_DATA_EXCEPT_INTERLEAVE: C2RustUnnamed_0 = 1073;
pub const XML_RNGP_PAT_DATA_EXCEPT_GROUP: C2RustUnnamed_0 = 1072;
pub const XML_RNGP_PAT_DATA_EXCEPT_EMPTY: C2RustUnnamed_0 = 1071;
pub const XML_RNGP_PAT_DATA_EXCEPT_ELEM: C2RustUnnamed_0 = 1070;
pub const XML_RNGP_PAT_DATA_EXCEPT_ATTR: C2RustUnnamed_0 = 1069;
pub const XML_RNGP_PAT_ATTR_ELEM: C2RustUnnamed_0 = 1068;
pub const XML_RNGP_PAT_ATTR_ATTR: C2RustUnnamed_0 = 1067;
pub const XML_RNGP_PAT_ANYNAME_EXCEPT_ANYNAME: C2RustUnnamed_0 = 1066;
pub const XML_RNGP_PARSE_ERROR: C2RustUnnamed_0 = 1065;
pub const XML_RNGP_PARENTREF_NOT_EMPTY: C2RustUnnamed_0 = 1064;
pub const XML_RNGP_PARENTREF_NO_PARENT: C2RustUnnamed_0 = 1063;
pub const XML_RNGP_PARENTREF_NO_NAME: C2RustUnnamed_0 = 1062;
pub const XML_RNGP_PARENTREF_NAME_INVALID: C2RustUnnamed_0 = 1061;
pub const XML_RNGP_PARENTREF_CREATE_FAILED: C2RustUnnamed_0 = 1060;
pub const XML_RNGP_PARAM_NAME_MISSING: C2RustUnnamed_0 = 1059;
pub const XML_RNGP_PARAM_FORBIDDEN: C2RustUnnamed_0 = 1058;
pub const XML_RNGP_NSNAME_NO_NS: C2RustUnnamed_0 = 1057;
pub const XML_RNGP_NSNAME_ATTR_ANCESTOR: C2RustUnnamed_0 = 1056;
pub const XML_RNGP_NOTALLOWED_NOT_EMPTY: C2RustUnnamed_0 = 1055;
pub const XML_RNGP_NEED_COMBINE: C2RustUnnamed_0 = 1054;
pub const XML_RNGP_NAME_MISSING: C2RustUnnamed_0 = 1053;
pub const XML_RNGP_MISSING_HREF: C2RustUnnamed_0 = 1052;
pub const XML_RNGP_INVALID_VALUE: C2RustUnnamed_0 = 1051;
pub const XML_RNGP_INVALID_URI: C2RustUnnamed_0 = 1050;
pub const XML_RNGP_INVALID_DEFINE_NAME: C2RustUnnamed_0 = 1049;
pub const XML_RNGP_INTERLEAVE_NO_CONTENT: C2RustUnnamed_0 = 1048;
pub const XML_RNGP_INTERLEAVE_EMPTY: C2RustUnnamed_0 = 1047;
pub const XML_RNGP_INTERLEAVE_CREATE_FAILED: C2RustUnnamed_0 = 1046;
pub const XML_RNGP_INTERLEAVE_ADD: C2RustUnnamed_0 = 1045;
pub const XML_RNGP_INCLUDE_RECURSE: C2RustUnnamed_0 = 1044;
pub const XML_RNGP_INCLUDE_FAILURE: C2RustUnnamed_0 = 1043;
pub const XML_RNGP_INCLUDE_EMPTY: C2RustUnnamed_0 = 1042;
pub const XML_RNGP_HREF_ERROR: C2RustUnnamed_0 = 1041;
pub const XML_RNGP_GROUP_ATTR_CONFLICT: C2RustUnnamed_0 = 1040;
pub const XML_RNGP_GRAMMAR_NO_START: C2RustUnnamed_0 = 1039;
pub const XML_RNGP_GRAMMAR_MISSING: C2RustUnnamed_0 = 1038;
pub const XML_RNGP_GRAMMAR_EMPTY: C2RustUnnamed_0 = 1037;
pub const XML_RNGP_GRAMMAR_CONTENT: C2RustUnnamed_0 = 1036;
pub const XML_RNGP_FOREIGN_ELEMENT: C2RustUnnamed_0 = 1035;
pub const XML_RNGP_FORBIDDEN_ATTRIBUTE: C2RustUnnamed_0 = 1034;
pub const XML_RNGP_EXTERNALREF_RECURSE: C2RustUnnamed_0 = 1033;
pub const XML_RNGP_EXTERNAL_REF_FAILURE: C2RustUnnamed_0 = 1032;
pub const XML_RNGP_EXTERNALREF_EMTPY: C2RustUnnamed_0 = 1031;
pub const XML_RNGP_EXCEPT_NO_CONTENT: C2RustUnnamed_0 = 1030;
pub const XML_RNGP_EXCEPT_MULTIPLE: C2RustUnnamed_0 = 1029;
pub const XML_RNGP_EXCEPT_MISSING: C2RustUnnamed_0 = 1028;
pub const XML_RNGP_EXCEPT_EMPTY: C2RustUnnamed_0 = 1027;
pub const XML_RNGP_ERROR_TYPE_LIB: C2RustUnnamed_0 = 1026;
pub const XML_RNGP_EMPTY_NOT_EMPTY: C2RustUnnamed_0 = 1025;
pub const XML_RNGP_EMPTY_CONTENT: C2RustUnnamed_0 = 1024;
pub const XML_RNGP_EMPTY_CONSTRUCT: C2RustUnnamed_0 = 1023;
pub const XML_RNGP_EMPTY: C2RustUnnamed_0 = 1022;
pub const XML_RNGP_ELEM_TEXT_CONFLICT: C2RustUnnamed_0 = 1021;
pub const XML_RNGP_ELEMENT_NO_CONTENT: C2RustUnnamed_0 = 1020;
pub const XML_RNGP_ELEMENT_NAME: C2RustUnnamed_0 = 1019;
pub const XML_RNGP_ELEMENT_CONTENT: C2RustUnnamed_0 = 1018;
pub const XML_RNGP_ELEMENT_EMPTY: C2RustUnnamed_0 = 1017;
pub const XML_RNGP_ELEM_CONTENT_ERROR: C2RustUnnamed_0 = 1016;
pub const XML_RNGP_ELEM_CONTENT_EMPTY: C2RustUnnamed_0 = 1015;
pub const XML_RNGP_DEFINE_NAME_MISSING: C2RustUnnamed_0 = 1014;
pub const XML_RNGP_DEFINE_MISSING: C2RustUnnamed_0 = 1013;
pub const XML_RNGP_DEFINE_EMPTY: C2RustUnnamed_0 = 1012;
pub const XML_RNGP_DEFINE_CREATE_FAILED: C2RustUnnamed_0 = 1011;
pub const XML_RNGP_DEF_CHOICE_AND_INTERLEAVE: C2RustUnnamed_0 = 1010;
pub const XML_RNGP_DATA_CONTENT: C2RustUnnamed_0 = 1009;
pub const XML_RNGP_CREATE_FAILURE: C2RustUnnamed_0 = 1008;
pub const XML_RNGP_CHOICE_EMPTY: C2RustUnnamed_0 = 1007;
pub const XML_RNGP_CHOICE_CONTENT: C2RustUnnamed_0 = 1006;
pub const XML_RNGP_ATTRIBUTE_NOOP: C2RustUnnamed_0 = 1005;
pub const XML_RNGP_ATTRIBUTE_EMPTY: C2RustUnnamed_0 = 1004;
pub const XML_RNGP_ATTRIBUTE_CONTENT: C2RustUnnamed_0 = 1003;
pub const XML_RNGP_ATTRIBUTE_CHILDREN: C2RustUnnamed_0 = 1002;
pub const XML_RNGP_ATTR_CONFLICT: C2RustUnnamed_0 = 1001;
pub const XML_RNGP_ANYNAME_ATTR_ANCESTOR: C2RustUnnamed_0 = 1000;
pub const XML_HTML_INCORRECTLY_OPENED_COMMENT: C2RustUnnamed_0 = 802;
pub const XML_HTML_UNKNOWN_TAG: C2RustUnnamed_0 = 801;
pub const XML_HTML_STRUCURE_ERROR: C2RustUnnamed_0 = 800;
pub const XML_DTD_DUP_TOKEN: C2RustUnnamed_0 = 541;
pub const XML_DTD_XMLID_TYPE: C2RustUnnamed_0 = 540;
pub const XML_DTD_XMLID_VALUE: C2RustUnnamed_0 = 539;
pub const XML_DTD_STANDALONE_DEFAULTED: C2RustUnnamed_0 = 538;
pub const XML_DTD_UNKNOWN_NOTATION: C2RustUnnamed_0 = 537;
pub const XML_DTD_UNKNOWN_ID: C2RustUnnamed_0 = 536;
pub const XML_DTD_UNKNOWN_ENTITY: C2RustUnnamed_0 = 535;
pub const XML_DTD_UNKNOWN_ELEM: C2RustUnnamed_0 = 534;
pub const XML_DTD_UNKNOWN_ATTRIBUTE: C2RustUnnamed_0 = 533;
pub const XML_DTD_STANDALONE_WHITE_SPACE: C2RustUnnamed_0 = 532;
pub const XML_DTD_ROOT_NAME: C2RustUnnamed_0 = 531;
pub const XML_DTD_NOT_STANDALONE: C2RustUnnamed_0 = 530;
pub const XML_DTD_NOT_PCDATA: C2RustUnnamed_0 = 529;
pub const XML_DTD_NOT_EMPTY: C2RustUnnamed_0 = 528;
pub const XML_DTD_NOTATION_VALUE: C2RustUnnamed_0 = 527;
pub const XML_DTD_NOTATION_REDEFINED: C2RustUnnamed_0 = 526;
pub const XML_DTD_NO_ROOT: C2RustUnnamed_0 = 525;
pub const XML_DTD_NO_PREFIX: C2RustUnnamed_0 = 524;
pub const XML_DTD_NO_ELEM_NAME: C2RustUnnamed_0 = 523;
pub const XML_DTD_NO_DTD: C2RustUnnamed_0 = 522;
pub const XML_DTD_NO_DOC: C2RustUnnamed_0 = 521;
pub const XML_DTD_MULTIPLE_ID: C2RustUnnamed_0 = 520;
pub const XML_DTD_MIXED_CORRUPT: C2RustUnnamed_0 = 519;
pub const XML_DTD_MISSING_ATTRIBUTE: C2RustUnnamed_0 = 518;
pub const XML_DTD_LOAD_ERROR: C2RustUnnamed_0 = 517;
pub const XML_DTD_INVALID_DEFAULT: C2RustUnnamed_0 = 516;
pub const XML_DTD_INVALID_CHILD: C2RustUnnamed_0 = 515;
pub const XML_DTD_ID_SUBSET: C2RustUnnamed_0 = 514;
pub const XML_DTD_ID_REDEFINED: C2RustUnnamed_0 = 513;
pub const XML_DTD_ID_FIXED: C2RustUnnamed_0 = 512;
pub const XML_DTD_ENTITY_TYPE: C2RustUnnamed_0 = 511;
pub const XML_DTD_EMPTY_NOTATION: C2RustUnnamed_0 = 510;
pub const XML_DTD_ELEM_REDEFINED: C2RustUnnamed_0 = 509;
pub const XML_DTD_ELEM_NAMESPACE: C2RustUnnamed_0 = 508;
pub const XML_DTD_ELEM_DEFAULT_NAMESPACE: C2RustUnnamed_0 = 507;
pub const XML_DTD_DIFFERENT_PREFIX: C2RustUnnamed_0 = 506;
pub const XML_DTD_CONTENT_NOT_DETERMINIST: C2RustUnnamed_0 = 505;
pub const XML_DTD_CONTENT_MODEL: C2RustUnnamed_0 = 504;
pub const XML_DTD_CONTENT_ERROR: C2RustUnnamed_0 = 503;
pub const XML_DTD_ATTRIBUTE_VALUE: C2RustUnnamed_0 = 502;
pub const XML_DTD_ATTRIBUTE_REDEFINED: C2RustUnnamed_0 = 501;
pub const XML_DTD_ATTRIBUTE_DEFAULT: C2RustUnnamed_0 = 500;
pub const XML_NS_ERR_COLON: C2RustUnnamed_0 = 205;
pub const XML_NS_ERR_EMPTY: C2RustUnnamed_0 = 204;
pub const XML_NS_ERR_ATTRIBUTE_REDEFINED: C2RustUnnamed_0 = 203;
pub const XML_NS_ERR_QNAME: C2RustUnnamed_0 = 202;
pub const XML_NS_ERR_UNDEFINED_NAMESPACE: C2RustUnnamed_0 = 201;
pub const XML_NS_ERR_XML_NAMESPACE: C2RustUnnamed_0 = 200;
pub const XML_ERR_COMMENT_ABRUPTLY_ENDED: C2RustUnnamed_0 = 112;
pub const XML_ERR_USER_STOP: C2RustUnnamed_0 = 111;
pub const XML_ERR_NAME_TOO_LONG: C2RustUnnamed_0 = 110;
pub const XML_ERR_VERSION_MISMATCH: C2RustUnnamed_0 = 109;
pub const XML_ERR_UNKNOWN_VERSION: C2RustUnnamed_0 = 108;
pub const XML_WAR_ENTITY_REDEFINED: C2RustUnnamed_0 = 107;
pub const XML_WAR_NS_COLUMN: C2RustUnnamed_0 = 106;
pub const XML_ERR_NOTATION_PROCESSING: C2RustUnnamed_0 = 105;
pub const XML_ERR_ENTITY_PROCESSING: C2RustUnnamed_0 = 104;
pub const XML_ERR_NOT_STANDALONE: C2RustUnnamed_0 = 103;
pub const XML_WAR_SPACE_VALUE: C2RustUnnamed_0 = 102;
pub const XML_ERR_MISSING_ENCODING: C2RustUnnamed_0 = 101;
pub const XML_WAR_NS_URI_RELATIVE: C2RustUnnamed_0 = 100;
pub const XML_WAR_NS_URI: C2RustUnnamed_0 = 99;
pub const XML_WAR_LANG_VALUE: C2RustUnnamed_0 = 98;
pub const XML_WAR_UNKNOWN_VERSION: C2RustUnnamed_0 = 97;
pub const XML_ERR_VERSION_MISSING: C2RustUnnamed_0 = 96;
pub const XML_ERR_CONDSEC_INVALID_KEYWORD: C2RustUnnamed_0 = 95;
pub const XML_ERR_NO_DTD: C2RustUnnamed_0 = 94;
pub const XML_WAR_CATALOG_PI: C2RustUnnamed_0 = 93;
pub const XML_ERR_URI_FRAGMENT: C2RustUnnamed_0 = 92;
pub const XML_ERR_INVALID_URI: C2RustUnnamed_0 = 91;
pub const XML_ERR_ENTITY_BOUNDARY: C2RustUnnamed_0 = 90;
pub const XML_ERR_ENTITY_LOOP: C2RustUnnamed_0 = 89;
pub const XML_ERR_ENTITY_PE_INTERNAL: C2RustUnnamed_0 = 88;
pub const XML_ERR_ENTITY_CHAR_ERROR: C2RustUnnamed_0 = 87;
pub const XML_ERR_EXTRA_CONTENT: C2RustUnnamed_0 = 86;
pub const XML_ERR_NOT_WELL_BALANCED: C2RustUnnamed_0 = 85;
pub const XML_ERR_VALUE_REQUIRED: C2RustUnnamed_0 = 84;
pub const XML_ERR_CONDSEC_INVALID: C2RustUnnamed_0 = 83;
pub const XML_ERR_EXT_ENTITY_STANDALONE: C2RustUnnamed_0 = 82;
pub const XML_ERR_INVALID_ENCODING: C2RustUnnamed_0 = 81;
pub const XML_ERR_HYPHEN_IN_COMMENT: C2RustUnnamed_0 = 80;
pub const XML_ERR_ENCODING_NAME: C2RustUnnamed_0 = 79;
pub const XML_ERR_STANDALONE_VALUE: C2RustUnnamed_0 = 78;
pub const XML_ERR_TAG_NOT_FINISHED: C2RustUnnamed_0 = 77;
pub const XML_ERR_TAG_NAME_MISMATCH: C2RustUnnamed_0 = 76;
pub const XML_ERR_EQUAL_REQUIRED: C2RustUnnamed_0 = 75;
pub const XML_ERR_LTSLASH_REQUIRED: C2RustUnnamed_0 = 74;
pub const XML_ERR_GT_REQUIRED: C2RustUnnamed_0 = 73;
pub const XML_ERR_LT_REQUIRED: C2RustUnnamed_0 = 72;
pub const XML_ERR_PUBID_REQUIRED: C2RustUnnamed_0 = 71;
pub const XML_ERR_URI_REQUIRED: C2RustUnnamed_0 = 70;
pub const XML_ERR_PCDATA_REQUIRED: C2RustUnnamed_0 = 69;
pub const XML_ERR_NAME_REQUIRED: C2RustUnnamed_0 = 68;
pub const XML_ERR_NMTOKEN_REQUIRED: C2RustUnnamed_0 = 67;
pub const XML_ERR_SEPARATOR_REQUIRED: C2RustUnnamed_0 = 66;
pub const XML_ERR_SPACE_REQUIRED: C2RustUnnamed_0 = 65;
pub const XML_ERR_RESERVED_XML_NAME: C2RustUnnamed_0 = 64;
pub const XML_ERR_CDATA_NOT_FINISHED: C2RustUnnamed_0 = 63;
pub const XML_ERR_MISPLACED_CDATA_END: C2RustUnnamed_0 = 62;
pub const XML_ERR_DOCTYPE_NOT_FINISHED: C2RustUnnamed_0 = 61;
pub const XML_ERR_EXT_SUBSET_NOT_FINISHED: C2RustUnnamed_0 = 60;
pub const XML_ERR_CONDSEC_NOT_FINISHED: C2RustUnnamed_0 = 59;
pub const XML_ERR_CONDSEC_NOT_STARTED: C2RustUnnamed_0 = 58;
pub const XML_ERR_XMLDECL_NOT_FINISHED: C2RustUnnamed_0 = 57;
pub const XML_ERR_XMLDECL_NOT_STARTED: C2RustUnnamed_0 = 56;
pub const XML_ERR_ELEMCONTENT_NOT_FINISHED: C2RustUnnamed_0 = 55;
pub const XML_ERR_ELEMCONTENT_NOT_STARTED: C2RustUnnamed_0 = 54;
pub const XML_ERR_MIXED_NOT_FINISHED: C2RustUnnamed_0 = 53;
pub const XML_ERR_MIXED_NOT_STARTED: C2RustUnnamed_0 = 52;
pub const XML_ERR_ATTLIST_NOT_FINISHED: C2RustUnnamed_0 = 51;
pub const XML_ERR_ATTLIST_NOT_STARTED: C2RustUnnamed_0 = 50;
pub const XML_ERR_NOTATION_NOT_FINISHED: C2RustUnnamed_0 = 49;
pub const XML_ERR_NOTATION_NOT_STARTED: C2RustUnnamed_0 = 48;
pub const XML_ERR_PI_NOT_FINISHED: C2RustUnnamed_0 = 47;
pub const XML_ERR_PI_NOT_STARTED: C2RustUnnamed_0 = 46;
pub const XML_ERR_COMMENT_NOT_FINISHED: C2RustUnnamed_0 = 45;
pub const XML_ERR_LITERAL_NOT_FINISHED: C2RustUnnamed_0 = 44;
pub const XML_ERR_LITERAL_NOT_STARTED: C2RustUnnamed_0 = 43;
pub const XML_ERR_ATTRIBUTE_REDEFINED: C2RustUnnamed_0 = 42;
pub const XML_ERR_ATTRIBUTE_WITHOUT_VALUE: C2RustUnnamed_0 = 41;
pub const XML_ERR_ATTRIBUTE_NOT_FINISHED: C2RustUnnamed_0 = 40;
pub const XML_ERR_ATTRIBUTE_NOT_STARTED: C2RustUnnamed_0 = 39;
pub const XML_ERR_LT_IN_ATTRIBUTE: C2RustUnnamed_0 = 38;
pub const XML_ERR_ENTITY_NOT_FINISHED: C2RustUnnamed_0 = 37;
pub const XML_ERR_ENTITY_NOT_STARTED: C2RustUnnamed_0 = 36;
pub const XML_ERR_NS_DECL_ERROR: C2RustUnnamed_0 = 35;
pub const XML_ERR_STRING_NOT_CLOSED: C2RustUnnamed_0 = 34;
pub const XML_ERR_STRING_NOT_STARTED: C2RustUnnamed_0 = 33;
pub const XML_ERR_UNSUPPORTED_ENCODING: C2RustUnnamed_0 = 32;
pub const XML_ERR_UNKNOWN_ENCODING: C2RustUnnamed_0 = 31;
pub const XML_ERR_ENTITY_IS_PARAMETER: C2RustUnnamed_0 = 30;
pub const XML_ERR_ENTITY_IS_EXTERNAL: C2RustUnnamed_0 = 29;
pub const XML_ERR_UNPARSED_ENTITY: C2RustUnnamed_0 = 28;
pub const XML_WAR_UNDECLARED_ENTITY: C2RustUnnamed_0 = 27;
pub const XML_ERR_UNDECLARED_ENTITY: C2RustUnnamed_0 = 26;
pub const XML_ERR_PEREF_SEMICOL_MISSING: C2RustUnnamed_0 = 25;
pub const XML_ERR_PEREF_NO_NAME: C2RustUnnamed_0 = 24;
pub const XML_ERR_ENTITYREF_SEMICOL_MISSING: C2RustUnnamed_0 = 23;
pub const XML_ERR_ENTITYREF_NO_NAME: C2RustUnnamed_0 = 22;
pub const XML_ERR_PEREF_IN_INT_SUBSET: C2RustUnnamed_0 = 21;
pub const XML_ERR_PEREF_IN_EPILOG: C2RustUnnamed_0 = 20;
pub const XML_ERR_PEREF_IN_PROLOG: C2RustUnnamed_0 = 19;
pub const XML_ERR_PEREF_AT_EOF: C2RustUnnamed_0 = 18;
pub const XML_ERR_ENTITYREF_IN_DTD: C2RustUnnamed_0 = 17;
pub const XML_ERR_ENTITYREF_IN_EPILOG: C2RustUnnamed_0 = 16;
pub const XML_ERR_ENTITYREF_IN_PROLOG: C2RustUnnamed_0 = 15;
pub const XML_ERR_ENTITYREF_AT_EOF: C2RustUnnamed_0 = 14;
pub const XML_ERR_CHARREF_IN_DTD: C2RustUnnamed_0 = 13;
pub const XML_ERR_CHARREF_IN_EPILOG: C2RustUnnamed_0 = 12;
pub const XML_ERR_CHARREF_IN_PROLOG: C2RustUnnamed_0 = 11;
pub const XML_ERR_CHARREF_AT_EOF: C2RustUnnamed_0 = 10;
pub const XML_ERR_INVALID_CHAR: C2RustUnnamed_0 = 9;
pub const XML_ERR_INVALID_CHARREF: C2RustUnnamed_0 = 8;
pub const XML_ERR_INVALID_DEC_CHARREF: C2RustUnnamed_0 = 7;
pub const XML_ERR_INVALID_HEX_CHARREF: C2RustUnnamed_0 = 6;
pub const XML_ERR_DOCUMENT_END: C2RustUnnamed_0 = 5;
pub const XML_ERR_DOCUMENT_EMPTY: C2RustUnnamed_0 = 4;
pub const XML_ERR_DOCUMENT_START: C2RustUnnamed_0 = 3;
pub const XML_ERR_NO_MEMORY: C2RustUnnamed_0 = 2;
pub const XML_ERR_INTERNAL_ERROR: C2RustUnnamed_0 = 1;
pub const XML_ERR_OK: C2RustUnnamed_0 = 0;
pub type xmlGenericErrorFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type _xmlSAXHandlerV1 = crate::src::HTMLparser::_xmlSAXHandlerV1;
pub type xmlSAXHandlerV1 = crate::src::HTMLparser::_xmlSAXHandlerV1;
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
pub type _xmlChSRange = crate::src::HTMLparser::_xmlChSRange;
pub type xmlChSRange = crate::src::HTMLparser::_xmlChSRange;
pub type _xmlChLRange = crate::src::HTMLparser::_xmlChLRange;
pub type xmlChLRange = crate::src::HTMLparser::_xmlChLRange;
pub type _xmlChRangeGroup = crate::src::HTMLparser::_xmlChRangeGroup;
pub type xmlChRangeGroup = crate::src::HTMLparser::_xmlChRangeGroup;
pub type xmlCatalogPrefer = u32;
pub const XML_CATA_PREFER_SYSTEM: xmlCatalogPrefer = 2;
pub const XML_CATA_PREFER_PUBLIC: xmlCatalogPrefer = 1;
pub const XML_CATA_PREFER_NONE: xmlCatalogPrefer = 0;
pub type xmlCatalogAllow = u32;
pub const XML_CATA_ALLOW_ALL: xmlCatalogAllow = 3;
pub const XML_CATA_ALLOW_DOCUMENT: xmlCatalogAllow = 2;
pub const XML_CATA_ALLOW_GLOBAL: xmlCatalogAllow = 1;
pub const XML_CATA_ALLOW_NONE: xmlCatalogAllow = 0;
#[repr(C)]
pub struct _xmlCatalog<'a> {
    pub type_0: u32,
    pub catalTab: [Option<&'a mut i8>; 10],
    pub catalNr: i32,
    pub catalMax: i32,
    pub sgml: *mut crate::src::hash::_xmlHashTable,
    pub prefer: u32,
    pub xml: *mut crate::src::catalog::_xmlCatalogEntry,
}
impl<'a> _xmlCatalog<'a> {
    pub const fn new() -> Self {
        _xmlCatalog {
            type_0: 0,
            catalTab: [None, None, None, None, None, None, None, None, None, None],
            catalNr: 0,
            catalMax: 0,
            sgml: (0 as *mut crate::src::hash::_xmlHashTable),
            prefer: 0,
            xml: (0 as *mut crate::src::catalog::_xmlCatalogEntry),
        }
    }
}
impl<'a> std::default::Default for _xmlCatalog<'a> {
    fn default() -> Self {
        _xmlCatalog::new()
    }
}
pub type xmlCatalogEntryPtr = *mut crate::src::catalog::_xmlCatalogEntry;
pub type xmlCatalogEntry = crate::src::catalog::_xmlCatalogEntry;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlCatalogEntry {
    pub next: *mut crate::src::catalog::_xmlCatalogEntry,
    pub parent: *mut crate::src::catalog::_xmlCatalogEntry,
    pub children: *mut crate::src::catalog::_xmlCatalogEntry,
    pub type_0: i32,
    pub name: *mut u8,
    pub value: *mut u8,
    pub URL: *mut u8,
    pub prefer: u32,
    pub dealloc: i32,
    pub depth: i32,
    pub group: *mut crate::src::catalog::_xmlCatalogEntry,
}
impl _xmlCatalogEntry {
    pub const fn new() -> Self {
        _xmlCatalogEntry {
            next: (0 as *mut crate::src::catalog::_xmlCatalogEntry),
            parent: (0 as *mut crate::src::catalog::_xmlCatalogEntry),
            children: (0 as *mut crate::src::catalog::_xmlCatalogEntry),
            type_0: 0,
            name: (0 as *mut u8),
            value: (0 as *mut u8),
            URL: (0 as *mut u8),
            prefer: 0,
            dealloc: 0,
            depth: 0,
            group: (0 as *mut crate::src::catalog::_xmlCatalogEntry),
        }
    }
}
impl std::default::Default for _xmlCatalogEntry {
    fn default() -> Self {
        _xmlCatalogEntry::new()
    }
}
pub type xmlCatalogEntryType = i32;
pub const SGML_CATA_SGMLDECL: xmlCatalogEntryType = 24;
pub const SGML_CATA_DOCUMENT: xmlCatalogEntryType = 23;
pub const SGML_CATA_CATALOG: xmlCatalogEntryType = 22;
pub const SGML_CATA_BASE: xmlCatalogEntryType = 21;
pub const SGML_CATA_DELEGATE: xmlCatalogEntryType = 20;
pub const SGML_CATA_NOTATION: xmlCatalogEntryType = 19;
pub const SGML_CATA_LINKTYPE: xmlCatalogEntryType = 18;
pub const SGML_CATA_DOCTYPE: xmlCatalogEntryType = 17;
pub const SGML_CATA_PENTITY: xmlCatalogEntryType = 16;
pub const SGML_CATA_ENTITY: xmlCatalogEntryType = 15;
pub const SGML_CATA_PUBLIC: xmlCatalogEntryType = 14;
pub const SGML_CATA_SYSTEM: xmlCatalogEntryType = 13;
pub const XML_CATA_DELEGATE_URI: xmlCatalogEntryType = 12;
pub const XML_CATA_REWRITE_URI: xmlCatalogEntryType = 11;
pub const XML_CATA_URI: xmlCatalogEntryType = 10;
pub const XML_CATA_DELEGATE_SYSTEM: xmlCatalogEntryType = 9;
pub const XML_CATA_DELEGATE_PUBLIC: xmlCatalogEntryType = 8;
pub const XML_CATA_REWRITE_SYSTEM: xmlCatalogEntryType = 7;
pub const XML_CATA_SYSTEM: xmlCatalogEntryType = 6;
pub const XML_CATA_PUBLIC: xmlCatalogEntryType = 5;
pub const XML_CATA_GROUP: xmlCatalogEntryType = 4;
pub const XML_CATA_NEXT_CATALOG: xmlCatalogEntryType = 3;
pub const XML_CATA_BROKEN_CATALOG: xmlCatalogEntryType = 2;
pub const XML_CATA_CATALOG: xmlCatalogEntryType = 1;
pub const XML_CATA_NONE: xmlCatalogEntryType = 0;
pub const XML_CATA_REMOVED: xmlCatalogEntryType = -1;
pub type xmlCatalogType = u32;
pub const XML_SGML_CATALOG_TYPE: xmlCatalogType = 2;
pub const XML_XML_CATALOG_TYPE: xmlCatalogType = 1;
pub type xmlCatalog<'a> = crate::src::catalog::_xmlCatalog<'a>;
pub type xmlCatalogPtr<'a> = *mut crate::src::catalog::_xmlCatalog<'a>;
#[inline]
extern "C" fn stat(mut __path: *const i8, mut __statbuf: *mut crate::src::catalog::stat) -> i32 {
    return unsafe { __xstat(1 as i32, __path, __statbuf) };
}
static mut xmlDebugCatalogs: i32 = 0 as i32;
static mut xmlCatalogDefaultAllow: u32 = XML_CATA_ALLOW_ALL;
static mut xmlCatalogDefaultPrefer: u32 = XML_CATA_PREFER_PUBLIC;
static mut xmlCatalogXMLFiles: *mut crate::src::hash::_xmlHashTable =
    0 as *const xmlHashTable as xmlHashTablePtr;
static mut xmlDefaultCatalog: *mut crate::src::catalog::_xmlCatalog<'static> =
    0 as *const xmlCatalog as xmlCatalogPtr;
static mut xmlCatalogMutex: *mut crate::src::catalog::_xmlRMutex =
    0 as *const xmlRMutex as xmlRMutexPtr;
static mut xmlCatalogInitialized: i32 = 0 as i32;
extern "C" fn xmlCatalogErrMemory(mut extra: *const i8) {
    (unsafe {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_CATALOG as i32,
            XML_ERR_NO_MEMORY as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            extra,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"Memory allocation failed : %s\n\0" as *const u8 as *const i8,
            extra,
        )
    });
}
extern "C" fn xmlCatalogErr(
    mut catal: *mut crate::src::catalog::_xmlCatalogEntry,
    mut node: *mut crate::src::HTMLparser::_xmlNode,
    mut error: i32,
    mut msg: *const i8,
    mut str1: *const u8,
    mut str2: *const u8,
    mut str3: *const u8,
) {
    (unsafe {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            catal as *mut libc::c_void,
            node as *mut libc::c_void,
            XML_FROM_CATALOG as i32,
            error,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            str1 as *const i8,
            str2 as *const i8,
            str3 as *const i8,
            0 as i32,
            0 as i32,
            msg,
            str1,
            str2,
            str3,
        )
    });
}
extern "C" fn xmlNewCatalogEntry(
    mut type_0: i32,
    mut name: *const u8,
    mut value: *const u8,
    mut URL: *const u8,
    mut prefer: u32,
    mut group: *mut crate::src::catalog::_xmlCatalogEntry,
) -> *mut crate::src::catalog::_xmlCatalogEntry {
    let mut ret: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    let mut normid: *mut u8 = 0 as *mut xmlChar;
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlCatalogEntry>() as u64
        )
    }) as xmlCatalogEntryPtr;
    if ret.is_null() {
        xmlCatalogErrMemory(b"allocating catalog entry\0" as *const u8 as *const i8);
        return 0 as xmlCatalogEntryPtr;
    }
    let fresh0 = unsafe { &mut ((*ret).next) };
    *fresh0 = 0 as *mut _xmlCatalogEntry;
    let fresh1 = unsafe { &mut ((*ret).parent) };
    *fresh1 = 0 as *mut _xmlCatalogEntry;
    let fresh2 = unsafe { &mut ((*ret).children) };
    *fresh2 = 0 as *mut _xmlCatalogEntry;
    (unsafe { (*ret).type_0 = type_0 });
    if type_0 as i32 == XML_CATA_PUBLIC as i32 || type_0 as i32 == XML_CATA_DELEGATE_PUBLIC as i32 {
        normid = xmlCatalogNormalizePublic(name);
        if !normid.is_null() {
            name = if (unsafe { *normid }) as i32 != 0 as i32 {
                normid
            } else {
                0 as *mut xmlChar
            };
        }
    }
    if !name.is_null() {
        let fresh3 = unsafe { &mut ((*ret).name) };
        *fresh3 = unsafe { xmlStrdup(name) };
    } else {
        let fresh4 = unsafe { &mut ((*ret).name) };
        *fresh4 = 0 as *mut xmlChar;
    }
    if !normid.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void) });
    }
    if !value.is_null() {
        let fresh5 = unsafe { &mut ((*ret).value) };
        *fresh5 = unsafe { xmlStrdup(value) };
    } else {
        let fresh6 = unsafe { &mut ((*ret).value) };
        *fresh6 = 0 as *mut xmlChar;
    }
    if URL.is_null() {
        URL = value;
    }
    if !URL.is_null() {
        let fresh7 = unsafe { &mut ((*ret).URL) };
        *fresh7 = unsafe { xmlStrdup(URL) };
    } else {
        let fresh8 = unsafe { &mut ((*ret).URL) };
        *fresh8 = 0 as *mut xmlChar;
    }
    (unsafe { (*ret).prefer = prefer });
    (unsafe { (*ret).dealloc = 0 as i32 });
    (unsafe { (*ret).depth = 0 as i32 });
    let fresh9 = unsafe { &mut ((*ret).group) };
    *fresh9 = group;
    return ret;
}
extern "C" fn xmlFreeCatalogEntry(mut payload: *mut core::ffi::c_void, mut _name: *const u8) {
    let mut ret: *mut crate::src::catalog::_xmlCatalogEntry = payload as xmlCatalogEntryPtr;
    if ret.is_null() {
        return;
    }
    if (unsafe { (*ret).dealloc }) == 1 as i32 {
        return;
    }
    if (unsafe { xmlDebugCatalogs }) != 0 {
        if !(unsafe { (*ret).name }).is_null() {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"Free catalog entry %s\n\0" as *const u8 as *const i8,
                    (*ret).name,
                )
            });
        } else if !(unsafe { (*ret).value }).is_null() {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"Free catalog entry %s\n\0" as *const u8 as *const i8,
                    (*ret).value,
                )
            });
        } else {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"Free catalog entry\n\0" as *const u8 as *const i8,
                )
            });
        }
    }
    if !(unsafe { (*ret).name }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*ret).name as *mut libc::c_void) });
    }
    if !(unsafe { (*ret).value }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*ret).value as *mut libc::c_void) });
    }
    if !(unsafe { (*ret).URL }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*ret).URL as *mut libc::c_void) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
}
extern "C" fn xmlFreeCatalogEntryList(mut ret: *mut crate::src::catalog::_xmlCatalogEntry) {
    let mut next: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    while !ret.is_null() {
        next = unsafe { (*ret).next };
        xmlFreeCatalogEntry(ret as *mut libc::c_void, 0 as *const xmlChar);
        ret = next;
    }
}
extern "C" fn xmlFreeCatalogHashEntryList(
    mut payload: *mut core::ffi::c_void,
    mut _name: *const u8,
) {
    let mut catal: *mut crate::src::catalog::_xmlCatalogEntry = payload as xmlCatalogEntryPtr;
    let mut children: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    let mut next: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    if catal.is_null() {
        return;
    }
    children = unsafe { (*catal).children };
    while !children.is_null() {
        next = unsafe { (*children).next };
        (unsafe { (*children).dealloc = 0 as i32 });
        let fresh10 = unsafe { &mut ((*children).children) };
        *fresh10 = 0 as *mut _xmlCatalogEntry;
        xmlFreeCatalogEntry(children as *mut libc::c_void, 0 as *const xmlChar);
        children = next;
    }
    (unsafe { (*catal).dealloc = 0 as i32 });
    xmlFreeCatalogEntry(catal as *mut libc::c_void, 0 as *const xmlChar);
}
extern "C" fn xmlCreateNewCatalog<'a1>(
    mut type_0: u32,
    mut prefer: u32,
) -> *mut crate::src::catalog::_xmlCatalog<'a1> {
    let mut ret: *mut crate::src::catalog::_xmlCatalog<'_> = 0 as *mut xmlCatalog;
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlCatalog>() as u64)
    }) as xmlCatalogPtr;
    if ret.is_null() {
        xmlCatalogErrMemory(b"allocating catalog\0" as *const u8 as *const i8);
        return 0 as xmlCatalogPtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlCatalog>() as u64,
        )
    });
    (unsafe { (*ret).type_0 = type_0 });
    (unsafe { (*ret).catalNr = 0 as i32 });
    (unsafe { (*ret).catalMax = 10 as i32 });
    (unsafe { (*ret).prefer = prefer });
    if (unsafe { (*ret).type_0 }) as u32 == XML_SGML_CATALOG_TYPE as i32 as u32 {
        let fresh11 = unsafe { &mut ((*ret).sgml) };
        *fresh11 = xmlHashCreate(10 as i32);
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlFreeCatalog<'a1>(mut catal: *mut crate::src::catalog::_xmlCatalog<'a1>) {
    if catal.is_null() {
        return;
    }
    if !(unsafe { (*catal).xml }).is_null() {
        xmlFreeCatalogEntryList(unsafe { (*catal).xml });
    }
    if !(unsafe { (*catal).sgml }).is_null() {
        xmlHashFree(unsafe { (*catal).sgml }, Some(xmlFreeCatalogEntry));
    }
    (unsafe { xmlFree.expect("non-null function pointer")(catal as *mut libc::c_void) });
}
extern "C" fn xmlCatalogDumpEntry(
    mut payload: *mut core::ffi::c_void,
    mut data: *mut core::ffi::c_void,
    mut _name: *const u8,
) {
    let mut entry: *mut crate::src::catalog::_xmlCatalogEntry = payload as xmlCatalogEntryPtr;
    let mut out: *mut crate::src::HTMLtree::_IO_FILE = data as *mut FILE;
    if entry.is_null() || out.is_null() {
        return;
    }
    match (unsafe { (*entry).type_0 }) as i32 {
        15 => {
            (unsafe { fprintf(out, b"ENTITY \0" as *const u8 as *const i8) });
        }
        16 => {
            (unsafe { fprintf(out, b"ENTITY %%\0" as *const u8 as *const i8) });
        }
        17 => {
            (unsafe { fprintf(out, b"DOCTYPE \0" as *const u8 as *const i8) });
        }
        18 => {
            (unsafe { fprintf(out, b"LINKTYPE \0" as *const u8 as *const i8) });
        }
        19 => {
            (unsafe { fprintf(out, b"NOTATION \0" as *const u8 as *const i8) });
        }
        14 => {
            (unsafe { fprintf(out, b"PUBLIC \0" as *const u8 as *const i8) });
        }
        13 => {
            (unsafe { fprintf(out, b"SYSTEM \0" as *const u8 as *const i8) });
        }
        20 => {
            (unsafe { fprintf(out, b"DELEGATE \0" as *const u8 as *const i8) });
        }
        21 => {
            (unsafe { fprintf(out, b"BASE \0" as *const u8 as *const i8) });
        }
        22 => {
            (unsafe { fprintf(out, b"CATALOG \0" as *const u8 as *const i8) });
        }
        23 => {
            (unsafe { fprintf(out, b"DOCUMENT \0" as *const u8 as *const i8) });
        }
        24 => {
            (unsafe { fprintf(out, b"SGMLDECL \0" as *const u8 as *const i8) });
        }
        _ => return,
    }
    match (unsafe { (*entry).type_0 }) as i32 {
        15 | 16 | 17 | 18 | 19 => {
            (unsafe {
                fprintf(
                    out,
                    b"%s\0" as *const u8 as *const i8,
                    (*entry).name as *const i8,
                )
            });
        }
        14 | 13 | 24 | 23 | 22 | 21 | 20 => {
            (unsafe { fprintf(out, b"\"%s\"\0" as *const u8 as *const i8, (*entry).name) });
        }
        _ => {}
    }
    match (unsafe { (*entry).type_0 }) as i32 {
        15 | 16 | 17 | 18 | 19 | 14 | 13 | 20 => {
            (unsafe { fprintf(out, b" \"%s\"\0" as *const u8 as *const i8, (*entry).value) });
        }
        _ => {}
    }
    (unsafe { fprintf(out, b"\n\0" as *const u8 as *const i8) });
}
extern "C" fn xmlDumpXMLCatalogNode(
    mut catal: *mut crate::src::catalog::_xmlCatalogEntry,
    mut catalog: *mut crate::src::HTMLparser::_xmlNode,
    mut doc: *mut crate::src::HTMLparser::_xmlDoc,
    mut ns: *mut crate::src::HTMLparser::_xmlNs,
    mut cgroup: *mut crate::src::catalog::_xmlCatalogEntry,
) {
    let mut node: *mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    let mut cur: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    cur = catal;
    let mut current_block_49: u64;
    while !cur.is_null() {
        if (unsafe { (*cur).group }) == cgroup {
            match (unsafe { (*cur).type_0 }) as i32 {
                2 | 1 => {
                    current_block_49 = 15414981286075827;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = unsafe { (*cur).children };
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16086062102548664993 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"name\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        776782378719281040 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16251997513805125340 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        12614018986753156024 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        3278478806863930313 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        2042511421509206405 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        17827901024417069171 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"group\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            if !(unsafe { (*cur).value }).is_null() {
                                let mut xns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
                                xns = unsafe {
                                    xmlSearchNsByHref(
                                        doc,
                                        node,
                                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                            as *const i8
                                            as *const xmlChar,
                                    )
                                };
                                if !xns.is_null() {
                                    (unsafe {
                                        xmlSetNsProp(
                                            node,
                                            xns,
                                            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                                            (*cur).value,
                                        )
                                    });
                                }
                            }
                            match (unsafe { (*cur).prefer }) as u32 {
                                1 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                2 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode(unsafe { (*cur).next }, node, doc, ns, cur);
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        5425920993883413897 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        _ => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                    }
                }
                3 => {
                    current_block_49 = 5425920993883413897;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = unsafe { (*cur).children };
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16086062102548664993 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"name\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        776782378719281040 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16251997513805125340 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        12614018986753156024 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        3278478806863930313 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        2042511421509206405 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        17827901024417069171 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"group\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            if !(unsafe { (*cur).value }).is_null() {
                                let mut xns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
                                xns = unsafe {
                                    xmlSearchNsByHref(
                                        doc,
                                        node,
                                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                            as *const i8
                                            as *const xmlChar,
                                    )
                                };
                                if !xns.is_null() {
                                    (unsafe {
                                        xmlSetNsProp(
                                            node,
                                            xns,
                                            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                                            (*cur).value,
                                        )
                                    });
                                }
                            }
                            match (unsafe { (*cur).prefer }) as u32 {
                                1 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                2 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode(unsafe { (*cur).next }, node, doc, ns, cur);
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        5425920993883413897 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        _ => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                    }
                }
                4 => {
                    current_block_49 = 17827901024417069171;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = unsafe { (*cur).children };
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16086062102548664993 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"name\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        776782378719281040 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16251997513805125340 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        12614018986753156024 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        3278478806863930313 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        2042511421509206405 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        17827901024417069171 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"group\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            if !(unsafe { (*cur).value }).is_null() {
                                let mut xns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
                                xns = unsafe {
                                    xmlSearchNsByHref(
                                        doc,
                                        node,
                                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                            as *const i8
                                            as *const xmlChar,
                                    )
                                };
                                if !xns.is_null() {
                                    (unsafe {
                                        xmlSetNsProp(
                                            node,
                                            xns,
                                            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                                            (*cur).value,
                                        )
                                    });
                                }
                            }
                            match (unsafe { (*cur).prefer }) as u32 {
                                1 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                2 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode(unsafe { (*cur).next }, node, doc, ns, cur);
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        5425920993883413897 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        _ => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                    }
                }
                5 => {
                    current_block_49 = 2042511421509206405;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = unsafe { (*cur).children };
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16086062102548664993 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"name\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        776782378719281040 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16251997513805125340 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        12614018986753156024 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        3278478806863930313 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        2042511421509206405 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        17827901024417069171 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"group\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            if !(unsafe { (*cur).value }).is_null() {
                                let mut xns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
                                xns = unsafe {
                                    xmlSearchNsByHref(
                                        doc,
                                        node,
                                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                            as *const i8
                                            as *const xmlChar,
                                    )
                                };
                                if !xns.is_null() {
                                    (unsafe {
                                        xmlSetNsProp(
                                            node,
                                            xns,
                                            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                                            (*cur).value,
                                        )
                                    });
                                }
                            }
                            match (unsafe { (*cur).prefer }) as u32 {
                                1 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                2 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode(unsafe { (*cur).next }, node, doc, ns, cur);
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        5425920993883413897 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        _ => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                    }
                }
                6 => {
                    current_block_49 = 3278478806863930313;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = unsafe { (*cur).children };
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16086062102548664993 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"name\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        776782378719281040 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16251997513805125340 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        12614018986753156024 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        3278478806863930313 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        2042511421509206405 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        17827901024417069171 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"group\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            if !(unsafe { (*cur).value }).is_null() {
                                let mut xns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
                                xns = unsafe {
                                    xmlSearchNsByHref(
                                        doc,
                                        node,
                                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                            as *const i8
                                            as *const xmlChar,
                                    )
                                };
                                if !xns.is_null() {
                                    (unsafe {
                                        xmlSetNsProp(
                                            node,
                                            xns,
                                            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                                            (*cur).value,
                                        )
                                    });
                                }
                            }
                            match (unsafe { (*cur).prefer }) as u32 {
                                1 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                2 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode(unsafe { (*cur).next }, node, doc, ns, cur);
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        5425920993883413897 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        _ => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                    }
                }
                7 => {
                    current_block_49 = 12614018986753156024;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = unsafe { (*cur).children };
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16086062102548664993 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"name\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        776782378719281040 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16251997513805125340 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        12614018986753156024 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        3278478806863930313 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        2042511421509206405 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        17827901024417069171 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"group\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            if !(unsafe { (*cur).value }).is_null() {
                                let mut xns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
                                xns = unsafe {
                                    xmlSearchNsByHref(
                                        doc,
                                        node,
                                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                            as *const i8
                                            as *const xmlChar,
                                    )
                                };
                                if !xns.is_null() {
                                    (unsafe {
                                        xmlSetNsProp(
                                            node,
                                            xns,
                                            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                                            (*cur).value,
                                        )
                                    });
                                }
                            }
                            match (unsafe { (*cur).prefer }) as u32 {
                                1 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                2 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode(unsafe { (*cur).next }, node, doc, ns, cur);
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        5425920993883413897 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        _ => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                    }
                }
                8 => {
                    current_block_49 = 16251997513805125340;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = unsafe { (*cur).children };
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16086062102548664993 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"name\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        776782378719281040 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16251997513805125340 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        12614018986753156024 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        3278478806863930313 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        2042511421509206405 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        17827901024417069171 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"group\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            if !(unsafe { (*cur).value }).is_null() {
                                let mut xns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
                                xns = unsafe {
                                    xmlSearchNsByHref(
                                        doc,
                                        node,
                                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                            as *const i8
                                            as *const xmlChar,
                                    )
                                };
                                if !xns.is_null() {
                                    (unsafe {
                                        xmlSetNsProp(
                                            node,
                                            xns,
                                            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                                            (*cur).value,
                                        )
                                    });
                                }
                            }
                            match (unsafe { (*cur).prefer }) as u32 {
                                1 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                2 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode(unsafe { (*cur).next }, node, doc, ns, cur);
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        5425920993883413897 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        _ => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                    }
                }
                9 => {
                    current_block_49 = 776782378719281040;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = unsafe { (*cur).children };
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16086062102548664993 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"name\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        776782378719281040 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16251997513805125340 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        12614018986753156024 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        3278478806863930313 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        2042511421509206405 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        17827901024417069171 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"group\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            if !(unsafe { (*cur).value }).is_null() {
                                let mut xns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
                                xns = unsafe {
                                    xmlSearchNsByHref(
                                        doc,
                                        node,
                                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                            as *const i8
                                            as *const xmlChar,
                                    )
                                };
                                if !xns.is_null() {
                                    (unsafe {
                                        xmlSetNsProp(
                                            node,
                                            xns,
                                            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                                            (*cur).value,
                                        )
                                    });
                                }
                            }
                            match (unsafe { (*cur).prefer }) as u32 {
                                1 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                2 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode(unsafe { (*cur).next }, node, doc, ns, cur);
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        5425920993883413897 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        _ => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                    }
                }
                10 => {
                    current_block_49 = 16086062102548664993;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = unsafe { (*cur).children };
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16086062102548664993 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"name\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        776782378719281040 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16251997513805125340 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        12614018986753156024 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        3278478806863930313 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        2042511421509206405 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        17827901024417069171 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"group\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            if !(unsafe { (*cur).value }).is_null() {
                                let mut xns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
                                xns = unsafe {
                                    xmlSearchNsByHref(
                                        doc,
                                        node,
                                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                            as *const i8
                                            as *const xmlChar,
                                    )
                                };
                                if !xns.is_null() {
                                    (unsafe {
                                        xmlSetNsProp(
                                            node,
                                            xns,
                                            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                                            (*cur).value,
                                        )
                                    });
                                }
                            }
                            match (unsafe { (*cur).prefer }) as u32 {
                                1 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                2 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode(unsafe { (*cur).next }, node, doc, ns, cur);
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        5425920993883413897 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        _ => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                    }
                }
                11 => {
                    current_block_49 = 3932087857103670784;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = unsafe { (*cur).children };
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16086062102548664993 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"name\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        776782378719281040 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16251997513805125340 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        12614018986753156024 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        3278478806863930313 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        2042511421509206405 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        17827901024417069171 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"group\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            if !(unsafe { (*cur).value }).is_null() {
                                let mut xns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
                                xns = unsafe {
                                    xmlSearchNsByHref(
                                        doc,
                                        node,
                                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                            as *const i8
                                            as *const xmlChar,
                                    )
                                };
                                if !xns.is_null() {
                                    (unsafe {
                                        xmlSetNsProp(
                                            node,
                                            xns,
                                            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                                            (*cur).value,
                                        )
                                    });
                                }
                            }
                            match (unsafe { (*cur).prefer }) as u32 {
                                1 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                2 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode(unsafe { (*cur).next }, node, doc, ns, cur);
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        5425920993883413897 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        _ => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                    }
                }
                12 => {
                    current_block_49 = 16685025456891485352;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = unsafe { (*cur).children };
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16086062102548664993 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"name\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        776782378719281040 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        16251997513805125340 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        12614018986753156024 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemIdStartString\0" as *const u8 as *const i8
                                        as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        3278478806863930313 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"systemId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        2042511421509206405 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"publicId\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        17827901024417069171 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"group\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            if !(unsafe { (*cur).value }).is_null() {
                                let mut xns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
                                xns = unsafe {
                                    xmlSearchNsByHref(
                                        doc,
                                        node,
                                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                            as *const i8
                                            as *const xmlChar,
                                    )
                                };
                                if !xns.is_null() {
                                    (unsafe {
                                        xmlSetNsProp(
                                            node,
                                            xns,
                                            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                                            (*cur).value,
                                        )
                                    });
                                }
                            }
                            match (unsafe { (*cur).prefer }) as u32 {
                                1 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                2 => {
                                    (unsafe {
                                        xmlSetProp(
                                            node,
                                            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
                                            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
                                        )
                                    });
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode(unsafe { (*cur).next }, node, doc, ns, cur);
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        5425920993883413897 => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                        _ => {
                            node = unsafe {
                                xmlNewDocNode(
                                    doc,
                                    ns,
                                    b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as *const xmlChar,
                                )
                            };
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).name,
                                )
                            });
                            (unsafe {
                                xmlSetProp(
                                    node,
                                    b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
                                    (*cur).value,
                                )
                            });
                            (unsafe { xmlAddChild(catalog, node) });
                        }
                    }
                }
                -1 | 0 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | _ => {}
            }
        }
        cur = unsafe { (*cur).next };
    }
}
extern "C" fn xmlDumpXMLCatalog(
    mut out: *mut crate::src::HTMLtree::_IO_FILE,
    mut catal: *mut crate::src::catalog::_xmlCatalogEntry,
) -> i32 {
    let mut ret: i32 = 0;
    let mut doc: *mut crate::src::HTMLparser::_xmlDoc = 0 as *mut xmlDoc;
    let mut ns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
    let mut dtd: *mut crate::src::HTMLparser::_xmlDtd = 0 as *mut xmlDtd;
    let mut catalog: *mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    let mut buf: *mut crate::src::HTMLtree::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    doc = unsafe { xmlNewDoc(0 as *const xmlChar) };
    if doc.is_null() {
        return -(1 as i32);
    }
    dtd = unsafe {
        xmlNewDtd(
            doc,
            b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
            b"-//OASIS//DTD Entity Resolution XML Catalog V1.0//EN\0" as *const u8 as *const i8
                as *mut xmlChar,
            b"http://www.oasis-open.org/committees/entity/release/1.0/catalog.dtd\0" as *const u8
                as *const i8 as *mut xmlChar,
        )
    };
    (unsafe { xmlAddChild(doc as xmlNodePtr, dtd as xmlNodePtr) });
    ns = unsafe {
        xmlNewNs(
            0 as xmlNodePtr,
            b"urn:oasis:names:tc:entity:xmlns:xml:catalog\0" as *const u8 as *const i8
                as *const xmlChar,
            0 as *const xmlChar,
        )
    };
    if ns.is_null() {
        (unsafe { xmlFreeDoc(doc) });
        return -(1 as i32);
    }
    catalog = unsafe {
        xmlNewDocNode(
            doc,
            ns,
            b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
            0 as *const xmlChar,
        )
    };
    if catalog.is_null() {
        (unsafe { xmlFreeNs(ns) });
        (unsafe { xmlFreeDoc(doc) });
        return -(1 as i32);
    }
    let fresh12 = unsafe { &mut ((*catalog).nsDef) };
    *fresh12 = ns;
    (unsafe { xmlAddChild(doc as xmlNodePtr, catalog) });
    xmlDumpXMLCatalogNode(catal, catalog, doc, ns, 0 as xmlCatalogEntryPtr);
    buf = unsafe { xmlOutputBufferCreateFile(out, 0 as xmlCharEncodingHandlerPtr) };
    if buf.is_null() {
        (unsafe { xmlFreeDoc(doc) });
        return -(1 as i32);
    }
    ret = unsafe { xmlSaveFormatFileTo(buf, doc, 0 as *const i8, 1 as i32) };
    (unsafe { xmlFreeDoc(doc) });
    return ret;
}
extern "C" fn xmlCatalogConvertEntry(
    mut payload: *mut core::ffi::c_void,
    mut data: *mut core::ffi::c_void,
    mut _name: *const u8,
) {
    let mut entry: *mut crate::src::catalog::_xmlCatalogEntry = payload as xmlCatalogEntryPtr;
    let mut catal: *mut crate::src::catalog::_xmlCatalog<'_> = data as xmlCatalogPtr;
    if entry.is_null()
        || catal.is_null()
        || (unsafe { (*catal).sgml }).is_null()
        || (unsafe { (*catal).xml }).is_null()
    {
        return;
    }
    match (unsafe { (*entry).type_0 }) as i32 {
        15 => {
            (unsafe { (*entry).type_0 = XML_CATA_PUBLIC });
        }
        16 => {
            (unsafe { (*entry).type_0 = XML_CATA_PUBLIC });
        }
        17 => {
            (unsafe { (*entry).type_0 = XML_CATA_PUBLIC });
        }
        18 => {
            (unsafe { (*entry).type_0 = XML_CATA_PUBLIC });
        }
        19 => {
            (unsafe { (*entry).type_0 = XML_CATA_PUBLIC });
        }
        14 => {
            (unsafe { (*entry).type_0 = XML_CATA_PUBLIC });
        }
        13 => {
            (unsafe { (*entry).type_0 = XML_CATA_SYSTEM });
        }
        20 => {
            (unsafe { (*entry).type_0 = XML_CATA_DELEGATE_PUBLIC });
        }
        22 => {
            (unsafe { (*entry).type_0 = XML_CATA_CATALOG });
        }
        _ => {
            xmlHashRemoveEntry(
                unsafe { (*catal).sgml },
                unsafe { (*entry).name },
                Some(xmlFreeCatalogEntry),
            );
            return;
        }
    }
    xmlHashRemoveEntry(unsafe { (*catal).sgml }, unsafe { (*entry).name }, None);
    let fresh13 = unsafe { &mut ((*entry).parent) };
    *fresh13 = unsafe { (*catal).xml };
    let fresh14 = unsafe { &mut ((*entry).next) };
    *fresh14 = 0 as *mut _xmlCatalogEntry;
    if (unsafe { (*(*catal).xml).children }).is_null() {
        let fresh15 = unsafe { &mut ((*(*catal).xml).children) };
        *fresh15 = entry;
    } else {
        let mut prev: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
        prev = unsafe { (*(*catal).xml).children };
        while !(unsafe { (*prev).next }).is_null() {
            prev = unsafe { (*prev).next };
        }
        let fresh16 = unsafe { &mut ((*prev).next) };
        *fresh16 = entry;
    };
}
#[no_mangle]
pub extern "C" fn xmlConvertSGMLCatalog<'a1>(
    mut catal: *mut crate::src::catalog::_xmlCatalog<'a1>,
) -> i32 {
    if catal.is_null() || (unsafe { (*catal).type_0 }) as u32 != XML_SGML_CATALOG_TYPE as i32 as u32
    {
        return -(1 as i32);
    }
    if (unsafe { xmlDebugCatalogs }) != 0 {
        (unsafe {
            (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                *(__xmlGenericErrorContext()).unwrap(),
                b"Converting SGML catalog to XML\n\0" as *const u8 as *const i8,
            )
        });
    }
    xmlHashScan(
        unsafe { (*catal).sgml },
        Some(xmlCatalogConvertEntry),
        &mut catal as *mut xmlCatalogPtr as *mut libc::c_void,
    );
    return 0 as i32;
}
extern "C" fn xmlCatalogUnWrapURN(mut urn: *const u8) -> *mut u8 {
    let mut result: [u8; 2000] = [0; 2000];
    let mut i: u32 = 0 as i32 as u32;
    if (unsafe {
        xmlStrncmp(
            urn,
            b"urn:publicid:\0" as *const u8 as *const i8 as *mut xmlChar,
            (::std::mem::size_of::<[i8; 14]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
        )
    }) != 0
    {
        return 0 as *mut xmlChar;
    }
    urn = unsafe {
        urn.offset(
            (::std::mem::size_of::<[i8; 14]>() as u64).wrapping_sub(1 as i32 as u64) as isize,
        )
    };
    while (unsafe { *urn }) as i32 != 0 as i32 {
        if i as u64
            > (::std::mem::size_of::<[xmlChar; 2000]>() as u64).wrapping_sub(4 as i32 as u64)
        {
            break;
        }
        if (unsafe { *urn }) as i32 == '+' as i32 {
            let mut fresh17 = i;
            i = i.wrapping_add(1);
            result[fresh17 as usize] = ' ' as i32 as xmlChar;
            urn = unsafe { urn.offset(1) };
        } else if (unsafe { *urn }) as i32 == ':' as i32 {
            let mut fresh18 = i;
            i = i.wrapping_add(1);
            result[fresh18 as usize] = '/' as i32 as xmlChar;
            let mut fresh19 = i;
            i = i.wrapping_add(1);
            result[fresh19 as usize] = '/' as i32 as xmlChar;
            urn = unsafe { urn.offset(1) };
        } else if (unsafe { *urn }) as i32 == ';' as i32 {
            let mut fresh20 = i;
            i = i.wrapping_add(1);
            result[fresh20 as usize] = ':' as i32 as xmlChar;
            let mut fresh21 = i;
            i = i.wrapping_add(1);
            result[fresh21 as usize] = ':' as i32 as xmlChar;
            urn = unsafe { urn.offset(1) };
        } else if (unsafe { *urn }) as i32 == '%' as i32 {
            if (unsafe { *urn.offset(1 as i32 as isize) }) as i32 == '2' as i32
                && (unsafe { *urn.offset(2 as i32 as isize) }) as i32 == 'B' as i32
            {
                let mut fresh22 = i;
                i = i.wrapping_add(1);
                result[fresh22 as usize] = '+' as i32 as xmlChar;
            } else if (unsafe { *urn.offset(1 as i32 as isize) }) as i32 == '3' as i32
                && (unsafe { *urn.offset(2 as i32 as isize) }) as i32 == 'A' as i32
            {
                let mut fresh23 = i;
                i = i.wrapping_add(1);
                result[fresh23 as usize] = ':' as i32 as xmlChar;
            } else if (unsafe { *urn.offset(1 as i32 as isize) }) as i32 == '2' as i32
                && (unsafe { *urn.offset(2 as i32 as isize) }) as i32 == 'F' as i32
            {
                let mut fresh24 = i;
                i = i.wrapping_add(1);
                result[fresh24 as usize] = '/' as i32 as xmlChar;
            } else if (unsafe { *urn.offset(1 as i32 as isize) }) as i32 == '3' as i32
                && (unsafe { *urn.offset(2 as i32 as isize) }) as i32 == 'B' as i32
            {
                let mut fresh25 = i;
                i = i.wrapping_add(1);
                result[fresh25 as usize] = ';' as i32 as xmlChar;
            } else if (unsafe { *urn.offset(1 as i32 as isize) }) as i32 == '2' as i32
                && (unsafe { *urn.offset(2 as i32 as isize) }) as i32 == '7' as i32
            {
                let mut fresh26 = i;
                i = i.wrapping_add(1);
                result[fresh26 as usize] = '\'' as i32 as xmlChar;
            } else if (unsafe { *urn.offset(1 as i32 as isize) }) as i32 == '3' as i32
                && (unsafe { *urn.offset(2 as i32 as isize) }) as i32 == 'F' as i32
            {
                let mut fresh27 = i;
                i = i.wrapping_add(1);
                result[fresh27 as usize] = '?' as i32 as xmlChar;
            } else if (unsafe { *urn.offset(1 as i32 as isize) }) as i32 == '2' as i32
                && (unsafe { *urn.offset(2 as i32 as isize) }) as i32 == '3' as i32
            {
                let mut fresh28 = i;
                i = i.wrapping_add(1);
                result[fresh28 as usize] = '#' as i32 as xmlChar;
            } else if (unsafe { *urn.offset(1 as i32 as isize) }) as i32 == '2' as i32
                && (unsafe { *urn.offset(2 as i32 as isize) }) as i32 == '5' as i32
            {
                let mut fresh29 = i;
                i = i.wrapping_add(1);
                result[fresh29 as usize] = '%' as i32 as xmlChar;
            } else {
                let mut fresh30 = i;
                i = i.wrapping_add(1);
                result[fresh30 as usize] = unsafe { *urn };
                urn = unsafe { urn.offset(1) };
                continue;
            }
            urn = unsafe { urn.offset(3 as i32 as isize) };
        } else {
            let mut fresh31 = i;
            i = i.wrapping_add(1);
            result[fresh31 as usize] = unsafe { *urn };
            urn = unsafe { urn.offset(1) };
        }
    }
    result[i as usize] = 0 as i32 as xmlChar;
    return unsafe { xmlStrdup(result.as_mut_ptr()) };
}
#[no_mangle]
pub extern "C" fn xmlParseCatalogFile(
    mut filename: *const i8,
) -> *mut crate::src::HTMLparser::_xmlDoc {
    let mut ret: *mut crate::src::HTMLparser::_xmlDoc = 0 as *mut xmlDoc;
    let mut ctxt: *mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut directory: *mut i8 = 0 as *mut i8;
    let mut inputStream: *mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut buf: *mut crate::src::HTMLparser::_xmlParserInputBuffer =
        0 as *mut xmlParserInputBuffer;
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        if unsafe { ((*__xmlDefaultSAXHandler()).error).is_some() } {
            (unsafe {
                ((*__xmlDefaultSAXHandler()).error).expect("non-null function pointer")(
                    0 as *mut libc::c_void,
                    b"out of memory\n\0" as *const u8 as *const i8,
                )
            });
        }
        return 0 as xmlDocPtr;
    }
    buf = unsafe { xmlParserInputBufferCreateFilename(filename, XML_CHAR_ENCODING_NONE) };
    if buf.is_null() {
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDocPtr;
    }
    inputStream = xmlNewInputStream(ctxt);
    if inputStream.is_null() {
        (unsafe { xmlFreeParserInputBuffer(buf) });
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDocPtr;
    }
    let fresh32 = unsafe { &mut ((*inputStream).filename) };
    *fresh32 = (unsafe { xmlCanonicPath(filename as *const xmlChar) }) as *mut i8;
    let fresh33 = unsafe { &mut ((*inputStream).buf) };
    *fresh33 = buf;
    xmlBufResetInput(unsafe { (*buf).buffer }, inputStream);
    inputPush(ctxt, inputStream);
    if (unsafe { (*ctxt).directory }).is_null() {
        directory = unsafe { xmlParserGetDirectory(filename) };
    }
    if (unsafe { (*ctxt).directory }).is_null() && !directory.is_null() {
        let fresh34 = unsafe { &mut ((*ctxt).directory) };
        *fresh34 = directory;
    }
    (unsafe { (*ctxt).valid = 0 as i32 });
    (unsafe { (*ctxt).validate = 0 as i32 });
    (unsafe { (*ctxt).loadsubset = 0 as i32 });
    (unsafe { (*ctxt).pedantic = 0 as i32 });
    (unsafe { (*ctxt).dictNames = 1 as i32 });
    xmlParseDocument(ctxt);
    if (unsafe { (*ctxt).wellFormed }) != 0 {
        ret = unsafe { (*ctxt).myDoc };
    } else {
        ret = 0 as xmlDocPtr;
        (unsafe { xmlFreeDoc((*ctxt).myDoc) });
        let fresh35 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh35 = 0 as xmlDocPtr;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
extern "C" fn xmlLoadFileContent(mut filename: *const i8) -> *mut u8 {
    let mut fd: i32 = 0;
    let mut len: i32 = 0;
    let mut size: i64 = 0;
    let mut info: crate::src::catalog::stat = stat {
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
        st_atim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_mtim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_ctim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        __glibc_reserved: [0; 3],
    };
    let mut content: *mut u8 = 0 as *mut xmlChar;
    if filename.is_null() {
        return 0 as *mut xmlChar;
    }
    if stat(filename, &mut info) < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    fd = unsafe { open(filename, 0 as i32) };
    if fd < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    size = info.st_size;
    content = (unsafe {
        xmlMallocAtomic.expect("non-null function pointer")((size + 10 as i32 as i64) as size_t)
    }) as *mut xmlChar;
    if content.is_null() {
        xmlCatalogErrMemory(b"allocating catalog data\0" as *const u8 as *const i8);
        (unsafe { close(fd) });
        return 0 as *mut xmlChar;
    }
    len = (unsafe { read(fd, content as *mut libc::c_void, size as size_t) }) as i32;
    (unsafe { close(fd) });
    if len < 0 as i32 {
        (unsafe { xmlFree.expect("non-null function pointer")(content as *mut libc::c_void) });
        return 0 as *mut xmlChar;
    }
    (unsafe { *content.offset(len as isize) = 0 as i32 as xmlChar });
    return content;
}
extern "C" fn xmlCatalogNormalizePublic(mut pubID: *const u8) -> *mut u8 {
    let mut ok: i32 = 1 as i32;
    let mut white: i32 = 0;
    let mut p: *const u8 = 0 as *const xmlChar;
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    let mut q: *mut u8 = 0 as *mut xmlChar;
    if pubID.is_null() {
        return 0 as *mut xmlChar;
    }
    white = 1 as i32;
    p = pubID;
    while (unsafe { *p }) as i32 != 0 as i32 && ok != 0 {
        if !((unsafe { *p }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *p }) as i32 && (unsafe { *p }) as i32 <= 0xa as i32
            || (unsafe { *p }) as i32 == 0xd as i32)
        {
            white = 0 as i32;
        } else if (unsafe { *p }) as i32 == 0x20 as i32 && white == 0 {
            white = 1 as i32;
        } else {
            ok = 0 as i32;
        }
        p = unsafe { p.offset(1) };
    }
    if ok != 0 && white == 0 {
        return 0 as *mut xmlChar;
    }
    ret = unsafe { xmlStrdup(pubID) };
    q = ret;
    white = 0 as i32;
    p = pubID;
    while (unsafe { *p }) as i32 != 0 as i32 {
        if (unsafe { *p }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *p }) as i32 && (unsafe { *p }) as i32 <= 0xa as i32
            || (unsafe { *p }) as i32 == 0xd as i32
        {
            if q != ret {
                white = 1 as i32;
            }
        } else {
            if white != 0 {
                let mut fresh36 = q;
                q = unsafe { q.offset(1) };
                (unsafe { *fresh36 = 0x20 as i32 as xmlChar });
                white = 0 as i32;
            }
            let mut fresh37 = q;
            q = unsafe { q.offset(1) };
            (unsafe { *fresh37 = *p });
        }
        p = unsafe { p.offset(1) };
    }
    (unsafe { *q = 0 as i32 as xmlChar });
    return ret;
}
extern "C" fn xmlGetXMLCatalogEntryType(mut name: *const u8) -> i32 {
    let mut type_0: i32 = XML_CATA_NONE;
    if (unsafe {
        xmlStrEqual(
            name,
            b"system\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = XML_CATA_SYSTEM;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"public\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = XML_CATA_PUBLIC;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"rewriteSystem\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = XML_CATA_REWRITE_SYSTEM;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"delegatePublic\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = XML_CATA_DELEGATE_PUBLIC;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"delegateSystem\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = XML_CATA_DELEGATE_SYSTEM;
    } else if (unsafe { xmlStrEqual(name, b"uri\0" as *const u8 as *const i8 as *const xmlChar) })
        != 0
    {
        type_0 = XML_CATA_URI;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"rewriteURI\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = XML_CATA_REWRITE_URI;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"delegateURI\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = XML_CATA_DELEGATE_URI;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"nextCatalog\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = XML_CATA_NEXT_CATALOG;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"catalog\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = XML_CATA_CATALOG;
    }
    return type_0;
}
extern "C" fn xmlParseXMLCatalogOneNode(
    mut cur: *mut crate::src::HTMLparser::_xmlNode,
    mut type_0: i32,
    mut name: *const u8,
    mut attrName: *const u8,
    mut uriAttrName: *const u8,
    mut prefer: u32,
    mut cgroup: *mut crate::src::catalog::_xmlCatalogEntry,
) -> *mut crate::src::catalog::_xmlCatalogEntry {
    let mut ok: i32 = 1 as i32;
    let mut uriValue: *mut u8 = 0 as *mut xmlChar;
    let mut nameValue: *mut u8 = 0 as *mut xmlChar;
    let mut base: *mut u8 = 0 as *mut xmlChar;
    let mut URL: *mut u8 = 0 as *mut xmlChar;
    let mut ret: *mut crate::src::catalog::_xmlCatalogEntry = 0 as xmlCatalogEntryPtr;
    if !attrName.is_null() {
        nameValue = unsafe { xmlGetProp(cur as *const xmlNode, attrName) };
        if nameValue.is_null() {
            xmlCatalogErr(
                ret,
                cur,
                XML_CATALOG_MISSING_ATTR as i32,
                b"%s entry lacks '%s'\n\0" as *const u8 as *const i8,
                name,
                attrName,
                0 as *const xmlChar,
            );
            ok = 0 as i32;
        }
    }
    uriValue = unsafe { xmlGetProp(cur as *const xmlNode, uriAttrName) };
    if uriValue.is_null() {
        xmlCatalogErr(
            ret,
            cur,
            XML_CATALOG_MISSING_ATTR as i32,
            b"%s entry lacks '%s'\n\0" as *const u8 as *const i8,
            name,
            uriAttrName,
            0 as *const xmlChar,
        );
        ok = 0 as i32;
    }
    if ok == 0 {
        if !nameValue.is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")(nameValue as *mut libc::c_void)
            });
        }
        if !uriValue.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(uriValue as *mut libc::c_void) });
        }
        return 0 as xmlCatalogEntryPtr;
    }
    base = unsafe { xmlNodeGetBase((*cur).doc, cur as *const xmlNode) };
    URL = unsafe { xmlBuildURI(uriValue, base) };
    if !URL.is_null() {
        if (unsafe { xmlDebugCatalogs }) > 1 as i32 {
            if !nameValue.is_null() {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"Found %s: '%s' '%s'\n\0" as *const u8 as *const i8,
                        name,
                        nameValue,
                        URL,
                    )
                });
            } else {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"Found %s: '%s'\n\0" as *const u8 as *const i8,
                        name,
                        URL,
                    )
                });
            }
        }
        ret = xmlNewCatalogEntry(type_0, nameValue, uriValue, URL, prefer, cgroup);
    } else {
        xmlCatalogErr(
            ret,
            cur,
            XML_CATALOG_ENTRY_BROKEN as i32,
            b"%s entry '%s' broken ?: %s\n\0" as *const u8 as *const i8,
            name,
            uriAttrName,
            uriValue,
        );
    }
    if !nameValue.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(nameValue as *mut libc::c_void) });
    }
    if !uriValue.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(uriValue as *mut libc::c_void) });
    }
    if !base.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(base as *mut libc::c_void) });
    }
    if !URL.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
    }
    return ret;
}
extern "C" fn xmlParseXMLCatalogNode(
    mut cur: *mut crate::src::HTMLparser::_xmlNode,
    mut prefer: u32,
    mut parent: *mut crate::src::catalog::_xmlCatalogEntry,
    mut cgroup: *mut crate::src::catalog::_xmlCatalogEntry,
) {
    let mut base: *mut u8 = 0 as *mut xmlChar;
    let mut entry: *mut crate::src::catalog::_xmlCatalogEntry = 0 as xmlCatalogEntryPtr;
    if cur.is_null() {
        return;
    }
    if (unsafe {
        xmlStrEqual(
            (*cur).name,
            b"group\0" as *const u8 as *const i8 as *mut xmlChar,
        )
    }) != 0
    {
        let mut prop: *mut u8 = 0 as *mut xmlChar;
        let mut pref: u32 = XML_CATA_PREFER_NONE;
        prop = unsafe {
            xmlGetProp(
                cur as *const xmlNode,
                b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
            )
        };
        if !prop.is_null() {
            if (unsafe { xmlStrEqual(prop, b"system\0" as *const u8 as *const i8 as *mut xmlChar) })
                != 0
            {
                prefer = XML_CATA_PREFER_SYSTEM;
            } else if (unsafe {
                xmlStrEqual(prop, b"public\0" as *const u8 as *const i8 as *mut xmlChar)
            }) != 0
            {
                prefer = XML_CATA_PREFER_PUBLIC;
            } else {
                xmlCatalogErr(
                    parent,
                    cur,
                    XML_CATALOG_PREFER_VALUE as i32,
                    b"Invalid value for prefer: '%s'\n\0" as *const u8 as *const i8,
                    prop,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
            }
            (unsafe { xmlFree.expect("non-null function pointer")(prop as *mut libc::c_void) });
            pref = prefer;
        }
        prop = unsafe {
            xmlGetProp(
                cur as *const xmlNode,
                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
            )
        };
        base = unsafe {
            xmlGetNsProp(
                cur as *const xmlNode,
                b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                    as *const xmlChar,
            )
        };
        entry = xmlNewCatalogEntry(
            XML_CATA_GROUP,
            prop,
            base,
            0 as *const xmlChar,
            pref,
            cgroup,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(prop as *mut libc::c_void) });
    } else if (unsafe {
        xmlStrEqual(
            (*cur).name,
            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
        )
    }) != 0
    {
        entry = xmlParseXMLCatalogOneNode(
            cur,
            XML_CATA_PUBLIC,
            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
            b"publicId\0" as *const u8 as *const i8 as *mut xmlChar,
            b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
            prefer,
            cgroup,
        );
    } else if (unsafe {
        xmlStrEqual(
            (*cur).name,
            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
        )
    }) != 0
    {
        entry = xmlParseXMLCatalogOneNode(
            cur,
            XML_CATA_SYSTEM,
            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
            b"systemId\0" as *const u8 as *const i8 as *mut xmlChar,
            b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
            prefer,
            cgroup,
        );
    } else if (unsafe {
        xmlStrEqual(
            (*cur).name,
            b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
        )
    }) != 0
    {
        entry = xmlParseXMLCatalogOneNode(
            cur,
            XML_CATA_REWRITE_SYSTEM,
            b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
            b"systemIdStartString\0" as *const u8 as *const i8 as *mut xmlChar,
            b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
            prefer,
            cgroup,
        );
    } else if (unsafe {
        xmlStrEqual(
            (*cur).name,
            b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
        )
    }) != 0
    {
        entry = xmlParseXMLCatalogOneNode(
            cur,
            XML_CATA_DELEGATE_PUBLIC,
            b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
            b"publicIdStartString\0" as *const u8 as *const i8 as *mut xmlChar,
            b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
            prefer,
            cgroup,
        );
    } else if (unsafe {
        xmlStrEqual(
            (*cur).name,
            b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
        )
    }) != 0
    {
        entry = xmlParseXMLCatalogOneNode(
            cur,
            XML_CATA_DELEGATE_SYSTEM,
            b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
            b"systemIdStartString\0" as *const u8 as *const i8 as *mut xmlChar,
            b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
            prefer,
            cgroup,
        );
    } else if (unsafe {
        xmlStrEqual(
            (*cur).name,
            b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
        )
    }) != 0
    {
        entry = xmlParseXMLCatalogOneNode(
            cur,
            XML_CATA_URI,
            b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
            b"name\0" as *const u8 as *const i8 as *mut xmlChar,
            b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
            prefer,
            cgroup,
        );
    } else if (unsafe {
        xmlStrEqual(
            (*cur).name,
            b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
        )
    }) != 0
    {
        entry = xmlParseXMLCatalogOneNode(
            cur,
            XML_CATA_REWRITE_URI,
            b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
            b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
            b"rewritePrefix\0" as *const u8 as *const i8 as *mut xmlChar,
            prefer,
            cgroup,
        );
    } else if (unsafe {
        xmlStrEqual(
            (*cur).name,
            b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
        )
    }) != 0
    {
        entry = xmlParseXMLCatalogOneNode(
            cur,
            XML_CATA_DELEGATE_URI,
            b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
            b"uriStartString\0" as *const u8 as *const i8 as *mut xmlChar,
            b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
            prefer,
            cgroup,
        );
    } else if (unsafe {
        xmlStrEqual(
            (*cur).name,
            b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
        )
    }) != 0
    {
        entry = xmlParseXMLCatalogOneNode(
            cur,
            XML_CATA_NEXT_CATALOG,
            b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
            0 as *const xmlChar,
            b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
            prefer,
            cgroup,
        );
    }
    if !entry.is_null() {
        if !parent.is_null() {
            let fresh38 = unsafe { &mut ((*entry).parent) };
            *fresh38 = parent;
            if (unsafe { (*parent).children }).is_null() {
                let fresh39 = unsafe { &mut ((*parent).children) };
                *fresh39 = entry;
            } else {
                let mut prev: *mut crate::src::catalog::_xmlCatalogEntry =
                    0 as *mut xmlCatalogEntry;
                prev = unsafe { (*parent).children };
                while !(unsafe { (*prev).next }).is_null() {
                    prev = unsafe { (*prev).next };
                }
                let fresh40 = unsafe { &mut ((*prev).next) };
                *fresh40 = entry;
            }
        }
        if (unsafe { (*entry).type_0 }) as i32 == XML_CATA_GROUP as i32 {
            xmlParseXMLCatalogNodeList(unsafe { (*cur).children }, prefer, parent, entry);
        }
    }
    if !base.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(base as *mut libc::c_void) });
    }
}
extern "C" fn xmlParseXMLCatalogNodeList(
    mut cur: *mut crate::src::HTMLparser::_xmlNode,
    mut prefer: u32,
    mut parent: *mut crate::src::catalog::_xmlCatalogEntry,
    mut cgroup: *mut crate::src::catalog::_xmlCatalogEntry,
) {
    while !cur.is_null() {
        if !(unsafe { (*cur).ns }).is_null()
            && !(unsafe { (*(*cur).ns).href }).is_null()
            && (unsafe {
                xmlStrEqual(
                    (*(*cur).ns).href,
                    b"urn:oasis:names:tc:entity:xmlns:xml:catalog\0" as *const u8 as *const i8
                        as *const xmlChar,
                )
            }) != 0
        {
            xmlParseXMLCatalogNode(cur, prefer, parent, cgroup);
        }
        cur = unsafe { (*cur).next };
    }
}
extern "C" fn xmlParseXMLCatalogFile(
    mut prefer: u32,
    mut filename: *const u8,
) -> *mut crate::src::catalog::_xmlCatalogEntry {
    let mut doc: *mut crate::src::HTMLparser::_xmlDoc = 0 as *mut xmlDoc;
    let mut cur: *mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    let mut prop: *mut u8 = 0 as *mut xmlChar;
    let mut parent: *mut crate::src::catalog::_xmlCatalogEntry = 0 as xmlCatalogEntryPtr;
    if filename.is_null() {
        return 0 as xmlCatalogEntryPtr;
    }
    doc = xmlParseCatalogFile(filename as *const i8);
    if doc.is_null() {
        if (unsafe { xmlDebugCatalogs }) != 0 {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"Failed to parse catalog %s\n\0" as *const u8 as *const i8,
                    filename,
                )
            });
        }
        return 0 as xmlCatalogEntryPtr;
    }
    if (unsafe { xmlDebugCatalogs }) != 0 {
        (unsafe {
            (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                *(__xmlGenericErrorContext()).unwrap(),
                b"%d Parsing catalog %s\n\0" as *const u8 as *const i8,
                xmlGetThreadId(),
                filename,
            )
        });
    }
    cur = unsafe { xmlDocGetRootElement(doc as *const xmlDoc) };
    if !cur.is_null()
        && (unsafe {
            xmlStrEqual(
                (*cur).name,
                b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
            )
        }) != 0
        && !(unsafe { (*cur).ns }).is_null()
        && !(unsafe { (*(*cur).ns).href }).is_null()
        && (unsafe {
            xmlStrEqual(
                (*(*cur).ns).href,
                b"urn:oasis:names:tc:entity:xmlns:xml:catalog\0" as *const u8 as *const i8
                    as *const xmlChar,
            )
        }) != 0
    {
        parent = xmlNewCatalogEntry(
            XML_CATA_CATALOG,
            0 as *const xmlChar,
            filename,
            0 as *const xmlChar,
            prefer,
            0 as xmlCatalogEntryPtr,
        );
        if parent.is_null() {
            (unsafe { xmlFreeDoc(doc) });
            return 0 as xmlCatalogEntryPtr;
        }
        prop = unsafe {
            xmlGetProp(
                cur as *const xmlNode,
                b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
            )
        };
        if !prop.is_null() {
            if (unsafe { xmlStrEqual(prop, b"system\0" as *const u8 as *const i8 as *mut xmlChar) })
                != 0
            {
                prefer = XML_CATA_PREFER_SYSTEM;
            } else if (unsafe {
                xmlStrEqual(prop, b"public\0" as *const u8 as *const i8 as *mut xmlChar)
            }) != 0
            {
                prefer = XML_CATA_PREFER_PUBLIC;
            } else {
                xmlCatalogErr(
                    0 as xmlCatalogEntryPtr,
                    cur,
                    XML_CATALOG_PREFER_VALUE as i32,
                    b"Invalid value for prefer: '%s'\n\0" as *const u8 as *const i8,
                    prop,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
            }
            (unsafe { xmlFree.expect("non-null function pointer")(prop as *mut libc::c_void) });
        }
        cur = unsafe { (*cur).children };
        xmlParseXMLCatalogNodeList(cur, prefer, parent, 0 as xmlCatalogEntryPtr);
    } else {
        xmlCatalogErr(
            0 as xmlCatalogEntryPtr,
            doc as xmlNodePtr,
            XML_CATALOG_NOT_CATALOG as i32,
            b"File %s is not an XML Catalog\n\0" as *const u8 as *const i8,
            filename,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        (unsafe { xmlFreeDoc(doc) });
        return 0 as xmlCatalogEntryPtr;
    }
    (unsafe { xmlFreeDoc(doc) });
    return parent;
}
extern "C" fn xmlFetchXMLCatalogFile(mut catal: *mut crate::src::catalog::_xmlCatalogEntry) -> i32 {
    let mut doc: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    if catal.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*catal).URL }).is_null() {
        return -(1 as i32);
    }
    (unsafe { xmlRMutexLock(xmlCatalogMutex) });
    if !(unsafe { (*catal).children }).is_null() {
        (unsafe { xmlRMutexUnlock(xmlCatalogMutex) });
        return 0 as i32;
    }
    if !(unsafe { xmlCatalogXMLFiles }).is_null() {
        doc = xmlHashLookup(unsafe { xmlCatalogXMLFiles }, unsafe { (*catal).URL })
            as xmlCatalogEntryPtr;
        if !doc.is_null() {
            if (unsafe { xmlDebugCatalogs }) != 0 {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"Found %s in file hash\n\0" as *const u8 as *const i8,
                        (*catal).URL,
                    )
                });
            }
            if (unsafe { (*catal).type_0 }) as i32 == XML_CATA_CATALOG as i32 {
                let fresh41 = unsafe { &mut ((*catal).children) };
                *fresh41 = unsafe { (*doc).children };
            } else {
                let fresh42 = unsafe { &mut ((*catal).children) };
                *fresh42 = doc;
            }
            (unsafe { (*catal).dealloc = 0 as i32 });
            (unsafe { xmlRMutexUnlock(xmlCatalogMutex) });
            return 0 as i32;
        }
        if (unsafe { xmlDebugCatalogs }) != 0 {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"%s not found in file hash\n\0" as *const u8 as *const i8,
                    (*catal).URL,
                )
            });
        }
    }
    doc = xmlParseXMLCatalogFile(unsafe { (*catal).prefer }, unsafe { (*catal).URL });
    if doc.is_null() {
        (unsafe { (*catal).type_0 = XML_CATA_BROKEN_CATALOG });
        (unsafe { xmlRMutexUnlock(xmlCatalogMutex) });
        return -(1 as i32);
    }
    if (unsafe { (*catal).type_0 }) as i32 == XML_CATA_CATALOG as i32 {
        let fresh43 = unsafe { &mut ((*catal).children) };
        *fresh43 = unsafe { (*doc).children };
    } else {
        let fresh44 = unsafe { &mut ((*catal).children) };
        *fresh44 = doc;
    }
    (unsafe { (*doc).dealloc = 1 as i32 });
    if (unsafe { xmlCatalogXMLFiles }).is_null() {
        (unsafe { xmlCatalogXMLFiles = xmlHashCreate(10 as i32) });
    }
    if !(unsafe { xmlCatalogXMLFiles }).is_null() {
        if (unsafe { xmlDebugCatalogs }) != 0 {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"%s added to file hash\n\0" as *const u8 as *const i8,
                    (*catal).URL,
                )
            });
        }
        xmlHashAddEntry(
            unsafe { xmlCatalogXMLFiles },
            unsafe { (*catal).URL },
            doc as *mut libc::c_void,
        );
    }
    (unsafe { xmlRMutexUnlock(xmlCatalogMutex) });
    return 0 as i32;
}
extern "C" fn xmlAddXMLCatalog(
    mut catal: *mut crate::src::catalog::_xmlCatalogEntry,
    mut type_0: *const u8,
    mut orig: *const u8,
    mut replace: *const u8,
) -> i32 {
    let mut cur: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    let mut typ: i32 = XML_CATA_NONE;
    let mut doregister: i32 = 0 as i32;
    if catal.is_null()
        || (unsafe { (*catal).type_0 }) as i32 != XML_CATA_CATALOG as i32
            && (unsafe { (*catal).type_0 }) as i32 != XML_CATA_BROKEN_CATALOG as i32
    {
        return -(1 as i32);
    }
    if (unsafe { (*catal).children }).is_null() {
        xmlFetchXMLCatalogFile(catal);
    }
    if (unsafe { (*catal).children }).is_null() {
        doregister = 1 as i32;
    }
    typ = xmlGetXMLCatalogEntryType(type_0);
    if typ as i32 == XML_CATA_NONE as i32 {
        if (unsafe { xmlDebugCatalogs }) != 0 {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"Failed to add unknown element %s to catalog\n\0" as *const u8 as *const i8,
                    type_0,
                )
            });
        }
        return -(1 as i32);
    }
    cur = unsafe { (*catal).children };
    if !cur.is_null() {
        while !cur.is_null() {
            if !orig.is_null()
                && (unsafe { (*cur).type_0 }) as i32 == typ as i32
                && (unsafe { xmlStrEqual(orig, (*cur).name) }) != 0
            {
                if (unsafe { xmlDebugCatalogs }) != 0 {
                    (unsafe {
                        (*(borrow(&__xmlGenericError())).unwrap())
                            .expect("non-null function pointer")(
                            *(__xmlGenericErrorContext()).unwrap(),
                            b"Updating element %s to catalog\n\0" as *const u8 as *const i8,
                            type_0,
                        )
                    });
                }
                if !(unsafe { (*cur).value }).is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(
                            (*cur).value as *mut libc::c_void,
                        )
                    });
                }
                if !(unsafe { (*cur).URL }).is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")((*cur).URL as *mut libc::c_void)
                    });
                }
                let fresh45 = unsafe { &mut ((*cur).value) };
                *fresh45 = unsafe { xmlStrdup(replace) };
                let fresh46 = unsafe { &mut ((*cur).URL) };
                *fresh46 = unsafe { xmlStrdup(replace) };
                return 0 as i32;
            }
            if (unsafe { (*cur).next }).is_null() {
                break;
            }
            cur = unsafe { (*cur).next };
        }
    }
    if (unsafe { xmlDebugCatalogs }) != 0 {
        (unsafe {
            (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                *(__xmlGenericErrorContext()).unwrap(),
                b"Adding element %s to catalog\n\0" as *const u8 as *const i8,
                type_0,
            )
        });
    }
    if cur.is_null() {
        let fresh47 = unsafe { &mut ((*catal).children) };
        *fresh47 = xmlNewCatalogEntry(
            typ,
            orig,
            replace,
            0 as *const xmlChar,
            unsafe { (*catal).prefer },
            0 as xmlCatalogEntryPtr,
        );
    } else {
        let fresh48 = unsafe { &mut ((*cur).next) };
        *fresh48 = xmlNewCatalogEntry(
            typ,
            orig,
            replace,
            0 as *const xmlChar,
            unsafe { (*catal).prefer },
            0 as xmlCatalogEntryPtr,
        );
    }
    if doregister != 0 {
        (unsafe { (*catal).type_0 = XML_CATA_CATALOG });
        cur = xmlHashLookup(unsafe { xmlCatalogXMLFiles }, unsafe { (*catal).URL })
            as xmlCatalogEntryPtr;
        if !cur.is_null() {
            let fresh49 = unsafe { &mut ((*cur).children) };
            *fresh49 = unsafe { (*catal).children };
        }
    }
    return 0 as i32;
}
extern "C" fn xmlDelXMLCatalog(
    mut catal: *mut crate::src::catalog::_xmlCatalogEntry,
    mut value: *const u8,
) -> i32 {
    let mut cur: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    let mut ret: i32 = 0 as i32;
    if catal.is_null()
        || (unsafe { (*catal).type_0 }) as i32 != XML_CATA_CATALOG as i32
            && (unsafe { (*catal).type_0 }) as i32 != XML_CATA_BROKEN_CATALOG as i32
    {
        return -(1 as i32);
    }
    if value.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*catal).children }).is_null() {
        xmlFetchXMLCatalogFile(catal);
    }
    cur = unsafe { (*catal).children };
    while !cur.is_null() {
        if !(unsafe { (*cur).name }).is_null()
            && (unsafe { xmlStrEqual(value, (*cur).name) }) != 0
            || (unsafe { xmlStrEqual(value, (*cur).value) }) != 0
        {
            if (unsafe { xmlDebugCatalogs }) != 0 {
                if !(unsafe { (*cur).name }).is_null() {
                    (unsafe {
                        (*(borrow(&__xmlGenericError())).unwrap())
                            .expect("non-null function pointer")(
                            *(__xmlGenericErrorContext()).unwrap(),
                            b"Removing element %s from catalog\n\0" as *const u8 as *const i8,
                            (*cur).name,
                        )
                    });
                } else {
                    (unsafe {
                        (*(borrow(&__xmlGenericError())).unwrap())
                            .expect("non-null function pointer")(
                            *(__xmlGenericErrorContext()).unwrap(),
                            b"Removing element %s from catalog\n\0" as *const u8 as *const i8,
                            (*cur).value,
                        )
                    });
                }
            }
            (unsafe { (*cur).type_0 = XML_CATA_REMOVED });
        }
        cur = unsafe { (*cur).next };
    }
    return ret;
}
extern "C" fn xmlCatalogXMLResolve(
    mut catal: *mut crate::src::catalog::_xmlCatalogEntry,
    mut pubID: *const u8,
    mut sysID: *const u8,
) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    let mut cur: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    let mut haveDelegate: i32 = 0 as i32;
    let mut haveNext: i32 = 0 as i32;
    if (unsafe { (*catal).depth }) > 50 as i32 {
        xmlCatalogErr(
            catal,
            0 as xmlNodePtr,
            XML_CATALOG_RECURSION as i32,
            b"Detected recursion in catalog %s\n\0" as *const u8 as *const i8,
            unsafe { (*catal).name },
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as *mut xmlChar;
    }
    let fresh50 = unsafe { &mut ((*catal).depth) };
    *fresh50 += 1;
    if !sysID.is_null() {
        let mut rewrite: *mut crate::src::catalog::_xmlCatalogEntry = 0 as xmlCatalogEntryPtr;
        let mut lenrewrite: i32 = 0 as i32;
        let mut len: i32 = 0;
        cur = catal;
        haveDelegate = 0 as i32;
        while !cur.is_null() {
            match (unsafe { (*cur).type_0 }) as i32 {
                6 => {
                    if (unsafe { xmlStrEqual(sysID, (*cur).name) }) != 0 {
                        if (unsafe { xmlDebugCatalogs }) != 0 {
                            (unsafe {
                                (*(borrow(&__xmlGenericError())).unwrap())
                                    .expect("non-null function pointer")(
                                    *(__xmlGenericErrorContext()).unwrap(),
                                    b"Found system match %s, using %s\n\0" as *const u8
                                        as *const i8,
                                    (*cur).name,
                                    (*cur).URL,
                                )
                            });
                        }
                        let fresh51 = unsafe { &mut ((*catal).depth) };
                        *fresh51 -= 1;
                        return unsafe { xmlStrdup((*cur).URL) };
                    }
                }
                7 => {
                    len = unsafe { xmlStrlen((*cur).name) };
                    if len > lenrewrite && (unsafe { xmlStrncmp(sysID, (*cur).name, len) }) == 0 {
                        lenrewrite = len;
                        rewrite = cur;
                    }
                }
                9 => {
                    if (unsafe { xmlStrncmp(sysID, (*cur).name, xmlStrlen((*cur).name)) }) == 0 {
                        haveDelegate += 1;
                    }
                }
                3 => {
                    haveNext += 1;
                }
                _ => {}
            }
            cur = unsafe { (*cur).next };
        }
        if !rewrite.is_null() {
            if (unsafe { xmlDebugCatalogs }) != 0 {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"Using rewriting rule %s\n\0" as *const u8 as *const i8,
                        (*rewrite).name,
                    )
                });
            }
            ret = unsafe { xmlStrdup((*rewrite).URL) };
            if !ret.is_null() {
                ret = unsafe { xmlStrcat(ret, &*sysID.offset(lenrewrite as isize)) };
            }
            let fresh52 = unsafe { &mut ((*catal).depth) };
            *fresh52 -= 1;
            return ret;
        }
        if haveDelegate != 0 {
            let mut delegates: [*const u8; 50] = [0 as *const xmlChar; 50];
            let mut nbList: i32 = 0 as i32;
            let mut i: i32 = 0;
            cur = catal;
            while !cur.is_null() {
                if (unsafe { (*cur).type_0 }) as i32 == XML_CATA_DELEGATE_SYSTEM as i32
                    && (unsafe { xmlStrncmp(sysID, (*cur).name, xmlStrlen((*cur).name)) }) == 0
                {
                    i = 0 as i32;
                    while i < nbList {
                        if (unsafe { xmlStrEqual((*cur).URL, delegates[i as usize]) }) != 0 {
                            break;
                        }
                        i += 1;
                    }
                    if i < nbList {
                        cur = unsafe { (*cur).next };
                        continue;
                    } else {
                        if nbList < 50 as i32 {
                            let mut fresh53 = nbList;
                            nbList = nbList + 1;
                            delegates[fresh53 as usize] = unsafe { (*cur).URL as *const u8 };
                        }
                        if (unsafe { (*cur).children }).is_null() {
                            xmlFetchXMLCatalogFile(cur);
                        }
                        if !(unsafe { (*cur).children }).is_null() {
                            if (unsafe { xmlDebugCatalogs }) != 0 {
                                (unsafe {
                                    (*(borrow(&__xmlGenericError())).unwrap())
                                        .expect("non-null function pointer")(
                                        *(__xmlGenericErrorContext()).unwrap(),
                                        b"Trying system delegate %s\n\0" as *const u8 as *const i8,
                                        (*cur).URL,
                                    )
                                });
                            }
                            ret = xmlCatalogListXMLResolve(
                                unsafe { (*cur).children },
                                0 as *const xmlChar,
                                sysID,
                            );
                            if !ret.is_null() {
                                let fresh54 = unsafe { &mut ((*catal).depth) };
                                *fresh54 -= 1;
                                return ret;
                            }
                        }
                    }
                }
                cur = unsafe { (*cur).next };
            }
            let fresh55 = unsafe { &mut ((*catal).depth) };
            *fresh55 -= 1;
            return -(1 as i32) as *mut xmlChar;
        }
    }
    if !pubID.is_null() {
        cur = catal;
        haveDelegate = 0 as i32;
        while !cur.is_null() {
            match (unsafe { (*cur).type_0 }) as i32 {
                5 => {
                    if (unsafe { xmlStrEqual(pubID, (*cur).name) }) != 0 {
                        if (unsafe { xmlDebugCatalogs }) != 0 {
                            (unsafe {
                                (*(borrow(&__xmlGenericError())).unwrap())
                                    .expect("non-null function pointer")(
                                    *(__xmlGenericErrorContext()).unwrap(),
                                    b"Found public match %s\n\0" as *const u8 as *const i8,
                                    (*cur).name,
                                )
                            });
                        }
                        let fresh56 = unsafe { &mut ((*catal).depth) };
                        *fresh56 -= 1;
                        return unsafe { xmlStrdup((*cur).URL) };
                    }
                }
                8 => {
                    if (unsafe { xmlStrncmp(pubID, (*cur).name, xmlStrlen((*cur).name)) }) == 0
                        && (unsafe { (*cur).prefer }) as u32 == XML_CATA_PREFER_PUBLIC as i32 as u32
                    {
                        haveDelegate += 1;
                    }
                }
                3 => {
                    if sysID.is_null() {
                        haveNext += 1;
                    }
                }
                _ => {}
            }
            cur = unsafe { (*cur).next };
        }
        if haveDelegate != 0 {
            let mut delegates_0: [*const u8; 50] = [0 as *const xmlChar; 50];
            let mut nbList_0: i32 = 0 as i32;
            let mut i_0: i32 = 0;
            cur = catal;
            while !cur.is_null() {
                if (unsafe { (*cur).type_0 }) as i32 == XML_CATA_DELEGATE_PUBLIC as i32
                    && (unsafe { (*cur).prefer }) as u32 == XML_CATA_PREFER_PUBLIC as i32 as u32
                    && (unsafe { xmlStrncmp(pubID, (*cur).name, xmlStrlen((*cur).name)) }) == 0
                {
                    i_0 = 0 as i32;
                    while i_0 < nbList_0 {
                        if (unsafe { xmlStrEqual((*cur).URL, delegates_0[i_0 as usize]) }) != 0 {
                            break;
                        }
                        i_0 += 1;
                    }
                    if i_0 < nbList_0 {
                        cur = unsafe { (*cur).next };
                        continue;
                    } else {
                        if nbList_0 < 50 as i32 {
                            let mut fresh57 = nbList_0;
                            nbList_0 = nbList_0 + 1;
                            delegates_0[fresh57 as usize] = unsafe { (*cur).URL as *const u8 };
                        }
                        if (unsafe { (*cur).children }).is_null() {
                            xmlFetchXMLCatalogFile(cur);
                        }
                        if !(unsafe { (*cur).children }).is_null() {
                            if (unsafe { xmlDebugCatalogs }) != 0 {
                                (unsafe {
                                    (*(borrow(&__xmlGenericError())).unwrap())
                                        .expect("non-null function pointer")(
                                        *(__xmlGenericErrorContext()).unwrap(),
                                        b"Trying public delegate %s\n\0" as *const u8 as *const i8,
                                        (*cur).URL,
                                    )
                                });
                            }
                            ret = xmlCatalogListXMLResolve(
                                unsafe { (*cur).children },
                                pubID,
                                0 as *const xmlChar,
                            );
                            if !ret.is_null() {
                                let fresh58 = unsafe { &mut ((*catal).depth) };
                                *fresh58 -= 1;
                                return ret;
                            }
                        }
                    }
                }
                cur = unsafe { (*cur).next };
            }
            let fresh59 = unsafe { &mut ((*catal).depth) };
            *fresh59 -= 1;
            return -(1 as i32) as *mut xmlChar;
        }
    }
    if haveNext != 0 {
        cur = catal;
        while !cur.is_null() {
            if (unsafe { (*cur).type_0 }) as i32 == XML_CATA_NEXT_CATALOG as i32 {
                if (unsafe { (*cur).children }).is_null() {
                    xmlFetchXMLCatalogFile(cur);
                }
                if !(unsafe { (*cur).children }).is_null() {
                    ret = xmlCatalogListXMLResolve(unsafe { (*cur).children }, pubID, sysID);
                    if !ret.is_null() {
                        let fresh60 = unsafe { &mut ((*catal).depth) };
                        *fresh60 -= 1;
                        return ret;
                    } else {
                        if (unsafe { (*catal).depth }) > 50 as i32 {
                            return 0 as *mut xmlChar;
                        }
                    }
                }
            }
            cur = unsafe { (*cur).next };
        }
    }
    let fresh61 = unsafe { &mut ((*catal).depth) };
    *fresh61 -= 1;
    return 0 as *mut xmlChar;
}
extern "C" fn xmlCatalogXMLResolveURI(
    mut catal: *mut crate::src::catalog::_xmlCatalogEntry,
    mut URI: *const u8,
) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    let mut cur: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    let mut haveDelegate: i32 = 0 as i32;
    let mut haveNext: i32 = 0 as i32;
    let mut rewrite: *mut crate::src::catalog::_xmlCatalogEntry = 0 as xmlCatalogEntryPtr;
    let mut lenrewrite: i32 = 0 as i32;
    let mut len: i32 = 0;
    if catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if URI.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { (*catal).depth }) > 50 as i32 {
        xmlCatalogErr(
            catal,
            0 as xmlNodePtr,
            XML_CATALOG_RECURSION as i32,
            b"Detected recursion in catalog %s\n\0" as *const u8 as *const i8,
            unsafe { (*catal).name },
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as *mut xmlChar;
    }
    cur = catal;
    haveDelegate = 0 as i32;
    while !cur.is_null() {
        match (unsafe { (*cur).type_0 }) as i32 {
            10 => {
                if (unsafe { xmlStrEqual(URI, (*cur).name) }) != 0 {
                    if (unsafe { xmlDebugCatalogs }) != 0 {
                        (unsafe {
                            (*(borrow(&__xmlGenericError())).unwrap())
                                .expect("non-null function pointer")(
                                *(__xmlGenericErrorContext()).unwrap(),
                                b"Found URI match %s\n\0" as *const u8 as *const i8,
                                (*cur).name,
                            )
                        });
                    }
                    return unsafe { xmlStrdup((*cur).URL) };
                }
            }
            11 => {
                len = unsafe { xmlStrlen((*cur).name) };
                if len > lenrewrite && (unsafe { xmlStrncmp(URI, (*cur).name, len) }) == 0 {
                    lenrewrite = len;
                    rewrite = cur;
                }
            }
            12 => {
                if (unsafe { xmlStrncmp(URI, (*cur).name, xmlStrlen((*cur).name)) }) == 0 {
                    haveDelegate += 1;
                }
            }
            3 => {
                haveNext += 1;
            }
            _ => {}
        }
        cur = unsafe { (*cur).next };
    }
    if !rewrite.is_null() {
        if (unsafe { xmlDebugCatalogs }) != 0 {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"Using rewriting rule %s\n\0" as *const u8 as *const i8,
                    (*rewrite).name,
                )
            });
        }
        ret = unsafe { xmlStrdup((*rewrite).URL) };
        if !ret.is_null() {
            ret = unsafe { xmlStrcat(ret, &*URI.offset(lenrewrite as isize)) };
        }
        return ret;
    }
    if haveDelegate != 0 {
        let mut delegates: [*const u8; 50] = [0 as *const xmlChar; 50];
        let mut nbList: i32 = 0 as i32;
        let mut i: i32 = 0;
        cur = catal;
        while !cur.is_null() {
            if ((unsafe { (*cur).type_0 }) as i32 == XML_CATA_DELEGATE_SYSTEM as i32
                || (unsafe { (*cur).type_0 }) as i32 == XML_CATA_DELEGATE_URI as i32)
                && (unsafe { xmlStrncmp(URI, (*cur).name, xmlStrlen((*cur).name)) }) == 0
            {
                i = 0 as i32;
                while i < nbList {
                    if (unsafe { xmlStrEqual((*cur).URL, delegates[i as usize]) }) != 0 {
                        break;
                    }
                    i += 1;
                }
                if i < nbList {
                    cur = unsafe { (*cur).next };
                    continue;
                } else {
                    if nbList < 50 as i32 {
                        let mut fresh62 = nbList;
                        nbList = nbList + 1;
                        delegates[fresh62 as usize] = unsafe { (*cur).URL as *const u8 };
                    }
                    if (unsafe { (*cur).children }).is_null() {
                        xmlFetchXMLCatalogFile(cur);
                    }
                    if !(unsafe { (*cur).children }).is_null() {
                        if (unsafe { xmlDebugCatalogs }) != 0 {
                            (unsafe {
                                (*(borrow(&__xmlGenericError())).unwrap())
                                    .expect("non-null function pointer")(
                                    *(__xmlGenericErrorContext()).unwrap(),
                                    b"Trying URI delegate %s\n\0" as *const u8 as *const i8,
                                    (*cur).URL,
                                )
                            });
                        }
                        ret = xmlCatalogListXMLResolveURI(unsafe { (*cur).children }, URI);
                        if !ret.is_null() {
                            return ret;
                        }
                    }
                }
            }
            cur = unsafe { (*cur).next };
        }
        return -(1 as i32) as *mut xmlChar;
    }
    if haveNext != 0 {
        cur = catal;
        while !cur.is_null() {
            if (unsafe { (*cur).type_0 }) as i32 == XML_CATA_NEXT_CATALOG as i32 {
                if (unsafe { (*cur).children }).is_null() {
                    xmlFetchXMLCatalogFile(cur);
                }
                if !(unsafe { (*cur).children }).is_null() {
                    ret = xmlCatalogListXMLResolveURI(unsafe { (*cur).children }, URI);
                    if !ret.is_null() {
                        return ret;
                    }
                }
            }
            cur = unsafe { (*cur).next };
        }
    }
    return 0 as *mut xmlChar;
}
extern "C" fn xmlCatalogListXMLResolve(
    mut catal: *mut crate::src::catalog::_xmlCatalogEntry,
    mut pubID: *const u8,
    mut sysID: *const u8,
) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    let mut urnID: *mut u8 = 0 as *mut xmlChar;
    let mut normid: *mut u8 = 0 as *mut xmlChar;
    if catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if pubID.is_null() && sysID.is_null() {
        return 0 as *mut xmlChar;
    }
    normid = xmlCatalogNormalizePublic(pubID);
    if !normid.is_null() {
        pubID = if (unsafe { *normid }) as i32 != 0 as i32 {
            normid
        } else {
            0 as *mut xmlChar
        };
    }
    if (unsafe {
        xmlStrncmp(
            pubID,
            b"urn:publicid:\0" as *const u8 as *const i8 as *mut xmlChar,
            (::std::mem::size_of::<[i8; 14]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
        )
    }) == 0
    {
        urnID = xmlCatalogUnWrapURN(pubID);
        if (unsafe { xmlDebugCatalogs }) != 0 {
            if urnID.is_null() {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"Public URN ID %s expanded to NULL\n\0" as *const u8 as *const i8,
                        pubID,
                    )
                });
            } else {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"Public URN ID expanded to %s\n\0" as *const u8 as *const i8,
                        urnID,
                    )
                });
            }
        }
        ret = xmlCatalogListXMLResolve(catal, urnID, sysID);
        if !urnID.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(urnID as *mut libc::c_void) });
        }
        if !normid.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void) });
        }
        return ret;
    }
    if (unsafe {
        xmlStrncmp(
            sysID,
            b"urn:publicid:\0" as *const u8 as *const i8 as *mut xmlChar,
            (::std::mem::size_of::<[i8; 14]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
        )
    }) == 0
    {
        urnID = xmlCatalogUnWrapURN(sysID);
        if (unsafe { xmlDebugCatalogs }) != 0 {
            if urnID.is_null() {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"System URN ID %s expanded to NULL\n\0" as *const u8 as *const i8,
                        sysID,
                    )
                });
            } else {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"System URN ID expanded to %s\n\0" as *const u8 as *const i8,
                        urnID,
                    )
                });
            }
        }
        if pubID.is_null() {
            ret = xmlCatalogListXMLResolve(catal, urnID, 0 as *const xmlChar);
        } else if (unsafe { xmlStrEqual(pubID, urnID) }) != 0 {
            ret = xmlCatalogListXMLResolve(catal, pubID, 0 as *const xmlChar);
        } else {
            ret = xmlCatalogListXMLResolve(catal, pubID, urnID);
        }
        if !urnID.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(urnID as *mut libc::c_void) });
        }
        if !normid.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void) });
        }
        return ret;
    }
    while !catal.is_null() {
        if (unsafe { (*catal).type_0 }) as i32 == XML_CATA_CATALOG as i32 {
            if (unsafe { (*catal).children }).is_null() {
                xmlFetchXMLCatalogFile(catal);
            }
            if !(unsafe { (*catal).children }).is_null() {
                ret = xmlCatalogXMLResolve(unsafe { (*catal).children }, pubID, sysID);
                if !ret.is_null() {
                    break;
                }
                if (unsafe { (*(*catal).children).depth }) > 50 as i32 {
                    ret = 0 as *mut xmlChar;
                    break;
                }
            }
        }
        catal = unsafe { (*catal).next };
    }
    if !normid.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void) });
    }
    return ret;
}
extern "C" fn xmlCatalogListXMLResolveURI(
    mut catal: *mut crate::src::catalog::_xmlCatalogEntry,
    mut URI: *const u8,
) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    let mut urnID: *mut u8 = 0 as *mut xmlChar;
    if catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if URI.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe {
        xmlStrncmp(
            URI,
            b"urn:publicid:\0" as *const u8 as *const i8 as *mut xmlChar,
            (::std::mem::size_of::<[i8; 14]>() as u64).wrapping_sub(1 as i32 as u64) as i32,
        )
    }) == 0
    {
        urnID = xmlCatalogUnWrapURN(URI);
        if (unsafe { xmlDebugCatalogs }) != 0 {
            if urnID.is_null() {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"URN ID %s expanded to NULL\n\0" as *const u8 as *const i8,
                        URI,
                    )
                });
            } else {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"URN ID expanded to %s\n\0" as *const u8 as *const i8,
                        urnID,
                    )
                });
            }
        }
        ret = xmlCatalogListXMLResolve(catal, urnID, 0 as *const xmlChar);
        if !urnID.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(urnID as *mut libc::c_void) });
        }
        return ret;
    }
    while !catal.is_null() {
        if (unsafe { (*catal).type_0 }) as i32 == XML_CATA_CATALOG as i32 {
            if (unsafe { (*catal).children }).is_null() {
                xmlFetchXMLCatalogFile(catal);
            }
            if !(unsafe { (*catal).children }).is_null() {
                ret = xmlCatalogXMLResolveURI(unsafe { (*catal).children }, URI);
                if !ret.is_null() {
                    return ret;
                }
            }
        }
        catal = unsafe { (*catal).next };
    }
    return ret;
}
extern "C" fn xmlParseSGMLCatalogComment(mut cur: *const u8) -> *const u8 {
    if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 != '-' as i32
        || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 != '-' as i32
    {
        return cur;
    }
    cur = unsafe { cur.offset(2 as i32 as isize) };
    while (unsafe { *cur.offset(0 as i32 as isize) }) as i32 != 0 as i32
        && ((unsafe { *cur.offset(0 as i32 as isize) }) as i32 != '-' as i32
            || (unsafe { *cur.offset(1 as i32 as isize) }) as i32 != '-' as i32)
    {
        cur = unsafe { cur.offset(1) };
    }
    if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
        return 0 as *const xmlChar;
    }
    return unsafe { cur.offset(2 as i32 as isize) };
}
extern "C" fn xmlParseSGMLCatalogPubid<'a1>(
    mut cur: *const u8,
    mut id: Option<&'a1 mut *mut u8>,
) -> *const u8 {
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    let mut tmp: *mut u8 = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 50 as i32;
    let mut stop: u8 = 0;
    let mut count: i32 = 0 as i32;
    *(borrow_mut(&mut id)).unwrap() = 0 as *mut xmlChar;
    if (unsafe { *cur }) as i32 == '"' as i32 {
        cur = unsafe { cur.offset(1) };
        stop = '"' as i32 as xmlChar;
    } else if (unsafe { *cur }) as i32 == '\'' as i32 {
        cur = unsafe { cur.offset(1) };
        stop = '\'' as i32 as xmlChar;
    } else {
        stop = ' ' as i32 as xmlChar;
    }
    buf = (unsafe {
        xmlMallocAtomic.expect("non-null function pointer")(
            (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    }) as *mut xmlChar;
    if buf.is_null() {
        xmlCatalogErrMemory(b"allocating public ID\0" as *const u8 as *const i8);
        return 0 as *const xmlChar;
    }
    while (unsafe { xmlIsPubidChar_tab[*cur as usize] }) as i32 != 0
        || (unsafe { *cur }) as i32 == '?' as i32
    {
        if (unsafe { *cur }) as i32 == stop as i32 && stop as i32 != ' ' as i32 {
            break;
        }
        if stop as i32 == ' ' as i32
            && ((unsafe { *cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
                || (unsafe { *cur }) as i32 == 0xd as i32)
        {
            break;
        }
        if len + 1 as i32 >= size {
            size *= 2 as i32;
            tmp = (unsafe {
                xmlRealloc.expect("non-null function pointer")(
                    buf as *mut libc::c_void,
                    (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
                )
            }) as *mut xmlChar;
            if tmp.is_null() {
                xmlCatalogErrMemory(b"allocating public ID\0" as *const u8 as *const i8);
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                return 0 as *const xmlChar;
            }
            buf = tmp;
        }
        let mut fresh63 = len;
        len = len + 1;
        (unsafe { *buf.offset(fresh63 as isize) = *cur });
        count += 1;
        cur = unsafe { cur.offset(1) };
    }
    (unsafe { *buf.offset(len as isize) = 0 as i32 as xmlChar });
    if stop as i32 == ' ' as i32 {
        if !((unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32)
        {
            (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
            return 0 as *const xmlChar;
        }
    } else {
        if (unsafe { *cur }) as i32 != stop as i32 {
            (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
            return 0 as *const xmlChar;
        }
        cur = unsafe { cur.offset(1) };
    }
    *(borrow_mut(&mut id)).unwrap() = buf;
    return cur;
}
extern "C" fn xmlParseSGMLCatalogName<'a1>(
    mut cur: *const u8,
    mut name: Option<&'a1 mut *mut u8>,
) -> *const u8 {
    let mut buf: [u8; 105] = [0; 105];
    let mut len: i32 = 0 as i32;
    let mut c: i32 = 0;
    *(borrow_mut(&mut name)).unwrap() = 0 as *mut xmlChar;
    c = (unsafe { *cur }) as i32;
    if !((if c < 0x100 as i32 {
        (0x41 as i32 <= c && c <= 0x5a as i32
            || 0x61 as i32 <= c && c <= 0x7a as i32
            || 0xc0 as i32 <= c && c <= 0xd6 as i32
            || 0xd8 as i32 <= c && c <= 0xf6 as i32
            || 0xf8 as i32 <= c) as i32
    } else {
        xmlCharInRange(c as u32, (Some(unsafe { &xmlIsBaseCharGroup })).clone())
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
        }) != 0)
        && c != '_' as i32
        && c != ':' as i32
    {
        return 0 as *const xmlChar;
    }
    while (if c < 0x100 as i32 {
        (0x41 as i32 <= c && c <= 0x5a as i32
            || 0x61 as i32 <= c && c <= 0x7a as i32
            || 0xc0 as i32 <= c && c <= 0xd6 as i32
            || 0xd8 as i32 <= c && c <= 0xf6 as i32
            || 0xf8 as i32 <= c) as i32
    } else {
        xmlCharInRange(c as u32, (Some(unsafe { &xmlIsBaseCharGroup })).clone())
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
        }) != 0
        || (if c < 0x100 as i32 {
            (0x30 as i32 <= c && c <= 0x39 as i32) as i32
        } else {
            xmlCharInRange(c as u32, (Some(unsafe { &xmlIsDigitGroup })).clone())
        }) != 0
        || c == '.' as i32
        || c == '-' as i32
        || c == '_' as i32
        || c == ':' as i32
    {
        let mut fresh64 = len;
        len = len + 1;
        buf[fresh64 as usize] = c as xmlChar;
        cur = unsafe { cur.offset(1) };
        c = (unsafe { *cur }) as i32;
        if len >= 100 as i32 {
            return 0 as *const xmlChar;
        }
    }
    *(borrow_mut(&mut name)).unwrap() = unsafe { xmlStrndup(buf.as_mut_ptr(), len) };
    return cur;
}
extern "C" fn xmlGetSGMLCatalogEntryType(mut name: *const u8) -> i32 {
    let mut type_0: i32 = XML_CATA_NONE;
    if (unsafe {
        xmlStrEqual(
            name,
            b"SYSTEM\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = SGML_CATA_SYSTEM;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"PUBLIC\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = SGML_CATA_PUBLIC;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"DELEGATE\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = SGML_CATA_DELEGATE;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"ENTITY\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = SGML_CATA_ENTITY;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"DOCTYPE\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = SGML_CATA_DOCTYPE;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"LINKTYPE\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = SGML_CATA_LINKTYPE;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"NOTATION\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = SGML_CATA_NOTATION;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"SGMLDECL\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = SGML_CATA_SGMLDECL;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"DOCUMENT\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = SGML_CATA_DOCUMENT;
    } else if (unsafe {
        xmlStrEqual(
            name,
            b"CATALOG\0" as *const u8 as *const i8 as *const xmlChar,
        )
    }) != 0
    {
        type_0 = SGML_CATA_CATALOG;
    } else if (unsafe { xmlStrEqual(name, b"BASE\0" as *const u8 as *const i8 as *const xmlChar) })
        != 0
    {
        type_0 = SGML_CATA_BASE;
    }
    return type_0;
}
extern "C" fn xmlParseSGMLCatalog<'a1>(
    mut catal: *mut crate::src::catalog::_xmlCatalog<'a1>,
    mut value: *const u8,
    mut file: *const i8,
    mut super_0: i32,
) -> i32 {
    let mut cur: *const u8 = value;
    let mut base: *mut u8 = 0 as *mut xmlChar;
    let mut res: i32 = 0;
    if cur.is_null() || file.is_null() {
        return -(1 as i32);
    }
    base = unsafe { xmlStrdup(file as *const xmlChar) };
    while !cur.is_null() && (unsafe { *cur.offset(0 as i32 as isize) }) as i32 != 0 as i32 {
        while (unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32
        {
            cur = unsafe { cur.offset(1) };
        }
        if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
            break;
        }
        if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '-' as i32
            && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '-' as i32
        {
            cur = xmlParseSGMLCatalogComment(cur);
            if !cur.is_null() {
                continue;
            }
            break;
        } else {
            let mut sysid: *mut u8 = 0 as *mut xmlChar;
            let mut name: *mut u8 = 0 as *mut xmlChar;
            let mut type_0: i32 = XML_CATA_NONE;
            cur = xmlParseSGMLCatalogName(cur, Some(&mut name));
            if cur.is_null() || name.is_null() {
                break;
            } else if !((unsafe { *cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
                || (unsafe { *cur }) as i32 == 0xd as i32)
            {
                (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
                break;
            } else {
                while (unsafe { *cur }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *cur }) as i32
                        && (unsafe { *cur }) as i32 <= 0xa as i32
                    || (unsafe { *cur }) as i32 == 0xd as i32
                {
                    cur = unsafe { cur.offset(1) };
                }
                if (unsafe {
                    xmlStrEqual(
                        name,
                        b"SYSTEM\0" as *const u8 as *const i8 as *const xmlChar,
                    )
                }) != 0
                {
                    type_0 = SGML_CATA_SYSTEM;
                } else if (unsafe {
                    xmlStrEqual(
                        name,
                        b"PUBLIC\0" as *const u8 as *const i8 as *const xmlChar,
                    )
                }) != 0
                {
                    type_0 = SGML_CATA_PUBLIC;
                } else if (unsafe {
                    xmlStrEqual(
                        name,
                        b"DELEGATE\0" as *const u8 as *const i8 as *const xmlChar,
                    )
                }) != 0
                {
                    type_0 = SGML_CATA_DELEGATE;
                } else if (unsafe {
                    xmlStrEqual(
                        name,
                        b"ENTITY\0" as *const u8 as *const i8 as *const xmlChar,
                    )
                }) != 0
                {
                    type_0 = SGML_CATA_ENTITY;
                } else if (unsafe {
                    xmlStrEqual(
                        name,
                        b"DOCTYPE\0" as *const u8 as *const i8 as *const xmlChar,
                    )
                }) != 0
                {
                    type_0 = SGML_CATA_DOCTYPE;
                } else if (unsafe {
                    xmlStrEqual(
                        name,
                        b"LINKTYPE\0" as *const u8 as *const i8 as *const xmlChar,
                    )
                }) != 0
                {
                    type_0 = SGML_CATA_LINKTYPE;
                } else if (unsafe {
                    xmlStrEqual(
                        name,
                        b"NOTATION\0" as *const u8 as *const i8 as *const xmlChar,
                    )
                }) != 0
                {
                    type_0 = SGML_CATA_NOTATION;
                } else if (unsafe {
                    xmlStrEqual(
                        name,
                        b"SGMLDECL\0" as *const u8 as *const i8 as *const xmlChar,
                    )
                }) != 0
                {
                    type_0 = SGML_CATA_SGMLDECL;
                } else if (unsafe {
                    xmlStrEqual(
                        name,
                        b"DOCUMENT\0" as *const u8 as *const i8 as *const xmlChar,
                    )
                }) != 0
                {
                    type_0 = SGML_CATA_DOCUMENT;
                } else if (unsafe {
                    xmlStrEqual(
                        name,
                        b"CATALOG\0" as *const u8 as *const i8 as *const xmlChar,
                    )
                }) != 0
                {
                    type_0 = SGML_CATA_CATALOG;
                } else if (unsafe {
                    xmlStrEqual(name, b"BASE\0" as *const u8 as *const i8 as *const xmlChar)
                }) != 0
                {
                    type_0 = SGML_CATA_BASE;
                } else if (unsafe {
                    xmlStrEqual(
                        name,
                        b"OVERRIDE\0" as *const u8 as *const i8 as *const xmlChar,
                    )
                }) != 0
                {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(name as *mut libc::c_void)
                    });
                    cur = xmlParseSGMLCatalogName(cur, Some(&mut name));
                    if name.is_null() {
                        break;
                    }
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(name as *mut libc::c_void)
                    });
                    continue;
                }
                (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
                name = 0 as *mut xmlChar;
                let mut current_block_56: u64;
                match type_0 as i32 {
                    15 => {
                        if (unsafe { *cur }) as i32 == '%' as i32 {
                            type_0 = SGML_CATA_PENTITY;
                        }
                        current_block_56 = 11907492662621709349;
                    }
                    16 | 17 | 18 | 19 => {
                        current_block_56 = 11907492662621709349;
                    }
                    14 | 13 | 20 => {
                        cur = xmlParseSGMLCatalogPubid(cur, Some(&mut name));
                        if !cur.is_null() {
                            if type_0 as i32 != SGML_CATA_SYSTEM as i32 {
                                let mut normid: *mut u8 = 0 as *mut xmlChar;
                                normid = xmlCatalogNormalizePublic(name);
                                if !normid.is_null() {
                                    if !name.is_null() {
                                        (unsafe {
                                            xmlFree.expect("non-null function pointer")(
                                                name as *mut libc::c_void,
                                            )
                                        });
                                    }
                                    if (unsafe { *normid }) as i32 != 0 as i32 {
                                        name = normid;
                                    } else {
                                        (unsafe {
                                            xmlFree.expect("non-null function pointer")(
                                                normid as *mut libc::c_void,
                                            )
                                        });
                                        name = 0 as *mut xmlChar;
                                    }
                                }
                            }
                            if (unsafe { *cur }) as i32 == 0x20 as i32
                                || 0x9 as i32 <= (unsafe { *cur }) as i32
                                    && (unsafe { *cur }) as i32 <= 0xa as i32
                                || (unsafe { *cur }) as i32 == 0xd as i32
                            {
                                while (unsafe { *cur }) as i32 == 0x20 as i32
                                    || 0x9 as i32 <= (unsafe { *cur }) as i32
                                        && (unsafe { *cur }) as i32 <= 0xa as i32
                                    || (unsafe { *cur }) as i32 == 0xd as i32
                                {
                                    cur = unsafe { cur.offset(1) };
                                }
                                cur = xmlParseSGMLCatalogPubid(cur, Some(&mut sysid));
                                cur.is_null();
                            }
                        }
                        current_block_56 = 6014157347423944569;
                    }
                    21 | 22 | 23 | 24 => {
                        cur = xmlParseSGMLCatalogPubid(cur, Some(&mut sysid));
                        cur.is_null();
                        current_block_56 = 6014157347423944569;
                    }
                    _ => {
                        current_block_56 = 6014157347423944569;
                    }
                }
                match current_block_56 {
                    11907492662621709349 => {
                        cur = xmlParseSGMLCatalogName(cur, Some(&mut name));
                        if !cur.is_null() {
                            if (unsafe { *cur }) as i32 == 0x20 as i32
                                || 0x9 as i32 <= (unsafe { *cur }) as i32
                                    && (unsafe { *cur }) as i32 <= 0xa as i32
                                || (unsafe { *cur }) as i32 == 0xd as i32
                            {
                                while (unsafe { *cur }) as i32 == 0x20 as i32
                                    || 0x9 as i32 <= (unsafe { *cur }) as i32
                                        && (unsafe { *cur }) as i32 <= 0xa as i32
                                    || (unsafe { *cur }) as i32 == 0xd as i32
                                {
                                    cur = unsafe { cur.offset(1) };
                                }
                                cur = xmlParseSGMLCatalogPubid(cur, Some(&mut sysid));
                                cur.is_null();
                            }
                        }
                    }
                    _ => {}
                }
                if cur.is_null() {
                    if !name.is_null() {
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(name as *mut libc::c_void)
                        });
                    }
                    if !sysid.is_null() {
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(sysid as *mut libc::c_void)
                        });
                    }
                    break;
                } else {
                    if type_0 as i32 == SGML_CATA_BASE as i32 {
                        if !base.is_null() {
                            (unsafe {
                                xmlFree.expect("non-null function pointer")(
                                    base as *mut libc::c_void,
                                )
                            });
                        }
                        base = unsafe { xmlStrdup(sysid) };
                    } else if type_0 as i32 == SGML_CATA_PUBLIC as i32
                        || type_0 as i32 == SGML_CATA_SYSTEM as i32
                    {
                        let mut filename: *mut u8 = 0 as *mut xmlChar;
                        filename = unsafe { xmlBuildURI(sysid, base) };
                        if !filename.is_null() {
                            let mut entry: *mut crate::src::catalog::_xmlCatalogEntry =
                                0 as *mut xmlCatalogEntry;
                            entry = xmlNewCatalogEntry(
                                type_0,
                                name,
                                filename,
                                0 as *const xmlChar,
                                XML_CATA_PREFER_NONE,
                                0 as xmlCatalogEntryPtr,
                            );
                            res = xmlHashAddEntry(
                                unsafe { (*catal).sgml },
                                name,
                                entry as *mut libc::c_void,
                            );
                            if res < 0 as i32 {
                                xmlFreeCatalogEntry(
                                    entry as *mut libc::c_void,
                                    0 as *const xmlChar,
                                );
                            }
                            (unsafe {
                                xmlFree.expect("non-null function pointer")(
                                    filename as *mut libc::c_void,
                                )
                            });
                        }
                    } else if type_0 as i32 == SGML_CATA_CATALOG as i32 {
                        if super_0 != 0 {
                            let mut entry_0: *mut crate::src::catalog::_xmlCatalogEntry =
                                0 as *mut xmlCatalogEntry;
                            entry_0 = xmlNewCatalogEntry(
                                type_0,
                                sysid,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                                XML_CATA_PREFER_NONE,
                                0 as xmlCatalogEntryPtr,
                            );
                            res = xmlHashAddEntry(
                                unsafe { (*catal).sgml },
                                sysid,
                                entry_0 as *mut libc::c_void,
                            );
                            if res < 0 as i32 {
                                xmlFreeCatalogEntry(
                                    entry_0 as *mut libc::c_void,
                                    0 as *const xmlChar,
                                );
                            }
                        } else {
                            let mut filename_0: *mut u8 = 0 as *mut xmlChar;
                            filename_0 = unsafe { xmlBuildURI(sysid, base) };
                            if !filename_0.is_null() {
                                xmlExpandCatalog(catal, filename_0 as *const i8);
                                (unsafe {
                                    xmlFree.expect("non-null function pointer")(
                                        filename_0 as *mut libc::c_void,
                                    )
                                });
                            }
                        }
                    }
                    if !name.is_null() {
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(name as *mut libc::c_void)
                        });
                    }
                    if !sysid.is_null() {
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(sysid as *mut libc::c_void)
                        });
                    }
                }
            }
        }
    }
    if !base.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(base as *mut libc::c_void) });
    }
    if cur.is_null() {
        return -(1 as i32);
    }
    return 0 as i32;
}
extern "C" fn xmlCatalogGetSGMLPublic(
    mut catal: *mut crate::src::hash::_xmlHashTable,
    mut pubID: *const u8,
) -> *const u8 {
    let mut entry: *mut crate::src::catalog::_xmlCatalogEntry =
        0 as *mut crate::src::catalog::_xmlCatalogEntry;
    let mut normid: *mut u8 = 0 as *mut xmlChar;
    if catal.is_null() {
        return 0 as *const xmlChar;
    }
    normid = xmlCatalogNormalizePublic(pubID);
    if !normid.is_null() {
        pubID = if (unsafe { *normid }) as i32 != 0 as i32 {
            normid
        } else {
            0 as *mut xmlChar
        };
    }
    entry = xmlHashLookup(catal, pubID) as xmlCatalogEntryPtr;
    if entry.is_null() {
        if !normid.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void) });
        }
        return 0 as *const xmlChar;
    }
    if (unsafe { (*entry).type_0 }) as i32 == SGML_CATA_PUBLIC as i32 {
        if !normid.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void) });
        }
        return unsafe { (*entry).URL };
    }
    if !normid.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void) });
    }
    return 0 as *const xmlChar;
}
extern "C" fn xmlCatalogGetSGMLSystem(
    mut catal: *mut crate::src::hash::_xmlHashTable,
    mut sysID: *const u8,
) -> *const u8 {
    let mut entry: *mut crate::src::catalog::_xmlCatalogEntry =
        0 as *mut crate::src::catalog::_xmlCatalogEntry;
    if catal.is_null() {
        return 0 as *const xmlChar;
    }
    entry = xmlHashLookup(catal, sysID) as xmlCatalogEntryPtr;
    if entry.is_null() {
        return 0 as *const xmlChar;
    }
    if (unsafe { (*entry).type_0 }) as i32 == SGML_CATA_SYSTEM as i32 {
        return unsafe { (*entry).URL };
    }
    return 0 as *const xmlChar;
}
extern "C" fn xmlCatalogSGMLResolve<'a1>(
    mut catal: *mut crate::src::catalog::_xmlCatalog<'a1>,
    mut pubID: *const u8,
    mut sysID: *const u8,
) -> *const u8 {
    let mut ret: *const u8 = 0 as *const xmlChar;
    if (unsafe { (*catal).sgml }).is_null() {
        return 0 as *const xmlChar;
    }
    if !pubID.is_null() {
        ret = xmlCatalogGetSGMLPublic(unsafe { (*catal).sgml }, pubID);
    }
    if !ret.is_null() {
        return ret;
    }
    if !sysID.is_null() {
        ret = xmlCatalogGetSGMLSystem(unsafe { (*catal).sgml }, sysID);
    }
    if !ret.is_null() {
        return ret;
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlLoadSGMLSuperCatalog<'a1>(
    mut filename: *const i8,
) -> *mut crate::src::catalog::_xmlCatalog<'a1> {
    let mut content: *mut u8 = 0 as *mut xmlChar;
    let mut catal: *mut crate::src::catalog::_xmlCatalog<'_> = 0 as *mut xmlCatalog;
    let mut ret: i32 = 0;
    content = xmlLoadFileContent(filename);
    if content.is_null() {
        return 0 as xmlCatalogPtr;
    }
    catal = xmlCreateNewCatalog(XML_SGML_CATALOG_TYPE, unsafe { xmlCatalogDefaultPrefer });
    if catal.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(content as *mut libc::c_void) });
        return 0 as xmlCatalogPtr;
    }
    ret = xmlParseSGMLCatalog(catal, content, filename, 1 as i32);
    (unsafe { xmlFree.expect("non-null function pointer")(content as *mut libc::c_void) });
    if ret < 0 as i32 {
        xmlFreeCatalog(catal);
        return 0 as xmlCatalogPtr;
    }
    return catal;
}
#[no_mangle]
pub extern "C" fn xmlLoadACatalog<'a1>(
    mut filename: *const i8,
) -> *mut crate::src::catalog::_xmlCatalog<'a1> {
    let mut content: *mut u8 = 0 as *mut xmlChar;
    let mut first: *mut u8 = 0 as *mut xmlChar;
    let mut catal: *mut crate::src::catalog::_xmlCatalog<'_> = 0 as *mut xmlCatalog;
    let mut ret: i32 = 0;
    content = xmlLoadFileContent(filename);
    if content.is_null() {
        return 0 as xmlCatalogPtr;
    }
    first = content;
    while (unsafe { *first }) as i32 != 0 as i32
        && (unsafe { *first }) as i32 != '-' as i32
        && (unsafe { *first }) as i32 != '<' as i32
        && !((unsafe { *first }) as i32 >= 'A' as i32 && (unsafe { *first }) as i32 <= 'Z' as i32
            || (unsafe { *first }) as i32 >= 'a' as i32 && (unsafe { *first }) as i32 <= 'z' as i32)
    {
        first = unsafe { first.offset(1) };
    }
    if (unsafe { *first }) as i32 != '<' as i32 {
        catal = xmlCreateNewCatalog(XML_SGML_CATALOG_TYPE, unsafe { xmlCatalogDefaultPrefer });
        if catal.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(content as *mut libc::c_void) });
            return 0 as xmlCatalogPtr;
        }
        ret = xmlParseSGMLCatalog(catal, content, filename, 0 as i32);
        if ret < 0 as i32 {
            xmlFreeCatalog(catal);
            (unsafe { xmlFree.expect("non-null function pointer")(content as *mut libc::c_void) });
            return 0 as xmlCatalogPtr;
        }
    } else {
        catal = xmlCreateNewCatalog(XML_XML_CATALOG_TYPE, unsafe { xmlCatalogDefaultPrefer });
        if catal.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(content as *mut libc::c_void) });
            return 0 as xmlCatalogPtr;
        }
        let fresh65 = unsafe { &mut ((*catal).xml) };
        *fresh65 = xmlNewCatalogEntry(
            XML_CATA_CATALOG,
            0 as *const xmlChar,
            0 as *const xmlChar,
            filename as *mut xmlChar,
            unsafe { xmlCatalogDefaultPrefer },
            0 as xmlCatalogEntryPtr,
        );
    }
    (unsafe { xmlFree.expect("non-null function pointer")(content as *mut libc::c_void) });
    return catal;
}
extern "C" fn xmlExpandCatalog<'a1>(
    mut catal: *mut crate::src::catalog::_xmlCatalog<'a1>,
    mut filename: *const i8,
) -> i32 {
    let mut ret: i32 = 0;
    if catal.is_null() || filename.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*catal).type_0 }) as u32 == XML_SGML_CATALOG_TYPE as i32 as u32 {
        let mut content: *mut u8 = 0 as *mut xmlChar;
        content = xmlLoadFileContent(filename);
        if content.is_null() {
            return -(1 as i32);
        }
        ret = xmlParseSGMLCatalog(catal, content, filename, 0 as i32);
        if ret < 0 as i32 {
            (unsafe { xmlFree.expect("non-null function pointer")(content as *mut libc::c_void) });
            return -(1 as i32);
        }
        (unsafe { xmlFree.expect("non-null function pointer")(content as *mut libc::c_void) });
    } else {
        let mut tmp: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
        let mut cur: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
        tmp = xmlNewCatalogEntry(
            XML_CATA_CATALOG,
            0 as *const xmlChar,
            0 as *const xmlChar,
            filename as *mut xmlChar,
            unsafe { xmlCatalogDefaultPrefer },
            0 as xmlCatalogEntryPtr,
        );
        cur = unsafe { (*catal).xml };
        if cur.is_null() {
            let fresh66 = unsafe { &mut ((*catal).xml) };
            *fresh66 = tmp;
        } else {
            while !(unsafe { (*cur).next }).is_null() {
                cur = unsafe { (*cur).next };
            }
            let fresh67 = unsafe { &mut ((*cur).next) };
            *fresh67 = tmp;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlACatalogResolveSystem<'a1>(
    mut catal: *mut crate::src::catalog::_xmlCatalog<'a1>,
    mut sysID: *const u8,
) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if sysID.is_null() || catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { xmlDebugCatalogs }) != 0 {
        (unsafe {
            (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                *(__xmlGenericErrorContext()).unwrap(),
                b"Resolve sysID %s\n\0" as *const u8 as *const i8,
                sysID,
            )
        });
    }
    if (unsafe { (*catal).type_0 }) as u32 == XML_XML_CATALOG_TYPE as i32 as u32 {
        ret = xmlCatalogListXMLResolve(unsafe { (*catal).xml }, 0 as *const xmlChar, sysID);
        if ret == -(1 as i32) as *mut xmlChar {
            ret = 0 as *mut xmlChar;
        }
    } else {
        let mut sgml: *const u8 = 0 as *const xmlChar;
        sgml = xmlCatalogGetSGMLSystem(unsafe { (*catal).sgml }, sysID);
        if !sgml.is_null() {
            ret = unsafe { xmlStrdup(sgml) };
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlACatalogResolvePublic<'a1>(
    mut catal: *mut crate::src::catalog::_xmlCatalog<'a1>,
    mut pubID: *const u8,
) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if pubID.is_null() || catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { xmlDebugCatalogs }) != 0 {
        (unsafe {
            (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                *(__xmlGenericErrorContext()).unwrap(),
                b"Resolve pubID %s\n\0" as *const u8 as *const i8,
                pubID,
            )
        });
    }
    if (unsafe { (*catal).type_0 }) as u32 == XML_XML_CATALOG_TYPE as i32 as u32 {
        ret = xmlCatalogListXMLResolve(unsafe { (*catal).xml }, pubID, 0 as *const xmlChar);
        if ret == -(1 as i32) as *mut xmlChar {
            ret = 0 as *mut xmlChar;
        }
    } else {
        let mut sgml: *const u8 = 0 as *const xmlChar;
        sgml = xmlCatalogGetSGMLPublic(unsafe { (*catal).sgml }, pubID);
        if !sgml.is_null() {
            ret = unsafe { xmlStrdup(sgml) };
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlACatalogResolve<'a1>(
    mut catal: *mut crate::src::catalog::_xmlCatalog<'a1>,
    mut pubID: *const u8,
    mut sysID: *const u8,
) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if pubID.is_null() && sysID.is_null() || catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { xmlDebugCatalogs }) != 0 {
        if !pubID.is_null() && !sysID.is_null() {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"Resolve: pubID %s sysID %s\n\0" as *const u8 as *const i8,
                    pubID,
                    sysID,
                )
            });
        } else if !pubID.is_null() {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"Resolve: pubID %s\n\0" as *const u8 as *const i8,
                    pubID,
                )
            });
        } else {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"Resolve: sysID %s\n\0" as *const u8 as *const i8,
                    sysID,
                )
            });
        }
    }
    if (unsafe { (*catal).type_0 }) as u32 == XML_XML_CATALOG_TYPE as i32 as u32 {
        ret = xmlCatalogListXMLResolve(unsafe { (*catal).xml }, pubID, sysID);
        if ret == -(1 as i32) as *mut xmlChar {
            ret = 0 as *mut xmlChar;
        }
    } else {
        let mut sgml: *const u8 = 0 as *const xmlChar;
        sgml = xmlCatalogSGMLResolve(catal, pubID, sysID);
        if !sgml.is_null() {
            ret = unsafe { xmlStrdup(sgml) };
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlACatalogResolveURI<'a1>(
    mut catal: *mut crate::src::catalog::_xmlCatalog<'a1>,
    mut URI: *const u8,
) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if URI.is_null() || catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { xmlDebugCatalogs }) != 0 {
        (unsafe {
            (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                *(__xmlGenericErrorContext()).unwrap(),
                b"Resolve URI %s\n\0" as *const u8 as *const i8,
                URI,
            )
        });
    }
    if (unsafe { (*catal).type_0 }) as u32 == XML_XML_CATALOG_TYPE as i32 as u32 {
        ret = xmlCatalogListXMLResolveURI(unsafe { (*catal).xml }, URI);
        if ret == -(1 as i32) as *mut xmlChar {
            ret = 0 as *mut xmlChar;
        }
    } else {
        let mut sgml: *const u8 = 0 as *const xmlChar;
        sgml = xmlCatalogSGMLResolve(catal, 0 as *const xmlChar, URI);
        if !sgml.is_null() {
            ret = unsafe { xmlStrdup(sgml) };
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlACatalogDump<'a1>(
    mut catal: *mut crate::src::catalog::_xmlCatalog<'a1>,
    mut out: *mut crate::src::HTMLtree::_IO_FILE,
) {
    if out.is_null() || catal.is_null() {
        return;
    }
    if (unsafe { (*catal).type_0 }) as u32 == XML_XML_CATALOG_TYPE as i32 as u32 {
        xmlDumpXMLCatalog(out, unsafe { (*catal).xml });
    } else {
        xmlHashScan(
            unsafe { (*catal).sgml },
            Some(xmlCatalogDumpEntry),
            out as *mut libc::c_void,
        );
    };
}
#[no_mangle]
pub extern "C" fn xmlACatalogAdd<'a1>(
    mut catal: *mut crate::src::catalog::_xmlCatalog<'a1>,
    mut type_0: *const u8,
    mut orig: *const u8,
    mut replace: *const u8,
) -> i32 {
    let mut res: i32 = -(1 as i32);
    if catal.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*catal).type_0 }) as u32 == XML_XML_CATALOG_TYPE as i32 as u32 {
        res = xmlAddXMLCatalog(unsafe { (*catal).xml }, type_0, orig, replace);
    } else {
        let mut cattype: i32 = XML_CATA_NONE;
        cattype = xmlGetSGMLCatalogEntryType(type_0);
        if cattype as i32 != XML_CATA_NONE as i32 {
            let mut entry: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
            entry = xmlNewCatalogEntry(
                cattype,
                orig,
                replace,
                0 as *const xmlChar,
                XML_CATA_PREFER_NONE,
                0 as xmlCatalogEntryPtr,
            );
            if (unsafe { (*catal).sgml }).is_null() {
                let fresh68 = unsafe { &mut ((*catal).sgml) };
                *fresh68 = xmlHashCreate(10 as i32);
            }
            res = xmlHashAddEntry(unsafe { (*catal).sgml }, orig, entry as *mut libc::c_void);
        }
    }
    return res;
}
#[no_mangle]
pub extern "C" fn xmlACatalogRemove<'a1>(
    mut catal: *mut crate::src::catalog::_xmlCatalog<'a1>,
    mut value: *const u8,
) -> i32 {
    let mut res: i32 = -(1 as i32);
    if catal.is_null() || value.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*catal).type_0 }) as u32 == XML_XML_CATALOG_TYPE as i32 as u32 {
        res = xmlDelXMLCatalog(unsafe { (*catal).xml }, value);
    } else {
        res = xmlHashRemoveEntry(unsafe { (*catal).sgml }, value, Some(xmlFreeCatalogEntry));
        if res == 0 as i32 {
            res = 1 as i32;
        }
    }
    return res;
}
#[no_mangle]
pub extern "C" fn xmlNewCatalog<'a1>(mut sgml: i32) -> *mut crate::src::catalog::_xmlCatalog<'a1> {
    let mut catal: *mut crate::src::catalog::_xmlCatalog<'_> = 0 as xmlCatalogPtr;
    if sgml != 0 {
        catal = xmlCreateNewCatalog(XML_SGML_CATALOG_TYPE, unsafe { xmlCatalogDefaultPrefer });
        if !catal.is_null() && (unsafe { (*catal).sgml }).is_null() {
            let fresh69 = unsafe { &mut ((*catal).sgml) };
            *fresh69 = xmlHashCreate(10 as i32);
        }
    } else {
        catal = xmlCreateNewCatalog(XML_XML_CATALOG_TYPE, unsafe { xmlCatalogDefaultPrefer });
    }
    return catal;
}
#[no_mangle]
pub extern "C" fn xmlCatalogIsEmpty<'a1, 'a2>(
    mut catal: Option<&'a1 mut crate::src::catalog::_xmlCatalog<'a2>>,
) -> i32 {
    if borrow(&catal).is_none() {
        return -(1 as i32);
    }
    if (*(borrow(&catal)).unwrap()).type_0 as u32 == XML_XML_CATALOG_TYPE as i32 as u32 {
        if ((*(borrow_mut(&mut catal)).unwrap()).xml).is_null() {
            return 1 as i32;
        }
        if (unsafe { (*(*(borrow(&catal)).unwrap()).xml).type_0 }) as i32 != XML_CATA_CATALOG as i32
            && (unsafe { (*(*(borrow(&catal)).unwrap()).xml).type_0 }) as i32
                != XML_CATA_BROKEN_CATALOG as i32
        {
            return -(1 as i32);
        }
        if (unsafe { (*(*(borrow_mut(&mut catal)).unwrap()).xml).children }).is_null() {
            return 1 as i32;
        }
        return 0 as i32;
    } else {
        let mut res: i32 = 0;
        if ((*(borrow_mut(&mut catal)).unwrap()).sgml).is_null() {
            return 1 as i32;
        }
        res = xmlHashSize((*(borrow_mut(&mut catal)).unwrap()).sgml);
        if res == 0 as i32 {
            return 1 as i32;
        }
        if res < 0 as i32 {
            return -(1 as i32);
        }
    }
    return 0 as i32;
}
extern "C" fn xmlInitializeCatalogData() {
    if (unsafe { xmlCatalogInitialized }) != 0 as i32 {
        return;
    }
    if !(unsafe { getenv(b"XML_DEBUG_CATALOG\0" as *const u8 as *const i8) }).is_null() {
        (unsafe { xmlDebugCatalogs = 1 as i32 });
    }
    (unsafe { xmlCatalogMutex = xmlNewRMutex() });
    (unsafe { xmlCatalogInitialized = 1 as i32 });
}
#[no_mangle]
pub extern "C" fn xmlInitializeCatalog() {
    if (unsafe { xmlCatalogInitialized }) != 0 as i32 {
        return;
    }
    xmlInitializeCatalogData();
    (unsafe { xmlRMutexLock(xmlCatalogMutex) });
    if !(unsafe { getenv(b"XML_DEBUG_CATALOG\0" as *const u8 as *const i8) }).is_null() {
        (unsafe { xmlDebugCatalogs = 1 as i32 });
    }
    if (unsafe { xmlDefaultCatalog }).is_null() {
        let mut catalogs: *const i8 = 0 as *const i8;
        let mut path: *mut i8 = 0 as *mut i8;
        let mut cur: *const i8 = 0 as *const i8;
        let mut paths: *const i8 = 0 as *const i8;
        let mut catal: *mut crate::src::catalog::_xmlCatalog<'_> = 0 as *mut xmlCatalog;
        let mut nextent: Option<&'_ mut *mut crate::src::catalog::_xmlCatalogEntry> =
            Option::<&'_ mut *mut crate::src::catalog::_xmlCatalogEntry>::None;
        catalogs =
            (unsafe { getenv(b"XML_CATALOG_FILES\0" as *const u8 as *const i8) }) as *const i8;
        if catalogs.is_null() {
            catalogs = b"file:///usr/local/etc/xml/catalog\0" as *const u8 as *const i8;
        }
        catal = xmlCreateNewCatalog(XML_XML_CATALOG_TYPE, unsafe { xmlCatalogDefaultPrefer });
        if !catal.is_null() {
            cur = catalogs;
            nextent = Some(unsafe { &mut (*catal).xml });
            while (unsafe { *cur }) as i32 != '\u{0}' as i32 {
                while (unsafe { *cur }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *cur }) as i32
                        && (unsafe { *cur }) as i32 <= 0xa as i32
                    || (unsafe { *cur }) as i32 == 0xd as i32
                {
                    cur = unsafe { cur.offset(1) };
                }
                if (unsafe { *cur }) as i32 != 0 as i32 {
                    paths = cur;
                    while (unsafe { *cur }) as i32 != 0 as i32
                        && !((unsafe { *cur }) as i32 == 0x20 as i32
                            || 0x9 as i32 <= (unsafe { *cur }) as i32
                                && (unsafe { *cur }) as i32 <= 0xa as i32
                            || (unsafe { *cur }) as i32 == 0xd as i32)
                    {
                        cur = unsafe { cur.offset(1) };
                    }
                    path = (unsafe {
                        xmlStrndup(
                            paths as *const xmlChar,
                            cur.offset_from(paths) as i64 as i32,
                        )
                    }) as *mut i8;
                    if !path.is_null() {
                        *(borrow_mut(&mut nextent)).unwrap() = xmlNewCatalogEntry(
                            XML_CATA_CATALOG,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                            path as *mut xmlChar,
                            unsafe { xmlCatalogDefaultPrefer },
                            0 as xmlCatalogEntryPtr,
                        );
                        if !(*(borrow_mut(&mut nextent)).unwrap()).is_null() {
                            nextent = Some(
                                unsafe { &mut (**(borrow_mut(&mut nextent)).unwrap()).next },
                            );
                        }
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(path as *mut libc::c_void)
                        });
                    }
                }
            }
            (unsafe { xmlDefaultCatalog = catal });
        }
    }
    (unsafe { xmlRMutexUnlock(xmlCatalogMutex) });
}
#[no_mangle]
pub extern "C" fn xmlLoadCatalog(mut filename: *const i8) -> i32 {
    let mut ret: i32 = 0;
    let mut catal: *mut crate::src::catalog::_xmlCatalog<'_> = 0 as *mut xmlCatalog;
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalogData();
    }
    (unsafe { xmlRMutexLock(xmlCatalogMutex) });
    if (unsafe { xmlDefaultCatalog }).is_null() {
        catal = xmlLoadACatalog(filename);
        if catal.is_null() {
            (unsafe { xmlRMutexUnlock(xmlCatalogMutex) });
            return -(1 as i32);
        }
        (unsafe { xmlDefaultCatalog = catal });
        (unsafe { xmlRMutexUnlock(xmlCatalogMutex) });
        return 0 as i32;
    }
    ret = xmlExpandCatalog(unsafe { xmlDefaultCatalog }, filename);
    (unsafe { xmlRMutexUnlock(xmlCatalogMutex) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlLoadCatalogs(mut pathss: *const i8) {
    let mut cur: *const i8 = 0 as *const i8;
    let mut paths: *const i8 = 0 as *const i8;
    let mut path: *mut u8 = 0 as *mut xmlChar;
    if pathss.is_null() {
        return;
    }
    cur = pathss;
    while (unsafe { *cur }) as i32 != 0 as i32 {
        while (unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32
        {
            cur = unsafe { cur.offset(1) };
        }
        if (unsafe { *cur }) as i32 != 0 as i32 {
            paths = cur;
            while (unsafe { *cur }) as i32 != 0 as i32
                && (unsafe { *cur }) as i32 != ':' as i32
                && !((unsafe { *cur }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *cur }) as i32
                        && (unsafe { *cur }) as i32 <= 0xa as i32
                    || (unsafe { *cur }) as i32 == 0xd as i32)
            {
                cur = unsafe { cur.offset(1) };
            }
            path = unsafe {
                xmlStrndup(
                    paths as *const xmlChar,
                    cur.offset_from(paths) as i64 as i32,
                )
            };
            if !path.is_null() {
                xmlLoadCatalog(path as *const i8);
                (unsafe { xmlFree.expect("non-null function pointer")(path as *mut libc::c_void) });
            }
        }
        while (unsafe { *cur }) as i32 == ':' as i32 {
            cur = unsafe { cur.offset(1) };
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlCatalogCleanup() {
    if (unsafe { xmlCatalogInitialized }) == 0 as i32 {
        return;
    }
    (unsafe { xmlRMutexLock(xmlCatalogMutex) });
    if (unsafe { xmlDebugCatalogs }) != 0 {
        (unsafe {
            (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                *(__xmlGenericErrorContext()).unwrap(),
                b"Catalogs cleanup\n\0" as *const u8 as *const i8,
            )
        });
    }
    if !(unsafe { xmlCatalogXMLFiles }).is_null() {
        xmlHashFree(
            unsafe { xmlCatalogXMLFiles },
            Some(xmlFreeCatalogHashEntryList),
        );
    }
    (unsafe { xmlCatalogXMLFiles = 0 as xmlHashTablePtr });
    if !(unsafe { xmlDefaultCatalog }).is_null() {
        xmlFreeCatalog(unsafe { xmlDefaultCatalog });
    }
    (unsafe { xmlDefaultCatalog = 0 as xmlCatalogPtr });
    (unsafe { xmlDebugCatalogs = 0 as i32 });
    (unsafe { xmlCatalogInitialized = 0 as i32 });
    (unsafe { xmlRMutexUnlock(xmlCatalogMutex) });
    (unsafe { xmlFreeRMutex(xmlCatalogMutex) });
}
#[no_mangle]
pub extern "C" fn xmlCatalogResolveSystem(mut sysID: *const u8) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalog();
    }
    ret = xmlACatalogResolveSystem(unsafe { xmlDefaultCatalog }, sysID);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCatalogResolvePublic(mut pubID: *const u8) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalog();
    }
    ret = xmlACatalogResolvePublic(unsafe { xmlDefaultCatalog }, pubID);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCatalogResolve(mut pubID: *const u8, mut sysID: *const u8) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalog();
    }
    ret = xmlACatalogResolve(unsafe { xmlDefaultCatalog }, pubID, sysID);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCatalogResolveURI(mut URI: *const u8) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalog();
    }
    ret = xmlACatalogResolveURI(unsafe { xmlDefaultCatalog }, URI);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCatalogDump(mut out: *mut crate::src::HTMLtree::_IO_FILE) {
    if out.is_null() {
        return;
    }
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalog();
    }
    xmlACatalogDump(unsafe { xmlDefaultCatalog }, out);
}
#[no_mangle]
pub extern "C" fn xmlCatalogAdd(
    mut type_0: *const u8,
    mut orig: *const u8,
    mut replace: *const u8,
) -> i32 {
    let mut res: i32 = -(1 as i32);
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalogData();
    }
    (unsafe { xmlRMutexLock(xmlCatalogMutex) });
    if (unsafe { xmlDefaultCatalog }).is_null()
        && (unsafe {
            xmlStrEqual(
                type_0,
                b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
            )
        }) != 0
    {
        (unsafe {
            xmlDefaultCatalog = xmlCreateNewCatalog(XML_XML_CATALOG_TYPE, xmlCatalogDefaultPrefer)
        });
        if !(unsafe { xmlDefaultCatalog }).is_null() {
            let fresh70 = unsafe { &mut ((*xmlDefaultCatalog).xml) };
            *fresh70 = xmlNewCatalogEntry(
                XML_CATA_CATALOG,
                0 as *const xmlChar,
                orig,
                0 as *const xmlChar,
                unsafe { xmlCatalogDefaultPrefer },
                0 as xmlCatalogEntryPtr,
            );
        }
        (unsafe { xmlRMutexUnlock(xmlCatalogMutex) });
        return 0 as i32;
    }
    res = xmlACatalogAdd(unsafe { xmlDefaultCatalog }, type_0, orig, replace);
    (unsafe { xmlRMutexUnlock(xmlCatalogMutex) });
    return res;
}
#[no_mangle]
pub extern "C" fn xmlCatalogRemove(mut value: *const u8) -> i32 {
    let mut res: i32 = 0;
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalog();
    }
    (unsafe { xmlRMutexLock(xmlCatalogMutex) });
    res = xmlACatalogRemove(unsafe { xmlDefaultCatalog }, value);
    (unsafe { xmlRMutexUnlock(xmlCatalogMutex) });
    return res;
}
#[no_mangle]
pub extern "C" fn xmlCatalogConvert() -> i32 {
    let mut res: i32 = -(1 as i32);
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalog();
    }
    (unsafe { xmlRMutexLock(xmlCatalogMutex) });
    res = xmlConvertSGMLCatalog(unsafe { xmlDefaultCatalog });
    (unsafe { xmlRMutexUnlock(xmlCatalogMutex) });
    return res;
}
#[no_mangle]
pub extern "C" fn xmlCatalogGetDefaults() -> u32 {
    return unsafe { xmlCatalogDefaultAllow };
}
#[no_mangle]
pub extern "C" fn xmlCatalogSetDefaults(mut allow: u32) {
    if (unsafe { xmlDebugCatalogs }) != 0 {
        match allow as u32 {
            0 => {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"Disabling catalog usage\n\0" as *const u8 as *const i8,
                    )
                });
            }
            1 => {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"Allowing only global catalogs\n\0" as *const u8 as *const i8,
                    )
                });
            }
            2 => {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"Allowing only catalogs from the document\n\0" as *const u8 as *const i8,
                    )
                });
            }
            3 => {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"Allowing all catalogs\n\0" as *const u8 as *const i8,
                    )
                });
            }
            _ => {}
        }
    }
    (unsafe { xmlCatalogDefaultAllow = allow });
}
#[no_mangle]
pub extern "C" fn xmlCatalogSetDefaultPrefer(mut prefer: u32) -> u32 {
    let mut ret: u32 = unsafe { xmlCatalogDefaultPrefer };
    if prefer as u32 == XML_CATA_PREFER_NONE as i32 as u32 {
        return ret;
    }
    if (unsafe { xmlDebugCatalogs }) != 0 {
        match prefer as u32 {
            1 => {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"Setting catalog preference to PUBLIC\n\0" as *const u8 as *const i8,
                    )
                });
            }
            2 => {
                (unsafe {
                    (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"Setting catalog preference to SYSTEM\n\0" as *const u8 as *const i8,
                    )
                });
            }
            _ => return ret,
        }
    }
    (unsafe { xmlCatalogDefaultPrefer = prefer });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCatalogSetDebug(mut level: i32) -> i32 {
    let mut ret: i32 = unsafe { xmlDebugCatalogs };
    if level <= 0 as i32 {
        (unsafe { xmlDebugCatalogs = 0 as i32 });
    } else {
        (unsafe { xmlDebugCatalogs = level });
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCatalogFreeLocal(mut catalogs: *mut core::ffi::c_void) {
    let mut catal: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalog();
    }
    catal = catalogs as xmlCatalogEntryPtr;
    if !catal.is_null() {
        xmlFreeCatalogEntryList(catal);
    }
}
#[no_mangle]
pub extern "C" fn xmlCatalogAddLocal(
    mut catalogs: *mut core::ffi::c_void,
    mut URL: *const u8,
) -> *mut core::ffi::c_void {
    let mut catal: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    let mut add: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalog();
    }
    if URL.is_null() {
        return catalogs;
    }
    if (unsafe { xmlDebugCatalogs }) != 0 {
        (unsafe {
            (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                *(__xmlGenericErrorContext()).unwrap(),
                b"Adding document catalog %s\n\0" as *const u8 as *const i8,
                URL,
            )
        });
    }
    add = xmlNewCatalogEntry(
        XML_CATA_CATALOG,
        0 as *const xmlChar,
        URL,
        0 as *const xmlChar,
        unsafe { xmlCatalogDefaultPrefer },
        0 as xmlCatalogEntryPtr,
    );
    if add.is_null() {
        return catalogs;
    }
    catal = catalogs as xmlCatalogEntryPtr;
    if catal.is_null() {
        return add as *mut libc::c_void;
    }
    while !(unsafe { (*catal).next }).is_null() {
        catal = unsafe { (*catal).next };
    }
    let fresh71 = unsafe { &mut ((*catal).next) };
    *fresh71 = add;
    return catalogs;
}
#[no_mangle]
pub extern "C" fn xmlCatalogLocalResolve(
    mut catalogs: *mut core::ffi::c_void,
    mut pubID: *const u8,
    mut sysID: *const u8,
) -> *mut u8 {
    let mut catal: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalog();
    }
    if pubID.is_null() && sysID.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { xmlDebugCatalogs }) != 0 {
        if !pubID.is_null() && !sysID.is_null() {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"Local Resolve: pubID %s sysID %s\n\0" as *const u8 as *const i8,
                    pubID,
                    sysID,
                )
            });
        } else if !pubID.is_null() {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"Local Resolve: pubID %s\n\0" as *const u8 as *const i8,
                    pubID,
                )
            });
        } else {
            (unsafe {
                (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"Local Resolve: sysID %s\n\0" as *const u8 as *const i8,
                    sysID,
                )
            });
        }
    }
    catal = catalogs as xmlCatalogEntryPtr;
    if catal.is_null() {
        return 0 as *mut xmlChar;
    }
    ret = xmlCatalogListXMLResolve(catal, pubID, sysID);
    if !ret.is_null() && ret != -(1 as i32) as *mut xmlChar {
        return ret;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlCatalogLocalResolveURI(
    mut catalogs: *mut core::ffi::c_void,
    mut URI: *const u8,
) -> *mut u8 {
    let mut catal: *mut crate::src::catalog::_xmlCatalogEntry = 0 as *mut xmlCatalogEntry;
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalog();
    }
    if URI.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { xmlDebugCatalogs }) != 0 {
        (unsafe {
            (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                *(__xmlGenericErrorContext()).unwrap(),
                b"Resolve URI %s\n\0" as *const u8 as *const i8,
                URI,
            )
        });
    }
    catal = catalogs as xmlCatalogEntryPtr;
    if catal.is_null() {
        return 0 as *mut xmlChar;
    }
    ret = xmlCatalogListXMLResolveURI(catal, URI);
    if !ret.is_null() && ret != -(1 as i32) as *mut xmlChar {
        return ret;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlCatalogGetSystem(mut sysID: *const u8) -> *const u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    static mut result: [u8; 1000] = [0; 1000];
    static mut msg: i32 = 0 as i32;
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalog();
    }
    if (unsafe { msg }) == 0 as i32 {
        (unsafe {
            (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                *(__xmlGenericErrorContext()).unwrap(),
                b"Use of deprecated xmlCatalogGetSystem() call\n\0" as *const u8 as *const i8,
            )
        });
        (unsafe { msg += 1 });
    }
    if sysID.is_null() {
        return 0 as *const xmlChar;
    }
    if !(unsafe { xmlDefaultCatalog }).is_null() {
        ret = xmlCatalogListXMLResolve(
            unsafe { (*xmlDefaultCatalog).xml },
            0 as *const xmlChar,
            sysID,
        );
        if !ret.is_null() && ret != -(1 as i32) as *mut xmlChar {
            (unsafe {
                snprintf(
                    result.as_mut_ptr() as *mut i8,
                    (::std::mem::size_of::<[xmlChar; 1000]>() as u64).wrapping_sub(1 as i32 as u64),
                    b"%s\0" as *const u8 as *const i8,
                    ret as *mut i8,
                )
            });
            (unsafe {
                result[(::std::mem::size_of::<[xmlChar; 1000]>() as u64)
                    .wrapping_sub(1 as i32 as u64) as usize] = 0 as i32 as xmlChar
            });
            return unsafe { result.as_mut_ptr() };
        }
    }
    if !(unsafe { xmlDefaultCatalog }).is_null() {
        return xmlCatalogGetSGMLSystem(unsafe { (*xmlDefaultCatalog).sgml }, sysID);
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlCatalogGetPublic(mut pubID: *const u8) -> *const u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    static mut result: [u8; 1000] = [0; 1000];
    static mut msg: i32 = 0 as i32;
    if (unsafe { xmlCatalogInitialized }) == 0 {
        xmlInitializeCatalog();
    }
    if (unsafe { msg }) == 0 as i32 {
        (unsafe {
            (*(borrow(&__xmlGenericError())).unwrap()).expect("non-null function pointer")(
                *(__xmlGenericErrorContext()).unwrap(),
                b"Use of deprecated xmlCatalogGetPublic() call\n\0" as *const u8 as *const i8,
            )
        });
        (unsafe { msg += 1 });
    }
    if pubID.is_null() {
        return 0 as *const xmlChar;
    }
    if !(unsafe { xmlDefaultCatalog }).is_null() {
        ret = xmlCatalogListXMLResolve(
            unsafe { (*xmlDefaultCatalog).xml },
            pubID,
            0 as *const xmlChar,
        );
        if !ret.is_null() && ret != -(1 as i32) as *mut xmlChar {
            (unsafe {
                snprintf(
                    result.as_mut_ptr() as *mut i8,
                    (::std::mem::size_of::<[xmlChar; 1000]>() as u64).wrapping_sub(1 as i32 as u64),
                    b"%s\0" as *const u8 as *const i8,
                    ret as *mut i8,
                )
            });
            (unsafe {
                result[(::std::mem::size_of::<[xmlChar; 1000]>() as u64)
                    .wrapping_sub(1 as i32 as u64) as usize] = 0 as i32 as xmlChar
            });
            return unsafe { result.as_mut_ptr() };
        }
    }
    if !(unsafe { xmlDefaultCatalog }).is_null() {
        return xmlCatalogGetSGMLPublic(unsafe { (*xmlDefaultCatalog).sgml }, pubID);
    }
    return 0 as *const xmlChar;
}
use crate::laertes_rt::*;
