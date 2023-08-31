use ::libc;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    fn snprintf(
        _: *mut i8,
        _: u64,
        _: *const i8,
        _: ...
    ) -> i32;
    fn getenv(__name: *const i8) -> *mut i8;
    fn memset(
        _: *mut libc::c_void,
        _: i32,
        _: u64,
    ) -> *mut libc::c_void;
    fn __xstat(
        __ver: i32,
        __filename: *const i8,
        __stat_buf: *mut stat,
    ) -> i32;
    fn close(__fd: i32) -> i32;
    fn read(__fd: i32, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::buf::xmlBufResetInput;
pub use crate::src::chvalid::xmlCharInRange;
pub use crate::src::error::__xmlRaiseError;
pub use crate::src::globals::__xmlDefaultSAXHandler;
pub use crate::src::globals::__xmlGenericError;
pub use crate::src::globals::__xmlGenericErrorContext;
pub use crate::src::hash::xmlHashAddEntry;
pub use crate::src::hash::xmlHashCreate;
pub use crate::src::hash::xmlHashFree;
pub use crate::src::hash::xmlHashLookup;
pub use crate::src::hash::xmlHashRemoveEntry;
pub use crate::src::hash::xmlHashScan;
pub use crate::src::hash::xmlHashSize;
pub use crate::src::parser::inputPush;
pub use crate::src::parser::xmlParseDocument;
pub use crate::src::parserInternals::xmlFreeParserCtxt;
pub use crate::src::parserInternals::xmlNewInputStream;
pub use crate::src::parserInternals::xmlNewParserCtxt;
pub use crate::src::threads::xmlFreeRMutex;
pub use crate::src::threads::xmlGetThreadId;
pub use crate::src::threads::xmlNewRMutex;
pub use crate::src::threads::xmlRMutexLock;
pub use crate::src::threads::xmlRMutexUnlock;
pub use crate::src::tree::xmlAddChild;
pub use crate::src::tree::xmlDocGetRootElement;
pub use crate::src::tree::xmlFreeDoc;
pub use crate::src::tree::xmlFreeNs;
pub use crate::src::tree::xmlGetNsProp;
pub use crate::src::tree::xmlGetProp;
pub use crate::src::tree::xmlNewDoc;
pub use crate::src::tree::xmlNewDocNode;
pub use crate::src::tree::xmlNewDtd;
pub use crate::src::tree::xmlNewNs;
pub use crate::src::tree::xmlNodeGetBase;
pub use crate::src::tree::xmlSearchNsByHref;
pub use crate::src::tree::xmlSetNsProp;
pub use crate::src::tree::xmlSetProp;
pub use crate::src::uri::xmlBuildURI;
pub use crate::src::uri::xmlCanonicPath;
pub use crate::src::xmlIO::xmlFreeParserInputBuffer;
pub use crate::src::xmlIO::xmlOutputBufferCreateFile;
pub use crate::src::xmlIO::xmlParserGetDirectory;
pub use crate::src::xmlIO::xmlParserInputBufferCreateFilename;
pub use crate::src::xmlsave::xmlSaveFormatFileTo;
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrcat;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrlen;
pub use crate::src::xmlstring::xmlStrncmp;
pub use crate::src::xmlstring::xmlStrndup;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::chvalid::xmlIsBaseCharGroup;
pub use crate::src::chvalid::xmlIsDigitGroup;
pub use crate::src::chvalid::xmlIsPubidChar_tab;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub use crate::src::globals::xmlMallocAtomic;
pub use crate::src::globals::xmlRealloc;
pub use crate::src::parserInternals::_IO_wide_data;
pub use crate::src::relaxng::_IO_codecvt;
pub use crate::src::uri::_IO_marker;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::parser::_xmlStartTag;
pub use crate::src::threads::_xmlRMutex;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub type xmlChar = crate::src::HTMLparser::xmlChar;
pub type size_t = crate::src::HTMLparser::size_t;
pub type __dev_t = u64;
pub type __uid_t = u32;
pub type __gid_t = u32;
pub type __ino_t = u64;
pub type __mode_t = u32;
pub type __nlink_t = u64;
pub type __off_t = crate::src::HTMLtree::__off_t;
pub type __off64_t = crate::src::HTMLtree::__off64_t;
pub type __time_t = i64;
pub type __blksize_t = i64;
pub type __blkcnt_t = i64;
pub type __ssize_t = i64;
pub type __syscall_slong_t = i64;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::HTMLtree::_IO_FILE;
pub type _IO_lock_t = crate::src::HTMLtree::_IO_lock_t;
pub type FILE = crate::src::HTMLtree::FILE;
pub type ssize_t = __ssize_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: i32,
    pub st_rdev: __dev_t,
    pub st_size: __off_t,
    pub st_blksize: __blksize_t,
    pub st_blocks: __blkcnt_t,
    pub st_atim: timespec,
    pub st_mtim: timespec,
    pub st_ctim: timespec,
    pub __glibc_reserved: [__syscall_slong_t; 3],
}
pub type xmlFreeFunc = crate::src::HTMLparser::xmlFreeFunc;
pub type xmlMallocFunc = crate::src::HTMLparser::xmlMallocFunc;
pub type xmlReallocFunc = crate::src::HTMLparser::xmlReallocFunc;
pub type xmlRMutex = _xmlRMutex;
pub type xmlRMutexPtr = *mut xmlRMutex;
// #[derive(Copy, Clone)]

pub type _xmlParserInputBuffer = crate::src::HTMLparser::_xmlParserInputBuffer;
pub type xmlBufPtr = crate::src::HTMLparser::xmlBufPtr;
pub type xmlBuf = crate::src::HTMLparser::xmlBuf;
pub type xmlCharEncodingHandlerPtr = crate::src::HTMLparser::xmlCharEncodingHandlerPtr;
pub type xmlCharEncodingHandler = crate::src::HTMLparser::xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub type _xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type iconv_t = crate::src::HTMLparser::iconv_t;
pub type xmlCharEncodingOutputFunc = crate::src::HTMLparser::xmlCharEncodingOutputFunc;
pub type xmlCharEncodingInputFunc = crate::src::HTMLparser::xmlCharEncodingInputFunc;
pub type xmlInputCloseCallback = crate::src::HTMLparser::xmlInputCloseCallback;
pub type xmlInputReadCallback = crate::src::HTMLparser::xmlInputReadCallback;
pub type xmlParserInputBuffer = crate::src::HTMLparser::xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = crate::src::HTMLparser::xmlParserInputBufferPtr;
// #[derive(Copy, Clone)]

pub type _xmlOutputBuffer = crate::src::HTMLtree::_xmlOutputBuffer;
pub type xmlOutputCloseCallback = crate::src::HTMLtree::xmlOutputCloseCallback;
pub type xmlOutputWriteCallback = crate::src::HTMLtree::xmlOutputWriteCallback;
pub type xmlOutputBuffer = crate::src::HTMLtree::xmlOutputBuffer;
pub type xmlOutputBufferPtr = crate::src::HTMLtree::xmlOutputBufferPtr;
// #[derive(Copy, Clone)]

pub type _xmlParserInput = crate::src::HTMLparser::_xmlParserInput;
pub type xmlParserInputDeallocate = crate::src::HTMLparser::xmlParserInputDeallocate;
pub type xmlParserInput = crate::src::HTMLparser::xmlParserInput;
pub type xmlParserInputPtr = crate::src::HTMLparser::xmlParserInputPtr;
// #[derive(Copy, Clone)]

pub type _xmlParserCtxt = crate::src::HTMLparser::_xmlParserCtxt;
pub type xmlParserNodeInfo = crate::src::HTMLparser::xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub type _xmlParserNodeInfo = crate::src::HTMLparser::_xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub type _xmlNode = crate::src::HTMLparser::_xmlNode;
pub type xmlNs = crate::src::HTMLparser::xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlNs = crate::src::HTMLparser::_xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlDoc = crate::src::HTMLparser::_xmlDoc;
// #[derive(Copy, Clone)]

pub type _xmlDtd = crate::src::HTMLparser::_xmlDtd;
pub type xmlElementType = crate::src::HTMLparser::xmlElementType;
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
pub type xmlNsType = crate::src::HTMLparser::xmlNsType;
// #[derive(Copy, Clone)]

pub type _xmlAttr = crate::src::HTMLparser::_xmlAttr;
pub type xmlAttributeType = crate::src::HTMLparser::xmlAttributeType;
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
pub type xmlParserMode = crate::src::HTMLparser::xmlParserMode;
pub const XML_PARSE_READER: xmlParserMode = 5;
pub const XML_PARSE_PUSH_SAX: xmlParserMode = 4;
pub const XML_PARSE_PUSH_DOM: xmlParserMode = 3;
pub const XML_PARSE_SAX: xmlParserMode = 2;
pub const XML_PARSE_DOM: xmlParserMode = 1;
pub const XML_PARSE_UNKNOWN: xmlParserMode = 0;
pub type xmlError = crate::src::HTMLparser::xmlError;
// #[derive(Copy, Clone)]

pub type _xmlError = crate::src::HTMLparser::_xmlError;
pub type xmlErrorLevel = crate::src::HTMLparser::xmlErrorLevel;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlAttrPtr = crate::src::HTMLparser::xmlAttrPtr;
pub type xmlAttr = crate::src::HTMLparser::xmlAttr;
pub type xmlNodePtr = crate::src::HTMLparser::xmlNodePtr;
pub type xmlNode = crate::src::HTMLparser::xmlNode;
pub type xmlHashTablePtr = crate::src::HTMLparser::xmlHashTablePtr;
pub type xmlHashTable = crate::src::HTMLparser::xmlHashTable;
pub type xmlStartTag = crate::src::HTMLparser::xmlStartTag;
pub type xmlDictPtr = crate::src::HTMLparser::xmlDictPtr;
pub type xmlDict = crate::src::HTMLparser::xmlDict;
pub type xmlParserInputState = crate::src::HTMLparser::xmlParserInputState;
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
pub type xmlValidCtxt = crate::src::HTMLparser::xmlValidCtxt;
// #[derive(Copy, Clone)]

pub type _xmlValidCtxt = crate::src::HTMLparser::_xmlValidCtxt;
pub type xmlAutomataStatePtr = crate::src::HTMLparser::xmlAutomataStatePtr;
pub type xmlAutomataState = crate::src::HTMLparser::xmlAutomataState;
pub type xmlAutomataPtr = crate::src::HTMLparser::xmlAutomataPtr;
pub type xmlAutomata = crate::src::HTMLparser::xmlAutomata;
pub type xmlValidState = crate::src::HTMLparser::xmlValidState;
pub type xmlDocPtr = crate::src::HTMLparser::xmlDocPtr;
pub type xmlDoc = crate::src::HTMLparser::xmlDoc;
pub type xmlValidityWarningFunc = crate::src::HTMLparser::xmlValidityWarningFunc;
pub type xmlValidityErrorFunc = crate::src::HTMLparser::xmlValidityErrorFunc;
pub type xmlParserNodeInfoSeq = crate::src::HTMLparser::xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub type _xmlParserNodeInfoSeq = crate::src::HTMLparser::_xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub type _xmlSAXHandler = crate::src::HTMLparser::_xmlSAXHandler;
pub type xmlStructuredErrorFunc = crate::src::HTMLparser::xmlStructuredErrorFunc;
pub type xmlErrorPtr = crate::src::HTMLparser::xmlErrorPtr;
pub type endElementNsSAX2Func = crate::src::HTMLparser::endElementNsSAX2Func;
pub type startElementNsSAX2Func = crate::src::HTMLparser::startElementNsSAX2Func;
pub type externalSubsetSAXFunc = crate::src::HTMLparser::externalSubsetSAXFunc;
pub type cdataBlockSAXFunc = crate::src::HTMLparser::cdataBlockSAXFunc;
pub type getParameterEntitySAXFunc = crate::src::HTMLparser::getParameterEntitySAXFunc;
pub type xmlEntityPtr = crate::src::HTMLparser::xmlEntityPtr;
pub type xmlEntity = crate::src::HTMLparser::xmlEntity;
// #[derive(Copy, Clone)]

pub type _xmlEntity = crate::src::HTMLparser::_xmlEntity;
pub type xmlEntityType = crate::src::HTMLparser::xmlEntityType;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = crate::src::HTMLparser::fatalErrorSAXFunc;
pub type errorSAXFunc = crate::src::HTMLparser::errorSAXFunc;
pub type warningSAXFunc = crate::src::HTMLparser::warningSAXFunc;
pub type commentSAXFunc = crate::src::HTMLparser::commentSAXFunc;
pub type processingInstructionSAXFunc = crate::src::HTMLparser::processingInstructionSAXFunc;
pub type ignorableWhitespaceSAXFunc = crate::src::HTMLparser::ignorableWhitespaceSAXFunc;
pub type charactersSAXFunc = crate::src::HTMLparser::charactersSAXFunc;
pub type referenceSAXFunc = crate::src::HTMLparser::referenceSAXFunc;
pub type endElementSAXFunc = crate::src::HTMLparser::endElementSAXFunc;
pub type startElementSAXFunc = crate::src::HTMLparser::startElementSAXFunc;
pub type endDocumentSAXFunc = crate::src::HTMLparser::endDocumentSAXFunc;
pub type startDocumentSAXFunc = crate::src::HTMLparser::startDocumentSAXFunc;
pub type setDocumentLocatorSAXFunc = crate::src::HTMLparser::setDocumentLocatorSAXFunc;
pub type xmlSAXLocatorPtr = crate::src::HTMLparser::xmlSAXLocatorPtr;
pub type xmlSAXLocator = crate::src::HTMLparser::xmlSAXLocator;
// #[derive(Copy, Clone)]

pub type _xmlSAXLocator = crate::src::HTMLparser::_xmlSAXLocator;
pub type unparsedEntityDeclSAXFunc = crate::src::HTMLparser::unparsedEntityDeclSAXFunc;
pub type elementDeclSAXFunc = crate::src::HTMLparser::elementDeclSAXFunc;
pub type xmlElementContentPtr = crate::src::HTMLparser::xmlElementContentPtr;
pub type xmlElementContent = crate::src::HTMLparser::xmlElementContent;
// #[derive(Copy, Clone)]

pub type _xmlElementContent = crate::src::HTMLparser::_xmlElementContent;
pub type xmlElementContentOccur = crate::src::HTMLparser::xmlElementContentOccur;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub type xmlElementContentType = crate::src::HTMLparser::xmlElementContentType;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub type attributeDeclSAXFunc = crate::src::HTMLparser::attributeDeclSAXFunc;
pub type xmlEnumerationPtr = crate::src::HTMLparser::xmlEnumerationPtr;
pub type xmlEnumeration = crate::src::HTMLparser::xmlEnumeration;
// #[derive(Copy, Clone)]

pub type _xmlEnumeration = crate::src::HTMLparser::_xmlEnumeration;
pub type notationDeclSAXFunc = crate::src::HTMLparser::notationDeclSAXFunc;
pub type entityDeclSAXFunc = crate::src::HTMLparser::entityDeclSAXFunc;
pub type getEntitySAXFunc = crate::src::HTMLparser::getEntitySAXFunc;
pub type resolveEntitySAXFunc = crate::src::HTMLparser::resolveEntitySAXFunc;
pub type hasExternalSubsetSAXFunc = crate::src::HTMLparser::hasExternalSubsetSAXFunc;
pub type hasInternalSubsetSAXFunc = crate::src::HTMLparser::hasInternalSubsetSAXFunc;
pub type isStandaloneSAXFunc = crate::src::HTMLparser::isStandaloneSAXFunc;
pub type internalSubsetSAXFunc = crate::src::HTMLparser::internalSubsetSAXFunc;
pub type xmlParserCtxt = crate::src::HTMLparser::xmlParserCtxt;
pub type xmlParserCtxtPtr = crate::src::HTMLparser::xmlParserCtxtPtr;
pub type xmlNsPtr = crate::src::HTMLtree::xmlNsPtr;
pub type xmlDtd = crate::src::HTMLparser::xmlDtd;
pub type xmlDtdPtr = crate::src::HTMLparser::xmlDtdPtr;
pub type xmlHashDeallocator = crate::src::HTMLparser::xmlHashDeallocator;
pub type xmlHashScanner = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void, *const xmlChar) -> (),
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
pub type xmlGenericErrorFunc = crate::src::HTMLparser::xmlGenericErrorFunc;
// #[derive(Copy, Clone)]

pub type _xmlSAXHandlerV1 = crate::src::HTMLparser::_xmlSAXHandlerV1;
pub type xmlSAXHandlerV1 = crate::src::HTMLparser::xmlSAXHandlerV1;
pub type xmlCharEncoding = crate::src::HTMLparser::xmlCharEncoding;
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
// #[derive(Copy, Clone)]

pub type _xmlChSRange = crate::src::HTMLparser::_xmlChSRange;
pub type xmlChSRange = crate::src::HTMLparser::xmlChSRange;
// #[derive(Copy, Clone)]

pub type _xmlChLRange = crate::src::HTMLparser::_xmlChLRange;
pub type xmlChLRange = crate::src::HTMLparser::xmlChLRange;
// #[derive(Copy, Clone)]

pub type _xmlChRangeGroup = crate::src::HTMLparser::_xmlChRangeGroup;
pub type xmlChRangeGroup = crate::src::HTMLparser::xmlChRangeGroup;
pub type xmlCatalogPrefer = u32;
pub const XML_CATA_PREFER_SYSTEM: xmlCatalogPrefer = 2;
pub const XML_CATA_PREFER_PUBLIC: xmlCatalogPrefer = 1;
pub const XML_CATA_PREFER_NONE: xmlCatalogPrefer = 0;
pub type xmlCatalogAllow = u32;
pub const XML_CATA_ALLOW_ALL: xmlCatalogAllow = 3;
pub const XML_CATA_ALLOW_DOCUMENT: xmlCatalogAllow = 2;
pub const XML_CATA_ALLOW_GLOBAL: xmlCatalogAllow = 1;
pub const XML_CATA_ALLOW_NONE: xmlCatalogAllow = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlCatalog {
    pub type_0: xmlCatalogType,
    pub catalTab: [*mut i8; 10],
    pub catalNr: i32,
    pub catalMax: i32,
    pub sgml: xmlHashTablePtr,
    pub prefer: xmlCatalogPrefer,
    pub xml: xmlCatalogEntryPtr,
}
pub type xmlCatalogEntryPtr = *mut xmlCatalogEntry;
pub type xmlCatalogEntry = _xmlCatalogEntry;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlCatalogEntry {
    pub next: *mut _xmlCatalogEntry,
    pub parent: *mut _xmlCatalogEntry,
    pub children: *mut _xmlCatalogEntry,
    pub type_0: xmlCatalogEntryType,
    pub name: *mut xmlChar,
    pub value: *mut xmlChar,
    pub URL: *mut xmlChar,
    pub prefer: xmlCatalogPrefer,
    pub dealloc: i32,
    pub depth: i32,
    pub group: *mut _xmlCatalogEntry,
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
pub type xmlCatalog = _xmlCatalog;
pub type xmlCatalogPtr = *mut xmlCatalog;
#[inline]
unsafe extern "C" fn stat(
    mut __path: *const i8,
    mut __statbuf: *mut stat,
) -> i32 {
    return __xstat(1 as i32, __path, __statbuf);
}
static mut xmlDebugCatalogs: i32 = 0 as i32;
static mut xmlCatalogDefaultAllow: xmlCatalogAllow = XML_CATA_ALLOW_ALL;
static mut xmlCatalogDefaultPrefer: xmlCatalogPrefer = XML_CATA_PREFER_PUBLIC;
static mut xmlCatalogXMLFiles: xmlHashTablePtr = 0 as *const xmlHashTable
    as xmlHashTablePtr;
static mut xmlDefaultCatalog: xmlCatalogPtr = 0 as *const xmlCatalog as xmlCatalogPtr;
static mut xmlCatalogMutex: xmlRMutexPtr = 0 as *const xmlRMutex as xmlRMutexPtr;
static mut xmlCatalogInitialized: i32 = 0 as i32;
unsafe extern "C" fn xmlCatalogErrMemory(mut extra: *const i8) {
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
    );
}
unsafe extern "C" fn xmlCatalogErr(
    mut catal: xmlCatalogEntryPtr,
    mut node: xmlNodePtr,
    mut error: i32,
    mut msg: *const i8,
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut str3: *const xmlChar,
) {
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
    );
}
unsafe extern "C" fn xmlNewCatalogEntry(
    mut type_0: xmlCatalogEntryType,
    mut name: *const xmlChar,
    mut value: *const xmlChar,
    mut URL: *const xmlChar,
    mut prefer: xmlCatalogPrefer,
    mut group: xmlCatalogEntryPtr,
) -> xmlCatalogEntryPtr {
    let mut ret: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    let mut normid: *mut xmlChar = 0 as *mut xmlChar;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlCatalogEntry>() as u64)
        as xmlCatalogEntryPtr;
    if ret.is_null() {
        xmlCatalogErrMemory(
            b"allocating catalog entry\0" as *const u8 as *const i8,
        );
        return 0 as xmlCatalogEntryPtr;
    }
    let fresh0 = &mut ((*ret).next);
    *fresh0 = 0 as *mut _xmlCatalogEntry;
    let fresh1 = &mut ((*ret).parent);
    *fresh1 = 0 as *mut _xmlCatalogEntry;
    let fresh2 = &mut ((*ret).children);
    *fresh2 = 0 as *mut _xmlCatalogEntry;
    (*ret).type_0 = type_0;
    if type_0 as i32 == XML_CATA_PUBLIC as i32
        || type_0 as i32 == XML_CATA_DELEGATE_PUBLIC as i32
    {
        normid = xmlCatalogNormalizePublic(name);
        if !normid.is_null() {
            name = if *normid as i32 != 0 as i32 {
                normid
            } else {
                0 as *mut xmlChar
            };
        }
    }
    if !name.is_null() {
        let fresh3 = &mut ((*ret).name);
        *fresh3 = xmlStrdup(name);
    } else {
        let fresh4 = &mut ((*ret).name);
        *fresh4 = 0 as *mut xmlChar;
    }
    if !normid.is_null() {
        xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void);
    }
    if !value.is_null() {
        let fresh5 = &mut ((*ret).value);
        *fresh5 = xmlStrdup(value);
    } else {
        let fresh6 = &mut ((*ret).value);
        *fresh6 = 0 as *mut xmlChar;
    }
    if URL.is_null() {
        URL = value;
    }
    if !URL.is_null() {
        let fresh7 = &mut ((*ret).URL);
        *fresh7 = xmlStrdup(URL);
    } else {
        let fresh8 = &mut ((*ret).URL);
        *fresh8 = 0 as *mut xmlChar;
    }
    (*ret).prefer = prefer;
    (*ret).dealloc = 0 as i32;
    (*ret).depth = 0 as i32;
    let fresh9 = &mut ((*ret).group);
    *fresh9 = group;
    return ret;
}
unsafe extern "C" fn xmlFreeCatalogEntry(
    mut payload: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    let mut ret: xmlCatalogEntryPtr = payload as xmlCatalogEntryPtr;
    if ret.is_null() {
        return;
    }
    if (*ret).dealloc == 1 as i32 {
        return;
    }
    if xmlDebugCatalogs != 0 {
        if !((*ret).name).is_null() {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Free catalog entry %s\n\0" as *const u8 as *const i8,
                (*ret).name,
            );
        } else if !((*ret).value).is_null() {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Free catalog entry %s\n\0" as *const u8 as *const i8,
                (*ret).value,
            );
        } else {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Free catalog entry\n\0" as *const u8 as *const i8,
            );
        }
    }
    if !((*ret).name).is_null() {
        xmlFree.expect("non-null function pointer")((*ret).name as *mut libc::c_void);
    }
    if !((*ret).value).is_null() {
        xmlFree.expect("non-null function pointer")((*ret).value as *mut libc::c_void);
    }
    if !((*ret).URL).is_null() {
        xmlFree.expect("non-null function pointer")((*ret).URL as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
}
unsafe extern "C" fn xmlFreeCatalogEntryList(mut ret: xmlCatalogEntryPtr) {
    let mut next: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    while !ret.is_null() {
        next = (*ret).next;
        xmlFreeCatalogEntry(ret as *mut libc::c_void, 0 as *const xmlChar);
        ret = next;
    }
}
unsafe extern "C" fn xmlFreeCatalogHashEntryList(
    mut payload: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    let mut catal: xmlCatalogEntryPtr = payload as xmlCatalogEntryPtr;
    let mut children: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    let mut next: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    if catal.is_null() {
        return;
    }
    children = (*catal).children;
    while !children.is_null() {
        next = (*children).next;
        (*children).dealloc = 0 as i32;
        let fresh10 = &mut ((*children).children);
        *fresh10 = 0 as *mut _xmlCatalogEntry;
        xmlFreeCatalogEntry(children as *mut libc::c_void, 0 as *const xmlChar);
        children = next;
    }
    (*catal).dealloc = 0 as i32;
    xmlFreeCatalogEntry(catal as *mut libc::c_void, 0 as *const xmlChar);
}
unsafe extern "C" fn xmlCreateNewCatalog(
    mut type_0: xmlCatalogType,
    mut prefer: xmlCatalogPrefer,
) -> xmlCatalogPtr {
    let mut ret: xmlCatalogPtr = 0 as *mut xmlCatalog;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlCatalog>() as u64) as xmlCatalogPtr;
    if ret.is_null() {
        xmlCatalogErrMemory(b"allocating catalog\0" as *const u8 as *const i8);
        return 0 as xmlCatalogPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlCatalog>() as u64,
    );
    (*ret).type_0 = type_0;
    (*ret).catalNr = 0 as i32;
    (*ret).catalMax = 10 as i32;
    (*ret).prefer = prefer;
    if (*ret).type_0 as u32
        == XML_SGML_CATALOG_TYPE as i32 as u32
    {
        let fresh11 = &mut ((*ret).sgml);
        *fresh11 = xmlHashCreate(10 as i32);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeCatalog(mut catal: xmlCatalogPtr) {
    if catal.is_null() {
        return;
    }
    if !((*catal).xml).is_null() {
        xmlFreeCatalogEntryList((*catal).xml);
    }
    if !((*catal).sgml).is_null() {
        xmlHashFree(
            (*catal).sgml,
            Some(
                xmlFreeCatalogEntry
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
        );
    }
    xmlFree.expect("non-null function pointer")(catal as *mut libc::c_void);
}
unsafe extern "C" fn xmlCatalogDumpEntry(
    mut payload: *mut libc::c_void,
    mut data: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    let mut entry: xmlCatalogEntryPtr = payload as xmlCatalogEntryPtr;
    let mut out: *mut FILE = data as *mut FILE;
    if entry.is_null() || out.is_null() {
        return;
    }
    match (*entry).type_0 as i32 {
        15 => {
            fprintf(out, b"ENTITY \0" as *const u8 as *const i8);
        }
        16 => {
            fprintf(out, b"ENTITY %%\0" as *const u8 as *const i8);
        }
        17 => {
            fprintf(out, b"DOCTYPE \0" as *const u8 as *const i8);
        }
        18 => {
            fprintf(out, b"LINKTYPE \0" as *const u8 as *const i8);
        }
        19 => {
            fprintf(out, b"NOTATION \0" as *const u8 as *const i8);
        }
        14 => {
            fprintf(out, b"PUBLIC \0" as *const u8 as *const i8);
        }
        13 => {
            fprintf(out, b"SYSTEM \0" as *const u8 as *const i8);
        }
        20 => {
            fprintf(out, b"DELEGATE \0" as *const u8 as *const i8);
        }
        21 => {
            fprintf(out, b"BASE \0" as *const u8 as *const i8);
        }
        22 => {
            fprintf(out, b"CATALOG \0" as *const u8 as *const i8);
        }
        23 => {
            fprintf(out, b"DOCUMENT \0" as *const u8 as *const i8);
        }
        24 => {
            fprintf(out, b"SGMLDECL \0" as *const u8 as *const i8);
        }
        _ => return,
    }
    match (*entry).type_0 as i32 {
        15 | 16 | 17 | 18 | 19 => {
            fprintf(
                out,
                b"%s\0" as *const u8 as *const i8,
                (*entry).name as *const i8,
            );
        }
        14 | 13 | 24 | 23 | 22 | 21 | 20 => {
            fprintf(out, b"\"%s\"\0" as *const u8 as *const i8, (*entry).name);
        }
        _ => {}
    }
    match (*entry).type_0 as i32 {
        15 | 16 | 17 | 18 | 19 | 14 | 13 | 20 => {
            fprintf(
                out,
                b" \"%s\"\0" as *const u8 as *const i8,
                (*entry).value,
            );
        }
        _ => {}
    }
    fprintf(out, b"\n\0" as *const u8 as *const i8);
}
unsafe extern "C" fn xmlDumpXMLCatalogNode(
    mut catal: xmlCatalogEntryPtr,
    mut catalog: xmlNodePtr,
    mut doc: xmlDocPtr,
    mut ns: xmlNsPtr,
    mut cgroup: xmlCatalogEntryPtr,
) {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut cur: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    cur = catal;
    let mut current_block_49: u64;
    while !cur.is_null() {
        if (*cur).group == cgroup {
            match (*cur).type_0 as i32 {
                2 | 1 => {
                    current_block_49 = 15414981286075827;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = (*cur).children;
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16086062102548664993 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"name\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        776782378719281040 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16251997513805125340 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegatePublic\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        12614018986753156024 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        3278478806863930313 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"system\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        2042511421509206405 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"public\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        17827901024417069171 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"group\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                (*cur).name,
                            );
                            if !((*cur).value).is_null() {
                                let mut xns: xmlNsPtr = 0 as *mut xmlNs;
                                xns = xmlSearchNsByHref(
                                    doc,
                                    node,
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const i8 as *const xmlChar,
                                );
                                if !xns.is_null() {
                                    xmlSetNsProp(
                                        node,
                                        xns,
                                        b"base\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        (*cur).value,
                                    );
                                }
                            }
                            match (*cur).prefer as u32 {
                                1 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"public\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                2 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"system\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode((*cur).next, node, doc, ns, cur);
                            xmlAddChild(catalog, node);
                        }
                        5425920993883413897 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"nextCatalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        _ => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                    }
                }
                3 => {
                    current_block_49 = 5425920993883413897;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = (*cur).children;
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16086062102548664993 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"name\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        776782378719281040 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16251997513805125340 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegatePublic\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        12614018986753156024 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        3278478806863930313 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"system\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        2042511421509206405 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"public\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        17827901024417069171 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"group\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                (*cur).name,
                            );
                            if !((*cur).value).is_null() {
                                let mut xns: xmlNsPtr = 0 as *mut xmlNs;
                                xns = xmlSearchNsByHref(
                                    doc,
                                    node,
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const i8 as *const xmlChar,
                                );
                                if !xns.is_null() {
                                    xmlSetNsProp(
                                        node,
                                        xns,
                                        b"base\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        (*cur).value,
                                    );
                                }
                            }
                            match (*cur).prefer as u32 {
                                1 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"public\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                2 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"system\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode((*cur).next, node, doc, ns, cur);
                            xmlAddChild(catalog, node);
                        }
                        5425920993883413897 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"nextCatalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        _ => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                    }
                }
                4 => {
                    current_block_49 = 17827901024417069171;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = (*cur).children;
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16086062102548664993 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"name\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        776782378719281040 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16251997513805125340 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegatePublic\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        12614018986753156024 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        3278478806863930313 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"system\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        2042511421509206405 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"public\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        17827901024417069171 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"group\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                (*cur).name,
                            );
                            if !((*cur).value).is_null() {
                                let mut xns: xmlNsPtr = 0 as *mut xmlNs;
                                xns = xmlSearchNsByHref(
                                    doc,
                                    node,
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const i8 as *const xmlChar,
                                );
                                if !xns.is_null() {
                                    xmlSetNsProp(
                                        node,
                                        xns,
                                        b"base\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        (*cur).value,
                                    );
                                }
                            }
                            match (*cur).prefer as u32 {
                                1 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"public\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                2 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"system\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode((*cur).next, node, doc, ns, cur);
                            xmlAddChild(catalog, node);
                        }
                        5425920993883413897 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"nextCatalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        _ => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                    }
                }
                5 => {
                    current_block_49 = 2042511421509206405;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = (*cur).children;
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16086062102548664993 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"name\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        776782378719281040 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16251997513805125340 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegatePublic\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        12614018986753156024 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        3278478806863930313 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"system\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        2042511421509206405 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"public\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        17827901024417069171 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"group\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                (*cur).name,
                            );
                            if !((*cur).value).is_null() {
                                let mut xns: xmlNsPtr = 0 as *mut xmlNs;
                                xns = xmlSearchNsByHref(
                                    doc,
                                    node,
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const i8 as *const xmlChar,
                                );
                                if !xns.is_null() {
                                    xmlSetNsProp(
                                        node,
                                        xns,
                                        b"base\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        (*cur).value,
                                    );
                                }
                            }
                            match (*cur).prefer as u32 {
                                1 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"public\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                2 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"system\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode((*cur).next, node, doc, ns, cur);
                            xmlAddChild(catalog, node);
                        }
                        5425920993883413897 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"nextCatalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        _ => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                    }
                }
                6 => {
                    current_block_49 = 3278478806863930313;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = (*cur).children;
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16086062102548664993 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"name\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        776782378719281040 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16251997513805125340 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegatePublic\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        12614018986753156024 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        3278478806863930313 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"system\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        2042511421509206405 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"public\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        17827901024417069171 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"group\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                (*cur).name,
                            );
                            if !((*cur).value).is_null() {
                                let mut xns: xmlNsPtr = 0 as *mut xmlNs;
                                xns = xmlSearchNsByHref(
                                    doc,
                                    node,
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const i8 as *const xmlChar,
                                );
                                if !xns.is_null() {
                                    xmlSetNsProp(
                                        node,
                                        xns,
                                        b"base\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        (*cur).value,
                                    );
                                }
                            }
                            match (*cur).prefer as u32 {
                                1 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"public\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                2 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"system\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode((*cur).next, node, doc, ns, cur);
                            xmlAddChild(catalog, node);
                        }
                        5425920993883413897 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"nextCatalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        _ => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                    }
                }
                7 => {
                    current_block_49 = 12614018986753156024;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = (*cur).children;
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16086062102548664993 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"name\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        776782378719281040 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16251997513805125340 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegatePublic\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        12614018986753156024 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        3278478806863930313 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"system\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        2042511421509206405 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"public\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        17827901024417069171 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"group\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                (*cur).name,
                            );
                            if !((*cur).value).is_null() {
                                let mut xns: xmlNsPtr = 0 as *mut xmlNs;
                                xns = xmlSearchNsByHref(
                                    doc,
                                    node,
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const i8 as *const xmlChar,
                                );
                                if !xns.is_null() {
                                    xmlSetNsProp(
                                        node,
                                        xns,
                                        b"base\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        (*cur).value,
                                    );
                                }
                            }
                            match (*cur).prefer as u32 {
                                1 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"public\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                2 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"system\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode((*cur).next, node, doc, ns, cur);
                            xmlAddChild(catalog, node);
                        }
                        5425920993883413897 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"nextCatalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        _ => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                    }
                }
                8 => {
                    current_block_49 = 16251997513805125340;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = (*cur).children;
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16086062102548664993 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"name\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        776782378719281040 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16251997513805125340 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegatePublic\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        12614018986753156024 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        3278478806863930313 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"system\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        2042511421509206405 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"public\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        17827901024417069171 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"group\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                (*cur).name,
                            );
                            if !((*cur).value).is_null() {
                                let mut xns: xmlNsPtr = 0 as *mut xmlNs;
                                xns = xmlSearchNsByHref(
                                    doc,
                                    node,
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const i8 as *const xmlChar,
                                );
                                if !xns.is_null() {
                                    xmlSetNsProp(
                                        node,
                                        xns,
                                        b"base\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        (*cur).value,
                                    );
                                }
                            }
                            match (*cur).prefer as u32 {
                                1 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"public\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                2 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"system\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode((*cur).next, node, doc, ns, cur);
                            xmlAddChild(catalog, node);
                        }
                        5425920993883413897 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"nextCatalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        _ => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                    }
                }
                9 => {
                    current_block_49 = 776782378719281040;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = (*cur).children;
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16086062102548664993 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"name\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        776782378719281040 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16251997513805125340 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegatePublic\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        12614018986753156024 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        3278478806863930313 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"system\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        2042511421509206405 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"public\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        17827901024417069171 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"group\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                (*cur).name,
                            );
                            if !((*cur).value).is_null() {
                                let mut xns: xmlNsPtr = 0 as *mut xmlNs;
                                xns = xmlSearchNsByHref(
                                    doc,
                                    node,
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const i8 as *const xmlChar,
                                );
                                if !xns.is_null() {
                                    xmlSetNsProp(
                                        node,
                                        xns,
                                        b"base\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        (*cur).value,
                                    );
                                }
                            }
                            match (*cur).prefer as u32 {
                                1 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"public\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                2 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"system\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode((*cur).next, node, doc, ns, cur);
                            xmlAddChild(catalog, node);
                        }
                        5425920993883413897 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"nextCatalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        _ => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                    }
                }
                10 => {
                    current_block_49 = 16086062102548664993;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = (*cur).children;
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16086062102548664993 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"name\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        776782378719281040 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16251997513805125340 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegatePublic\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        12614018986753156024 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        3278478806863930313 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"system\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        2042511421509206405 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"public\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        17827901024417069171 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"group\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                (*cur).name,
                            );
                            if !((*cur).value).is_null() {
                                let mut xns: xmlNsPtr = 0 as *mut xmlNs;
                                xns = xmlSearchNsByHref(
                                    doc,
                                    node,
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const i8 as *const xmlChar,
                                );
                                if !xns.is_null() {
                                    xmlSetNsProp(
                                        node,
                                        xns,
                                        b"base\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        (*cur).value,
                                    );
                                }
                            }
                            match (*cur).prefer as u32 {
                                1 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"public\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                2 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"system\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode((*cur).next, node, doc, ns, cur);
                            xmlAddChild(catalog, node);
                        }
                        5425920993883413897 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"nextCatalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        _ => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                    }
                }
                11 => {
                    current_block_49 = 3932087857103670784;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = (*cur).children;
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16086062102548664993 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"name\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        776782378719281040 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16251997513805125340 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegatePublic\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        12614018986753156024 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        3278478806863930313 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"system\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        2042511421509206405 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"public\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        17827901024417069171 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"group\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                (*cur).name,
                            );
                            if !((*cur).value).is_null() {
                                let mut xns: xmlNsPtr = 0 as *mut xmlNs;
                                xns = xmlSearchNsByHref(
                                    doc,
                                    node,
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const i8 as *const xmlChar,
                                );
                                if !xns.is_null() {
                                    xmlSetNsProp(
                                        node,
                                        xns,
                                        b"base\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        (*cur).value,
                                    );
                                }
                            }
                            match (*cur).prefer as u32 {
                                1 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"public\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                2 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"system\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode((*cur).next, node, doc, ns, cur);
                            xmlAddChild(catalog, node);
                        }
                        5425920993883413897 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"nextCatalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        _ => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                    }
                }
                12 => {
                    current_block_49 = 16685025456891485352;
                    match current_block_49 {
                        15414981286075827 => {
                            if cur == catal {
                                cur = (*cur).children;
                                continue;
                            }
                        }
                        3932087857103670784 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16086062102548664993 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"name\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        776782378719281040 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        16251997513805125340 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegatePublic\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        12614018986753156024 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"rewriteSystem\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemIdStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"rewritePrefix\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        3278478806863930313 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"system\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"systemId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        2042511421509206405 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"public\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"publicId\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"uri\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        17827901024417069171 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"group\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                                (*cur).name,
                            );
                            if !((*cur).value).is_null() {
                                let mut xns: xmlNsPtr = 0 as *mut xmlNs;
                                xns = xmlSearchNsByHref(
                                    doc,
                                    node,
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const i8 as *const xmlChar,
                                );
                                if !xns.is_null() {
                                    xmlSetNsProp(
                                        node,
                                        xns,
                                        b"base\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        (*cur).value,
                                    );
                                }
                            }
                            match (*cur).prefer as u32 {
                                1 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"public\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                2 => {
                                    xmlSetProp(
                                        node,
                                        b"prefer\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                        b"system\0" as *const u8 as *const i8
                                            as *mut xmlChar,
                                    );
                                }
                                0 | _ => {}
                            }
                            xmlDumpXMLCatalogNode((*cur).next, node, doc, ns, cur);
                            xmlAddChild(catalog, node);
                        }
                        5425920993883413897 => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"nextCatalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                        _ => {
                            node = xmlNewDocNode(
                                doc,
                                ns,
                                b"delegateURI\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            xmlSetProp(
                                node,
                                b"uriStartString\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).name,
                            );
                            xmlSetProp(
                                node,
                                b"catalog\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                                (*cur).value,
                            );
                            xmlAddChild(catalog, node);
                        }
                    }
                }
                -1 | 0 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24
                | _ => {}
            }
        }
        cur = (*cur).next;
    }
}
unsafe extern "C" fn xmlDumpXMLCatalog(
    mut out: *mut FILE,
    mut catal: xmlCatalogEntryPtr,
) -> i32 {
    let mut ret: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut catalog: xmlNodePtr = 0 as *mut xmlNode;
    let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    doc = xmlNewDoc(0 as *const xmlChar);
    if doc.is_null() {
        return -(1 as i32);
    }
    dtd = xmlNewDtd(
        doc,
        b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
        b"-//OASIS//DTD Entity Resolution XML Catalog V1.0//EN\0" as *const u8
            as *const i8 as *mut xmlChar,
        b"http://www.oasis-open.org/committees/entity/release/1.0/catalog.dtd\0"
            as *const u8 as *const i8 as *mut xmlChar,
    );
    xmlAddChild(doc as xmlNodePtr, dtd as xmlNodePtr);
    ns = xmlNewNs(
        0 as xmlNodePtr,
        b"urn:oasis:names:tc:entity:xmlns:xml:catalog\0" as *const u8
            as *const i8 as *const xmlChar,
        0 as *const xmlChar,
    );
    if ns.is_null() {
        xmlFreeDoc(doc);
        return -(1 as i32);
    }
    catalog = xmlNewDocNode(
        doc,
        ns,
        b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
        0 as *const xmlChar,
    );
    if catalog.is_null() {
        xmlFreeNs(ns);
        xmlFreeDoc(doc);
        return -(1 as i32);
    }
    let fresh12 = &mut ((*catalog).nsDef);
    *fresh12 = ns;
    xmlAddChild(doc as xmlNodePtr, catalog);
    xmlDumpXMLCatalogNode(catal, catalog, doc, ns, 0 as xmlCatalogEntryPtr);
    buf = xmlOutputBufferCreateFile(out, 0 as xmlCharEncodingHandlerPtr);
    if buf.is_null() {
        xmlFreeDoc(doc);
        return -(1 as i32);
    }
    ret = xmlSaveFormatFileTo(buf, doc, 0 as *const i8, 1 as i32);
    xmlFreeDoc(doc);
    return ret;
}
unsafe extern "C" fn xmlCatalogConvertEntry(
    mut payload: *mut libc::c_void,
    mut data: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    let mut entry: xmlCatalogEntryPtr = payload as xmlCatalogEntryPtr;
    let mut catal: xmlCatalogPtr = data as xmlCatalogPtr;
    if entry.is_null() || catal.is_null() || ((*catal).sgml).is_null()
        || ((*catal).xml).is_null()
    {
        return;
    }
    match (*entry).type_0 as i32 {
        15 => {
            (*entry).type_0 = XML_CATA_PUBLIC;
        }
        16 => {
            (*entry).type_0 = XML_CATA_PUBLIC;
        }
        17 => {
            (*entry).type_0 = XML_CATA_PUBLIC;
        }
        18 => {
            (*entry).type_0 = XML_CATA_PUBLIC;
        }
        19 => {
            (*entry).type_0 = XML_CATA_PUBLIC;
        }
        14 => {
            (*entry).type_0 = XML_CATA_PUBLIC;
        }
        13 => {
            (*entry).type_0 = XML_CATA_SYSTEM;
        }
        20 => {
            (*entry).type_0 = XML_CATA_DELEGATE_PUBLIC;
        }
        22 => {
            (*entry).type_0 = XML_CATA_CATALOG;
        }
        _ => {
            xmlHashRemoveEntry(
                (*catal).sgml,
                (*entry).name,
                Some(
                    xmlFreeCatalogEntry
                        as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
                ),
            );
            return;
        }
    }
    xmlHashRemoveEntry((*catal).sgml, (*entry).name, None);
    let fresh13 = &mut ((*entry).parent);
    *fresh13 = (*catal).xml;
    let fresh14 = &mut ((*entry).next);
    *fresh14 = 0 as *mut _xmlCatalogEntry;
    if ((*(*catal).xml).children).is_null() {
        let fresh15 = &mut ((*(*catal).xml).children);
        *fresh15 = entry;
    } else {
        let mut prev: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
        prev = (*(*catal).xml).children;
        while !((*prev).next).is_null() {
            prev = (*prev).next;
        }
        let fresh16 = &mut ((*prev).next);
        *fresh16 = entry;
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlConvertSGMLCatalog(mut catal: xmlCatalogPtr) -> i32 {
    if catal.is_null()
        || (*catal).type_0 as u32
            != XML_SGML_CATALOG_TYPE as i32 as u32
    {
        return -(1 as i32);
    }
    if xmlDebugCatalogs != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Converting SGML catalog to XML\n\0" as *const u8 as *const i8,
        );
    }
    xmlHashScan(
        (*catal).sgml,
        Some(
            xmlCatalogConvertEntry
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_void,
                    *const xmlChar,
                ) -> (),
        ),
        &mut catal as *mut xmlCatalogPtr as *mut libc::c_void,
    );
    return 0 as i32;
}
unsafe extern "C" fn xmlCatalogUnWrapURN(mut urn: *const xmlChar) -> *mut xmlChar {
    let mut result: [xmlChar; 2000] = [0; 2000];
    let mut i: u32 = 0 as i32 as u32;
    if xmlStrncmp(
        urn,
        b"urn:publicid:\0" as *const u8 as *const i8 as *mut xmlChar,
        (::std::mem::size_of::<[i8; 14]>() as u64)
            .wrapping_sub(1 as i32 as u64) as i32,
    ) != 0
    {
        return 0 as *mut xmlChar;
    }
    urn = urn
        .offset(
            (::std::mem::size_of::<[i8; 14]>() as u64)
                .wrapping_sub(1 as i32 as u64) as isize,
        );
    while *urn as i32 != 0 as i32 {
        if i as u64
            > (::std::mem::size_of::<[xmlChar; 2000]>() as u64)
                .wrapping_sub(4 as i32 as u64)
        {
            break;
        }
        if *urn as i32 == '+' as i32 {
            let fresh17 = i;
            i = i.wrapping_add(1);
            result[fresh17 as usize] = ' ' as i32 as xmlChar;
            urn = urn.offset(1);
        } else if *urn as i32 == ':' as i32 {
            let fresh18 = i;
            i = i.wrapping_add(1);
            result[fresh18 as usize] = '/' as i32 as xmlChar;
            let fresh19 = i;
            i = i.wrapping_add(1);
            result[fresh19 as usize] = '/' as i32 as xmlChar;
            urn = urn.offset(1);
        } else if *urn as i32 == ';' as i32 {
            let fresh20 = i;
            i = i.wrapping_add(1);
            result[fresh20 as usize] = ':' as i32 as xmlChar;
            let fresh21 = i;
            i = i.wrapping_add(1);
            result[fresh21 as usize] = ':' as i32 as xmlChar;
            urn = urn.offset(1);
        } else if *urn as i32 == '%' as i32 {
            if *urn.offset(1 as i32 as isize) as i32 == '2' as i32
                && *urn.offset(2 as i32 as isize) as i32 == 'B' as i32
            {
                let fresh22 = i;
                i = i.wrapping_add(1);
                result[fresh22 as usize] = '+' as i32 as xmlChar;
            } else if *urn.offset(1 as i32 as isize) as i32 == '3' as i32
                    && *urn.offset(2 as i32 as isize) as i32
                        == 'A' as i32
                {
                let fresh23 = i;
                i = i.wrapping_add(1);
                result[fresh23 as usize] = ':' as i32 as xmlChar;
            } else if *urn.offset(1 as i32 as isize) as i32 == '2' as i32
                    && *urn.offset(2 as i32 as isize) as i32
                        == 'F' as i32
                {
                let fresh24 = i;
                i = i.wrapping_add(1);
                result[fresh24 as usize] = '/' as i32 as xmlChar;
            } else if *urn.offset(1 as i32 as isize) as i32 == '3' as i32
                    && *urn.offset(2 as i32 as isize) as i32
                        == 'B' as i32
                {
                let fresh25 = i;
                i = i.wrapping_add(1);
                result[fresh25 as usize] = ';' as i32 as xmlChar;
            } else if *urn.offset(1 as i32 as isize) as i32 == '2' as i32
                    && *urn.offset(2 as i32 as isize) as i32
                        == '7' as i32
                {
                let fresh26 = i;
                i = i.wrapping_add(1);
                result[fresh26 as usize] = '\'' as i32 as xmlChar;
            } else if *urn.offset(1 as i32 as isize) as i32 == '3' as i32
                    && *urn.offset(2 as i32 as isize) as i32
                        == 'F' as i32
                {
                let fresh27 = i;
                i = i.wrapping_add(1);
                result[fresh27 as usize] = '?' as i32 as xmlChar;
            } else if *urn.offset(1 as i32 as isize) as i32 == '2' as i32
                    && *urn.offset(2 as i32 as isize) as i32
                        == '3' as i32
                {
                let fresh28 = i;
                i = i.wrapping_add(1);
                result[fresh28 as usize] = '#' as i32 as xmlChar;
            } else if *urn.offset(1 as i32 as isize) as i32 == '2' as i32
                    && *urn.offset(2 as i32 as isize) as i32
                        == '5' as i32
                {
                let fresh29 = i;
                i = i.wrapping_add(1);
                result[fresh29 as usize] = '%' as i32 as xmlChar;
            } else {
                let fresh30 = i;
                i = i.wrapping_add(1);
                result[fresh30 as usize] = *urn;
                urn = urn.offset(1);
                continue;
            }
            urn = urn.offset(3 as i32 as isize);
        } else {
            let fresh31 = i;
            i = i.wrapping_add(1);
            result[fresh31 as usize] = *urn;
            urn = urn.offset(1);
        }
    }
    result[i as usize] = 0 as i32 as xmlChar;
    return xmlStrdup(result.as_mut_ptr());
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseCatalogFile(
    mut filename: *const i8,
) -> xmlDocPtr {
    let mut ret: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut directory: *mut i8 = 0 as *mut i8;
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        if ((*__xmlDefaultSAXHandler()).error).is_some() {
            ((*__xmlDefaultSAXHandler()).error)
                .expect(
                    "non-null function pointer",
                )(
                0 as *mut libc::c_void,
                b"out of memory\n\0" as *const u8 as *const i8,
            );
        }
        return 0 as xmlDocPtr;
    }
    buf = xmlParserInputBufferCreateFilename(filename, XML_CHAR_ENCODING_NONE);
    if buf.is_null() {
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDocPtr;
    }
    inputStream = xmlNewInputStream(ctxt);
    if inputStream.is_null() {
        xmlFreeParserInputBuffer(buf);
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDocPtr;
    }
    let fresh32 = &mut ((*inputStream).filename);
    *fresh32 = xmlCanonicPath(filename as *const xmlChar) as *mut i8;
    let fresh33 = &mut ((*inputStream).buf);
    *fresh33 = buf;
    xmlBufResetInput((*buf).buffer, inputStream);
    inputPush(ctxt, inputStream);
    if ((*ctxt).directory).is_null() {
        directory = xmlParserGetDirectory(filename);
    }
    if ((*ctxt).directory).is_null() && !directory.is_null() {
        let fresh34 = &mut ((*ctxt).directory);
        *fresh34 = directory;
    }
    (*ctxt).valid = 0 as i32;
    (*ctxt).validate = 0 as i32;
    (*ctxt).loadsubset = 0 as i32;
    (*ctxt).pedantic = 0 as i32;
    (*ctxt).dictNames = 1 as i32;
    xmlParseDocument(ctxt);
    if (*ctxt).wellFormed != 0 {
        ret = (*ctxt).myDoc;
    } else {
        ret = 0 as xmlDocPtr;
        xmlFreeDoc((*ctxt).myDoc);
        let fresh35 = &mut ((*ctxt).myDoc);
        *fresh35 = 0 as xmlDocPtr;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
unsafe extern "C" fn xmlLoadFileContent(
    mut filename: *const i8,
) -> *mut xmlChar {
    let mut fd: i32 = 0;
    let mut len: i32 = 0;
    let mut size: i64 = 0;
    let mut info: stat = stat {
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
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if filename.is_null() {
        return 0 as *mut xmlChar;
    }
    if stat(filename, &mut info) < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    fd = open(filename, 0 as i32);
    if fd < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    size = info.st_size;
    content = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )((size + 10 as i32 as i64) as size_t) as *mut xmlChar;
    if content.is_null() {
        xmlCatalogErrMemory(
            b"allocating catalog data\0" as *const u8 as *const i8,
        );
        close(fd);
        return 0 as *mut xmlChar;
    }
    len = read(fd, content as *mut libc::c_void, size as size_t) as i32;
    close(fd);
    if len < 0 as i32 {
        xmlFree.expect("non-null function pointer")(content as *mut libc::c_void);
        return 0 as *mut xmlChar;
    }
    *content.offset(len as isize) = 0 as i32 as xmlChar;
    return content;
}
unsafe extern "C" fn xmlCatalogNormalizePublic(
    mut pubID: *const xmlChar,
) -> *mut xmlChar {
    let mut ok: i32 = 1 as i32;
    let mut white: i32 = 0;
    let mut p: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut q: *mut xmlChar = 0 as *mut xmlChar;
    if pubID.is_null() {
        return 0 as *mut xmlChar;
    }
    white = 1 as i32;
    p = pubID;
    while *p as i32 != 0 as i32 && ok != 0 {
        if !(*p as i32 == 0x20 as i32
            || 0x9 as i32 <= *p as i32
                && *p as i32 <= 0xa as i32
            || *p as i32 == 0xd as i32)
        {
            white = 0 as i32;
        } else if *p as i32 == 0x20 as i32 && white == 0 {
            white = 1 as i32;
        } else {
            ok = 0 as i32;
        }
        p = p.offset(1);
    }
    if ok != 0 && white == 0 {
        return 0 as *mut xmlChar;
    }
    ret = xmlStrdup(pubID);
    q = ret;
    white = 0 as i32;
    p = pubID;
    while *p as i32 != 0 as i32 {
        if *p as i32 == 0x20 as i32
            || 0x9 as i32 <= *p as i32
                && *p as i32 <= 0xa as i32
            || *p as i32 == 0xd as i32
        {
            if q != ret {
                white = 1 as i32;
            }
        } else {
            if white != 0 {
                let fresh36 = q;
                q = q.offset(1);
                *fresh36 = 0x20 as i32 as xmlChar;
                white = 0 as i32;
            }
            let fresh37 = q;
            q = q.offset(1);
            *fresh37 = *p;
        }
        p = p.offset(1);
    }
    *q = 0 as i32 as xmlChar;
    return ret;
}
unsafe extern "C" fn xmlGetXMLCatalogEntryType(
    mut name: *const xmlChar,
) -> xmlCatalogEntryType {
    let mut type_0: xmlCatalogEntryType = XML_CATA_NONE;
    if xmlStrEqual(
        name,
        b"system\0" as *const u8 as *const i8 as *const xmlChar,
    ) != 0
    {
        type_0 = XML_CATA_SYSTEM;
    } else if xmlStrEqual(
            name,
            b"public\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = XML_CATA_PUBLIC;
    } else if xmlStrEqual(
            name,
            b"rewriteSystem\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = XML_CATA_REWRITE_SYSTEM;
    } else if xmlStrEqual(
            name,
            b"delegatePublic\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = XML_CATA_DELEGATE_PUBLIC;
    } else if xmlStrEqual(
            name,
            b"delegateSystem\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = XML_CATA_DELEGATE_SYSTEM;
    } else if xmlStrEqual(
            name,
            b"uri\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = XML_CATA_URI;
    } else if xmlStrEqual(
            name,
            b"rewriteURI\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = XML_CATA_REWRITE_URI;
    } else if xmlStrEqual(
            name,
            b"delegateURI\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = XML_CATA_DELEGATE_URI;
    } else if xmlStrEqual(
            name,
            b"nextCatalog\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = XML_CATA_NEXT_CATALOG;
    } else if xmlStrEqual(
            name,
            b"catalog\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = XML_CATA_CATALOG;
    }
    return type_0;
}
unsafe extern "C" fn xmlParseXMLCatalogOneNode(
    mut cur: xmlNodePtr,
    mut type_0: xmlCatalogEntryType,
    mut name: *const xmlChar,
    mut attrName: *const xmlChar,
    mut uriAttrName: *const xmlChar,
    mut prefer: xmlCatalogPrefer,
    mut cgroup: xmlCatalogEntryPtr,
) -> xmlCatalogEntryPtr {
    let mut ok: i32 = 1 as i32;
    let mut uriValue: *mut xmlChar = 0 as *mut xmlChar;
    let mut nameValue: *mut xmlChar = 0 as *mut xmlChar;
    let mut base: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut xmlChar = 0 as *mut xmlChar;
    let mut ret: xmlCatalogEntryPtr = 0 as xmlCatalogEntryPtr;
    if !attrName.is_null() {
        nameValue = xmlGetProp(cur as *const xmlNode, attrName);
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
    uriValue = xmlGetProp(cur as *const xmlNode, uriAttrName);
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
            xmlFree.expect("non-null function pointer")(nameValue as *mut libc::c_void);
        }
        if !uriValue.is_null() {
            xmlFree.expect("non-null function pointer")(uriValue as *mut libc::c_void);
        }
        return 0 as xmlCatalogEntryPtr;
    }
    base = xmlNodeGetBase((*cur).doc, cur as *const xmlNode);
    URL = xmlBuildURI(uriValue, base);
    if !URL.is_null() {
        if xmlDebugCatalogs > 1 as i32 {
            if !nameValue.is_null() {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Found %s: '%s' '%s'\n\0" as *const u8 as *const i8,
                    name,
                    nameValue,
                    URL,
                );
            } else {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Found %s: '%s'\n\0" as *const u8 as *const i8,
                    name,
                    URL,
                );
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
        xmlFree.expect("non-null function pointer")(nameValue as *mut libc::c_void);
    }
    if !uriValue.is_null() {
        xmlFree.expect("non-null function pointer")(uriValue as *mut libc::c_void);
    }
    if !base.is_null() {
        xmlFree.expect("non-null function pointer")(base as *mut libc::c_void);
    }
    if !URL.is_null() {
        xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void);
    }
    return ret;
}
unsafe extern "C" fn xmlParseXMLCatalogNode(
    mut cur: xmlNodePtr,
    mut prefer: xmlCatalogPrefer,
    mut parent: xmlCatalogEntryPtr,
    mut cgroup: xmlCatalogEntryPtr,
) {
    let mut base: *mut xmlChar = 0 as *mut xmlChar;
    let mut entry: xmlCatalogEntryPtr = 0 as xmlCatalogEntryPtr;
    if cur.is_null() {
        return;
    }
    if xmlStrEqual(
        (*cur).name,
        b"group\0" as *const u8 as *const i8 as *mut xmlChar,
    ) != 0
    {
        let mut prop: *mut xmlChar = 0 as *mut xmlChar;
        let mut pref: xmlCatalogPrefer = XML_CATA_PREFER_NONE;
        prop = xmlGetProp(
            cur as *const xmlNode,
            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        if !prop.is_null() {
            if xmlStrEqual(
                prop,
                b"system\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                prefer = XML_CATA_PREFER_SYSTEM;
            } else if xmlStrEqual(
                    prop,
                    b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
                {
                prefer = XML_CATA_PREFER_PUBLIC;
            } else {
                xmlCatalogErr(
                    parent,
                    cur,
                    XML_CATALOG_PREFER_VALUE as i32,
                    b"Invalid value for prefer: '%s'\n\0" as *const u8
                        as *const i8,
                    prop,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
            }
            xmlFree.expect("non-null function pointer")(prop as *mut libc::c_void);
            pref = prefer;
        }
        prop = xmlGetProp(
            cur as *const xmlNode,
            b"id\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        base = xmlGetNsProp(
            cur as *const xmlNode,
            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                as *const xmlChar,
        );
        entry = xmlNewCatalogEntry(
            XML_CATA_GROUP,
            prop,
            base,
            0 as *const xmlChar,
            pref,
            cgroup,
        );
        xmlFree.expect("non-null function pointer")(prop as *mut libc::c_void);
    } else if xmlStrEqual(
            (*cur).name,
            b"public\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
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
    } else if xmlStrEqual(
            (*cur).name,
            b"system\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
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
    } else if xmlStrEqual(
            (*cur).name,
            b"rewriteSystem\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
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
    } else if xmlStrEqual(
            (*cur).name,
            b"delegatePublic\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
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
    } else if xmlStrEqual(
            (*cur).name,
            b"delegateSystem\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
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
    } else if xmlStrEqual(
            (*cur).name,
            b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
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
    } else if xmlStrEqual(
            (*cur).name,
            b"rewriteURI\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
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
    } else if xmlStrEqual(
            (*cur).name,
            b"delegateURI\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
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
    } else if xmlStrEqual(
            (*cur).name,
            b"nextCatalog\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
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
            let fresh38 = &mut ((*entry).parent);
            *fresh38 = parent;
            if ((*parent).children).is_null() {
                let fresh39 = &mut ((*parent).children);
                *fresh39 = entry;
            } else {
                let mut prev: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
                prev = (*parent).children;
                while !((*prev).next).is_null() {
                    prev = (*prev).next;
                }
                let fresh40 = &mut ((*prev).next);
                *fresh40 = entry;
            }
        }
        if (*entry).type_0 as i32 == XML_CATA_GROUP as i32 {
            xmlParseXMLCatalogNodeList((*cur).children, prefer, parent, entry);
        }
    }
    if !base.is_null() {
        xmlFree.expect("non-null function pointer")(base as *mut libc::c_void);
    }
}
unsafe extern "C" fn xmlParseXMLCatalogNodeList(
    mut cur: xmlNodePtr,
    mut prefer: xmlCatalogPrefer,
    mut parent: xmlCatalogEntryPtr,
    mut cgroup: xmlCatalogEntryPtr,
) {
    while !cur.is_null() {
        if !((*cur).ns).is_null() && !((*(*cur).ns).href).is_null()
            && xmlStrEqual(
                (*(*cur).ns).href,
                b"urn:oasis:names:tc:entity:xmlns:xml:catalog\0" as *const u8
                    as *const i8 as *const xmlChar,
            ) != 0
        {
            xmlParseXMLCatalogNode(cur, prefer, parent, cgroup);
        }
        cur = (*cur).next;
    }
}
unsafe extern "C" fn xmlParseXMLCatalogFile(
    mut prefer: xmlCatalogPrefer,
    mut filename: *const xmlChar,
) -> xmlCatalogEntryPtr {
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut prop: *mut xmlChar = 0 as *mut xmlChar;
    let mut parent: xmlCatalogEntryPtr = 0 as xmlCatalogEntryPtr;
    if filename.is_null() {
        return 0 as xmlCatalogEntryPtr;
    }
    doc = xmlParseCatalogFile(filename as *const i8);
    if doc.is_null() {
        if xmlDebugCatalogs != 0 {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Failed to parse catalog %s\n\0" as *const u8 as *const i8,
                filename,
            );
        }
        return 0 as xmlCatalogEntryPtr;
    }
    if xmlDebugCatalogs != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"%d Parsing catalog %s\n\0" as *const u8 as *const i8,
            xmlGetThreadId(),
            filename,
        );
    }
    cur = xmlDocGetRootElement(doc as *const xmlDoc);
    if !cur.is_null()
        && xmlStrEqual(
            (*cur).name,
            b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0 && !((*cur).ns).is_null() && !((*(*cur).ns).href).is_null()
        && xmlStrEqual(
            (*(*cur).ns).href,
            b"urn:oasis:names:tc:entity:xmlns:xml:catalog\0" as *const u8
                as *const i8 as *const xmlChar,
        ) != 0
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
            xmlFreeDoc(doc);
            return 0 as xmlCatalogEntryPtr;
        }
        prop = xmlGetProp(
            cur as *const xmlNode,
            b"prefer\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        if !prop.is_null() {
            if xmlStrEqual(
                prop,
                b"system\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                prefer = XML_CATA_PREFER_SYSTEM;
            } else if xmlStrEqual(
                    prop,
                    b"public\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
                {
                prefer = XML_CATA_PREFER_PUBLIC;
            } else {
                xmlCatalogErr(
                    0 as xmlCatalogEntryPtr,
                    cur,
                    XML_CATALOG_PREFER_VALUE as i32,
                    b"Invalid value for prefer: '%s'\n\0" as *const u8
                        as *const i8,
                    prop,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
            }
            xmlFree.expect("non-null function pointer")(prop as *mut libc::c_void);
        }
        cur = (*cur).children;
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
        xmlFreeDoc(doc);
        return 0 as xmlCatalogEntryPtr;
    }
    xmlFreeDoc(doc);
    return parent;
}
unsafe extern "C" fn xmlFetchXMLCatalogFile(
    mut catal: xmlCatalogEntryPtr,
) -> i32 {
    let mut doc: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    if catal.is_null() {
        return -(1 as i32);
    }
    if ((*catal).URL).is_null() {
        return -(1 as i32);
    }
    xmlRMutexLock(xmlCatalogMutex);
    if !((*catal).children).is_null() {
        xmlRMutexUnlock(xmlCatalogMutex);
        return 0 as i32;
    }
    if !xmlCatalogXMLFiles.is_null() {
        doc = xmlHashLookup(xmlCatalogXMLFiles, (*catal).URL) as xmlCatalogEntryPtr;
        if !doc.is_null() {
            if xmlDebugCatalogs != 0 {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Found %s in file hash\n\0" as *const u8 as *const i8,
                    (*catal).URL,
                );
            }
            if (*catal).type_0 as i32 == XML_CATA_CATALOG as i32 {
                let fresh41 = &mut ((*catal).children);
                *fresh41 = (*doc).children;
            } else {
                let fresh42 = &mut ((*catal).children);
                *fresh42 = doc;
            }
            (*catal).dealloc = 0 as i32;
            xmlRMutexUnlock(xmlCatalogMutex);
            return 0 as i32;
        }
        if xmlDebugCatalogs != 0 {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"%s not found in file hash\n\0" as *const u8 as *const i8,
                (*catal).URL,
            );
        }
    }
    doc = xmlParseXMLCatalogFile((*catal).prefer, (*catal).URL);
    if doc.is_null() {
        (*catal).type_0 = XML_CATA_BROKEN_CATALOG;
        xmlRMutexUnlock(xmlCatalogMutex);
        return -(1 as i32);
    }
    if (*catal).type_0 as i32 == XML_CATA_CATALOG as i32 {
        let fresh43 = &mut ((*catal).children);
        *fresh43 = (*doc).children;
    } else {
        let fresh44 = &mut ((*catal).children);
        *fresh44 = doc;
    }
    (*doc).dealloc = 1 as i32;
    if xmlCatalogXMLFiles.is_null() {
        xmlCatalogXMLFiles = xmlHashCreate(10 as i32);
    }
    if !xmlCatalogXMLFiles.is_null() {
        if xmlDebugCatalogs != 0 {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"%s added to file hash\n\0" as *const u8 as *const i8,
                (*catal).URL,
            );
        }
        xmlHashAddEntry(xmlCatalogXMLFiles, (*catal).URL, doc as *mut libc::c_void);
    }
    xmlRMutexUnlock(xmlCatalogMutex);
    return 0 as i32;
}
unsafe extern "C" fn xmlAddXMLCatalog(
    mut catal: xmlCatalogEntryPtr,
    mut type_0: *const xmlChar,
    mut orig: *const xmlChar,
    mut replace: *const xmlChar,
) -> i32 {
    let mut cur: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    let mut typ: xmlCatalogEntryType = XML_CATA_NONE;
    let mut doregister: i32 = 0 as i32;
    if catal.is_null()
        || (*catal).type_0 as i32 != XML_CATA_CATALOG as i32
            && (*catal).type_0 as i32 != XML_CATA_BROKEN_CATALOG as i32
    {
        return -(1 as i32);
    }
    if ((*catal).children).is_null() {
        xmlFetchXMLCatalogFile(catal);
    }
    if ((*catal).children).is_null() {
        doregister = 1 as i32;
    }
    typ = xmlGetXMLCatalogEntryType(type_0);
    if typ as i32 == XML_CATA_NONE as i32 {
        if xmlDebugCatalogs != 0 {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Failed to add unknown element %s to catalog\n\0" as *const u8
                    as *const i8,
                type_0,
            );
        }
        return -(1 as i32);
    }
    cur = (*catal).children;
    if !cur.is_null() {
        while !cur.is_null() {
            if !orig.is_null() && (*cur).type_0 as i32 == typ as i32
                && xmlStrEqual(orig, (*cur).name) != 0
            {
                if xmlDebugCatalogs != 0 {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"Updating element %s to catalog\n\0" as *const u8
                            as *const i8,
                        type_0,
                    );
                }
                if !((*cur).value).is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )((*cur).value as *mut libc::c_void);
                }
                if !((*cur).URL).is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )((*cur).URL as *mut libc::c_void);
                }
                let fresh45 = &mut ((*cur).value);
                *fresh45 = xmlStrdup(replace);
                let fresh46 = &mut ((*cur).URL);
                *fresh46 = xmlStrdup(replace);
                return 0 as i32;
            }
            if ((*cur).next).is_null() {
                break;
            }
            cur = (*cur).next;
        }
    }
    if xmlDebugCatalogs != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Adding element %s to catalog\n\0" as *const u8 as *const i8,
            type_0,
        );
    }
    if cur.is_null() {
        let fresh47 = &mut ((*catal).children);
        *fresh47 = xmlNewCatalogEntry(
            typ,
            orig,
            replace,
            0 as *const xmlChar,
            (*catal).prefer,
            0 as xmlCatalogEntryPtr,
        );
    } else {
        let fresh48 = &mut ((*cur).next);
        *fresh48 = xmlNewCatalogEntry(
            typ,
            orig,
            replace,
            0 as *const xmlChar,
            (*catal).prefer,
            0 as xmlCatalogEntryPtr,
        );
    }
    if doregister != 0 {
        (*catal).type_0 = XML_CATA_CATALOG;
        cur = xmlHashLookup(xmlCatalogXMLFiles, (*catal).URL) as xmlCatalogEntryPtr;
        if !cur.is_null() {
            let fresh49 = &mut ((*cur).children);
            *fresh49 = (*catal).children;
        }
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlDelXMLCatalog(
    mut catal: xmlCatalogEntryPtr,
    mut value: *const xmlChar,
) -> i32 {
    let mut cur: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    let mut ret: i32 = 0 as i32;
    if catal.is_null()
        || (*catal).type_0 as i32 != XML_CATA_CATALOG as i32
            && (*catal).type_0 as i32 != XML_CATA_BROKEN_CATALOG as i32
    {
        return -(1 as i32);
    }
    if value.is_null() {
        return -(1 as i32);
    }
    if ((*catal).children).is_null() {
        xmlFetchXMLCatalogFile(catal);
    }
    cur = (*catal).children;
    while !cur.is_null() {
        if !((*cur).name).is_null() && xmlStrEqual(value, (*cur).name) != 0
            || xmlStrEqual(value, (*cur).value) != 0
        {
            if xmlDebugCatalogs != 0 {
                if !((*cur).name).is_null() {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"Removing element %s from catalog\n\0" as *const u8
                            as *const i8,
                        (*cur).name,
                    );
                } else {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"Removing element %s from catalog\n\0" as *const u8
                            as *const i8,
                        (*cur).value,
                    );
                }
            }
            (*cur).type_0 = XML_CATA_REMOVED;
        }
        cur = (*cur).next;
    }
    return ret;
}
unsafe extern "C" fn xmlCatalogXMLResolve(
    mut catal: xmlCatalogEntryPtr,
    mut pubID: *const xmlChar,
    mut sysID: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    let mut haveDelegate: i32 = 0 as i32;
    let mut haveNext: i32 = 0 as i32;
    if (*catal).depth > 50 as i32 {
        xmlCatalogErr(
            catal,
            0 as xmlNodePtr,
            XML_CATALOG_RECURSION as i32,
            b"Detected recursion in catalog %s\n\0" as *const u8 as *const i8,
            (*catal).name,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as *mut xmlChar;
    }
    let fresh50 = &mut ((*catal).depth);
    *fresh50 += 1;
    if !sysID.is_null() {
        let mut rewrite: xmlCatalogEntryPtr = 0 as xmlCatalogEntryPtr;
        let mut lenrewrite: i32 = 0 as i32;
        let mut len: i32 = 0;
        cur = catal;
        haveDelegate = 0 as i32;
        while !cur.is_null() {
            match (*cur).type_0 as i32 {
                6 => {
                    if xmlStrEqual(sysID, (*cur).name) != 0 {
                        if xmlDebugCatalogs != 0 {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"Found system match %s, using %s\n\0" as *const u8
                                    as *const i8,
                                (*cur).name,
                                (*cur).URL,
                            );
                        }
                        let fresh51 = &mut ((*catal).depth);
                        *fresh51 -= 1;
                        return xmlStrdup((*cur).URL);
                    }
                }
                7 => {
                    len = xmlStrlen((*cur).name);
                    if len > lenrewrite && xmlStrncmp(sysID, (*cur).name, len) == 0 {
                        lenrewrite = len;
                        rewrite = cur;
                    }
                }
                9 => {
                    if xmlStrncmp(sysID, (*cur).name, xmlStrlen((*cur).name)) == 0 {
                        haveDelegate += 1;
                    }
                }
                3 => {
                    haveNext += 1;
                }
                _ => {}
            }
            cur = (*cur).next;
        }
        if !rewrite.is_null() {
            if xmlDebugCatalogs != 0 {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Using rewriting rule %s\n\0" as *const u8 as *const i8,
                    (*rewrite).name,
                );
            }
            ret = xmlStrdup((*rewrite).URL);
            if !ret.is_null() {
                ret = xmlStrcat(ret, &*sysID.offset(lenrewrite as isize));
            }
            let fresh52 = &mut ((*catal).depth);
            *fresh52 -= 1;
            return ret;
        }
        if haveDelegate != 0 {
            let mut delegates: [*const xmlChar; 50] = [0 as *const xmlChar; 50];
            let mut nbList: i32 = 0 as i32;
            let mut i: i32 = 0;
            cur = catal;
            while !cur.is_null() {
                if (*cur).type_0 as i32
                    == XML_CATA_DELEGATE_SYSTEM as i32
                    && xmlStrncmp(sysID, (*cur).name, xmlStrlen((*cur).name)) == 0
                {
                    i = 0 as i32;
                    while i < nbList {
                        if xmlStrEqual((*cur).URL, delegates[i as usize]) != 0 {
                            break;
                        }
                        i += 1;
                    }
                    if i < nbList {
                        cur = (*cur).next;
                        continue;
                    } else {
                        if nbList < 50 as i32 {
                            let fresh53 = nbList;
                            nbList = nbList + 1;
                            delegates[fresh53 as usize] = (*cur).URL as *const u8;
                        }
                        if ((*cur).children).is_null() {
                            xmlFetchXMLCatalogFile(cur);
                        }
                        if !((*cur).children).is_null() {
                            if xmlDebugCatalogs != 0 {
                                (*__xmlGenericError())
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    *__xmlGenericErrorContext(),
                                    b"Trying system delegate %s\n\0" as *const u8
                                        as *const i8,
                                    (*cur).URL,
                                );
                            }
                            ret = xmlCatalogListXMLResolve(
                                (*cur).children,
                                0 as *const xmlChar,
                                sysID,
                            );
                            if !ret.is_null() {
                                let fresh54 = &mut ((*catal).depth);
                                *fresh54 -= 1;
                                return ret;
                            }
                        }
                    }
                }
                cur = (*cur).next;
            }
            let fresh55 = &mut ((*catal).depth);
            *fresh55 -= 1;
            return -(1 as i32) as *mut xmlChar;
        }
    }
    if !pubID.is_null() {
        cur = catal;
        haveDelegate = 0 as i32;
        while !cur.is_null() {
            match (*cur).type_0 as i32 {
                5 => {
                    if xmlStrEqual(pubID, (*cur).name) != 0 {
                        if xmlDebugCatalogs != 0 {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"Found public match %s\n\0" as *const u8
                                    as *const i8,
                                (*cur).name,
                            );
                        }
                        let fresh56 = &mut ((*catal).depth);
                        *fresh56 -= 1;
                        return xmlStrdup((*cur).URL);
                    }
                }
                8 => {
                    if xmlStrncmp(pubID, (*cur).name, xmlStrlen((*cur).name)) == 0
                        && (*cur).prefer as u32
                            == XML_CATA_PREFER_PUBLIC as i32 as u32
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
            cur = (*cur).next;
        }
        if haveDelegate != 0 {
            let mut delegates_0: [*const xmlChar; 50] = [0 as *const xmlChar; 50];
            let mut nbList_0: i32 = 0 as i32;
            let mut i_0: i32 = 0;
            cur = catal;
            while !cur.is_null() {
                if (*cur).type_0 as i32
                    == XML_CATA_DELEGATE_PUBLIC as i32
                    && (*cur).prefer as u32
                        == XML_CATA_PREFER_PUBLIC as i32 as u32
                    && xmlStrncmp(pubID, (*cur).name, xmlStrlen((*cur).name)) == 0
                {
                    i_0 = 0 as i32;
                    while i_0 < nbList_0 {
                        if xmlStrEqual((*cur).URL, delegates_0[i_0 as usize]) != 0 {
                            break;
                        }
                        i_0 += 1;
                    }
                    if i_0 < nbList_0 {
                        cur = (*cur).next;
                        continue;
                    } else {
                        if nbList_0 < 50 as i32 {
                            let fresh57 = nbList_0;
                            nbList_0 = nbList_0 + 1;
                            delegates_0[fresh57 as usize] = (*cur).URL as *const u8;
                        }
                        if ((*cur).children).is_null() {
                            xmlFetchXMLCatalogFile(cur);
                        }
                        if !((*cur).children).is_null() {
                            if xmlDebugCatalogs != 0 {
                                (*__xmlGenericError())
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    *__xmlGenericErrorContext(),
                                    b"Trying public delegate %s\n\0" as *const u8
                                        as *const i8,
                                    (*cur).URL,
                                );
                            }
                            ret = xmlCatalogListXMLResolve(
                                (*cur).children,
                                pubID,
                                0 as *const xmlChar,
                            );
                            if !ret.is_null() {
                                let fresh58 = &mut ((*catal).depth);
                                *fresh58 -= 1;
                                return ret;
                            }
                        }
                    }
                }
                cur = (*cur).next;
            }
            let fresh59 = &mut ((*catal).depth);
            *fresh59 -= 1;
            return -(1 as i32) as *mut xmlChar;
        }
    }
    if haveNext != 0 {
        cur = catal;
        while !cur.is_null() {
            if (*cur).type_0 as i32 == XML_CATA_NEXT_CATALOG as i32 {
                if ((*cur).children).is_null() {
                    xmlFetchXMLCatalogFile(cur);
                }
                if !((*cur).children).is_null() {
                    ret = xmlCatalogListXMLResolve((*cur).children, pubID, sysID);
                    if !ret.is_null() {
                        let fresh60 = &mut ((*catal).depth);
                        *fresh60 -= 1;
                        return ret;
                    } else {
                        if (*catal).depth > 50 as i32 {
                            return 0 as *mut xmlChar;
                        }
                    }
                }
            }
            cur = (*cur).next;
        }
    }
    let fresh61 = &mut ((*catal).depth);
    *fresh61 -= 1;
    return 0 as *mut xmlChar;
}
unsafe extern "C" fn xmlCatalogXMLResolveURI(
    mut catal: xmlCatalogEntryPtr,
    mut URI: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    let mut haveDelegate: i32 = 0 as i32;
    let mut haveNext: i32 = 0 as i32;
    let mut rewrite: xmlCatalogEntryPtr = 0 as xmlCatalogEntryPtr;
    let mut lenrewrite: i32 = 0 as i32;
    let mut len: i32 = 0;
    if catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if URI.is_null() {
        return 0 as *mut xmlChar;
    }
    if (*catal).depth > 50 as i32 {
        xmlCatalogErr(
            catal,
            0 as xmlNodePtr,
            XML_CATALOG_RECURSION as i32,
            b"Detected recursion in catalog %s\n\0" as *const u8 as *const i8,
            (*catal).name,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as *mut xmlChar;
    }
    cur = catal;
    haveDelegate = 0 as i32;
    while !cur.is_null() {
        match (*cur).type_0 as i32 {
            10 => {
                if xmlStrEqual(URI, (*cur).name) != 0 {
                    if xmlDebugCatalogs != 0 {
                        (*__xmlGenericError())
                            .expect(
                                "non-null function pointer",
                            )(
                            *__xmlGenericErrorContext(),
                            b"Found URI match %s\n\0" as *const u8
                                as *const i8,
                            (*cur).name,
                        );
                    }
                    return xmlStrdup((*cur).URL);
                }
            }
            11 => {
                len = xmlStrlen((*cur).name);
                if len > lenrewrite && xmlStrncmp(URI, (*cur).name, len) == 0 {
                    lenrewrite = len;
                    rewrite = cur;
                }
            }
            12 => {
                if xmlStrncmp(URI, (*cur).name, xmlStrlen((*cur).name)) == 0 {
                    haveDelegate += 1;
                }
            }
            3 => {
                haveNext += 1;
            }
            _ => {}
        }
        cur = (*cur).next;
    }
    if !rewrite.is_null() {
        if xmlDebugCatalogs != 0 {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Using rewriting rule %s\n\0" as *const u8 as *const i8,
                (*rewrite).name,
            );
        }
        ret = xmlStrdup((*rewrite).URL);
        if !ret.is_null() {
            ret = xmlStrcat(ret, &*URI.offset(lenrewrite as isize));
        }
        return ret;
    }
    if haveDelegate != 0 {
        let mut delegates: [*const xmlChar; 50] = [0 as *const xmlChar; 50];
        let mut nbList: i32 = 0 as i32;
        let mut i: i32 = 0;
        cur = catal;
        while !cur.is_null() {
            if ((*cur).type_0 as i32 == XML_CATA_DELEGATE_SYSTEM as i32
                || (*cur).type_0 as i32 == XML_CATA_DELEGATE_URI as i32)
                && xmlStrncmp(URI, (*cur).name, xmlStrlen((*cur).name)) == 0
            {
                i = 0 as i32;
                while i < nbList {
                    if xmlStrEqual((*cur).URL, delegates[i as usize]) != 0 {
                        break;
                    }
                    i += 1;
                }
                if i < nbList {
                    cur = (*cur).next;
                    continue;
                } else {
                    if nbList < 50 as i32 {
                        let fresh62 = nbList;
                        nbList = nbList + 1;
                        delegates[fresh62 as usize] = (*cur).URL as *const u8;
                    }
                    if ((*cur).children).is_null() {
                        xmlFetchXMLCatalogFile(cur);
                    }
                    if !((*cur).children).is_null() {
                        if xmlDebugCatalogs != 0 {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"Trying URI delegate %s\n\0" as *const u8
                                    as *const i8,
                                (*cur).URL,
                            );
                        }
                        ret = xmlCatalogListXMLResolveURI((*cur).children, URI);
                        if !ret.is_null() {
                            return ret;
                        }
                    }
                }
            }
            cur = (*cur).next;
        }
        return -(1 as i32) as *mut xmlChar;
    }
    if haveNext != 0 {
        cur = catal;
        while !cur.is_null() {
            if (*cur).type_0 as i32 == XML_CATA_NEXT_CATALOG as i32 {
                if ((*cur).children).is_null() {
                    xmlFetchXMLCatalogFile(cur);
                }
                if !((*cur).children).is_null() {
                    ret = xmlCatalogListXMLResolveURI((*cur).children, URI);
                    if !ret.is_null() {
                        return ret;
                    }
                }
            }
            cur = (*cur).next;
        }
    }
    return 0 as *mut xmlChar;
}
unsafe extern "C" fn xmlCatalogListXMLResolve(
    mut catal: xmlCatalogEntryPtr,
    mut pubID: *const xmlChar,
    mut sysID: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut urnID: *mut xmlChar = 0 as *mut xmlChar;
    let mut normid: *mut xmlChar = 0 as *mut xmlChar;
    if catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if pubID.is_null() && sysID.is_null() {
        return 0 as *mut xmlChar;
    }
    normid = xmlCatalogNormalizePublic(pubID);
    if !normid.is_null() {
        pubID = if *normid as i32 != 0 as i32 {
            normid
        } else {
            0 as *mut xmlChar
        };
    }
    if xmlStrncmp(
        pubID,
        b"urn:publicid:\0" as *const u8 as *const i8 as *mut xmlChar,
        (::std::mem::size_of::<[i8; 14]>() as u64)
            .wrapping_sub(1 as i32 as u64) as i32,
    ) == 0
    {
        urnID = xmlCatalogUnWrapURN(pubID);
        if xmlDebugCatalogs != 0 {
            if urnID.is_null() {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Public URN ID %s expanded to NULL\n\0" as *const u8
                        as *const i8,
                    pubID,
                );
            } else {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Public URN ID expanded to %s\n\0" as *const u8
                        as *const i8,
                    urnID,
                );
            }
        }
        ret = xmlCatalogListXMLResolve(catal, urnID, sysID);
        if !urnID.is_null() {
            xmlFree.expect("non-null function pointer")(urnID as *mut libc::c_void);
        }
        if !normid.is_null() {
            xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void);
        }
        return ret;
    }
    if xmlStrncmp(
        sysID,
        b"urn:publicid:\0" as *const u8 as *const i8 as *mut xmlChar,
        (::std::mem::size_of::<[i8; 14]>() as u64)
            .wrapping_sub(1 as i32 as u64) as i32,
    ) == 0
    {
        urnID = xmlCatalogUnWrapURN(sysID);
        if xmlDebugCatalogs != 0 {
            if urnID.is_null() {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"System URN ID %s expanded to NULL\n\0" as *const u8
                        as *const i8,
                    sysID,
                );
            } else {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"System URN ID expanded to %s\n\0" as *const u8
                        as *const i8,
                    urnID,
                );
            }
        }
        if pubID.is_null() {
            ret = xmlCatalogListXMLResolve(catal, urnID, 0 as *const xmlChar);
        } else if xmlStrEqual(pubID, urnID) != 0 {
            ret = xmlCatalogListXMLResolve(catal, pubID, 0 as *const xmlChar);
        } else {
            ret = xmlCatalogListXMLResolve(catal, pubID, urnID);
        }
        if !urnID.is_null() {
            xmlFree.expect("non-null function pointer")(urnID as *mut libc::c_void);
        }
        if !normid.is_null() {
            xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void);
        }
        return ret;
    }
    while !catal.is_null() {
        if (*catal).type_0 as i32 == XML_CATA_CATALOG as i32 {
            if ((*catal).children).is_null() {
                xmlFetchXMLCatalogFile(catal);
            }
            if !((*catal).children).is_null() {
                ret = xmlCatalogXMLResolve((*catal).children, pubID, sysID);
                if !ret.is_null() {
                    break;
                }
                if (*(*catal).children).depth > 50 as i32 {
                    ret = 0 as *mut xmlChar;
                    break;
                }
            }
        }
        catal = (*catal).next;
    }
    if !normid.is_null() {
        xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void);
    }
    return ret;
}
unsafe extern "C" fn xmlCatalogListXMLResolveURI(
    mut catal: xmlCatalogEntryPtr,
    mut URI: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut urnID: *mut xmlChar = 0 as *mut xmlChar;
    if catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if URI.is_null() {
        return 0 as *mut xmlChar;
    }
    if xmlStrncmp(
        URI,
        b"urn:publicid:\0" as *const u8 as *const i8 as *mut xmlChar,
        (::std::mem::size_of::<[i8; 14]>() as u64)
            .wrapping_sub(1 as i32 as u64) as i32,
    ) == 0
    {
        urnID = xmlCatalogUnWrapURN(URI);
        if xmlDebugCatalogs != 0 {
            if urnID.is_null() {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"URN ID %s expanded to NULL\n\0" as *const u8
                        as *const i8,
                    URI,
                );
            } else {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"URN ID expanded to %s\n\0" as *const u8 as *const i8,
                    urnID,
                );
            }
        }
        ret = xmlCatalogListXMLResolve(catal, urnID, 0 as *const xmlChar);
        if !urnID.is_null() {
            xmlFree.expect("non-null function pointer")(urnID as *mut libc::c_void);
        }
        return ret;
    }
    while !catal.is_null() {
        if (*catal).type_0 as i32 == XML_CATA_CATALOG as i32 {
            if ((*catal).children).is_null() {
                xmlFetchXMLCatalogFile(catal);
            }
            if !((*catal).children).is_null() {
                ret = xmlCatalogXMLResolveURI((*catal).children, URI);
                if !ret.is_null() {
                    return ret;
                }
            }
        }
        catal = (*catal).next;
    }
    return ret;
}
unsafe extern "C" fn xmlParseSGMLCatalogComment(
    mut cur: *const xmlChar,
) -> *const xmlChar {
    if *cur.offset(0 as i32 as isize) as i32 != '-' as i32
        || *cur.offset(1 as i32 as isize) as i32 != '-' as i32
    {
        return cur;
    }
    cur = cur.offset(2 as i32 as isize);
    while *cur.offset(0 as i32 as isize) as i32 != 0 as i32
        && (*cur.offset(0 as i32 as isize) as i32 != '-' as i32
            || *cur.offset(1 as i32 as isize) as i32 != '-' as i32)
    {
        cur = cur.offset(1);
    }
    if *cur.offset(0 as i32 as isize) as i32 == 0 as i32 {
        return 0 as *const xmlChar;
    }
    return cur.offset(2 as i32 as isize);
}
unsafe extern "C" fn xmlParseSGMLCatalogPubid(
    mut cur: *const xmlChar,
    mut id: *mut *mut xmlChar,
) -> *const xmlChar {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 50 as i32;
    let mut stop: xmlChar = 0;
    let mut count: i32 = 0 as i32;
    *id = 0 as *mut xmlChar;
    if *cur as i32 == '"' as i32 {
        cur = cur.offset(1);
        stop = '"' as i32 as xmlChar;
    } else if *cur as i32 == '\'' as i32 {
        cur = cur.offset(1);
        stop = '\'' as i32 as xmlChar;
    } else {
        stop = ' ' as i32 as xmlChar;
    }
    buf = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (size as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) as *mut xmlChar;
    if buf.is_null() {
        xmlCatalogErrMemory(
            b"allocating public ID\0" as *const u8 as *const i8,
        );
        return 0 as *const xmlChar;
    }
    while xmlIsPubidChar_tab[*cur as usize] as i32 != 0
        || *cur as i32 == '?' as i32
    {
        if *cur as i32 == stop as i32
            && stop as i32 != ' ' as i32
        {
            break;
        }
        if stop as i32 == ' ' as i32
            && (*cur as i32 == 0x20 as i32
                || 0x9 as i32 <= *cur as i32
                    && *cur as i32 <= 0xa as i32
                || *cur as i32 == 0xd as i32)
        {
            break;
        }
        if len + 1 as i32 >= size {
            size *= 2 as i32;
            tmp = xmlRealloc
                .expect(
                    "non-null function pointer",
                )(
                buf as *mut libc::c_void,
                (size as u64)
                    .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) as *mut xmlChar;
            if tmp.is_null() {
                xmlCatalogErrMemory(
                    b"allocating public ID\0" as *const u8 as *const i8,
                );
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return 0 as *const xmlChar;
            }
            buf = tmp;
        }
        let fresh63 = len;
        len = len + 1;
        *buf.offset(fresh63 as isize) = *cur;
        count += 1;
        cur = cur.offset(1);
    }
    *buf.offset(len as isize) = 0 as i32 as xmlChar;
    if stop as i32 == ' ' as i32 {
        if !(*cur as i32 == 0x20 as i32
            || 0x9 as i32 <= *cur as i32
                && *cur as i32 <= 0xa as i32
            || *cur as i32 == 0xd as i32)
        {
            xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
            return 0 as *const xmlChar;
        }
    } else {
        if *cur as i32 != stop as i32 {
            xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
            return 0 as *const xmlChar;
        }
        cur = cur.offset(1);
    }
    *id = buf;
    return cur;
}
unsafe extern "C" fn xmlParseSGMLCatalogName(
    mut cur: *const xmlChar,
    mut name: *mut *mut xmlChar,
) -> *const xmlChar {
    let mut buf: [xmlChar; 105] = [0; 105];
    let mut len: i32 = 0 as i32;
    let mut c: i32 = 0;
    *name = 0 as *mut xmlChar;
    c = *cur as i32;
    if !((if c < 0x100 as i32 {
        (0x41 as i32 <= c && c <= 0x5a as i32
            || 0x61 as i32 <= c && c <= 0x7a as i32
            || 0xc0 as i32 <= c && c <= 0xd6 as i32
            || 0xd8 as i32 <= c && c <= 0xf6 as i32
            || 0xf8 as i32 <= c) as i32
    } else {
        xmlCharInRange(c as u32, &xmlIsBaseCharGroup)
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32)
                as i32
        }) != 0) && c != '_' as i32 && c != ':' as i32
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
        xmlCharInRange(c as u32, &xmlIsBaseCharGroup)
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32)
                as i32
        }) != 0
        || (if c < 0x100 as i32 {
            (0x30 as i32 <= c && c <= 0x39 as i32) as i32
        } else {
            xmlCharInRange(c as u32, &xmlIsDigitGroup)
        }) != 0 || c == '.' as i32 || c == '-' as i32 || c == '_' as i32
        || c == ':' as i32
    {
        let fresh64 = len;
        len = len + 1;
        buf[fresh64 as usize] = c as xmlChar;
        cur = cur.offset(1);
        c = *cur as i32;
        if len >= 100 as i32 {
            return 0 as *const xmlChar;
        }
    }
    *name = xmlStrndup(buf.as_mut_ptr(), len);
    return cur;
}
unsafe extern "C" fn xmlGetSGMLCatalogEntryType(
    mut name: *const xmlChar,
) -> xmlCatalogEntryType {
    let mut type_0: xmlCatalogEntryType = XML_CATA_NONE;
    if xmlStrEqual(
        name,
        b"SYSTEM\0" as *const u8 as *const i8 as *const xmlChar,
    ) != 0
    {
        type_0 = SGML_CATA_SYSTEM;
    } else if xmlStrEqual(
            name,
            b"PUBLIC\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = SGML_CATA_PUBLIC;
    } else if xmlStrEqual(
            name,
            b"DELEGATE\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = SGML_CATA_DELEGATE;
    } else if xmlStrEqual(
            name,
            b"ENTITY\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = SGML_CATA_ENTITY;
    } else if xmlStrEqual(
            name,
            b"DOCTYPE\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = SGML_CATA_DOCTYPE;
    } else if xmlStrEqual(
            name,
            b"LINKTYPE\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = SGML_CATA_LINKTYPE;
    } else if xmlStrEqual(
            name,
            b"NOTATION\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = SGML_CATA_NOTATION;
    } else if xmlStrEqual(
            name,
            b"SGMLDECL\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = SGML_CATA_SGMLDECL;
    } else if xmlStrEqual(
            name,
            b"DOCUMENT\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = SGML_CATA_DOCUMENT;
    } else if xmlStrEqual(
            name,
            b"CATALOG\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = SGML_CATA_CATALOG;
    } else if xmlStrEqual(
            name,
            b"BASE\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
        type_0 = SGML_CATA_BASE;
    }
    return type_0;
}
unsafe extern "C" fn xmlParseSGMLCatalog(
    mut catal: xmlCatalogPtr,
    mut value: *const xmlChar,
    mut file: *const i8,
    mut super_0: i32,
) -> i32 {
    let mut cur: *const xmlChar = value;
    let mut base: *mut xmlChar = 0 as *mut xmlChar;
    let mut res: i32 = 0;
    if cur.is_null() || file.is_null() {
        return -(1 as i32);
    }
    base = xmlStrdup(file as *const xmlChar);
    while !cur.is_null()
        && *cur.offset(0 as i32 as isize) as i32 != 0 as i32
    {
        while *cur as i32 == 0x20 as i32
            || 0x9 as i32 <= *cur as i32
                && *cur as i32 <= 0xa as i32
            || *cur as i32 == 0xd as i32
        {
            cur = cur.offset(1);
        }
        if *cur.offset(0 as i32 as isize) as i32 == 0 as i32 {
            break;
        }
        if *cur.offset(0 as i32 as isize) as i32 == '-' as i32
            && *cur.offset(1 as i32 as isize) as i32 == '-' as i32
        {
            cur = xmlParseSGMLCatalogComment(cur);
            if !cur.is_null() {
                continue;
            }
            break;
        } else {
            let mut sysid: *mut xmlChar = 0 as *mut xmlChar;
            let mut name: *mut xmlChar = 0 as *mut xmlChar;
            let mut type_0: xmlCatalogEntryType = XML_CATA_NONE;
            cur = xmlParseSGMLCatalogName(cur, &mut name);
            if cur.is_null() || name.is_null() {
                break;
            } else if !(*cur as i32 == 0x20 as i32
                    || 0x9 as i32 <= *cur as i32
                        && *cur as i32 <= 0xa as i32
                    || *cur as i32 == 0xd as i32)
                {
                xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
                break;
            } else {
                while *cur as i32 == 0x20 as i32
                    || 0x9 as i32 <= *cur as i32
                        && *cur as i32 <= 0xa as i32
                    || *cur as i32 == 0xd as i32
                {
                    cur = cur.offset(1);
                }
                if xmlStrEqual(
                    name,
                    b"SYSTEM\0" as *const u8 as *const i8 as *const xmlChar,
                ) != 0
                {
                    type_0 = SGML_CATA_SYSTEM;
                } else if xmlStrEqual(
                        name,
                        b"PUBLIC\0" as *const u8 as *const i8 as *const xmlChar,
                    ) != 0
                    {
                    type_0 = SGML_CATA_PUBLIC;
                } else if xmlStrEqual(
                        name,
                        b"DELEGATE\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) != 0
                    {
                    type_0 = SGML_CATA_DELEGATE;
                } else if xmlStrEqual(
                        name,
                        b"ENTITY\0" as *const u8 as *const i8 as *const xmlChar,
                    ) != 0
                    {
                    type_0 = SGML_CATA_ENTITY;
                } else if xmlStrEqual(
                        name,
                        b"DOCTYPE\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) != 0
                    {
                    type_0 = SGML_CATA_DOCTYPE;
                } else if xmlStrEqual(
                        name,
                        b"LINKTYPE\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) != 0
                    {
                    type_0 = SGML_CATA_LINKTYPE;
                } else if xmlStrEqual(
                        name,
                        b"NOTATION\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) != 0
                    {
                    type_0 = SGML_CATA_NOTATION;
                } else if xmlStrEqual(
                        name,
                        b"SGMLDECL\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) != 0
                    {
                    type_0 = SGML_CATA_SGMLDECL;
                } else if xmlStrEqual(
                        name,
                        b"DOCUMENT\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) != 0
                    {
                    type_0 = SGML_CATA_DOCUMENT;
                } else if xmlStrEqual(
                        name,
                        b"CATALOG\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) != 0
                    {
                    type_0 = SGML_CATA_CATALOG;
                } else if xmlStrEqual(
                        name,
                        b"BASE\0" as *const u8 as *const i8 as *const xmlChar,
                    ) != 0
                    {
                    type_0 = SGML_CATA_BASE;
                } else if xmlStrEqual(
                        name,
                        b"OVERRIDE\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) != 0
                    {
                    xmlFree
                        .expect("non-null function pointer")(name as *mut libc::c_void);
                    cur = xmlParseSGMLCatalogName(cur, &mut name);
                    if name.is_null() {
                        break;
                    }
                    xmlFree
                        .expect("non-null function pointer")(name as *mut libc::c_void);
                    continue;
                }
                xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
                name = 0 as *mut xmlChar;
                let mut current_block_56: u64;
                match type_0 as i32 {
                    15 => {
                        if *cur as i32 == '%' as i32 {
                            type_0 = SGML_CATA_PENTITY;
                        }
                        current_block_56 = 11907492662621709349;
                    }
                    16 | 17 | 18 | 19 => {
                        current_block_56 = 11907492662621709349;
                    }
                    14 | 13 | 20 => {
                        cur = xmlParseSGMLCatalogPubid(cur, &mut name);
                        if !cur.is_null() {
                            if type_0 as i32 != SGML_CATA_SYSTEM as i32 {
                                let mut normid: *mut xmlChar = 0 as *mut xmlChar;
                                normid = xmlCatalogNormalizePublic(name);
                                if !normid.is_null() {
                                    if !name.is_null() {
                                        xmlFree
                                            .expect(
                                                "non-null function pointer",
                                            )(name as *mut libc::c_void);
                                    }
                                    if *normid as i32 != 0 as i32 {
                                        name = normid;
                                    } else {
                                        xmlFree
                                            .expect(
                                                "non-null function pointer",
                                            )(normid as *mut libc::c_void);
                                        name = 0 as *mut xmlChar;
                                    }
                                }
                            }
                            if *cur as i32 == 0x20 as i32
                                || 0x9 as i32 <= *cur as i32
                                    && *cur as i32 <= 0xa as i32
                                || *cur as i32 == 0xd as i32
                            {
                                while *cur as i32 == 0x20 as i32
                                    || 0x9 as i32 <= *cur as i32
                                        && *cur as i32 <= 0xa as i32
                                    || *cur as i32 == 0xd as i32
                                {
                                    cur = cur.offset(1);
                                }
                                cur = xmlParseSGMLCatalogPubid(cur, &mut sysid);
                                cur.is_null();
                            }
                        }
                        current_block_56 = 6014157347423944569;
                    }
                    21 | 22 | 23 | 24 => {
                        cur = xmlParseSGMLCatalogPubid(cur, &mut sysid);
                        cur.is_null();
                        current_block_56 = 6014157347423944569;
                    }
                    _ => {
                        current_block_56 = 6014157347423944569;
                    }
                }
                match current_block_56 {
                    11907492662621709349 => {
                        cur = xmlParseSGMLCatalogName(cur, &mut name);
                        if !cur.is_null() {
                            if *cur as i32 == 0x20 as i32
                                || 0x9 as i32 <= *cur as i32
                                    && *cur as i32 <= 0xa as i32
                                || *cur as i32 == 0xd as i32
                            {
                                while *cur as i32 == 0x20 as i32
                                    || 0x9 as i32 <= *cur as i32
                                        && *cur as i32 <= 0xa as i32
                                    || *cur as i32 == 0xd as i32
                                {
                                    cur = cur.offset(1);
                                }
                                cur = xmlParseSGMLCatalogPubid(cur, &mut sysid);
                                cur.is_null();
                            }
                        }
                    }
                    _ => {}
                }
                if cur.is_null() {
                    if !name.is_null() {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(name as *mut libc::c_void);
                    }
                    if !sysid.is_null() {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(sysid as *mut libc::c_void);
                    }
                    break;
                } else {
                    if type_0 as i32 == SGML_CATA_BASE as i32 {
                        if !base.is_null() {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(base as *mut libc::c_void);
                        }
                        base = xmlStrdup(sysid);
                    } else if type_0 as i32 == SGML_CATA_PUBLIC as i32
                            || type_0 as i32 == SGML_CATA_SYSTEM as i32
                        {
                        let mut filename: *mut xmlChar = 0 as *mut xmlChar;
                        filename = xmlBuildURI(sysid, base);
                        if !filename.is_null() {
                            let mut entry: xmlCatalogEntryPtr = 0
                                as *mut xmlCatalogEntry;
                            entry = xmlNewCatalogEntry(
                                type_0,
                                name,
                                filename,
                                0 as *const xmlChar,
                                XML_CATA_PREFER_NONE,
                                0 as xmlCatalogEntryPtr,
                            );
                            res = xmlHashAddEntry(
                                (*catal).sgml,
                                name,
                                entry as *mut libc::c_void,
                            );
                            if res < 0 as i32 {
                                xmlFreeCatalogEntry(
                                    entry as *mut libc::c_void,
                                    0 as *const xmlChar,
                                );
                            }
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(filename as *mut libc::c_void);
                        }
                    } else if type_0 as i32 == SGML_CATA_CATALOG as i32 {
                        if super_0 != 0 {
                            let mut entry_0: xmlCatalogEntryPtr = 0
                                as *mut xmlCatalogEntry;
                            entry_0 = xmlNewCatalogEntry(
                                type_0,
                                sysid,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                                XML_CATA_PREFER_NONE,
                                0 as xmlCatalogEntryPtr,
                            );
                            res = xmlHashAddEntry(
                                (*catal).sgml,
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
                            let mut filename_0: *mut xmlChar = 0 as *mut xmlChar;
                            filename_0 = xmlBuildURI(sysid, base);
                            if !filename_0.is_null() {
                                xmlExpandCatalog(catal, filename_0 as *const i8);
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(filename_0 as *mut libc::c_void);
                            }
                        }
                    }
                    if !name.is_null() {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(name as *mut libc::c_void);
                    }
                    if !sysid.is_null() {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(sysid as *mut libc::c_void);
                    }
                }
            }
        }
    }
    if !base.is_null() {
        xmlFree.expect("non-null function pointer")(base as *mut libc::c_void);
    }
    if cur.is_null() {
        return -(1 as i32);
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlCatalogGetSGMLPublic(
    mut catal: xmlHashTablePtr,
    mut pubID: *const xmlChar,
) -> *const xmlChar {
    let mut entry: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    let mut normid: *mut xmlChar = 0 as *mut xmlChar;
    if catal.is_null() {
        return 0 as *const xmlChar;
    }
    normid = xmlCatalogNormalizePublic(pubID);
    if !normid.is_null() {
        pubID = if *normid as i32 != 0 as i32 {
            normid
        } else {
            0 as *mut xmlChar
        };
    }
    entry = xmlHashLookup(catal, pubID) as xmlCatalogEntryPtr;
    if entry.is_null() {
        if !normid.is_null() {
            xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void);
        }
        return 0 as *const xmlChar;
    }
    if (*entry).type_0 as i32 == SGML_CATA_PUBLIC as i32 {
        if !normid.is_null() {
            xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void);
        }
        return (*entry).URL;
    }
    if !normid.is_null() {
        xmlFree.expect("non-null function pointer")(normid as *mut libc::c_void);
    }
    return 0 as *const xmlChar;
}
unsafe extern "C" fn xmlCatalogGetSGMLSystem(
    mut catal: xmlHashTablePtr,
    mut sysID: *const xmlChar,
) -> *const xmlChar {
    let mut entry: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    if catal.is_null() {
        return 0 as *const xmlChar;
    }
    entry = xmlHashLookup(catal, sysID) as xmlCatalogEntryPtr;
    if entry.is_null() {
        return 0 as *const xmlChar;
    }
    if (*entry).type_0 as i32 == SGML_CATA_SYSTEM as i32 {
        return (*entry).URL;
    }
    return 0 as *const xmlChar;
}
unsafe extern "C" fn xmlCatalogSGMLResolve(
    mut catal: xmlCatalogPtr,
    mut pubID: *const xmlChar,
    mut sysID: *const xmlChar,
) -> *const xmlChar {
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    if ((*catal).sgml).is_null() {
        return 0 as *const xmlChar;
    }
    if !pubID.is_null() {
        ret = xmlCatalogGetSGMLPublic((*catal).sgml, pubID);
    }
    if !ret.is_null() {
        return ret;
    }
    if !sysID.is_null() {
        ret = xmlCatalogGetSGMLSystem((*catal).sgml, sysID);
    }
    if !ret.is_null() {
        return ret;
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlLoadSGMLSuperCatalog(
    mut filename: *const i8,
) -> xmlCatalogPtr {
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut ret: i32 = 0;
    content = xmlLoadFileContent(filename);
    if content.is_null() {
        return 0 as xmlCatalogPtr;
    }
    catal = xmlCreateNewCatalog(XML_SGML_CATALOG_TYPE, xmlCatalogDefaultPrefer);
    if catal.is_null() {
        xmlFree.expect("non-null function pointer")(content as *mut libc::c_void);
        return 0 as xmlCatalogPtr;
    }
    ret = xmlParseSGMLCatalog(catal, content, filename, 1 as i32);
    xmlFree.expect("non-null function pointer")(content as *mut libc::c_void);
    if ret < 0 as i32 {
        xmlFreeCatalog(catal);
        return 0 as xmlCatalogPtr;
    }
    return catal;
}
#[no_mangle]
pub unsafe extern "C" fn xmlLoadACatalog(
    mut filename: *const i8,
) -> xmlCatalogPtr {
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut first: *mut xmlChar = 0 as *mut xmlChar;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut ret: i32 = 0;
    content = xmlLoadFileContent(filename);
    if content.is_null() {
        return 0 as xmlCatalogPtr;
    }
    first = content;
    while *first as i32 != 0 as i32
        && *first as i32 != '-' as i32 && *first as i32 != '<' as i32
        && !(*first as i32 >= 'A' as i32 && *first as i32 <= 'Z' as i32
            || *first as i32 >= 'a' as i32
                && *first as i32 <= 'z' as i32)
    {
        first = first.offset(1);
    }
    if *first as i32 != '<' as i32 {
        catal = xmlCreateNewCatalog(XML_SGML_CATALOG_TYPE, xmlCatalogDefaultPrefer);
        if catal.is_null() {
            xmlFree.expect("non-null function pointer")(content as *mut libc::c_void);
            return 0 as xmlCatalogPtr;
        }
        ret = xmlParseSGMLCatalog(catal, content, filename, 0 as i32);
        if ret < 0 as i32 {
            xmlFreeCatalog(catal);
            xmlFree.expect("non-null function pointer")(content as *mut libc::c_void);
            return 0 as xmlCatalogPtr;
        }
    } else {
        catal = xmlCreateNewCatalog(XML_XML_CATALOG_TYPE, xmlCatalogDefaultPrefer);
        if catal.is_null() {
            xmlFree.expect("non-null function pointer")(content as *mut libc::c_void);
            return 0 as xmlCatalogPtr;
        }
        let fresh65 = &mut ((*catal).xml);
        *fresh65 = xmlNewCatalogEntry(
            XML_CATA_CATALOG,
            0 as *const xmlChar,
            0 as *const xmlChar,
            filename as *mut xmlChar,
            xmlCatalogDefaultPrefer,
            0 as xmlCatalogEntryPtr,
        );
    }
    xmlFree.expect("non-null function pointer")(content as *mut libc::c_void);
    return catal;
}
unsafe extern "C" fn xmlExpandCatalog(
    mut catal: xmlCatalogPtr,
    mut filename: *const i8,
) -> i32 {
    let mut ret: i32 = 0;
    if catal.is_null() || filename.is_null() {
        return -(1 as i32);
    }
    if (*catal).type_0 as u32
        == XML_SGML_CATALOG_TYPE as i32 as u32
    {
        let mut content: *mut xmlChar = 0 as *mut xmlChar;
        content = xmlLoadFileContent(filename);
        if content.is_null() {
            return -(1 as i32);
        }
        ret = xmlParseSGMLCatalog(catal, content, filename, 0 as i32);
        if ret < 0 as i32 {
            xmlFree.expect("non-null function pointer")(content as *mut libc::c_void);
            return -(1 as i32);
        }
        xmlFree.expect("non-null function pointer")(content as *mut libc::c_void);
    } else {
        let mut tmp: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
        let mut cur: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
        tmp = xmlNewCatalogEntry(
            XML_CATA_CATALOG,
            0 as *const xmlChar,
            0 as *const xmlChar,
            filename as *mut xmlChar,
            xmlCatalogDefaultPrefer,
            0 as xmlCatalogEntryPtr,
        );
        cur = (*catal).xml;
        if cur.is_null() {
            let fresh66 = &mut ((*catal).xml);
            *fresh66 = tmp;
        } else {
            while !((*cur).next).is_null() {
                cur = (*cur).next;
            }
            let fresh67 = &mut ((*cur).next);
            *fresh67 = tmp;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlACatalogResolveSystem(
    mut catal: xmlCatalogPtr,
    mut sysID: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if sysID.is_null() || catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if xmlDebugCatalogs != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Resolve sysID %s\n\0" as *const u8 as *const i8,
            sysID,
        );
    }
    if (*catal).type_0 as u32
        == XML_XML_CATALOG_TYPE as i32 as u32
    {
        ret = xmlCatalogListXMLResolve((*catal).xml, 0 as *const xmlChar, sysID);
        if ret == -(1 as i32) as *mut xmlChar {
            ret = 0 as *mut xmlChar;
        }
    } else {
        let mut sgml: *const xmlChar = 0 as *const xmlChar;
        sgml = xmlCatalogGetSGMLSystem((*catal).sgml, sysID);
        if !sgml.is_null() {
            ret = xmlStrdup(sgml);
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlACatalogResolvePublic(
    mut catal: xmlCatalogPtr,
    mut pubID: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if pubID.is_null() || catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if xmlDebugCatalogs != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Resolve pubID %s\n\0" as *const u8 as *const i8,
            pubID,
        );
    }
    if (*catal).type_0 as u32
        == XML_XML_CATALOG_TYPE as i32 as u32
    {
        ret = xmlCatalogListXMLResolve((*catal).xml, pubID, 0 as *const xmlChar);
        if ret == -(1 as i32) as *mut xmlChar {
            ret = 0 as *mut xmlChar;
        }
    } else {
        let mut sgml: *const xmlChar = 0 as *const xmlChar;
        sgml = xmlCatalogGetSGMLPublic((*catal).sgml, pubID);
        if !sgml.is_null() {
            ret = xmlStrdup(sgml);
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlACatalogResolve(
    mut catal: xmlCatalogPtr,
    mut pubID: *const xmlChar,
    mut sysID: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if pubID.is_null() && sysID.is_null() || catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if xmlDebugCatalogs != 0 {
        if !pubID.is_null() && !sysID.is_null() {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Resolve: pubID %s sysID %s\n\0" as *const u8 as *const i8,
                pubID,
                sysID,
            );
        } else if !pubID.is_null() {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Resolve: pubID %s\n\0" as *const u8 as *const i8,
                pubID,
            );
        } else {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Resolve: sysID %s\n\0" as *const u8 as *const i8,
                sysID,
            );
        }
    }
    if (*catal).type_0 as u32
        == XML_XML_CATALOG_TYPE as i32 as u32
    {
        ret = xmlCatalogListXMLResolve((*catal).xml, pubID, sysID);
        if ret == -(1 as i32) as *mut xmlChar {
            ret = 0 as *mut xmlChar;
        }
    } else {
        let mut sgml: *const xmlChar = 0 as *const xmlChar;
        sgml = xmlCatalogSGMLResolve(catal, pubID, sysID);
        if !sgml.is_null() {
            ret = xmlStrdup(sgml);
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlACatalogResolveURI(
    mut catal: xmlCatalogPtr,
    mut URI: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if URI.is_null() || catal.is_null() {
        return 0 as *mut xmlChar;
    }
    if xmlDebugCatalogs != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Resolve URI %s\n\0" as *const u8 as *const i8,
            URI,
        );
    }
    if (*catal).type_0 as u32
        == XML_XML_CATALOG_TYPE as i32 as u32
    {
        ret = xmlCatalogListXMLResolveURI((*catal).xml, URI);
        if ret == -(1 as i32) as *mut xmlChar {
            ret = 0 as *mut xmlChar;
        }
    } else {
        let mut sgml: *const xmlChar = 0 as *const xmlChar;
        sgml = xmlCatalogSGMLResolve(catal, 0 as *const xmlChar, URI);
        if !sgml.is_null() {
            ret = xmlStrdup(sgml);
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlACatalogDump(mut catal: xmlCatalogPtr, mut out: *mut FILE) {
    if out.is_null() || catal.is_null() {
        return;
    }
    if (*catal).type_0 as u32
        == XML_XML_CATALOG_TYPE as i32 as u32
    {
        xmlDumpXMLCatalog(out, (*catal).xml);
    } else {
        xmlHashScan(
            (*catal).sgml,
            Some(
                xmlCatalogDumpEntry
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> (),
            ),
            out as *mut libc::c_void,
        );
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlACatalogAdd(
    mut catal: xmlCatalogPtr,
    mut type_0: *const xmlChar,
    mut orig: *const xmlChar,
    mut replace: *const xmlChar,
) -> i32 {
    let mut res: i32 = -(1 as i32);
    if catal.is_null() {
        return -(1 as i32);
    }
    if (*catal).type_0 as u32
        == XML_XML_CATALOG_TYPE as i32 as u32
    {
        res = xmlAddXMLCatalog((*catal).xml, type_0, orig, replace);
    } else {
        let mut cattype: xmlCatalogEntryType = XML_CATA_NONE;
        cattype = xmlGetSGMLCatalogEntryType(type_0);
        if cattype as i32 != XML_CATA_NONE as i32 {
            let mut entry: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
            entry = xmlNewCatalogEntry(
                cattype,
                orig,
                replace,
                0 as *const xmlChar,
                XML_CATA_PREFER_NONE,
                0 as xmlCatalogEntryPtr,
            );
            if ((*catal).sgml).is_null() {
                let fresh68 = &mut ((*catal).sgml);
                *fresh68 = xmlHashCreate(10 as i32);
            }
            res = xmlHashAddEntry((*catal).sgml, orig, entry as *mut libc::c_void);
        }
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlACatalogRemove(
    mut catal: xmlCatalogPtr,
    mut value: *const xmlChar,
) -> i32 {
    let mut res: i32 = -(1 as i32);
    if catal.is_null() || value.is_null() {
        return -(1 as i32);
    }
    if (*catal).type_0 as u32
        == XML_XML_CATALOG_TYPE as i32 as u32
    {
        res = xmlDelXMLCatalog((*catal).xml, value);
    } else {
        res = xmlHashRemoveEntry(
            (*catal).sgml,
            value,
            Some(
                xmlFreeCatalogEntry
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
        );
        if res == 0 as i32 {
            res = 1 as i32;
        }
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewCatalog(mut sgml: i32) -> xmlCatalogPtr {
    let mut catal: xmlCatalogPtr = 0 as xmlCatalogPtr;
    if sgml != 0 {
        catal = xmlCreateNewCatalog(XML_SGML_CATALOG_TYPE, xmlCatalogDefaultPrefer);
        if !catal.is_null() && ((*catal).sgml).is_null() {
            let fresh69 = &mut ((*catal).sgml);
            *fresh69 = xmlHashCreate(10 as i32);
        }
    } else {
        catal = xmlCreateNewCatalog(XML_XML_CATALOG_TYPE, xmlCatalogDefaultPrefer);
    }
    return catal;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogIsEmpty(mut catal: xmlCatalogPtr) -> i32 {
    if catal.is_null() {
        return -(1 as i32);
    }
    if (*catal).type_0 as u32
        == XML_XML_CATALOG_TYPE as i32 as u32
    {
        if ((*catal).xml).is_null() {
            return 1 as i32;
        }
        if (*(*catal).xml).type_0 as i32 != XML_CATA_CATALOG as i32
            && (*(*catal).xml).type_0 as i32
                != XML_CATA_BROKEN_CATALOG as i32
        {
            return -(1 as i32);
        }
        if ((*(*catal).xml).children).is_null() {
            return 1 as i32;
        }
        return 0 as i32;
    } else {
        let mut res: i32 = 0;
        if ((*catal).sgml).is_null() {
            return 1 as i32;
        }
        res = xmlHashSize((*catal).sgml);
        if res == 0 as i32 {
            return 1 as i32;
        }
        if res < 0 as i32 {
            return -(1 as i32);
        }
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlInitializeCatalogData() {
    if xmlCatalogInitialized != 0 as i32 {
        return;
    }
    if !(getenv(b"XML_DEBUG_CATALOG\0" as *const u8 as *const i8)).is_null() {
        xmlDebugCatalogs = 1 as i32;
    }
    xmlCatalogMutex = xmlNewRMutex();
    xmlCatalogInitialized = 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlInitializeCatalog() {
    if xmlCatalogInitialized != 0 as i32 {
        return;
    }
    xmlInitializeCatalogData();
    xmlRMutexLock(xmlCatalogMutex);
    if !(getenv(b"XML_DEBUG_CATALOG\0" as *const u8 as *const i8)).is_null() {
        xmlDebugCatalogs = 1 as i32;
    }
    if xmlDefaultCatalog.is_null() {
        let mut catalogs: *const i8 = 0 as *const i8;
        let mut path: *mut i8 = 0 as *mut i8;
        let mut cur: *const i8 = 0 as *const i8;
        let mut paths: *const i8 = 0 as *const i8;
        let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
        let mut nextent: *mut xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntryPtr;
        catalogs = getenv(b"XML_CATALOG_FILES\0" as *const u8 as *const i8)
            as *const i8;
        if catalogs.is_null() {
            catalogs = b"file:///usr/local/etc/xml/catalog\0" as *const u8
                as *const i8;
        }
        catal = xmlCreateNewCatalog(XML_XML_CATALOG_TYPE, xmlCatalogDefaultPrefer);
        if !catal.is_null() {
            cur = catalogs;
            nextent = &mut (*catal).xml;
            while *cur as i32 != '\u{0}' as i32 {
                while *cur as i32 == 0x20 as i32
                    || 0x9 as i32 <= *cur as i32
                        && *cur as i32 <= 0xa as i32
                    || *cur as i32 == 0xd as i32
                {
                    cur = cur.offset(1);
                }
                if *cur as i32 != 0 as i32 {
                    paths = cur;
                    while *cur as i32 != 0 as i32
                        && !(*cur as i32 == 0x20 as i32
                            || 0x9 as i32 <= *cur as i32
                                && *cur as i32 <= 0xa as i32
                            || *cur as i32 == 0xd as i32)
                    {
                        cur = cur.offset(1);
                    }
                    path = xmlStrndup(
                        paths as *const xmlChar,
                        cur.offset_from(paths) as i64 as i32,
                    ) as *mut i8;
                    if !path.is_null() {
                        *nextent = xmlNewCatalogEntry(
                            XML_CATA_CATALOG,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                            path as *mut xmlChar,
                            xmlCatalogDefaultPrefer,
                            0 as xmlCatalogEntryPtr,
                        );
                        if !(*nextent).is_null() {
                            nextent = &mut (**nextent).next;
                        }
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(path as *mut libc::c_void);
                    }
                }
            }
            xmlDefaultCatalog = catal;
        }
    }
    xmlRMutexUnlock(xmlCatalogMutex);
}
#[no_mangle]
pub unsafe extern "C" fn xmlLoadCatalog(
    mut filename: *const i8,
) -> i32 {
    let mut ret: i32 = 0;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalogData();
    }
    xmlRMutexLock(xmlCatalogMutex);
    if xmlDefaultCatalog.is_null() {
        catal = xmlLoadACatalog(filename);
        if catal.is_null() {
            xmlRMutexUnlock(xmlCatalogMutex);
            return -(1 as i32);
        }
        xmlDefaultCatalog = catal;
        xmlRMutexUnlock(xmlCatalogMutex);
        return 0 as i32;
    }
    ret = xmlExpandCatalog(xmlDefaultCatalog, filename);
    xmlRMutexUnlock(xmlCatalogMutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlLoadCatalogs(mut pathss: *const i8) {
    let mut cur: *const i8 = 0 as *const i8;
    let mut paths: *const i8 = 0 as *const i8;
    let mut path: *mut xmlChar = 0 as *mut xmlChar;
    if pathss.is_null() {
        return;
    }
    cur = pathss;
    while *cur as i32 != 0 as i32 {
        while *cur as i32 == 0x20 as i32
            || 0x9 as i32 <= *cur as i32
                && *cur as i32 <= 0xa as i32
            || *cur as i32 == 0xd as i32
        {
            cur = cur.offset(1);
        }
        if *cur as i32 != 0 as i32 {
            paths = cur;
            while *cur as i32 != 0 as i32
                && *cur as i32 != ':' as i32
                && !(*cur as i32 == 0x20 as i32
                    || 0x9 as i32 <= *cur as i32
                        && *cur as i32 <= 0xa as i32
                    || *cur as i32 == 0xd as i32)
            {
                cur = cur.offset(1);
            }
            path = xmlStrndup(
                paths as *const xmlChar,
                cur.offset_from(paths) as i64 as i32,
            );
            if !path.is_null() {
                xmlLoadCatalog(path as *const i8);
                xmlFree.expect("non-null function pointer")(path as *mut libc::c_void);
            }
        }
        while *cur as i32 == ':' as i32 {
            cur = cur.offset(1);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogCleanup() {
    if xmlCatalogInitialized == 0 as i32 {
        return;
    }
    xmlRMutexLock(xmlCatalogMutex);
    if xmlDebugCatalogs != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Catalogs cleanup\n\0" as *const u8 as *const i8,
        );
    }
    if !xmlCatalogXMLFiles.is_null() {
        xmlHashFree(
            xmlCatalogXMLFiles,
            Some(
                xmlFreeCatalogHashEntryList
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
        );
    }
    xmlCatalogXMLFiles = 0 as xmlHashTablePtr;
    if !xmlDefaultCatalog.is_null() {
        xmlFreeCatalog(xmlDefaultCatalog);
    }
    xmlDefaultCatalog = 0 as xmlCatalogPtr;
    xmlDebugCatalogs = 0 as i32;
    xmlCatalogInitialized = 0 as i32;
    xmlRMutexUnlock(xmlCatalogMutex);
    xmlFreeRMutex(xmlCatalogMutex);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogResolveSystem(
    mut sysID: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalog();
    }
    ret = xmlACatalogResolveSystem(xmlDefaultCatalog, sysID);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogResolvePublic(
    mut pubID: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalog();
    }
    ret = xmlACatalogResolvePublic(xmlDefaultCatalog, pubID);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogResolve(
    mut pubID: *const xmlChar,
    mut sysID: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalog();
    }
    ret = xmlACatalogResolve(xmlDefaultCatalog, pubID, sysID);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogResolveURI(mut URI: *const xmlChar) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalog();
    }
    ret = xmlACatalogResolveURI(xmlDefaultCatalog, URI);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogDump(mut out: *mut FILE) {
    if out.is_null() {
        return;
    }
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalog();
    }
    xmlACatalogDump(xmlDefaultCatalog, out);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogAdd(
    mut type_0: *const xmlChar,
    mut orig: *const xmlChar,
    mut replace: *const xmlChar,
) -> i32 {
    let mut res: i32 = -(1 as i32);
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalogData();
    }
    xmlRMutexLock(xmlCatalogMutex);
    if xmlDefaultCatalog.is_null()
        && xmlStrEqual(
            type_0,
            b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
    {
        xmlDefaultCatalog = xmlCreateNewCatalog(
            XML_XML_CATALOG_TYPE,
            xmlCatalogDefaultPrefer,
        );
        if !xmlDefaultCatalog.is_null() {
            let fresh70 = &mut ((*xmlDefaultCatalog).xml);
            *fresh70 = xmlNewCatalogEntry(
                XML_CATA_CATALOG,
                0 as *const xmlChar,
                orig,
                0 as *const xmlChar,
                xmlCatalogDefaultPrefer,
                0 as xmlCatalogEntryPtr,
            );
        }
        xmlRMutexUnlock(xmlCatalogMutex);
        return 0 as i32;
    }
    res = xmlACatalogAdd(xmlDefaultCatalog, type_0, orig, replace);
    xmlRMutexUnlock(xmlCatalogMutex);
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogRemove(mut value: *const xmlChar) -> i32 {
    let mut res: i32 = 0;
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalog();
    }
    xmlRMutexLock(xmlCatalogMutex);
    res = xmlACatalogRemove(xmlDefaultCatalog, value);
    xmlRMutexUnlock(xmlCatalogMutex);
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogConvert() -> i32 {
    let mut res: i32 = -(1 as i32);
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalog();
    }
    xmlRMutexLock(xmlCatalogMutex);
    res = xmlConvertSGMLCatalog(xmlDefaultCatalog);
    xmlRMutexUnlock(xmlCatalogMutex);
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogGetDefaults() -> xmlCatalogAllow {
    return xmlCatalogDefaultAllow;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogSetDefaults(mut allow: xmlCatalogAllow) {
    if xmlDebugCatalogs != 0 {
        match allow as u32 {
            0 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Disabling catalog usage\n\0" as *const u8 as *const i8,
                );
            }
            1 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Allowing only global catalogs\n\0" as *const u8
                        as *const i8,
                );
            }
            2 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Allowing only catalogs from the document\n\0" as *const u8
                        as *const i8,
                );
            }
            3 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Allowing all catalogs\n\0" as *const u8 as *const i8,
                );
            }
            _ => {}
        }
    }
    xmlCatalogDefaultAllow = allow;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogSetDefaultPrefer(
    mut prefer: xmlCatalogPrefer,
) -> xmlCatalogPrefer {
    let mut ret: xmlCatalogPrefer = xmlCatalogDefaultPrefer;
    if prefer as u32 == XML_CATA_PREFER_NONE as i32 as u32 {
        return ret;
    }
    if xmlDebugCatalogs != 0 {
        match prefer as u32 {
            1 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Setting catalog preference to PUBLIC\n\0" as *const u8
                        as *const i8,
                );
            }
            2 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Setting catalog preference to SYSTEM\n\0" as *const u8
                        as *const i8,
                );
            }
            _ => return ret,
        }
    }
    xmlCatalogDefaultPrefer = prefer;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogSetDebug(mut level: i32) -> i32 {
    let mut ret: i32 = xmlDebugCatalogs;
    if level <= 0 as i32 {
        xmlDebugCatalogs = 0 as i32;
    } else {
        xmlDebugCatalogs = level;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogFreeLocal(mut catalogs: *mut libc::c_void) {
    let mut catal: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalog();
    }
    catal = catalogs as xmlCatalogEntryPtr;
    if !catal.is_null() {
        xmlFreeCatalogEntryList(catal);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogAddLocal(
    mut catalogs: *mut libc::c_void,
    mut URL: *const xmlChar,
) -> *mut libc::c_void {
    let mut catal: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    let mut add: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalog();
    }
    if URL.is_null() {
        return catalogs;
    }
    if xmlDebugCatalogs != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Adding document catalog %s\n\0" as *const u8 as *const i8,
            URL,
        );
    }
    add = xmlNewCatalogEntry(
        XML_CATA_CATALOG,
        0 as *const xmlChar,
        URL,
        0 as *const xmlChar,
        xmlCatalogDefaultPrefer,
        0 as xmlCatalogEntryPtr,
    );
    if add.is_null() {
        return catalogs;
    }
    catal = catalogs as xmlCatalogEntryPtr;
    if catal.is_null() {
        return add as *mut libc::c_void;
    }
    while !((*catal).next).is_null() {
        catal = (*catal).next;
    }
    let fresh71 = &mut ((*catal).next);
    *fresh71 = add;
    return catalogs;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogLocalResolve(
    mut catalogs: *mut libc::c_void,
    mut pubID: *const xmlChar,
    mut sysID: *const xmlChar,
) -> *mut xmlChar {
    let mut catal: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalog();
    }
    if pubID.is_null() && sysID.is_null() {
        return 0 as *mut xmlChar;
    }
    if xmlDebugCatalogs != 0 {
        if !pubID.is_null() && !sysID.is_null() {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Local Resolve: pubID %s sysID %s\n\0" as *const u8
                    as *const i8,
                pubID,
                sysID,
            );
        } else if !pubID.is_null() {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Local Resolve: pubID %s\n\0" as *const u8 as *const i8,
                pubID,
            );
        } else {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Local Resolve: sysID %s\n\0" as *const u8 as *const i8,
                sysID,
            );
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
pub unsafe extern "C" fn xmlCatalogLocalResolveURI(
    mut catalogs: *mut libc::c_void,
    mut URI: *const xmlChar,
) -> *mut xmlChar {
    let mut catal: xmlCatalogEntryPtr = 0 as *mut xmlCatalogEntry;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalog();
    }
    if URI.is_null() {
        return 0 as *mut xmlChar;
    }
    if xmlDebugCatalogs != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Resolve URI %s\n\0" as *const u8 as *const i8,
            URI,
        );
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
pub unsafe extern "C" fn xmlCatalogGetSystem(
    mut sysID: *const xmlChar,
) -> *const xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    static mut result: [xmlChar; 1000] = [0; 1000];
    static mut msg: i32 = 0 as i32;
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalog();
    }
    if msg == 0 as i32 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated xmlCatalogGetSystem() call\n\0" as *const u8
                as *const i8,
        );
        msg += 1;
    }
    if sysID.is_null() {
        return 0 as *const xmlChar;
    }
    if !xmlDefaultCatalog.is_null() {
        ret = xmlCatalogListXMLResolve(
            (*xmlDefaultCatalog).xml,
            0 as *const xmlChar,
            sysID,
        );
        if !ret.is_null() && ret != -(1 as i32) as *mut xmlChar {
            snprintf(
                result.as_mut_ptr() as *mut i8,
                (::std::mem::size_of::<[xmlChar; 1000]>() as u64)
                    .wrapping_sub(1 as i32 as u64),
                b"%s\0" as *const u8 as *const i8,
                ret as *mut i8,
            );
            result[(::std::mem::size_of::<[xmlChar; 1000]>() as u64)
                .wrapping_sub(1 as i32 as u64)
                as usize] = 0 as i32 as xmlChar;
            return result.as_mut_ptr();
        }
    }
    if !xmlDefaultCatalog.is_null() {
        return xmlCatalogGetSGMLSystem((*xmlDefaultCatalog).sgml, sysID);
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCatalogGetPublic(
    mut pubID: *const xmlChar,
) -> *const xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    static mut result: [xmlChar; 1000] = [0; 1000];
    static mut msg: i32 = 0 as i32;
    if xmlCatalogInitialized == 0 {
        xmlInitializeCatalog();
    }
    if msg == 0 as i32 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated xmlCatalogGetPublic() call\n\0" as *const u8
                as *const i8,
        );
        msg += 1;
    }
    if pubID.is_null() {
        return 0 as *const xmlChar;
    }
    if !xmlDefaultCatalog.is_null() {
        ret = xmlCatalogListXMLResolve(
            (*xmlDefaultCatalog).xml,
            pubID,
            0 as *const xmlChar,
        );
        if !ret.is_null() && ret != -(1 as i32) as *mut xmlChar {
            snprintf(
                result.as_mut_ptr() as *mut i8,
                (::std::mem::size_of::<[xmlChar; 1000]>() as u64)
                    .wrapping_sub(1 as i32 as u64),
                b"%s\0" as *const u8 as *const i8,
                ret as *mut i8,
            );
            result[(::std::mem::size_of::<[xmlChar; 1000]>() as u64)
                .wrapping_sub(1 as i32 as u64)
                as usize] = 0 as i32 as xmlChar;
            return result.as_mut_ptr();
        }
    }
    if !xmlDefaultCatalog.is_null() {
        return xmlCatalogGetSGMLPublic((*xmlDefaultCatalog).sgml, pubID);
    }
    return 0 as *const xmlChar;
}
