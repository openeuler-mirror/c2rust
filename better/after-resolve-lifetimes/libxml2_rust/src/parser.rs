use ::libc;
extern "C" {
    
    
    
    
    
    
    fn xmlStrlen(str: * const u8) -> i32;
    fn xmlCharStrdup(cur: * const i8) -> * mut u8;
    fn xmlStrEqual(str1: * const u8, str2: * const u8) -> i32;
    fn xmlStrcasecmp(str1: * const u8, str2: * const u8) -> i32;
    fn xmlStrncmp(
        str1: * const u8,
        str2: * const u8,
        len: i32,
    ) -> i32;
    fn xmlStrcmp(str1: * const u8, str2: * const u8) -> i32;
    fn xmlStrcasestr(str: * const u8, val: * const u8) -> * const u8;
    fn xmlStrchr(str: * const u8, val: u8) -> * const u8;
    fn xmlStrndup(cur: * const u8, len: i32) -> * mut u8;
    fn xmlStrdup(cur: * const u8) -> * mut u8;
    fn snprintf(
        _: * mut i8,
        _: u64,
        _: * const i8,
        _: ...
    ) -> i32;
    
    fn __xmlGlobalInitMutexLock();
    fn __xmlGlobalInitMutexUnlock();
    fn xmlInputReadCallbackNop(
        context: * mut core::ffi::c_void,
        buffer: * mut i8,
        len: i32,
    ) -> i32;
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn memmove(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn memset(
        _: * mut core::ffi::c_void,
        _: i32,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn memchr(
        _: * const core::ffi::c_void,
        _: i32,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn strncmp(
        _: * const i8,
        _: * const i8,
        _: u64,
    ) -> i32;
    fn strlen(_: * const i8) -> u64;
    fn xmlNewDocElementContent(
        doc: * mut crate::src::HTMLparser::_xmlDoc,
        name: * const u8,
        type_0: u32,
    ) -> * mut crate::src::HTMLparser::_xmlElementContent;
    fn xmlFreeDocElementContent(doc: * mut crate::src::HTMLparser::_xmlDoc, cur: * mut crate::src::HTMLparser::_xmlElementContent);
    fn xmlCreateEnumeration(name: * const u8) -> * mut crate::src::HTMLparser::_xmlEnumeration;
    fn xmlFreeEnumeration(cur: * mut crate::src::HTMLparser::_xmlEnumeration);
    
    
    
    
    
    
    
    
    
    fn xmlBuildQName(
        ncname: * const u8,
        prefix: * const u8,
        memory: * mut u8,
        len: i32,
    ) -> * mut u8;
    fn xmlSplitQName3(name: * const u8, len: * mut i32) -> * const u8;
    fn xmlBufferCreate() -> * mut crate::src::HTMLtree::_xmlBuffer;
    fn xmlBufferFree(buf: * mut crate::src::HTMLtree::_xmlBuffer);
    fn xmlBufferAdd(
        buf: * mut crate::src::HTMLtree::_xmlBuffer,
        str: * const u8,
        len: i32,
    ) -> i32;
    fn xmlBufferSetAllocationScheme(
        buf: * mut crate::src::HTMLtree::_xmlBuffer,
        scheme: u32,
    );
    fn xmlCreateIntSubset(
        doc: * mut crate::src::HTMLparser::_xmlDoc,
        name: * const u8,
        ExternalID: * const u8,
        SystemID: * const u8,
    ) -> * mut crate::src::HTMLparser::_xmlDtd;
    fn xmlNewDtd(
        doc: * mut crate::src::HTMLparser::_xmlDoc,
        name: * const u8,
        ExternalID: * const u8,
        SystemID: * const u8,
    ) -> * mut crate::src::HTMLparser::_xmlDtd;
    fn xmlNewDoc(version: * const u8) -> * mut crate::src::HTMLparser::_xmlDoc;
    fn xmlFreeDoc(cur: * mut crate::src::HTMLparser::_xmlDoc);
    fn xmlNewDocNode(
        doc: * mut crate::src::HTMLparser::_xmlDoc,
        ns: * mut crate::src::HTMLparser::_xmlNs,
        name: * const u8,
        content: * const u8,
    ) -> * mut crate::src::HTMLparser::_xmlNode;
    fn xmlNewDocComment(doc: * mut crate::src::HTMLparser::_xmlDoc, content: * const u8) -> * mut crate::src::HTMLparser::_xmlNode;
    fn xmlDocCopyNode(
        node: * mut crate::src::HTMLparser::_xmlNode,
        doc: * mut crate::src::HTMLparser::_xmlDoc,
        recursive: i32,
    ) -> * mut crate::src::HTMLparser::_xmlNode;
    fn xmlGetLastChild(parent: * const crate::src::HTMLparser::_xmlNode) -> * mut crate::src::HTMLparser::_xmlNode;
    fn xmlNodeIsText(node: * const crate::src::HTMLparser::_xmlNode) -> i32;
    fn xmlAddChild(parent: * mut crate::src::HTMLparser::_xmlNode, cur: * mut crate::src::HTMLparser::_xmlNode) -> * mut crate::src::HTMLparser::_xmlNode;
    fn xmlAddChildList(parent: * mut crate::src::HTMLparser::_xmlNode, cur: * mut crate::src::HTMLparser::_xmlNode) -> * mut crate::src::HTMLparser::_xmlNode;
    fn xmlUnlinkNode(cur: * mut crate::src::HTMLparser::_xmlNode);
    fn xmlFreeNodeList(cur: * mut crate::src::HTMLparser::_xmlNode);
    fn xmlFreeNode(cur: * mut crate::src::HTMLparser::_xmlNode);
    fn xmlSetTreeDoc(tree: * mut crate::src::HTMLparser::_xmlNode, doc: * mut crate::src::HTMLparser::_xmlDoc);
    fn xmlSearchNsByHref(
        doc: * mut crate::src::HTMLparser::_xmlDoc,
        node: * mut crate::src::HTMLparser::_xmlNode,
        href: * const u8,
    ) -> * mut crate::src::HTMLparser::_xmlNs;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn xmlCleanupMemory();
    fn xmlInitMemory() -> i32;
    fn xmlValidateRoot(ctxt: * mut crate::src::HTMLparser::_xmlValidCtxt, doc: * mut crate::src::HTMLparser::_xmlDoc) -> i32;
    fn xmlValidateElement(
        ctxt: * mut crate::src::HTMLparser::_xmlValidCtxt,
        doc: * mut crate::src::HTMLparser::_xmlDoc,
        elem: * mut crate::src::HTMLparser::_xmlNode,
    ) -> i32;
    fn xmlIsMixedElement(doc: * mut crate::src::HTMLparser::_xmlDoc, name: * const u8) -> i32;
    
    
    
    
    
    fn xmlCleanupInputCallbacks();
    fn xmlRegisterDefaultInputCallbacks();
    fn xmlAllocParserInputBuffer(enc: i32) -> * mut crate::src::HTMLparser::_xmlParserInputBuffer;
    fn xmlParserInputBufferCreateFd(
        fd: i32,
        enc: i32,
    ) -> * mut crate::src::HTMLparser::_xmlParserInputBuffer;
    fn xmlParserInputBufferCreateMem(
        mem: * const i8,
        size: i32,
        enc: i32,
    ) -> * mut crate::src::HTMLparser::_xmlParserInputBuffer;
    fn xmlParserInputBufferCreateIO(
        ioread: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut i8,_: i32,) -> i32>,
        ioclose: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>,
        ioctx: * mut core::ffi::c_void,
        enc: i32,
    ) -> * mut crate::src::HTMLparser::_xmlParserInputBuffer;
    fn xmlParserInputBufferPush(
        in_0: * mut crate::src::HTMLparser::_xmlParserInputBuffer,
        len: i32,
        buf: * const i8,
    ) -> i32;
    fn xmlFreeParserInputBuffer(in_0: * mut crate::src::HTMLparser::_xmlParserInputBuffer);
    fn xmlParserGetDirectory(filename: * const i8) -> * mut i8;
    fn xmlCleanupOutputCallbacks();
    fn xmlRegisterDefaultOutputCallbacks();
    
    
    
    
    fn xmlInitThreads();
    fn xmlCleanupThreads();
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn xmlLoadExternalEntity(
        URL: * const i8,
        ID: * const i8,
        ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    ) -> * mut crate::src::HTMLparser::_xmlParserInput;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn xmlBuildURI(URI: * const u8, base: * const u8) -> * mut u8;
    fn xmlParseURI(str: * const i8) -> * mut crate::src::SAX2::_xmlURI;
    fn xmlFreeURI(uri: * mut crate::src::SAX2::_xmlURI);
    fn xmlCanonicPath(path: * const u8) -> * mut u8;
    
    
    
    
    fn xmlSchemaCleanupTypes();
    
    
    
    
    
    
    fn xmlXPathInit();
    
}
pub use crate::src::HTMLparser::__htmlParseContent;
pub use crate::src::HTMLparser::htmlCreateMemoryParserCtxt;
pub use crate::src::HTMLparser::htmlInitAutoClose;
pub use crate::src::SAX2::htmlDefaultSAXHandlerInit;
pub use crate::src::SAX2::xmlDefaultSAXHandlerInit;
pub use crate::src::SAX2::xmlSAX2EndElement;
pub use crate::src::SAX2::xmlSAX2EntityDecl;
pub use crate::src::SAX2::xmlSAX2GetEntity;
pub use crate::src::SAX2::xmlSAX2IgnorableWhitespace;
pub use crate::src::SAX2::xmlSAX2StartElement;
pub use crate::src::buf::xmlBufContent;
pub use crate::src::buf::xmlBufGetInputBase;
pub use crate::src::buf::xmlBufIsEmpty;
pub use crate::src::buf::xmlBufResetInput;
pub use crate::src::buf::xmlBufSetInputBaseCur;
pub use crate::src::buf::xmlBufUse;
pub use crate::src::catalog::xmlCatalogAddLocal;
pub use crate::src::catalog::xmlCatalogCleanup;
pub use crate::src::catalog::xmlCatalogFreeLocal;
pub use crate::src::catalog::xmlCatalogGetDefaults;
pub use crate::src::chvalid::xmlCharInRange;
pub use crate::src::dict::xmlDictCleanup;
pub use crate::src::dict::xmlDictFree;
pub use crate::src::dict::xmlDictLookup;
pub use crate::src::dict::xmlDictOwns;
pub use crate::src::dict::xmlDictReference;
pub use crate::src::dict::xmlDictSetLimit;
pub use crate::src::dict::xmlInitializeDict;
pub use crate::src::encoding::xmlCharEncInput;
pub use crate::src::encoding::xmlCleanupCharEncodingHandlers;
pub use crate::src::encoding::xmlDetectCharEncoding;
pub use crate::src::encoding::xmlFindCharEncodingHandler;
pub use crate::src::encoding::xmlInitCharEncodingHandlers;
pub use crate::src::entities::xmlGetPredefinedEntity;
pub use crate::src::error::__xmlRaiseError;
pub use crate::src::error::initGenericErrorDefaultFunc;
pub use crate::src::error::xmlCopyError;
pub use crate::src::error::xmlGenericErrorDefaultFunc;
pub use crate::src::error::xmlResetError;
pub use crate::src::globals::__xmlDefaultSAXHandler;
pub use crate::src::globals::__xmlDefaultSAXLocator;
pub use crate::src::globals::__xmlGenericError;
pub use crate::src::globals::__xmlGenericErrorContext;
pub use crate::src::globals::__xmlParserDebugEntities;
pub use crate::src::globals::xmlCleanupGlobals;
pub use crate::src::globals::xmlInitGlobals;
pub use crate::src::hash::xmlHashAddEntry2;
pub use crate::src::hash::xmlHashCreateDict;
pub use crate::src::hash::xmlHashDefaultDeallocator;
pub use crate::src::hash::xmlHashFree;
pub use crate::src::hash::xmlHashLookup2;
pub use crate::src::hash::xmlHashQLookup2;
pub use crate::src::hash::xmlHashRemoveEntry2;
pub use crate::src::hash::xmlHashScanFull;
pub use crate::src::hash::xmlHashSize;
pub use crate::src::hash::xmlHashUpdateEntry2;
pub use crate::src::parserInternals::__xmlErrEncoding;
pub use crate::src::parserInternals::xmlClearParserCtxt;
pub use crate::src::parserInternals::xmlCopyChar;
pub use crate::src::parserInternals::xmlCopyCharMultiByte;
pub use crate::src::parserInternals::xmlCurrentChar;
pub use crate::src::parserInternals::xmlErrMemory;
pub use crate::src::parserInternals::xmlFreeInputStream;
pub use crate::src::parserInternals::xmlFreeParserCtxt;
pub use crate::src::parserInternals::xmlInitNodeInfoSeq;
pub use crate::src::parserInternals::xmlNewEntityInputStream;
pub use crate::src::parserInternals::xmlNewIOInputStream;
pub use crate::src::parserInternals::xmlNewInputStream;
pub use crate::src::parserInternals::xmlNewParserCtxt;
pub use crate::src::parserInternals::xmlNewStringInputStream;
pub use crate::src::parserInternals::xmlNextChar;
pub use crate::src::parserInternals::xmlParserAddNodeInfo;
pub use crate::src::parserInternals::xmlParserInputGrow;
pub use crate::src::parserInternals::xmlParserInputShrink;
pub use crate::src::parserInternals::xmlStringCurrentChar;
pub use crate::src::parserInternals::xmlSwitchEncoding;
pub use crate::src::parserInternals::xmlSwitchToEncoding;
pub use crate::src::relaxng::xmlRelaxNGCleanupTypes;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::catalog::_xmlAutomata;
pub use crate::src::chvalid::xmlIsBaseCharGroup;
pub use crate::src::chvalid::xmlIsCombiningGroup;
pub use crate::src::chvalid::xmlIsDigitGroup;
pub use crate::src::chvalid::xmlIsExtenderGroup;
pub use crate::src::chvalid::xmlIsPubidChar_tab;
pub use crate::src::debugXML::_xmlValidState;
pub use crate::src::encoding::_xmlAutomataState;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub use crate::src::globals::xmlMallocAtomic;
pub use crate::src::globals::xmlRealloc;
pub type xmlChar = u8;
pub type size_t = u64;
pub type ptrdiff_t = i64;
pub type xmlFreeFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>;
pub type xmlReallocFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: u64,) -> * mut core::ffi::c_void>;
// #[derive(Copy, Clone)]

pub type _xmlParserInputBuffer = crate::src::HTMLparser::_xmlParserInputBuffer;
pub type xmlBufPtr = * mut crate::src::buf::_xmlBuf;
pub type xmlBuf = crate::src::buf::_xmlBuf;
pub type xmlCharEncodingHandlerPtr = * mut crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub type _xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type iconv_t = * mut core::ffi::c_void;
pub type xmlCharEncodingOutputFunc = Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>;
pub type xmlCharEncodingInputFunc = Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>;
pub type xmlInputCloseCallback = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type xmlInputReadCallback = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut i8,_: i32,) -> i32>;
pub type xmlParserInputBuffer = crate::src::HTMLparser::_xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = * mut crate::src::HTMLparser::_xmlParserInputBuffer;
// #[derive(Copy, Clone)]

pub type _xmlParserInput = crate::src::HTMLparser::_xmlParserInput;
pub type xmlParserInputDeallocate = Option<unsafe extern "C"  fn(_: * mut u8,) -> ()>;
pub type xmlParserInput = crate::src::HTMLparser::_xmlParserInput;
pub type xmlParserInputPtr = * mut crate::src::HTMLparser::_xmlParserInput;
// #[derive(Copy, Clone)]

pub type _xmlParserCtxt = crate::src::HTMLparser::_xmlParserCtxt;
pub type xmlParserNodeInfo = crate::src::HTMLparser::_xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub type _xmlParserNodeInfo = crate::src::HTMLparser::_xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub type _xmlNode = crate::src::HTMLparser::_xmlNode;
pub type xmlNs = crate::src::HTMLparser::_xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlNs = crate::src::HTMLparser::_xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlDoc = crate::src::HTMLparser::_xmlDoc;
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

pub type _xmlError = crate::src::HTMLparser::_xmlError;
pub type xmlErrorLevel = u32;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlAttrPtr = * mut crate::src::HTMLparser::_xmlAttr;
pub type xmlAttr = crate::src::HTMLparser::_xmlAttr;
pub type xmlNodePtr = * mut crate::src::HTMLparser::_xmlNode;
pub type xmlNode = crate::src::HTMLparser::_xmlNode;
pub type xmlHashTablePtr = * mut crate::src::hash::_xmlHashTable;
pub type xmlHashTable = crate::src::hash::_xmlHashTable;
pub type xmlStartTag = crate::src::parser::_xmlStartTag;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStartTag {
    pub prefix: * const u8,
    pub URI: * const u8,
    pub line: i32,
    pub nsNr: i32,
}
impl _xmlStartTag {
    pub const fn new() -> Self {
        _xmlStartTag {
        prefix: (0 as * const u8),
        URI: (0 as * const u8),
        line: 0,
        nsNr: 0
        }
    }
}

impl std::default::Default for _xmlStartTag {
    fn default() -> Self { _xmlStartTag::new() }
}

pub type xmlDictPtr = * mut crate::src::dict::_xmlDict;
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
// #[derive(Copy, Clone)]

pub type _xmlValidCtxt = crate::src::HTMLparser::_xmlValidCtxt;
pub type xmlAutomataStatePtr = * mut crate::src::encoding::_xmlAutomataState;
pub type xmlAutomataState = crate::src::encoding::_xmlAutomataState;
pub type xmlAutomataPtr = * mut crate::src::catalog::_xmlAutomata;
pub type xmlAutomata = crate::src::catalog::_xmlAutomata;
pub type xmlValidState = crate::src::debugXML::_xmlValidState;
pub type xmlDocPtr = * mut crate::src::HTMLparser::_xmlDoc;
pub type xmlDoc = crate::src::HTMLparser::_xmlDoc;
pub type xmlValidityWarningFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type xmlValidityErrorFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type xmlParserNodeInfoSeq = crate::src::HTMLparser::_xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub type _xmlParserNodeInfoSeq = crate::src::HTMLparser::_xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub type _xmlSAXHandler = crate::src::HTMLparser::_xmlSAXHandler;
pub type xmlStructuredErrorFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut crate::src::HTMLparser::_xmlError,) -> ()>;
pub type xmlErrorPtr = * mut crate::src::HTMLparser::_xmlError;
pub type endElementNsSAX2Func = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type startElementNsSAX2Func = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,_: i32,_: * mut * const u8,_: i32,_: i32,_: * mut * const u8,) -> ()>;
pub type externalSubsetSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type cdataBlockSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,) -> ()>;
pub type getParameterEntitySAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> * mut crate::src::HTMLparser::_xmlEntity>;
pub type xmlEntityPtr = * mut crate::src::HTMLparser::_xmlEntity;
pub type xmlEntity = crate::src::HTMLparser::_xmlEntity;
// #[derive(Copy, Clone)]

pub type _xmlEntity = crate::src::HTMLparser::_xmlEntity;
pub type xmlEntityType = u32;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type errorSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type warningSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type commentSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> ()>;
pub type processingInstructionSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,) -> ()>;
pub type ignorableWhitespaceSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,) -> ()>;
pub type charactersSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,) -> ()>;
pub type referenceSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> ()>;
pub type endElementSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> ()>;
pub type startElementSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * mut * const u8,) -> ()>;
pub type endDocumentSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
pub type startDocumentSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
pub type setDocumentLocatorSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut crate::src::HTMLparser::_xmlSAXLocator,) -> ()>;
pub type xmlSAXLocatorPtr = * mut crate::src::HTMLparser::_xmlSAXLocator;
pub type xmlSAXLocator = crate::src::HTMLparser::_xmlSAXLocator;
// #[derive(Copy, Clone)]

pub type _xmlSAXLocator = crate::src::HTMLparser::_xmlSAXLocator;
pub type unparsedEntityDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type elementDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,_: * mut crate::src::HTMLparser::_xmlElementContent,) -> ()>;
pub type xmlElementContentPtr = * mut crate::src::HTMLparser::_xmlElementContent;
pub type xmlElementContent = crate::src::HTMLparser::_xmlElementContent;
// #[derive(Copy, Clone)]

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
pub type attributeDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: i32,_: i32,_: * const u8,_: * mut crate::src::HTMLparser::_xmlEnumeration,) -> ()>;
pub type xmlEnumerationPtr = * mut crate::src::HTMLparser::_xmlEnumeration;
pub type xmlEnumeration = crate::src::HTMLparser::_xmlEnumeration;
// #[derive(Copy, Clone)]

pub type _xmlEnumeration = crate::src::HTMLparser::_xmlEnumeration;
pub type notationDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type entityDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,_: * const u8,_: * const u8,_: * mut u8,) -> ()>;
pub type getEntitySAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> * mut crate::src::HTMLparser::_xmlEntity>;
pub type resolveEntitySAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,) -> * mut crate::src::HTMLparser::_xmlParserInput>;
pub type hasExternalSubsetSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type hasInternalSubsetSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type isStandaloneSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type internalSubsetSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type xmlParserCtxt = crate::src::HTMLparser::_xmlParserCtxt;
pub type xmlParserCtxtPtr = * mut crate::src::HTMLparser::_xmlParserCtxt;
pub type xmlSAXHandler = crate::src::HTMLparser::_xmlSAXHandler;
pub type xmlSAXHandlerPtr = * mut crate::src::HTMLparser::_xmlSAXHandler;
pub type xmlBufferAllocationScheme = u32;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
// #[derive(Copy, Clone)]

pub type _xmlBuffer = crate::src::HTMLtree::_xmlBuffer;
pub type xmlBuffer = crate::src::HTMLtree::_xmlBuffer;
pub type xmlBufferPtr = * mut crate::src::HTMLtree::_xmlBuffer;
pub type C2RustUnnamed = u32;
pub const XML_ATTRIBUTE_FIXED: C2RustUnnamed = 4;
pub const XML_ATTRIBUTE_IMPLIED: C2RustUnnamed = 3;
pub const XML_ATTRIBUTE_REQUIRED: C2RustUnnamed = 2;
pub const XML_ATTRIBUTE_NONE: C2RustUnnamed = 1;
pub type C2RustUnnamed_0 = u32;
pub const XML_ELEMENT_TYPE_ELEMENT: C2RustUnnamed_0 = 4;
pub const XML_ELEMENT_TYPE_MIXED: C2RustUnnamed_0 = 3;
pub const XML_ELEMENT_TYPE_ANY: C2RustUnnamed_0 = 2;
pub const XML_ELEMENT_TYPE_EMPTY: C2RustUnnamed_0 = 1;
pub const XML_ELEMENT_TYPE_UNDEFINED: C2RustUnnamed_0 = 0;
pub type xmlNsPtr = * mut crate::src::HTMLparser::_xmlNs;
pub type xmlDtd = crate::src::HTMLparser::_xmlDtd;
pub type xmlDtdPtr = * mut crate::src::HTMLparser::_xmlDtd;
pub type C2RustUnnamed_1 = u32;
pub const XML_DOC_HTML: C2RustUnnamed_1 = 128;
pub const XML_DOC_INTERNAL: C2RustUnnamed_1 = 64;
pub const XML_DOC_USERBUILT: C2RustUnnamed_1 = 32;
pub const XML_DOC_XINCLUDE: C2RustUnnamed_1 = 16;
pub const XML_DOC_DTDVALID: C2RustUnnamed_1 = 8;
pub const XML_DOC_OLD10: C2RustUnnamed_1 = 4;
pub const XML_DOC_NSVALID: C2RustUnnamed_1 = 2;
pub const XML_DOC_WELLFORMED: C2RustUnnamed_1 = 1;
pub type xmlHashDeallocator = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> ()>;
pub type xmlHashScannerFull = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type C2RustUnnamed_2 = u32;
pub const XML_FROM_URI: C2RustUnnamed_2 = 30;
pub const XML_FROM_BUFFER: C2RustUnnamed_2 = 29;
pub const XML_FROM_SCHEMATRONV: C2RustUnnamed_2 = 28;
pub const XML_FROM_I18N: C2RustUnnamed_2 = 27;
pub const XML_FROM_MODULE: C2RustUnnamed_2 = 26;
pub const XML_FROM_WRITER: C2RustUnnamed_2 = 25;
pub const XML_FROM_CHECK: C2RustUnnamed_2 = 24;
pub const XML_FROM_VALID: C2RustUnnamed_2 = 23;
pub const XML_FROM_XSLT: C2RustUnnamed_2 = 22;
pub const XML_FROM_C14N: C2RustUnnamed_2 = 21;
pub const XML_FROM_CATALOG: C2RustUnnamed_2 = 20;
pub const XML_FROM_RELAXNGV: C2RustUnnamed_2 = 19;
pub const XML_FROM_RELAXNGP: C2RustUnnamed_2 = 18;
pub const XML_FROM_SCHEMASV: C2RustUnnamed_2 = 17;
pub const XML_FROM_SCHEMASP: C2RustUnnamed_2 = 16;
pub const XML_FROM_DATATYPE: C2RustUnnamed_2 = 15;
pub const XML_FROM_REGEXP: C2RustUnnamed_2 = 14;
pub const XML_FROM_XPOINTER: C2RustUnnamed_2 = 13;
pub const XML_FROM_XPATH: C2RustUnnamed_2 = 12;
pub const XML_FROM_XINCLUDE: C2RustUnnamed_2 = 11;
pub const XML_FROM_HTTP: C2RustUnnamed_2 = 10;
pub const XML_FROM_FTP: C2RustUnnamed_2 = 9;
pub const XML_FROM_IO: C2RustUnnamed_2 = 8;
pub const XML_FROM_OUTPUT: C2RustUnnamed_2 = 7;
pub const XML_FROM_MEMORY: C2RustUnnamed_2 = 6;
pub const XML_FROM_HTML: C2RustUnnamed_2 = 5;
pub const XML_FROM_DTD: C2RustUnnamed_2 = 4;
pub const XML_FROM_NAMESPACE: C2RustUnnamed_2 = 3;
pub const XML_FROM_TREE: C2RustUnnamed_2 = 2;
pub const XML_FROM_PARSER: C2RustUnnamed_2 = 1;
pub const XML_FROM_NONE: C2RustUnnamed_2 = 0;
pub type xmlParserErrors = u32;
pub const XML_BUF_OVERFLOW: xmlParserErrors = 7000;
pub const XML_I18N_NO_OUTPUT: xmlParserErrors = 6004;
pub const XML_I18N_CONV_FAILED: xmlParserErrors = 6003;
pub const XML_I18N_EXCESS_HANDLER: xmlParserErrors = 6002;
pub const XML_I18N_NO_HANDLER: xmlParserErrors = 6001;
pub const XML_I18N_NO_NAME: xmlParserErrors = 6000;
pub const XML_CHECK_NAME_NOT_NULL: xmlParserErrors = 5037;
pub const XML_CHECK_WRONG_NAME: xmlParserErrors = 5036;
pub const XML_CHECK_OUTSIDE_DICT: xmlParserErrors = 5035;
pub const XML_CHECK_NOT_NCNAME: xmlParserErrors = 5034;
pub const XML_CHECK_NO_DICT: xmlParserErrors = 5033;
pub const XML_CHECK_NOT_UTF8: xmlParserErrors = 5032;
pub const XML_CHECK_NS_ANCESTOR: xmlParserErrors = 5031;
pub const XML_CHECK_NS_SCOPE: xmlParserErrors = 5030;
pub const XML_CHECK_WRONG_PARENT: xmlParserErrors = 5029;
pub const XML_CHECK_NO_HREF: xmlParserErrors = 5028;
pub const XML_CHECK_NOT_NS_DECL: xmlParserErrors = 5027;
pub const XML_CHECK_NOT_ENTITY_DECL: xmlParserErrors = 5026;
pub const XML_CHECK_NOT_ELEM_DECL: xmlParserErrors = 5025;
pub const XML_CHECK_NOT_ATTR_DECL: xmlParserErrors = 5024;
pub const XML_CHECK_NOT_ATTR: xmlParserErrors = 5023;
pub const XML_CHECK_NOT_DTD: xmlParserErrors = 5022;
pub const XML_CHECK_WRONG_NEXT: xmlParserErrors = 5021;
pub const XML_CHECK_NO_NEXT: xmlParserErrors = 5020;
pub const XML_CHECK_WRONG_PREV: xmlParserErrors = 5019;
pub const XML_CHECK_NO_PREV: xmlParserErrors = 5018;
pub const XML_CHECK_WRONG_DOC: xmlParserErrors = 5017;
pub const XML_CHECK_NO_ELEM: xmlParserErrors = 5016;
pub const XML_CHECK_NO_NAME: xmlParserErrors = 5015;
pub const XML_CHECK_NO_DOC: xmlParserErrors = 5014;
pub const XML_CHECK_NO_PARENT: xmlParserErrors = 5013;
pub const XML_CHECK_ENTITY_TYPE: xmlParserErrors = 5012;
pub const XML_CHECK_UNKNOWN_NODE: xmlParserErrors = 5011;
pub const XML_CHECK_FOUND_NOTATION: xmlParserErrors = 5010;
pub const XML_CHECK_FOUND_FRAGMENT: xmlParserErrors = 5009;
pub const XML_CHECK_FOUND_DOCTYPE: xmlParserErrors = 5008;
pub const XML_CHECK_FOUND_COMMENT: xmlParserErrors = 5007;
pub const XML_CHECK_FOUND_PI: xmlParserErrors = 5006;
pub const XML_CHECK_FOUND_ENTITY: xmlParserErrors = 5005;
pub const XML_CHECK_FOUND_ENTITYREF: xmlParserErrors = 5004;
pub const XML_CHECK_FOUND_CDATA: xmlParserErrors = 5003;
pub const XML_CHECK_FOUND_TEXT: xmlParserErrors = 5002;
pub const XML_CHECK_FOUND_ATTRIBUTE: xmlParserErrors = 5001;
pub const XML_CHECK_FOUND_ELEMENT: xmlParserErrors = 5000;
pub const XML_MODULE_CLOSE: xmlParserErrors = 4901;
pub const XML_MODULE_OPEN: xmlParserErrors = 4900;
pub const XML_SCHEMATRONV_REPORT: xmlParserErrors = 4001;
pub const XML_SCHEMATRONV_ASSERT: xmlParserErrors = 4000;
pub const XML_SCHEMAP_COS_ALL_LIMITED: xmlParserErrors = 3091;
pub const XML_SCHEMAP_A_PROPS_CORRECT_3: xmlParserErrors = 3090;
pub const XML_SCHEMAP_AU_PROPS_CORRECT: xmlParserErrors = 3089;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_2: xmlParserErrors = 3088;
pub const XML_SCHEMAP_AG_PROPS_CORRECT: xmlParserErrors = 3087;
pub const XML_SCHEMAP_WARN_ATTR_POINTLESS_PROH: xmlParserErrors = 3086;
pub const XML_SCHEMAP_WARN_ATTR_REDECL_PROH: xmlParserErrors = 3085;
pub const XML_SCHEMAP_WARN_UNLOCATED_SCHEMA: xmlParserErrors = 3084;
pub const XML_SCHEMAP_WARN_SKIP_SCHEMA: xmlParserErrors = 3083;
pub const XML_SCHEMAP_SRC_IMPORT: xmlParserErrors = 3082;
pub const XML_SCHEMAP_SRC_REDEFINE: xmlParserErrors = 3081;
pub const XML_SCHEMAP_C_PROPS_CORRECT: xmlParserErrors = 3080;
pub const XML_SCHEMAP_A_PROPS_CORRECT_2: xmlParserErrors = 3079;
pub const XML_SCHEMAP_AU_PROPS_CORRECT_2: xmlParserErrors = 3078;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_3: xmlParserErrors = 3077;
pub const XML_SCHEMAP_SRC_CT_1: xmlParserErrors = 3076;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_2: xmlParserErrors = 3075;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_1: xmlParserErrors = 3074;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_3: xmlParserErrors = 3073;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_2: xmlParserErrors = 3072;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_1: xmlParserErrors = 3071;
pub const XML_SCHEMAP_NOT_DETERMINISTIC: xmlParserErrors = 3070;
pub const XML_SCHEMAP_INTERNAL: xmlParserErrors = 3069;
pub const XML_SCHEMAP_SRC_IMPORT_2_2: xmlParserErrors = 3068;
pub const XML_SCHEMAP_SRC_IMPORT_2_1: xmlParserErrors = 3067;
pub const XML_SCHEMAP_SRC_IMPORT_2: xmlParserErrors = 3066;
pub const XML_SCHEMAP_SRC_IMPORT_1_2: xmlParserErrors = 3065;
pub const XML_SCHEMAP_SRC_IMPORT_1_1: xmlParserErrors = 3064;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_1: xmlParserErrors = 3063;
pub const XML_SCHEMAP_CVC_SIMPLE_TYPE: xmlParserErrors = 3062;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_2: xmlParserErrors = 3061;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_1: xmlParserErrors = 3060;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_1: xmlParserErrors = 3059;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_1: xmlParserErrors = 3058;
pub const XML_SCHEMAP_NO_XSI: xmlParserErrors = 3057;
pub const XML_SCHEMAP_NO_XMLNS: xmlParserErrors = 3056;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_4: xmlParserErrors = 3055;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_2: xmlParserErrors = 3054;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_1: xmlParserErrors = 3053;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_2: xmlParserErrors = 3052;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_1: xmlParserErrors = 3051;
pub const XML_SCHEMAP_SRC_INCLUDE: xmlParserErrors = 3050;
pub const XML_SCHEMAP_E_PROPS_CORRECT_6: xmlParserErrors = 3049;
pub const XML_SCHEMAP_E_PROPS_CORRECT_5: xmlParserErrors = 3048;
pub const XML_SCHEMAP_E_PROPS_CORRECT_4: xmlParserErrors = 3047;
pub const XML_SCHEMAP_E_PROPS_CORRECT_3: xmlParserErrors = 3046;
pub const XML_SCHEMAP_E_PROPS_CORRECT_2: xmlParserErrors = 3045;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_2: xmlParserErrors = 3044;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_1: xmlParserErrors = 3043;
pub const XML_SCHEMAP_P_PROPS_CORRECT_1: xmlParserErrors = 3042;
pub const XML_SCHEMAP_SRC_ELEMENT_3: xmlParserErrors = 3041;
pub const XML_SCHEMAP_SRC_ELEMENT_2_2: xmlParserErrors = 3040;
pub const XML_SCHEMAP_SRC_ELEMENT_2_1: xmlParserErrors = 3039;
pub const XML_SCHEMAP_SRC_ELEMENT_1: xmlParserErrors = 3038;
pub const XML_SCHEMAP_S4S_ATTR_INVALID_VALUE: xmlParserErrors = 3037;
pub const XML_SCHEMAP_S4S_ATTR_MISSING: xmlParserErrors = 3036;
pub const XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED: xmlParserErrors = 3035;
pub const XML_SCHEMAP_S4S_ELEM_MISSING: xmlParserErrors = 3034;
pub const XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED: xmlParserErrors = 3033;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_2: xmlParserErrors = 3032;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_1: xmlParserErrors = 3031;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_5: xmlParserErrors = 3030;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_4: xmlParserErrors = 3029;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_3: xmlParserErrors = 3028;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_1: xmlParserErrors = 3027;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_2: xmlParserErrors = 3026;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1_2: xmlParserErrors = 3025;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1: xmlParserErrors = 3024;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_1: xmlParserErrors = 3023;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_5: xmlParserErrors = 3022;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_4: xmlParserErrors = 3021;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_3: xmlParserErrors = 3020;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_2: xmlParserErrors = 3019;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_1: xmlParserErrors = 3018;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_2: xmlParserErrors = 3017;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_1: xmlParserErrors = 3016;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_1: xmlParserErrors = 3015;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_2: xmlParserErrors = 3014;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_1: xmlParserErrors = 3013;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_2: xmlParserErrors = 3012;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_1: xmlParserErrors = 3011;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_3: xmlParserErrors = 3010;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_2: xmlParserErrors = 3009;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_1: xmlParserErrors = 3008;
pub const XML_SCHEMAP_SRC_UNION_MEMBERTYPES_OR_SIMPLETYPES: xmlParserErrors = 3007;
pub const XML_SCHEMAP_SRC_LIST_ITEMTYPE_OR_SIMPLETYPE: xmlParserErrors = 3006;
pub const XML_SCHEMAP_SRC_RESTRICTION_BASE_OR_SIMPLETYPE: xmlParserErrors = 3005;
pub const XML_SCHEMAP_SRC_RESOLVE: xmlParserErrors = 3004;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_4: xmlParserErrors = 3003;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_3: xmlParserErrors = 3002;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_2: xmlParserErrors = 3001;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_1: xmlParserErrors = 3000;
pub const XML_HTTP_UNKNOWN_HOST: xmlParserErrors = 2022;
pub const XML_HTTP_USE_IP: xmlParserErrors = 2021;
pub const XML_HTTP_URL_SYNTAX: xmlParserErrors = 2020;
pub const XML_FTP_URL_SYNTAX: xmlParserErrors = 2003;
pub const XML_FTP_ACCNT: xmlParserErrors = 2002;
pub const XML_FTP_EPSV_ANSWER: xmlParserErrors = 2001;
pub const XML_FTP_PASV_ANSWER: xmlParserErrors = 2000;
pub const XML_C14N_RELATIVE_NAMESPACE: xmlParserErrors = 1955;
pub const XML_C14N_UNKNOW_NODE: xmlParserErrors = 1954;
pub const XML_C14N_INVALID_NODE: xmlParserErrors = 1953;
pub const XML_C14N_CREATE_STACK: xmlParserErrors = 1952;
pub const XML_C14N_REQUIRES_UTF8: xmlParserErrors = 1951;
pub const XML_C14N_CREATE_CTXT: xmlParserErrors = 1950;
pub const XML_XPTR_EXTRA_OBJECTS: xmlParserErrors = 1903;
pub const XML_XPTR_EVAL_FAILED: xmlParserErrors = 1902;
pub const XML_XPTR_CHILDSEQ_START: xmlParserErrors = 1901;
pub const XML_XPTR_UNKNOWN_SCHEME: xmlParserErrors = 1900;
pub const XML_SCHEMAV_MISC: xmlParserErrors = 1879;
pub const XML_SCHEMAV_CVC_WILDCARD: xmlParserErrors = 1878;
pub const XML_SCHEMAV_CVC_IDC: xmlParserErrors = 1877;
pub const XML_SCHEMAV_CVC_TYPE_2: xmlParserErrors = 1876;
pub const XML_SCHEMAV_CVC_TYPE_1: xmlParserErrors = 1875;
pub const XML_SCHEMAV_CVC_AU: xmlParserErrors = 1874;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_1: xmlParserErrors = 1873;
pub const XML_SCHEMAV_DOCUMENT_ELEMENT_MISSING: xmlParserErrors = 1872;
pub const XML_SCHEMAV_ELEMENT_CONTENT: xmlParserErrors = 1871;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_2: xmlParserErrors = 1870;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_1: xmlParserErrors = 1869;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_4: xmlParserErrors = 1868;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_2: xmlParserErrors = 1867;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_1: xmlParserErrors = 1866;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_1: xmlParserErrors = 1865;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_4: xmlParserErrors = 1864;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_3: xmlParserErrors = 1863;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_2: xmlParserErrors = 1862;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_1: xmlParserErrors = 1861;
pub const XML_SCHEMAV_CVC_ELT_7: xmlParserErrors = 1860;
pub const XML_SCHEMAV_CVC_ELT_6: xmlParserErrors = 1859;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_2: xmlParserErrors = 1858;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_1: xmlParserErrors = 1857;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_1: xmlParserErrors = 1856;
pub const XML_SCHEMAV_CVC_ELT_5_2_1: xmlParserErrors = 1855;
pub const XML_SCHEMAV_CVC_ELT_5_1_2: xmlParserErrors = 1854;
pub const XML_SCHEMAV_CVC_ELT_5_1_1: xmlParserErrors = 1853;
pub const XML_SCHEMAV_CVC_ELT_4_3: xmlParserErrors = 1852;
pub const XML_SCHEMAV_CVC_ELT_4_2: xmlParserErrors = 1851;
pub const XML_SCHEMAV_CVC_ELT_4_1: xmlParserErrors = 1850;
pub const XML_SCHEMAV_CVC_ELT_3_2_2: xmlParserErrors = 1849;
pub const XML_SCHEMAV_CVC_ELT_3_2_1: xmlParserErrors = 1848;
pub const XML_SCHEMAV_CVC_ELT_3_1: xmlParserErrors = 1847;
pub const XML_SCHEMAV_CVC_ELT_2: xmlParserErrors = 1846;
pub const XML_SCHEMAV_CVC_ELT_1: xmlParserErrors = 1845;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_4: xmlParserErrors = 1844;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_3: xmlParserErrors = 1843;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2: xmlParserErrors = 1842;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_1: xmlParserErrors = 1841;
pub const XML_SCHEMAV_CVC_ENUMERATION_VALID: xmlParserErrors = 1840;
pub const XML_SCHEMAV_CVC_PATTERN_VALID: xmlParserErrors = 1839;
pub const XML_SCHEMAV_CVC_FRACTIONDIGITS_VALID: xmlParserErrors = 1838;
pub const XML_SCHEMAV_CVC_TOTALDIGITS_VALID: xmlParserErrors = 1837;
pub const XML_SCHEMAV_CVC_MAXEXCLUSIVE_VALID: xmlParserErrors = 1836;
pub const XML_SCHEMAV_CVC_MINEXCLUSIVE_VALID: xmlParserErrors = 1835;
pub const XML_SCHEMAV_CVC_MAXINCLUSIVE_VALID: xmlParserErrors = 1834;
pub const XML_SCHEMAV_CVC_MININCLUSIVE_VALID: xmlParserErrors = 1833;
pub const XML_SCHEMAV_CVC_MAXLENGTH_VALID: xmlParserErrors = 1832;
pub const XML_SCHEMAV_CVC_MINLENGTH_VALID: xmlParserErrors = 1831;
pub const XML_SCHEMAV_CVC_LENGTH_VALID: xmlParserErrors = 1830;
pub const XML_SCHEMAV_CVC_FACET_VALID: xmlParserErrors = 1829;
pub const XML_SCHEMAV_CVC_TYPE_3_1_2: xmlParserErrors = 1828;
pub const XML_SCHEMAV_CVC_TYPE_3_1_1: xmlParserErrors = 1827;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_3: xmlParserErrors = 1826;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2: xmlParserErrors = 1825;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1: xmlParserErrors = 1824;
pub const XML_SCHEMAV_FACET: xmlParserErrors = 1823;
pub const XML_SCHEMAV_VALUE: xmlParserErrors = 1822;
pub const XML_SCHEMAV_ATTRINVALID: xmlParserErrors = 1821;
pub const XML_SCHEMAV_ATTRUNKNOWN: xmlParserErrors = 1820;
pub const XML_SCHEMAV_NOTSIMPLE: xmlParserErrors = 1819;
pub const XML_SCHEMAV_INTERNAL: xmlParserErrors = 1818;
pub const XML_SCHEMAV_CONSTRUCT: xmlParserErrors = 1817;
pub const XML_SCHEMAV_NOTDETERMINIST: xmlParserErrors = 1816;
pub const XML_SCHEMAV_INVALIDELEM: xmlParserErrors = 1815;
pub const XML_SCHEMAV_INVALIDATTR: xmlParserErrors = 1814;
pub const XML_SCHEMAV_EXTRACONTENT: xmlParserErrors = 1813;
pub const XML_SCHEMAV_NOTNILLABLE: xmlParserErrors = 1812;
pub const XML_SCHEMAV_HAVEDEFAULT: xmlParserErrors = 1811;
pub const XML_SCHEMAV_ELEMCONT: xmlParserErrors = 1810;
pub const XML_SCHEMAV_NOTEMPTY: xmlParserErrors = 1809;
pub const XML_SCHEMAV_ISABSTRACT: xmlParserErrors = 1808;
pub const XML_SCHEMAV_NOROLLBACK: xmlParserErrors = 1807;
pub const XML_SCHEMAV_NOTYPE: xmlParserErrors = 1806;
pub const XML_SCHEMAV_WRONGELEM: xmlParserErrors = 1805;
pub const XML_SCHEMAV_MISSING: xmlParserErrors = 1804;
pub const XML_SCHEMAV_NOTTOPLEVEL: xmlParserErrors = 1803;
pub const XML_SCHEMAV_UNDECLAREDELEM: xmlParserErrors = 1802;
pub const XML_SCHEMAV_NOROOT: xmlParserErrors = 1801;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_3: xmlParserErrors = 1800;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_3: xmlParserErrors = 1799;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_2: xmlParserErrors = 1798;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_1: xmlParserErrors = 1797;
pub const XML_SCHEMAP_SRC_IMPORT_3_2: xmlParserErrors = 1796;
pub const XML_SCHEMAP_SRC_IMPORT_3_1: xmlParserErrors = 1795;
pub const XML_SCHEMAP_UNION_NOT_EXPRESSIBLE: xmlParserErrors = 1794;
pub const XML_SCHEMAP_INTERSECTION_NOT_EXPRESSIBLE: xmlParserErrors = 1793;
pub const XML_SCHEMAP_WILDCARD_INVALID_NS_MEMBER: xmlParserErrors = 1792;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_3: xmlParserErrors = 1791;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_2: xmlParserErrors = 1790;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_2: xmlParserErrors = 1789;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_1: xmlParserErrors = 1788;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_1: xmlParserErrors = 1787;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_5: xmlParserErrors = 1786;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_4: xmlParserErrors = 1785;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_3: xmlParserErrors = 1784;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_2: xmlParserErrors = 1783;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_1: xmlParserErrors = 1782;
pub const XML_SCHEMAP_REF_AND_CONTENT: xmlParserErrors = 1781;
pub const XML_SCHEMAP_INVALID_ATTR_NAME: xmlParserErrors = 1780;
pub const XML_SCHEMAP_MISSING_SIMPLETYPE_CHILD: xmlParserErrors = 1779;
pub const XML_SCHEMAP_INVALID_ATTR_INLINE_COMBINATION: xmlParserErrors = 1778;
pub const XML_SCHEMAP_INVALID_ATTR_COMBINATION: xmlParserErrors = 1777;
pub const XML_SCHEMAP_SUPERNUMEROUS_LIST_ITEM_TYPE: xmlParserErrors = 1776;
pub const XML_SCHEMAP_RECURSIVE: xmlParserErrors = 1775;
pub const XML_SCHEMAP_INVALID_ATTR_USE: xmlParserErrors = 1774;
pub const XML_SCHEMAP_UNKNOWN_MEMBER_TYPE: xmlParserErrors = 1773;
pub const XML_SCHEMAP_NOT_SCHEMA: xmlParserErrors = 1772;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NO_URI: xmlParserErrors = 1771;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NOT_URI: xmlParserErrors = 1770;
pub const XML_SCHEMAP_UNKNOWN_INCLUDE_CHILD: xmlParserErrors = 1769;
pub const XML_SCHEMAP_DEF_AND_PREFIX: xmlParserErrors = 1768;
pub const XML_SCHEMAP_UNKNOWN_PREFIX: xmlParserErrors = 1767;
pub const XML_SCHEMAP_FAILED_PARSE: xmlParserErrors = 1766;
pub const XML_SCHEMAP_REDEFINED_NOTATION: xmlParserErrors = 1765;
pub const XML_SCHEMAP_REDEFINED_ATTR: xmlParserErrors = 1764;
pub const XML_SCHEMAP_REDEFINED_ATTRGROUP: xmlParserErrors = 1763;
pub const XML_SCHEMAP_REDEFINED_ELEMENT: xmlParserErrors = 1762;
pub const XML_SCHEMAP_REDEFINED_TYPE: xmlParserErrors = 1761;
pub const XML_SCHEMAP_REDEFINED_GROUP: xmlParserErrors = 1760;
pub const XML_SCHEMAP_NOROOT: xmlParserErrors = 1759;
pub const XML_SCHEMAP_NOTHING_TO_PARSE: xmlParserErrors = 1758;
pub const XML_SCHEMAP_FAILED_LOAD: xmlParserErrors = 1757;
pub const XML_SCHEMAP_REGEXP_INVALID: xmlParserErrors = 1756;
pub const XML_SCHEMAP_ELEM_DEFAULT_FIXED: xmlParserErrors = 1755;
pub const XML_SCHEMAP_UNKNOWN_UNION_CHILD: xmlParserErrors = 1754;
pub const XML_SCHEMAP_UNKNOWN_TYPE: xmlParserErrors = 1753;
pub const XML_SCHEMAP_UNKNOWN_SIMPLETYPE_CHILD: xmlParserErrors = 1752;
pub const XML_SCHEMAP_UNKNOWN_SIMPLECONTENT_CHILD: xmlParserErrors = 1751;
pub const XML_SCHEMAP_UNKNOWN_SEQUENCE_CHILD: xmlParserErrors = 1750;
pub const XML_SCHEMAP_UNKNOWN_SCHEMAS_CHILD: xmlParserErrors = 1749;
pub const XML_SCHEMAP_UNKNOWN_RESTRICTION_CHILD: xmlParserErrors = 1748;
pub const XML_SCHEMAP_UNKNOWN_REF: xmlParserErrors = 1747;
pub const XML_SCHEMAP_UNKNOWN_PROCESSCONTENT_CHILD: xmlParserErrors = 1746;
pub const XML_SCHEMAP_UNKNOWN_NOTATION_CHILD: xmlParserErrors = 1745;
pub const XML_SCHEMAP_UNKNOWN_LIST_CHILD: xmlParserErrors = 1744;
pub const XML_SCHEMAP_UNKNOWN_IMPORT_CHILD: xmlParserErrors = 1743;
pub const XML_SCHEMAP_UNKNOWN_GROUP_CHILD: xmlParserErrors = 1742;
pub const XML_SCHEMAP_UNKNOWN_FACET_TYPE: xmlParserErrors = 1741;
pub const XML_SCHEMAP_UNKNOWN_FACET_CHILD: xmlParserErrors = 1740;
pub const XML_SCHEMAP_UNKNOWN_EXTENSION_CHILD: xmlParserErrors = 1739;
pub const XML_SCHEMAP_UNKNOWN_ELEM_CHILD: xmlParserErrors = 1738;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXTYPE_CHILD: xmlParserErrors = 1737;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXCONTENT_CHILD: xmlParserErrors = 1736;
pub const XML_SCHEMAP_UNKNOWN_CHOICE_CHILD: xmlParserErrors = 1735;
pub const XML_SCHEMAP_UNKNOWN_BASE_TYPE: xmlParserErrors = 1734;
pub const XML_SCHEMAP_UNKNOWN_ATTRIBUTE_GROUP: xmlParserErrors = 1733;
pub const XML_SCHEMAP_UNKNOWN_ATTRGRP_CHILD: xmlParserErrors = 1732;
pub const XML_SCHEMAP_UNKNOWN_ATTR_CHILD: xmlParserErrors = 1731;
pub const XML_SCHEMAP_UNKNOWN_ANYATTRIBUTE_CHILD: xmlParserErrors = 1730;
pub const XML_SCHEMAP_UNKNOWN_ALL_CHILD: xmlParserErrors = 1729;
pub const XML_SCHEMAP_TYPE_AND_SUBTYPE: xmlParserErrors = 1728;
pub const XML_SCHEMAP_SIMPLETYPE_NONAME: xmlParserErrors = 1727;
pub const XML_SCHEMAP_RESTRICTION_NONAME_NOREF: xmlParserErrors = 1726;
pub const XML_SCHEMAP_REF_AND_SUBTYPE: xmlParserErrors = 1725;
pub const XML_SCHEMAP_NOTYPE_NOREF: xmlParserErrors = 1724;
pub const XML_SCHEMAP_NOTATION_NO_NAME: xmlParserErrors = 1723;
pub const XML_SCHEMAP_NOATTR_NOREF: xmlParserErrors = 1722;
pub const XML_SCHEMAP_INVALID_WHITE_SPACE: xmlParserErrors = 1721;
pub const XML_SCHEMAP_INVALID_REF_AND_SUBTYPE: xmlParserErrors = 1720;
pub const XML_SCHEMAP_INVALID_MINOCCURS: xmlParserErrors = 1719;
pub const XML_SCHEMAP_INVALID_MAXOCCURS: xmlParserErrors = 1718;
pub const XML_SCHEMAP_INVALID_FACET_VALUE: xmlParserErrors = 1717;
pub const XML_SCHEMAP_INVALID_FACET: xmlParserErrors = 1716;
pub const XML_SCHEMAP_INVALID_ENUM: xmlParserErrors = 1715;
pub const XML_SCHEMAP_INVALID_BOOLEAN: xmlParserErrors = 1714;
pub const XML_SCHEMAP_IMPORT_SCHEMA_NOT_URI: xmlParserErrors = 1713;
pub const XML_SCHEMAP_IMPORT_REDEFINE_NSNAME: xmlParserErrors = 1712;
pub const XML_SCHEMAP_IMPORT_NAMESPACE_NOT_URI: xmlParserErrors = 1711;
pub const XML_SCHEMAP_GROUP_NONAME_NOREF: xmlParserErrors = 1710;
pub const XML_SCHEMAP_FAILED_BUILD_IMPORT: xmlParserErrors = 1709;
pub const XML_SCHEMAP_FACET_NO_VALUE: xmlParserErrors = 1708;
pub const XML_SCHEMAP_EXTENSION_NO_BASE: xmlParserErrors = 1707;
pub const XML_SCHEMAP_ELEM_NONAME_NOREF: xmlParserErrors = 1706;
pub const XML_SCHEMAP_ELEMFORMDEFAULT_VALUE: xmlParserErrors = 1705;
pub const XML_SCHEMAP_COMPLEXTYPE_NONAME_NOREF: xmlParserErrors = 1704;
pub const XML_SCHEMAP_ATTR_NONAME_NOREF: xmlParserErrors = 1703;
pub const XML_SCHEMAP_ATTRGRP_NONAME_NOREF: xmlParserErrors = 1702;
pub const XML_SCHEMAP_ATTRFORMDEFAULT_VALUE: xmlParserErrors = 1701;
pub const XML_SCHEMAP_PREFIX_UNDEFINED: xmlParserErrors = 1700;
pub const XML_CATALOG_RECURSION: xmlParserErrors = 1654;
pub const XML_CATALOG_NOT_CATALOG: xmlParserErrors = 1653;
pub const XML_CATALOG_PREFER_VALUE: xmlParserErrors = 1652;
pub const XML_CATALOG_ENTRY_BROKEN: xmlParserErrors = 1651;
pub const XML_CATALOG_MISSING_ATTR: xmlParserErrors = 1650;
pub const XML_XINCLUDE_FRAGMENT_ID: xmlParserErrors = 1618;
pub const XML_XINCLUDE_DEPRECATED_NS: xmlParserErrors = 1617;
pub const XML_XINCLUDE_FALLBACK_NOT_IN_INCLUDE: xmlParserErrors = 1616;
pub const XML_XINCLUDE_FALLBACKS_IN_INCLUDE: xmlParserErrors = 1615;
pub const XML_XINCLUDE_INCLUDE_IN_INCLUDE: xmlParserErrors = 1614;
pub const XML_XINCLUDE_XPTR_RESULT: xmlParserErrors = 1613;
pub const XML_XINCLUDE_XPTR_FAILED: xmlParserErrors = 1612;
pub const XML_XINCLUDE_MULTIPLE_ROOT: xmlParserErrors = 1611;
pub const XML_XINCLUDE_UNKNOWN_ENCODING: xmlParserErrors = 1610;
pub const XML_XINCLUDE_BUILD_FAILED: xmlParserErrors = 1609;
pub const XML_XINCLUDE_INVALID_CHAR: xmlParserErrors = 1608;
pub const XML_XINCLUDE_TEXT_DOCUMENT: xmlParserErrors = 1607;
pub const XML_XINCLUDE_TEXT_FRAGMENT: xmlParserErrors = 1606;
pub const XML_XINCLUDE_HREF_URI: xmlParserErrors = 1605;
pub const XML_XINCLUDE_NO_FALLBACK: xmlParserErrors = 1604;
pub const XML_XINCLUDE_NO_HREF: xmlParserErrors = 1603;
pub const XML_XINCLUDE_ENTITY_DEF_MISMATCH: xmlParserErrors = 1602;
pub const XML_XINCLUDE_PARSE_VALUE: xmlParserErrors = 1601;
pub const XML_XINCLUDE_RECURSION: xmlParserErrors = 1600;
pub const XML_IO_EAFNOSUPPORT: xmlParserErrors = 1556;
pub const XML_IO_EALREADY: xmlParserErrors = 1555;
pub const XML_IO_EADDRINUSE: xmlParserErrors = 1554;
pub const XML_IO_ENETUNREACH: xmlParserErrors = 1553;
pub const XML_IO_ECONNREFUSED: xmlParserErrors = 1552;
pub const XML_IO_EISCONN: xmlParserErrors = 1551;
pub const XML_IO_ENOTSOCK: xmlParserErrors = 1550;
pub const XML_IO_LOAD_ERROR: xmlParserErrors = 1549;
pub const XML_IO_BUFFER_FULL: xmlParserErrors = 1548;
pub const XML_IO_NO_INPUT: xmlParserErrors = 1547;
pub const XML_IO_WRITE: xmlParserErrors = 1546;
pub const XML_IO_FLUSH: xmlParserErrors = 1545;
pub const XML_IO_ENCODER: xmlParserErrors = 1544;
pub const XML_IO_NETWORK_ATTEMPT: xmlParserErrors = 1543;
pub const XML_IO_EXDEV: xmlParserErrors = 1542;
pub const XML_IO_ETIMEDOUT: xmlParserErrors = 1541;
pub const XML_IO_ESRCH: xmlParserErrors = 1540;
pub const XML_IO_ESPIPE: xmlParserErrors = 1539;
pub const XML_IO_EROFS: xmlParserErrors = 1538;
pub const XML_IO_ERANGE: xmlParserErrors = 1537;
pub const XML_IO_EPIPE: xmlParserErrors = 1536;
pub const XML_IO_EPERM: xmlParserErrors = 1535;
pub const XML_IO_ENXIO: xmlParserErrors = 1534;
pub const XML_IO_ENOTTY: xmlParserErrors = 1533;
pub const XML_IO_ENOTSUP: xmlParserErrors = 1532;
pub const XML_IO_ENOTEMPTY: xmlParserErrors = 1531;
pub const XML_IO_ENOTDIR: xmlParserErrors = 1530;
pub const XML_IO_ENOSYS: xmlParserErrors = 1529;
pub const XML_IO_ENOSPC: xmlParserErrors = 1528;
pub const XML_IO_ENOMEM: xmlParserErrors = 1527;
pub const XML_IO_ENOLCK: xmlParserErrors = 1526;
pub const XML_IO_ENOEXEC: xmlParserErrors = 1525;
pub const XML_IO_ENOENT: xmlParserErrors = 1524;
pub const XML_IO_ENODEV: xmlParserErrors = 1523;
pub const XML_IO_ENFILE: xmlParserErrors = 1522;
pub const XML_IO_ENAMETOOLONG: xmlParserErrors = 1521;
pub const XML_IO_EMSGSIZE: xmlParserErrors = 1520;
pub const XML_IO_EMLINK: xmlParserErrors = 1519;
pub const XML_IO_EMFILE: xmlParserErrors = 1518;
pub const XML_IO_EISDIR: xmlParserErrors = 1517;
pub const XML_IO_EIO: xmlParserErrors = 1516;
pub const XML_IO_EINVAL: xmlParserErrors = 1515;
pub const XML_IO_EINTR: xmlParserErrors = 1514;
pub const XML_IO_EINPROGRESS: xmlParserErrors = 1513;
pub const XML_IO_EFBIG: xmlParserErrors = 1512;
pub const XML_IO_EFAULT: xmlParserErrors = 1511;
pub const XML_IO_EEXIST: xmlParserErrors = 1510;
pub const XML_IO_EDOM: xmlParserErrors = 1509;
pub const XML_IO_EDEADLK: xmlParserErrors = 1508;
pub const XML_IO_ECHILD: xmlParserErrors = 1507;
pub const XML_IO_ECANCELED: xmlParserErrors = 1506;
pub const XML_IO_EBUSY: xmlParserErrors = 1505;
pub const XML_IO_EBADMSG: xmlParserErrors = 1504;
pub const XML_IO_EBADF: xmlParserErrors = 1503;
pub const XML_IO_EAGAIN: xmlParserErrors = 1502;
pub const XML_IO_EACCES: xmlParserErrors = 1501;
pub const XML_IO_UNKNOWN: xmlParserErrors = 1500;
pub const XML_REGEXP_COMPILE_ERROR: xmlParserErrors = 1450;
pub const XML_SAVE_UNKNOWN_ENCODING: xmlParserErrors = 1403;
pub const XML_SAVE_NO_DOCTYPE: xmlParserErrors = 1402;
pub const XML_SAVE_CHAR_INVALID: xmlParserErrors = 1401;
pub const XML_SAVE_NOT_UTF8: xmlParserErrors = 1400;
pub const XML_TREE_NOT_UTF8: xmlParserErrors = 1303;
pub const XML_TREE_UNTERMINATED_ENTITY: xmlParserErrors = 1302;
pub const XML_TREE_INVALID_DEC: xmlParserErrors = 1301;
pub const XML_TREE_INVALID_HEX: xmlParserErrors = 1300;
pub const XML_XPATH_INVALID_CHAR_ERROR: xmlParserErrors = 1221;
pub const XML_XPATH_ENCODING_ERROR: xmlParserErrors = 1220;
pub const XML_XPATH_UNDEF_PREFIX_ERROR: xmlParserErrors = 1219;
pub const XML_XPTR_SUB_RESOURCE_ERROR: xmlParserErrors = 1218;
pub const XML_XPTR_RESOURCE_ERROR: xmlParserErrors = 1217;
pub const XML_XPTR_SYNTAX_ERROR: xmlParserErrors = 1216;
pub const XML_XPATH_MEMORY_ERROR: xmlParserErrors = 1215;
pub const XML_XPATH_INVALID_CTXT_POSITION: xmlParserErrors = 1214;
pub const XML_XPATH_INVALID_CTXT_SIZE: xmlParserErrors = 1213;
pub const XML_XPATH_INVALID_ARITY: xmlParserErrors = 1212;
pub const XML_XPATH_INVALID_TYPE: xmlParserErrors = 1211;
pub const XML_XPATH_INVALID_OPERAND: xmlParserErrors = 1210;
pub const XML_XPATH_UNKNOWN_FUNC_ERROR: xmlParserErrors = 1209;
pub const XML_XPATH_UNCLOSED_ERROR: xmlParserErrors = 1208;
pub const XML_XPATH_EXPR_ERROR: xmlParserErrors = 1207;
pub const XML_XPATH_INVALID_PREDICATE_ERROR: xmlParserErrors = 1206;
pub const XML_XPATH_UNDEF_VARIABLE_ERROR: xmlParserErrors = 1205;
pub const XML_XPATH_VARIABLE_REF_ERROR: xmlParserErrors = 1204;
pub const XML_XPATH_START_LITERAL_ERROR: xmlParserErrors = 1203;
pub const XML_XPATH_UNFINISHED_LITERAL_ERROR: xmlParserErrors = 1202;
pub const XML_XPATH_NUMBER_ERROR: xmlParserErrors = 1201;
pub const XML_XPATH_EXPRESSION_OK: xmlParserErrors = 1200;
pub const XML_RNGP_XML_NS: xmlParserErrors = 1122;
pub const XML_RNGP_XMLNS_NAME: xmlParserErrors = 1121;
pub const XML_RNGP_VALUE_NO_CONTENT: xmlParserErrors = 1120;
pub const XML_RNGP_VALUE_EMPTY: xmlParserErrors = 1119;
pub const XML_RNGP_URI_NOT_ABSOLUTE: xmlParserErrors = 1118;
pub const XML_RNGP_URI_FRAGMENT: xmlParserErrors = 1117;
pub const XML_RNGP_UNKNOWN_TYPE_LIB: xmlParserErrors = 1116;
pub const XML_RNGP_UNKNOWN_CONSTRUCT: xmlParserErrors = 1115;
pub const XML_RNGP_UNKNOWN_COMBINE: xmlParserErrors = 1114;
pub const XML_RNGP_UNKNOWN_ATTRIBUTE: xmlParserErrors = 1113;
pub const XML_RNGP_TYPE_VALUE: xmlParserErrors = 1112;
pub const XML_RNGP_TYPE_NOT_FOUND: xmlParserErrors = 1111;
pub const XML_RNGP_TYPE_MISSING: xmlParserErrors = 1110;
pub const XML_RNGP_TEXT_HAS_CHILD: xmlParserErrors = 1109;
pub const XML_RNGP_TEXT_EXPECTED: xmlParserErrors = 1108;
pub const XML_RNGP_START_MISSING: xmlParserErrors = 1107;
pub const XML_RNGP_START_EMPTY: xmlParserErrors = 1106;
pub const XML_RNGP_START_CONTENT: xmlParserErrors = 1105;
pub const XML_RNGP_START_CHOICE_AND_INTERLEAVE: xmlParserErrors = 1104;
pub const XML_RNGP_REF_NOT_EMPTY: xmlParserErrors = 1103;
pub const XML_RNGP_REF_NO_NAME: xmlParserErrors = 1102;
pub const XML_RNGP_REF_NO_DEF: xmlParserErrors = 1101;
pub const XML_RNGP_REF_NAME_INVALID: xmlParserErrors = 1100;
pub const XML_RNGP_REF_CYCLE: xmlParserErrors = 1099;
pub const XML_RNGP_REF_CREATE_FAILED: xmlParserErrors = 1098;
pub const XML_RNGP_PREFIX_UNDEFINED: xmlParserErrors = 1097;
pub const XML_RNGP_PAT_START_VALUE: xmlParserErrors = 1096;
pub const XML_RNGP_PAT_START_TEXT: xmlParserErrors = 1095;
pub const XML_RNGP_PAT_START_ONEMORE: xmlParserErrors = 1094;
pub const XML_RNGP_PAT_START_LIST: xmlParserErrors = 1093;
pub const XML_RNGP_PAT_START_INTERLEAVE: xmlParserErrors = 1092;
pub const XML_RNGP_PAT_START_GROUP: xmlParserErrors = 1091;
pub const XML_RNGP_PAT_START_EMPTY: xmlParserErrors = 1090;
pub const XML_RNGP_PAT_START_DATA: xmlParserErrors = 1089;
pub const XML_RNGP_PAT_START_ATTR: xmlParserErrors = 1088;
pub const XML_RNGP_PAT_ONEMORE_INTERLEAVE_ATTR: xmlParserErrors = 1087;
pub const XML_RNGP_PAT_ONEMORE_GROUP_ATTR: xmlParserErrors = 1086;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_NSNAME: xmlParserErrors = 1085;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_ANYNAME: xmlParserErrors = 1084;
pub const XML_RNGP_PAT_LIST_TEXT: xmlParserErrors = 1083;
pub const XML_RNGP_PAT_LIST_REF: xmlParserErrors = 1082;
pub const XML_RNGP_PAT_LIST_LIST: xmlParserErrors = 1081;
pub const XML_RNGP_PAT_LIST_INTERLEAVE: xmlParserErrors = 1080;
pub const XML_RNGP_PAT_LIST_ELEM: xmlParserErrors = 1079;
pub const XML_RNGP_PAT_LIST_ATTR: xmlParserErrors = 1078;
pub const XML_RNGP_PAT_DATA_EXCEPT_TEXT: xmlParserErrors = 1077;
pub const XML_RNGP_PAT_DATA_EXCEPT_REF: xmlParserErrors = 1076;
pub const XML_RNGP_PAT_DATA_EXCEPT_ONEMORE: xmlParserErrors = 1075;
pub const XML_RNGP_PAT_DATA_EXCEPT_LIST: xmlParserErrors = 1074;
pub const XML_RNGP_PAT_DATA_EXCEPT_INTERLEAVE: xmlParserErrors = 1073;
pub const XML_RNGP_PAT_DATA_EXCEPT_GROUP: xmlParserErrors = 1072;
pub const XML_RNGP_PAT_DATA_EXCEPT_EMPTY: xmlParserErrors = 1071;
pub const XML_RNGP_PAT_DATA_EXCEPT_ELEM: xmlParserErrors = 1070;
pub const XML_RNGP_PAT_DATA_EXCEPT_ATTR: xmlParserErrors = 1069;
pub const XML_RNGP_PAT_ATTR_ELEM: xmlParserErrors = 1068;
pub const XML_RNGP_PAT_ATTR_ATTR: xmlParserErrors = 1067;
pub const XML_RNGP_PAT_ANYNAME_EXCEPT_ANYNAME: xmlParserErrors = 1066;
pub const XML_RNGP_PARSE_ERROR: xmlParserErrors = 1065;
pub const XML_RNGP_PARENTREF_NOT_EMPTY: xmlParserErrors = 1064;
pub const XML_RNGP_PARENTREF_NO_PARENT: xmlParserErrors = 1063;
pub const XML_RNGP_PARENTREF_NO_NAME: xmlParserErrors = 1062;
pub const XML_RNGP_PARENTREF_NAME_INVALID: xmlParserErrors = 1061;
pub const XML_RNGP_PARENTREF_CREATE_FAILED: xmlParserErrors = 1060;
pub const XML_RNGP_PARAM_NAME_MISSING: xmlParserErrors = 1059;
pub const XML_RNGP_PARAM_FORBIDDEN: xmlParserErrors = 1058;
pub const XML_RNGP_NSNAME_NO_NS: xmlParserErrors = 1057;
pub const XML_RNGP_NSNAME_ATTR_ANCESTOR: xmlParserErrors = 1056;
pub const XML_RNGP_NOTALLOWED_NOT_EMPTY: xmlParserErrors = 1055;
pub const XML_RNGP_NEED_COMBINE: xmlParserErrors = 1054;
pub const XML_RNGP_NAME_MISSING: xmlParserErrors = 1053;
pub const XML_RNGP_MISSING_HREF: xmlParserErrors = 1052;
pub const XML_RNGP_INVALID_VALUE: xmlParserErrors = 1051;
pub const XML_RNGP_INVALID_URI: xmlParserErrors = 1050;
pub const XML_RNGP_INVALID_DEFINE_NAME: xmlParserErrors = 1049;
pub const XML_RNGP_INTERLEAVE_NO_CONTENT: xmlParserErrors = 1048;
pub const XML_RNGP_INTERLEAVE_EMPTY: xmlParserErrors = 1047;
pub const XML_RNGP_INTERLEAVE_CREATE_FAILED: xmlParserErrors = 1046;
pub const XML_RNGP_INTERLEAVE_ADD: xmlParserErrors = 1045;
pub const XML_RNGP_INCLUDE_RECURSE: xmlParserErrors = 1044;
pub const XML_RNGP_INCLUDE_FAILURE: xmlParserErrors = 1043;
pub const XML_RNGP_INCLUDE_EMPTY: xmlParserErrors = 1042;
pub const XML_RNGP_HREF_ERROR: xmlParserErrors = 1041;
pub const XML_RNGP_GROUP_ATTR_CONFLICT: xmlParserErrors = 1040;
pub const XML_RNGP_GRAMMAR_NO_START: xmlParserErrors = 1039;
pub const XML_RNGP_GRAMMAR_MISSING: xmlParserErrors = 1038;
pub const XML_RNGP_GRAMMAR_EMPTY: xmlParserErrors = 1037;
pub const XML_RNGP_GRAMMAR_CONTENT: xmlParserErrors = 1036;
pub const XML_RNGP_FOREIGN_ELEMENT: xmlParserErrors = 1035;
pub const XML_RNGP_FORBIDDEN_ATTRIBUTE: xmlParserErrors = 1034;
pub const XML_RNGP_EXTERNALREF_RECURSE: xmlParserErrors = 1033;
pub const XML_RNGP_EXTERNAL_REF_FAILURE: xmlParserErrors = 1032;
pub const XML_RNGP_EXTERNALREF_EMTPY: xmlParserErrors = 1031;
pub const XML_RNGP_EXCEPT_NO_CONTENT: xmlParserErrors = 1030;
pub const XML_RNGP_EXCEPT_MULTIPLE: xmlParserErrors = 1029;
pub const XML_RNGP_EXCEPT_MISSING: xmlParserErrors = 1028;
pub const XML_RNGP_EXCEPT_EMPTY: xmlParserErrors = 1027;
pub const XML_RNGP_ERROR_TYPE_LIB: xmlParserErrors = 1026;
pub const XML_RNGP_EMPTY_NOT_EMPTY: xmlParserErrors = 1025;
pub const XML_RNGP_EMPTY_CONTENT: xmlParserErrors = 1024;
pub const XML_RNGP_EMPTY_CONSTRUCT: xmlParserErrors = 1023;
pub const XML_RNGP_EMPTY: xmlParserErrors = 1022;
pub const XML_RNGP_ELEM_TEXT_CONFLICT: xmlParserErrors = 1021;
pub const XML_RNGP_ELEMENT_NO_CONTENT: xmlParserErrors = 1020;
pub const XML_RNGP_ELEMENT_NAME: xmlParserErrors = 1019;
pub const XML_RNGP_ELEMENT_CONTENT: xmlParserErrors = 1018;
pub const XML_RNGP_ELEMENT_EMPTY: xmlParserErrors = 1017;
pub const XML_RNGP_ELEM_CONTENT_ERROR: xmlParserErrors = 1016;
pub const XML_RNGP_ELEM_CONTENT_EMPTY: xmlParserErrors = 1015;
pub const XML_RNGP_DEFINE_NAME_MISSING: xmlParserErrors = 1014;
pub const XML_RNGP_DEFINE_MISSING: xmlParserErrors = 1013;
pub const XML_RNGP_DEFINE_EMPTY: xmlParserErrors = 1012;
pub const XML_RNGP_DEFINE_CREATE_FAILED: xmlParserErrors = 1011;
pub const XML_RNGP_DEF_CHOICE_AND_INTERLEAVE: xmlParserErrors = 1010;
pub const XML_RNGP_DATA_CONTENT: xmlParserErrors = 1009;
pub const XML_RNGP_CREATE_FAILURE: xmlParserErrors = 1008;
pub const XML_RNGP_CHOICE_EMPTY: xmlParserErrors = 1007;
pub const XML_RNGP_CHOICE_CONTENT: xmlParserErrors = 1006;
pub const XML_RNGP_ATTRIBUTE_NOOP: xmlParserErrors = 1005;
pub const XML_RNGP_ATTRIBUTE_EMPTY: xmlParserErrors = 1004;
pub const XML_RNGP_ATTRIBUTE_CONTENT: xmlParserErrors = 1003;
pub const XML_RNGP_ATTRIBUTE_CHILDREN: xmlParserErrors = 1002;
pub const XML_RNGP_ATTR_CONFLICT: xmlParserErrors = 1001;
pub const XML_RNGP_ANYNAME_ATTR_ANCESTOR: xmlParserErrors = 1000;
pub const XML_HTML_INCORRECTLY_OPENED_COMMENT: xmlParserErrors = 802;
pub const XML_HTML_UNKNOWN_TAG: xmlParserErrors = 801;
pub const XML_HTML_STRUCURE_ERROR: xmlParserErrors = 800;
pub const XML_DTD_DUP_TOKEN: xmlParserErrors = 541;
pub const XML_DTD_XMLID_TYPE: xmlParserErrors = 540;
pub const XML_DTD_XMLID_VALUE: xmlParserErrors = 539;
pub const XML_DTD_STANDALONE_DEFAULTED: xmlParserErrors = 538;
pub const XML_DTD_UNKNOWN_NOTATION: xmlParserErrors = 537;
pub const XML_DTD_UNKNOWN_ID: xmlParserErrors = 536;
pub const XML_DTD_UNKNOWN_ENTITY: xmlParserErrors = 535;
pub const XML_DTD_UNKNOWN_ELEM: xmlParserErrors = 534;
pub const XML_DTD_UNKNOWN_ATTRIBUTE: xmlParserErrors = 533;
pub const XML_DTD_STANDALONE_WHITE_SPACE: xmlParserErrors = 532;
pub const XML_DTD_ROOT_NAME: xmlParserErrors = 531;
pub const XML_DTD_NOT_STANDALONE: xmlParserErrors = 530;
pub const XML_DTD_NOT_PCDATA: xmlParserErrors = 529;
pub const XML_DTD_NOT_EMPTY: xmlParserErrors = 528;
pub const XML_DTD_NOTATION_VALUE: xmlParserErrors = 527;
pub const XML_DTD_NOTATION_REDEFINED: xmlParserErrors = 526;
pub const XML_DTD_NO_ROOT: xmlParserErrors = 525;
pub const XML_DTD_NO_PREFIX: xmlParserErrors = 524;
pub const XML_DTD_NO_ELEM_NAME: xmlParserErrors = 523;
pub const XML_DTD_NO_DTD: xmlParserErrors = 522;
pub const XML_DTD_NO_DOC: xmlParserErrors = 521;
pub const XML_DTD_MULTIPLE_ID: xmlParserErrors = 520;
pub const XML_DTD_MIXED_CORRUPT: xmlParserErrors = 519;
pub const XML_DTD_MISSING_ATTRIBUTE: xmlParserErrors = 518;
pub const XML_DTD_LOAD_ERROR: xmlParserErrors = 517;
pub const XML_DTD_INVALID_DEFAULT: xmlParserErrors = 516;
pub const XML_DTD_INVALID_CHILD: xmlParserErrors = 515;
pub const XML_DTD_ID_SUBSET: xmlParserErrors = 514;
pub const XML_DTD_ID_REDEFINED: xmlParserErrors = 513;
pub const XML_DTD_ID_FIXED: xmlParserErrors = 512;
pub const XML_DTD_ENTITY_TYPE: xmlParserErrors = 511;
pub const XML_DTD_EMPTY_NOTATION: xmlParserErrors = 510;
pub const XML_DTD_ELEM_REDEFINED: xmlParserErrors = 509;
pub const XML_DTD_ELEM_NAMESPACE: xmlParserErrors = 508;
pub const XML_DTD_ELEM_DEFAULT_NAMESPACE: xmlParserErrors = 507;
pub const XML_DTD_DIFFERENT_PREFIX: xmlParserErrors = 506;
pub const XML_DTD_CONTENT_NOT_DETERMINIST: xmlParserErrors = 505;
pub const XML_DTD_CONTENT_MODEL: xmlParserErrors = 504;
pub const XML_DTD_CONTENT_ERROR: xmlParserErrors = 503;
pub const XML_DTD_ATTRIBUTE_VALUE: xmlParserErrors = 502;
pub const XML_DTD_ATTRIBUTE_REDEFINED: xmlParserErrors = 501;
pub const XML_DTD_ATTRIBUTE_DEFAULT: xmlParserErrors = 500;
pub const XML_NS_ERR_COLON: xmlParserErrors = 205;
pub const XML_NS_ERR_EMPTY: xmlParserErrors = 204;
pub const XML_NS_ERR_ATTRIBUTE_REDEFINED: xmlParserErrors = 203;
pub const XML_NS_ERR_QNAME: xmlParserErrors = 202;
pub const XML_NS_ERR_UNDEFINED_NAMESPACE: xmlParserErrors = 201;
pub const XML_NS_ERR_XML_NAMESPACE: xmlParserErrors = 200;
pub const XML_ERR_COMMENT_ABRUPTLY_ENDED: xmlParserErrors = 112;
pub const XML_ERR_USER_STOP: xmlParserErrors = 111;
pub const XML_ERR_NAME_TOO_LONG: xmlParserErrors = 110;
pub const XML_ERR_VERSION_MISMATCH: xmlParserErrors = 109;
pub const XML_ERR_UNKNOWN_VERSION: xmlParserErrors = 108;
pub const XML_WAR_ENTITY_REDEFINED: xmlParserErrors = 107;
pub const XML_WAR_NS_COLUMN: xmlParserErrors = 106;
pub const XML_ERR_NOTATION_PROCESSING: xmlParserErrors = 105;
pub const XML_ERR_ENTITY_PROCESSING: xmlParserErrors = 104;
pub const XML_ERR_NOT_STANDALONE: xmlParserErrors = 103;
pub const XML_WAR_SPACE_VALUE: xmlParserErrors = 102;
pub const XML_ERR_MISSING_ENCODING: xmlParserErrors = 101;
pub const XML_WAR_NS_URI_RELATIVE: xmlParserErrors = 100;
pub const XML_WAR_NS_URI: xmlParserErrors = 99;
pub const XML_WAR_LANG_VALUE: xmlParserErrors = 98;
pub const XML_WAR_UNKNOWN_VERSION: xmlParserErrors = 97;
pub const XML_ERR_VERSION_MISSING: xmlParserErrors = 96;
pub const XML_ERR_CONDSEC_INVALID_KEYWORD: xmlParserErrors = 95;
pub const XML_ERR_NO_DTD: xmlParserErrors = 94;
pub const XML_WAR_CATALOG_PI: xmlParserErrors = 93;
pub const XML_ERR_URI_FRAGMENT: xmlParserErrors = 92;
pub const XML_ERR_INVALID_URI: xmlParserErrors = 91;
pub const XML_ERR_ENTITY_BOUNDARY: xmlParserErrors = 90;
pub const XML_ERR_ENTITY_LOOP: xmlParserErrors = 89;
pub const XML_ERR_ENTITY_PE_INTERNAL: xmlParserErrors = 88;
pub const XML_ERR_ENTITY_CHAR_ERROR: xmlParserErrors = 87;
pub const XML_ERR_EXTRA_CONTENT: xmlParserErrors = 86;
pub const XML_ERR_NOT_WELL_BALANCED: xmlParserErrors = 85;
pub const XML_ERR_VALUE_REQUIRED: xmlParserErrors = 84;
pub const XML_ERR_CONDSEC_INVALID: xmlParserErrors = 83;
pub const XML_ERR_EXT_ENTITY_STANDALONE: xmlParserErrors = 82;
pub const XML_ERR_INVALID_ENCODING: xmlParserErrors = 81;
pub const XML_ERR_HYPHEN_IN_COMMENT: xmlParserErrors = 80;
pub const XML_ERR_ENCODING_NAME: xmlParserErrors = 79;
pub const XML_ERR_STANDALONE_VALUE: xmlParserErrors = 78;
pub const XML_ERR_TAG_NOT_FINISHED: xmlParserErrors = 77;
pub const XML_ERR_TAG_NAME_MISMATCH: xmlParserErrors = 76;
pub const XML_ERR_EQUAL_REQUIRED: xmlParserErrors = 75;
pub const XML_ERR_LTSLASH_REQUIRED: xmlParserErrors = 74;
pub const XML_ERR_GT_REQUIRED: xmlParserErrors = 73;
pub const XML_ERR_LT_REQUIRED: xmlParserErrors = 72;
pub const XML_ERR_PUBID_REQUIRED: xmlParserErrors = 71;
pub const XML_ERR_URI_REQUIRED: xmlParserErrors = 70;
pub const XML_ERR_PCDATA_REQUIRED: xmlParserErrors = 69;
pub const XML_ERR_NAME_REQUIRED: xmlParserErrors = 68;
pub const XML_ERR_NMTOKEN_REQUIRED: xmlParserErrors = 67;
pub const XML_ERR_SEPARATOR_REQUIRED: xmlParserErrors = 66;
pub const XML_ERR_SPACE_REQUIRED: xmlParserErrors = 65;
pub const XML_ERR_RESERVED_XML_NAME: xmlParserErrors = 64;
pub const XML_ERR_CDATA_NOT_FINISHED: xmlParserErrors = 63;
pub const XML_ERR_MISPLACED_CDATA_END: xmlParserErrors = 62;
pub const XML_ERR_DOCTYPE_NOT_FINISHED: xmlParserErrors = 61;
pub const XML_ERR_EXT_SUBSET_NOT_FINISHED: xmlParserErrors = 60;
pub const XML_ERR_CONDSEC_NOT_FINISHED: xmlParserErrors = 59;
pub const XML_ERR_CONDSEC_NOT_STARTED: xmlParserErrors = 58;
pub const XML_ERR_XMLDECL_NOT_FINISHED: xmlParserErrors = 57;
pub const XML_ERR_XMLDECL_NOT_STARTED: xmlParserErrors = 56;
pub const XML_ERR_ELEMCONTENT_NOT_FINISHED: xmlParserErrors = 55;
pub const XML_ERR_ELEMCONTENT_NOT_STARTED: xmlParserErrors = 54;
pub const XML_ERR_MIXED_NOT_FINISHED: xmlParserErrors = 53;
pub const XML_ERR_MIXED_NOT_STARTED: xmlParserErrors = 52;
pub const XML_ERR_ATTLIST_NOT_FINISHED: xmlParserErrors = 51;
pub const XML_ERR_ATTLIST_NOT_STARTED: xmlParserErrors = 50;
pub const XML_ERR_NOTATION_NOT_FINISHED: xmlParserErrors = 49;
pub const XML_ERR_NOTATION_NOT_STARTED: xmlParserErrors = 48;
pub const XML_ERR_PI_NOT_FINISHED: xmlParserErrors = 47;
pub const XML_ERR_PI_NOT_STARTED: xmlParserErrors = 46;
pub const XML_ERR_COMMENT_NOT_FINISHED: xmlParserErrors = 45;
pub const XML_ERR_LITERAL_NOT_FINISHED: xmlParserErrors = 44;
pub const XML_ERR_LITERAL_NOT_STARTED: xmlParserErrors = 43;
pub const XML_ERR_ATTRIBUTE_REDEFINED: xmlParserErrors = 42;
pub const XML_ERR_ATTRIBUTE_WITHOUT_VALUE: xmlParserErrors = 41;
pub const XML_ERR_ATTRIBUTE_NOT_FINISHED: xmlParserErrors = 40;
pub const XML_ERR_ATTRIBUTE_NOT_STARTED: xmlParserErrors = 39;
pub const XML_ERR_LT_IN_ATTRIBUTE: xmlParserErrors = 38;
pub const XML_ERR_ENTITY_NOT_FINISHED: xmlParserErrors = 37;
pub const XML_ERR_ENTITY_NOT_STARTED: xmlParserErrors = 36;
pub const XML_ERR_NS_DECL_ERROR: xmlParserErrors = 35;
pub const XML_ERR_STRING_NOT_CLOSED: xmlParserErrors = 34;
pub const XML_ERR_STRING_NOT_STARTED: xmlParserErrors = 33;
pub const XML_ERR_UNSUPPORTED_ENCODING: xmlParserErrors = 32;
pub const XML_ERR_UNKNOWN_ENCODING: xmlParserErrors = 31;
pub const XML_ERR_ENTITY_IS_PARAMETER: xmlParserErrors = 30;
pub const XML_ERR_ENTITY_IS_EXTERNAL: xmlParserErrors = 29;
pub const XML_ERR_UNPARSED_ENTITY: xmlParserErrors = 28;
pub const XML_WAR_UNDECLARED_ENTITY: xmlParserErrors = 27;
pub const XML_ERR_UNDECLARED_ENTITY: xmlParserErrors = 26;
pub const XML_ERR_PEREF_SEMICOL_MISSING: xmlParserErrors = 25;
pub const XML_ERR_PEREF_NO_NAME: xmlParserErrors = 24;
pub const XML_ERR_ENTITYREF_SEMICOL_MISSING: xmlParserErrors = 23;
pub const XML_ERR_ENTITYREF_NO_NAME: xmlParserErrors = 22;
pub const XML_ERR_PEREF_IN_INT_SUBSET: xmlParserErrors = 21;
pub const XML_ERR_PEREF_IN_EPILOG: xmlParserErrors = 20;
pub const XML_ERR_PEREF_IN_PROLOG: xmlParserErrors = 19;
pub const XML_ERR_PEREF_AT_EOF: xmlParserErrors = 18;
pub const XML_ERR_ENTITYREF_IN_DTD: xmlParserErrors = 17;
pub const XML_ERR_ENTITYREF_IN_EPILOG: xmlParserErrors = 16;
pub const XML_ERR_ENTITYREF_IN_PROLOG: xmlParserErrors = 15;
pub const XML_ERR_ENTITYREF_AT_EOF: xmlParserErrors = 14;
pub const XML_ERR_CHARREF_IN_DTD: xmlParserErrors = 13;
pub const XML_ERR_CHARREF_IN_EPILOG: xmlParserErrors = 12;
pub const XML_ERR_CHARREF_IN_PROLOG: xmlParserErrors = 11;
pub const XML_ERR_CHARREF_AT_EOF: xmlParserErrors = 10;
pub const XML_ERR_INVALID_CHAR: xmlParserErrors = 9;
pub const XML_ERR_INVALID_CHARREF: xmlParserErrors = 8;
pub const XML_ERR_INVALID_DEC_CHARREF: xmlParserErrors = 7;
pub const XML_ERR_INVALID_HEX_CHARREF: xmlParserErrors = 6;
pub const XML_ERR_DOCUMENT_END: xmlParserErrors = 5;
pub const XML_ERR_DOCUMENT_EMPTY: xmlParserErrors = 4;
pub const XML_ERR_DOCUMENT_START: xmlParserErrors = 3;
pub const XML_ERR_NO_MEMORY: xmlParserErrors = 2;
pub const XML_ERR_INTERNAL_ERROR: xmlParserErrors = 1;
pub const XML_ERR_OK: xmlParserErrors = 0;
pub type xmlGenericErrorFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type xmlValidCtxtPtr = * mut crate::src::HTMLparser::_xmlValidCtxt;
pub type xmlParserNodeInfoPtr = * mut crate::src::HTMLparser::_xmlParserNodeInfo;
pub type xmlParserNodeInfoSeqPtr = * mut crate::src::HTMLparser::_xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

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
pub const XML_PARSE_OLD10: C2RustUnnamed_3 = 131072;
pub const XML_PARSE_HUGE: C2RustUnnamed_3 = 524288;
pub const XML_CATA_ALLOW_ALL: xmlCatalogAllow = 3;
pub type xmlCatalogAllow = u32;
pub const XML_CATA_ALLOW_DOCUMENT: xmlCatalogAllow = 2;
pub const XML_CATA_ALLOW_GLOBAL: xmlCatalogAllow = 1;
pub const XML_CATA_ALLOW_NONE: xmlCatalogAllow = 0;
pub const XML_PARSE_IGNORE_ENC: C2RustUnnamed_3 = 2097152;
pub const XML_PARSE_DTDATTR: C2RustUnnamed_3 = 8;
pub const XML_PARSE_DTDLOAD: C2RustUnnamed_3 = 4;
pub const XML_PARSE_DTDVALID: C2RustUnnamed_3 = 16;
pub const XML_PARSE_NOENT: C2RustUnnamed_3 = 2;
pub type xmlChRangeGroup = crate::src::HTMLparser::_xmlChRangeGroup;
// #[derive(Copy, Clone)]

pub type _xmlChRangeGroup = crate::src::HTMLparser::_xmlChRangeGroup;
pub type xmlChLRange = crate::src::HTMLparser::_xmlChLRange;
// #[derive(Copy, Clone)]

pub type _xmlChLRange = crate::src::HTMLparser::_xmlChLRange;
pub type xmlChSRange = crate::src::HTMLparser::_xmlChSRange;
// #[derive(Copy, Clone)]

pub type _xmlChSRange = crate::src::HTMLparser::_xmlChSRange;
pub const XML_PARSE_OLDSAX: C2RustUnnamed_3 = 1048576;
pub type xmlEntityReferenceFunc = Option<unsafe extern "C"  fn(_: * mut crate::src::HTMLparser::_xmlEntity,_: * mut crate::src::HTMLparser::_xmlNode,_: * mut crate::src::HTMLparser::_xmlNode,) -> ()>;
pub const XML_PARSE_NSCLEAN: C2RustUnnamed_3 = 8192;
pub type xmlDefAttrsPtr = * mut crate::src::parser::_xmlDefAttrs;
pub type xmlDefAttrs = crate::src::parser::_xmlDefAttrs;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDefAttrs {
    pub nbAttrs: i32,
    pub maxAttrs: i32,
    pub values: Option<crate::__laertes_array::CustomSlice<'static, * const u8, [* const u8; 0]>>,
}
impl _xmlDefAttrs {
    pub const fn new() -> Self {
        _xmlDefAttrs {
        nbAttrs: 0,
        maxAttrs: 0,
        values: None
        }
    }
}

impl std::default::Default for _xmlDefAttrs {
    fn default() -> Self { _xmlDefAttrs::new() }
}

pub type xmlURIPtr = * mut crate::src::SAX2::_xmlURI;
pub type xmlURI = crate::src::SAX2::_xmlURI;
// #[derive(Copy, Clone)]

pub type _xmlURI = crate::src::SAX2::_xmlURI;
pub const XML_PARSE_BIG_LINES: C2RustUnnamed_3 = 4194304;
pub const XML_PARSE_NOBASEFIX: C2RustUnnamed_3 = 262144;
pub const XML_PARSE_COMPACT: C2RustUnnamed_3 = 65536;
pub const XML_PARSE_NONET: C2RustUnnamed_3 = 2048;
pub const XML_PARSE_NOCDATA: C2RustUnnamed_3 = 16384;
pub const XML_PARSE_NODICT: C2RustUnnamed_3 = 4096;
pub const XML_PARSE_SAX1: C2RustUnnamed_3 = 512;
pub const XML_PARSE_NOERROR: C2RustUnnamed_3 = 32;
pub const XML_PARSE_NOWARNING: C2RustUnnamed_3 = 64;
pub const XML_PARSE_NOBLANKS: C2RustUnnamed_3 = 256;
pub const XML_PARSE_PEDANTIC: C2RustUnnamed_3 = 128;
pub const XML_PARSE_RECOVER: C2RustUnnamed_3 = 1;
pub const HTML_PARSE_NOIMPLIED: C2RustUnnamed_4 = 8192;
pub type htmlParserCtxtPtr = * mut crate::src::HTMLparser::_xmlParserCtxt;
pub type C2RustUnnamed_3 = u32;
pub const XML_PARSE_NOXINCNODE: C2RustUnnamed_3 = 32768;
pub const XML_PARSE_XINCLUDE: C2RustUnnamed_3 = 1024;
pub type xmlFeature = u32;
pub const XML_WITH_NONE: xmlFeature = 99999;
pub const XML_WITH_LZMA: xmlFeature = 33;
pub const XML_WITH_ICU: xmlFeature = 32;
pub const XML_WITH_ZLIB: xmlFeature = 31;
pub const XML_WITH_DEBUG_RUN: xmlFeature = 30;
pub const XML_WITH_DEBUG_MEM: xmlFeature = 29;
pub const XML_WITH_DEBUG: xmlFeature = 28;
pub const XML_WITH_MODULES: xmlFeature = 27;
pub const XML_WITH_SCHEMATRON: xmlFeature = 26;
pub const XML_WITH_SCHEMAS: xmlFeature = 25;
pub const XML_WITH_EXPR: xmlFeature = 24;
pub const XML_WITH_AUTOMATA: xmlFeature = 23;
pub const XML_WITH_REGEXP: xmlFeature = 22;
pub const XML_WITH_UNICODE: xmlFeature = 21;
pub const XML_WITH_ISO8859X: xmlFeature = 20;
pub const XML_WITH_ICONV: xmlFeature = 19;
pub const XML_WITH_XINCLUDE: xmlFeature = 18;
pub const XML_WITH_XPTR: xmlFeature = 17;
pub const XML_WITH_XPATH: xmlFeature = 16;
pub const XML_WITH_CATALOG: xmlFeature = 15;
pub const XML_WITH_C14N: xmlFeature = 14;
pub const XML_WITH_LEGACY: xmlFeature = 13;
pub const XML_WITH_HTML: xmlFeature = 12;
pub const XML_WITH_VALID: xmlFeature = 11;
pub const XML_WITH_HTTP: xmlFeature = 10;
pub const XML_WITH_FTP: xmlFeature = 9;
pub const XML_WITH_SAX1: xmlFeature = 8;
pub const XML_WITH_WRITER: xmlFeature = 7;
pub const XML_WITH_PATTERN: xmlFeature = 6;
pub const XML_WITH_READER: xmlFeature = 5;
pub const XML_WITH_PUSH: xmlFeature = 4;
pub const XML_WITH_OUTPUT: xmlFeature = 3;
pub const XML_WITH_TREE: xmlFeature = 2;
pub const XML_WITH_THREAD: xmlFeature = 1;
pub type C2RustUnnamed_4 = u32;
pub const HTML_PARSE_IGNORE_ENC: C2RustUnnamed_4 = 2097152;
pub const HTML_PARSE_COMPACT: C2RustUnnamed_4 = 65536;
pub const HTML_PARSE_NONET: C2RustUnnamed_4 = 2048;
pub const HTML_PARSE_NOBLANKS: C2RustUnnamed_4 = 256;
pub const HTML_PARSE_PEDANTIC: C2RustUnnamed_4 = 128;
pub const HTML_PARSE_NOWARNING: C2RustUnnamed_4 = 64;
pub const HTML_PARSE_NOERROR: C2RustUnnamed_4 = 32;
pub const HTML_PARSE_NODEFDTD: C2RustUnnamed_4 = 4;
pub const HTML_PARSE_RECOVER: C2RustUnnamed_4 = 1;
unsafe extern "C" fn xmlParserEntityCheck(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut size: u64,
    mut ent: * mut crate::src::HTMLparser::_xmlEntity,
    mut replacement: u64,
) -> i32 {
    let mut consumed: u64 = 0 as i32 as size_t;
    let mut i: i32 = 0;
    if ctxt.is_null() || (*ctxt).options & XML_PARSE_HUGE as i32 != 0 {
        return 0 as i32;
    }
    if (*ctxt).lastError.code == XML_ERR_ENTITY_LOOP as i32 {
        return 1 as i32;
    }
    if !ent.is_null()
        && (*ent).etype as u32
            != XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
        && !((*ent).content).is_null() && (*ent).checked == 0 as i32
        && (*ctxt).errNo != XML_ERR_ENTITY_LOOP as i32
    {
        let mut oldnbent: u64 = (*ctxt).nbentities;
        let mut diff: u64 = 0;
        let mut rep: * mut u8 = 0 as *mut xmlChar;
        (*ent).checked = 1 as i32;
        let fresh0 = &mut ((*ctxt).depth);
        *fresh0 += 1;
        rep = xmlStringDecodeEntities(
            ctxt,
            (*ent).content,
            1 as i32,
            0 as i32 as xmlChar,
            0 as i32 as xmlChar,
            0 as i32 as xmlChar,
        );
        let fresh1 = &mut ((*ctxt).depth);
        *fresh1 -= 1;
        if rep.is_null() || (*ctxt).errNo == XML_ERR_ENTITY_LOOP as i32 {
            *((*ent).content)
                .offset(0 as i32 as isize) = 0 as i32 as xmlChar;
        }
        diff = ((*ctxt).nbentities)
            .wrapping_sub(oldnbent)
            .wrapping_add(1 as i32 as u64);
        if diff > (2147483647 as i32 / 2 as i32) as u64 {
            diff = (2147483647 as i32 / 2 as i32) as u64;
        }
        (*ent)
            .checked = diff.wrapping_mul(2 as i32 as u64)
            as i32;
        if !rep.is_null() {
            if !(xmlStrchr(rep, '<' as i32 as xmlChar)).is_null() {
                (*ent).checked |= 1 as i32;
            }
            xmlFree.expect("non-null function pointer")(rep as *mut libc::c_void);
            rep = 0 as *mut xmlChar;
        }
    }
    if (*ctxt).instate as i32 == XML_PARSER_DTD as i32
        && (*ctxt).nbentities > 10000 as i32 as u64
        && ((*ctxt).nbentities).wrapping_rem(1024 as i32 as u64)
            == 0 as i32 as u64
    {
        i = 0 as i32;
        while i < (*ctxt).inputNr {
            consumed = (consumed as u64)
                .wrapping_add(
                    ((**((*ctxt).inputTab).offset(i as isize)).consumed)
                        .wrapping_add(
                            ((**((*ctxt).inputTab).offset(i as isize)).cur)
                                .offset_from((**((*ctxt).inputTab).offset(i as isize)).base)
                                as i64 as u64,
                        ),
                ) as size_t as size_t;
            i += 1;
        }
        if (*ctxt).nbentities > consumed.wrapping_mul(10 as i32 as u64)
        {
            xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const i8);
            (*ctxt).instate = XML_PARSER_EOF;
            return 1 as i32;
        }
        consumed = 0 as i32 as size_t;
    }
    if replacement != 0 as i32 as u64 {
        if replacement < 10000000 as i32 as u64 {
            return 0 as i32;
        }
        if !((*ctxt).input).is_null() {
            consumed = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as i64 as u64,
                );
        }
        consumed = (consumed as u64).wrapping_add((*ctxt).sizeentities)
            as size_t as size_t;
        if replacement < (10 as i32 as u64).wrapping_mul(consumed) {
            return 0 as i32;
        }
    } else if size != 0 as i32 as u64 {
        if size < 1000 as i32 as u64 {
            return 0 as i32;
        }
        if !((*ctxt).input).is_null() {
            consumed = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as i64 as u64,
                );
        }
        consumed = (consumed as u64).wrapping_add((*ctxt).sizeentities)
            as size_t as size_t;
        if size < (10 as i32 as u64).wrapping_mul(consumed)
            && ((*ctxt).nbentities).wrapping_mul(3 as i32 as u64)
                < (10 as i32 as u64).wrapping_mul(consumed)
        {
            return 0 as i32;
        }
    } else if !ent.is_null() {
        size = ((*ent).checked / 2 as i32) as size_t;
        if !((*ctxt).input).is_null() {
            consumed = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as i64 as u64,
                );
        }
        consumed = (consumed as u64).wrapping_add((*ctxt).sizeentities)
            as size_t as size_t;
        if size.wrapping_mul(3 as i32 as u64)
            < consumed.wrapping_mul(10 as i32 as u64)
        {
            return 0 as i32;
        }
    } else if (*ctxt).lastError.code != XML_ERR_UNDECLARED_ENTITY as i32
            && (*ctxt).lastError.code != XML_WAR_UNDECLARED_ENTITY as i32
            || (*ctxt).nbentities <= 10000 as i32 as u64
        {
        return 0 as i32
    }
    xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const i8);
    return 1 as i32;
}
#[no_mangle]
pub static mut xmlParserMaxDepth: u32 = 256 as i32 as u32;
static mut xmlW3CPIs: [* const i8; 3] = [
    b"xml-stylesheet\0" as *const u8 as *const i8,
    b"xml-model\0" as *const u8 as *const i8,
    0 as *const i8,
];
unsafe extern "C" fn xmlErrAttributeDup(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut prefix: * const u8,
    mut localname: * const u8,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = XML_ERR_ATTRIBUTE_REDEFINED as i32;
    }
    if prefix.is_null() {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as i32,
            XML_ERR_ATTRIBUTE_REDEFINED as i32,
            XML_ERR_FATAL,
            0 as *const i8,
            0 as i32,
            localname as *const i8,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"Attribute %s redefined\n\0" as *const u8 as *const i8,
            localname,
        );
    } else {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as i32,
            XML_ERR_ATTRIBUTE_REDEFINED as i32,
            XML_ERR_FATAL,
            0 as *const i8,
            0 as i32,
            prefix as *const i8,
            localname as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"Attribute %s:%s redefined\n\0" as *const u8 as *const i8,
            prefix,
            localname,
        );
    }
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as i32;
        if (*ctxt).recovery == 0 as i32 {
            (*ctxt).disableSAX = 1 as i32;
        }
    }
}
unsafe extern "C" fn xmlFatalErr(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut error: u32,
    mut info: * const i8,
) {
    let mut errmsg: * const i8 = 0 as *const i8;
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    match error as u32 {
        6 => {
            errmsg = b"CharRef: invalid hexadecimal value\0" as *const u8
                as *const i8;
        }
        7 => {
            errmsg = b"CharRef: invalid decimal value\0" as *const u8
                as *const i8;
        }
        8 => {
            errmsg = b"CharRef: invalid value\0" as *const u8 as *const i8;
        }
        1 => {
            errmsg = b"internal error\0" as *const u8 as *const i8;
        }
        18 => {
            errmsg = b"PEReference at end of document\0" as *const u8
                as *const i8;
        }
        19 => {
            errmsg = b"PEReference in prolog\0" as *const u8 as *const i8;
        }
        20 => {
            errmsg = b"PEReference in epilog\0" as *const u8 as *const i8;
        }
        24 => {
            errmsg = b"PEReference: no name\0" as *const u8 as *const i8;
        }
        25 => {
            errmsg = b"PEReference: expecting ';'\0" as *const u8 as *const i8;
        }
        89 => {
            errmsg = b"Detected an entity reference loop\0" as *const u8
                as *const i8;
        }
        36 => {
            errmsg = b"EntityValue: \" or ' expected\0" as *const u8
                as *const i8;
        }
        88 => {
            errmsg = b"PEReferences forbidden in internal subset\0" as *const u8
                as *const i8;
        }
        37 => {
            errmsg = b"EntityValue: \" or ' expected\0" as *const u8
                as *const i8;
        }
        39 => {
            errmsg = b"AttValue: \" or ' expected\0" as *const u8 as *const i8;
        }
        38 => {
            errmsg = b"Unescaped '<' not allowed in attributes values\0" as *const u8
                as *const i8;
        }
        43 => {
            errmsg = b"SystemLiteral \" or ' expected\0" as *const u8
                as *const i8;
        }
        44 => {
            errmsg = b"Unfinished System or Public ID \" or ' expected\0" as *const u8
                as *const i8;
        }
        62 => {
            errmsg = b"Sequence ']]>' not allowed in content\0" as *const u8
                as *const i8;
        }
        70 => {
            errmsg = b"SYSTEM or PUBLIC, the URI is missing\0" as *const u8
                as *const i8;
        }
        71 => {
            errmsg = b"PUBLIC, the Public Identifier is missing\0" as *const u8
                as *const i8;
        }
        80 => {
            errmsg = b"Comment must not contain '--' (double-hyphen)\0" as *const u8
                as *const i8;
        }
        46 => {
            errmsg = b"xmlParsePI : no target name\0" as *const u8
                as *const i8;
        }
        64 => {
            errmsg = b"Invalid PI name\0" as *const u8 as *const i8;
        }
        48 => {
            errmsg = b"NOTATION: Name expected here\0" as *const u8
                as *const i8;
        }
        49 => {
            errmsg = b"'>' required to close NOTATION declaration\0" as *const u8
                as *const i8;
        }
        84 => {
            errmsg = b"Entity value required\0" as *const u8 as *const i8;
        }
        92 => {
            errmsg = b"Fragment not allowed\0" as *const u8 as *const i8;
        }
        50 => {
            errmsg = b"'(' required to start ATTLIST enumeration\0" as *const u8
                as *const i8;
        }
        67 => {
            errmsg = b"NmToken expected in ATTLIST enumeration\0" as *const u8
                as *const i8;
        }
        51 => {
            errmsg = b"')' required to finish ATTLIST enumeration\0" as *const u8
                as *const i8;
        }
        52 => {
            errmsg = b"MixedContentDecl : '|' or ')*' expected\0" as *const u8
                as *const i8;
        }
        69 => {
            errmsg = b"MixedContentDecl : '#PCDATA' expected\0" as *const u8
                as *const i8;
        }
        54 => {
            errmsg = b"ContentDecl : Name or '(' expected\0" as *const u8
                as *const i8;
        }
        55 => {
            errmsg = b"ContentDecl : ',' '|' or ')' expected\0" as *const u8
                as *const i8;
        }
        21 => {
            errmsg = b"PEReference: forbidden within markup decl in internal subset\0"
                as *const u8 as *const i8;
        }
        73 => {
            errmsg = b"expected '>'\0" as *const u8 as *const i8;
        }
        83 => {
            errmsg = b"XML conditional section '[' expected\0" as *const u8
                as *const i8;
        }
        60 => {
            errmsg = b"Content error in the external subset\0" as *const u8
                as *const i8;
        }
        95 => {
            errmsg = b"conditional section INCLUDE or IGNORE keyword expected\0"
                as *const u8 as *const i8;
        }
        59 => {
            errmsg = b"XML conditional section not closed\0" as *const u8
                as *const i8;
        }
        56 => {
            errmsg = b"Text declaration '<?xml' required\0" as *const u8
                as *const i8;
        }
        57 => {
            errmsg = b"parsing XML declaration: '?>' expected\0" as *const u8
                as *const i8;
        }
        82 => {
            errmsg = b"external parsed entities cannot be standalone\0" as *const u8
                as *const i8;
        }
        23 => {
            errmsg = b"EntityRef: expecting ';'\0" as *const u8 as *const i8;
        }
        61 => {
            errmsg = b"DOCTYPE improperly terminated\0" as *const u8
                as *const i8;
        }
        74 => {
            errmsg = b"EndTag: '</' not found\0" as *const u8 as *const i8;
        }
        75 => {
            errmsg = b"expected '='\0" as *const u8 as *const i8;
        }
        34 => {
            errmsg = b"String not closed expecting \" or '\0" as *const u8
                as *const i8;
        }
        33 => {
            errmsg = b"String not started expecting ' or \"\0" as *const u8
                as *const i8;
        }
        79 => {
            errmsg = b"Invalid XML encoding name\0" as *const u8 as *const i8;
        }
        78 => {
            errmsg = b"standalone accepts only 'yes' or 'no'\0" as *const u8
                as *const i8;
        }
        4 => {
            errmsg = b"Document is empty\0" as *const u8 as *const i8;
        }
        5 => {
            errmsg = b"Extra content at the end of the document\0" as *const u8
                as *const i8;
        }
        85 => {
            errmsg = b"chunk is not well balanced\0" as *const u8 as *const i8;
        }
        86 => {
            errmsg = b"extra content at the end of well balanced chunk\0" as *const u8
                as *const i8;
        }
        96 => {
            errmsg = b"Malformed declaration expecting version\0" as *const u8
                as *const i8;
        }
        110 => {
            errmsg = b"Name too long use XML_PARSE_HUGE option\0" as *const u8
                as *const i8;
        }
        _ => {
            errmsg = b"Unregistered error message\0" as *const u8 as *const i8;
        }
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as i32;
    }
    if info.is_null() {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as i32,
            error as i32,
            XML_ERR_FATAL,
            0 as *const i8,
            0 as i32,
            info,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"%s\n\0" as *const u8 as *const i8,
            errmsg,
        );
    } else {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as i32,
            error as i32,
            XML_ERR_FATAL,
            0 as *const i8,
            0 as i32,
            info,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"%s: %s\n\0" as *const u8 as *const i8,
            errmsg,
            info,
        );
    }
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as i32;
        if (*ctxt).recovery == 0 as i32 {
            (*ctxt).disableSAX = 1 as i32;
        }
    }
}
unsafe extern "C" fn xmlFatalErrMsg(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut error: u32,
    mut msg: * const i8,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as i32;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_PARSER as i32,
        error as i32,
        XML_ERR_FATAL,
        0 as *const i8,
        0 as i32,
        0 as *const i8,
        0 as *const i8,
        0 as *const i8,
        0 as i32,
        0 as i32,
        b"%s\0" as *const u8 as *const i8,
        msg,
    );
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as i32;
        if (*ctxt).recovery == 0 as i32 {
            (*ctxt).disableSAX = 1 as i32;
        }
    }
}
unsafe extern "C" fn xmlWarningMsg(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut error: u32,
    mut msg: * const i8,
    mut str1: * const u8,
    mut str2: * const u8,
) {
    let mut schannel: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut crate::src::HTMLparser::_xmlError,) -> ()> = None;
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() && !((*ctxt).sax).is_null()
        && (*(*ctxt).sax).initialized == 0xdeedbeaf as u32
    {
        schannel = (*(*ctxt).sax).serror;
    }
    if !ctxt.is_null() {
        __xmlRaiseError(
            schannel,
            if !((*ctxt).sax).is_null() { (*(*ctxt).sax).warning } else { None },
            (*ctxt).userData,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as i32,
            error as i32,
            XML_ERR_WARNING,
            0 as *const i8,
            0 as i32,
            str1 as *const i8,
            str2 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            msg,
            str1 as *const i8,
            str2 as *const i8,
        );
    } else {
        __xmlRaiseError(
            schannel,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as i32,
            error as i32,
            XML_ERR_WARNING,
            0 as *const i8,
            0 as i32,
            str1 as *const i8,
            str2 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            msg,
            str1 as *const i8,
            str2 as *const i8,
        );
    };
}
unsafe extern "C" fn xmlValidityError(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut error: u32,
    mut msg: * const i8,
    mut str1: * const u8,
    mut str2: * const u8,
) {
    let mut schannel: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut crate::src::HTMLparser::_xmlError,) -> ()> = None;
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as i32;
        if !((*ctxt).sax).is_null()
            && (*(*ctxt).sax).initialized == 0xdeedbeaf as u32
        {
            schannel = (*(*ctxt).sax).serror;
        }
    }
    if !ctxt.is_null() {
        __xmlRaiseError(
            schannel,
            (*ctxt).vctxt.error,
            (*ctxt).vctxt.userData,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_DTD as i32,
            error as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            str1 as *const i8,
            str2 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            msg,
            str1 as *const i8,
            str2 as *const i8,
        );
        (*ctxt).valid = 0 as i32;
    } else {
        __xmlRaiseError(
            schannel,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_DTD as i32,
            error as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            str1 as *const i8,
            str2 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            msg,
            str1 as *const i8,
            str2 as *const i8,
        );
    };
}
unsafe extern "C" fn xmlFatalErrMsgInt(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut error: u32,
    mut msg: * const i8,
    mut val: i32,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as i32;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_PARSER as i32,
        error as i32,
        XML_ERR_FATAL,
        0 as *const i8,
        0 as i32,
        0 as *const i8,
        0 as *const i8,
        0 as *const i8,
        val,
        0 as i32,
        msg,
        val,
    );
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as i32;
        if (*ctxt).recovery == 0 as i32 {
            (*ctxt).disableSAX = 1 as i32;
        }
    }
}
unsafe extern "C" fn xmlFatalErrMsgStrIntStr(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut error: u32,
    mut msg: * const i8,
    mut str1: * const u8,
    mut val: i32,
    mut str2: * const u8,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as i32;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_PARSER as i32,
        error as i32,
        XML_ERR_FATAL,
        0 as *const i8,
        0 as i32,
        str1 as *const i8,
        str2 as *const i8,
        0 as *const i8,
        val,
        0 as i32,
        msg,
        str1,
        val,
        str2,
    );
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as i32;
        if (*ctxt).recovery == 0 as i32 {
            (*ctxt).disableSAX = 1 as i32;
        }
    }
}
unsafe extern "C" fn xmlFatalErrMsgStr(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut error: u32,
    mut msg: * const i8,
    mut val: * const u8,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as i32;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_PARSER as i32,
        error as i32,
        XML_ERR_FATAL,
        0 as *const i8,
        0 as i32,
        val as *const i8,
        0 as *const i8,
        0 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        val,
    );
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as i32;
        if (*ctxt).recovery == 0 as i32 {
            (*ctxt).disableSAX = 1 as i32;
        }
    }
}
unsafe extern "C" fn xmlErrMsgStr(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut error: u32,
    mut msg: * const i8,
    mut val: * const u8,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as i32;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_PARSER as i32,
        error as i32,
        XML_ERR_ERROR,
        0 as *const i8,
        0 as i32,
        val as *const i8,
        0 as *const i8,
        0 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        val,
    );
}
unsafe extern "C" fn xmlNsErr(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut error: u32,
    mut msg: * const i8,
    mut info1: * const u8,
    mut info2: * const u8,
    mut info3: * const u8,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as i32;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_NAMESPACE as i32,
        error as i32,
        XML_ERR_ERROR,
        0 as *const i8,
        0 as i32,
        info1 as *const i8,
        info2 as *const i8,
        info3 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        info1,
        info2,
        info3,
    );
    if !ctxt.is_null() {
        (*ctxt).nsWellFormed = 0 as i32;
    }
}
unsafe extern "C" fn xmlNsWarn(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut error: u32,
    mut msg: * const i8,
    mut info1: * const u8,
    mut info2: * const u8,
    mut info3: * const u8,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_NAMESPACE as i32,
        error as i32,
        XML_ERR_WARNING,
        0 as *const i8,
        0 as i32,
        info1 as *const i8,
        info2 as *const i8,
        info3 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        info1,
        info2,
        info3,
    );
}
#[no_mangle]
pub extern "C" fn xmlHasFeature(mut feature: u32) -> i32 {
    match feature as u32 {
        1 => return 1 as i32,
        2 => return 1 as i32,
        3 => return 1 as i32,
        4 => return 1 as i32,
        5 => return 1 as i32,
        6 => return 1 as i32,
        7 => return 1 as i32,
        8 => return 1 as i32,
        9 => return 1 as i32,
        10 => return 1 as i32,
        11 => return 1 as i32,
        12 => return 1 as i32,
        13 => return 1 as i32,
        14 => return 1 as i32,
        15 => return 1 as i32,
        16 => return 1 as i32,
        17 => return 1 as i32,
        18 => return 1 as i32,
        19 => return 1 as i32,
        20 => return 1 as i32,
        21 => return 1 as i32,
        22 => return 1 as i32,
        23 => return 1 as i32,
        24 => return 0 as i32,
        25 => return 1 as i32,
        26 => return 1 as i32,
        27 => return 1 as i32,
        28 => return 1 as i32,
        29 => return 0 as i32,
        30 => return 0 as i32,
        31 => return 1 as i32,
        33 => return 0 as i32,
        32 => return 0 as i32,
        _ => {}
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlDetectSAX2(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler = 0 as *mut xmlSAXHandler;
    if ctxt.is_null() {
        return;
    }
    sax = (*ctxt).sax;
    if !sax.is_null() && (*sax).initialized == 0xdeedbeaf as u32
        && (((*sax).startElementNs).is_some() || ((*sax).endElementNs).is_some()
            || ((*sax).startElement).is_none() && ((*sax).endElement).is_none())
    {
        (*ctxt).sax2 = 1 as i32;
    }
    let fresh2 = &mut ((*ctxt).str_xml);
    *fresh2 = xmlDictLookup(
        (*ctxt).dict,
        b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
        3 as i32,
    );
    let fresh3 = &mut ((*ctxt).str_xmlns);
    *fresh3 = xmlDictLookup(
        (*ctxt).dict,
        b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
        5 as i32,
    );
    let fresh4 = &mut ((*ctxt).str_xml_ns);
    *fresh4 = xmlDictLookup(
        (*ctxt).dict,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
            as *const xmlChar,
        36 as i32,
    );
    if ((*ctxt).str_xml).is_null() || ((*ctxt).str_xmlns).is_null()
        || ((*ctxt).str_xml_ns).is_null()
    {
        xmlErrMemory(ctxt, 0 as *const i8);
    }
}
unsafe extern "C" fn xmlAttrNormalizeSpace(
    mut src: * const u8,
    mut dst: * mut u8,
) -> * mut u8 {
    if src.is_null() || dst.is_null() {
        return 0 as *mut xmlChar;
    }
    while *src as i32 == 0x20 as i32 {
        src = src.offset(1);
    }
    while *src as i32 != 0 as i32 {
        if *src as i32 == 0x20 as i32 {
            while *src as i32 == 0x20 as i32 {
                src = src.offset(1);
            }
            if *src as i32 != 0 as i32 {
                let mut fresh5 = dst;
                dst = dst.offset(1);
                *fresh5 = 0x20 as i32 as xmlChar;
            }
        } else {
            let mut fresh6 = src;
            src = src.offset(1);
            let mut fresh7 = dst;
            dst = dst.offset(1);
            *fresh7 = *fresh6;
        }
    }
    *dst = 0 as i32 as xmlChar;
    if dst == src as *mut xmlChar {
        return 0 as *mut xmlChar;
    }
    return dst;
}
unsafe extern "C" fn xmlAttrNormalizeSpace2<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut src: * mut u8,
    mut len: Option<&'a1 mut i32>,
) -> * const u8 {
    let mut i: i32 = 0;
    let mut remove_head: i32 = 0 as i32;
    let mut need_realloc: i32 = 0 as i32;
    let mut cur: * const u8 = 0 as *const xmlChar;
    if ctxt.is_null() || src.is_null() || borrow(& len).is_none() {
        return 0 as *const xmlChar;
    }
    i = *(borrow_mut(&mut len)).unwrap();
    if i <= 0 as i32 {
        return 0 as *const xmlChar;
    }
    cur = src;
    while *cur as i32 == 0x20 as i32 {
        cur = cur.offset(1);
        remove_head += 1;
    }
    while *cur as i32 != 0 as i32 {
        if *cur as i32 == 0x20 as i32 {
            cur = cur.offset(1);
            if !(*cur as i32 == 0x20 as i32
                || *cur as i32 == 0 as i32)
            {
                continue;
            }
            need_realloc = 1 as i32;
            break;
        } else {
            cur = cur.offset(1);
        }
    }
    if need_realloc != 0 {
        let mut ret: * mut u8 = 0 as *mut xmlChar;
        ret = xmlStrndup(
            src.offset(remove_head as isize),
            i - remove_head + 1 as i32,
        );
        if ret.is_null() {
            xmlErrMemory(ctxt, 0 as *const i8);
            return 0 as *const xmlChar;
        }
        xmlAttrNormalizeSpace(ret, ret);
        *(borrow_mut(&mut len)).unwrap() = strlen(ret as *const i8) as i32;
        return ret;
    } else {
        if remove_head != 0 {
            *(borrow_mut(&mut len)).unwrap() -= remove_head;
            memmove(
                src as *mut libc::c_void,
                src.offset(remove_head as isize) as *const libc::c_void,
                (1 as i32 + *(borrow(& len)).unwrap()) as u64,
            );
            return src;
        }
    }
    return 0 as *const xmlChar;
}
unsafe extern "C" fn xmlAddDefAttrs(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut fullname: * const u8,
    mut fullattr: * const u8,
    mut value: * const u8,
) {
    let mut current_block: u64;
    let mut defaults: * mut crate::src::parser::_xmlDefAttrs = 0 as *mut xmlDefAttrs;
    let mut len: i32 = 0;
    let mut name: * const u8 = 0 as *const xmlChar;
    let mut prefix: * const u8 = 0 as *const xmlChar;
    if !((*ctxt).attsSpecial).is_null() {
        if !(xmlHashLookup2((*ctxt).attsSpecial, fullname, fullattr)).is_null() {
            return;
        }
    }
    if ((*ctxt).attsDefault).is_null() {
        let fresh8 = &mut ((*ctxt).attsDefault);
        *fresh8 = xmlHashCreateDict(10 as i32, (*ctxt).dict);
        if ((*ctxt).attsDefault).is_null() {
            current_block = 15121983726504061653;
        } else {
            current_block = 13183875560443969876;
        }
    } else {
        current_block = 13183875560443969876;
    }
    match current_block {
        13183875560443969876 => {
            name = xmlSplitQName3(fullname, &mut len);
            if name.is_null() {
                name = xmlDictLookup((*ctxt).dict, fullname, -(1 as i32));
                prefix = 0 as *const xmlChar;
            } else {
                name = xmlDictLookup((*ctxt).dict, name, -(1 as i32));
                prefix = xmlDictLookup((*ctxt).dict, fullname, len);
            }
            defaults = xmlHashLookup2((*ctxt).attsDefault, name, prefix)
                as xmlDefAttrsPtr;
            if defaults.is_null() {
                defaults = xmlMalloc
                    .expect(
                        "non-null function pointer",
                    )(
                    (::std::mem::size_of::<xmlDefAttrs>() as u64)
                        .wrapping_add(
                            ((4 as i32 * 5 as i32) as u64)
                                .wrapping_mul(
                                    ::std::mem::size_of::<*const xmlChar>() as u64,
                                ),
                        ),
                ) as xmlDefAttrsPtr;
                if defaults.is_null() {
                    current_block = 15121983726504061653;
                } else {
                    (*defaults).nbAttrs = 0 as i32;
                    (*defaults).maxAttrs = 4 as i32;
                    if xmlHashUpdateEntry2(
                        (*ctxt).attsDefault,
                        name,
                        prefix,
                        defaults as *mut libc::c_void,
                        None,
                    ) < 0 as i32
                    {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(defaults as *mut libc::c_void);
                        current_block = 15121983726504061653;
                    } else {
                        current_block = 8704759739624374314;
                    }
                }
            } else if (*defaults).nbAttrs >= (*defaults).maxAttrs {
                let mut temp: * mut crate::src::parser::_xmlDefAttrs = 0 as *mut xmlDefAttrs;
                temp = xmlRealloc
                    .expect(
                        "non-null function pointer",
                    )(
                    defaults as *mut libc::c_void,
                    (::std::mem::size_of::<xmlDefAttrs>() as u64)
                        .wrapping_add(
                            ((2 as i32 * (*defaults).maxAttrs * 5 as i32)
                                as u64)
                                .wrapping_mul(
                                    ::std::mem::size_of::<*const xmlChar>() as u64,
                                ),
                        ),
                ) as xmlDefAttrsPtr;
                if temp.is_null() {
                    current_block = 15121983726504061653;
                } else {
                    defaults = temp;
                    (*defaults).maxAttrs *= 2 as i32;
                    if xmlHashUpdateEntry2(
                        (*ctxt).attsDefault,
                        name,
                        prefix,
                        defaults as *mut libc::c_void,
                        None,
                    ) < 0 as i32
                    {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(defaults as *mut libc::c_void);
                        current_block = 15121983726504061653;
                    } else {
                        current_block = 8704759739624374314;
                    }
                }
            } else {
                current_block = 8704759739624374314;
            }
            match current_block {
                15121983726504061653 => {}
                _ => {
                    name = xmlSplitQName3(fullattr, &mut len);
                    if name.is_null() {
                        name = xmlDictLookup(
                            (*ctxt).dict,
                            fullattr,
                            -(1 as i32),
                        );
                        prefix = 0 as *const xmlChar;
                    } else {
                        name = xmlDictLookup((*ctxt).dict, name, -(1 as i32));
                        prefix = xmlDictLookup((*ctxt).dict, fullattr, len);
                    }
                    let fresh9 = &mut ((*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(((*defaults).values).as_mut().unwrap(), ((5 as i32 * (*defaults).nbAttrs) as isize))));
                    *fresh9 = name;
                    let fresh10 = &mut ((*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(((*defaults).values).as_mut().unwrap(), ((5 as i32 * (*defaults).nbAttrs + 1 as i32)
                                as isize))));
                    *fresh10 = prefix;
                    len = xmlStrlen(value);
                    value = xmlDictLookup((*ctxt).dict, value, len);
                    let fresh11 = &mut ((*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(((*defaults).values).as_mut().unwrap(), ((5 as i32 * (*defaults).nbAttrs + 2 as i32)
                                as isize))));
                    *fresh11 = value;
                    let fresh12 = &mut ((*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(((*defaults).values).as_mut().unwrap(), ((5 as i32 * (*defaults).nbAttrs + 3 as i32)
                                as isize))));
                    *fresh12 = value.offset(len as isize);
                    if (*ctxt).external != 0 {
                        let fresh13 = &mut ((*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(((*defaults).values).as_mut().unwrap(), ((5 as i32 * (*defaults).nbAttrs + 4 as i32)
                                    as isize))));
                        *fresh13 = b"external\0" as *const u8 as *const i8
                            as *mut xmlChar;
                    } else {
                        let fresh14 = &mut ((*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(((*defaults).values).as_mut().unwrap(), ((5 as i32 * (*defaults).nbAttrs + 4 as i32)
                                    as isize))));
                        *fresh14 = 0 as *const xmlChar;
                    }
                    let fresh15 = &mut ((*defaults).nbAttrs);
                    *fresh15 += 1;
                    return;
                }
            }
        }
        _ => {}
    }
    xmlErrMemory(ctxt, 0 as *const i8);
}
unsafe extern "C" fn xmlAddSpecialAttr(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut fullname: * const u8,
    mut fullattr: * const u8,
    mut type_0: i32,
) {
    if ((*ctxt).attsSpecial).is_null() {
        let fresh16 = &mut ((*ctxt).attsSpecial);
        *fresh16 = xmlHashCreateDict(10 as i32, (*ctxt).dict);
        if ((*ctxt).attsSpecial).is_null() {
            xmlErrMemory(ctxt, 0 as *const i8);
            return;
        }
    }
    if !(xmlHashLookup2((*ctxt).attsSpecial, fullname, fullattr)).is_null() {
        return;
    }
    xmlHashAddEntry2(
        (*ctxt).attsSpecial,
        fullname,
        fullattr,
        type_0 as ptrdiff_t as *mut libc::c_void,
    );
}
unsafe extern "C" fn xmlCleanSpecialAttrCallback(
    mut payload: * mut core::ffi::c_void,
    mut data: * mut core::ffi::c_void,
    mut fullname: * const u8,
    mut fullattr: * const u8,
    mut unused: * const u8,
) {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = data as xmlParserCtxtPtr;
    if payload as ptrdiff_t == XML_ATTRIBUTE_CDATA as i32 as i64 {
        xmlHashRemoveEntry2((*ctxt).attsSpecial, fullname, fullattr, None);
    }
}
unsafe extern "C" fn xmlCleanSpecialAttr(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    if ((*ctxt).attsSpecial).is_null() {
        return;
    }
    xmlHashScanFull(
        (*ctxt).attsSpecial,
        Some(
            xmlCleanSpecialAttrCallback,
        ),
        ctxt as *mut libc::c_void,
    );
    if xmlHashSize((*ctxt).attsSpecial) == 0 as i32 {
        xmlHashFree((*ctxt).attsSpecial, None);
        let fresh17 = &mut ((*ctxt).attsSpecial);
        *fresh17 = 0 as xmlHashTablePtr;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlCheckLanguageID(mut lang: * const u8) -> i32 {
    let mut current_block: u64;
    let mut cur: * const u8 = lang;
    let mut nxt: * const u8 = 0 as *const xmlChar;
    if cur.is_null() {
        return 0 as i32;
    }
    if *cur.offset(0 as i32 as isize) as i32 == 'i' as i32
        && *cur.offset(1 as i32 as isize) as i32 == '-' as i32
        || *cur.offset(0 as i32 as isize) as i32 == 'I' as i32
            && *cur.offset(1 as i32 as isize) as i32 == '-' as i32
        || *cur.offset(0 as i32 as isize) as i32 == 'x' as i32
            && *cur.offset(1 as i32 as isize) as i32 == '-' as i32
        || *cur.offset(0 as i32 as isize) as i32 == 'X' as i32
            && *cur.offset(1 as i32 as isize) as i32 == '-' as i32
    {
        cur = cur.offset(2 as i32 as isize);
        while *cur.offset(0 as i32 as isize) as i32 >= 'A' as i32
            && *cur.offset(0 as i32 as isize) as i32 <= 'Z' as i32
            || *cur.offset(0 as i32 as isize) as i32 >= 'a' as i32
                && *cur.offset(0 as i32 as isize) as i32 <= 'z' as i32
        {
            cur = cur.offset(1);
        }
        return (*cur.offset(0 as i32 as isize) as i32
            == 0 as i32) as i32;
    }
    nxt = cur;
    while *nxt.offset(0 as i32 as isize) as i32 >= 'A' as i32
        && *nxt.offset(0 as i32 as isize) as i32 <= 'Z' as i32
        || *nxt.offset(0 as i32 as isize) as i32 >= 'a' as i32
            && *nxt.offset(0 as i32 as isize) as i32 <= 'z' as i32
    {
        nxt = nxt.offset(1);
    }
    if nxt.offset_from(cur) as i64 >= 4 as i32 as i64 {
        if nxt.offset_from(cur) as i64 > 8 as i32 as i64
            || *nxt.offset(0 as i32 as isize) as i32 != 0 as i32
        {
            return 0 as i32;
        }
        return 1 as i32;
    }
    if (nxt.offset_from(cur) as i64) < 2 as i32 as i64 {
        return 0 as i32;
    }
    if *nxt.offset(0 as i32 as isize) as i32 == 0 as i32 {
        return 1 as i32;
    }
    if *nxt.offset(0 as i32 as isize) as i32 != '-' as i32 {
        return 0 as i32;
    }
    nxt = nxt.offset(1);
    cur = nxt;
    if *nxt.offset(0 as i32 as isize) as i32 >= '0' as i32
        && *nxt.offset(0 as i32 as isize) as i32 <= '9' as i32
    {
        current_block = 16811467638080314455;
    } else {
        while *nxt.offset(0 as i32 as isize) as i32 >= 'A' as i32
            && *nxt.offset(0 as i32 as isize) as i32 <= 'Z' as i32
            || *nxt.offset(0 as i32 as isize) as i32 >= 'a' as i32
                && *nxt.offset(0 as i32 as isize) as i32 <= 'z' as i32
        {
            nxt = nxt.offset(1);
        }
        if nxt.offset_from(cur) as i64 == 4 as i32 as i64 {
            current_block = 9144990194416275176;
        } else if nxt.offset_from(cur) as i64
                == 2 as i32 as i64
            {
            current_block = 8704481894642172821;
        } else if nxt.offset_from(cur) as i64
                >= 5 as i32 as i64
                && nxt.offset_from(cur) as i64
                    <= 8 as i32 as i64
            {
            current_block = 9213009941721548937;
        } else {
            if nxt.offset_from(cur) as i64 != 3 as i32 as i64 {
                return 0 as i32;
            }
            if *nxt.offset(0 as i32 as isize) as i32 == 0 as i32
            {
                return 1 as i32;
            }
            if *nxt.offset(0 as i32 as isize) as i32 != '-' as i32 {
                return 0 as i32;
            }
            nxt = nxt.offset(1);
            cur = nxt;
            if *nxt.offset(0 as i32 as isize) as i32 >= '0' as i32
                && *nxt.offset(0 as i32 as isize) as i32 <= '9' as i32
            {
                current_block = 16811467638080314455;
            } else {
                while *nxt.offset(0 as i32 as isize) as i32 >= 'A' as i32
                    && *nxt.offset(0 as i32 as isize) as i32
                        <= 'Z' as i32
                    || *nxt.offset(0 as i32 as isize) as i32
                        >= 'a' as i32
                        && *nxt.offset(0 as i32 as isize) as i32
                            <= 'z' as i32
                {
                    nxt = nxt.offset(1);
                }
                if nxt.offset_from(cur) as i64
                    == 2 as i32 as i64
                {
                    current_block = 8704481894642172821;
                } else if nxt.offset_from(cur) as i64
                        >= 5 as i32 as i64
                        && nxt.offset_from(cur) as i64
                            <= 8 as i32 as i64
                    {
                    current_block = 9213009941721548937;
                } else {
                    if nxt.offset_from(cur) as i64
                        != 4 as i32 as i64
                    {
                        return 0 as i32;
                    }
                    current_block = 9144990194416275176;
                }
            }
        }
        match current_block {
            8704481894642172821 => {}
            9213009941721548937 => {}
            16811467638080314455 => {}
            _ => {
                if *nxt.offset(0 as i32 as isize) as i32
                    == 0 as i32
                {
                    return 1 as i32;
                }
                if *nxt.offset(0 as i32 as isize) as i32 != '-' as i32 {
                    return 0 as i32;
                }
                nxt = nxt.offset(1);
                cur = nxt;
                if *nxt.offset(0 as i32 as isize) as i32 >= '0' as i32
                    && *nxt.offset(0 as i32 as isize) as i32
                        <= '9' as i32
                {
                    current_block = 16811467638080314455;
                } else {
                    while *nxt.offset(0 as i32 as isize) as i32
                        >= 'A' as i32
                        && *nxt.offset(0 as i32 as isize) as i32
                            <= 'Z' as i32
                        || *nxt.offset(0 as i32 as isize) as i32
                            >= 'a' as i32
                            && *nxt.offset(0 as i32 as isize) as i32
                                <= 'z' as i32
                    {
                        nxt = nxt.offset(1);
                    }
                    if nxt.offset_from(cur) as i64
                        >= 5 as i32 as i64
                        && nxt.offset_from(cur) as i64
                            <= 8 as i32 as i64
                    {
                        current_block = 9213009941721548937;
                    } else {
                        if nxt.offset_from(cur) as i64
                            != 2 as i32 as i64
                        {
                            return 0 as i32;
                        }
                        current_block = 8704481894642172821;
                    }
                }
            }
        }
    }
    match current_block {
        16811467638080314455 => {
            if *nxt.offset(1 as i32 as isize) as i32 >= '0' as i32
                && *nxt.offset(1 as i32 as isize) as i32 <= '9' as i32
                && (*nxt.offset(2 as i32 as isize) as i32 >= '0' as i32
                    && *nxt.offset(2 as i32 as isize) as i32
                        <= '9' as i32)
            {
                nxt = nxt.offset(3 as i32 as isize);
            } else {
                return 0 as i32
            }
            current_block = 8704481894642172821;
        }
        _ => {}
    }
    match current_block {
        8704481894642172821 => {
            if *nxt.offset(0 as i32 as isize) as i32 == 0 as i32
            {
                return 1 as i32;
            }
            if *nxt.offset(0 as i32 as isize) as i32 != '-' as i32 {
                return 0 as i32;
            }
            nxt = nxt.offset(1);
            cur = nxt;
            while *nxt.offset(0 as i32 as isize) as i32 >= 'A' as i32
                && *nxt.offset(0 as i32 as isize) as i32 <= 'Z' as i32
                || *nxt.offset(0 as i32 as isize) as i32 >= 'a' as i32
                    && *nxt.offset(0 as i32 as isize) as i32
                        <= 'z' as i32
            {
                nxt = nxt.offset(1);
            }
            if (nxt.offset_from(cur) as i64) < 5 as i32 as i64
                || nxt.offset_from(cur) as i64
                    > 8 as i32 as i64
            {
                return 0 as i32;
            }
        }
        _ => {}
    }
    if *nxt.offset(0 as i32 as isize) as i32 == 0 as i32 {
        return 1 as i32;
    }
    if *nxt.offset(0 as i32 as isize) as i32 != '-' as i32 {
        return 0 as i32;
    }
    return 1 as i32;
}
unsafe extern "C" fn nsPush(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut prefix: * const u8,
    mut URL: * const u8,
) -> i32 {
    if (*ctxt).options & XML_PARSE_NSCLEAN as i32 != 0 {
        let mut i: i32 = 0;
        i = (*ctxt).nsNr - 2 as i32;
        while i >= 0 as i32 {
            if *((*ctxt).nsTab).offset(i as isize) == prefix {
                if *((*ctxt).nsTab).offset((i + 1 as i32) as isize) == URL {
                    return -(2 as i32);
                }
                break;
            } else {
                i -= 2 as i32;
            }
        }
    }
    if (*ctxt).nsMax == 0 as i32 || ((*ctxt).nsTab).is_null() {
        (*ctxt).nsMax = 10 as i32;
        (*ctxt).nsNr = 0 as i32;
        let fresh18 = &mut ((*ctxt).nsTab);
        *fresh18 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*ctxt).nsMax as u64)
                .wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
        ) as *mut *const xmlChar;
        if ((*ctxt).nsTab).is_null() {
            xmlErrMemory(ctxt, 0 as *const i8);
            (*ctxt).nsMax = 0 as i32;
            return -(1 as i32);
        }
    } else if (*ctxt).nsNr >= (*ctxt).nsMax {
        let mut tmp: * mut * const u8 = 0 as *mut *const xmlChar;
        (*ctxt).nsMax *= 2 as i32;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).nsTab as *mut i8 as *mut libc::c_void,
            ((*ctxt).nsMax as u64)
                .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as u64),
        ) as *mut *const xmlChar;
        if tmp.is_null() {
            xmlErrMemory(ctxt, 0 as *const i8);
            (*ctxt).nsMax /= 2 as i32;
            return -(1 as i32);
        }
        let fresh19 = &mut ((*ctxt).nsTab);
        *fresh19 = tmp;
    }
    let fresh20 = &mut ((*ctxt).nsNr);
    let mut fresh21 = *fresh20;
    *fresh20 = *fresh20 + 1;
    let fresh22 = &mut (*((*ctxt).nsTab).offset(fresh21 as isize));
    *fresh22 = prefix;
    let fresh23 = &mut ((*ctxt).nsNr);
    let mut fresh24 = *fresh23;
    *fresh23 = *fresh23 + 1;
    let fresh25 = &mut (*((*ctxt).nsTab).offset(fresh24 as isize));
    *fresh25 = URL;
    return (*ctxt).nsNr;
}
unsafe extern "C" fn nsPop(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut nr: i32,
) -> i32 {
    let mut i: i32 = 0;
    if ((*ctxt).nsTab).is_null() {
        return 0 as i32;
    }
    if (*ctxt).nsNr < nr {
        (*(borrow(& __xmlGenericError())).unwrap())
            .expect(
                "non-null function pointer",
            )(
            *(__xmlGenericErrorContext()).unwrap(),
            b"Pbm popping %d NS\n\0" as *const u8 as *const i8,
            nr,
        );
        nr = (*ctxt).nsNr;
    }
    if (*ctxt).nsNr <= 0 as i32 {
        return 0 as i32;
    }
    i = 0 as i32;
    while i < nr {
        let fresh26 = &mut ((*ctxt).nsNr);
        *fresh26 -= 1;
        let fresh27 = &mut (*((*ctxt).nsTab).offset((*ctxt).nsNr as isize));
        *fresh27 = 0 as *const xmlChar;
        i += 1;
    }
    return nr;
}
unsafe extern "C" fn xmlCtxtGrowAttrs(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut nr: i32,
) -> i32 {
    let mut current_block: u64;
    let mut atts: * mut * const u8 = 0 as *mut *const xmlChar;
    let mut attallocs: * mut i32 = 0 as *mut i32;
    let mut maxatts: i32 = 0;
    if ((*ctxt).atts).is_null() {
        maxatts = 55 as i32;
        atts = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            (maxatts as u64)
                .wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
        ) as *mut *const xmlChar;
        if atts.is_null() {
            current_block = 15593660875440590097;
        } else {
            let fresh28 = &mut ((*ctxt).atts);
            *fresh28 = atts;
            attallocs = xmlMalloc
                .expect(
                    "non-null function pointer",
                )(
                ((maxatts / 5 as i32) as u64)
                    .wrapping_mul(::std::mem::size_of::<i32>() as u64),
            ) as *mut i32;
            if attallocs.is_null() {
                current_block = 15593660875440590097;
            } else {
                let fresh29 = &mut ((*ctxt).attallocs);
                *fresh29 = attallocs;
                (*ctxt).maxatts = maxatts;
                current_block = 13242334135786603907;
            }
        }
    } else if nr + 5 as i32 > (*ctxt).maxatts {
        maxatts = (nr + 5 as i32) * 2 as i32;
        atts = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).atts as *mut libc::c_void,
            (maxatts as u64)
                .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as u64),
        ) as *mut *const xmlChar;
        if atts.is_null() {
            current_block = 15593660875440590097;
        } else {
            let fresh30 = &mut ((*ctxt).atts);
            *fresh30 = atts;
            attallocs = xmlRealloc
                .expect(
                    "non-null function pointer",
                )(
                (*ctxt).attallocs as *mut libc::c_void,
                ((maxatts / 5 as i32) as u64)
                    .wrapping_mul(::std::mem::size_of::<i32>() as u64),
            ) as *mut i32;
            if attallocs.is_null() {
                current_block = 15593660875440590097;
            } else {
                let fresh31 = &mut ((*ctxt).attallocs);
                *fresh31 = attallocs;
                (*ctxt).maxatts = maxatts;
                current_block = 13242334135786603907;
            }
        }
    } else {
        current_block = 13242334135786603907;
    }
    match current_block {
        13242334135786603907 => return (*ctxt).maxatts,
        _ => {
            xmlErrMemory(ctxt, 0 as *const i8);
            return -(1 as i32);
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn inputPush(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut value: * mut crate::src::HTMLparser::_xmlParserInput,
) -> i32 {
    if ctxt.is_null() || value.is_null() {
        return -(1 as i32);
    }
    if (*ctxt).inputNr >= (*ctxt).inputMax {
        (*ctxt).inputMax *= 2 as i32;
        let fresh32 = &mut ((*ctxt).inputTab);
        *fresh32 = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).inputTab as *mut libc::c_void,
            ((*ctxt).inputMax as u64)
                .wrapping_mul(
                    ::std::mem::size_of::<xmlParserInputPtr>() as u64,
                ),
        ) as *mut xmlParserInputPtr;
        if ((*ctxt).inputTab).is_null() {
            xmlErrMemory(ctxt, 0 as *const i8);
            (*ctxt).inputMax /= 2 as i32;
            return -(1 as i32);
        }
    }
    let fresh33 = &mut (*((*ctxt).inputTab).offset((*ctxt).inputNr as isize));
    *fresh33 = value;
    let fresh34 = &mut ((*ctxt).input);
    *fresh34 = value;
    let fresh35 = &mut ((*ctxt).inputNr);
    let mut fresh36 = *fresh35;
    *fresh35 = *fresh35 + 1;
    return fresh36;
}
#[no_mangle]
pub unsafe extern "C" fn inputPop(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * mut crate::src::HTMLparser::_xmlParserInput {
    let mut ret: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    if ctxt.is_null() {
        return 0 as xmlParserInputPtr;
    }
    if (*ctxt).inputNr <= 0 as i32 {
        return 0 as xmlParserInputPtr;
    }
    let fresh37 = &mut ((*ctxt).inputNr);
    *fresh37 -= 1;
    if (*ctxt).inputNr > 0 as i32 {
        let fresh38 = &mut ((*ctxt).input);
        *fresh38 = *((*ctxt).inputTab)
            .offset(((*ctxt).inputNr - 1 as i32) as isize);
    } else {
        let fresh39 = &mut ((*ctxt).input);
        *fresh39 = 0 as xmlParserInputPtr;
    }
    ret = *((*ctxt).inputTab).offset((*ctxt).inputNr as isize);
    let fresh40 = &mut (*((*ctxt).inputTab).offset((*ctxt).inputNr as isize));
    *fresh40 = 0 as xmlParserInputPtr;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn nodePush(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut value: * mut crate::src::HTMLparser::_xmlNode,
) -> i32 {
    if ctxt.is_null() {
        return 0 as i32;
    }
    if (*ctxt).nodeNr >= (*ctxt).nodeMax {
        let mut tmp: * mut * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNodePtr;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).nodeTab as *mut libc::c_void,
            (((*ctxt).nodeMax * 2 as i32) as u64)
                .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) as *mut xmlNodePtr;
        if tmp.is_null() {
            xmlErrMemory(ctxt, 0 as *const i8);
            return -(1 as i32);
        }
        let fresh41 = &mut ((*ctxt).nodeTab);
        *fresh41 = tmp;
        (*ctxt).nodeMax *= 2 as i32;
    }
    if (*ctxt).nodeNr as u32 > xmlParserMaxDepth
        && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
    {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"Excessive depth in document: %d use XML_PARSE_HUGE option\n\0" as *const u8
                as *const i8,
            xmlParserMaxDepth as i32,
        );
        xmlHaltParser(ctxt);
        return -(1 as i32);
    }
    let fresh42 = &mut (*((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize));
    *fresh42 = value;
    let fresh43 = &mut ((*ctxt).node);
    *fresh43 = value;
    let fresh44 = &mut ((*ctxt).nodeNr);
    let mut fresh45 = *fresh44;
    *fresh44 = *fresh44 + 1;
    return fresh45;
}
#[no_mangle]
pub unsafe extern "C" fn nodePop(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * mut crate::src::HTMLparser::_xmlNode {
    let mut ret: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    if ctxt.is_null() {
        return 0 as xmlNodePtr;
    }
    if (*ctxt).nodeNr <= 0 as i32 {
        return 0 as xmlNodePtr;
    }
    let fresh46 = &mut ((*ctxt).nodeNr);
    *fresh46 -= 1;
    if (*ctxt).nodeNr > 0 as i32 {
        let fresh47 = &mut ((*ctxt).node);
        *fresh47 = *((*ctxt).nodeTab)
            .offset(((*ctxt).nodeNr - 1 as i32) as isize);
    } else {
        let fresh48 = &mut ((*ctxt).node);
        *fresh48 = 0 as xmlNodePtr;
    }
    ret = *((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize);
    let fresh49 = &mut (*((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize));
    *fresh49 = 0 as xmlNodePtr;
    return ret;
}
unsafe extern "C" fn nameNsPush(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut value: * const u8,
    mut prefix: * const u8,
    mut URI: * const u8,
    mut line: i32,
    mut nsNr: i32,
) -> i32 {
    let mut current_block: u64;
    let mut tag: Option<&'_ mut crate::src::parser::_xmlStartTag> = Option::<&'_ mut crate::src::parser::_xmlStartTag>::None;
    if (*ctxt).nameNr >= (*ctxt).nameMax {
        let mut tmp: * mut * const u8 = 0 as *mut *const xmlChar;
        let mut tmp2: * mut crate::src::parser::_xmlStartTag = 0 as *mut xmlStartTag;
        (*ctxt).nameMax *= 2 as i32;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).nameTab as *mut *mut xmlChar as *mut libc::c_void,
            ((*ctxt).nameMax as u64)
                .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as u64),
        ) as *mut *const xmlChar;
        if tmp.is_null() {
            (*ctxt).nameMax /= 2 as i32;
            current_block = 17671332882901204954;
        } else {
            let fresh50 = &mut ((*ctxt).nameTab);
            *fresh50 = tmp;
            tmp2 = xmlRealloc
                .expect(
                    "non-null function pointer",
                )(
                (*ctxt).pushTab as *mut *mut libc::c_void as *mut libc::c_void,
                ((*ctxt).nameMax as u64)
                    .wrapping_mul(::std::mem::size_of::<xmlStartTag>() as u64),
            ) as *mut xmlStartTag;
            if tmp2.is_null() {
                (*ctxt).nameMax /= 2 as i32;
                current_block = 17671332882901204954;
            } else {
                let fresh51 = &mut ((*ctxt).pushTab);
                *fresh51 = tmp2;
                current_block = 1054647088692577877;
            }
        }
    } else if ((*ctxt).pushTab).is_null() {
        let fresh52 = &mut ((*ctxt).pushTab);
        *fresh52 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*ctxt).nameMax as u64)
                .wrapping_mul(::std::mem::size_of::<xmlStartTag>() as u64),
        ) as *mut xmlStartTag;
        if ((*ctxt).pushTab).is_null() {
            current_block = 17671332882901204954;
        } else {
            current_block = 1054647088692577877;
        }
    } else {
        current_block = 1054647088692577877;
    }
    match current_block {
        17671332882901204954 => {
            xmlErrMemory(ctxt, 0 as *const i8);
            return -(1 as i32);
        }
        _ => {
            let fresh53 = &mut (*((*ctxt).nameTab).offset((*ctxt).nameNr as isize));
            *fresh53 = value;
            let fresh54 = &mut ((*ctxt).name);
            *fresh54 = value;
            tag = Some(&mut *((*ctxt).pushTab).offset((*ctxt).nameNr as isize));
            let fresh55 = &mut ((*(borrow_mut(&mut tag)).unwrap()).prefix);
            *fresh55 = prefix;
            let fresh56 = &mut ((*(borrow_mut(&mut tag)).unwrap()).URI);
            *fresh56 = URI;
            (*(borrow_mut(&mut tag)).unwrap()).line = line;
            (*(borrow_mut(&mut tag)).unwrap()).nsNr = nsNr;
            let fresh57 = &mut ((*ctxt).nameNr);
            let mut fresh58 = *fresh57;
            *fresh57 = *fresh57 + 1;
            return fresh58;
        }
    };
}
unsafe extern "C" fn nameNsPop(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * const u8 {
    let mut ret: * const u8 = 0 as *const xmlChar;
    if (*ctxt).nameNr <= 0 as i32 {
        return 0 as *const xmlChar;
    }
    let fresh59 = &mut ((*ctxt).nameNr);
    *fresh59 -= 1;
    if (*ctxt).nameNr > 0 as i32 {
        let fresh60 = &mut ((*ctxt).name);
        *fresh60 = *((*ctxt).nameTab)
            .offset(((*ctxt).nameNr - 1 as i32) as isize);
    } else {
        let fresh61 = &mut ((*ctxt).name);
        *fresh61 = 0 as *const xmlChar;
    }
    ret = *((*ctxt).nameTab).offset((*ctxt).nameNr as isize);
    let fresh62 = &mut (*((*ctxt).nameTab).offset((*ctxt).nameNr as isize));
    *fresh62 = 0 as *const xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn namePush(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut value: * const u8,
) -> i32 {
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if (*ctxt).nameNr >= (*ctxt).nameMax {
        let mut tmp: * mut * const u8 = 0 as *mut *const xmlChar;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).nameTab as *mut *mut xmlChar as *mut libc::c_void,
            (((*ctxt).nameMax * 2 as i32) as u64)
                .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as u64),
        ) as *mut *const xmlChar;
        if tmp.is_null() {
            xmlErrMemory(ctxt, 0 as *const i8);
            return -(1 as i32);
        } else {
            let fresh63 = &mut ((*ctxt).nameTab);
            *fresh63 = tmp;
            (*ctxt).nameMax *= 2 as i32;
        }
    }
    let fresh64 = &mut (*((*ctxt).nameTab).offset((*ctxt).nameNr as isize));
    *fresh64 = value;
    let fresh65 = &mut ((*ctxt).name);
    *fresh65 = value;
    let fresh66 = &mut ((*ctxt).nameNr);
    let mut fresh67 = *fresh66;
    *fresh66 = *fresh66 + 1;
    return fresh67;
}
#[no_mangle]
pub unsafe extern "C" fn namePop(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * const u8 {
    let mut ret: * const u8 = 0 as *const xmlChar;
    if ctxt.is_null() || (*ctxt).nameNr <= 0 as i32 {
        return 0 as *const xmlChar;
    }
    let fresh68 = &mut ((*ctxt).nameNr);
    *fresh68 -= 1;
    if (*ctxt).nameNr > 0 as i32 {
        let fresh69 = &mut ((*ctxt).name);
        *fresh69 = *((*ctxt).nameTab)
            .offset(((*ctxt).nameNr - 1 as i32) as isize);
    } else {
        let fresh70 = &mut ((*ctxt).name);
        *fresh70 = 0 as *const xmlChar;
    }
    ret = *((*ctxt).nameTab).offset((*ctxt).nameNr as isize);
    let fresh71 = &mut (*((*ctxt).nameTab).offset((*ctxt).nameNr as isize));
    *fresh71 = 0 as *const xmlChar;
    return ret;
}
unsafe extern "C" fn spacePush(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut val: i32,
) -> i32 {
    if (*ctxt).spaceNr >= (*ctxt).spaceMax {
        let mut tmp: * mut i32 = 0 as *mut i32;
        (*ctxt).spaceMax *= 2 as i32;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).spaceTab as *mut libc::c_void,
            ((*ctxt).spaceMax as u64)
                .wrapping_mul(::std::mem::size_of::<i32>() as u64),
        ) as *mut i32;
        if tmp.is_null() {
            xmlErrMemory(ctxt, 0 as *const i8);
            (*ctxt).spaceMax /= 2 as i32;
            return -(1 as i32);
        }
        let fresh72 = &mut ((*ctxt).spaceTab);
        *fresh72 = tmp;
    }
    *((*ctxt).spaceTab).offset((*ctxt).spaceNr as isize) = val;
    let fresh73 = &mut ((*ctxt).space);
    *fresh73 = &mut *((*ctxt).spaceTab).offset((*ctxt).spaceNr as isize)
        as *mut i32;
    let fresh74 = &mut ((*ctxt).spaceNr);
    let mut fresh75 = *fresh74;
    *fresh74 = *fresh74 + 1;
    return fresh75;
}
unsafe extern "C" fn spacePop(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> i32 {
    let mut ret: i32 = 0;
    if (*ctxt).spaceNr <= 0 as i32 {
        return 0 as i32;
    }
    let fresh76 = &mut ((*ctxt).spaceNr);
    *fresh76 -= 1;
    if (*ctxt).spaceNr > 0 as i32 {
        let fresh77 = &mut ((*ctxt).space);
        *fresh77 = &mut *((*ctxt).spaceTab)
            .offset(((*ctxt).spaceNr - 1 as i32) as isize) as *mut i32;
    } else {
        let fresh78 = &mut ((*ctxt).space);
        *fresh78 = &mut *((*ctxt).spaceTab).offset(0 as i32 as isize)
            as *mut i32;
    }
    ret = *((*ctxt).spaceTab).offset((*ctxt).spaceNr as isize);
    *((*ctxt).spaceTab).offset((*ctxt).spaceNr as isize) = -(1 as i32);
    return ret;
}
unsafe extern "C" fn xmlSHRINK(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    xmlParserInputShrink((*ctxt).input);
    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
        xmlParserInputGrow((*ctxt).input, 250 as i32);
    }
}
unsafe extern "C" fn xmlGROW(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut curEnd: i64 = ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
        as i64;
    let mut curBase: i64 = ((*(*ctxt).input).cur)
        .offset_from((*(*ctxt).input).base) as i64;
    if (curEnd > 10000000 as i32 as i64
        || curBase > 10000000 as i32 as i64)
        && (!((*(*ctxt).input).buf).is_null()
            && ((*(*(*ctxt).input).buf).readcallback
                ).map(|f| f as usize) == ( Some(
                    xmlInputReadCallbackNop,
                )).map(|f| f as usize)) && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"Huge input lookup\0" as *const u8 as *const i8,
        );
        xmlHaltParser(ctxt);
        return;
    }
    xmlParserInputGrow((*ctxt).input, 250 as i32);
    if (*(*ctxt).input).cur > (*(*ctxt).input).end
        || (*(*ctxt).input).cur < (*(*ctxt).input).base
    {
        xmlHaltParser(ctxt);
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"cur index out of bound\0" as *const u8 as *const i8,
        );
        return;
    }
    if !((*(*ctxt).input).cur).is_null()
        && *(*(*ctxt).input).cur as i32 == 0 as i32
    {
        xmlParserInputGrow((*ctxt).input, 250 as i32);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlSkipBlankChars(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> i32 {
    let mut res: i32 = 0 as i32;
    if (*ctxt).inputNr == 1 as i32
        && (*ctxt).instate as i32 != XML_PARSER_DTD as i32
        || (*ctxt).instate as i32 == XML_PARSER_START as i32
    {
        let mut cur: * const u8 = 0 as *const xmlChar;
        cur = (*(*ctxt).input).cur;
        while *cur as i32 == 0x20 as i32
            || 0x9 as i32 <= *cur as i32
                && *cur as i32 <= 0xa as i32
            || *cur as i32 == 0xd as i32
        {
            if *cur as i32 == '\n' as i32 {
                let fresh79 = &mut ((*(*ctxt).input).line);
                *fresh79 += 1;
                (*(*ctxt).input).col = 1 as i32;
            } else {
                let fresh80 = &mut ((*(*ctxt).input).col);
                *fresh80 += 1;
            }
            cur = cur.offset(1);
            if res < 2147483647 as i32 {
                res += 1;
            }
            if *cur as i32 == 0 as i32 {
                let fresh81 = &mut ((*(*ctxt).input).cur);
                *fresh81 = cur;
                xmlParserInputGrow((*ctxt).input, 250 as i32);
                cur = (*(*ctxt).input).cur;
            }
        }
        let fresh82 = &mut ((*(*ctxt).input).cur);
        *fresh82 = cur;
    } else {
        let mut expandPE: i32 = ((*ctxt).external != 0 as i32
            || (*ctxt).inputNr != 1 as i32) as i32;
        loop {
            if *(*(*ctxt).input).cur as i32 == 0x20 as i32
                || 0x9 as i32 <= *(*(*ctxt).input).cur as i32
                    && *(*(*ctxt).input).cur as i32 <= 0xa as i32
                || *(*(*ctxt).input).cur as i32 == 0xd as i32
            {
                xmlNextChar(ctxt);
            } else if *(*(*ctxt).input).cur as i32 == '%' as i32 {
                if expandPE == 0 as i32
                    || (*((*(*ctxt).input).cur).offset(1 as i32 as isize)
                        as i32 == 0x20 as i32
                        || 0x9 as i32
                            <= *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                                as i32
                            && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                                as i32 <= 0xa as i32
                        || *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                            as i32 == 0xd as i32)
                    || *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                        as i32 == 0 as i32
                {
                    break;
                }
                xmlParsePEReference(ctxt);
            } else {
                if !(*(*(*ctxt).input).cur as i32 == 0 as i32) {
                    break;
                }
                if (*ctxt).inputNr <= 1 as i32 {
                    break;
                }
                xmlPopInput(ctxt);
            }
            if res < 2147483647 as i32 {
                res += 1;
            }
        }
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlPopInput(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> u8 {
    if ctxt.is_null() || (*ctxt).inputNr <= 1 as i32 {
        return 0 as i32 as xmlChar;
    }
    if *(borrow(& __xmlParserDebugEntities())).unwrap() != 0 {
        (*(borrow(& __xmlGenericError())).unwrap())
            .expect(
                "non-null function pointer",
            )(
            *(__xmlGenericErrorContext()).unwrap(),
            b"Popping input %d\n\0" as *const u8 as *const i8,
            (*ctxt).inputNr,
        );
    }
    if (*ctxt).inputNr > 1 as i32 && (*ctxt).inSubset == 0 as i32
        && (*ctxt).instate as i32 != XML_PARSER_EOF as i32
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"Unfinished entity outside the DTD\0" as *const u8 as *const i8,
        );
    }
    xmlFreeInputStream(inputPop(ctxt));
    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
        xmlParserInputGrow((*ctxt).input, 250 as i32);
    }
    return *(*(*ctxt).input).cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlPushInput(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut input: * mut crate::src::HTMLparser::_xmlParserInput,
) -> i32 {
    let mut ret: i32 = 0;
    if input.is_null() {
        return -(1 as i32);
    }
    if *(borrow(& __xmlParserDebugEntities())).unwrap() != 0 {
        if !((*ctxt).input).is_null() && !((*(*ctxt).input).filename).is_null() {
            (*(borrow(& __xmlGenericError())).unwrap())
                .expect(
                    "non-null function pointer",
                )(
                *(__xmlGenericErrorContext()).unwrap(),
                b"%s(%d): \0" as *const u8 as *const i8,
                (*(*ctxt).input).filename,
                (*(*ctxt).input).line,
            );
        }
        (*(borrow(& __xmlGenericError())).unwrap())
            .expect(
                "non-null function pointer",
            )(
            *(__xmlGenericErrorContext()).unwrap(),
            b"Pushing input %d : %.30s\n\0" as *const u8 as *const i8,
            (*ctxt).inputNr + 1 as i32,
            (*input).cur,
        );
    }
    if (*ctxt).inputNr > 40 as i32
        && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
        || (*ctxt).inputNr > 1024 as i32
    {
        xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const i8);
        while (*ctxt).inputNr > 1 as i32 {
            xmlFreeInputStream(inputPop(ctxt));
        }
        return -(1 as i32);
    }
    ret = inputPush(ctxt, input);
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseCharRef(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> i32 {
    let mut val: i32 = 0 as i32;
    let mut count: i32 = 0 as i32;
    if *(*(*ctxt).input).cur as i32 == '&' as i32
        && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            == '#' as i32
        && *((*(*ctxt).input).cur).offset(2 as i32 as isize) as i32
            == 'x' as i32
    {
        let fresh83 = &mut ((*(*ctxt).input).cur);
        *fresh83 = (*fresh83).offset(3 as i32 as isize);
        (*(*ctxt).input).col += 3 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        while *(*(*ctxt).input).cur as i32 != ';' as i32 {
            let mut fresh84 = count;
            count = count + 1;
            if fresh84 > 20 as i32 {
                count = 0 as i32;
                if (*ctxt).progressive == 0 as i32
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64) < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                    return 0 as i32;
                }
            }
            if *(*(*ctxt).input).cur as i32 >= '0' as i32
                && *(*(*ctxt).input).cur as i32 <= '9' as i32
            {
                val = val * 16 as i32
                    + (*(*(*ctxt).input).cur as i32 - '0' as i32);
            } else if *(*(*ctxt).input).cur as i32 >= 'a' as i32
                    && *(*(*ctxt).input).cur as i32 <= 'f' as i32
                    && count < 20 as i32
                {
                val = val * 16 as i32
                    + (*(*(*ctxt).input).cur as i32 - 'a' as i32)
                    + 10 as i32;
            } else if *(*(*ctxt).input).cur as i32 >= 'A' as i32
                    && *(*(*ctxt).input).cur as i32 <= 'F' as i32
                    && count < 20 as i32
                {
                val = val * 16 as i32
                    + (*(*(*ctxt).input).cur as i32 - 'A' as i32)
                    + 10 as i32;
            } else {
                xmlFatalErr(ctxt, XML_ERR_INVALID_HEX_CHARREF, 0 as *const i8);
                val = 0 as i32;
                break;
            }
            if val > 0x110000 as i32 {
                val = 0x110000 as i32;
            }
            xmlNextChar(ctxt);
            count += 1;
        }
        if *(*(*ctxt).input).cur as i32 == ';' as i32 {
            let fresh85 = &mut ((*(*ctxt).input).col);
            *fresh85 += 1;
            let fresh86 = &mut ((*(*ctxt).input).cur);
            *fresh86 = (*fresh86).offset(1);
        }
    } else if *(*(*ctxt).input).cur as i32 == '&' as i32
            && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
                == '#' as i32
        {
        let fresh87 = &mut ((*(*ctxt).input).cur);
        *fresh87 = (*fresh87).offset(2 as i32 as isize);
        (*(*ctxt).input).col += 2 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        while *(*(*ctxt).input).cur as i32 != ';' as i32 {
            let mut fresh88 = count;
            count = count + 1;
            if fresh88 > 20 as i32 {
                count = 0 as i32;
                if (*ctxt).progressive == 0 as i32
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64) < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                    return 0 as i32;
                }
            }
            if *(*(*ctxt).input).cur as i32 >= '0' as i32
                && *(*(*ctxt).input).cur as i32 <= '9' as i32
            {
                val = val * 10 as i32
                    + (*(*(*ctxt).input).cur as i32 - '0' as i32);
                if val > 0x110000 as i32 {
                    val = 0x110000 as i32;
                }
                xmlNextChar(ctxt);
                count += 1;
            } else {
                xmlFatalErr(ctxt, XML_ERR_INVALID_DEC_CHARREF, 0 as *const i8);
                val = 0 as i32;
                break;
            }
        }
        if *(*(*ctxt).input).cur as i32 == ';' as i32 {
            let fresh89 = &mut ((*(*ctxt).input).col);
            *fresh89 += 1;
            let fresh90 = &mut ((*(*ctxt).input).cur);
            *fresh90 = (*fresh90).offset(1);
        }
    } else {
        xmlFatalErr(ctxt, XML_ERR_INVALID_CHARREF, 0 as *const i8);
    }
    if val >= 0x110000 as i32 {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlParseCharRef: character reference out of bounds\n\0" as *const u8
                as *const i8,
            val,
        );
    } else if if val < 0x100 as i32 {
            (0x9 as i32 <= val && val <= 0xa as i32
                || val == 0xd as i32 || 0x20 as i32 <= val)
                as i32
        } else {
            (0x100 as i32 <= val && val <= 0xd7ff as i32
                || 0xe000 as i32 <= val && val <= 0xfffd as i32
                || 0x10000 as i32 <= val && val <= 0x10ffff as i32)
                as i32
        } != 0
        {
        return val
    } else {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlParseCharRef: invalid xmlChar value %d\n\0" as *const u8
                as *const i8,
            val,
        );
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlParseStringCharRef<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut str: Option<&'a1 mut * const u8>,
) -> i32 {
    let mut ptr: * const u8 = 0 as *const xmlChar;
    let mut cur: u8 = 0;
    let mut val: i32 = 0 as i32;
    if borrow(& str).is_none() || (*(borrow_mut(&mut str)).unwrap()).is_null() {
        return 0 as i32;
    }
    ptr = *(borrow(& str)).unwrap();
    cur = *ptr;
    if cur as i32 == '&' as i32
        && *ptr.offset(1 as i32 as isize) as i32 == '#' as i32
        && *ptr.offset(2 as i32 as isize) as i32 == 'x' as i32
    {
        ptr = ptr.offset(3 as i32 as isize);
        cur = *ptr;
        while cur as i32 != ';' as i32 {
            if cur as i32 >= '0' as i32 && cur as i32 <= '9' as i32 {
                val = val * 16 as i32 + (cur as i32 - '0' as i32);
            } else if cur as i32 >= 'a' as i32
                    && cur as i32 <= 'f' as i32
                {
                val = val * 16 as i32 + (cur as i32 - 'a' as i32)
                    + 10 as i32;
            } else if cur as i32 >= 'A' as i32
                    && cur as i32 <= 'F' as i32
                {
                val = val * 16 as i32 + (cur as i32 - 'A' as i32)
                    + 10 as i32;
            } else {
                xmlFatalErr(ctxt, XML_ERR_INVALID_HEX_CHARREF, 0 as *const i8);
                val = 0 as i32;
                break;
            }
            if val > 0x110000 as i32 {
                val = 0x110000 as i32;
            }
            ptr = ptr.offset(1);
            cur = *ptr;
        }
        if cur as i32 == ';' as i32 {
            ptr = ptr.offset(1);
        }
    } else if cur as i32 == '&' as i32
            && *ptr.offset(1 as i32 as isize) as i32 == '#' as i32
        {
        ptr = ptr.offset(2 as i32 as isize);
        cur = *ptr;
        while cur as i32 != ';' as i32 {
            if cur as i32 >= '0' as i32 && cur as i32 <= '9' as i32 {
                val = val * 10 as i32 + (cur as i32 - '0' as i32);
                if val > 0x110000 as i32 {
                    val = 0x110000 as i32;
                }
                ptr = ptr.offset(1);
                cur = *ptr;
            } else {
                xmlFatalErr(ctxt, XML_ERR_INVALID_DEC_CHARREF, 0 as *const i8);
                val = 0 as i32;
                break;
            }
        }
        if cur as i32 == ';' as i32 {
            ptr = ptr.offset(1);
        }
    } else {
        xmlFatalErr(ctxt, XML_ERR_INVALID_CHARREF, 0 as *const i8);
        return 0 as i32;
    }
    *(borrow_mut(&mut str)).unwrap() = ptr;
    if val >= 0x110000 as i32 {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlParseStringCharRef: character reference out of bounds\n\0" as *const u8
                as *const i8,
            val,
        );
    } else if if val < 0x100 as i32 {
            (0x9 as i32 <= val && val <= 0xa as i32
                || val == 0xd as i32 || 0x20 as i32 <= val)
                as i32
        } else {
            (0x100 as i32 <= val && val <= 0xd7ff as i32
                || 0xe000 as i32 <= val && val <= 0xfffd as i32
                || 0x10000 as i32 <= val && val <= 0x10ffff as i32)
                as i32
        } != 0
        {
        return val
    } else {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlParseStringCharRef: invalid xmlChar value %d\n\0" as *const u8
                as *const i8,
            val,
        );
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserHandlePEReference(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    match (*ctxt).instate as i32 {
        8 => return,
        5 => return,
        6 => return,
        9 => return,
        -1 => {
            xmlFatalErr(ctxt, XML_ERR_PEREF_AT_EOF, 0 as *const i8);
            return;
        }
        4 | 0 | 1 => {
            xmlFatalErr(ctxt, XML_ERR_PEREF_IN_PROLOG, 0 as *const i8);
            return;
        }
        10 | 7 | 12 | 2 | 13 | 16 => return,
        14 => {
            xmlFatalErr(ctxt, XML_ERR_PEREF_IN_EPILOG, 0 as *const i8);
            return;
        }
        11 => return,
        3 => {
            if (*ctxt).external == 0 as i32
                && (*ctxt).inputNr == 1 as i32
            {
                return;
            }
            if *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
                == 0x20 as i32
                || 0x9 as i32
                    <= *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                        as i32
                    && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                        as i32 <= 0xa as i32
                || *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == 0xd as i32
                || *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == 0 as i32
            {
                return;
            }
        }
        15 => return,
        _ => {}
    }
    xmlParsePEReference(ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStringLenDecodeEntities(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut str: * const u8,
    mut len: i32,
    mut what: i32,
    mut end: u8,
    mut end2: u8,
    mut end3: u8,
) -> * mut u8 {
    let mut current_block: u64;
    let mut buffer: * mut u8 = 0 as *mut xmlChar;
    let mut buffer_size: u64 = 0 as i32 as size_t;
    let mut nbchars: u64 = 0 as i32 as size_t;
    let mut current: * mut u8 = 0 as *mut xmlChar;
    let mut rep: * mut u8 = 0 as *mut xmlChar;
    let mut last: * const u8 = 0 as *const xmlChar;
    let mut ent: * mut crate::src::HTMLparser::_xmlEntity = 0 as *mut xmlEntity;
    let mut c: i32 = 0;
    let mut l: i32 = 0;
    if ctxt.is_null() || str.is_null() || len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    last = str.offset(len as isize);
    if (*ctxt).depth > 40 as i32
        && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
        || (*ctxt).depth > 1024 as i32
    {
        xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    buffer_size = 300 as i32 as size_t;
    buffer = xmlMallocAtomic.expect("non-null function pointer")(buffer_size)
        as *mut xmlChar;
    if buffer.is_null() {
        current_block = 12997678243655494442;
    } else {
        if str < last {
            c = xmlStringCurrentChar(ctxt, str, Some(&mut l));
        } else {
            c = 0 as i32;
        }
        's_81: loop {
            if !(c != 0 as i32 && c != end as i32
                && c != end2 as i32 && c != end3 as i32
                && (*ctxt).instate as i32 != XML_PARSER_EOF as i32)
            {
                current_block = 13810333397648094191;
                break;
            }
            if c == 0 as i32 {
                current_block = 13810333397648094191;
                break;
            }
            if c == '&' as i32
                && *str.offset(1 as i32 as isize) as i32 == '#' as i32
            {
                let mut val: i32 = xmlParseStringCharRef(ctxt, Some(&mut str));
                if val == 0 as i32 {
                    current_block = 15857547771987096737;
                    break;
                }
                if 0 as i32 == 1 as i32 {
                    let mut fresh91 = nbchars;
                    nbchars = nbchars.wrapping_add(1);
                    *buffer.offset(fresh91 as isize) = val as xmlChar;
                } else {
                    nbchars = (nbchars as u64)
                        .wrapping_add(
                            xmlCopyCharMultiByte(
                                &mut *buffer.offset(nbchars as isize),
                                val,
                            ) as u64,
                        ) as size_t as size_t;
                }
                if nbchars.wrapping_add(100 as i32 as u64)
                    > buffer_size
                {
                    let mut tmp: * mut u8 = 0 as *mut xmlChar;
                    let mut new_size: u64 = buffer_size
                        .wrapping_mul(2 as i32 as u64)
                        .wrapping_add(100 as i32 as u64);
                    if new_size < buffer_size {
                        current_block = 12997678243655494442;
                        break;
                    }
                    tmp = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(buffer as *mut libc::c_void, new_size) as *mut xmlChar;
                    if tmp.is_null() {
                        current_block = 12997678243655494442;
                        break;
                    }
                    buffer = tmp;
                    buffer_size = new_size;
                }
            } else if c == '&' as i32 && what & 1 as i32 != 0 {
                if *(borrow(& __xmlParserDebugEntities())).unwrap() != 0 {
                    (*(borrow(& __xmlGenericError())).unwrap())
                        .expect(
                            "non-null function pointer",
                        )(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"String decoding Entity Reference: %.30s\n\0" as *const u8
                            as *const i8,
                        str,
                    );
                }
                ent = xmlParseStringEntityRef(ctxt, Some(&mut str));
                xmlParserEntityCheck(
                    ctxt,
                    0 as i32 as size_t,
                    ent,
                    0 as i32 as size_t,
                );
                if !ent.is_null() {
                    let fresh92 = &mut ((*ctxt).nbentities);
                    *fresh92 = (*fresh92)
                        .wrapping_add(
                            ((*ent).checked / 2 as i32) as u64,
                        );
                }
                if !ent.is_null()
                    && (*ent).etype as u32
                        == XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
                {
                    if !((*ent).content).is_null() {
                        if 0 as i32 == 1 as i32 {
                            let mut fresh93 = nbchars;
                            nbchars = nbchars.wrapping_add(1);
                            *buffer
                                .offset(
                                    fresh93 as isize,
                                ) = *((*ent).content).offset(0 as i32 as isize);
                        } else {
                            nbchars = (nbchars as u64)
                                .wrapping_add(
                                    xmlCopyCharMultiByte(
                                        &mut *buffer.offset(nbchars as isize),
                                        *((*ent).content).offset(0 as i32 as isize)
                                            as i32,
                                    ) as u64,
                                ) as size_t as size_t;
                        }
                        if nbchars.wrapping_add(100 as i32 as u64)
                            > buffer_size
                        {
                            let mut tmp_0: * mut u8 = 0 as *mut xmlChar;
                            let mut new_size_0: u64 = buffer_size
                                .wrapping_mul(2 as i32 as u64)
                                .wrapping_add(100 as i32 as u64);
                            if new_size_0 < buffer_size {
                                current_block = 12997678243655494442;
                                break;
                            }
                            tmp_0 = xmlRealloc
                                .expect(
                                    "non-null function pointer",
                                )(buffer as *mut libc::c_void, new_size_0) as *mut xmlChar;
                            if tmp_0.is_null() {
                                current_block = 12997678243655494442;
                                break;
                            }
                            buffer = tmp_0;
                            buffer_size = new_size_0;
                        }
                    } else {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_INTERNAL_ERROR,
                            b"predefined entity has no content\n\0" as *const u8
                                as *const i8,
                        );
                        current_block = 15857547771987096737;
                        break;
                    }
                } else if !ent.is_null() && !((*ent).content).is_null() {
                    let fresh94 = &mut ((*ctxt).depth);
                    *fresh94 += 1;
                    rep = xmlStringDecodeEntities(
                        ctxt,
                        (*ent).content,
                        what,
                        0 as i32 as xmlChar,
                        0 as i32 as xmlChar,
                        0 as i32 as xmlChar,
                    );
                    let fresh95 = &mut ((*ctxt).depth);
                    *fresh95 -= 1;
                    if rep.is_null() {
                        *((*ent).content)
                            .offset(
                                0 as i32 as isize,
                            ) = 0 as i32 as xmlChar;
                        current_block = 15857547771987096737;
                        break;
                    } else {
                        current = rep;
                        while *current as i32 != 0 as i32 {
                            let mut fresh96 = current;
                            current = current.offset(1);
                            let mut fresh97 = nbchars;
                            nbchars = nbchars.wrapping_add(1);
                            *buffer.offset(fresh97 as isize) = *fresh96;
                            if !(nbchars
                                .wrapping_add(100 as i32 as u64)
                                > buffer_size)
                            {
                                continue;
                            }
                            if xmlParserEntityCheck(
                                ctxt,
                                nbchars,
                                ent,
                                0 as i32 as size_t,
                            ) != 0
                            {
                                current_block = 15857547771987096737;
                                break 's_81;
                            }
                            let mut tmp_1: * mut u8 = 0 as *mut xmlChar;
                            let mut new_size_1: u64 = buffer_size
                                .wrapping_mul(2 as i32 as u64)
                                .wrapping_add(100 as i32 as u64);
                            if new_size_1 < buffer_size {
                                current_block = 12997678243655494442;
                                break 's_81;
                            }
                            tmp_1 = xmlRealloc
                                .expect(
                                    "non-null function pointer",
                                )(buffer as *mut libc::c_void, new_size_1) as *mut xmlChar;
                            if tmp_1.is_null() {
                                current_block = 12997678243655494442;
                                break 's_81;
                            }
                            buffer = tmp_1;
                            buffer_size = new_size_1;
                        }
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(rep as *mut libc::c_void);
                        rep = 0 as *mut xmlChar;
                    }
                } else if !ent.is_null() {
                    let mut i: i32 = xmlStrlen((*ent).name);
                    let mut cur: * const u8 = (*ent).name;
                    let mut fresh98 = nbchars;
                    nbchars = nbchars.wrapping_add(1);
                    *buffer.offset(fresh98 as isize) = '&' as i32 as xmlChar;
                    if nbchars
                        .wrapping_add(i as u64)
                        .wrapping_add(100 as i32 as u64) > buffer_size
                    {
                        let mut tmp_2: * mut u8 = 0 as *mut xmlChar;
                        let mut new_size_2: u64 = buffer_size
                            .wrapping_mul(2 as i32 as u64)
                            .wrapping_add(i as u64)
                            .wrapping_add(100 as i32 as u64);
                        if new_size_2 < buffer_size {
                            current_block = 12997678243655494442;
                            break;
                        }
                        tmp_2 = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void, new_size_2) as *mut xmlChar;
                        if tmp_2.is_null() {
                            current_block = 12997678243655494442;
                            break;
                        }
                        buffer = tmp_2;
                        buffer_size = new_size_2;
                    }
                    while i > 0 as i32 {
                        let mut fresh99 = cur;
                        cur = cur.offset(1);
                        let mut fresh100 = nbchars;
                        nbchars = nbchars.wrapping_add(1);
                        *buffer.offset(fresh100 as isize) = *fresh99;
                        i -= 1;
                    }
                    let mut fresh101 = nbchars;
                    nbchars = nbchars.wrapping_add(1);
                    *buffer.offset(fresh101 as isize) = ';' as i32 as xmlChar;
                }
            } else if c == '%' as i32 && what & 2 as i32 != 0 {
                if *(borrow(& __xmlParserDebugEntities())).unwrap() != 0 {
                    (*(borrow(& __xmlGenericError())).unwrap())
                        .expect(
                            "non-null function pointer",
                        )(
                        *(__xmlGenericErrorContext()).unwrap(),
                        b"String decoding PE Reference: %.30s\n\0" as *const u8
                            as *const i8,
                        str,
                    );
                }
                ent = xmlParseStringPEReference(ctxt, Some(&mut str));
                xmlParserEntityCheck(
                    ctxt,
                    0 as i32 as size_t,
                    ent,
                    0 as i32 as size_t,
                );
                if !ent.is_null() {
                    let fresh102 = &mut ((*ctxt).nbentities);
                    *fresh102 = (*fresh102)
                        .wrapping_add(
                            ((*ent).checked / 2 as i32) as u64,
                        );
                }
                if !ent.is_null() {
                    if ((*ent).content).is_null() {
                        if (*ctxt).options & XML_PARSE_NOENT as i32
                            != 0 as i32
                            || (*ctxt).options & XML_PARSE_DTDVALID as i32
                                != 0 as i32 || (*ctxt).validate != 0 as i32
                        {
                            xmlLoadEntityContent(ctxt, ent);
                        } else {
                            xmlWarningMsg(
                                ctxt,
                                XML_ERR_ENTITY_PROCESSING,
                                b"not validating will not read content for PE entity %s\n\0"
                                    as *const u8 as *const i8,
                                (*ent).name,
                                0 as *const xmlChar,
                            );
                        }
                    }
                    let fresh103 = &mut ((*ctxt).depth);
                    *fresh103 += 1;
                    rep = xmlStringDecodeEntities(
                        ctxt,
                        (*ent).content,
                        what,
                        0 as i32 as xmlChar,
                        0 as i32 as xmlChar,
                        0 as i32 as xmlChar,
                    );
                    let fresh104 = &mut ((*ctxt).depth);
                    *fresh104 -= 1;
                    if rep.is_null() {
                        if !((*ent).content).is_null() {
                            *((*ent).content)
                                .offset(
                                    0 as i32 as isize,
                                ) = 0 as i32 as xmlChar;
                        }
                        current_block = 15857547771987096737;
                        break;
                    } else {
                        current = rep;
                        while *current as i32 != 0 as i32 {
                            let mut fresh105 = current;
                            current = current.offset(1);
                            let mut fresh106 = nbchars;
                            nbchars = nbchars.wrapping_add(1);
                            *buffer.offset(fresh106 as isize) = *fresh105;
                            if !(nbchars
                                .wrapping_add(100 as i32 as u64)
                                > buffer_size)
                            {
                                continue;
                            }
                            if xmlParserEntityCheck(
                                ctxt,
                                nbchars,
                                ent,
                                0 as i32 as size_t,
                            ) != 0
                            {
                                current_block = 15857547771987096737;
                                break 's_81;
                            }
                            let mut tmp_3: * mut u8 = 0 as *mut xmlChar;
                            let mut new_size_3: u64 = buffer_size
                                .wrapping_mul(2 as i32 as u64)
                                .wrapping_add(100 as i32 as u64);
                            if new_size_3 < buffer_size {
                                current_block = 12997678243655494442;
                                break 's_81;
                            }
                            tmp_3 = xmlRealloc
                                .expect(
                                    "non-null function pointer",
                                )(buffer as *mut libc::c_void, new_size_3) as *mut xmlChar;
                            if tmp_3.is_null() {
                                current_block = 12997678243655494442;
                                break 's_81;
                            }
                            buffer = tmp_3;
                            buffer_size = new_size_3;
                        }
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(rep as *mut libc::c_void);
                        rep = 0 as *mut xmlChar;
                    }
                }
            } else {
                if l == 1 as i32 {
                    let mut fresh107 = nbchars;
                    nbchars = nbchars.wrapping_add(1);
                    *buffer.offset(fresh107 as isize) = c as xmlChar;
                } else {
                    nbchars = (nbchars as u64)
                        .wrapping_add(
                            xmlCopyCharMultiByte(
                                &mut *buffer.offset(nbchars as isize),
                                c,
                            ) as u64,
                        ) as size_t as size_t;
                }
                str = str.offset(l as isize);
                if nbchars.wrapping_add(100 as i32 as u64)
                    > buffer_size
                {
                    let mut tmp_4: * mut u8 = 0 as *mut xmlChar;
                    let mut new_size_4: u64 = buffer_size
                        .wrapping_mul(2 as i32 as u64)
                        .wrapping_add(100 as i32 as u64);
                    if new_size_4 < buffer_size {
                        current_block = 12997678243655494442;
                        break;
                    }
                    tmp_4 = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(buffer as *mut libc::c_void, new_size_4) as *mut xmlChar;
                    if tmp_4.is_null() {
                        current_block = 12997678243655494442;
                        break;
                    }
                    buffer = tmp_4;
                    buffer_size = new_size_4;
                }
            }
            if str < last {
                c = xmlStringCurrentChar(ctxt, str, Some(&mut l));
            } else {
                c = 0 as i32;
            }
        }
        match current_block {
            12997678243655494442 => {}
            15857547771987096737 => {}
            _ => {
                *buffer.offset(nbchars as isize) = 0 as i32 as xmlChar;
                return buffer;
            }
        }
    }
    match current_block {
        12997678243655494442 => {
            xmlErrMemory(ctxt, 0 as *const i8);
        }
        _ => {}
    }
    if !rep.is_null() {
        xmlFree.expect("non-null function pointer")(rep as *mut libc::c_void);
    }
    if !buffer.is_null() {
        xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void);
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStringDecodeEntities(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut str: * const u8,
    mut what: i32,
    mut end: u8,
    mut end2: u8,
    mut end3: u8,
) -> * mut u8 {
    if ctxt.is_null() || str.is_null() {
        return 0 as *mut xmlChar;
    }
    return xmlStringLenDecodeEntities(ctxt, str, xmlStrlen(str), what, end, end2, end3);
}
unsafe extern "C" fn areBlanks(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut str: * const u8,
    mut len: i32,
    mut blank_chars: i32,
) -> i32 {
    let mut i: i32 = 0;
    let mut ret: i32 = 0;
    let mut lastChild: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    if ((*(*ctxt).sax).ignorableWhitespace ).map(|f| f as usize) == ( (*(*ctxt).sax).characters).map(|f| f as usize) {
        return 0 as i32;
    }
    if ((*ctxt).space).is_null() || *(*ctxt).space == 1 as i32
        || *(*ctxt).space == -(2 as i32)
    {
        return 0 as i32;
    }
    if blank_chars == 0 as i32 {
        i = 0 as i32;
        while i < len {
            if !(*str.offset(i as isize) as i32 == 0x20 as i32
                || 0x9 as i32 <= *str.offset(i as isize) as i32
                    && *str.offset(i as isize) as i32 <= 0xa as i32
                || *str.offset(i as isize) as i32 == 0xd as i32)
            {
                return 0 as i32;
            }
            i += 1;
        }
    }
    if ((*ctxt).node).is_null() {
        return 0 as i32;
    }
    if !((*ctxt).myDoc).is_null() {
        ret = xmlIsMixedElement((*ctxt).myDoc, (*(*ctxt).node).name);
        if ret == 0 as i32 {
            return 1 as i32;
        }
        if ret == 1 as i32 {
            return 0 as i32;
        }
    }
    if *(*(*ctxt).input).cur as i32 != '<' as i32
        && *(*(*ctxt).input).cur as i32 != 0xd as i32
    {
        return 0 as i32;
    }
    if ((*(*ctxt).node).children).is_null()
        && *(*(*ctxt).input).cur as i32 == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            == '/' as i32
    {
        return 0 as i32;
    }
    lastChild = xmlGetLastChild((*ctxt).node as *const xmlNode);
    if lastChild.is_null() {
        if (*(*ctxt).node).type_0 as u32
            != XML_ELEMENT_NODE as i32 as u32
            && !((*(*ctxt).node).content).is_null()
        {
            return 0 as i32;
        }
    } else if xmlNodeIsText(lastChild as *const xmlNode) != 0 {
        return 0 as i32
    } else {
        if !((*(*ctxt).node).children).is_null()
            && xmlNodeIsText((*(*ctxt).node).children) != 0
        {
            return 0 as i32;
        }
    }
    return 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSplitQName<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut name: * const u8,
    mut prefix: Option<&'a1 mut * mut u8>,
) -> * mut u8 {
    let mut buf: [u8; 105] = [0; 105];
    let mut buffer: * mut u8 = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut max: i32 = 100 as i32;
    let mut ret: * mut u8 = 0 as *mut xmlChar;
    let mut cur: * const u8 = name;
    let mut c: i32 = 0;
    if borrow(& prefix).is_none() {
        return 0 as *mut xmlChar;
    }
    *(borrow_mut(&mut prefix)).unwrap() = 0 as *mut xmlChar;
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    if *cur.offset(0 as i32 as isize) as i32 == ':' as i32 {
        return xmlStrdup(name);
    }
    let mut fresh108 = cur;
    cur = cur.offset(1);
    c = *fresh108 as i32;
    while c != 0 as i32 && c != ':' as i32 && len < max {
        let mut fresh109 = len;
        len = len + 1;
        buf[fresh109 as usize] = c as xmlChar;
        let mut fresh110 = cur;
        cur = cur.offset(1);
        c = *fresh110 as i32;
    }
    if len >= max {
        max = len * 2 as i32;
        buffer = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )(
            (max as u64)
                .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        ) as *mut xmlChar;
        if buffer.is_null() {
            xmlErrMemory(ctxt, 0 as *const i8);
            return 0 as *mut xmlChar;
        }
        memcpy(
            buffer as *mut libc::c_void,
            buf.as_mut_ptr() as *const libc::c_void,
            len as u64,
        );
        while c != 0 as i32 && c != ':' as i32 {
            if len + 10 as i32 > max {
                let mut tmp: * mut u8 = 0 as *mut xmlChar;
                max *= 2 as i32;
                tmp = xmlRealloc
                    .expect(
                        "non-null function pointer",
                    )(
                    buffer as *mut libc::c_void,
                    (max as u64)
                        .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
                ) as *mut xmlChar;
                if tmp.is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(buffer as *mut libc::c_void);
                    xmlErrMemory(ctxt, 0 as *const i8);
                    return 0 as *mut xmlChar;
                }
                buffer = tmp;
            }
            let mut fresh111 = len;
            len = len + 1;
            *buffer.offset(fresh111 as isize) = c as xmlChar;
            let mut fresh112 = cur;
            cur = cur.offset(1);
            c = *fresh112 as i32;
        }
        *buffer.offset(len as isize) = 0 as i32 as xmlChar;
    }
    if c == ':' as i32 && *cur as i32 == 0 as i32 {
        if !buffer.is_null() {
            xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void);
        }
        *(borrow_mut(&mut prefix)).unwrap() = 0 as *mut xmlChar;
        return xmlStrdup(name);
    }
    if buffer.is_null() {
        ret = xmlStrndup(buf.as_mut_ptr(), len);
    } else {
        ret = buffer;
        buffer = 0 as *mut xmlChar;
        max = 100 as i32;
    }
    if c == ':' as i32 {
        c = *cur as i32;
        *(borrow_mut(&mut prefix)).unwrap() = ret;
        if c == 0 as i32 {
            return xmlStrndup(
                b"\0" as *const u8 as *const i8 as *mut xmlChar,
                0 as i32,
            );
        }
        len = 0 as i32;
        if !(c >= 0x61 as i32 && c <= 0x7a as i32
            || c >= 0x41 as i32 && c <= 0x5a as i32 || c == '_' as i32
            || c == ':' as i32)
        {
            let mut l: i32 = 0;
            let mut first: i32 = xmlStringCurrentChar(ctxt, cur, Some(&mut l));
            if !((if first < 0x100 as i32 {
                (0x41 as i32 <= first && first <= 0x5a as i32
                    || 0x61 as i32 <= first && first <= 0x7a as i32
                    || 0xc0 as i32 <= first && first <= 0xd6 as i32
                    || 0xd8 as i32 <= first && first <= 0xf6 as i32
                    || 0xf8 as i32 <= first) as i32
            } else {
                xmlCharInRange(first as u32, (Some(&xmlIsBaseCharGroup)).clone())
            }) != 0
                || (if first < 0x100 as i32 {
                    0 as i32
                } else {
                    (0x4e00 as i32 <= first && first <= 0x9fa5 as i32
                        || first == 0x3007 as i32
                        || 0x3021 as i32 <= first
                            && first <= 0x3029 as i32) as i32
                }) != 0) && first != '_' as i32
            {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_NS_ERR_QNAME,
                    b"Name %s is not XML Namespace compliant\n\0" as *const u8
                        as *const i8,
                    name,
                );
            }
        }
        cur = cur.offset(1);
        while c != 0 as i32 && len < max {
            let mut fresh113 = len;
            len = len + 1;
            buf[fresh113 as usize] = c as xmlChar;
            let mut fresh114 = cur;
            cur = cur.offset(1);
            c = *fresh114 as i32;
        }
        if len >= max {
            max = len * 2 as i32;
            buffer = xmlMallocAtomic
                .expect(
                    "non-null function pointer",
                )(
                (max as u64)
                    .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) as *mut xmlChar;
            if buffer.is_null() {
                xmlErrMemory(ctxt, 0 as *const i8);
                return 0 as *mut xmlChar;
            }
            memcpy(
                buffer as *mut libc::c_void,
                buf.as_mut_ptr() as *const libc::c_void,
                len as u64,
            );
            while c != 0 as i32 {
                if len + 10 as i32 > max {
                    let mut tmp_0: * mut u8 = 0 as *mut xmlChar;
                    max *= 2 as i32;
                    tmp_0 = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(
                        buffer as *mut libc::c_void,
                        (max as u64)
                            .wrapping_mul(
                                ::std::mem::size_of::<xmlChar>() as u64,
                            ),
                    ) as *mut xmlChar;
                    if tmp_0.is_null() {
                        xmlErrMemory(ctxt, 0 as *const i8);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                    buffer = tmp_0;
                }
                let mut fresh115 = len;
                len = len + 1;
                *buffer.offset(fresh115 as isize) = c as xmlChar;
                let mut fresh116 = cur;
                cur = cur.offset(1);
                c = *fresh116 as i32;
            }
            *buffer.offset(len as isize) = 0 as i32 as xmlChar;
        }
        if buffer.is_null() {
            ret = xmlStrndup(buf.as_mut_ptr(), len);
        } else {
            ret = buffer;
        }
    }
    return ret;
}
unsafe extern "C" fn xmlIsNameStartChar(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut c: i32,
) -> i32 {
    if (*ctxt).options & XML_PARSE_OLD10 as i32 == 0 as i32 {
        if c != ' ' as i32 && c != '>' as i32 && c != '/' as i32
            && (c >= 'a' as i32 && c <= 'z' as i32 || c >= 'A' as i32 && c <= 'Z' as i32
                || c == '_' as i32 || c == ':' as i32
                || c >= 0xc0 as i32 && c <= 0xd6 as i32
                || c >= 0xd8 as i32 && c <= 0xf6 as i32
                || c >= 0xf8 as i32 && c <= 0x2ff as i32
                || c >= 0x370 as i32 && c <= 0x37d as i32
                || c >= 0x37f as i32 && c <= 0x1fff as i32
                || c >= 0x200c as i32 && c <= 0x200d as i32
                || c >= 0x2070 as i32 && c <= 0x218f as i32
                || c >= 0x2c00 as i32 && c <= 0x2fef as i32
                || c >= 0x3001 as i32 && c <= 0xd7ff as i32
                || c >= 0xf900 as i32 && c <= 0xfdcf as i32
                || c >= 0xfdf0 as i32 && c <= 0xfffd as i32
                || c >= 0x10000 as i32 && c <= 0xeffff as i32)
        {
            return 1 as i32;
        }
    } else if (if c < 0x100 as i32 {
            (0x41 as i32 <= c && c <= 0x5a as i32
                || 0x61 as i32 <= c && c <= 0x7a as i32
                || 0xc0 as i32 <= c && c <= 0xd6 as i32
                || 0xd8 as i32 <= c && c <= 0xf6 as i32
                || 0xf8 as i32 <= c) as i32
        } else {
            xmlCharInRange(c as u32, (Some(&xmlIsBaseCharGroup)).clone())
        }) != 0
            || (if c < 0x100 as i32 {
                0 as i32
            } else {
                (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                    || c == 0x3007 as i32
                    || 0x3021 as i32 <= c && c <= 0x3029 as i32)
                    as i32
            }) != 0 || c == '_' as i32 || c == ':' as i32
        {
        return 1 as i32
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlIsNameChar(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut c: i32,
) -> i32 {
    if (*ctxt).options & XML_PARSE_OLD10 as i32 == 0 as i32 {
        if c != ' ' as i32 && c != '>' as i32 && c != '/' as i32
            && (c >= 'a' as i32 && c <= 'z' as i32 || c >= 'A' as i32 && c <= 'Z' as i32
                || c >= '0' as i32 && c <= '9' as i32 || c == '_' as i32
                || c == ':' as i32 || c == '-' as i32 || c == '.' as i32
                || c == 0xb7 as i32
                || c >= 0xc0 as i32 && c <= 0xd6 as i32
                || c >= 0xd8 as i32 && c <= 0xf6 as i32
                || c >= 0xf8 as i32 && c <= 0x2ff as i32
                || c >= 0x300 as i32 && c <= 0x36f as i32
                || c >= 0x370 as i32 && c <= 0x37d as i32
                || c >= 0x37f as i32 && c <= 0x1fff as i32
                || c >= 0x200c as i32 && c <= 0x200d as i32
                || c >= 0x203f as i32 && c <= 0x2040 as i32
                || c >= 0x2070 as i32 && c <= 0x218f as i32
                || c >= 0x2c00 as i32 && c <= 0x2fef as i32
                || c >= 0x3001 as i32 && c <= 0xd7ff as i32
                || c >= 0xf900 as i32 && c <= 0xfdcf as i32
                || c >= 0xfdf0 as i32 && c <= 0xfffd as i32
                || c >= 0x10000 as i32 && c <= 0xeffff as i32)
        {
            return 1 as i32;
        }
    } else if (if c < 0x100 as i32 {
            (0x41 as i32 <= c && c <= 0x5a as i32
                || 0x61 as i32 <= c && c <= 0x7a as i32
                || 0xc0 as i32 <= c && c <= 0xd6 as i32
                || 0xd8 as i32 <= c && c <= 0xf6 as i32
                || 0xf8 as i32 <= c) as i32
        } else {
            xmlCharInRange(c as u32, (Some(&xmlIsBaseCharGroup)).clone())
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
                xmlCharInRange(c as u32, (Some(&xmlIsDigitGroup)).clone())
            }) != 0 || c == '.' as i32 || c == '-' as i32 || c == '_' as i32
            || c == ':' as i32
            || (if c < 0x100 as i32 {
                0 as i32
            } else {
                xmlCharInRange(c as u32, (Some(&xmlIsCombiningGroup)).clone())
            }) != 0
            || (if c < 0x100 as i32 {
                (c == 0xb7 as i32) as i32
            } else {
                xmlCharInRange(c as u32, (Some(&xmlIsExtenderGroup)).clone())
            }) != 0
        {
        return 1 as i32
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlParseNameComplex(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * const u8 {
    let mut len: i32 = 0 as i32;
    let mut l: i32 = 0;
    let mut c: i32 = 0;
    let mut count: i32 = 0 as i32;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return 0 as *const xmlChar;
    }
    c = xmlCurrentChar(ctxt, Some(&mut l));
    if (*ctxt).options & XML_PARSE_OLD10 as i32 == 0 as i32 {
        if c == ' ' as i32 || c == '>' as i32 || c == '/' as i32
            || !(c >= 'a' as i32 && c <= 'z' as i32 || c >= 'A' as i32 && c <= 'Z' as i32
                || c == '_' as i32 || c == ':' as i32
                || c >= 0xc0 as i32 && c <= 0xd6 as i32
                || c >= 0xd8 as i32 && c <= 0xf6 as i32
                || c >= 0xf8 as i32 && c <= 0x2ff as i32
                || c >= 0x370 as i32 && c <= 0x37d as i32
                || c >= 0x37f as i32 && c <= 0x1fff as i32
                || c >= 0x200c as i32 && c <= 0x200d as i32
                || c >= 0x2070 as i32 && c <= 0x218f as i32
                || c >= 0x2c00 as i32 && c <= 0x2fef as i32
                || c >= 0x3001 as i32 && c <= 0xd7ff as i32
                || c >= 0xf900 as i32 && c <= 0xfdcf as i32
                || c >= 0xfdf0 as i32 && c <= 0xfffd as i32
                || c >= 0x10000 as i32 && c <= 0xeffff as i32)
        {
            return 0 as *const xmlChar;
        }
        len += l;
        if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
            let fresh117 = &mut ((*(*ctxt).input).line);
            *fresh117 += 1;
            (*(*ctxt).input).col = 1 as i32;
        } else {
            let fresh118 = &mut ((*(*ctxt).input).col);
            *fresh118 += 1;
        }
        let fresh119 = &mut ((*(*ctxt).input).cur);
        *fresh119 = (*fresh119).offset(l as isize);
        c = xmlCurrentChar(ctxt, Some(&mut l));
        while c != ' ' as i32 && c != '>' as i32 && c != '/' as i32
            && (c >= 'a' as i32 && c <= 'z' as i32 || c >= 'A' as i32 && c <= 'Z' as i32
                || c >= '0' as i32 && c <= '9' as i32 || c == '_' as i32
                || c == ':' as i32 || c == '-' as i32 || c == '.' as i32
                || c == 0xb7 as i32
                || c >= 0xc0 as i32 && c <= 0xd6 as i32
                || c >= 0xd8 as i32 && c <= 0xf6 as i32
                || c >= 0xf8 as i32 && c <= 0x2ff as i32
                || c >= 0x300 as i32 && c <= 0x36f as i32
                || c >= 0x370 as i32 && c <= 0x37d as i32
                || c >= 0x37f as i32 && c <= 0x1fff as i32
                || c >= 0x200c as i32 && c <= 0x200d as i32
                || c >= 0x203f as i32 && c <= 0x2040 as i32
                || c >= 0x2070 as i32 && c <= 0x218f as i32
                || c >= 0x2c00 as i32 && c <= 0x2fef as i32
                || c >= 0x3001 as i32 && c <= 0xd7ff as i32
                || c >= 0xf900 as i32 && c <= 0xfdcf as i32
                || c >= 0xfdf0 as i32 && c <= 0xfffd as i32
                || c >= 0x10000 as i32 && c <= 0xeffff as i32)
        {
            let mut fresh120 = count;
            count = count + 1;
            if fresh120 > 100 as i32 {
                count = 0 as i32;
                if (*ctxt).progressive == 0 as i32
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64) < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *const xmlChar;
                }
            }
            len += l;
            if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
                let fresh121 = &mut ((*(*ctxt).input).line);
                *fresh121 += 1;
                (*(*ctxt).input).col = 1 as i32;
            } else {
                let fresh122 = &mut ((*(*ctxt).input).col);
                *fresh122 += 1;
            }
            let fresh123 = &mut ((*(*ctxt).input).cur);
            *fresh123 = (*fresh123).offset(l as isize);
            c = xmlCurrentChar(ctxt, Some(&mut l));
        }
    } else {
        if c == ' ' as i32 || c == '>' as i32 || c == '/' as i32
            || !((if c < 0x100 as i32 {
                (0x41 as i32 <= c && c <= 0x5a as i32
                    || 0x61 as i32 <= c && c <= 0x7a as i32
                    || 0xc0 as i32 <= c && c <= 0xd6 as i32
                    || 0xd8 as i32 <= c && c <= 0xf6 as i32
                    || 0xf8 as i32 <= c) as i32
            } else {
                xmlCharInRange(c as u32, (Some(&xmlIsBaseCharGroup)).clone())
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
        len += l;
        if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
            let fresh124 = &mut ((*(*ctxt).input).line);
            *fresh124 += 1;
            (*(*ctxt).input).col = 1 as i32;
        } else {
            let fresh125 = &mut ((*(*ctxt).input).col);
            *fresh125 += 1;
        }
        let fresh126 = &mut ((*(*ctxt).input).cur);
        *fresh126 = (*fresh126).offset(l as isize);
        c = xmlCurrentChar(ctxt, Some(&mut l));
        while c != ' ' as i32 && c != '>' as i32 && c != '/' as i32
            && ((if c < 0x100 as i32 {
                (0x41 as i32 <= c && c <= 0x5a as i32
                    || 0x61 as i32 <= c && c <= 0x7a as i32
                    || 0xc0 as i32 <= c && c <= 0xd6 as i32
                    || 0xd8 as i32 <= c && c <= 0xf6 as i32
                    || 0xf8 as i32 <= c) as i32
            } else {
                xmlCharInRange(c as u32, (Some(&xmlIsBaseCharGroup)).clone())
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
                    xmlCharInRange(c as u32, (Some(&xmlIsDigitGroup)).clone())
                }) != 0 || c == '.' as i32 || c == '-' as i32 || c == '_' as i32
                || c == ':' as i32
                || (if c < 0x100 as i32 {
                    0 as i32
                } else {
                    xmlCharInRange(c as u32, (Some(&xmlIsCombiningGroup)).clone())
                }) != 0
                || (if c < 0x100 as i32 {
                    (c == 0xb7 as i32) as i32
                } else {
                    xmlCharInRange(c as u32, (Some(&xmlIsExtenderGroup)).clone())
                }) != 0)
        {
            let mut fresh127 = count;
            count = count + 1;
            if fresh127 > 100 as i32 {
                count = 0 as i32;
                if (*ctxt).progressive == 0 as i32
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64) < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *const xmlChar;
                }
            }
            len += l;
            if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
                let fresh128 = &mut ((*(*ctxt).input).line);
                *fresh128 += 1;
                (*(*ctxt).input).col = 1 as i32;
            } else {
                let fresh129 = &mut ((*(*ctxt).input).col);
                *fresh129 += 1;
            }
            let fresh130 = &mut ((*(*ctxt).input).cur);
            *fresh130 = (*fresh130).offset(l as isize);
            c = xmlCurrentChar(ctxt, Some(&mut l));
        }
    }
    if len > 50000 as i32
        && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_NAME_TOO_LONG,
            b"Name\0" as *const u8 as *const i8,
        );
        return 0 as *const xmlChar;
    }
    if (((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64)
        < len as i64
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"unexpected change of input buffer\0" as *const u8 as *const i8,
        );
        return 0 as *const xmlChar;
    }
    if *(*(*ctxt).input).cur as i32 == '\n' as i32
        && *((*(*ctxt).input).cur).offset(-(1 as i32) as isize) as i32
            == '\r' as i32
    {
        return xmlDictLookup(
            (*ctxt).dict,
            ((*(*ctxt).input).cur).offset(-((len + 1 as i32) as isize)),
            len,
        );
    }
    return xmlDictLookup(
        (*ctxt).dict,
        ((*(*ctxt).input).cur).offset(-(len as isize)),
        len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseName(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * const u8 {
    let mut in_0: * const u8 = 0 as *const xmlChar;
    let mut ret: * const u8 = 0 as *const xmlChar;
    let mut count: i32 = 0 as i32;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    in_0 = (*(*ctxt).input).cur;
    if *in_0 as i32 >= 0x61 as i32
        && *in_0 as i32 <= 0x7a as i32
        || *in_0 as i32 >= 0x41 as i32
            && *in_0 as i32 <= 0x5a as i32
        || *in_0 as i32 == '_' as i32 || *in_0 as i32 == ':' as i32
    {
        in_0 = in_0.offset(1);
        while *in_0 as i32 >= 0x61 as i32
            && *in_0 as i32 <= 0x7a as i32
            || *in_0 as i32 >= 0x41 as i32
                && *in_0 as i32 <= 0x5a as i32
            || *in_0 as i32 >= 0x30 as i32
                && *in_0 as i32 <= 0x39 as i32
            || *in_0 as i32 == '_' as i32 || *in_0 as i32 == '-' as i32
            || *in_0 as i32 == ':' as i32 || *in_0 as i32 == '.' as i32
        {
            in_0 = in_0.offset(1);
        }
        if *in_0 as i32 > 0 as i32
            && (*in_0 as i32) < 0x80 as i32
        {
            count = in_0.offset_from((*(*ctxt).input).cur) as i64
                as i32;
            if count > 50000 as i32
                && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
            {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_NAME_TOO_LONG,
                    b"Name\0" as *const u8 as *const i8,
                );
                return 0 as *const xmlChar;
            }
            ret = xmlDictLookup((*ctxt).dict, (*(*ctxt).input).cur, count);
            let fresh131 = &mut ((*(*ctxt).input).cur);
            *fresh131 = in_0;
            (*(*ctxt).input).col += count;
            if ret.is_null() {
                xmlErrMemory(ctxt, 0 as *const i8);
            }
            return ret;
        }
    }
    return xmlParseNameComplex(ctxt);
}
unsafe extern "C" fn xmlParseNCNameComplex(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
) -> * const u8 {
    let mut len: i32 = 0 as i32;
    let mut l: i32 = 0;
    let mut c: i32 = 0;
    let mut count: i32 = 0 as i32;
    let mut startPosition: u64 = 0 as i32 as size_t;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    startPosition = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
        as i64 as size_t;
    c = xmlCurrentChar(ctxt, Some(&mut l));
    if c == ' ' as i32 || c == '>' as i32 || c == '/' as i32
        || (xmlIsNameStartChar(ctxt, c) == 0 || c == ':' as i32)
    {
        return 0 as *const xmlChar;
    }
    while c != ' ' as i32 && c != '>' as i32 && c != '/' as i32
        && (xmlIsNameChar(ctxt, c) != 0 && c != ':' as i32)
    {
        let mut fresh132 = count;
        count = count + 1;
        if fresh132 > 100 as i32 {
            if len > 50000 as i32
                && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
            {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_NAME_TOO_LONG,
                    b"NCName\0" as *const u8 as *const i8,
                );
                return 0 as *const xmlChar;
            }
            count = 0 as i32;
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                return 0 as *const xmlChar;
            }
        }
        len += l;
        if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
            let fresh133 = &mut ((*(*ctxt).input).line);
            *fresh133 += 1;
            (*(*ctxt).input).col = 1 as i32;
        } else {
            let fresh134 = &mut ((*(*ctxt).input).col);
            *fresh134 += 1;
        }
        let fresh135 = &mut ((*(*ctxt).input).cur);
        *fresh135 = (*fresh135).offset(l as isize);
        c = xmlCurrentChar(ctxt, Some(&mut l));
        if c == 0 as i32 {
            count = 0 as i32;
            let fresh136 = &mut ((*(*ctxt).input).cur);
            *fresh136 = (*fresh136).offset(-(l as isize));
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                return 0 as *const xmlChar;
            }
            let fresh137 = &mut ((*(*ctxt).input).cur);
            *fresh137 = (*fresh137).offset(l as isize);
            c = xmlCurrentChar(ctxt, Some(&mut l));
        }
    }
    if len > 50000 as i32
        && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_NAME_TOO_LONG,
            b"NCName\0" as *const u8 as *const i8,
        );
        return 0 as *const xmlChar;
    }
    return xmlDictLookup(
        (*ctxt).dict,
        ((*(*ctxt).input).base).offset(startPosition as isize),
        len,
    );
}
unsafe extern "C" fn xmlParseNCName(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * const u8 {
    let mut in_0: * const u8 = 0 as *const xmlChar;
    let mut e: * const u8 = 0 as *const xmlChar;
    let mut ret: * const u8 = 0 as *const xmlChar;
    let mut count: i32 = 0 as i32;
    in_0 = (*(*ctxt).input).cur;
    e = (*(*ctxt).input).end;
    if (*in_0 as i32 >= 0x61 as i32
        && *in_0 as i32 <= 0x7a as i32
        || *in_0 as i32 >= 0x41 as i32
            && *in_0 as i32 <= 0x5a as i32
        || *in_0 as i32 == '_' as i32) && in_0 < e
    {
        in_0 = in_0.offset(1);
        while (*in_0 as i32 >= 0x61 as i32
            && *in_0 as i32 <= 0x7a as i32
            || *in_0 as i32 >= 0x41 as i32
                && *in_0 as i32 <= 0x5a as i32
            || *in_0 as i32 >= 0x30 as i32
                && *in_0 as i32 <= 0x39 as i32
            || *in_0 as i32 == '_' as i32 || *in_0 as i32 == '-' as i32
            || *in_0 as i32 == '.' as i32) && in_0 < e
        {
            in_0 = in_0.offset(1);
        }
        if !(in_0 >= e) {
            if *in_0 as i32 > 0 as i32
                && (*in_0 as i32) < 0x80 as i32
            {
                count = in_0.offset_from((*(*ctxt).input).cur) as i64
                    as i32;
                if count > 50000 as i32
                    && (*ctxt).options & XML_PARSE_HUGE as i32
                        == 0 as i32
                {
                    xmlFatalErr(
                        ctxt,
                        XML_ERR_NAME_TOO_LONG,
                        b"NCName\0" as *const u8 as *const i8,
                    );
                    return 0 as *const xmlChar;
                }
                ret = xmlDictLookup((*ctxt).dict, (*(*ctxt).input).cur, count);
                let fresh138 = &mut ((*(*ctxt).input).cur);
                *fresh138 = in_0;
                (*(*ctxt).input).col += count;
                if ret.is_null() {
                    xmlErrMemory(ctxt, 0 as *const i8);
                }
                return ret;
            }
        }
    }
    return xmlParseNCNameComplex(ctxt);
}
unsafe extern "C" fn xmlParseNameAndCompare(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut other: * const u8,
) -> * const u8 {
    let mut cmp: * const u8 = other;
    let mut in_0: * const u8 = 0 as *const xmlChar;
    let mut ret: * const u8 = 0 as *const xmlChar;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return 0 as *const xmlChar;
    }
    in_0 = (*(*ctxt).input).cur;
    while *in_0 as i32 != 0 as i32
        && *in_0 as i32 == *cmp as i32
    {
        in_0 = in_0.offset(1);
        cmp = cmp.offset(1);
    }
    if *cmp as i32 == 0 as i32
        && (*in_0 as i32 == '>' as i32
            || (*in_0 as i32 == 0x20 as i32
                || 0x9 as i32 <= *in_0 as i32
                    && *in_0 as i32 <= 0xa as i32
                || *in_0 as i32 == 0xd as i32))
    {
        let fresh139 = &mut ((*(*ctxt).input).col);
        *fresh139 = (*fresh139 as i64
            + in_0.offset_from((*(*ctxt).input).cur) as i64) as i32;
        let fresh140 = &mut ((*(*ctxt).input).cur);
        *fresh140 = in_0;
        return 1 as i32 as *const xmlChar;
    }
    ret = xmlParseName(ctxt);
    if ret == other {
        return 1 as i32 as *const xmlChar;
    }
    return ret;
}
unsafe extern "C" fn xmlParseStringName<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut str: Option<&'a1 mut * const u8>,
) -> * mut u8 {
    let mut buf: [u8; 105] = [0; 105];
    let mut cur: * const u8 = *(borrow(& str)).unwrap();
    let mut len: i32 = 0 as i32;
    let mut l: i32 = 0;
    let mut c: i32 = 0;
    c = xmlStringCurrentChar(ctxt, cur, Some(&mut l));
    if xmlIsNameStartChar(ctxt, c) == 0 {
        return 0 as *mut xmlChar;
    }
    if l == 1 as i32 {
        let mut fresh141 = len;
        len = len + 1;
        buf[fresh141 as usize] = c as xmlChar;
    } else {
        len += xmlCopyCharMultiByte(&mut *buf.as_mut_ptr().offset(len as isize), c);
    }
    cur = cur.offset(l as isize);
    c = xmlStringCurrentChar(ctxt, cur, Some(&mut l));
    while xmlIsNameChar(ctxt, c) != 0 {
        if l == 1 as i32 {
            let mut fresh142 = len;
            len = len + 1;
            buf[fresh142 as usize] = c as xmlChar;
        } else {
            len += xmlCopyCharMultiByte(&mut *buf.as_mut_ptr().offset(len as isize), c);
        }
        cur = cur.offset(l as isize);
        c = xmlStringCurrentChar(ctxt, cur, Some(&mut l));
        if len >= 100 as i32 {
            let mut buffer: * mut u8 = 0 as *mut xmlChar;
            let mut max: i32 = len * 2 as i32;
            buffer = xmlMallocAtomic
                .expect(
                    "non-null function pointer",
                )(
                (max as u64)
                    .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) as *mut xmlChar;
            if buffer.is_null() {
                xmlErrMemory(ctxt, 0 as *const i8);
                return 0 as *mut xmlChar;
            }
            memcpy(
                buffer as *mut libc::c_void,
                buf.as_mut_ptr() as *const libc::c_void,
                len as u64,
            );
            while xmlIsNameChar(ctxt, c) != 0 {
                if len + 10 as i32 > max {
                    let mut tmp: * mut u8 = 0 as *mut xmlChar;
                    if len > 50000 as i32
                        && (*ctxt).options & XML_PARSE_HUGE as i32
                            == 0 as i32
                    {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_NAME_TOO_LONG,
                            b"NCName\0" as *const u8 as *const i8,
                        );
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                    max *= 2 as i32;
                    tmp = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(
                        buffer as *mut libc::c_void,
                        (max as u64)
                            .wrapping_mul(
                                ::std::mem::size_of::<xmlChar>() as u64,
                            ),
                    ) as *mut xmlChar;
                    if tmp.is_null() {
                        xmlErrMemory(ctxt, 0 as *const i8);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                    buffer = tmp;
                }
                if l == 1 as i32 {
                    let mut fresh143 = len;
                    len = len + 1;
                    *buffer.offset(fresh143 as isize) = c as xmlChar;
                } else {
                    len += xmlCopyCharMultiByte(&mut *buffer.offset(len as isize), c);
                }
                cur = cur.offset(l as isize);
                c = xmlStringCurrentChar(ctxt, cur, Some(&mut l));
            }
            *buffer.offset(len as isize) = 0 as i32 as xmlChar;
            *(borrow_mut(&mut str)).unwrap() = cur;
            return buffer;
        }
    }
    if len > 50000 as i32
        && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_NAME_TOO_LONG,
            b"NCName\0" as *const u8 as *const i8,
        );
        return 0 as *mut xmlChar;
    }
    *(borrow_mut(&mut str)).unwrap() = cur;
    return xmlStrndup(buf.as_mut_ptr(), len);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseNmtoken(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * mut u8 {
    let mut buf: [u8; 105] = [0; 105];
    let mut len: i32 = 0 as i32;
    let mut l: i32 = 0;
    let mut c: i32 = 0;
    let mut count: i32 = 0 as i32;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return 0 as *mut xmlChar;
    }
    c = xmlCurrentChar(ctxt, Some(&mut l));
    while xmlIsNameChar(ctxt, c) != 0 {
        let mut fresh144 = count;
        count = count + 1;
        if fresh144 > 100 as i32 {
            count = 0 as i32;
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
        }
        if l == 1 as i32 {
            let mut fresh145 = len;
            len = len + 1;
            buf[fresh145 as usize] = c as xmlChar;
        } else {
            len += xmlCopyCharMultiByte(&mut *buf.as_mut_ptr().offset(len as isize), c);
        }
        if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
            let fresh146 = &mut ((*(*ctxt).input).line);
            *fresh146 += 1;
            (*(*ctxt).input).col = 1 as i32;
        } else {
            let fresh147 = &mut ((*(*ctxt).input).col);
            *fresh147 += 1;
        }
        let fresh148 = &mut ((*(*ctxt).input).cur);
        *fresh148 = (*fresh148).offset(l as isize);
        c = xmlCurrentChar(ctxt, Some(&mut l));
        if c == 0 as i32 {
            count = 0 as i32;
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                return 0 as *mut xmlChar;
            }
            c = xmlCurrentChar(ctxt, Some(&mut l));
        }
        if len >= 100 as i32 {
            let mut buffer: * mut u8 = 0 as *mut xmlChar;
            let mut max: i32 = len * 2 as i32;
            buffer = xmlMallocAtomic
                .expect(
                    "non-null function pointer",
                )(
                (max as u64)
                    .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) as *mut xmlChar;
            if buffer.is_null() {
                xmlErrMemory(ctxt, 0 as *const i8);
                return 0 as *mut xmlChar;
            }
            memcpy(
                buffer as *mut libc::c_void,
                buf.as_mut_ptr() as *const libc::c_void,
                len as u64,
            );
            while xmlIsNameChar(ctxt, c) != 0 {
                let mut fresh149 = count;
                count = count + 1;
                if fresh149 > 100 as i32 {
                    count = 0 as i32;
                    if (*ctxt).progressive == 0 as i32
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as i64) < 250 as i32 as i64
                    {
                        xmlGROW(ctxt);
                    }
                    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                }
                if len + 10 as i32 > max {
                    let mut tmp: * mut u8 = 0 as *mut xmlChar;
                    if max > 50000 as i32
                        && (*ctxt).options & XML_PARSE_HUGE as i32
                            == 0 as i32
                    {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_NAME_TOO_LONG,
                            b"NmToken\0" as *const u8 as *const i8,
                        );
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                    max *= 2 as i32;
                    tmp = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(
                        buffer as *mut libc::c_void,
                        (max as u64)
                            .wrapping_mul(
                                ::std::mem::size_of::<xmlChar>() as u64,
                            ),
                    ) as *mut xmlChar;
                    if tmp.is_null() {
                        xmlErrMemory(ctxt, 0 as *const i8);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                    buffer = tmp;
                }
                if l == 1 as i32 {
                    let mut fresh150 = len;
                    len = len + 1;
                    *buffer.offset(fresh150 as isize) = c as xmlChar;
                } else {
                    len += xmlCopyCharMultiByte(&mut *buffer.offset(len as isize), c);
                }
                if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
                    let fresh151 = &mut ((*(*ctxt).input).line);
                    *fresh151 += 1;
                    (*(*ctxt).input).col = 1 as i32;
                } else {
                    let fresh152 = &mut ((*(*ctxt).input).col);
                    *fresh152 += 1;
                }
                let fresh153 = &mut ((*(*ctxt).input).cur);
                *fresh153 = (*fresh153).offset(l as isize);
                c = xmlCurrentChar(ctxt, Some(&mut l));
            }
            *buffer.offset(len as isize) = 0 as i32 as xmlChar;
            return buffer;
        }
    }
    if len == 0 as i32 {
        return 0 as *mut xmlChar;
    }
    if len > 50000 as i32
        && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_NAME_TOO_LONG,
            b"NmToken\0" as *const u8 as *const i8,
        );
        return 0 as *mut xmlChar;
    }
    return xmlStrndup(buf.as_mut_ptr(), len);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEntityValue<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut orig: Option<&'a1 mut * mut u8>,
) -> * mut u8 {
    let mut current_block: u64;
    let mut buf: * mut u8 = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 100 as i32;
    let mut c: i32 = 0;
    let mut l: i32 = 0;
    let mut stop: u8 = 0;
    let mut ret: * mut u8 = 0 as *mut xmlChar;
    let mut cur: * const u8 = 0 as *const xmlChar;
    let mut input: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    if *(*(*ctxt).input).cur as i32 == '"' as i32 {
        stop = '"' as i32 as xmlChar;
    } else if *(*(*ctxt).input).cur as i32 == '\'' as i32 {
        stop = '\'' as i32 as xmlChar;
    } else {
        xmlFatalErr(ctxt, XML_ERR_ENTITY_NOT_STARTED, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    buf = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (size as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) as *mut xmlChar;
    if buf.is_null() {
        xmlErrMemory(ctxt, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    (*ctxt).instate = XML_PARSER_ENTITY_VALUE;
    input = (*ctxt).input;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if !((*ctxt).instate as i32 == XML_PARSER_EOF as i32) {
        xmlNextChar(ctxt);
        c = xmlCurrentChar(ctxt, Some(&mut l));
        loop {
            if !((if c < 0x100 as i32 {
                (0x9 as i32 <= c && c <= 0xa as i32
                    || c == 0xd as i32 || 0x20 as i32 <= c)
                    as i32
            } else {
                (0x100 as i32 <= c && c <= 0xd7ff as i32
                    || 0xe000 as i32 <= c && c <= 0xfffd as i32
                    || 0x10000 as i32 <= c && c <= 0x10ffff as i32)
                    as i32
            }) != 0 && (c != stop as i32 || (*ctxt).input != input)
                && (*ctxt).instate as i32 != XML_PARSER_EOF as i32)
            {
                current_block = 13460095289871124136;
                break;
            }
            if len + 5 as i32 >= size {
                let mut tmp: * mut u8 = 0 as *mut xmlChar;
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
                    xmlErrMemory(ctxt, 0 as *const i8);
                    current_block = 1959508989248982327;
                    break;
                } else {
                    buf = tmp;
                }
            }
            if l == 1 as i32 {
                let mut fresh154 = len;
                len = len + 1;
                *buf.offset(fresh154 as isize) = c as xmlChar;
            } else {
                len += xmlCopyCharMultiByte(&mut *buf.offset(len as isize), c);
            }
            if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
                let fresh155 = &mut ((*(*ctxt).input).line);
                *fresh155 += 1;
                (*(*ctxt).input).col = 1 as i32;
            } else {
                let fresh156 = &mut ((*(*ctxt).input).col);
                *fresh156 += 1;
            }
            let fresh157 = &mut ((*(*ctxt).input).cur);
            *fresh157 = (*fresh157).offset(l as isize);
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            c = xmlCurrentChar(ctxt, Some(&mut l));
            if c == 0 as i32 {
                if (*ctxt).progressive == 0 as i32
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64) < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                c = xmlCurrentChar(ctxt, Some(&mut l));
            }
        }
        match current_block {
            1959508989248982327 => {}
            _ => {
                *buf.offset(len as isize) = 0 as i32 as xmlChar;
                if !((*ctxt).instate as i32 == XML_PARSER_EOF as i32) {
                    if c != stop as i32 {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_ENTITY_NOT_FINISHED,
                            0 as *const i8,
                        );
                    } else {
                        xmlNextChar(ctxt);
                        cur = buf;
                        loop {
                            if !(*cur as i32 != 0 as i32) {
                                current_block = 7158658067966855297;
                                break;
                            }
                            if *cur as i32 == '%' as i32
                                || *cur as i32 == '&' as i32
                                    && *cur.offset(1 as i32 as isize) as i32
                                        != '#' as i32
                            {
                                let mut name: * mut u8 = 0 as *mut xmlChar;
                                let mut tmp_0: u8 = *cur;
                                let mut nameOk: i32 = 0 as i32;
                                cur = cur.offset(1);
                                name = xmlParseStringName(ctxt, Some(&mut cur));
                                if !name.is_null() {
                                    nameOk = 1 as i32;
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(name as *mut libc::c_void);
                                }
                                if nameOk == 0 as i32
                                    || *cur as i32 != ';' as i32
                                {
                                    xmlFatalErrMsgInt(
                                        ctxt,
                                        XML_ERR_ENTITY_CHAR_ERROR,
                                        b"EntityValue: '%c' forbidden except for entities references\n\0"
                                            as *const u8 as *const i8,
                                        tmp_0 as i32,
                                    );
                                    current_block = 1959508989248982327;
                                    break;
                                } else if tmp_0 as i32 == '%' as i32
                                        && (*ctxt).inSubset == 1 as i32
                                        && (*ctxt).inputNr == 1 as i32
                                    {
                                    xmlFatalErr(
                                        ctxt,
                                        XML_ERR_ENTITY_PE_INTERNAL,
                                        0 as *const i8,
                                    );
                                    current_block = 1959508989248982327;
                                    break;
                                } else if *cur as i32 == 0 as i32 {
                                    current_block = 7158658067966855297;
                                    break;
                                }
                            }
                            cur = cur.offset(1);
                        }
                        match current_block {
                            1959508989248982327 => {}
                            _ => {
                                let fresh158 = &mut ((*ctxt).depth);
                                *fresh158 += 1;
                                ret = xmlStringDecodeEntities(
                                    ctxt,
                                    buf,
                                    2 as i32,
                                    0 as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                );
                                let fresh159 = &mut ((*ctxt).depth);
                                *fresh159 -= 1;
                                if !borrow(& orig).is_none() {
                                    *(borrow_mut(&mut orig)).unwrap() = buf;
                                    buf = 0 as *mut xmlChar;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !buf.is_null() {
        xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    }
    return ret;
}
unsafe extern "C" fn xmlParseAttValueComplex<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut attlen: Option<&'a1 mut i32>,
    mut normalize: i32,
) -> * mut u8 {
    let mut current_block: u64;
    let mut limit: u8 = 0 as i32 as xmlChar;
    let mut buf: * mut u8 = 0 as *mut xmlChar;
    let mut rep: * mut u8 = 0 as *mut xmlChar;
    let mut len: u64 = 0 as i32 as size_t;
    let mut buf_size: u64 = 0 as i32 as size_t;
    let mut c: i32 = 0;
    let mut l: i32 = 0;
    let mut in_space: i32 = 0 as i32;
    let mut current: * mut u8 = 0 as *mut xmlChar;
    let mut ent: * mut crate::src::HTMLparser::_xmlEntity = 0 as *mut xmlEntity;
    if *((*(*ctxt).input).cur).offset(0 as i32 as isize) as i32
        == '"' as i32
    {
        (*ctxt).instate = XML_PARSER_ATTRIBUTE_VALUE;
        limit = '"' as i32 as xmlChar;
        xmlNextChar(ctxt);
    } else if *((*(*ctxt).input).cur).offset(0 as i32 as isize) as i32
            == '\'' as i32
        {
        limit = '\'' as i32 as xmlChar;
        (*ctxt).instate = XML_PARSER_ATTRIBUTE_VALUE;
        xmlNextChar(ctxt);
    } else {
        xmlFatalErr(ctxt, XML_ERR_ATTRIBUTE_NOT_STARTED, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    buf_size = 100 as i32 as size_t;
    buf = xmlMallocAtomic.expect("non-null function pointer")(buf_size) as *mut xmlChar;
    if buf.is_null() {
        current_block = 4728557498262148097;
    } else {
        c = xmlCurrentChar(ctxt, Some(&mut l));
        's_99: loop {
            if !(*((*(*ctxt).input).cur).offset(0 as i32 as isize) as i32
                != limit as i32
                && (if c < 0x100 as i32 {
                    (0x9 as i32 <= c && c <= 0xa as i32
                        || c == 0xd as i32 || 0x20 as i32 <= c)
                        as i32
                } else {
                    (0x100 as i32 <= c && c <= 0xd7ff as i32
                        || 0xe000 as i32 <= c && c <= 0xfffd as i32
                        || 0x10000 as i32 <= c && c <= 0x10ffff as i32)
                        as i32
                }) != 0 && c != '<' as i32
                && (*ctxt).instate as i32 != XML_PARSER_EOF as i32)
            {
                current_block = 3166194604430448652;
                break;
            }
            if len > 10000000 as i32 as u64
                && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
            {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ATTRIBUTE_NOT_FINISHED,
                    b"AttValue length too long\n\0" as *const u8 as *const i8,
                );
                current_block = 4728557498262148097;
                break;
            } else {
                if c == '&' as i32 {
                    in_space = 0 as i32;
                    if *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                        as i32 == '#' as i32
                    {
                        let mut val: i32 = xmlParseCharRef(ctxt);
                        if val == '&' as i32 {
                            if (*ctxt).replaceEntities != 0 {
                                if len.wrapping_add(10 as i32 as u64)
                                    > buf_size
                                {
                                    let mut tmp: * mut u8 = 0 as *mut xmlChar;
                                    let mut new_size: u64 = buf_size
                                        .wrapping_mul(2 as i32 as u64)
                                        .wrapping_add(10 as i32 as u64);
                                    if new_size < buf_size {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    tmp = xmlRealloc
                                        .expect(
                                            "non-null function pointer",
                                        )(buf as *mut libc::c_void, new_size) as *mut xmlChar;
                                    if tmp.is_null() {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    buf = tmp;
                                    buf_size = new_size;
                                }
                                let mut fresh160 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh160 as isize) = '&' as i32 as xmlChar;
                            } else {
                                if len.wrapping_add(10 as i32 as u64)
                                    > buf_size
                                {
                                    let mut tmp_0: * mut u8 = 0 as *mut xmlChar;
                                    let mut new_size_0: u64 = buf_size
                                        .wrapping_mul(2 as i32 as u64)
                                        .wrapping_add(10 as i32 as u64);
                                    if new_size_0 < buf_size {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    tmp_0 = xmlRealloc
                                        .expect(
                                            "non-null function pointer",
                                        )(buf as *mut libc::c_void, new_size_0) as *mut xmlChar;
                                    if tmp_0.is_null() {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    buf = tmp_0;
                                    buf_size = new_size_0;
                                }
                                let mut fresh161 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh161 as isize) = '&' as i32 as xmlChar;
                                let mut fresh162 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh162 as isize) = '#' as i32 as xmlChar;
                                let mut fresh163 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh163 as isize) = '3' as i32 as xmlChar;
                                let mut fresh164 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh164 as isize) = '8' as i32 as xmlChar;
                                let mut fresh165 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh165 as isize) = ';' as i32 as xmlChar;
                            }
                        } else if val != 0 as i32 {
                            if len.wrapping_add(10 as i32 as u64)
                                > buf_size
                            {
                                let mut tmp_1: * mut u8 = 0 as *mut xmlChar;
                                let mut new_size_1: u64 = buf_size
                                    .wrapping_mul(2 as i32 as u64)
                                    .wrapping_add(10 as i32 as u64);
                                if new_size_1 < buf_size {
                                    current_block = 4728557498262148097;
                                    break;
                                }
                                tmp_1 = xmlRealloc
                                    .expect(
                                        "non-null function pointer",
                                    )(buf as *mut libc::c_void, new_size_1) as *mut xmlChar;
                                if tmp_1.is_null() {
                                    current_block = 4728557498262148097;
                                    break;
                                }
                                buf = tmp_1;
                                buf_size = new_size_1;
                            }
                            len = (len as u64)
                                .wrapping_add(
                                    xmlCopyChar(
                                        0 as i32,
                                        &mut *buf.offset(len as isize),
                                        val,
                                    ) as u64,
                                ) as size_t as size_t;
                        }
                    } else {
                        ent = xmlParseEntityRef(ctxt);
                        let fresh166 = &mut ((*ctxt).nbentities);
                        *fresh166 = (*fresh166).wrapping_add(1);
                        if !ent.is_null() {
                            let fresh167 = &mut ((*ctxt).nbentities);
                            *fresh167 = (*fresh167)
                                .wrapping_add((*ent).owner as u64);
                        }
                        if !ent.is_null()
                            && (*ent).etype as u32
                                == XML_INTERNAL_PREDEFINED_ENTITY as i32
                                    as u32
                        {
                            if len.wrapping_add(10 as i32 as u64)
                                > buf_size
                            {
                                let mut tmp_2: * mut u8 = 0 as *mut xmlChar;
                                let mut new_size_2: u64 = buf_size
                                    .wrapping_mul(2 as i32 as u64)
                                    .wrapping_add(10 as i32 as u64);
                                if new_size_2 < buf_size {
                                    current_block = 4728557498262148097;
                                    break;
                                }
                                tmp_2 = xmlRealloc
                                    .expect(
                                        "non-null function pointer",
                                    )(buf as *mut libc::c_void, new_size_2) as *mut xmlChar;
                                if tmp_2.is_null() {
                                    current_block = 4728557498262148097;
                                    break;
                                }
                                buf = tmp_2;
                                buf_size = new_size_2;
                            }
                            if (*ctxt).replaceEntities == 0 as i32
                                && *((*ent).content).offset(0 as i32 as isize)
                                    as i32 == '&' as i32
                            {
                                let mut fresh168 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh168 as isize) = '&' as i32 as xmlChar;
                                let mut fresh169 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh169 as isize) = '#' as i32 as xmlChar;
                                let mut fresh170 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh170 as isize) = '3' as i32 as xmlChar;
                                let mut fresh171 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh171 as isize) = '8' as i32 as xmlChar;
                                let mut fresh172 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh172 as isize) = ';' as i32 as xmlChar;
                            } else {
                                let mut fresh173 = len;
                                len = len.wrapping_add(1);
                                *buf
                                    .offset(
                                        fresh173 as isize,
                                    ) = *((*ent).content).offset(0 as i32 as isize);
                            }
                        } else if !ent.is_null()
                                && (*ctxt).replaceEntities != 0 as i32
                            {
                            if (*ent).etype as u32
                                != XML_INTERNAL_PREDEFINED_ENTITY as i32
                                    as u32
                            {
                                let fresh174 = &mut ((*ctxt).depth);
                                *fresh174 += 1;
                                rep = xmlStringDecodeEntities(
                                    ctxt,
                                    (*ent).content,
                                    1 as i32,
                                    0 as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                );
                                let fresh175 = &mut ((*ctxt).depth);
                                *fresh175 -= 1;
                                if !rep.is_null() {
                                    current = rep;
                                    while *current as i32 != 0 as i32 {
                                        if *current as i32 == 0xd as i32
                                            || *current as i32 == 0xa as i32
                                            || *current as i32 == 0x9 as i32
                                        {
                                            let mut fresh176 = len;
                                            len = len.wrapping_add(1);
                                            *buf
                                                .offset(fresh176 as isize) = 0x20 as i32 as xmlChar;
                                            current = current.offset(1);
                                        } else {
                                            let mut fresh177 = current;
                                            current = current.offset(1);
                                            let mut fresh178 = len;
                                            len = len.wrapping_add(1);
                                            *buf.offset(fresh178 as isize) = *fresh177;
                                        }
                                        if !(len.wrapping_add(10 as i32 as u64)
                                            > buf_size)
                                        {
                                            continue;
                                        }
                                        let mut tmp_3: * mut u8 = 0 as *mut xmlChar;
                                        let mut new_size_3: u64 = buf_size
                                            .wrapping_mul(2 as i32 as u64)
                                            .wrapping_add(10 as i32 as u64);
                                        if new_size_3 < buf_size {
                                            current_block = 4728557498262148097;
                                            break 's_99;
                                        }
                                        tmp_3 = xmlRealloc
                                            .expect(
                                                "non-null function pointer",
                                            )(buf as *mut libc::c_void, new_size_3) as *mut xmlChar;
                                        if tmp_3.is_null() {
                                            current_block = 4728557498262148097;
                                            break 's_99;
                                        }
                                        buf = tmp_3;
                                        buf_size = new_size_3;
                                    }
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(rep as *mut libc::c_void);
                                    rep = 0 as *mut xmlChar;
                                }
                            } else {
                                if len.wrapping_add(10 as i32 as u64)
                                    > buf_size
                                {
                                    let mut tmp_4: * mut u8 = 0 as *mut xmlChar;
                                    let mut new_size_4: u64 = buf_size
                                        .wrapping_mul(2 as i32 as u64)
                                        .wrapping_add(10 as i32 as u64);
                                    if new_size_4 < buf_size {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    tmp_4 = xmlRealloc
                                        .expect(
                                            "non-null function pointer",
                                        )(buf as *mut libc::c_void, new_size_4) as *mut xmlChar;
                                    if tmp_4.is_null() {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    buf = tmp_4;
                                    buf_size = new_size_4;
                                }
                                if !((*ent).content).is_null() {
                                    let mut fresh179 = len;
                                    len = len.wrapping_add(1);
                                    *buf
                                        .offset(
                                            fresh179 as isize,
                                        ) = *((*ent).content).offset(0 as i32 as isize);
                                }
                            }
                        } else if !ent.is_null() {
                            let mut i: i32 = xmlStrlen((*ent).name);
                            let mut cur: * const u8 = (*ent).name;
                            if (*ent).etype as u32
                                != XML_INTERNAL_PREDEFINED_ENTITY as i32
                                    as u32 && !((*ent).content).is_null()
                                && (*ent).checked == 0 as i32
                            {
                                let mut oldnbent: u64 = (*ctxt).nbentities;
                                let mut diff: u64 = 0;
                                let fresh180 = &mut ((*ctxt).depth);
                                *fresh180 += 1;
                                rep = xmlStringDecodeEntities(
                                    ctxt,
                                    (*ent).content,
                                    1 as i32,
                                    0 as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                );
                                let fresh181 = &mut ((*ctxt).depth);
                                *fresh181 -= 1;
                                diff = ((*ctxt).nbentities)
                                    .wrapping_sub(oldnbent)
                                    .wrapping_add(1 as i32 as u64);
                                if diff
                                    > (2147483647 as i32 / 2 as i32)
                                        as u64
                                {
                                    diff = (2147483647 as i32 / 2 as i32)
                                        as u64;
                                }
                                (*ent)
                                    .checked = diff
                                    .wrapping_mul(2 as i32 as u64)
                                    as i32;
                                if !rep.is_null() {
                                    if !(xmlStrchr(rep, '<' as i32 as xmlChar)).is_null() {
                                        (*ent).checked |= 1 as i32;
                                    }
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(rep as *mut libc::c_void);
                                    rep = 0 as *mut xmlChar;
                                } else {
                                    *((*ent).content)
                                        .offset(
                                            0 as i32 as isize,
                                        ) = 0 as i32 as xmlChar;
                                }
                            }
                            let mut fresh182 = len;
                            len = len.wrapping_add(1);
                            *buf.offset(fresh182 as isize) = '&' as i32 as xmlChar;
                            while len
                                .wrapping_add(i as u64)
                                .wrapping_add(10 as i32 as u64) > buf_size
                            {
                                let mut tmp_5: * mut u8 = 0 as *mut xmlChar;
                                let mut new_size_5: u64 = buf_size
                                    .wrapping_mul(2 as i32 as u64)
                                    .wrapping_add(i as u64)
                                    .wrapping_add(10 as i32 as u64);
                                if new_size_5 < buf_size {
                                    current_block = 4728557498262148097;
                                    break 's_99;
                                }
                                tmp_5 = xmlRealloc
                                    .expect(
                                        "non-null function pointer",
                                    )(buf as *mut libc::c_void, new_size_5) as *mut xmlChar;
                                if tmp_5.is_null() {
                                    current_block = 4728557498262148097;
                                    break 's_99;
                                }
                                buf = tmp_5;
                                buf_size = new_size_5;
                            }
                            while i > 0 as i32 {
                                let mut fresh183 = cur;
                                cur = cur.offset(1);
                                let mut fresh184 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh184 as isize) = *fresh183;
                                i -= 1;
                            }
                            let mut fresh185 = len;
                            len = len.wrapping_add(1);
                            *buf.offset(fresh185 as isize) = ';' as i32 as xmlChar;
                        }
                    }
                } else {
                    if c == 0x20 as i32 || c == 0xd as i32
                        || c == 0xa as i32 || c == 0x9 as i32
                    {
                        if len != 0 as i32 as u64 || normalize == 0 {
                            if normalize == 0 || in_space == 0 {
                                if l == 1 as i32 {
                                    let mut fresh186 = len;
                                    len = len.wrapping_add(1);
                                    *buf
                                        .offset(fresh186 as isize) = 0x20 as i32 as xmlChar;
                                } else {
                                    len = (len as u64)
                                        .wrapping_add(
                                            xmlCopyCharMultiByte(
                                                &mut *buf.offset(len as isize),
                                                0x20 as i32,
                                            ) as u64,
                                        ) as size_t as size_t;
                                }
                                while len.wrapping_add(10 as i32 as u64)
                                    > buf_size
                                {
                                    let mut tmp_6: * mut u8 = 0 as *mut xmlChar;
                                    let mut new_size_6: u64 = buf_size
                                        .wrapping_mul(2 as i32 as u64)
                                        .wrapping_add(10 as i32 as u64);
                                    if new_size_6 < buf_size {
                                        current_block = 4728557498262148097;
                                        break 's_99;
                                    }
                                    tmp_6 = xmlRealloc
                                        .expect(
                                            "non-null function pointer",
                                        )(buf as *mut libc::c_void, new_size_6) as *mut xmlChar;
                                    if tmp_6.is_null() {
                                        current_block = 4728557498262148097;
                                        break 's_99;
                                    }
                                    buf = tmp_6;
                                    buf_size = new_size_6;
                                }
                            }
                            in_space = 1 as i32;
                        }
                    } else {
                        in_space = 0 as i32;
                        if l == 1 as i32 {
                            let mut fresh187 = len;
                            len = len.wrapping_add(1);
                            *buf.offset(fresh187 as isize) = c as xmlChar;
                        } else {
                            len = (len as u64)
                                .wrapping_add(
                                    xmlCopyCharMultiByte(&mut *buf.offset(len as isize), c)
                                        as u64,
                                ) as size_t as size_t;
                        }
                        if len.wrapping_add(10 as i32 as u64)
                            > buf_size
                        {
                            let mut tmp_7: * mut u8 = 0 as *mut xmlChar;
                            let mut new_size_7: u64 = buf_size
                                .wrapping_mul(2 as i32 as u64)
                                .wrapping_add(10 as i32 as u64);
                            if new_size_7 < buf_size {
                                current_block = 4728557498262148097;
                                break;
                            }
                            tmp_7 = xmlRealloc
                                .expect(
                                    "non-null function pointer",
                                )(buf as *mut libc::c_void, new_size_7) as *mut xmlChar;
                            if tmp_7.is_null() {
                                current_block = 4728557498262148097;
                                break;
                            }
                            buf = tmp_7;
                            buf_size = new_size_7;
                        }
                    }
                    if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
                        let fresh188 = &mut ((*(*ctxt).input).line);
                        *fresh188 += 1;
                        (*(*ctxt).input).col = 1 as i32;
                    } else {
                        let fresh189 = &mut ((*(*ctxt).input).col);
                        *fresh189 += 1;
                    }
                    let fresh190 = &mut ((*(*ctxt).input).cur);
                    *fresh190 = (*fresh190).offset(l as isize);
                }
                if (*ctxt).progressive == 0 as i32
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64) < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                c = xmlCurrentChar(ctxt, Some(&mut l));
            }
        }
        match current_block {
            4728557498262148097 => {}
            _ => {
                if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                    current_block = 7833996145497313433;
                } else {
                    if in_space != 0 && normalize != 0 {
                        while len > 0 as i32 as u64
                            && *buf
                                .offset(
                                    len.wrapping_sub(1 as i32 as u64) as isize,
                                ) as i32 == 0x20 as i32
                        {
                            len = len.wrapping_sub(1);
                        }
                    }
                    *buf.offset(len as isize) = 0 as i32 as xmlChar;
                    if *(*(*ctxt).input).cur as i32 == '<' as i32 {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_LT_IN_ATTRIBUTE,
                            0 as *const i8,
                        );
                    } else if *(*(*ctxt).input).cur as i32
                            != limit as i32
                        {
                        if c != 0 as i32
                            && (if c < 0x100 as i32 {
                                (0x9 as i32 <= c && c <= 0xa as i32
                                    || c == 0xd as i32 || 0x20 as i32 <= c)
                                    as i32
                            } else {
                                (0x100 as i32 <= c && c <= 0xd7ff as i32
                                    || 0xe000 as i32 <= c && c <= 0xfffd as i32
                                    || 0x10000 as i32 <= c
                                        && c <= 0x10ffff as i32) as i32
                            }) == 0
                        {
                            xmlFatalErrMsg(
                                ctxt,
                                XML_ERR_INVALID_CHAR,
                                b"invalid character in attribute value\n\0" as *const u8
                                    as *const i8,
                            );
                        } else {
                            xmlFatalErrMsg(
                                ctxt,
                                XML_ERR_ATTRIBUTE_NOT_FINISHED,
                                b"AttValue: ' expected\n\0" as *const u8
                                    as *const i8,
                            );
                        }
                    } else {
                        xmlNextChar(ctxt);
                    }
                    if len >= 2147483647 as i32 as u64 {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_ATTRIBUTE_NOT_FINISHED,
                            b"AttValue length too long\n\0" as *const u8
                                as *const i8,
                        );
                    } else {
                        if !borrow(& attlen).is_none() {
                            *(borrow_mut(&mut attlen)).unwrap() = len as i32;
                        }
                        return buf;
                    }
                    current_block = 4728557498262148097;
                }
            }
        }
    }
    match current_block {
        4728557498262148097 => {
            xmlErrMemory(ctxt, 0 as *const i8);
        }
        _ => {}
    }
    if !buf.is_null() {
        xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    }
    if !rep.is_null() {
        xmlFree.expect("non-null function pointer")(rep as *mut libc::c_void);
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseAttValue(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * mut u8 {
    if ctxt.is_null() || ((*ctxt).input).is_null() {
        return 0 as *mut xmlChar;
    }
    return xmlParseAttValueInternal(
        ctxt,
        Option::<&'_ mut i32>::None,
        Option::<&'_ mut i32>::None,
        0 as i32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseSystemLiteral(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
) -> * mut u8 {
    let mut buf: * mut u8 = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 100 as i32;
    let mut cur: i32 = 0;
    let mut l: i32 = 0;
    let mut stop: u8 = 0;
    let mut state: i32 = (*ctxt).instate as i32;
    let mut count: i32 = 0 as i32;
    if (*ctxt).progressive == 0 as i32
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
            > (2 as i32 * 250 as i32) as i64
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    if *(*(*ctxt).input).cur as i32 == '"' as i32 {
        xmlNextChar(ctxt);
        stop = '"' as i32 as xmlChar;
    } else if *(*(*ctxt).input).cur as i32 == '\'' as i32 {
        xmlNextChar(ctxt);
        stop = '\'' as i32 as xmlChar;
    } else {
        xmlFatalErr(ctxt, XML_ERR_LITERAL_NOT_STARTED, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    buf = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (size as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) as *mut xmlChar;
    if buf.is_null() {
        xmlErrMemory(ctxt, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    (*ctxt).instate = XML_PARSER_SYSTEM_LITERAL;
    cur = xmlCurrentChar(ctxt, Some(&mut l));
    while (if cur < 0x100 as i32 {
        (0x9 as i32 <= cur && cur <= 0xa as i32
            || cur == 0xd as i32 || 0x20 as i32 <= cur) as i32
    } else {
        (0x100 as i32 <= cur && cur <= 0xd7ff as i32
            || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
            || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32)
            as i32
    }) != 0 && cur != stop as i32
    {
        if len + 5 as i32 >= size {
            let mut tmp: * mut u8 = 0 as *mut xmlChar;
            if size > 50000 as i32
                && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
            {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_NAME_TOO_LONG,
                    b"SystemLiteral\0" as *const u8 as *const i8,
                );
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                (*ctxt).instate = state as xmlParserInputState;
                return 0 as *mut xmlChar;
            }
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
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                xmlErrMemory(ctxt, 0 as *const i8);
                (*ctxt).instate = state as xmlParserInputState;
                return 0 as *mut xmlChar;
            }
            buf = tmp;
        }
        count += 1;
        if count > 50 as i32 {
            if (*ctxt).progressive == 0 as i32
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as i64
                    > (2 as i32 * 250 as i32) as i64
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            count = 0 as i32;
            if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return 0 as *mut xmlChar;
            }
        }
        if l == 1 as i32 {
            let mut fresh191 = len;
            len = len + 1;
            *buf.offset(fresh191 as isize) = cur as xmlChar;
        } else {
            len += xmlCopyCharMultiByte(&mut *buf.offset(len as isize), cur);
        }
        if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
            let fresh192 = &mut ((*(*ctxt).input).line);
            *fresh192 += 1;
            (*(*ctxt).input).col = 1 as i32;
        } else {
            let fresh193 = &mut ((*(*ctxt).input).col);
            *fresh193 += 1;
        }
        let fresh194 = &mut ((*(*ctxt).input).cur);
        *fresh194 = (*fresh194).offset(l as isize);
        cur = xmlCurrentChar(ctxt, Some(&mut l));
        if cur == 0 as i32 {
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).progressive == 0 as i32
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as i64
                    > (2 as i32 * 250 as i32) as i64
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            cur = xmlCurrentChar(ctxt, Some(&mut l));
        }
    }
    *buf.offset(len as isize) = 0 as i32 as xmlChar;
    (*ctxt).instate = state as xmlParserInputState;
    if if cur < 0x100 as i32 {
        (0x9 as i32 <= cur && cur <= 0xa as i32
            || cur == 0xd as i32 || 0x20 as i32 <= cur) as i32
    } else {
        (0x100 as i32 <= cur && cur <= 0xd7ff as i32
            || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
            || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32)
            as i32
    } == 0
    {
        xmlFatalErr(ctxt, XML_ERR_LITERAL_NOT_FINISHED, 0 as *const i8);
    } else {
        xmlNextChar(ctxt);
    }
    return buf;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParsePubidLiteral(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
) -> * mut u8 {
    let mut buf: * mut u8 = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 100 as i32;
    let mut cur: u8 = 0;
    let mut stop: u8 = 0;
    let mut count: i32 = 0 as i32;
    let mut oldstate: i32 = (*ctxt).instate;
    if (*ctxt).progressive == 0 as i32
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
            > (2 as i32 * 250 as i32) as i64
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    if *(*(*ctxt).input).cur as i32 == '"' as i32 {
        xmlNextChar(ctxt);
        stop = '"' as i32 as xmlChar;
    } else if *(*(*ctxt).input).cur as i32 == '\'' as i32 {
        xmlNextChar(ctxt);
        stop = '\'' as i32 as xmlChar;
    } else {
        xmlFatalErr(ctxt, XML_ERR_LITERAL_NOT_STARTED, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    buf = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (size as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) as *mut xmlChar;
    if buf.is_null() {
        xmlErrMemory(ctxt, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    (*ctxt).instate = XML_PARSER_PUBLIC_LITERAL;
    cur = *(*(*ctxt).input).cur;
    while xmlIsPubidChar_tab[cur as usize] as i32 != 0
        && cur as i32 != stop as i32
    {
        if len + 1 as i32 >= size {
            let mut tmp: * mut u8 = 0 as *mut xmlChar;
            if size > 50000 as i32
                && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
            {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_NAME_TOO_LONG,
                    b"Public ID\0" as *const u8 as *const i8,
                );
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return 0 as *mut xmlChar;
            }
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
                xmlErrMemory(ctxt, 0 as *const i8);
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return 0 as *mut xmlChar;
            }
            buf = tmp;
        }
        let mut fresh195 = len;
        len = len + 1;
        *buf.offset(fresh195 as isize) = cur;
        count += 1;
        if count > 50 as i32 {
            if (*ctxt).progressive == 0 as i32
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as i64
                    > (2 as i32 * 250 as i32) as i64
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            count = 0 as i32;
            if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return 0 as *mut xmlChar;
            }
        }
        xmlNextChar(ctxt);
        cur = *(*(*ctxt).input).cur;
        if cur as i32 == 0 as i32 {
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).progressive == 0 as i32
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as i64
                    > (2 as i32 * 250 as i32) as i64
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            cur = *(*(*ctxt).input).cur;
        }
    }
    *buf.offset(len as isize) = 0 as i32 as xmlChar;
    if cur as i32 != stop as i32 {
        xmlFatalErr(ctxt, XML_ERR_LITERAL_NOT_FINISHED, 0 as *const i8);
    } else {
        xmlNextChar(ctxt);
    }
    (*ctxt).instate = oldstate;
    return buf;
}
static mut test_char_data: [u8; 256] = [
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0x9 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0x20 as i32 as u8,
    0x21 as i32 as u8,
    0x22 as i32 as u8,
    0x23 as i32 as u8,
    0x24 as i32 as u8,
    0x25 as i32 as u8,
    0 as i32 as u8,
    0x27 as i32 as u8,
    0x28 as i32 as u8,
    0x29 as i32 as u8,
    0x2a as i32 as u8,
    0x2b as i32 as u8,
    0x2c as i32 as u8,
    0x2d as i32 as u8,
    0x2e as i32 as u8,
    0x2f as i32 as u8,
    0x30 as i32 as u8,
    0x31 as i32 as u8,
    0x32 as i32 as u8,
    0x33 as i32 as u8,
    0x34 as i32 as u8,
    0x35 as i32 as u8,
    0x36 as i32 as u8,
    0x37 as i32 as u8,
    0x38 as i32 as u8,
    0x39 as i32 as u8,
    0x3a as i32 as u8,
    0x3b as i32 as u8,
    0 as i32 as u8,
    0x3d as i32 as u8,
    0x3e as i32 as u8,
    0x3f as i32 as u8,
    0x40 as i32 as u8,
    0x41 as i32 as u8,
    0x42 as i32 as u8,
    0x43 as i32 as u8,
    0x44 as i32 as u8,
    0x45 as i32 as u8,
    0x46 as i32 as u8,
    0x47 as i32 as u8,
    0x48 as i32 as u8,
    0x49 as i32 as u8,
    0x4a as i32 as u8,
    0x4b as i32 as u8,
    0x4c as i32 as u8,
    0x4d as i32 as u8,
    0x4e as i32 as u8,
    0x4f as i32 as u8,
    0x50 as i32 as u8,
    0x51 as i32 as u8,
    0x52 as i32 as u8,
    0x53 as i32 as u8,
    0x54 as i32 as u8,
    0x55 as i32 as u8,
    0x56 as i32 as u8,
    0x57 as i32 as u8,
    0x58 as i32 as u8,
    0x59 as i32 as u8,
    0x5a as i32 as u8,
    0x5b as i32 as u8,
    0x5c as i32 as u8,
    0 as i32 as u8,
    0x5e as i32 as u8,
    0x5f as i32 as u8,
    0x60 as i32 as u8,
    0x61 as i32 as u8,
    0x62 as i32 as u8,
    0x63 as i32 as u8,
    0x64 as i32 as u8,
    0x65 as i32 as u8,
    0x66 as i32 as u8,
    0x67 as i32 as u8,
    0x68 as i32 as u8,
    0x69 as i32 as u8,
    0x6a as i32 as u8,
    0x6b as i32 as u8,
    0x6c as i32 as u8,
    0x6d as i32 as u8,
    0x6e as i32 as u8,
    0x6f as i32 as u8,
    0x70 as i32 as u8,
    0x71 as i32 as u8,
    0x72 as i32 as u8,
    0x73 as i32 as u8,
    0x74 as i32 as u8,
    0x75 as i32 as u8,
    0x76 as i32 as u8,
    0x77 as i32 as u8,
    0x78 as i32 as u8,
    0x79 as i32 as u8,
    0x7a as i32 as u8,
    0x7b as i32 as u8,
    0x7c as i32 as u8,
    0x7d as i32 as u8,
    0x7e as i32 as u8,
    0x7f as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
];
#[no_mangle]
pub unsafe extern "C" fn xmlParseCharData(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut cdata: i32,
) {
    let mut current_block: u64;
    let mut in_0: * const u8 = 0 as *const xmlChar;
    let mut nbchar: i32 = 0 as i32;
    let mut line: i32 = (*(*ctxt).input).line;
    let mut col: i32 = (*(*ctxt).input).col;
    let mut ccol: i32 = 0;
    if (*ctxt).progressive == 0 as i32
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
            > (2 as i32 * 250 as i32) as i64
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if cdata == 0 {
        in_0 = (*(*ctxt).input).cur;
        loop {
            while *in_0 as i32 == 0x20 as i32 {
                in_0 = in_0.offset(1);
                let fresh196 = &mut ((*(*ctxt).input).col);
                *fresh196 += 1;
            }
            if *in_0 as i32 == 0xa as i32 {
                loop {
                    let fresh197 = &mut ((*(*ctxt).input).line);
                    *fresh197 += 1;
                    (*(*ctxt).input).col = 1 as i32;
                    in_0 = in_0.offset(1);
                    if !(*in_0 as i32 == 0xa as i32) {
                        break;
                    }
                }
            } else {
                if *in_0 as i32 == '<' as i32 {
                    nbchar = in_0.offset_from((*(*ctxt).input).cur) as i64
                        as i32;
                    if nbchar > 0 as i32 {
                        let mut tmp: * const u8 = (*(*ctxt).input).cur;
                        let fresh198 = &mut ((*(*ctxt).input).cur);
                        *fresh198 = in_0;
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).ignorableWhitespace
                                ).map(|f| f as usize) == ( (*(*ctxt).sax).characters).map(|f| f as usize)
                        {
                            if areBlanks(ctxt, tmp, nbchar, 1 as i32) != 0 {
                                if ((*(*ctxt).sax).ignorableWhitespace).is_some() {
                                    ((*(*ctxt).sax).ignorableWhitespace)
                                        .expect(
                                            "non-null function pointer",
                                        )((*ctxt).userData, tmp, nbchar);
                                }
                            } else {
                                if ((*(*ctxt).sax).characters).is_some() {
                                    ((*(*ctxt).sax).characters)
                                        .expect(
                                            "non-null function pointer",
                                        )((*ctxt).userData, tmp, nbchar);
                                }
                                if *(*ctxt).space == -(1 as i32) {
                                    *(*ctxt).space = -(2 as i32);
                                }
                            }
                        } else if !((*ctxt).sax).is_null()
                                && ((*(*ctxt).sax).characters).is_some()
                            {
                            ((*(*ctxt).sax).characters)
                                .expect(
                                    "non-null function pointer",
                                )((*ctxt).userData, tmp, nbchar);
                        }
                    }
                    return;
                }
                loop {
                    ccol = (*(*ctxt).input).col;
                    while test_char_data[*in_0 as usize] != 0 {
                        in_0 = in_0.offset(1);
                        ccol += 1;
                    }
                    (*(*ctxt).input).col = ccol;
                    if *in_0 as i32 == 0xa as i32 {
                        loop {
                            let fresh199 = &mut ((*(*ctxt).input).line);
                            *fresh199 += 1;
                            (*(*ctxt).input).col = 1 as i32;
                            in_0 = in_0.offset(1);
                            if !(*in_0 as i32 == 0xa as i32) {
                                break;
                            }
                        }
                    } else {
                        if !(*in_0 as i32 == ']' as i32) {
                            break;
                        }
                        if *in_0.offset(1 as i32 as isize) as i32
                            == ']' as i32
                            && *in_0.offset(2 as i32 as isize) as i32
                                == '>' as i32
                        {
                            xmlFatalErr(
                                ctxt,
                                XML_ERR_MISPLACED_CDATA_END,
                                0 as *const i8,
                            );
                            let fresh200 = &mut ((*(*ctxt).input).cur);
                            *fresh200 = in_0.offset(1 as i32 as isize);
                            return;
                        }
                        in_0 = in_0.offset(1);
                        let fresh201 = &mut ((*(*ctxt).input).col);
                        *fresh201 += 1;
                    }
                }
                nbchar = in_0.offset_from((*(*ctxt).input).cur) as i64
                    as i32;
                if nbchar > 0 as i32 {
                    if !((*ctxt).sax).is_null()
                        && ((*(*ctxt).sax).ignorableWhitespace
                            ).map(|f| f as usize) == ( (*(*ctxt).sax).characters).map(|f| f as usize)
                        && (*(*(*ctxt).input).cur as i32 == 0x20 as i32
                            || 0x9 as i32 <= *(*(*ctxt).input).cur as i32
                                && *(*(*ctxt).input).cur as i32
                                    <= 0xa as i32
                            || *(*(*ctxt).input).cur as i32
                                == 0xd as i32)
                    {
                        let mut tmp_0: * const u8 = (*(*ctxt).input).cur;
                        let fresh202 = &mut ((*(*ctxt).input).cur);
                        *fresh202 = in_0;
                        if areBlanks(ctxt, tmp_0, nbchar, 0 as i32) != 0 {
                            if ((*(*ctxt).sax).ignorableWhitespace).is_some() {
                                ((*(*ctxt).sax).ignorableWhitespace)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, tmp_0, nbchar);
                            }
                        } else {
                            if ((*(*ctxt).sax).characters).is_some() {
                                ((*(*ctxt).sax).characters)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, tmp_0, nbchar);
                            }
                            if *(*ctxt).space == -(1 as i32) {
                                *(*ctxt).space = -(2 as i32);
                            }
                        }
                        line = (*(*ctxt).input).line;
                        col = (*(*ctxt).input).col;
                    } else if !((*ctxt).sax).is_null() {
                        if ((*(*ctxt).sax).characters).is_some() {
                            ((*(*ctxt).sax).characters)
                                .expect(
                                    "non-null function pointer",
                                )((*ctxt).userData, (*(*ctxt).input).cur, nbchar);
                        }
                        line = (*(*ctxt).input).line;
                        col = (*(*ctxt).input).col;
                    }
                    if (*ctxt).instate as i32
                        != XML_PARSER_CONTENT as i32
                    {
                        return;
                    }
                }
                let fresh203 = &mut ((*(*ctxt).input).cur);
                *fresh203 = in_0;
                if *in_0 as i32 == 0xd as i32 {
                    in_0 = in_0.offset(1);
                    if *in_0 as i32 == 0xa as i32 {
                        let fresh204 = &mut ((*(*ctxt).input).cur);
                        *fresh204 = in_0;
                        in_0 = in_0.offset(1);
                        let fresh205 = &mut ((*(*ctxt).input).line);
                        *fresh205 += 1;
                        (*(*ctxt).input).col = 1 as i32;
                        current_block = 1917311967535052937;
                    } else {
                        in_0 = in_0.offset(-1);
                        current_block = 17769492591016358583;
                    }
                } else {
                    current_block = 17769492591016358583;
                }
                match current_block {
                    17769492591016358583 => {
                        if *in_0 as i32 == '<' as i32 {
                            return;
                        }
                        if *in_0 as i32 == '&' as i32 {
                            return;
                        }
                        if (*ctxt).progressive == 0 as i32
                            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as i64
                                > (2 as i32 * 250 as i32) as i64
                            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                as i64)
                                < (2 as i32 * 250 as i32) as i64
                        {
                            xmlSHRINK(ctxt);
                        }
                        if (*ctxt).progressive == 0 as i32
                            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                as i64) < 250 as i32 as i64
                        {
                            xmlGROW(ctxt);
                        }
                        if (*ctxt).instate as i32
                            == XML_PARSER_EOF as i32
                        {
                            return;
                        }
                        in_0 = (*(*ctxt).input).cur;
                    }
                    _ => {}
                }
                if !(*in_0 as i32 >= 0x20 as i32
                    && *in_0 as i32 <= 0x7f as i32
                    || *in_0 as i32 == 0x9 as i32
                    || *in_0 as i32 == 0xa as i32)
                {
                    break;
                }
            }
        }
        nbchar = 0 as i32;
    }
    (*(*ctxt).input).line = line;
    (*(*ctxt).input).col = col;
    xmlParseCharDataComplex(ctxt, cdata);
}
unsafe extern "C" fn xmlParseCharDataComplex(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut cdata: i32,
) {
    let mut buf: [u8; 305] = [0; 305];
    let mut nbchar: i32 = 0 as i32;
    let mut cur: i32 = 0;
    let mut l: i32 = 0;
    let mut count: i32 = 0 as i32;
    if (*ctxt).progressive == 0 as i32
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
            > (2 as i32 * 250 as i32) as i64
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    cur = xmlCurrentChar(ctxt, Some(&mut l));
    while cur != '<' as i32 && cur != '&' as i32
        && (if cur < 0x100 as i32 {
            (0x9 as i32 <= cur && cur <= 0xa as i32
                || cur == 0xd as i32 || 0x20 as i32 <= cur)
                as i32
        } else {
            (0x100 as i32 <= cur && cur <= 0xd7ff as i32
                || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
                || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32)
                as i32
        }) != 0
    {
        if cur == ']' as i32
            && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
                == ']' as i32
            && *((*(*ctxt).input).cur).offset(2 as i32 as isize) as i32
                == '>' as i32
        {
            if cdata != 0 {
                break;
            }
            xmlFatalErr(ctxt, XML_ERR_MISPLACED_CDATA_END, 0 as *const i8);
        }
        if l == 1 as i32 {
            let mut fresh206 = nbchar;
            nbchar = nbchar + 1;
            buf[fresh206 as usize] = cur as xmlChar;
        } else {
            nbchar
                += xmlCopyCharMultiByte(
                    &mut *buf.as_mut_ptr().offset(nbchar as isize),
                    cur,
                );
        }
        if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
            let fresh207 = &mut ((*(*ctxt).input).line);
            *fresh207 += 1;
            (*(*ctxt).input).col = 1 as i32;
        } else {
            let fresh208 = &mut ((*(*ctxt).input).col);
            *fresh208 += 1;
        }
        let fresh209 = &mut ((*(*ctxt).input).cur);
        *fresh209 = (*fresh209).offset(l as isize);
        cur = xmlCurrentChar(ctxt, Some(&mut l));
        if nbchar >= 300 as i32 {
            buf[nbchar as usize] = 0 as i32 as xmlChar;
            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0 {
                if areBlanks(ctxt, buf.as_mut_ptr(), nbchar, 0 as i32) != 0 {
                    if ((*(*ctxt).sax).ignorableWhitespace).is_some() {
                        ((*(*ctxt).sax).ignorableWhitespace)
                            .expect(
                                "non-null function pointer",
                            )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                    }
                } else {
                    if ((*(*ctxt).sax).characters).is_some() {
                        ((*(*ctxt).sax).characters)
                            .expect(
                                "non-null function pointer",
                            )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                    }
                    if ((*(*ctxt).sax).characters ).map(|f| f as usize) == ( (*(*ctxt).sax).ignorableWhitespace).map(|f| f as usize)
                        && *(*ctxt).space == -(1 as i32)
                    {
                        *(*ctxt).space = -(2 as i32);
                    }
                }
            }
            nbchar = 0 as i32;
            if (*ctxt).instate as i32 != XML_PARSER_CONTENT as i32 {
                return;
            }
        }
        count += 1;
        if count > 50 as i32 {
            if (*ctxt).progressive == 0 as i32
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as i64
                    > (2 as i32 * 250 as i32) as i64
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            count = 0 as i32;
            if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                return;
            }
        }
    }
    if nbchar != 0 as i32 {
        buf[nbchar as usize] = 0 as i32 as xmlChar;
        if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0 {
            if areBlanks(ctxt, buf.as_mut_ptr(), nbchar, 0 as i32) != 0 {
                if ((*(*ctxt).sax).ignorableWhitespace).is_some() {
                    ((*(*ctxt).sax).ignorableWhitespace)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                }
            } else {
                if ((*(*ctxt).sax).characters).is_some() {
                    ((*(*ctxt).sax).characters)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                }
                if ((*(*ctxt).sax).characters ).map(|f| f as usize) == ( (*(*ctxt).sax).ignorableWhitespace).map(|f| f as usize)
                    && *(*ctxt).space == -(1 as i32)
                {
                    *(*ctxt).space = -(2 as i32);
                }
            }
        }
    }
    if cur != 0 as i32
        && (if cur < 0x100 as i32 {
            (0x9 as i32 <= cur && cur <= 0xa as i32
                || cur == 0xd as i32 || 0x20 as i32 <= cur)
                as i32
        } else {
            (0x100 as i32 <= cur && cur <= 0xd7ff as i32
                || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
                || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32)
                as i32
        }) == 0
    {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"PCDATA invalid Char value %d\n\0" as *const u8 as *const i8,
            cur,
        );
        if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
            let fresh210 = &mut ((*(*ctxt).input).line);
            *fresh210 += 1;
            (*(*ctxt).input).col = 1 as i32;
        } else {
            let fresh211 = &mut ((*(*ctxt).input).col);
            *fresh211 += 1;
        }
        let fresh212 = &mut ((*(*ctxt).input).cur);
        *fresh212 = (*fresh212).offset(l as isize);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseExternalID<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut publicID: Option<&'a1 mut * mut u8>,
    mut strict: i32,
) -> * mut u8 {
    let mut URI: * mut u8 = 0 as *mut xmlChar;
    if (*ctxt).progressive == 0 as i32
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
            > (2 as i32 * 250 as i32) as i64
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    *(borrow_mut(&mut publicID)).unwrap() = 0 as *mut xmlChar;
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == 'S' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == 'Y' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'S' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'E' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'M' as i32
    {
        let fresh213 = &mut ((*(*ctxt).input).cur);
        *fresh213 = (*fresh213).offset(6 as i32 as isize);
        (*(*ctxt).input).col += 6 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after 'SYSTEM'\n\0" as *const u8 as *const i8,
            );
        }
        URI = xmlParseSystemLiteral(ctxt);
        if URI.is_null() {
            xmlFatalErr(ctxt, XML_ERR_URI_REQUIRED, 0 as *const i8);
        }
    } else if *((*(*ctxt).input).cur as *mut u8)
            .offset(0 as i32 as isize) as i32 == 'P' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(1 as i32 as isize) as i32 == 'U' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(2 as i32 as isize) as i32 == 'B' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(3 as i32 as isize) as i32 == 'L' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(4 as i32 as isize) as i32 == 'I' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(5 as i32 as isize) as i32 == 'C' as i32
        {
        let fresh214 = &mut ((*(*ctxt).input).cur);
        *fresh214 = (*fresh214).offset(6 as i32 as isize);
        (*(*ctxt).input).col += 6 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after 'PUBLIC'\n\0" as *const u8 as *const i8,
            );
        }
        *(borrow_mut(&mut publicID)).unwrap() = xmlParsePubidLiteral(ctxt);
        if (*(borrow_mut(&mut publicID)).unwrap()).is_null() {
            xmlFatalErr(ctxt, XML_ERR_PUBID_REQUIRED, 0 as *const i8);
        }
        if strict != 0 {
            if xmlSkipBlankChars(ctxt) == 0 as i32 {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_SPACE_REQUIRED,
                    b"Space required after the Public Identifier\n\0" as *const u8
                        as *const i8,
                );
            }
        } else {
            if xmlSkipBlankChars(ctxt) == 0 as i32 {
                return 0 as *mut xmlChar;
            }
            if *(*(*ctxt).input).cur as i32 != '\'' as i32
                && *(*(*ctxt).input).cur as i32 != '"' as i32
            {
                return 0 as *mut xmlChar;
            }
        }
        URI = xmlParseSystemLiteral(ctxt);
        if URI.is_null() {
            xmlFatalErr(ctxt, XML_ERR_URI_REQUIRED, 0 as *const i8);
        }
    }
    return URI;
}
unsafe extern "C" fn xmlParseCommentComplex(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut buf: * mut u8,
    mut len: u64,
    mut size: u64,
) {
    let mut q: i32 = 0;
    let mut ql: i32 = 0;
    let mut r: i32 = 0;
    let mut rl: i32 = 0;
    let mut cur: i32 = 0;
    let mut l: i32 = 0;
    let mut count: u64 = 0 as i32 as size_t;
    let mut inputid: i32 = 0;
    inputid = (*(*ctxt).input).id;
    if buf.is_null() {
        len = 0 as i32 as size_t;
        size = 100 as i32 as size_t;
        buf = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )(size.wrapping_mul(::std::mem::size_of::<xmlChar>() as u64))
            as *mut xmlChar;
        if buf.is_null() {
            xmlErrMemory(ctxt, 0 as *const i8);
            return;
        }
    }
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    q = xmlCurrentChar(ctxt, Some(&mut ql));
    if !(q == 0 as i32) {
        if if q < 0x100 as i32 {
            (0x9 as i32 <= q && q <= 0xa as i32
                || q == 0xd as i32 || 0x20 as i32 <= q) as i32
        } else {
            (0x100 as i32 <= q && q <= 0xd7ff as i32
                || 0xe000 as i32 <= q && q <= 0xfffd as i32
                || 0x10000 as i32 <= q && q <= 0x10ffff as i32)
                as i32
        } == 0
        {
            xmlFatalErrMsgInt(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"xmlParseComment: invalid xmlChar value %d\n\0" as *const u8
                    as *const i8,
                q,
            );
            xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
            return;
        }
        if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
            let fresh215 = &mut ((*(*ctxt).input).line);
            *fresh215 += 1;
            (*(*ctxt).input).col = 1 as i32;
        } else {
            let fresh216 = &mut ((*(*ctxt).input).col);
            *fresh216 += 1;
        }
        let fresh217 = &mut ((*(*ctxt).input).cur);
        *fresh217 = (*fresh217).offset(ql as isize);
        r = xmlCurrentChar(ctxt, Some(&mut rl));
        if !(r == 0 as i32) {
            if if r < 0x100 as i32 {
                (0x9 as i32 <= r && r <= 0xa as i32
                    || r == 0xd as i32 || 0x20 as i32 <= r)
                    as i32
            } else {
                (0x100 as i32 <= r && r <= 0xd7ff as i32
                    || 0xe000 as i32 <= r && r <= 0xfffd as i32
                    || 0x10000 as i32 <= r && r <= 0x10ffff as i32)
                    as i32
            } == 0
            {
                xmlFatalErrMsgInt(
                    ctxt,
                    XML_ERR_INVALID_CHAR,
                    b"xmlParseComment: invalid xmlChar value %d\n\0" as *const u8
                        as *const i8,
                    q,
                );
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return;
            }
            if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
                let fresh218 = &mut ((*(*ctxt).input).line);
                *fresh218 += 1;
                (*(*ctxt).input).col = 1 as i32;
            } else {
                let fresh219 = &mut ((*(*ctxt).input).col);
                *fresh219 += 1;
            }
            let fresh220 = &mut ((*(*ctxt).input).cur);
            *fresh220 = (*fresh220).offset(rl as isize);
            cur = xmlCurrentChar(ctxt, Some(&mut l));
            if !(cur == 0 as i32) {
                while (if cur < 0x100 as i32 {
                    (0x9 as i32 <= cur && cur <= 0xa as i32
                        || cur == 0xd as i32 || 0x20 as i32 <= cur)
                        as i32
                } else {
                    (0x100 as i32 <= cur && cur <= 0xd7ff as i32
                        || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
                        || 0x10000 as i32 <= cur
                            && cur <= 0x10ffff as i32) as i32
                }) != 0 && (cur != '>' as i32 || r != '-' as i32 || q != '-' as i32)
                {
                    if r == '-' as i32 && q == '-' as i32 {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_HYPHEN_IN_COMMENT,
                            0 as *const i8,
                        );
                    }
                    if len > 10000000 as i32 as u64
                        && (*ctxt).options & XML_PARSE_HUGE as i32
                            == 0 as i32
                    {
                        xmlFatalErrMsgStr(
                            ctxt,
                            XML_ERR_COMMENT_NOT_FINISHED,
                            b"Comment too big found\0" as *const u8
                                as *const i8,
                            0 as *const xmlChar,
                        );
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buf as *mut libc::c_void);
                        return;
                    }
                    if len.wrapping_add(5 as i32 as u64) >= size {
                        let mut new_buf: * mut u8 = 0 as *mut xmlChar;
                        let mut new_size: u64 = 0;
                        new_size = size.wrapping_mul(2 as i32 as u64);
                        new_buf = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(buf as *mut libc::c_void, new_size) as *mut xmlChar;
                        if new_buf.is_null() {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(buf as *mut libc::c_void);
                            xmlErrMemory(ctxt, 0 as *const i8);
                            return;
                        }
                        buf = new_buf;
                        size = new_size;
                    }
                    if ql == 1 as i32 {
                        let mut fresh221 = len;
                        len = len.wrapping_add(1);
                        *buf.offset(fresh221 as isize) = q as xmlChar;
                    } else {
                        len = (len as u64)
                            .wrapping_add(
                                xmlCopyCharMultiByte(&mut *buf.offset(len as isize), q)
                                    as u64,
                            ) as size_t as size_t;
                    }
                    q = r;
                    ql = rl;
                    r = cur;
                    rl = l;
                    count = count.wrapping_add(1);
                    if count > 50 as i32 as u64 {
                        if (*ctxt).progressive == 0 as i32
                            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as i64
                                > (2 as i32 * 250 as i32) as i64
                            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                as i64)
                                < (2 as i32 * 250 as i32) as i64
                        {
                            xmlSHRINK(ctxt);
                        }
                        if (*ctxt).progressive == 0 as i32
                            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                as i64) < 250 as i32 as i64
                        {
                            xmlGROW(ctxt);
                        }
                        count = 0 as i32 as size_t;
                        if (*ctxt).instate as i32
                            == XML_PARSER_EOF as i32
                        {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(buf as *mut libc::c_void);
                            return;
                        }
                    }
                    if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
                        let fresh222 = &mut ((*(*ctxt).input).line);
                        *fresh222 += 1;
                        (*(*ctxt).input).col = 1 as i32;
                    } else {
                        let fresh223 = &mut ((*(*ctxt).input).col);
                        *fresh223 += 1;
                    }
                    let fresh224 = &mut ((*(*ctxt).input).cur);
                    *fresh224 = (*fresh224).offset(l as isize);
                    cur = xmlCurrentChar(ctxt, Some(&mut l));
                    if cur == 0 as i32 {
                        if (*ctxt).progressive == 0 as i32
                            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as i64
                                > (2 as i32 * 250 as i32) as i64
                            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                as i64)
                                < (2 as i32 * 250 as i32) as i64
                        {
                            xmlSHRINK(ctxt);
                        }
                        if (*ctxt).progressive == 0 as i32
                            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                as i64) < 250 as i32 as i64
                        {
                            xmlGROW(ctxt);
                        }
                        cur = xmlCurrentChar(ctxt, Some(&mut l));
                    }
                }
                *buf.offset(len as isize) = 0 as i32 as xmlChar;
                if cur == 0 as i32 {
                    xmlFatalErrMsgStr(
                        ctxt,
                        XML_ERR_COMMENT_NOT_FINISHED,
                        b"Comment not terminated \n<!--%.50s\n\0" as *const u8
                            as *const i8,
                        buf,
                    );
                } else if if cur < 0x100 as i32 {
                        (0x9 as i32 <= cur && cur <= 0xa as i32
                            || cur == 0xd as i32 || 0x20 as i32 <= cur)
                            as i32
                    } else {
                        (0x100 as i32 <= cur && cur <= 0xd7ff as i32
                            || 0xe000 as i32 <= cur
                                && cur <= 0xfffd as i32
                            || 0x10000 as i32 <= cur
                                && cur <= 0x10ffff as i32) as i32
                    } == 0
                    {
                    xmlFatalErrMsgInt(
                        ctxt,
                        XML_ERR_INVALID_CHAR,
                        b"xmlParseComment: invalid xmlChar value %d\n\0" as *const u8
                            as *const i8,
                        cur,
                    );
                } else {
                    if inputid != (*(*ctxt).input).id {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_ENTITY_BOUNDARY,
                            b"Comment doesn't start and stop in the same entity\n\0"
                                as *const u8 as *const i8,
                        );
                    }
                    xmlNextChar(ctxt);
                    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).comment).is_some()
                        && (*ctxt).disableSAX == 0
                    {
                        ((*(*ctxt).sax).comment)
                            .expect("non-null function pointer")((*ctxt).userData, buf);
                    }
                }
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return;
            }
        }
    }
    xmlFatalErrMsgStr(
        ctxt,
        XML_ERR_COMMENT_NOT_FINISHED,
        b"Comment not terminated\n\0" as *const u8 as *const i8,
        0 as *const xmlChar,
    );
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseComment(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut buf: * mut u8 = 0 as *mut xmlChar;
    let mut size: u64 = 100 as i32 as size_t;
    let mut len: u64 = 0 as i32 as size_t;
    let mut state: i32 = XML_PARSER_START;
    let mut in_0: * const u8 = 0 as *const xmlChar;
    let mut nbchar: u64 = 0 as i32 as size_t;
    let mut ccol: i32 = 0;
    let mut inputid: i32 = 0;
    if *(*(*ctxt).input).cur as i32 != '<' as i32
        || *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            != '!' as i32
        || *((*(*ctxt).input).cur).offset(2 as i32 as isize) as i32
            != '-' as i32
        || *((*(*ctxt).input).cur).offset(3 as i32 as isize) as i32
            != '-' as i32
    {
        return;
    }
    state = (*ctxt).instate;
    (*ctxt).instate = XML_PARSER_COMMENT;
    inputid = (*(*ctxt).input).id;
    let fresh225 = &mut ((*(*ctxt).input).cur);
    *fresh225 = (*fresh225).offset(4 as i32 as isize);
    (*(*ctxt).input).col += 4 as i32;
    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
        xmlParserInputGrow((*ctxt).input, 250 as i32);
    }
    if (*ctxt).progressive == 0 as i32
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
            > (2 as i32 * 250 as i32) as i64
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    in_0 = (*(*ctxt).input).cur;
    loop {
        if *in_0 as i32 == 0xa as i32 {
            loop {
                let fresh226 = &mut ((*(*ctxt).input).line);
                *fresh226 += 1;
                (*(*ctxt).input).col = 1 as i32;
                in_0 = in_0.offset(1);
                if !(*in_0 as i32 == 0xa as i32) {
                    break;
                }
            }
        }
        loop {
            ccol = (*(*ctxt).input).col;
            while *in_0 as i32 > '-' as i32
                && *in_0 as i32 <= 0x7f as i32
                || *in_0 as i32 >= 0x20 as i32
                    && (*in_0 as i32) < '-' as i32
                || *in_0 as i32 == 0x9 as i32
            {
                in_0 = in_0.offset(1);
                ccol += 1;
            }
            (*(*ctxt).input).col = ccol;
            if *in_0 as i32 == 0xa as i32 {
                loop {
                    let fresh227 = &mut ((*(*ctxt).input).line);
                    *fresh227 += 1;
                    (*(*ctxt).input).col = 1 as i32;
                    in_0 = in_0.offset(1);
                    if !(*in_0 as i32 == 0xa as i32) {
                        break;
                    }
                }
            } else {
                nbchar = in_0.offset_from((*(*ctxt).input).cur) as i64
                    as size_t;
                if nbchar > 0 as i32 as u64 {
                    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).comment).is_some() {
                        if buf.is_null() {
                            if *in_0 as i32 == '-' as i32
                                && *in_0.offset(1 as i32 as isize) as i32
                                    == '-' as i32
                            {
                                size = nbchar
                                    .wrapping_add(1 as i32 as u64);
                            } else {
                                size = (100 as i32 as u64)
                                    .wrapping_add(nbchar);
                            }
                            buf = xmlMallocAtomic
                                .expect(
                                    "non-null function pointer",
                                )(
                                size
                                    .wrapping_mul(
                                        ::std::mem::size_of::<xmlChar>() as u64,
                                    ),
                            ) as *mut xmlChar;
                            if buf.is_null() {
                                xmlErrMemory(ctxt, 0 as *const i8);
                                (*ctxt).instate = state;
                                return;
                            }
                            len = 0 as i32 as size_t;
                        } else if len
                                .wrapping_add(nbchar)
                                .wrapping_add(1 as i32 as u64) >= size
                            {
                            let mut new_buf: * mut u8 = 0 as *mut xmlChar;
                            size = (size as u64)
                                .wrapping_add(
                                    len
                                        .wrapping_add(nbchar)
                                        .wrapping_add(100 as i32 as u64),
                                ) as size_t as size_t;
                            new_buf = xmlRealloc
                                .expect(
                                    "non-null function pointer",
                                )(
                                buf as *mut libc::c_void,
                                size
                                    .wrapping_mul(
                                        ::std::mem::size_of::<xmlChar>() as u64,
                                    ),
                            ) as *mut xmlChar;
                            if new_buf.is_null() {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(buf as *mut libc::c_void);
                                xmlErrMemory(ctxt, 0 as *const i8);
                                (*ctxt).instate = state;
                                return;
                            }
                            buf = new_buf;
                        }
                        memcpy(
                            &mut *buf.offset(len as isize) as *mut xmlChar
                                as *mut libc::c_void,
                            (*(*ctxt).input).cur as *const libc::c_void,
                            nbchar,
                        );
                        len = (len as u64).wrapping_add(nbchar) as size_t
                            as size_t;
                        *buf.offset(len as isize) = 0 as i32 as xmlChar;
                    }
                }
                if len > 10000000 as i32 as u64
                    && (*ctxt).options & XML_PARSE_HUGE as i32
                        == 0 as i32
                {
                    xmlFatalErrMsgStr(
                        ctxt,
                        XML_ERR_COMMENT_NOT_FINISHED,
                        b"Comment too big found\0" as *const u8 as *const i8,
                        0 as *const xmlChar,
                    );
                    xmlFree
                        .expect("non-null function pointer")(buf as *mut libc::c_void);
                    return;
                }
                let fresh228 = &mut ((*(*ctxt).input).cur);
                *fresh228 = in_0;
                if *in_0 as i32 == 0xa as i32 {
                    in_0 = in_0.offset(1);
                    let fresh229 = &mut ((*(*ctxt).input).line);
                    *fresh229 += 1;
                    (*(*ctxt).input).col = 1 as i32;
                }
                if *in_0 as i32 == 0xd as i32 {
                    in_0 = in_0.offset(1);
                    if *in_0 as i32 == 0xa as i32 {
                        let fresh230 = &mut ((*(*ctxt).input).cur);
                        *fresh230 = in_0;
                        in_0 = in_0.offset(1);
                        let fresh231 = &mut ((*(*ctxt).input).line);
                        *fresh231 += 1;
                        (*(*ctxt).input).col = 1 as i32;
                        continue;
                    } else {
                        in_0 = in_0.offset(-1);
                    }
                }
                if (*ctxt).progressive == 0 as i32
                    && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as i64
                        > (2 as i32 * 250 as i32) as i64
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64)
                        < (2 as i32 * 250 as i32) as i64
                {
                    xmlSHRINK(ctxt);
                }
                if (*ctxt).progressive == 0 as i32
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64) < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                    xmlFree
                        .expect("non-null function pointer")(buf as *mut libc::c_void);
                    return;
                }
                in_0 = (*(*ctxt).input).cur;
                if !(*in_0 as i32 == '-' as i32) {
                    break;
                }
                if *in_0.offset(1 as i32 as isize) as i32 == '-' as i32 {
                    if *in_0.offset(2 as i32 as isize) as i32
                        == '>' as i32
                    {
                        if (*(*ctxt).input).id != inputid {
                            xmlFatalErrMsg(
                                ctxt,
                                XML_ERR_ENTITY_BOUNDARY,
                                b"comment doesn't start and stop in the same entity\n\0"
                                    as *const u8 as *const i8,
                            );
                        }
                        let fresh232 = &mut ((*(*ctxt).input).cur);
                        *fresh232 = (*fresh232).offset(3 as i32 as isize);
                        (*(*ctxt).input).col += 3 as i32;
                        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                            xmlParserInputGrow((*ctxt).input, 250 as i32);
                        }
                        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).comment).is_some()
                            && (*ctxt).disableSAX == 0
                        {
                            if !buf.is_null() {
                                ((*(*ctxt).sax).comment)
                                    .expect("non-null function pointer")((*ctxt).userData, buf);
                            } else {
                                ((*(*ctxt).sax).comment)
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    (*ctxt).userData,
                                    b"\0" as *const u8 as *const i8 as *mut xmlChar,
                                );
                            }
                        }
                        if !buf.is_null() {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(buf as *mut libc::c_void);
                        }
                        if (*ctxt).instate as i32
                            != XML_PARSER_EOF as i32
                        {
                            (*ctxt).instate = state;
                        }
                        return;
                    }
                    if !buf.is_null() {
                        xmlFatalErrMsgStr(
                            ctxt,
                            XML_ERR_HYPHEN_IN_COMMENT,
                            b"Double hyphen within comment: <!--%.50s\n\0" as *const u8
                                as *const i8,
                            buf,
                        );
                    } else {
                        xmlFatalErrMsgStr(
                            ctxt,
                            XML_ERR_HYPHEN_IN_COMMENT,
                            b"Double hyphen within comment\n\0" as *const u8
                                as *const i8,
                            0 as *const xmlChar,
                        );
                    }
                    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buf as *mut libc::c_void);
                        return;
                    }
                    in_0 = in_0.offset(1);
                    let fresh233 = &mut ((*(*ctxt).input).col);
                    *fresh233 += 1;
                }
                in_0 = in_0.offset(1);
                let fresh234 = &mut ((*(*ctxt).input).col);
                *fresh234 += 1;
            }
        }
        if !(*in_0 as i32 >= 0x20 as i32
            && *in_0 as i32 <= 0x7f as i32
            || *in_0 as i32 == 0x9 as i32
            || *in_0 as i32 == 0xa as i32)
        {
            break;
        }
    }
    xmlParseCommentComplex(ctxt, buf, len, size);
    (*ctxt).instate = state;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParsePITarget(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * const u8 {
    let mut name: * const u8 = 0 as *const xmlChar;
    name = xmlParseName(ctxt);
    if !name.is_null()
        && (*name.offset(0 as i32 as isize) as i32 == 'x' as i32
            || *name.offset(0 as i32 as isize) as i32 == 'X' as i32)
        && (*name.offset(1 as i32 as isize) as i32 == 'm' as i32
            || *name.offset(1 as i32 as isize) as i32 == 'M' as i32)
        && (*name.offset(2 as i32 as isize) as i32 == 'l' as i32
            || *name.offset(2 as i32 as isize) as i32 == 'L' as i32)
    {
        let mut i: i32 = 0;
        if *name.offset(0 as i32 as isize) as i32 == 'x' as i32
            && *name.offset(1 as i32 as isize) as i32 == 'm' as i32
            && *name.offset(2 as i32 as isize) as i32 == 'l' as i32
            && *name.offset(3 as i32 as isize) as i32 == 0 as i32
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_RESERVED_XML_NAME,
                b"XML declaration allowed only at the start of the document\n\0"
                    as *const u8 as *const i8,
            );
            return name;
        } else {
            if *name.offset(3 as i32 as isize) as i32 == 0 as i32
            {
                xmlFatalErr(ctxt, XML_ERR_RESERVED_XML_NAME, 0 as *const i8);
                return name;
            }
        }
        i = 0 as i32;
        while !(xmlW3CPIs[i as usize]).is_null() {
            if xmlStrEqual(name, xmlW3CPIs[i as usize] as *const xmlChar) != 0 {
                return name;
            }
            i += 1;
        }
        xmlWarningMsg(
            ctxt,
            XML_ERR_RESERVED_XML_NAME,
            b"xmlParsePITarget: invalid name prefix 'xml'\n\0" as *const u8
                as *const i8,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    }
    if !name.is_null() && !(xmlStrchr(name, ':' as i32 as xmlChar)).is_null() {
        xmlNsErr(
            ctxt,
            XML_NS_ERR_COLON,
            b"colons are forbidden from PI names '%s'\n\0" as *const u8
                as *const i8,
            name,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    }
    return name;
}
unsafe extern "C" fn xmlParseCatalogPI(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut catalog: * const u8,
) {
    let mut URL: * mut u8 = 0 as *mut xmlChar;
    let mut tmp: * const u8 = 0 as *const xmlChar;
    let mut base: * const u8 = 0 as *const xmlChar;
    let mut marker: u8 = 0;
    tmp = catalog;
    while *tmp as i32 == 0x20 as i32
        || 0x9 as i32 <= *tmp as i32
            && *tmp as i32 <= 0xa as i32
        || *tmp as i32 == 0xd as i32
    {
        tmp = tmp.offset(1);
    }
    if !(xmlStrncmp(
        tmp,
        b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
        7 as i32,
    ) != 0)
    {
        tmp = tmp.offset(7 as i32 as isize);
        while *tmp as i32 == 0x20 as i32
            || 0x9 as i32 <= *tmp as i32
                && *tmp as i32 <= 0xa as i32
            || *tmp as i32 == 0xd as i32
        {
            tmp = tmp.offset(1);
        }
        if *tmp as i32 != '=' as i32 {
            return;
        }
        tmp = tmp.offset(1);
        while *tmp as i32 == 0x20 as i32
            || 0x9 as i32 <= *tmp as i32
                && *tmp as i32 <= 0xa as i32
            || *tmp as i32 == 0xd as i32
        {
            tmp = tmp.offset(1);
        }
        marker = *tmp;
        if !(marker as i32 != '\'' as i32 && marker as i32 != '"' as i32)
        {
            tmp = tmp.offset(1);
            base = tmp;
            while *tmp as i32 != 0 as i32
                && *tmp as i32 != marker as i32
            {
                tmp = tmp.offset(1);
            }
            if !(*tmp as i32 == 0 as i32) {
                URL = xmlStrndup(
                    base,
                    tmp.offset_from(base) as i64 as i32,
                );
                tmp = tmp.offset(1);
                while *tmp as i32 == 0x20 as i32
                    || 0x9 as i32 <= *tmp as i32
                        && *tmp as i32 <= 0xa as i32
                    || *tmp as i32 == 0xd as i32
                {
                    tmp = tmp.offset(1);
                }
                if !(*tmp as i32 != 0 as i32) {
                    if !URL.is_null() {
                        let fresh235 = &mut ((*ctxt).catalogs);
                        *fresh235 = xmlCatalogAddLocal((*ctxt).catalogs, URL);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(URL as *mut libc::c_void);
                    }
                    return;
                }
            }
        }
    }
    xmlWarningMsg(
        ctxt,
        XML_WAR_CATALOG_PI,
        b"Catalog PI syntax error: %s\n\0" as *const u8 as *const i8,
        catalog,
        0 as *const xmlChar,
    );
    if !URL.is_null() {
        xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParsePI(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut buf: * mut u8 = 0 as *mut xmlChar;
    let mut len: u64 = 0 as i32 as size_t;
    let mut size: u64 = 100 as i32 as size_t;
    let mut cur: i32 = 0;
    let mut l: i32 = 0;
    let mut target: * const u8 = 0 as *const xmlChar;
    let mut state: i32 = XML_PARSER_START;
    let mut count: i32 = 0 as i32;
    if *(*(*ctxt).input).cur as i32 == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            == '?' as i32
    {
        let mut inputid: i32 = (*(*ctxt).input).id;
        state = (*ctxt).instate;
        (*ctxt).instate = XML_PARSER_PI;
        let fresh236 = &mut ((*(*ctxt).input).cur);
        *fresh236 = (*fresh236).offset(2 as i32 as isize);
        (*(*ctxt).input).col += 2 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        if (*ctxt).progressive == 0 as i32
            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
                > (2 as i32 * 250 as i32) as i64
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < (2 as i32 * 250 as i32) as i64
        {
            xmlSHRINK(ctxt);
        }
        target = xmlParsePITarget(ctxt);
        if !target.is_null() {
            if *(*(*ctxt).input).cur as i32 == '?' as i32
                && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == '>' as i32
            {
                if inputid != (*(*ctxt).input).id {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ENTITY_BOUNDARY,
                        b"PI declaration doesn't start and stop in the same entity\n\0"
                            as *const u8 as *const i8,
                    );
                }
                let fresh237 = &mut ((*(*ctxt).input).cur);
                *fresh237 = (*fresh237).offset(2 as i32 as isize);
                (*(*ctxt).input).col += 2 as i32;
                if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                    xmlParserInputGrow((*ctxt).input, 250 as i32);
                }
                if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                    && ((*(*ctxt).sax).processingInstruction).is_some()
                {
                    ((*(*ctxt).sax).processingInstruction)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, target, 0 as *const xmlChar);
                }
                if (*ctxt).instate as i32 != XML_PARSER_EOF as i32 {
                    (*ctxt).instate = state;
                }
                return;
            }
            buf = xmlMallocAtomic
                .expect(
                    "non-null function pointer",
                )(size.wrapping_mul(::std::mem::size_of::<xmlChar>() as u64))
                as *mut xmlChar;
            if buf.is_null() {
                xmlErrMemory(ctxt, 0 as *const i8);
                (*ctxt).instate = state;
                return;
            }
            if xmlSkipBlankChars(ctxt) == 0 as i32 {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_SPACE_REQUIRED,
                    b"ParsePI: PI %s space expected\n\0" as *const u8
                        as *const i8,
                    target,
                );
            }
            cur = xmlCurrentChar(ctxt, Some(&mut l));
            while (if cur < 0x100 as i32 {
                (0x9 as i32 <= cur && cur <= 0xa as i32
                    || cur == 0xd as i32 || 0x20 as i32 <= cur)
                    as i32
            } else {
                (0x100 as i32 <= cur && cur <= 0xd7ff as i32
                    || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
                    || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32)
                    as i32
            }) != 0
                && (cur != '?' as i32
                    || *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                        as i32 != '>' as i32)
            {
                if len.wrapping_add(5 as i32 as u64) >= size {
                    let mut tmp: * mut u8 = 0 as *mut xmlChar;
                    let mut new_size: u64 = size
                        .wrapping_mul(2 as i32 as u64);
                    tmp = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(buf as *mut libc::c_void, new_size) as *mut xmlChar;
                    if tmp.is_null() {
                        xmlErrMemory(ctxt, 0 as *const i8);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buf as *mut libc::c_void);
                        (*ctxt).instate = state;
                        return;
                    }
                    buf = tmp;
                    size = new_size;
                }
                count += 1;
                if count > 50 as i32 {
                    if (*ctxt).progressive == 0 as i32
                        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as i64
                            > (2 as i32 * 250 as i32) as i64
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as i64)
                            < (2 as i32 * 250 as i32) as i64
                    {
                        xmlSHRINK(ctxt);
                    }
                    if (*ctxt).progressive == 0 as i32
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as i64) < 250 as i32 as i64
                    {
                        xmlGROW(ctxt);
                    }
                    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buf as *mut libc::c_void);
                        return;
                    }
                    count = 0 as i32;
                    if len > 10000000 as i32 as u64
                        && (*ctxt).options & XML_PARSE_HUGE as i32
                            == 0 as i32
                    {
                        xmlFatalErrMsgStr(
                            ctxt,
                            XML_ERR_PI_NOT_FINISHED,
                            b"PI %s too big found\0" as *const u8 as *const i8,
                            target,
                        );
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buf as *mut libc::c_void);
                        (*ctxt).instate = state;
                        return;
                    }
                }
                if l == 1 as i32 {
                    let mut fresh238 = len;
                    len = len.wrapping_add(1);
                    *buf.offset(fresh238 as isize) = cur as xmlChar;
                } else {
                    len = (len as u64)
                        .wrapping_add(
                            xmlCopyCharMultiByte(&mut *buf.offset(len as isize), cur)
                                as u64,
                        ) as size_t as size_t;
                }
                if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
                    let fresh239 = &mut ((*(*ctxt).input).line);
                    *fresh239 += 1;
                    (*(*ctxt).input).col = 1 as i32;
                } else {
                    let fresh240 = &mut ((*(*ctxt).input).col);
                    *fresh240 += 1;
                }
                let fresh241 = &mut ((*(*ctxt).input).cur);
                *fresh241 = (*fresh241).offset(l as isize);
                cur = xmlCurrentChar(ctxt, Some(&mut l));
                if cur == 0 as i32 {
                    if (*ctxt).progressive == 0 as i32
                        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as i64
                            > (2 as i32 * 250 as i32) as i64
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as i64)
                            < (2 as i32 * 250 as i32) as i64
                    {
                        xmlSHRINK(ctxt);
                    }
                    if (*ctxt).progressive == 0 as i32
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as i64) < 250 as i32 as i64
                    {
                        xmlGROW(ctxt);
                    }
                    cur = xmlCurrentChar(ctxt, Some(&mut l));
                }
            }
            if len > 10000000 as i32 as u64
                && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
            {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_PI_NOT_FINISHED,
                    b"PI %s too big found\0" as *const u8 as *const i8,
                    target,
                );
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                (*ctxt).instate = state;
                return;
            }
            *buf.offset(len as isize) = 0 as i32 as xmlChar;
            if cur != '?' as i32 {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_PI_NOT_FINISHED,
                    b"ParsePI: PI %s never end ...\n\0" as *const u8
                        as *const i8,
                    target,
                );
            } else {
                if inputid != (*(*ctxt).input).id {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ENTITY_BOUNDARY,
                        b"PI declaration doesn't start and stop in the same entity\n\0"
                            as *const u8 as *const i8,
                    );
                }
                let fresh242 = &mut ((*(*ctxt).input).cur);
                *fresh242 = (*fresh242).offset(2 as i32 as isize);
                (*(*ctxt).input).col += 2 as i32;
                if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                    xmlParserInputGrow((*ctxt).input, 250 as i32);
                }
                if (state as i32 == XML_PARSER_MISC as i32
                    || state as i32 == XML_PARSER_START as i32)
                    && xmlStrEqual(
                        target,
                        b"oasis-xml-catalog\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) != 0
                {
                    let mut allow: u32 = xmlCatalogGetDefaults();
                    if allow as u32
                        == XML_CATA_ALLOW_DOCUMENT as i32 as u32
                        || allow as u32
                            == XML_CATA_ALLOW_ALL as i32 as u32
                    {
                        xmlParseCatalogPI(ctxt, buf);
                    }
                }
                if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                    && ((*(*ctxt).sax).processingInstruction).is_some()
                {
                    ((*(*ctxt).sax).processingInstruction)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, target, buf);
                }
            }
            xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
        } else {
            xmlFatalErr(ctxt, XML_ERR_PI_NOT_STARTED, 0 as *const i8);
        }
        if (*ctxt).instate as i32 != XML_PARSER_EOF as i32 {
            (*ctxt).instate = state;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseNotationDecl(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut name: * const u8 = 0 as *const xmlChar;
    let mut Pubid: * mut u8 = 0 as *mut xmlChar;
    let mut Systemid: * mut u8 = 0 as *mut xmlChar;
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '<' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == '!' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'N' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'O' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'A' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(7 as i32 as isize) as i32 == 'I' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(8 as i32 as isize) as i32 == 'O' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(9 as i32 as isize) as i32 == 'N' as i32
    {
        let mut inputid: i32 = (*(*ctxt).input).id;
        if (*ctxt).progressive == 0 as i32
            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
                > (2 as i32 * 250 as i32) as i64
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < (2 as i32 * 250 as i32) as i64
        {
            xmlSHRINK(ctxt);
        }
        let fresh243 = &mut ((*(*ctxt).input).cur);
        *fresh243 = (*fresh243).offset(10 as i32 as isize);
        (*(*ctxt).input).col += 10 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after '<!NOTATION'\n\0" as *const u8
                    as *const i8,
            );
            return;
        }
        name = xmlParseName(ctxt);
        if name.is_null() {
            xmlFatalErr(ctxt, XML_ERR_NOTATION_NOT_STARTED, 0 as *const i8);
            return;
        }
        if !(xmlStrchr(name, ':' as i32 as xmlChar)).is_null() {
            xmlNsErr(
                ctxt,
                XML_NS_ERR_COLON,
                b"colons are forbidden from notation names '%s'\n\0" as *const u8
                    as *const i8,
                name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after the NOTATION name'\n\0" as *const u8
                    as *const i8,
            );
            return;
        }
        Systemid = xmlParseExternalID(ctxt, Some(&mut Pubid), 0 as i32);
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as i32 == '>' as i32 {
            if inputid != (*(*ctxt).input).id {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Notation declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const i8,
                );
            }
            xmlNextChar(ctxt);
            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                && ((*(*ctxt).sax).notationDecl).is_some()
            {
                ((*(*ctxt).sax).notationDecl)
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).userData, name, Pubid, Systemid);
            }
        } else {
            xmlFatalErr(ctxt, XML_ERR_NOTATION_NOT_FINISHED, 0 as *const i8);
        }
        if !Systemid.is_null() {
            xmlFree.expect("non-null function pointer")(Systemid as *mut libc::c_void);
        }
        if !Pubid.is_null() {
            xmlFree.expect("non-null function pointer")(Pubid as *mut libc::c_void);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEntityDecl(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut name: * const u8 = 0 as *const xmlChar;
    let mut value: * mut u8 = 0 as *mut xmlChar;
    let mut URI: * mut u8 = 0 as *mut xmlChar;
    let mut literal: * mut u8 = 0 as *mut xmlChar;
    let mut ndata: * const u8 = 0 as *const xmlChar;
    let mut isParameter: i32 = 0 as i32;
    let mut orig: * mut u8 = 0 as *mut xmlChar;
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '<' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == '!' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'E' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'N' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'I' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(7 as i32 as isize) as i32 == 'Y' as i32
    {
        let mut inputid: i32 = (*(*ctxt).input).id;
        if (*ctxt).progressive == 0 as i32
            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
                > (2 as i32 * 250 as i32) as i64
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < (2 as i32 * 250 as i32) as i64
        {
            xmlSHRINK(ctxt);
        }
        let fresh244 = &mut ((*(*ctxt).input).cur);
        *fresh244 = (*fresh244).offset(8 as i32 as isize);
        (*(*ctxt).input).col += 8 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after '<!ENTITY'\n\0" as *const u8
                    as *const i8,
            );
        }
        if *(*(*ctxt).input).cur as i32 == '%' as i32 {
            xmlNextChar(ctxt);
            if xmlSkipBlankChars(ctxt) == 0 as i32 {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_SPACE_REQUIRED,
                    b"Space required after '%%'\n\0" as *const u8 as *const i8,
                );
            }
            isParameter = 1 as i32;
        }
        name = xmlParseName(ctxt);
        if name.is_null() {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_NAME_REQUIRED,
                b"xmlParseEntityDecl: no name\n\0" as *const u8 as *const i8,
            );
            return;
        }
        if !(xmlStrchr(name, ':' as i32 as xmlChar)).is_null() {
            xmlNsErr(
                ctxt,
                XML_NS_ERR_COLON,
                b"colons are forbidden from entities names '%s'\n\0" as *const u8
                    as *const i8,
                name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after the entity name\n\0" as *const u8
                    as *const i8,
            );
        }
        (*ctxt).instate = XML_PARSER_ENTITY_DECL;
        if isParameter != 0 {
            if *(*(*ctxt).input).cur as i32 == '"' as i32
                || *(*(*ctxt).input).cur as i32 == '\'' as i32
            {
                value = xmlParseEntityValue(ctxt, Some(&mut orig));
                if !value.is_null() {
                    if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                        && ((*(*ctxt).sax).entityDecl).is_some()
                    {
                        ((*(*ctxt).sax).entityDecl)
                            .expect(
                                "non-null function pointer",
                            )(
                            (*ctxt).userData,
                            name,
                            XML_INTERNAL_PARAMETER_ENTITY as i32,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                            value,
                        );
                    }
                }
            } else {
                URI = xmlParseExternalID(ctxt, Some(&mut literal), 1 as i32);
                if URI.is_null() && literal.is_null() {
                    xmlFatalErr(ctxt, XML_ERR_VALUE_REQUIRED, 0 as *const i8);
                }
                if !URI.is_null() {
                    let mut uri: * mut crate::src::SAX2::_xmlURI = 0 as *mut xmlURI;
                    uri = xmlParseURI(URI as *const i8);
                    if uri.is_null() {
                        xmlErrMsgStr(
                            ctxt,
                            XML_ERR_INVALID_URI,
                            b"Invalid URI: %s\n\0" as *const u8 as *const i8,
                            URI,
                        );
                    } else {
                        if !((*uri).fragment).is_null() {
                            xmlFatalErr(
                                ctxt,
                                XML_ERR_URI_FRAGMENT,
                                0 as *const i8,
                            );
                        } else if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                                && ((*(*ctxt).sax).entityDecl).is_some()
                            {
                            ((*(*ctxt).sax).entityDecl)
                                .expect(
                                    "non-null function pointer",
                                )(
                                (*ctxt).userData,
                                name,
                                XML_EXTERNAL_PARAMETER_ENTITY as i32,
                                literal,
                                URI,
                                0 as *mut xmlChar,
                            );
                        }
                        xmlFreeURI(uri);
                    }
                }
            }
        } else if *(*(*ctxt).input).cur as i32 == '"' as i32
                || *(*(*ctxt).input).cur as i32 == '\'' as i32
            {
            value = xmlParseEntityValue(ctxt, Some(&mut orig));
            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                && ((*(*ctxt).sax).entityDecl).is_some()
            {
                ((*(*ctxt).sax).entityDecl)
                    .expect(
                        "non-null function pointer",
                    )(
                    (*ctxt).userData,
                    name,
                    XML_INTERNAL_GENERAL_ENTITY as i32,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    value,
                );
            }
            if ((*ctxt).myDoc).is_null()
                || xmlStrEqual(
                    (*(*ctxt).myDoc).version,
                    b"SAX compatibility mode document\0" as *const u8
                        as *const i8 as *mut xmlChar,
                ) != 0
            {
                if ((*ctxt).myDoc).is_null() {
                    let fresh245 = &mut ((*ctxt).myDoc);
                    *fresh245 = xmlNewDoc(
                        b"SAX compatibility mode document\0" as *const u8
                            as *const i8 as *mut xmlChar,
                    );
                    if ((*ctxt).myDoc).is_null() {
                        xmlErrMemory(
                            ctxt,
                            b"New Doc failed\0" as *const u8 as *const i8,
                        );
                        return;
                    }
                    (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as i32;
                }
                if ((*(*ctxt).myDoc).intSubset).is_null() {
                    let fresh246 = &mut ((*(*ctxt).myDoc).intSubset);
                    *fresh246 = xmlNewDtd(
                        (*ctxt).myDoc,
                        b"fake\0" as *const u8 as *const i8 as *mut xmlChar,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                }
                xmlSAX2EntityDecl(
                    ctxt as *mut libc::c_void,
                    name,
                    XML_INTERNAL_GENERAL_ENTITY as i32,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    value,
                );
            }
        } else {
            URI = xmlParseExternalID(ctxt, Some(&mut literal), 1 as i32);
            if URI.is_null() && literal.is_null() {
                xmlFatalErr(ctxt, XML_ERR_VALUE_REQUIRED, 0 as *const i8);
            }
            if !URI.is_null() {
                let mut uri_0: * mut crate::src::SAX2::_xmlURI = 0 as *mut xmlURI;
                uri_0 = xmlParseURI(URI as *const i8);
                if uri_0.is_null() {
                    xmlErrMsgStr(
                        ctxt,
                        XML_ERR_INVALID_URI,
                        b"Invalid URI: %s\n\0" as *const u8 as *const i8,
                        URI,
                    );
                } else {
                    if !((*uri_0).fragment).is_null() {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_URI_FRAGMENT,
                            0 as *const i8,
                        );
                    }
                    xmlFreeURI(uri_0);
                }
            }
            if *(*(*ctxt).input).cur as i32 != '>' as i32
                && xmlSkipBlankChars(ctxt) == 0 as i32
            {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_SPACE_REQUIRED,
                    b"Space required before 'NDATA'\n\0" as *const u8
                        as *const i8,
                );
            }
            if *((*(*ctxt).input).cur as *mut u8)
                .offset(0 as i32 as isize) as i32 == 'N' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(1 as i32 as isize) as i32 == 'D' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(2 as i32 as isize) as i32 == 'A' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(3 as i32 as isize) as i32 == 'T' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(4 as i32 as isize) as i32 == 'A' as i32
            {
                let fresh247 = &mut ((*(*ctxt).input).cur);
                *fresh247 = (*fresh247).offset(5 as i32 as isize);
                (*(*ctxt).input).col += 5 as i32;
                if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                    xmlParserInputGrow((*ctxt).input, 250 as i32);
                }
                if xmlSkipBlankChars(ctxt) == 0 as i32 {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_SPACE_REQUIRED,
                        b"Space required after 'NDATA'\n\0" as *const u8
                            as *const i8,
                    );
                }
                ndata = xmlParseName(ctxt);
                if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                    && ((*(*ctxt).sax).unparsedEntityDecl).is_some()
                {
                    ((*(*ctxt).sax).unparsedEntityDecl)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, name, literal, URI, ndata);
                }
            } else {
                if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                    && ((*(*ctxt).sax).entityDecl).is_some()
                {
                    ((*(*ctxt).sax).entityDecl)
                        .expect(
                            "non-null function pointer",
                        )(
                        (*ctxt).userData,
                        name,
                        XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32,
                        literal,
                        URI,
                        0 as *mut xmlChar,
                    );
                }
                if (*ctxt).replaceEntities != 0 as i32
                    && (((*ctxt).myDoc).is_null()
                        || xmlStrEqual(
                            (*(*ctxt).myDoc).version,
                            b"SAX compatibility mode document\0" as *const u8
                                as *const i8 as *mut xmlChar,
                        ) != 0)
                {
                    if ((*ctxt).myDoc).is_null() {
                        let fresh248 = &mut ((*ctxt).myDoc);
                        *fresh248 = xmlNewDoc(
                            b"SAX compatibility mode document\0" as *const u8
                                as *const i8 as *mut xmlChar,
                        );
                        if ((*ctxt).myDoc).is_null() {
                            xmlErrMemory(
                                ctxt,
                                b"New Doc failed\0" as *const u8 as *const i8,
                            );
                            return;
                        }
                        (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as i32;
                    }
                    if ((*(*ctxt).myDoc).intSubset).is_null() {
                        let fresh249 = &mut ((*(*ctxt).myDoc).intSubset);
                        *fresh249 = xmlNewDtd(
                            (*ctxt).myDoc,
                            b"fake\0" as *const u8 as *const i8
                                as *mut xmlChar,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                    }
                    xmlSAX2EntityDecl(
                        ctxt as *mut libc::c_void,
                        name,
                        XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32,
                        literal,
                        URI,
                        0 as *mut xmlChar,
                    );
                }
            }
        }
        if !((*ctxt).instate as i32 == XML_PARSER_EOF as i32) {
            xmlSkipBlankChars(ctxt);
            if *(*(*ctxt).input).cur as i32 != '>' as i32 {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_ENTITY_NOT_FINISHED,
                    b"xmlParseEntityDecl: entity %s not terminated\n\0" as *const u8
                        as *const i8,
                    name,
                );
                xmlHaltParser(ctxt);
            } else {
                if inputid != (*(*ctxt).input).id {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ENTITY_BOUNDARY,
                        b"Entity declaration doesn't start and stop in the same entity\n\0"
                            as *const u8 as *const i8,
                    );
                }
                xmlNextChar(ctxt);
            }
            if !orig.is_null() {
                let mut cur: * mut crate::src::HTMLparser::_xmlEntity = 0 as xmlEntityPtr;
                if isParameter != 0 {
                    if !((*ctxt).sax).is_null()
                        && ((*(*ctxt).sax).getParameterEntity).is_some()
                    {
                        cur = ((*(*ctxt).sax).getParameterEntity)
                            .expect("non-null function pointer")((*ctxt).userData, name);
                    }
                } else {
                    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).getEntity).is_some() {
                        cur = ((*(*ctxt).sax).getEntity)
                            .expect("non-null function pointer")((*ctxt).userData, name);
                    }
                    if cur.is_null() && (*ctxt).userData == ctxt as *mut libc::c_void {
                        cur = xmlSAX2GetEntity(ctxt as *mut libc::c_void, name);
                    }
                }
                if !cur.is_null() && ((*cur).orig).is_null() {
                    let fresh250 = &mut ((*cur).orig);
                    *fresh250 = orig;
                    orig = 0 as *mut xmlChar;
                }
            }
        }
        if !value.is_null() {
            xmlFree.expect("non-null function pointer")(value as *mut libc::c_void);
        }
        if !URI.is_null() {
            xmlFree.expect("non-null function pointer")(URI as *mut libc::c_void);
        }
        if !literal.is_null() {
            xmlFree.expect("non-null function pointer")(literal as *mut libc::c_void);
        }
        if !orig.is_null() {
            xmlFree.expect("non-null function pointer")(orig as *mut libc::c_void);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseDefaultDecl<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut value: Option<&'a1 mut * mut u8>,
) -> i32 {
    let mut val: i32 = 0;
    let mut ret: * mut u8 = 0 as *mut xmlChar;
    *(borrow_mut(&mut value)).unwrap() = 0 as *mut xmlChar;
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '#' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == 'R' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'E' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'Q' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'U' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'I' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'R' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(7 as i32 as isize) as i32 == 'E' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(8 as i32 as isize) as i32 == 'D' as i32
    {
        let fresh251 = &mut ((*(*ctxt).input).cur);
        *fresh251 = (*fresh251).offset(9 as i32 as isize);
        (*(*ctxt).input).col += 9 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        return XML_ATTRIBUTE_REQUIRED as i32;
    }
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '#' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == 'I' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'M' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'P' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'L' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'I' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'E' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(7 as i32 as isize) as i32 == 'D' as i32
    {
        let fresh252 = &mut ((*(*ctxt).input).cur);
        *fresh252 = (*fresh252).offset(8 as i32 as isize);
        (*(*ctxt).input).col += 8 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        return XML_ATTRIBUTE_IMPLIED as i32;
    }
    val = XML_ATTRIBUTE_NONE as i32;
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '#' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == 'F' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'I' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'X' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'E' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'D' as i32
    {
        let fresh253 = &mut ((*(*ctxt).input).cur);
        *fresh253 = (*fresh253).offset(6 as i32 as isize);
        (*(*ctxt).input).col += 6 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        val = XML_ATTRIBUTE_FIXED as i32;
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after '#FIXED'\n\0" as *const u8 as *const i8,
            );
        }
    }
    ret = xmlParseAttValue(ctxt);
    (*ctxt).instate = XML_PARSER_DTD;
    if ret.is_null() {
        xmlFatalErrMsg(
            ctxt,
            (*ctxt).errNo as xmlParserErrors,
            b"Attribute default value declaration error\n\0" as *const u8
                as *const i8,
        );
    } else {
        *(borrow_mut(&mut value)).unwrap() = ret;
    }
    return val;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseNotationType(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
) -> * mut crate::src::HTMLparser::_xmlEnumeration {
    let mut name: * const u8 = 0 as *const xmlChar;
    let mut ret: * mut crate::src::HTMLparser::_xmlEnumeration = 0 as xmlEnumerationPtr;
    let mut last: * mut crate::src::HTMLparser::_xmlEnumeration = 0 as xmlEnumerationPtr;
    let mut cur: * mut crate::src::HTMLparser::_xmlEnumeration = 0 as *mut xmlEnumeration;
    let mut tmp: * mut crate::src::HTMLparser::_xmlEnumeration = 0 as *mut xmlEnumeration;
    if *(*(*ctxt).input).cur as i32 != '(' as i32 {
        xmlFatalErr(ctxt, XML_ERR_NOTATION_NOT_STARTED, 0 as *const i8);
        return 0 as xmlEnumerationPtr;
    }
    if (*ctxt).progressive == 0 as i32
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
            > (2 as i32 * 250 as i32) as i64
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    loop {
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        name = xmlParseName(ctxt);
        if name.is_null() {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_NAME_REQUIRED,
                b"Name expected in NOTATION declaration\n\0" as *const u8
                    as *const i8,
            );
            xmlFreeEnumeration(ret);
            return 0 as xmlEnumerationPtr;
        }
        tmp = ret;
        while !tmp.is_null() {
            if xmlStrEqual(name, (*tmp).name) != 0 {
                xmlValidityError(
                    ctxt,
                    XML_DTD_DUP_TOKEN,
                    b"standalone: attribute notation value token %s duplicated\n\0"
                        as *const u8 as *const i8,
                    name,
                    0 as *const xmlChar,
                );
                if xmlDictOwns((*ctxt).dict, name) == 0 {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(name as *mut xmlChar as *mut libc::c_void);
                }
                break;
            } else {
                tmp = (*tmp).next;
            }
        }
        if tmp.is_null() {
            cur = xmlCreateEnumeration(name);
            if cur.is_null() {
                xmlFreeEnumeration(ret);
                return 0 as xmlEnumerationPtr;
            }
            if last.is_null() {
                last = cur;
                ret = last;
            } else {
                let fresh254 = &mut ((*last).next);
                *fresh254 = cur;
                last = cur;
            }
        }
        xmlSkipBlankChars(ctxt);
        if !(*(*(*ctxt).input).cur as i32 == '|' as i32) {
            break;
        }
    }
    if *(*(*ctxt).input).cur as i32 != ')' as i32 {
        xmlFatalErr(ctxt, XML_ERR_NOTATION_NOT_FINISHED, 0 as *const i8);
        xmlFreeEnumeration(ret);
        return 0 as xmlEnumerationPtr;
    }
    xmlNextChar(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEnumerationType(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
) -> * mut crate::src::HTMLparser::_xmlEnumeration {
    let mut name: * mut u8 = 0 as *mut xmlChar;
    let mut ret: * mut crate::src::HTMLparser::_xmlEnumeration = 0 as xmlEnumerationPtr;
    let mut last: * mut crate::src::HTMLparser::_xmlEnumeration = 0 as xmlEnumerationPtr;
    let mut cur: * mut crate::src::HTMLparser::_xmlEnumeration = 0 as *mut xmlEnumeration;
    let mut tmp: * mut crate::src::HTMLparser::_xmlEnumeration = 0 as *mut xmlEnumeration;
    if *(*(*ctxt).input).cur as i32 != '(' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ATTLIST_NOT_STARTED, 0 as *const i8);
        return 0 as xmlEnumerationPtr;
    }
    if (*ctxt).progressive == 0 as i32
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
            > (2 as i32 * 250 as i32) as i64
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    loop {
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        name = xmlParseNmtoken(ctxt);
        if name.is_null() {
            xmlFatalErr(ctxt, XML_ERR_NMTOKEN_REQUIRED, 0 as *const i8);
            return ret;
        }
        tmp = ret;
        while !tmp.is_null() {
            if xmlStrEqual(name, (*tmp).name) != 0 {
                xmlValidityError(
                    ctxt,
                    XML_DTD_DUP_TOKEN,
                    b"standalone: attribute enumeration value token %s duplicated\n\0"
                        as *const u8 as *const i8,
                    name,
                    0 as *const xmlChar,
                );
                if xmlDictOwns((*ctxt).dict, name) == 0 {
                    xmlFree
                        .expect("non-null function pointer")(name as *mut libc::c_void);
                }
                break;
            } else {
                tmp = (*tmp).next;
            }
        }
        if tmp.is_null() {
            cur = xmlCreateEnumeration(name);
            if xmlDictOwns((*ctxt).dict, name) == 0 {
                xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
            }
            if cur.is_null() {
                xmlFreeEnumeration(ret);
                return 0 as xmlEnumerationPtr;
            }
            if last.is_null() {
                last = cur;
                ret = last;
            } else {
                let fresh255 = &mut ((*last).next);
                *fresh255 = cur;
                last = cur;
            }
        }
        xmlSkipBlankChars(ctxt);
        if !(*(*(*ctxt).input).cur as i32 == '|' as i32) {
            break;
        }
    }
    if *(*(*ctxt).input).cur as i32 != ')' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ATTLIST_NOT_FINISHED, 0 as *const i8);
        return ret;
    }
    xmlNextChar(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEnumeratedType<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut tree: Option<&'a1 mut * mut crate::src::HTMLparser::_xmlEnumeration>,
) -> i32 {
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == 'N' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == 'O' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'A' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'I' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'O' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(7 as i32 as isize) as i32 == 'N' as i32
    {
        let fresh256 = &mut ((*(*ctxt).input).cur);
        *fresh256 = (*fresh256).offset(8 as i32 as isize);
        (*(*ctxt).input).col += 8 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after 'NOTATION'\n\0" as *const u8
                    as *const i8,
            );
            return 0 as i32;
        }
        *(borrow_mut(&mut tree)).unwrap() = xmlParseNotationType(ctxt);
        if (*(borrow_mut(&mut tree)).unwrap()).is_null() {
            return 0 as i32;
        }
        return XML_ATTRIBUTE_NOTATION as i32;
    }
    *(borrow_mut(&mut tree)).unwrap() = xmlParseEnumerationType(ctxt);
    if (*(borrow_mut(&mut tree)).unwrap()).is_null() {
        return 0 as i32;
    }
    return XML_ATTRIBUTE_ENUMERATION as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseAttributeType<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut tree: Option<&'a1 mut * mut crate::src::HTMLparser::_xmlEnumeration>,
) -> i32 {
    if (*ctxt).progressive == 0 as i32
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
            > (2 as i32 * 250 as i32) as i64
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == 'C' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == 'D' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'A' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'A' as i32
    {
        let fresh257 = &mut ((*(*ctxt).input).cur);
        *fresh257 = (*fresh257).offset(5 as i32 as isize);
        (*(*ctxt).input).col += 5 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        return XML_ATTRIBUTE_CDATA as i32;
    } else {
        if *((*(*ctxt).input).cur as *mut u8)
            .offset(0 as i32 as isize) as i32 == 'I' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(1 as i32 as isize) as i32 == 'D' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(2 as i32 as isize) as i32 == 'R' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(3 as i32 as isize) as i32 == 'E' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(4 as i32 as isize) as i32 == 'F' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(5 as i32 as isize) as i32 == 'S' as i32
        {
            let fresh258 = &mut ((*(*ctxt).input).cur);
            *fresh258 = (*fresh258).offset(6 as i32 as isize);
            (*(*ctxt).input).col += 6 as i32;
            if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                xmlParserInputGrow((*ctxt).input, 250 as i32);
            }
            return XML_ATTRIBUTE_IDREFS as i32;
        } else {
            if *((*(*ctxt).input).cur as *mut u8)
                .offset(0 as i32 as isize) as i32 == 'I' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(1 as i32 as isize) as i32 == 'D' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(2 as i32 as isize) as i32 == 'R' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(3 as i32 as isize) as i32 == 'E' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(4 as i32 as isize) as i32 == 'F' as i32
            {
                let fresh259 = &mut ((*(*ctxt).input).cur);
                *fresh259 = (*fresh259).offset(5 as i32 as isize);
                (*(*ctxt).input).col += 5 as i32;
                if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                    xmlParserInputGrow((*ctxt).input, 250 as i32);
                }
                return XML_ATTRIBUTE_IDREF as i32;
            } else {
                if *(*(*ctxt).input).cur as i32 == 'I' as i32
                    && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                        as i32 == 'D' as i32
                {
                    let fresh260 = &mut ((*(*ctxt).input).cur);
                    *fresh260 = (*fresh260).offset(2 as i32 as isize);
                    (*(*ctxt).input).col += 2 as i32;
                    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                        xmlParserInputGrow((*ctxt).input, 250 as i32);
                    }
                    return XML_ATTRIBUTE_ID as i32;
                } else {
                    if *((*(*ctxt).input).cur as *mut u8)
                        .offset(0 as i32 as isize) as i32 == 'E' as i32
                        && *((*(*ctxt).input).cur as *mut u8)
                            .offset(1 as i32 as isize) as i32
                            == 'N' as i32
                        && *((*(*ctxt).input).cur as *mut u8)
                            .offset(2 as i32 as isize) as i32
                            == 'T' as i32
                        && *((*(*ctxt).input).cur as *mut u8)
                            .offset(3 as i32 as isize) as i32
                            == 'I' as i32
                        && *((*(*ctxt).input).cur as *mut u8)
                            .offset(4 as i32 as isize) as i32
                            == 'T' as i32
                        && *((*(*ctxt).input).cur as *mut u8)
                            .offset(5 as i32 as isize) as i32
                            == 'Y' as i32
                    {
                        let fresh261 = &mut ((*(*ctxt).input).cur);
                        *fresh261 = (*fresh261).offset(6 as i32 as isize);
                        (*(*ctxt).input).col += 6 as i32;
                        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                            xmlParserInputGrow((*ctxt).input, 250 as i32);
                        }
                        return XML_ATTRIBUTE_ENTITY as i32;
                    } else {
                        if *((*(*ctxt).input).cur as *mut u8)
                            .offset(0 as i32 as isize) as i32
                            == 'E' as i32
                            && *((*(*ctxt).input).cur as *mut u8)
                                .offset(1 as i32 as isize) as i32
                                == 'N' as i32
                            && *((*(*ctxt).input).cur as *mut u8)
                                .offset(2 as i32 as isize) as i32
                                == 'T' as i32
                            && *((*(*ctxt).input).cur as *mut u8)
                                .offset(3 as i32 as isize) as i32
                                == 'I' as i32
                            && *((*(*ctxt).input).cur as *mut u8)
                                .offset(4 as i32 as isize) as i32
                                == 'T' as i32
                            && *((*(*ctxt).input).cur as *mut u8)
                                .offset(5 as i32 as isize) as i32
                                == 'I' as i32
                            && *((*(*ctxt).input).cur as *mut u8)
                                .offset(6 as i32 as isize) as i32
                                == 'E' as i32
                            && *((*(*ctxt).input).cur as *mut u8)
                                .offset(7 as i32 as isize) as i32
                                == 'S' as i32
                        {
                            let fresh262 = &mut ((*(*ctxt).input).cur);
                            *fresh262 = (*fresh262).offset(8 as i32 as isize);
                            (*(*ctxt).input).col += 8 as i32;
                            if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                                xmlParserInputGrow((*ctxt).input, 250 as i32);
                            }
                            return XML_ATTRIBUTE_ENTITIES as i32;
                        } else {
                            if *((*(*ctxt).input).cur as *mut u8)
                                .offset(0 as i32 as isize) as i32
                                == 'N' as i32
                                && *((*(*ctxt).input).cur as *mut u8)
                                    .offset(1 as i32 as isize) as i32
                                    == 'M' as i32
                                && *((*(*ctxt).input).cur as *mut u8)
                                    .offset(2 as i32 as isize) as i32
                                    == 'T' as i32
                                && *((*(*ctxt).input).cur as *mut u8)
                                    .offset(3 as i32 as isize) as i32
                                    == 'O' as i32
                                && *((*(*ctxt).input).cur as *mut u8)
                                    .offset(4 as i32 as isize) as i32
                                    == 'K' as i32
                                && *((*(*ctxt).input).cur as *mut u8)
                                    .offset(5 as i32 as isize) as i32
                                    == 'E' as i32
                                && *((*(*ctxt).input).cur as *mut u8)
                                    .offset(6 as i32 as isize) as i32
                                    == 'N' as i32
                                && *((*(*ctxt).input).cur as *mut u8)
                                    .offset(7 as i32 as isize) as i32
                                    == 'S' as i32
                            {
                                let fresh263 = &mut ((*(*ctxt).input).cur);
                                *fresh263 = (*fresh263).offset(8 as i32 as isize);
                                (*(*ctxt).input).col += 8 as i32;
                                if *(*(*ctxt).input).cur as i32 == 0 as i32
                                {
                                    xmlParserInputGrow((*ctxt).input, 250 as i32);
                                }
                                return XML_ATTRIBUTE_NMTOKENS as i32;
                            } else {
                                if *((*(*ctxt).input).cur as *mut u8)
                                    .offset(0 as i32 as isize) as i32
                                    == 'N' as i32
                                    && *((*(*ctxt).input).cur as *mut u8)
                                        .offset(1 as i32 as isize) as i32
                                        == 'M' as i32
                                    && *((*(*ctxt).input).cur as *mut u8)
                                        .offset(2 as i32 as isize) as i32
                                        == 'T' as i32
                                    && *((*(*ctxt).input).cur as *mut u8)
                                        .offset(3 as i32 as isize) as i32
                                        == 'O' as i32
                                    && *((*(*ctxt).input).cur as *mut u8)
                                        .offset(4 as i32 as isize) as i32
                                        == 'K' as i32
                                    && *((*(*ctxt).input).cur as *mut u8)
                                        .offset(5 as i32 as isize) as i32
                                        == 'E' as i32
                                    && *((*(*ctxt).input).cur as *mut u8)
                                        .offset(6 as i32 as isize) as i32
                                        == 'N' as i32
                                {
                                    let fresh264 = &mut ((*(*ctxt).input).cur);
                                    *fresh264 = (*fresh264).offset(7 as i32 as isize);
                                    (*(*ctxt).input).col += 7 as i32;
                                    if *(*(*ctxt).input).cur as i32 == 0 as i32
                                    {
                                        xmlParserInputGrow((*ctxt).input, 250 as i32);
                                    }
                                    return XML_ATTRIBUTE_NMTOKEN as i32;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return xmlParseEnumeratedType(ctxt, borrow_mut(&mut tree));
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseAttributeListDecl(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut elemName: * const u8 = 0 as *const xmlChar;
    let mut attrName: * const u8 = 0 as *const xmlChar;
    let mut tree: * mut crate::src::HTMLparser::_xmlEnumeration = 0 as *mut xmlEnumeration;
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '<' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == '!' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'A' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'L' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'I' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(7 as i32 as isize) as i32 == 'S' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(8 as i32 as isize) as i32 == 'T' as i32
    {
        let mut inputid: i32 = (*(*ctxt).input).id;
        let fresh265 = &mut ((*(*ctxt).input).cur);
        *fresh265 = (*fresh265).offset(9 as i32 as isize);
        (*(*ctxt).input).col += 9 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after '<!ATTLIST'\n\0" as *const u8
                    as *const i8,
            );
        }
        elemName = xmlParseName(ctxt);
        if elemName.is_null() {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_NAME_REQUIRED,
                b"ATTLIST: no name for Element\n\0" as *const u8 as *const i8,
            );
            return;
        }
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        while *(*(*ctxt).input).cur as i32 != '>' as i32
            && (*ctxt).instate as i32 != XML_PARSER_EOF as i32
        {
            let mut type_0: i32 = 0;
            let mut def: i32 = 0;
            let mut defaultValue: * mut u8 = 0 as *mut xmlChar;
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            tree = 0 as xmlEnumerationPtr;
            attrName = xmlParseName(ctxt);
            if attrName.is_null() {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_NAME_REQUIRED,
                    b"ATTLIST: no name for Attribute\n\0" as *const u8
                        as *const i8,
                );
                break;
            } else {
                if (*ctxt).progressive == 0 as i32
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64) < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if xmlSkipBlankChars(ctxt) == 0 as i32 {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_SPACE_REQUIRED,
                        b"Space required after the attribute name\n\0" as *const u8
                            as *const i8,
                    );
                    break;
                } else {
                    type_0 = xmlParseAttributeType(ctxt, Some(&mut tree));
                    if type_0 <= 0 as i32 {
                        break;
                    }
                    if (*ctxt).progressive == 0 as i32
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as i64) < 250 as i32 as i64
                    {
                        xmlGROW(ctxt);
                    }
                    if xmlSkipBlankChars(ctxt) == 0 as i32 {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_SPACE_REQUIRED,
                            b"Space required after the attribute type\n\0" as *const u8
                                as *const i8,
                        );
                        if !tree.is_null() {
                            xmlFreeEnumeration(tree);
                        }
                        break;
                    } else {
                        def = xmlParseDefaultDecl(ctxt, Some(&mut defaultValue));
                        if def <= 0 as i32 {
                            if !defaultValue.is_null() {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(defaultValue as *mut libc::c_void);
                            }
                            if !tree.is_null() {
                                xmlFreeEnumeration(tree);
                            }
                            break;
                        } else {
                            if type_0 != XML_ATTRIBUTE_CDATA as i32
                                && !defaultValue.is_null()
                            {
                                xmlAttrNormalizeSpace(defaultValue, defaultValue);
                            }
                            if (*ctxt).progressive == 0 as i32
                                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                    as i64) < 250 as i32 as i64
                            {
                                xmlGROW(ctxt);
                            }
                            if *(*(*ctxt).input).cur as i32 != '>' as i32 {
                                if xmlSkipBlankChars(ctxt) == 0 as i32 {
                                    xmlFatalErrMsg(
                                        ctxt,
                                        XML_ERR_SPACE_REQUIRED,
                                        b"Space required after the attribute default value\n\0"
                                            as *const u8 as *const i8,
                                    );
                                    if !defaultValue.is_null() {
                                        xmlFree
                                            .expect(
                                                "non-null function pointer",
                                            )(defaultValue as *mut libc::c_void);
                                    }
                                    if !tree.is_null() {
                                        xmlFreeEnumeration(tree);
                                    }
                                    break;
                                }
                            }
                            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                                && ((*(*ctxt).sax).attributeDecl).is_some()
                            {
                                ((*(*ctxt).sax).attributeDecl)
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    (*ctxt).userData,
                                    elemName,
                                    attrName,
                                    type_0,
                                    def,
                                    defaultValue,
                                    tree,
                                );
                            } else if !tree.is_null() {
                                xmlFreeEnumeration(tree);
                            }
                            if (*ctxt).sax2 != 0 && !defaultValue.is_null()
                                && def != XML_ATTRIBUTE_IMPLIED as i32
                                && def != XML_ATTRIBUTE_REQUIRED as i32
                            {
                                xmlAddDefAttrs(ctxt, elemName, attrName, defaultValue);
                            }
                            if (*ctxt).sax2 != 0 {
                                xmlAddSpecialAttr(ctxt, elemName, attrName, type_0);
                            }
                            if !defaultValue.is_null() {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(defaultValue as *mut libc::c_void);
                            }
                            if (*ctxt).progressive == 0 as i32
                                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                    as i64) < 250 as i32 as i64
                            {
                                xmlGROW(ctxt);
                            }
                        }
                    }
                }
            }
        }
        if *(*(*ctxt).input).cur as i32 == '>' as i32 {
            if inputid != (*(*ctxt).input).id {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Attribute list declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const i8,
                );
            }
            xmlNextChar(ctxt);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseElementMixedContentDecl(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut inputchk: i32,
) -> * mut crate::src::HTMLparser::_xmlElementContent {
    let mut ret: * mut crate::src::HTMLparser::_xmlElementContent = 0 as xmlElementContentPtr;
    let mut cur: * mut crate::src::HTMLparser::_xmlElementContent = 0 as xmlElementContentPtr;
    let mut n: * mut crate::src::HTMLparser::_xmlElementContent = 0 as *mut xmlElementContent;
    let mut elem: * const u8 = 0 as *const xmlChar;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '#' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == 'P' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'C' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'D' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'A' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'A' as i32
    {
        let fresh266 = &mut ((*(*ctxt).input).cur);
        *fresh266 = (*fresh266).offset(7 as i32 as isize);
        (*(*ctxt).input).col += 7 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as i32
            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
                > (2 as i32 * 250 as i32) as i64
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < (2 as i32 * 250 as i32) as i64
        {
            xmlSHRINK(ctxt);
        }
        if *(*(*ctxt).input).cur as i32 == ')' as i32 {
            if (*(*ctxt).input).id != inputchk {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Element content declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const i8,
                );
            }
            xmlNextChar(ctxt);
            ret = xmlNewDocElementContent(
                (*ctxt).myDoc,
                0 as *const xmlChar,
                XML_ELEMENT_CONTENT_PCDATA,
            );
            if ret.is_null() {
                return 0 as xmlElementContentPtr;
            }
            if *(*(*ctxt).input).cur as i32 == '*' as i32 {
                (*ret).ocur = XML_ELEMENT_CONTENT_MULT;
                xmlNextChar(ctxt);
            }
            return ret;
        }
        if *(*(*ctxt).input).cur as i32 == '(' as i32
            || *(*(*ctxt).input).cur as i32 == '|' as i32
        {
            cur = xmlNewDocElementContent(
                (*ctxt).myDoc,
                0 as *const xmlChar,
                XML_ELEMENT_CONTENT_PCDATA,
            );
            ret = cur;
            if ret.is_null() {
                return 0 as xmlElementContentPtr;
            }
        }
        while *(*(*ctxt).input).cur as i32 == '|' as i32
            && (*ctxt).instate as i32 != XML_PARSER_EOF as i32
        {
            xmlNextChar(ctxt);
            if elem.is_null() {
                ret = xmlNewDocElementContent(
                    (*ctxt).myDoc,
                    0 as *const xmlChar,
                    XML_ELEMENT_CONTENT_OR,
                );
                if ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, cur);
                    return 0 as xmlElementContentPtr;
                }
                let fresh267 = &mut ((*ret).c1);
                *fresh267 = cur;
                if !cur.is_null() {
                    let fresh268 = &mut ((*cur).parent);
                    *fresh268 = ret;
                }
                cur = ret;
            } else {
                n = xmlNewDocElementContent(
                    (*ctxt).myDoc,
                    0 as *const xmlChar,
                    XML_ELEMENT_CONTENT_OR,
                );
                if n.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                    return 0 as xmlElementContentPtr;
                }
                let fresh269 = &mut ((*n).c1);
                *fresh269 = xmlNewDocElementContent(
                    (*ctxt).myDoc,
                    elem,
                    XML_ELEMENT_CONTENT_ELEMENT,
                );
                if !((*n).c1).is_null() {
                    let fresh270 = &mut ((*(*n).c1).parent);
                    *fresh270 = n;
                }
                let fresh271 = &mut ((*cur).c2);
                *fresh271 = n;
                if !n.is_null() {
                    let fresh272 = &mut ((*n).parent);
                    *fresh272 = cur;
                }
                cur = n;
            }
            xmlSkipBlankChars(ctxt);
            elem = xmlParseName(ctxt);
            if elem.is_null() {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_NAME_REQUIRED,
                    b"xmlParseElementMixedContentDecl : Name expected\n\0" as *const u8
                        as *const i8,
                );
                xmlFreeDocElementContent((*ctxt).myDoc, ret);
                return 0 as xmlElementContentPtr;
            }
            xmlSkipBlankChars(ctxt);
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
        }
        if *(*(*ctxt).input).cur as i32 == ')' as i32
            && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
                == '*' as i32
        {
            if !elem.is_null() {
                let fresh273 = &mut ((*cur).c2);
                *fresh273 = xmlNewDocElementContent(
                    (*ctxt).myDoc,
                    elem,
                    XML_ELEMENT_CONTENT_ELEMENT,
                );
                if !((*cur).c2).is_null() {
                    let fresh274 = &mut ((*(*cur).c2).parent);
                    *fresh274 = cur;
                }
            }
            if !ret.is_null() {
                (*ret).ocur = XML_ELEMENT_CONTENT_MULT;
            }
            if (*(*ctxt).input).id != inputchk {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Element content declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const i8,
                );
            }
            let fresh275 = &mut ((*(*ctxt).input).cur);
            *fresh275 = (*fresh275).offset(2 as i32 as isize);
            (*(*ctxt).input).col += 2 as i32;
            if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                xmlParserInputGrow((*ctxt).input, 250 as i32);
            }
        } else {
            xmlFreeDocElementContent((*ctxt).myDoc, ret);
            xmlFatalErr(ctxt, XML_ERR_MIXED_NOT_STARTED, 0 as *const i8);
            return 0 as xmlElementContentPtr;
        }
    } else {
        xmlFatalErr(ctxt, XML_ERR_PCDATA_REQUIRED, 0 as *const i8);
    }
    return ret;
}
unsafe extern "C" fn xmlParseElementChildrenContentDeclPriv(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut inputchk: i32,
    mut depth: i32,
) -> * mut crate::src::HTMLparser::_xmlElementContent {
    let mut ret: * mut crate::src::HTMLparser::_xmlElementContent = 0 as xmlElementContentPtr;
    let mut cur: * mut crate::src::HTMLparser::_xmlElementContent = 0 as xmlElementContentPtr;
    let mut last: * mut crate::src::HTMLparser::_xmlElementContent = 0 as xmlElementContentPtr;
    let mut op: * mut crate::src::HTMLparser::_xmlElementContent = 0 as xmlElementContentPtr;
    let mut elem: * const u8 = 0 as *const xmlChar;
    let mut type_0: u8 = 0 as i32 as xmlChar;
    if depth > 128 as i32
        && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
        || depth > 2048 as i32
    {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_ELEMCONTENT_NOT_FINISHED,
            b"xmlParseElementChildrenContentDecl : depth %d too deep, use XML_PARSE_HUGE\n\0"
                as *const u8 as *const i8,
            depth,
        );
        return 0 as xmlElementContentPtr;
    }
    xmlSkipBlankChars(ctxt);
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if *(*(*ctxt).input).cur as i32 == '(' as i32 {
        let mut inputid: i32 = (*(*ctxt).input).id;
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        ret = xmlParseElementChildrenContentDeclPriv(
            ctxt,
            inputid,
            depth + 1 as i32,
        );
        cur = ret;
        if cur.is_null() {
            return 0 as xmlElementContentPtr;
        }
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
    } else {
        elem = xmlParseName(ctxt);
        if elem.is_null() {
            xmlFatalErr(ctxt, XML_ERR_ELEMCONTENT_NOT_STARTED, 0 as *const i8);
            return 0 as xmlElementContentPtr;
        }
        ret = xmlNewDocElementContent((*ctxt).myDoc, elem, XML_ELEMENT_CONTENT_ELEMENT);
        cur = ret;
        if cur.is_null() {
            xmlErrMemory(ctxt, 0 as *const i8);
            return 0 as xmlElementContentPtr;
        }
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if *(*(*ctxt).input).cur as i32 == '?' as i32 {
            (*cur).ocur = XML_ELEMENT_CONTENT_OPT;
            xmlNextChar(ctxt);
        } else if *(*(*ctxt).input).cur as i32 == '*' as i32 {
            (*cur).ocur = XML_ELEMENT_CONTENT_MULT;
            xmlNextChar(ctxt);
        } else if *(*(*ctxt).input).cur as i32 == '+' as i32 {
            (*cur).ocur = XML_ELEMENT_CONTENT_PLUS;
            xmlNextChar(ctxt);
        } else {
            (*cur).ocur = XML_ELEMENT_CONTENT_ONCE;
        }
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
    }
    xmlSkipBlankChars(ctxt);
    if (*ctxt).progressive == 0 as i32
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
            > (2 as i32 * 250 as i32) as i64
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    while *(*(*ctxt).input).cur as i32 != ')' as i32
        && (*ctxt).instate as i32 != XML_PARSER_EOF as i32
    {
        if *(*(*ctxt).input).cur as i32 == ',' as i32 {
            if type_0 as i32 == 0 as i32 {
                type_0 = *(*(*ctxt).input).cur;
            } else if type_0 as i32 != *(*(*ctxt).input).cur as i32 {
                xmlFatalErrMsgInt(
                    ctxt,
                    XML_ERR_SEPARATOR_REQUIRED,
                    b"xmlParseElementChildrenContentDecl : '%c' expected\n\0"
                        as *const u8 as *const i8,
                    type_0 as i32,
                );
                if !last.is_null() && last != ret {
                    xmlFreeDocElementContent((*ctxt).myDoc, last);
                }
                if !ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                }
                return 0 as xmlElementContentPtr;
            }
            xmlNextChar(ctxt);
            op = xmlNewDocElementContent(
                (*ctxt).myDoc,
                0 as *const xmlChar,
                XML_ELEMENT_CONTENT_SEQ,
            );
            if op.is_null() {
                if !last.is_null() && last != ret {
                    xmlFreeDocElementContent((*ctxt).myDoc, last);
                }
                xmlFreeDocElementContent((*ctxt).myDoc, ret);
                return 0 as xmlElementContentPtr;
            }
            if last.is_null() {
                let fresh276 = &mut ((*op).c1);
                *fresh276 = ret;
                if !ret.is_null() {
                    let fresh277 = &mut ((*ret).parent);
                    *fresh277 = op;
                }
                cur = op;
                ret = cur;
            } else {
                let fresh278 = &mut ((*cur).c2);
                *fresh278 = op;
                if !op.is_null() {
                    let fresh279 = &mut ((*op).parent);
                    *fresh279 = cur;
                }
                let fresh280 = &mut ((*op).c1);
                *fresh280 = last;
                if !last.is_null() {
                    let fresh281 = &mut ((*last).parent);
                    *fresh281 = op;
                }
                cur = op;
                last = 0 as xmlElementContentPtr;
            }
        } else if *(*(*ctxt).input).cur as i32 == '|' as i32 {
            if type_0 as i32 == 0 as i32 {
                type_0 = *(*(*ctxt).input).cur;
            } else if type_0 as i32 != *(*(*ctxt).input).cur as i32 {
                xmlFatalErrMsgInt(
                    ctxt,
                    XML_ERR_SEPARATOR_REQUIRED,
                    b"xmlParseElementChildrenContentDecl : '%c' expected\n\0"
                        as *const u8 as *const i8,
                    type_0 as i32,
                );
                if !last.is_null() && last != ret {
                    xmlFreeDocElementContent((*ctxt).myDoc, last);
                }
                if !ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                }
                return 0 as xmlElementContentPtr;
            }
            xmlNextChar(ctxt);
            op = xmlNewDocElementContent(
                (*ctxt).myDoc,
                0 as *const xmlChar,
                XML_ELEMENT_CONTENT_OR,
            );
            if op.is_null() {
                if !last.is_null() && last != ret {
                    xmlFreeDocElementContent((*ctxt).myDoc, last);
                }
                if !ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                }
                return 0 as xmlElementContentPtr;
            }
            if last.is_null() {
                let fresh282 = &mut ((*op).c1);
                *fresh282 = ret;
                if !ret.is_null() {
                    let fresh283 = &mut ((*ret).parent);
                    *fresh283 = op;
                }
                cur = op;
                ret = cur;
            } else {
                let fresh284 = &mut ((*cur).c2);
                *fresh284 = op;
                if !op.is_null() {
                    let fresh285 = &mut ((*op).parent);
                    *fresh285 = cur;
                }
                let fresh286 = &mut ((*op).c1);
                *fresh286 = last;
                if !last.is_null() {
                    let fresh287 = &mut ((*last).parent);
                    *fresh287 = op;
                }
                cur = op;
                last = 0 as xmlElementContentPtr;
            }
        } else {
            xmlFatalErr(
                ctxt,
                XML_ERR_ELEMCONTENT_NOT_FINISHED,
                0 as *const i8,
            );
            if !last.is_null() && last != ret {
                xmlFreeDocElementContent((*ctxt).myDoc, last);
            }
            if !ret.is_null() {
                xmlFreeDocElementContent((*ctxt).myDoc, ret);
            }
            return 0 as xmlElementContentPtr;
        }
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if *(*(*ctxt).input).cur as i32 == '(' as i32 {
            let mut inputid_0: i32 = (*(*ctxt).input).id;
            xmlNextChar(ctxt);
            xmlSkipBlankChars(ctxt);
            last = xmlParseElementChildrenContentDeclPriv(
                ctxt,
                inputid_0,
                depth + 1 as i32,
            );
            if last.is_null() {
                if !ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                }
                return 0 as xmlElementContentPtr;
            }
            xmlSkipBlankChars(ctxt);
        } else {
            elem = xmlParseName(ctxt);
            if elem.is_null() {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_ELEMCONTENT_NOT_STARTED,
                    0 as *const i8,
                );
                if !ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                }
                return 0 as xmlElementContentPtr;
            }
            last = xmlNewDocElementContent(
                (*ctxt).myDoc,
                elem,
                XML_ELEMENT_CONTENT_ELEMENT,
            );
            if last.is_null() {
                if !ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                }
                return 0 as xmlElementContentPtr;
            }
            if *(*(*ctxt).input).cur as i32 == '?' as i32 {
                (*last).ocur = XML_ELEMENT_CONTENT_OPT;
                xmlNextChar(ctxt);
            } else if *(*(*ctxt).input).cur as i32 == '*' as i32 {
                (*last).ocur = XML_ELEMENT_CONTENT_MULT;
                xmlNextChar(ctxt);
            } else if *(*(*ctxt).input).cur as i32 == '+' as i32 {
                (*last).ocur = XML_ELEMENT_CONTENT_PLUS;
                xmlNextChar(ctxt);
            } else {
                (*last).ocur = XML_ELEMENT_CONTENT_ONCE;
            }
        }
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
    }
    if !cur.is_null() && !last.is_null() {
        let fresh288 = &mut ((*cur).c2);
        *fresh288 = last;
        if !last.is_null() {
            let fresh289 = &mut ((*last).parent);
            *fresh289 = cur;
        }
    }
    if (*(*ctxt).input).id != inputchk {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_ENTITY_BOUNDARY,
            b"Element content declaration doesn't start and stop in the same entity\n\0"
                as *const u8 as *const i8,
        );
    }
    xmlNextChar(ctxt);
    if *(*(*ctxt).input).cur as i32 == '?' as i32 {
        if !ret.is_null() {
            if (*ret).ocur as u32
                == XML_ELEMENT_CONTENT_PLUS as i32 as u32
                || (*ret).ocur as u32
                    == XML_ELEMENT_CONTENT_MULT as i32 as u32
            {
                (*ret).ocur = XML_ELEMENT_CONTENT_MULT;
            } else {
                (*ret).ocur = XML_ELEMENT_CONTENT_OPT;
            }
        }
        xmlNextChar(ctxt);
    } else if *(*(*ctxt).input).cur as i32 == '*' as i32 {
        if !ret.is_null() {
            (*ret).ocur = XML_ELEMENT_CONTENT_MULT;
            cur = ret;
            while !cur.is_null()
                && (*cur).type_0 as u32
                    == XML_ELEMENT_CONTENT_OR as i32 as u32
            {
                if !((*cur).c1).is_null()
                    && ((*(*cur).c1).ocur as u32
                        == XML_ELEMENT_CONTENT_OPT as i32 as u32
                        || (*(*cur).c1).ocur as u32
                            == XML_ELEMENT_CONTENT_MULT as i32 as u32)
                {
                    (*(*cur).c1).ocur = XML_ELEMENT_CONTENT_ONCE;
                }
                if !((*cur).c2).is_null()
                    && ((*(*cur).c2).ocur as u32
                        == XML_ELEMENT_CONTENT_OPT as i32 as u32
                        || (*(*cur).c2).ocur as u32
                            == XML_ELEMENT_CONTENT_MULT as i32 as u32)
                {
                    (*(*cur).c2).ocur = XML_ELEMENT_CONTENT_ONCE;
                }
                cur = (*cur).c2;
            }
        }
        xmlNextChar(ctxt);
    } else if *(*(*ctxt).input).cur as i32 == '+' as i32 {
        if !ret.is_null() {
            let mut found: i32 = 0 as i32;
            if (*ret).ocur as u32
                == XML_ELEMENT_CONTENT_OPT as i32 as u32
                || (*ret).ocur as u32
                    == XML_ELEMENT_CONTENT_MULT as i32 as u32
            {
                (*ret).ocur = XML_ELEMENT_CONTENT_MULT;
            } else {
                (*ret).ocur = XML_ELEMENT_CONTENT_PLUS;
            }
            while !cur.is_null()
                && (*cur).type_0 as u32
                    == XML_ELEMENT_CONTENT_OR as i32 as u32
            {
                if !((*cur).c1).is_null()
                    && ((*(*cur).c1).ocur as u32
                        == XML_ELEMENT_CONTENT_OPT as i32 as u32
                        || (*(*cur).c1).ocur as u32
                            == XML_ELEMENT_CONTENT_MULT as i32 as u32)
                {
                    (*(*cur).c1).ocur = XML_ELEMENT_CONTENT_ONCE;
                    found = 1 as i32;
                }
                if !((*cur).c2).is_null()
                    && ((*(*cur).c2).ocur as u32
                        == XML_ELEMENT_CONTENT_OPT as i32 as u32
                        || (*(*cur).c2).ocur as u32
                            == XML_ELEMENT_CONTENT_MULT as i32 as u32)
                {
                    (*(*cur).c2).ocur = XML_ELEMENT_CONTENT_ONCE;
                    found = 1 as i32;
                }
                cur = (*cur).c2;
            }
            if found != 0 {
                (*ret).ocur = XML_ELEMENT_CONTENT_MULT;
            }
        }
        xmlNextChar(ctxt);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseElementChildrenContentDecl(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut inputchk: i32,
) -> * mut crate::src::HTMLparser::_xmlElementContent {
    return xmlParseElementChildrenContentDeclPriv(ctxt, inputchk, 1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseElementContentDecl<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut name: * const u8,
    mut result: Option<&'a1 mut * mut crate::src::HTMLparser::_xmlElementContent>,
) -> i32 {
    let mut tree: * mut crate::src::HTMLparser::_xmlElementContent = 0 as xmlElementContentPtr;
    let mut inputid: i32 = (*(*ctxt).input).id;
    let mut res: i32 = 0;
    *(borrow_mut(&mut result)).unwrap() = 0 as xmlElementContentPtr;
    if *(*(*ctxt).input).cur as i32 != '(' as i32 {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ELEMCONTENT_NOT_STARTED,
            b"xmlParseElementContentDecl : %s '(' expected\n\0" as *const u8
                as *const i8,
            name,
        );
        return -(1 as i32);
    }
    xmlNextChar(ctxt);
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    xmlSkipBlankChars(ctxt);
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '#' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == 'P' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'C' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'D' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'A' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'A' as i32
    {
        tree = xmlParseElementMixedContentDecl(ctxt, inputid);
        res = XML_ELEMENT_TYPE_MIXED as i32;
    } else {
        tree = xmlParseElementChildrenContentDeclPriv(ctxt, inputid, 1 as i32);
        res = XML_ELEMENT_TYPE_ELEMENT as i32;
    }
    xmlSkipBlankChars(ctxt);
    *(borrow_mut(&mut result)).unwrap() = tree;
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseElementDecl(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> i32 {
    let mut name: * const u8 = 0 as *const xmlChar;
    let mut ret: i32 = -(1 as i32);
    let mut content: * mut crate::src::HTMLparser::_xmlElementContent = 0 as xmlElementContentPtr;
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '<' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == '!' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'E' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'L' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'E' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'M' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'E' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(7 as i32 as isize) as i32 == 'N' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(8 as i32 as isize) as i32 == 'T' as i32
    {
        let mut inputid: i32 = (*(*ctxt).input).id;
        let fresh290 = &mut ((*(*ctxt).input).cur);
        *fresh290 = (*fresh290).offset(9 as i32 as isize);
        (*(*ctxt).input).col += 9 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after 'ELEMENT'\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        name = xmlParseName(ctxt);
        if name.is_null() {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_NAME_REQUIRED,
                b"xmlParseElementDecl: no name for Element\n\0" as *const u8
                    as *const i8,
            );
            return -(1 as i32);
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after the element name\n\0" as *const u8
                    as *const i8,
            );
        }
        if *((*(*ctxt).input).cur as *mut u8)
            .offset(0 as i32 as isize) as i32 == 'E' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(1 as i32 as isize) as i32 == 'M' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(2 as i32 as isize) as i32 == 'P' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(3 as i32 as isize) as i32 == 'T' as i32
            && *((*(*ctxt).input).cur as *mut u8)
                .offset(4 as i32 as isize) as i32 == 'Y' as i32
        {
            let fresh291 = &mut ((*(*ctxt).input).cur);
            *fresh291 = (*fresh291).offset(5 as i32 as isize);
            (*(*ctxt).input).col += 5 as i32;
            if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                xmlParserInputGrow((*ctxt).input, 250 as i32);
            }
            ret = XML_ELEMENT_TYPE_EMPTY as i32;
        } else if *(*(*ctxt).input).cur as i32 == 'A' as i32
                && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == 'N' as i32
                && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                    as i32 == 'Y' as i32
            {
            let fresh292 = &mut ((*(*ctxt).input).cur);
            *fresh292 = (*fresh292).offset(3 as i32 as isize);
            (*(*ctxt).input).col += 3 as i32;
            if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                xmlParserInputGrow((*ctxt).input, 250 as i32);
            }
            ret = XML_ELEMENT_TYPE_ANY as i32;
        } else if *(*(*ctxt).input).cur as i32 == '(' as i32 {
            ret = xmlParseElementContentDecl(ctxt, name, Some(&mut content));
        } else {
            if *(*(*ctxt).input).cur as i32 == '%' as i32
                && (*ctxt).external == 0 as i32
                && (*ctxt).inputNr == 1 as i32
            {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_PEREF_IN_INT_SUBSET,
                    b"PEReference: forbidden within markup decl in internal subset\n\0"
                        as *const u8 as *const i8,
                );
            } else {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ELEMCONTENT_NOT_STARTED,
                    b"xmlParseElementDecl: 'EMPTY', 'ANY' or '(' expected\n\0"
                        as *const u8 as *const i8,
                );
            }
            return -(1 as i32);
        }
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as i32 != '>' as i32 {
            xmlFatalErr(ctxt, XML_ERR_GT_REQUIRED, 0 as *const i8);
            if !content.is_null() {
                xmlFreeDocElementContent((*ctxt).myDoc, content);
            }
        } else {
            if inputid != (*(*ctxt).input).id {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Element declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const i8,
                );
            }
            xmlNextChar(ctxt);
            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                && ((*(*ctxt).sax).elementDecl).is_some()
            {
                if !content.is_null() {
                    let fresh293 = &mut ((*content).parent);
                    *fresh293 = 0 as *mut _xmlElementContent;
                }
                ((*(*ctxt).sax).elementDecl)
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).userData, name, ret, content);
                if !content.is_null() && ((*content).parent).is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, content);
                }
            } else if !content.is_null() {
                xmlFreeDocElementContent((*ctxt).myDoc, content);
            }
        }
    }
    return ret;
}
unsafe extern "C" fn xmlParseConditionalSections(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut inputIds: * mut i32 = 0 as *mut i32;
    let mut inputIdsSize: u64 = 0 as i32 as size_t;
    let mut depth: u64 = 0 as i32 as size_t;
    's_11: while (*ctxt).instate as i32 != XML_PARSER_EOF as i32 {
        if *(*(*ctxt).input).cur as i32 == '<' as i32
            && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
                == '!' as i32
            && *((*(*ctxt).input).cur).offset(2 as i32 as isize) as i32
                == '[' as i32
        {
            let mut id: i32 = (*(*ctxt).input).id;
            let fresh294 = &mut ((*(*ctxt).input).cur);
            *fresh294 = (*fresh294).offset(3 as i32 as isize);
            (*(*ctxt).input).col += 3 as i32;
            if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                xmlParserInputGrow((*ctxt).input, 250 as i32);
            }
            xmlSkipBlankChars(ctxt);
            if *((*(*ctxt).input).cur as *mut u8)
                .offset(0 as i32 as isize) as i32 == 'I' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(1 as i32 as isize) as i32 == 'N' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(2 as i32 as isize) as i32 == 'C' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(3 as i32 as isize) as i32 == 'L' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(4 as i32 as isize) as i32 == 'U' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(5 as i32 as isize) as i32 == 'D' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(6 as i32 as isize) as i32 == 'E' as i32
            {
                let fresh295 = &mut ((*(*ctxt).input).cur);
                *fresh295 = (*fresh295).offset(7 as i32 as isize);
                (*(*ctxt).input).col += 7 as i32;
                if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                    xmlParserInputGrow((*ctxt).input, 250 as i32);
                }
                xmlSkipBlankChars(ctxt);
                if *(*(*ctxt).input).cur as i32 != '[' as i32 {
                    xmlFatalErr(ctxt, XML_ERR_CONDSEC_INVALID, 0 as *const i8);
                    xmlHaltParser(ctxt);
                    break;
                } else {
                    if (*(*ctxt).input).id != id {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_ENTITY_BOUNDARY,
                            b"All markup of the conditional section is not in the same entity\n\0"
                                as *const u8 as *const i8,
                        );
                    }
                    xmlNextChar(ctxt);
                    if inputIdsSize <= depth {
                        let mut tmp: * mut i32 = 0 as *mut i32;
                        inputIdsSize = if inputIdsSize
                            == 0 as i32 as u64
                        {
                            4 as i32 as u64
                        } else {
                            inputIdsSize.wrapping_mul(2 as i32 as u64)
                        };
                        tmp = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(
                            inputIds as *mut libc::c_void,
                            inputIdsSize
                                .wrapping_mul(
                                    ::std::mem::size_of::<i32>() as u64,
                                ),
                        ) as *mut i32;
                        if tmp.is_null() {
                            xmlErrMemory(ctxt, 0 as *const i8);
                            break;
                        } else {
                            inputIds = tmp;
                        }
                    }
                    *inputIds.offset(depth as isize) = id;
                    depth = depth.wrapping_add(1);
                }
            } else if *((*(*ctxt).input).cur as *mut u8)
                    .offset(0 as i32 as isize) as i32 == 'I' as i32
                    && *((*(*ctxt).input).cur as *mut u8)
                        .offset(1 as i32 as isize) as i32 == 'G' as i32
                    && *((*(*ctxt).input).cur as *mut u8)
                        .offset(2 as i32 as isize) as i32 == 'N' as i32
                    && *((*(*ctxt).input).cur as *mut u8)
                        .offset(3 as i32 as isize) as i32 == 'O' as i32
                    && *((*(*ctxt).input).cur as *mut u8)
                        .offset(4 as i32 as isize) as i32 == 'R' as i32
                    && *((*(*ctxt).input).cur as *mut u8)
                        .offset(5 as i32 as isize) as i32 == 'E' as i32
                {
                let mut state: i32 = 0;
                let mut instate: i32 = XML_PARSER_START;
                let mut ignoreDepth: u64 = 0 as i32 as size_t;
                let fresh296 = &mut ((*(*ctxt).input).cur);
                *fresh296 = (*fresh296).offset(6 as i32 as isize);
                (*(*ctxt).input).col += 6 as i32;
                if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                    xmlParserInputGrow((*ctxt).input, 250 as i32);
                }
                xmlSkipBlankChars(ctxt);
                if *(*(*ctxt).input).cur as i32 != '[' as i32 {
                    xmlFatalErr(ctxt, XML_ERR_CONDSEC_INVALID, 0 as *const i8);
                    xmlHaltParser(ctxt);
                    break;
                } else {
                    if (*(*ctxt).input).id != id {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_ENTITY_BOUNDARY,
                            b"All markup of the conditional section is not in the same entity\n\0"
                                as *const u8 as *const i8,
                        );
                    }
                    xmlNextChar(ctxt);
                    state = (*ctxt).disableSAX;
                    instate = (*ctxt).instate;
                    if (*ctxt).recovery == 0 as i32 {
                        (*ctxt).disableSAX = 1 as i32;
                    }
                    (*ctxt).instate = XML_PARSER_IGNORE;
                    while *(*(*ctxt).input).cur as i32 != 0 as i32 {
                        if *(*(*ctxt).input).cur as i32 == '<' as i32
                            && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                                as i32 == '!' as i32
                            && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                                as i32 == '[' as i32
                        {
                            let fresh297 = &mut ((*(*ctxt).input).cur);
                            *fresh297 = (*fresh297).offset(3 as i32 as isize);
                            (*(*ctxt).input).col += 3 as i32;
                            if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                                xmlParserInputGrow((*ctxt).input, 250 as i32);
                            }
                            ignoreDepth = ignoreDepth.wrapping_add(1);
                            if !(ignoreDepth == 0 as i32 as u64) {
                                continue;
                            }
                            xmlErrMemory(ctxt, 0 as *const i8);
                            break 's_11;
                        } else if *(*(*ctxt).input).cur as i32 == ']' as i32
                                && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                                    as i32 == ']' as i32
                                && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                                    as i32 == '>' as i32
                            {
                            if ignoreDepth == 0 as i32 as u64 {
                                break;
                            }
                            let fresh298 = &mut ((*(*ctxt).input).cur);
                            *fresh298 = (*fresh298).offset(3 as i32 as isize);
                            (*(*ctxt).input).col += 3 as i32;
                            if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                                xmlParserInputGrow((*ctxt).input, 250 as i32);
                            }
                            ignoreDepth = ignoreDepth.wrapping_sub(1);
                        } else {
                            xmlNextChar(ctxt);
                        }
                    }
                    (*ctxt).disableSAX = state;
                    (*ctxt).instate = instate;
                    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_CONDSEC_NOT_FINISHED,
                            0 as *const i8,
                        );
                        break;
                    } else {
                        if (*(*ctxt).input).id != id {
                            xmlFatalErrMsg(
                                ctxt,
                                XML_ERR_ENTITY_BOUNDARY,
                                b"All markup of the conditional section is not in the same entity\n\0"
                                    as *const u8 as *const i8,
                            );
                        }
                        let fresh299 = &mut ((*(*ctxt).input).cur);
                        *fresh299 = (*fresh299).offset(3 as i32 as isize);
                        (*(*ctxt).input).col += 3 as i32;
                        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                            xmlParserInputGrow((*ctxt).input, 250 as i32);
                        }
                    }
                }
            } else {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_CONDSEC_INVALID_KEYWORD,
                    0 as *const i8,
                );
                xmlHaltParser(ctxt);
                break;
            }
        } else if depth > 0 as i32 as u64
                && *(*(*ctxt).input).cur as i32 == ']' as i32
                && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == ']' as i32
                && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                    as i32 == '>' as i32
            {
            depth = depth.wrapping_sub(1);
            if (*(*ctxt).input).id != *inputIds.offset(depth as isize) {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"All markup of the conditional section is not in the same entity\n\0"
                        as *const u8 as *const i8,
                );
            }
            let fresh300 = &mut ((*(*ctxt).input).cur);
            *fresh300 = (*fresh300).offset(3 as i32 as isize);
            (*(*ctxt).input).col += 3 as i32;
            if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                xmlParserInputGrow((*ctxt).input, 250 as i32);
            }
        } else {
            let mut id_0: i32 = (*(*ctxt).input).id;
            let mut cons: u64 = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as i64 as u64,
                );
            xmlParseMarkupDecl(ctxt);
            if id_0 == (*(*ctxt).input).id
                && cons
                    == ((*(*ctxt).input).consumed)
                        .wrapping_add(
                            ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as i64 as u64,
                        )
            {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_EXT_SUBSET_NOT_FINISHED,
                    0 as *const i8,
                );
                xmlHaltParser(ctxt);
                break;
            }
        }
        if depth == 0 as i32 as u64 {
            break;
        }
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
    }
    xmlFree.expect("non-null function pointer")(inputIds as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseMarkupDecl(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if *(*(*ctxt).input).cur as i32 == '<' as i32 {
        if *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            == '!' as i32
        {
            match *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                as i32
            {
                69 => {
                    if *((*(*ctxt).input).cur).offset(3 as i32 as isize)
                        as i32 == 'L' as i32
                    {
                        xmlParseElementDecl(ctxt);
                    } else if *((*(*ctxt).input).cur).offset(3 as i32 as isize)
                            as i32 == 'N' as i32
                        {
                        xmlParseEntityDecl(ctxt);
                    }
                }
                65 => {
                    xmlParseAttributeListDecl(ctxt);
                }
                78 => {
                    xmlParseNotationDecl(ctxt);
                }
                45 => {
                    xmlParseComment(ctxt);
                }
                _ => {}
            }
        } else if *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                as i32 == '?' as i32
            {
            xmlParsePI(ctxt);
        }
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return;
    }
    (*ctxt).instate = XML_PARSER_DTD;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseTextDecl(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut version: * mut u8 = 0 as *mut xmlChar;
    let mut encoding: * const u8 = 0 as *const xmlChar;
    let mut oldstate: i32 = 0;
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '<' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == '?' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'x' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'm' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'l' as i32
        && (*((*(*ctxt).input).cur).offset(5 as i32 as isize) as i32
            == 0x20 as i32
            || 0x9 as i32
                <= *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                    as i32
                && *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                    as i32 <= 0xa as i32
            || *((*(*ctxt).input).cur).offset(5 as i32 as isize) as i32
                == 0xd as i32)
    {
        let fresh301 = &mut ((*(*ctxt).input).cur);
        *fresh301 = (*fresh301).offset(5 as i32 as isize);
        (*(*ctxt).input).col += 5 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
    } else {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_STARTED, 0 as *const i8);
        return;
    }
    oldstate = (*ctxt).instate as i32;
    (*ctxt).instate = XML_PARSER_START;
    if xmlSkipBlankChars(ctxt) == 0 as i32 {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_SPACE_REQUIRED,
            b"Space needed after '<?xml'\n\0" as *const u8 as *const i8,
        );
    }
    version = xmlParseVersionInfo(ctxt);
    if version.is_null() {
        version = xmlCharStrdup(b"1.0\0" as *const u8 as *const i8);
    } else if xmlSkipBlankChars(ctxt) == 0 as i32 {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_SPACE_REQUIRED,
            b"Space needed here\n\0" as *const u8 as *const i8,
        );
    }
    let fresh302 = &mut ((*(*ctxt).input).version);
    *fresh302 = version;
    encoding = xmlParseEncodingDecl(ctxt);
    if (*ctxt).errNo == XML_ERR_UNSUPPORTED_ENCODING as i32 {
        (*ctxt).instate = oldstate as xmlParserInputState;
        return;
    }
    if encoding.is_null() && (*ctxt).errNo == XML_ERR_OK as i32 {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_MISSING_ENCODING,
            b"Missing encoding in text declaration\n\0" as *const u8
                as *const i8,
        );
    }
    xmlSkipBlankChars(ctxt);
    if *(*(*ctxt).input).cur as i32 == '?' as i32
        && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            == '>' as i32
    {
        let fresh303 = &mut ((*(*ctxt).input).cur);
        *fresh303 = (*fresh303).offset(2 as i32 as isize);
        (*(*ctxt).input).col += 2 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
    } else if *(*(*ctxt).input).cur as i32 == '>' as i32 {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, 0 as *const i8);
        xmlNextChar(ctxt);
    } else {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, 0 as *const i8);
        while *(*(*ctxt).input).cur as i32 != 0
            && *(*(*ctxt).input).cur as i32 != '>' as i32
        {
            let fresh304 = &mut ((*(*ctxt).input).cur);
            *fresh304 = (*fresh304).offset(1);
        }
        xmlNextChar(ctxt);
    }
    (*ctxt).instate = oldstate as xmlParserInputState;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseExternalSubset(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut ExternalID: * const u8,
    mut SystemID: * const u8,
) {
    xmlDetectSAX2(ctxt);
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if ((*ctxt).encoding).is_null()
        && ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64
            >= 4 as i32 as i64
    {
        let mut start: [u8; 4] = [0; 4];
        let mut enc: i32 = XML_CHAR_ENCODING_NONE;
        start[0 as i32 as usize] = *(*(*ctxt).input).cur;
        start[1 as i32
            as usize] = *((*(*ctxt).input).cur).offset(1 as i32 as isize);
        start[2 as i32
            as usize] = *((*(*ctxt).input).cur).offset(2 as i32 as isize);
        start[3 as i32
            as usize] = *((*(*ctxt).input).cur).offset(3 as i32 as isize);
        enc = xmlDetectCharEncoding(start.as_mut_ptr(), 4 as i32);
        if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
            xmlSwitchEncoding(ctxt, enc);
        }
    }
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '<' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == '?' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'x' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'm' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'l' as i32
    {
        xmlParseTextDecl(ctxt);
        if (*ctxt).errNo == XML_ERR_UNSUPPORTED_ENCODING as i32 {
            xmlHaltParser(ctxt);
            return;
        }
    }
    if ((*ctxt).myDoc).is_null() {
        let fresh305 = &mut ((*ctxt).myDoc);
        *fresh305 = xmlNewDoc(
            b"1.0\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        if ((*ctxt).myDoc).is_null() {
            xmlErrMemory(ctxt, b"New Doc failed\0" as *const u8 as *const i8);
            return;
        }
        (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as i32;
    }
    if !((*ctxt).myDoc).is_null() && ((*(*ctxt).myDoc).intSubset).is_null() {
        xmlCreateIntSubset((*ctxt).myDoc, 0 as *const xmlChar, ExternalID, SystemID);
    }
    (*ctxt).instate = XML_PARSER_DTD;
    (*ctxt).external = 1 as i32;
    xmlSkipBlankChars(ctxt);
    while *(*(*ctxt).input).cur as i32 == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            == '?' as i32
        || *(*(*ctxt).input).cur as i32 == '<' as i32
            && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
                == '!' as i32 || *(*(*ctxt).input).cur as i32 == '%' as i32
    {
        let mut id: i32 = (*(*ctxt).input).id;
        let mut cons: u64 = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
                    as u64,
            );
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if *(*(*ctxt).input).cur as i32 == '<' as i32
            && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
                == '!' as i32
            && *((*(*ctxt).input).cur).offset(2 as i32 as isize) as i32
                == '[' as i32
        {
            xmlParseConditionalSections(ctxt);
        } else {
            xmlParseMarkupDecl(ctxt);
        }
        xmlSkipBlankChars(ctxt);
        if !(id == (*(*ctxt).input).id
            && cons
                == ((*(*ctxt).input).consumed)
                    .wrapping_add(
                        ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as i64 as u64,
                    ))
        {
            continue;
        }
        xmlFatalErr(ctxt, XML_ERR_EXT_SUBSET_NOT_FINISHED, 0 as *const i8);
        break;
    }
    if *(*(*ctxt).input).cur as i32 != 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_EXT_SUBSET_NOT_FINISHED, 0 as *const i8);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseReference(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut ent: * mut crate::src::HTMLparser::_xmlEntity = 0 as *mut xmlEntity;
    let mut val: * mut u8 = 0 as *mut xmlChar;
    let mut was_checked: i32 = 0;
    let mut list: * mut crate::src::HTMLparser::_xmlNode = 0 as xmlNodePtr;
    let mut ret: u32 = XML_ERR_OK;
    if *(*(*ctxt).input).cur as i32 != '&' as i32 {
        return;
    }
    if *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
        == '#' as i32
    {
        let mut i: i32 = 0 as i32;
        let mut out: [u8; 16] = [0; 16];
        let mut hex: i32 = *((*(*ctxt).input).cur)
            .offset(2 as i32 as isize) as i32;
        let mut value: i32 = xmlParseCharRef(ctxt);
        if value == 0 as i32 {
            return;
        }
        if (*ctxt).charset != XML_CHAR_ENCODING_UTF8 as i32 {
            if value <= 0xff as i32 {
                out[0 as i32 as usize] = value as xmlChar;
                out[1 as i32 as usize] = 0 as i32 as xmlChar;
                if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).characters).is_some()
                    && (*ctxt).disableSAX == 0
                {
                    ((*(*ctxt).sax).characters)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, out.as_mut_ptr(), 1 as i32);
                }
            } else {
                if hex == 'x' as i32 || hex == 'X' as i32 {
                    snprintf(
                        out.as_mut_ptr() as *mut i8,
                        ::std::mem::size_of::<[xmlChar; 16]>() as u64,
                        b"#x%X\0" as *const u8 as *const i8,
                        value,
                    );
                } else {
                    snprintf(
                        out.as_mut_ptr() as *mut i8,
                        ::std::mem::size_of::<[xmlChar; 16]>() as u64,
                        b"#%d\0" as *const u8 as *const i8,
                        value,
                    );
                }
                if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).reference).is_some()
                    && (*ctxt).disableSAX == 0
                {
                    ((*(*ctxt).sax).reference)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, out.as_mut_ptr());
                }
            }
        } else {
            if 0 as i32 == 1 as i32 {
                let mut fresh306 = i;
                i = i + 1;
                out[fresh306 as usize] = value as xmlChar;
            } else {
                i
                    += xmlCopyCharMultiByte(
                        &mut *out.as_mut_ptr().offset(i as isize),
                        value,
                    );
            }
            out[i as usize] = 0 as i32 as xmlChar;
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).characters).is_some()
                && (*ctxt).disableSAX == 0
            {
                ((*(*ctxt).sax).characters)
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).userData, out.as_mut_ptr(), i);
            }
        }
        return;
    }
    ent = xmlParseEntityRef(ctxt);
    if ent.is_null() {
        return;
    }
    if (*ctxt).wellFormed == 0 {
        return;
    }
    was_checked = (*ent).checked;
    if ((*ent).name).is_null()
        || (*ent).etype as u32
            == XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
    {
        val = (*ent).content;
        if val.is_null() {
            return;
        }
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).characters).is_some()
            && (*ctxt).disableSAX == 0
        {
            ((*(*ctxt).sax).characters)
                .expect(
                    "non-null function pointer",
                )((*ctxt).userData, val, xmlStrlen(val));
        }
        return;
    }
    if ((*ent).checked == 0 as i32
        || ((*ent).children).is_null()
            && (*ctxt).options & XML_PARSE_NOENT as i32 != 0)
        && ((*ent).etype as u32
            != XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32
            || (*ctxt).options
                & (XML_PARSE_NOENT as i32 | XML_PARSE_DTDVALID as i32)
                != 0)
    {
        let mut oldnbent: u64 = (*ctxt).nbentities;
        let mut diff: u64 = 0;
        let mut user_data: * mut core::ffi::c_void = 0 as *mut libc::c_void;
        if (*ctxt).userData == ctxt as *mut libc::c_void {
            user_data = 0 as *mut libc::c_void;
        } else {
            user_data = (*ctxt).userData;
        }
        if (*ent).etype as u32
            == XML_INTERNAL_GENERAL_ENTITY as i32 as u32
        {
            let fresh307 = &mut ((*ctxt).depth);
            *fresh307 += 1;
            ret = xmlParseBalancedChunkMemoryInternal(
                ctxt,
                (*ent).content,
                user_data,
                Some(&mut list),
            );
            let fresh308 = &mut ((*ctxt).depth);
            *fresh308 -= 1;
        } else if (*ent).etype as u32
                == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32
            {
            let fresh309 = &mut ((*ctxt).depth);
            *fresh309 += 1;
            ret = xmlParseExternalEntityPrivate(
                (*ctxt).myDoc,
                ctxt,
                (*ctxt).sax,
                user_data,
                (*ctxt).depth,
                (*ent).URI,
                (*ent).ExternalID,
                Some(&mut list),
            );
            let fresh310 = &mut ((*ctxt).depth);
            *fresh310 -= 1;
        } else {
            ret = XML_ERR_ENTITY_PE_INTERNAL;
            xmlErrMsgStr(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"invalid entity type found\n\0" as *const u8 as *const i8,
                0 as *const xmlChar,
            );
        }
        diff = ((*ctxt).nbentities)
            .wrapping_sub(oldnbent)
            .wrapping_add(1 as i32 as u64);
        if diff > (2147483647 as i32 / 2 as i32) as u64 {
            diff = (2147483647 as i32 / 2 as i32) as u64;
        }
        (*ent)
            .checked = diff.wrapping_mul(2 as i32 as u64)
            as i32;
        if !((*ent).content).is_null()
            && !(xmlStrchr((*ent).content, '<' as i32 as xmlChar)).is_null()
        {
            (*ent).checked |= 1 as i32;
        }
        if ret as u32 == XML_ERR_ENTITY_LOOP as i32 as u32 {
            xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const i8);
            xmlHaltParser(ctxt);
            xmlFreeNodeList(list);
            return;
        }
        if xmlParserEntityCheck(
            ctxt,
            0 as i32 as size_t,
            ent,
            0 as i32 as size_t,
        ) != 0
        {
            xmlFreeNodeList(list);
            return;
        }
        if ret as u32 == XML_ERR_OK as i32 as u32
            && !list.is_null()
        {
            if ((*ent).etype as u32
                == XML_INTERNAL_GENERAL_ENTITY as i32 as u32
                || (*ent).etype as u32
                    == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32)
                && ((*ent).children).is_null()
            {
                let fresh311 = &mut ((*ent).children);
                *fresh311 = list;
                if (*ctxt).replaceEntities == 0 as i32
                    || (*ctxt).parseMode as u32
                        == XML_PARSE_READER as i32 as u32
                    || (*list).type_0 as u32
                        == XML_TEXT_NODE as i32 as u32
                        && ((*list).next).is_null()
                {
                    (*ent).owner = 1 as i32;
                    while !list.is_null() {
                        let fresh312 = &mut ((*list).parent);
                        *fresh312 = ent as xmlNodePtr;
                        if (*list).doc != (*ent).doc {
                            xmlSetTreeDoc(list, (*ent).doc);
                        }
                        if ((*list).next).is_null() {
                            let fresh313 = &mut ((*ent).last);
                            *fresh313 = list;
                        }
                        list = (*list).next;
                    }
                    list = 0 as xmlNodePtr;
                } else {
                    (*ent).owner = 0 as i32;
                    while !list.is_null() {
                        let fresh314 = &mut ((*list).parent);
                        *fresh314 = (*ctxt).node;
                        let fresh315 = &mut ((*list).doc);
                        *fresh315 = (*ctxt).myDoc;
                        if ((*list).next).is_null() {
                            let fresh316 = &mut ((*ent).last);
                            *fresh316 = list;
                        }
                        list = (*list).next;
                    }
                    list = (*ent).children;
                    if (*ent).etype as u32
                        == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32
                            as u32
                    {
                        xmlAddEntityReference(ent, list, 0 as xmlNodePtr);
                    }
                }
            } else {
                xmlFreeNodeList(list);
                list = 0 as xmlNodePtr;
            }
        } else if ret as u32 != XML_ERR_OK as i32 as u32
                && ret as u32
                    != XML_WAR_UNDECLARED_ENTITY as i32 as u32
            {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNDECLARED_ENTITY,
                b"Entity '%s' failed to parse\n\0" as *const u8 as *const i8,
                (*ent).name,
            );
            if !((*ent).content).is_null() {
                *((*ent).content)
                    .offset(0 as i32 as isize) = 0 as i32 as xmlChar;
            }
            xmlParserEntityCheck(
                ctxt,
                0 as i32 as size_t,
                ent,
                0 as i32 as size_t,
            );
        } else if !list.is_null() {
            xmlFreeNodeList(list);
            list = 0 as xmlNodePtr;
        }
        if (*ent).checked == 0 as i32 {
            (*ent).checked = 2 as i32;
        }
        was_checked = 0 as i32;
    } else if (*ent).checked != 1 as i32 {
        let fresh317 = &mut ((*ctxt).nbentities);
        *fresh317 = (*fresh317)
            .wrapping_add(((*ent).checked / 2 as i32) as u64);
    }
    if ((*ent).children).is_null() {
        if was_checked != 0 as i32 {
            let mut user_data_0: * mut core::ffi::c_void = 0 as *mut libc::c_void;
            if (*ctxt).userData == ctxt as *mut libc::c_void {
                user_data_0 = 0 as *mut libc::c_void;
            } else {
                user_data_0 = (*ctxt).userData;
            }
            if (*ent).etype as u32
                == XML_INTERNAL_GENERAL_ENTITY as i32 as u32
            {
                let fresh318 = &mut ((*ctxt).depth);
                *fresh318 += 1;
                ret = xmlParseBalancedChunkMemoryInternal(
                    ctxt,
                    (*ent).content,
                    user_data_0,
                    Option::<&'_ mut * mut crate::src::HTMLparser::_xmlNode>::None,
                );
                let fresh319 = &mut ((*ctxt).depth);
                *fresh319 -= 1;
            } else if (*ent).etype as u32
                    == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32
                {
                let fresh320 = &mut ((*ctxt).depth);
                *fresh320 += 1;
                ret = xmlParseExternalEntityPrivate(
                    (*ctxt).myDoc,
                    ctxt,
                    (*ctxt).sax,
                    user_data_0,
                    (*ctxt).depth,
                    (*ent).URI,
                    (*ent).ExternalID,
                    Option::<&'_ mut * mut crate::src::HTMLparser::_xmlNode>::None,
                );
                let fresh321 = &mut ((*ctxt).depth);
                *fresh321 -= 1;
            } else {
                ret = XML_ERR_ENTITY_PE_INTERNAL;
                xmlErrMsgStr(
                    ctxt,
                    XML_ERR_INTERNAL_ERROR,
                    b"invalid entity type found\n\0" as *const u8 as *const i8,
                    0 as *const xmlChar,
                );
            }
            if ret as u32 == XML_ERR_ENTITY_LOOP as i32 as u32
            {
                xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const i8);
                return;
            }
        }
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).reference).is_some()
            && (*ctxt).replaceEntities == 0 as i32 && (*ctxt).disableSAX == 0
        {
            ((*(*ctxt).sax).reference)
                .expect("non-null function pointer")((*ctxt).userData, (*ent).name);
        }
        return;
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).reference).is_some()
        && (*ctxt).replaceEntities == 0 as i32 && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).reference)
            .expect("non-null function pointer")((*ctxt).userData, (*ent).name);
        return;
    }
    if (*ctxt).replaceEntities != 0 || ((*ent).children).is_null() {
        if !((*ctxt).node).is_null() && !((*ent).children).is_null() {
            if list.is_null() && (*ent).owner == 0 as i32
                || (*ctxt).parseMode as u32
                    == XML_PARSE_READER as i32 as u32
            {
                let mut nw: * mut crate::src::HTMLparser::_xmlNode = 0 as xmlNodePtr;
                let mut cur: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
                let mut firstChild: * mut crate::src::HTMLparser::_xmlNode = 0 as xmlNodePtr;
                let fresh322 = &mut ((*ctxt).sizeentcopy);
                *fresh322 = (*fresh322)
                    .wrapping_add(((*ent).length + 5 as i32) as u64);
                if xmlParserEntityCheck(
                    ctxt,
                    0 as i32 as size_t,
                    ent,
                    (*ctxt).sizeentcopy,
                ) != 0
                {
                    return;
                }
                cur = (*ent).children;
                while !cur.is_null() {
                    nw = xmlDocCopyNode(cur, (*ctxt).myDoc, 1 as i32);
                    if !nw.is_null() {
                        if ((*nw)._private).is_null() {
                            let fresh323 = &mut ((*nw)._private);
                            *fresh323 = (*cur)._private;
                        }
                        if firstChild.is_null() {
                            firstChild = nw;
                        }
                        nw = xmlAddChild((*ctxt).node, nw);
                    }
                    if cur == (*ent).last {
                        if (*ctxt).parseMode as u32
                            == XML_PARSE_READER as i32 as u32
                            && !nw.is_null()
                            && (*nw).type_0 as u32
                                == XML_ELEMENT_NODE as i32 as u32
                            && ((*nw).children).is_null()
                        {
                            (*nw).extra = 1 as i32 as u16;
                        }
                        break;
                    } else {
                        cur = (*cur).next;
                    }
                }
                if (*ent).etype as u32
                    == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32
                {
                    xmlAddEntityReference(ent, firstChild, nw);
                }
            } else if list.is_null() || (*ctxt).inputNr > 0 as i32 {
                let mut nw_0: * mut crate::src::HTMLparser::_xmlNode = 0 as xmlNodePtr;
                let mut cur_0: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
                let mut next: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
                let mut last: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
                let mut firstChild_0: * mut crate::src::HTMLparser::_xmlNode = 0 as xmlNodePtr;
                let fresh324 = &mut ((*ctxt).sizeentcopy);
                *fresh324 = (*fresh324)
                    .wrapping_add(((*ent).length + 5 as i32) as u64);
                if xmlParserEntityCheck(
                    ctxt,
                    0 as i32 as size_t,
                    ent,
                    (*ctxt).sizeentcopy,
                ) != 0
                {
                    return;
                }
                cur_0 = (*ent).children;
                let fresh325 = &mut ((*ent).children);
                *fresh325 = 0 as *mut _xmlNode;
                last = (*ent).last;
                let fresh326 = &mut ((*ent).last);
                *fresh326 = 0 as *mut _xmlNode;
                while !cur_0.is_null() {
                    next = (*cur_0).next;
                    let fresh327 = &mut ((*cur_0).next);
                    *fresh327 = 0 as *mut _xmlNode;
                    let fresh328 = &mut ((*cur_0).parent);
                    *fresh328 = 0 as *mut _xmlNode;
                    nw_0 = xmlDocCopyNode(cur_0, (*ctxt).myDoc, 1 as i32);
                    if !nw_0.is_null() {
                        if ((*nw_0)._private).is_null() {
                            let fresh329 = &mut ((*nw_0)._private);
                            *fresh329 = (*cur_0)._private;
                        }
                        if firstChild_0.is_null() {
                            firstChild_0 = cur_0;
                        }
                        xmlAddChild(ent as xmlNodePtr, nw_0);
                        xmlAddChild((*ctxt).node, cur_0);
                    }
                    if cur_0 == last {
                        break;
                    }
                    cur_0 = next;
                }
                if (*ent).owner == 0 as i32 {
                    (*ent).owner = 1 as i32;
                }
                if (*ent).etype as u32
                    == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32
                {
                    xmlAddEntityReference(ent, firstChild_0, nw_0);
                }
            } else {
                let mut nbktext: * const u8 = 0 as *const xmlChar;
                nbktext = xmlDictLookup(
                    (*ctxt).dict,
                    b"nbktext\0" as *const u8 as *const i8 as *mut xmlChar,
                    -(1 as i32),
                );
                if (*(*ent).children).type_0 as u32
                    == XML_TEXT_NODE as i32 as u32
                {
                    let fresh330 = &mut ((*(*ent).children).name);
                    *fresh330 = nbktext;
                }
                if (*ent).last != (*ent).children
                    && (*(*ent).last).type_0 as u32
                        == XML_TEXT_NODE as i32 as u32
                {
                    let fresh331 = &mut ((*(*ent).last).name);
                    *fresh331 = nbktext;
                }
                xmlAddChildList((*ctxt).node, (*ent).children);
            }
            (*ctxt).nodemem = 0 as i32;
            (*ctxt).nodelen = 0 as i32;
            return;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEntityRef(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * mut crate::src::HTMLparser::_xmlEntity {
    let mut name: * const u8 = 0 as *const xmlChar;
    let mut ent: * mut crate::src::HTMLparser::_xmlEntity = 0 as xmlEntityPtr;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return 0 as xmlEntityPtr;
    }
    if *(*(*ctxt).input).cur as i32 != '&' as i32 {
        return 0 as xmlEntityPtr;
    }
    xmlNextChar(ctxt);
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseEntityRef: no name\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlEntityPtr;
    }
    if *(*(*ctxt).input).cur as i32 != ';' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ENTITYREF_SEMICOL_MISSING, 0 as *const i8);
        return 0 as xmlEntityPtr;
    }
    xmlNextChar(ctxt);
    if (*ctxt).options & XML_PARSE_OLDSAX as i32 == 0 as i32 {
        ent = xmlGetPredefinedEntity(name);
        if !ent.is_null() {
            return ent;
        }
    }
    let fresh332 = &mut ((*ctxt).nbentities);
    *fresh332 = (*fresh332).wrapping_add(1);
    if !((*ctxt).sax).is_null() {
        if ((*(*ctxt).sax).getEntity).is_some() {
            ent = ((*(*ctxt).sax).getEntity)
                .expect("non-null function pointer")((*ctxt).userData, name);
        }
        if (*ctxt).wellFormed == 1 as i32 && ent.is_null()
            && (*ctxt).options & XML_PARSE_OLDSAX as i32 != 0
        {
            ent = xmlGetPredefinedEntity(name);
        }
        if (*ctxt).wellFormed == 1 as i32 && ent.is_null()
            && (*ctxt).userData == ctxt as *mut libc::c_void
        {
            ent = xmlSAX2GetEntity(ctxt as *mut libc::c_void, name);
        }
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return 0 as xmlEntityPtr;
    }
    if ent.is_null() {
        if (*ctxt).standalone == 1 as i32
            || (*ctxt).hasExternalSubset == 0 as i32
                && (*ctxt).hasPErefs == 0 as i32
        {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNDECLARED_ENTITY,
                b"Entity '%s' not defined\n\0" as *const u8 as *const i8,
                name,
            );
        } else {
            xmlErrMsgStr(
                ctxt,
                XML_WAR_UNDECLARED_ENTITY,
                b"Entity '%s' not defined\n\0" as *const u8 as *const i8,
                name,
            );
            if (*ctxt).inSubset == 0 as i32 && !((*ctxt).sax).is_null()
                && ((*(*ctxt).sax).reference).is_some()
            {
                ((*(*ctxt).sax).reference)
                    .expect("non-null function pointer")((*ctxt).userData, name);
            }
        }
        xmlParserEntityCheck(
            ctxt,
            0 as i32 as size_t,
            ent,
            0 as i32 as size_t,
        );
        (*ctxt).valid = 0 as i32;
    } else if (*ent).etype as u32
            == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as i32 as u32
        {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_UNPARSED_ENTITY,
            b"Entity reference to unparsed entity %s\n\0" as *const u8
                as *const i8,
            name,
        );
    } else if (*ctxt).instate as i32 == XML_PARSER_ATTRIBUTE_VALUE as i32
            && (*ent).etype as u32
                == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32
        {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ENTITY_IS_EXTERNAL,
            b"Attribute references external entity '%s'\n\0" as *const u8
                as *const i8,
            name,
        );
    } else if (*ctxt).instate as i32 == XML_PARSER_ATTRIBUTE_VALUE as i32
            && !ent.is_null()
            && (*ent).etype as u32
                != XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
        {
        if ((*ent).checked & 1 as i32 != 0 || (*ent).checked == 0 as i32)
            && !((*ent).content).is_null()
            && !(xmlStrchr((*ent).content, '<' as i32 as xmlChar)).is_null()
        {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_LT_IN_ATTRIBUTE,
                b"'<' in entity '%s' is not allowed in attributes values\n\0"
                    as *const u8 as *const i8,
                name,
            );
        }
    } else {
        match (*ent).etype as u32 {
            4 | 5 => {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_ENTITY_IS_PARAMETER,
                    b"Attempt to reference the parameter entity '%s'\n\0" as *const u8
                        as *const i8,
                    name,
                );
            }
            _ => {}
        }
    }
    return ent;
}
unsafe extern "C" fn xmlParseStringEntityRef<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut str: Option<&'a1 mut * const u8>,
) -> * mut crate::src::HTMLparser::_xmlEntity {
    let mut name: * mut u8 = 0 as *mut xmlChar;
    let mut ptr: * const u8 = 0 as *const xmlChar;
    let mut cur: u8 = 0;
    let mut ent: * mut crate::src::HTMLparser::_xmlEntity = 0 as xmlEntityPtr;
    if borrow(& str).is_none() || (*(borrow_mut(&mut str)).unwrap()).is_null() {
        return 0 as xmlEntityPtr;
    }
    ptr = *(borrow(& str)).unwrap();
    cur = *ptr;
    if cur as i32 != '&' as i32 {
        return 0 as xmlEntityPtr;
    }
    ptr = ptr.offset(1);
    name = xmlParseStringName(ctxt, Some(&mut ptr));
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseStringEntityRef: no name\n\0" as *const u8 as *const i8,
        );
        *(borrow_mut(&mut str)).unwrap() = ptr;
        return 0 as xmlEntityPtr;
    }
    if *ptr as i32 != ';' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ENTITYREF_SEMICOL_MISSING, 0 as *const i8);
        xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
        *(borrow_mut(&mut str)).unwrap() = ptr;
        return 0 as xmlEntityPtr;
    }
    ptr = ptr.offset(1);
    if (*ctxt).options & XML_PARSE_OLDSAX as i32 == 0 as i32 {
        ent = xmlGetPredefinedEntity(name);
        if !ent.is_null() {
            xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
            *(borrow_mut(&mut str)).unwrap() = ptr;
            return ent;
        }
    }
    let fresh333 = &mut ((*ctxt).nbentities);
    *fresh333 = (*fresh333).wrapping_add(1);
    if !((*ctxt).sax).is_null() {
        if ((*(*ctxt).sax).getEntity).is_some() {
            ent = ((*(*ctxt).sax).getEntity)
                .expect("non-null function pointer")((*ctxt).userData, name);
        }
        if ent.is_null() && (*ctxt).options & XML_PARSE_OLDSAX as i32 != 0 {
            ent = xmlGetPredefinedEntity(name);
        }
        if ent.is_null() && (*ctxt).userData == ctxt as *mut libc::c_void {
            ent = xmlSAX2GetEntity(ctxt as *mut libc::c_void, name);
        }
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
        return 0 as xmlEntityPtr;
    }
    if ent.is_null() {
        if (*ctxt).standalone == 1 as i32
            || (*ctxt).hasExternalSubset == 0 as i32
                && (*ctxt).hasPErefs == 0 as i32
        {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNDECLARED_ENTITY,
                b"Entity '%s' not defined\n\0" as *const u8 as *const i8,
                name,
            );
        } else {
            xmlErrMsgStr(
                ctxt,
                XML_WAR_UNDECLARED_ENTITY,
                b"Entity '%s' not defined\n\0" as *const u8 as *const i8,
                name,
            );
        }
        xmlParserEntityCheck(
            ctxt,
            0 as i32 as size_t,
            ent,
            0 as i32 as size_t,
        );
    } else if (*ent).etype as u32
            == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as i32 as u32
        {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_UNPARSED_ENTITY,
            b"Entity reference to unparsed entity %s\n\0" as *const u8
                as *const i8,
            name,
        );
    } else if (*ctxt).instate as i32 == XML_PARSER_ATTRIBUTE_VALUE as i32
            && (*ent).etype as u32
                == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32
        {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ENTITY_IS_EXTERNAL,
            b"Attribute references external entity '%s'\n\0" as *const u8
                as *const i8,
            name,
        );
    } else if (*ctxt).instate as i32 == XML_PARSER_ATTRIBUTE_VALUE as i32
            && !ent.is_null() && !((*ent).content).is_null()
            && (*ent).etype as u32
                != XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
            && !(xmlStrchr((*ent).content, '<' as i32 as xmlChar)).is_null()
        {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_LT_IN_ATTRIBUTE,
            b"'<' in entity '%s' is not allowed in attributes values\n\0" as *const u8
                as *const i8,
            name,
        );
    } else {
        match (*ent).etype as u32 {
            4 | 5 => {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_ENTITY_IS_PARAMETER,
                    b"Attempt to reference the parameter entity '%s'\n\0" as *const u8
                        as *const i8,
                    name,
                );
            }
            _ => {}
        }
    }
    xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
    *(borrow_mut(&mut str)).unwrap() = ptr;
    return ent;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParsePEReference(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut name: * const u8 = 0 as *const xmlChar;
    let mut entity: * mut crate::src::HTMLparser::_xmlEntity = 0 as xmlEntityPtr;
    let mut input: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    if *(*(*ctxt).input).cur as i32 != '%' as i32 {
        return;
    }
    xmlNextChar(ctxt);
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_PEREF_NO_NAME,
            b"PEReference: no name\n\0" as *const u8 as *const i8,
        );
        return;
    }
    if *(borrow(& __xmlParserDebugEntities())).unwrap() != 0 {
        (*(borrow(& __xmlGenericError())).unwrap())
            .expect(
                "non-null function pointer",
            )(
            *(__xmlGenericErrorContext()).unwrap(),
            b"PEReference: %s\n\0" as *const u8 as *const i8,
            name,
        );
    }
    if *(*(*ctxt).input).cur as i32 != ';' as i32 {
        xmlFatalErr(ctxt, XML_ERR_PEREF_SEMICOL_MISSING, 0 as *const i8);
        return;
    }
    xmlNextChar(ctxt);
    let fresh334 = &mut ((*ctxt).nbentities);
    *fresh334 = (*fresh334).wrapping_add(1);
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).getParameterEntity).is_some() {
        entity = ((*(*ctxt).sax).getParameterEntity)
            .expect("non-null function pointer")((*ctxt).userData, name);
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return;
    }
    if entity.is_null() {
        if (*ctxt).standalone == 1 as i32
            || (*ctxt).hasExternalSubset == 0 as i32
                && (*ctxt).hasPErefs == 0 as i32
        {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNDECLARED_ENTITY,
                b"PEReference: %%%s; not found\n\0" as *const u8 as *const i8,
                name,
            );
        } else {
            if (*ctxt).validate != 0 && ((*ctxt).vctxt.error).is_some() {
                xmlValidityError(
                    ctxt,
                    XML_WAR_UNDECLARED_ENTITY,
                    b"PEReference: %%%s; not found\n\0" as *const u8
                        as *const i8,
                    name,
                    0 as *const xmlChar,
                );
            } else {
                xmlWarningMsg(
                    ctxt,
                    XML_WAR_UNDECLARED_ENTITY,
                    b"PEReference: %%%s; not found\n\0" as *const u8
                        as *const i8,
                    name,
                    0 as *const xmlChar,
                );
            }
            (*ctxt).valid = 0 as i32;
        }
        xmlParserEntityCheck(
            ctxt,
            0 as i32 as size_t,
            0 as xmlEntityPtr,
            0 as i32 as size_t,
        );
    } else if (*entity).etype as u32
            != XML_INTERNAL_PARAMETER_ENTITY as i32 as u32
            && (*entity).etype as u32
                != XML_EXTERNAL_PARAMETER_ENTITY as i32 as u32
        {
        xmlWarningMsg(
            ctxt,
            XML_WAR_UNDECLARED_ENTITY,
            b"Internal: %%%s; is not a parameter entity\n\0" as *const u8
                as *const i8,
            name,
            0 as *const xmlChar,
        );
    } else {
        let mut start: [u8; 4] = [0; 4];
        let mut enc: i32 = XML_CHAR_ENCODING_NONE;
        if xmlParserEntityCheck(
            ctxt,
            0 as i32 as size_t,
            entity,
            0 as i32 as size_t,
        ) != 0
        {
            return;
        }
        if (*entity).etype as u32
            == XML_EXTERNAL_PARAMETER_ENTITY as i32 as u32
            && (*ctxt).options & XML_PARSE_NOENT as i32 == 0 as i32
            && (*ctxt).options & XML_PARSE_DTDVALID as i32 == 0 as i32
            && (*ctxt).options & XML_PARSE_DTDLOAD as i32 == 0 as i32
            && (*ctxt).options & XML_PARSE_DTDATTR as i32 == 0 as i32
            && (*ctxt).replaceEntities == 0 as i32
            && (*ctxt).validate == 0 as i32
        {
            return;
        }
        input = xmlNewEntityInputStream(ctxt, entity);
        if xmlPushInput(ctxt, input) < 0 as i32 {
            xmlFreeInputStream(input);
            return;
        }
        if (*entity).etype as u32
            == XML_EXTERNAL_PARAMETER_ENTITY as i32 as u32
        {
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                return;
            }
            if ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64
                >= 4 as i32 as i64
            {
                start[0 as i32 as usize] = *(*(*ctxt).input).cur;
                start[1 as i32
                    as usize] = *((*(*ctxt).input).cur)
                    .offset(1 as i32 as isize);
                start[2 as i32
                    as usize] = *((*(*ctxt).input).cur)
                    .offset(2 as i32 as isize);
                start[3 as i32
                    as usize] = *((*(*ctxt).input).cur)
                    .offset(3 as i32 as isize);
                enc = xmlDetectCharEncoding(start.as_mut_ptr(), 4 as i32);
                if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
                    xmlSwitchEncoding(ctxt, enc);
                }
            }
            if *((*(*ctxt).input).cur as *mut u8)
                .offset(0 as i32 as isize) as i32 == '<' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(1 as i32 as isize) as i32 == '?' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(2 as i32 as isize) as i32 == 'x' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(3 as i32 as isize) as i32 == 'm' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(4 as i32 as isize) as i32 == 'l' as i32
                && (*((*(*ctxt).input).cur).offset(5 as i32 as isize)
                    as i32 == 0x20 as i32
                    || 0x9 as i32
                        <= *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                            as i32
                        && *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                            as i32 <= 0xa as i32
                    || *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                        as i32 == 0xd as i32)
            {
                xmlParseTextDecl(ctxt);
            }
        }
    }
    (*ctxt).hasPErefs = 1 as i32;
}
unsafe extern "C" fn xmlLoadEntityContent(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut entity: * mut crate::src::HTMLparser::_xmlEntity,
) -> i32 {
    let mut input: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut buf: * mut crate::src::HTMLtree::_xmlBuffer = 0 as *mut xmlBuffer;
    let mut l: i32 = 0;
    let mut c: i32 = 0;
    let mut count: i32 = 0 as i32;
    if ctxt.is_null() || entity.is_null()
        || (*entity).etype as u32
            != XML_EXTERNAL_PARAMETER_ENTITY as i32 as u32
            && (*entity).etype as u32
                != XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32
        || !((*entity).content).is_null()
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"xmlLoadEntityContent parameter error\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    if *(borrow(& __xmlParserDebugEntities())).unwrap() != 0 {
        (*(borrow(& __xmlGenericError())).unwrap())
            .expect(
                "non-null function pointer",
            )(
            *(__xmlGenericErrorContext()).unwrap(),
            b"Reading %s entity content input\n\0" as *const u8 as *const i8,
            (*entity).name,
        );
    }
    buf = xmlBufferCreate();
    if buf.is_null() {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"xmlLoadEntityContent parameter error\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    xmlBufferSetAllocationScheme(buf, XML_BUFFER_ALLOC_DOUBLEIT);
    input = xmlNewEntityInputStream(ctxt, entity);
    if input.is_null() {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"xmlLoadEntityContent input error\0" as *const u8 as *const i8,
        );
        xmlBufferFree(buf);
        return -(1 as i32);
    }
    if xmlPushInput(ctxt, input) < 0 as i32 {
        xmlBufferFree(buf);
        xmlFreeInputStream(input);
        return -(1 as i32);
    }
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    c = xmlCurrentChar(ctxt, Some(&mut l));
    while (*ctxt).input == input && (*(*ctxt).input).cur < (*(*ctxt).input).end
        && (if c < 0x100 as i32 {
            (0x9 as i32 <= c && c <= 0xa as i32
                || c == 0xd as i32 || 0x20 as i32 <= c) as i32
        } else {
            (0x100 as i32 <= c && c <= 0xd7ff as i32
                || 0xe000 as i32 <= c && c <= 0xfffd as i32
                || 0x10000 as i32 <= c && c <= 0x10ffff as i32)
                as i32
        }) != 0
    {
        xmlBufferAdd(buf, (*(*ctxt).input).cur, l);
        let mut fresh335 = count;
        count = count + 1;
        if fresh335 > 100 as i32 {
            count = 0 as i32;
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                xmlBufferFree(buf);
                return -(1 as i32);
            }
        }
        if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
            let fresh336 = &mut ((*(*ctxt).input).line);
            *fresh336 += 1;
            (*(*ctxt).input).col = 1 as i32;
        } else {
            let fresh337 = &mut ((*(*ctxt).input).col);
            *fresh337 += 1;
        }
        let fresh338 = &mut ((*(*ctxt).input).cur);
        *fresh338 = (*fresh338).offset(l as isize);
        c = xmlCurrentChar(ctxt, Some(&mut l));
        if c == 0 as i32 {
            count = 0 as i32;
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                xmlBufferFree(buf);
                return -(1 as i32);
            }
            c = xmlCurrentChar(ctxt, Some(&mut l));
        }
    }
    if (*ctxt).input == input && (*(*ctxt).input).cur >= (*(*ctxt).input).end {
        xmlPopInput(ctxt);
    } else if if c < 0x100 as i32 {
            (0x9 as i32 <= c && c <= 0xa as i32
                || c == 0xd as i32 || 0x20 as i32 <= c) as i32
        } else {
            (0x100 as i32 <= c && c <= 0xd7ff as i32
                || 0xe000 as i32 <= c && c <= 0xfffd as i32
                || 0x10000 as i32 <= c && c <= 0x10ffff as i32)
                as i32
        } == 0
        {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlLoadEntityContent: invalid char value %d\n\0" as *const u8
                as *const i8,
            c,
        );
        xmlBufferFree(buf);
        return -(1 as i32);
    }
    let fresh339 = &mut ((*entity).content);
    *fresh339 = (*buf).content;
    let fresh340 = &mut ((*buf).content);
    *fresh340 = 0 as *mut xmlChar;
    xmlBufferFree(buf);
    return 0 as i32;
}
unsafe extern "C" fn xmlParseStringPEReference<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut str: Option<&'a1 mut * const u8>,
) -> * mut crate::src::HTMLparser::_xmlEntity {
    let mut ptr: * const u8 = 0 as *const xmlChar;
    let mut cur: u8 = 0;
    let mut name: * mut u8 = 0 as *mut xmlChar;
    let mut entity: * mut crate::src::HTMLparser::_xmlEntity = 0 as xmlEntityPtr;
    if borrow(& str).is_none() || (*(borrow_mut(&mut str)).unwrap()).is_null() {
        return 0 as xmlEntityPtr;
    }
    ptr = *(borrow(& str)).unwrap();
    cur = *ptr;
    if cur as i32 != '%' as i32 {
        return 0 as xmlEntityPtr;
    }
    ptr = ptr.offset(1);
    name = xmlParseStringName(ctxt, Some(&mut ptr));
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseStringPEReference: no name\n\0" as *const u8 as *const i8,
        );
        *(borrow_mut(&mut str)).unwrap() = ptr;
        return 0 as xmlEntityPtr;
    }
    cur = *ptr;
    if cur as i32 != ';' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ENTITYREF_SEMICOL_MISSING, 0 as *const i8);
        xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
        *(borrow_mut(&mut str)).unwrap() = ptr;
        return 0 as xmlEntityPtr;
    }
    ptr = ptr.offset(1);
    let fresh341 = &mut ((*ctxt).nbentities);
    *fresh341 = (*fresh341).wrapping_add(1);
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).getParameterEntity).is_some() {
        entity = ((*(*ctxt).sax).getParameterEntity)
            .expect("non-null function pointer")((*ctxt).userData, name);
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
        *(borrow_mut(&mut str)).unwrap() = ptr;
        return 0 as xmlEntityPtr;
    }
    if entity.is_null() {
        if (*ctxt).standalone == 1 as i32
            || (*ctxt).hasExternalSubset == 0 as i32
                && (*ctxt).hasPErefs == 0 as i32
        {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNDECLARED_ENTITY,
                b"PEReference: %%%s; not found\n\0" as *const u8 as *const i8,
                name,
            );
        } else {
            xmlWarningMsg(
                ctxt,
                XML_WAR_UNDECLARED_ENTITY,
                b"PEReference: %%%s; not found\n\0" as *const u8 as *const i8,
                name,
                0 as *const xmlChar,
            );
            (*ctxt).valid = 0 as i32;
        }
        xmlParserEntityCheck(
            ctxt,
            0 as i32 as size_t,
            0 as xmlEntityPtr,
            0 as i32 as size_t,
        );
    } else if (*entity).etype as u32
            != XML_INTERNAL_PARAMETER_ENTITY as i32 as u32
            && (*entity).etype as u32
                != XML_EXTERNAL_PARAMETER_ENTITY as i32 as u32
        {
        xmlWarningMsg(
            ctxt,
            XML_WAR_UNDECLARED_ENTITY,
            b"%%%s; is not a parameter entity\n\0" as *const u8 as *const i8,
            name,
            0 as *const xmlChar,
        );
    }
    (*ctxt).hasPErefs = 1 as i32;
    xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
    *(borrow_mut(&mut str)).unwrap() = ptr;
    return entity;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseDocTypeDecl(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut name: * const u8 = 0 as *const xmlChar;
    let mut ExternalID: * mut u8 = 0 as *mut xmlChar;
    let mut URI: * mut u8 = 0 as *mut xmlChar;
    let fresh342 = &mut ((*(*ctxt).input).cur);
    *fresh342 = (*fresh342).offset(9 as i32 as isize);
    (*(*ctxt).input).col += 9 as i32;
    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
        xmlParserInputGrow((*ctxt).input, 250 as i32);
    }
    xmlSkipBlankChars(ctxt);
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseDocTypeDecl : no DOCTYPE name !\n\0" as *const u8
                as *const i8,
        );
    }
    let fresh343 = &mut ((*ctxt).intSubName);
    *fresh343 = name;
    xmlSkipBlankChars(ctxt);
    URI = xmlParseExternalID(ctxt, Some(&mut ExternalID), 1 as i32);
    if !URI.is_null() || !ExternalID.is_null() {
        (*ctxt).hasExternalSubset = 1 as i32;
    }
    let fresh344 = &mut ((*ctxt).extSubURI);
    *fresh344 = URI;
    let fresh345 = &mut ((*ctxt).extSubSystem);
    *fresh345 = ExternalID;
    xmlSkipBlankChars(ctxt);
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).internalSubset).is_some()
        && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).internalSubset)
            .expect(
                "non-null function pointer",
            )((*ctxt).userData, name, ExternalID, URI);
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return;
    }
    if *(*(*ctxt).input).cur as i32 == '[' as i32 {
        return;
    }
    if *(*(*ctxt).input).cur as i32 != '>' as i32 {
        xmlFatalErr(ctxt, XML_ERR_DOCTYPE_NOT_FINISHED, 0 as *const i8);
    }
    xmlNextChar(ctxt);
}
unsafe extern "C" fn xmlParseInternalSubset(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    if *(*(*ctxt).input).cur as i32 == '[' as i32 {
        let mut baseInputNr: i32 = (*ctxt).inputNr;
        (*ctxt).instate = XML_PARSER_DTD;
        xmlNextChar(ctxt);
        while (*(*(*ctxt).input).cur as i32 != ']' as i32
            || (*ctxt).inputNr > baseInputNr)
            && (*ctxt).instate as i32 != XML_PARSER_EOF as i32
        {
            let mut id: i32 = (*(*ctxt).input).id;
            let mut cons: u64 = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as i64 as u64,
                );
            xmlSkipBlankChars(ctxt);
            xmlParseMarkupDecl(ctxt);
            xmlParsePEReference(ctxt);
            if (*ctxt).inputNr > 1 as i32
                && !((*(*ctxt).input).filename).is_null()
                && *(*(*ctxt).input).cur as i32 == '<' as i32
                && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == '!' as i32
                && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                    as i32 == '[' as i32
            {
                xmlParseConditionalSections(ctxt);
            }
            if !(id == (*(*ctxt).input).id
                && cons
                    == ((*(*ctxt).input).consumed)
                        .wrapping_add(
                            ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as i64 as u64,
                        ))
            {
                continue;
            }
            xmlFatalErr(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"xmlParseInternalSubset: error detected in Markup declaration\n\0"
                    as *const u8 as *const i8,
            );
            if !((*ctxt).inputNr > baseInputNr) {
                break;
            }
            xmlPopInput(ctxt);
        }
        if *(*(*ctxt).input).cur as i32 == ']' as i32 {
            xmlNextChar(ctxt);
            xmlSkipBlankChars(ctxt);
        }
    }
    if *(*(*ctxt).input).cur as i32 != '>' as i32 {
        xmlFatalErr(ctxt, XML_ERR_DOCTYPE_NOT_FINISHED, 0 as *const i8);
        return;
    }
    xmlNextChar(ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseAttribute<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut value: Option<&'a1 mut * mut u8>,
) -> * const u8 {
    let mut name: * const u8 = 0 as *const xmlChar;
    let mut val: * mut u8 = 0 as *mut xmlChar;
    *(borrow_mut(&mut value)).unwrap() = 0 as *mut xmlChar;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"error parsing attribute name\n\0" as *const u8 as *const i8,
        );
        return 0 as *const xmlChar;
    }
    xmlSkipBlankChars(ctxt);
    if *(*(*ctxt).input).cur as i32 == '=' as i32 {
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        val = xmlParseAttValue(ctxt);
        (*ctxt).instate = XML_PARSER_CONTENT;
    } else {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ATTRIBUTE_WITHOUT_VALUE,
            b"Specification mandates value for attribute %s\n\0" as *const u8
                as *const i8,
            name,
        );
        return 0 as *const xmlChar;
    }
    if (*ctxt).pedantic != 0
        && xmlStrEqual(
            name,
            b"xml:lang\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
    {
        if xmlCheckLanguageID(val) == 0 {
            xmlWarningMsg(
                ctxt,
                XML_WAR_LANG_VALUE,
                b"Malformed value for xml:lang : %s\n\0" as *const u8
                    as *const i8,
                val,
                0 as *const xmlChar,
            );
        }
    }
    if xmlStrEqual(
        name,
        b"xml:space\0" as *const u8 as *const i8 as *mut xmlChar,
    ) != 0
    {
        if xmlStrEqual(
            val,
            b"default\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
        {
            *(*ctxt).space = 0 as i32;
        } else if xmlStrEqual(
                val,
                b"preserve\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
            *(*ctxt).space = 1 as i32;
        } else {
            xmlWarningMsg(
                ctxt,
                XML_WAR_SPACE_VALUE,
                b"Invalid value \"%s\" for xml:space : \"default\" or \"preserve\" expected\n\0"
                    as *const u8 as *const i8,
                val,
                0 as *const xmlChar,
            );
        }
    }
    *(borrow_mut(&mut value)).unwrap() = val;
    return name;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseStartTag(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * const u8 {
    let mut current_block: u64;
    let mut name: * const u8 = 0 as *const xmlChar;
    let mut attname: * const u8 = 0 as *const xmlChar;
    let mut attvalue: * mut u8 = 0 as *mut xmlChar;
    let mut atts: * mut * const u8 = (*ctxt).atts;
    let mut nbatts: i32 = 0 as i32;
    let mut maxatts: i32 = (*ctxt).maxatts;
    let mut i: i32 = 0;
    if *(*(*ctxt).input).cur as i32 != '<' as i32 {
        return 0 as *const xmlChar;
    }
    let fresh346 = &mut ((*(*ctxt).input).col);
    *fresh346 += 1;
    let fresh347 = &mut ((*(*ctxt).input).cur);
    *fresh347 = (*fresh347).offset(1);
    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
        xmlParserInputGrow((*ctxt).input, 250 as i32);
    }
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseStartTag: invalid element name\n\0" as *const u8
                as *const i8,
        );
        return 0 as *const xmlChar;
    }
    xmlSkipBlankChars(ctxt);
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    while *(*(*ctxt).input).cur as i32 != '>' as i32
        && (*(*(*ctxt).input).cur as i32 != '/' as i32
            || *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
                != '>' as i32)
        && (0x9 as i32 <= *(*(*ctxt).input).cur as i32
            && *(*(*ctxt).input).cur as i32 <= 0xa as i32
            || *(*(*ctxt).input).cur as i32 == 0xd as i32
            || 0x20 as i32 <= *(*(*ctxt).input).cur as i32)
        && (*ctxt).instate as i32 != XML_PARSER_EOF as i32
    {
        let mut id: i32 = (*(*ctxt).input).id;
        let mut cons: u64 = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
                    as u64,
            );
        attname = xmlParseAttribute(ctxt, Some(&mut attvalue));
        if !attname.is_null() && !attvalue.is_null() {
            i = 0 as i32;
            loop {
                if !(i < nbatts) {
                    current_block = 3437258052017859086;
                    break;
                }
                if xmlStrEqual(*atts.offset(i as isize), attname) != 0 {
                    xmlErrAttributeDup(ctxt, 0 as *const xmlChar, attname);
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(attvalue as *mut libc::c_void);
                    current_block = 16521494893250375975;
                    break;
                } else {
                    i += 2 as i32;
                }
            }
            match current_block {
                16521494893250375975 => {}
                _ => {
                    if atts.is_null() {
                        maxatts = 22 as i32;
                        atts = xmlMalloc
                            .expect(
                                "non-null function pointer",
                            )(
                            (maxatts as u64)
                                .wrapping_mul(
                                    ::std::mem::size_of::<*mut xmlChar>() as u64,
                                ),
                        ) as *mut *const xmlChar;
                        if atts.is_null() {
                            xmlErrMemory(ctxt, 0 as *const i8);
                            if !attvalue.is_null() {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(attvalue as *mut libc::c_void);
                            }
                            current_block = 16521494893250375975;
                        } else {
                            let fresh348 = &mut ((*ctxt).atts);
                            *fresh348 = atts;
                            (*ctxt).maxatts = maxatts;
                            current_block = 11763295167351361500;
                        }
                    } else if nbatts + 4 as i32 > maxatts {
                        let mut n: * mut * const u8 = 0 as *mut *const xmlChar;
                        maxatts *= 2 as i32;
                        n = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(
                            atts as *mut libc::c_void,
                            (maxatts as u64)
                                .wrapping_mul(
                                    ::std::mem::size_of::<*const xmlChar>() as u64,
                                ),
                        ) as *mut *const xmlChar;
                        if n.is_null() {
                            xmlErrMemory(ctxt, 0 as *const i8);
                            if !attvalue.is_null() {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(attvalue as *mut libc::c_void);
                            }
                            current_block = 16521494893250375975;
                        } else {
                            atts = n;
                            let fresh349 = &mut ((*ctxt).atts);
                            *fresh349 = atts;
                            (*ctxt).maxatts = maxatts;
                            current_block = 11763295167351361500;
                        }
                    } else {
                        current_block = 11763295167351361500;
                    }
                    match current_block {
                        16521494893250375975 => {}
                        _ => {
                            let mut fresh350 = nbatts;
                            nbatts = nbatts + 1;
                            let fresh351 = &mut (*atts.offset(fresh350 as isize));
                            *fresh351 = attname;
                            let mut fresh352 = nbatts;
                            nbatts = nbatts + 1;
                            let fresh353 = &mut (*atts.offset(fresh352 as isize));
                            *fresh353 = attvalue;
                            let fresh354 = &mut (*atts.offset(nbatts as isize));
                            *fresh354 = 0 as *const xmlChar;
                            let fresh355 = &mut (*atts
                                .offset((nbatts + 1 as i32) as isize));
                            *fresh355 = 0 as *const xmlChar;
                        }
                    }
                }
            }
        } else if !attvalue.is_null() {
            xmlFree.expect("non-null function pointer")(attvalue as *mut libc::c_void);
        }
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if *(*(*ctxt).input).cur as i32 == '>' as i32
            || *(*(*ctxt).input).cur as i32 == '/' as i32
                && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == '>' as i32
        {
            break;
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"attributes construct error\n\0" as *const u8 as *const i8,
            );
        }
        if cons
            == ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as i64 as u64,
                ) && id == (*(*ctxt).input).id && attname.is_null() && attvalue.is_null()
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"xmlParseStartTag: problem parsing attributes\n\0" as *const u8
                    as *const i8,
            );
            break;
        } else {
            if (*ctxt).progressive == 0 as i32
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as i64
                    > (2 as i32 * 250 as i32) as i64
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
        }
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).startElement).is_some()
        && (*ctxt).disableSAX == 0
    {
        if nbatts > 0 as i32 {
            ((*(*ctxt).sax).startElement)
                .expect("non-null function pointer")((*ctxt).userData, name, atts);
        } else {
            ((*(*ctxt).sax).startElement)
                .expect(
                    "non-null function pointer",
                )((*ctxt).userData, name, 0 as *mut *const xmlChar);
        }
    }
    if !atts.is_null() {
        i = 1 as i32;
        while i < nbatts {
            if !(*atts.offset(i as isize)).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(*atts.offset(i as isize) as *mut xmlChar as *mut libc::c_void);
            }
            i += 2 as i32;
        }
    }
    return name;
}
unsafe extern "C" fn xmlParseEndTag1(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt, mut line: i32) {
    let mut name: * const u8 = 0 as *const xmlChar;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if *(*(*ctxt).input).cur as i32 != '<' as i32
        || *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            != '/' as i32
    {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_LTSLASH_REQUIRED,
            b"xmlParseEndTag: '</' not found\n\0" as *const u8 as *const i8,
        );
        return;
    }
    let fresh356 = &mut ((*(*ctxt).input).cur);
    *fresh356 = (*fresh356).offset(2 as i32 as isize);
    (*(*ctxt).input).col += 2 as i32;
    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
        xmlParserInputGrow((*ctxt).input, 250 as i32);
    }
    name = xmlParseNameAndCompare(ctxt, (*ctxt).name);
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    xmlSkipBlankChars(ctxt);
    if !(0x9 as i32 <= *(*(*ctxt).input).cur as i32
        && *(*(*ctxt).input).cur as i32 <= 0xa as i32
        || *(*(*ctxt).input).cur as i32 == 0xd as i32
        || 0x20 as i32 <= *(*(*ctxt).input).cur as i32)
        || *(*(*ctxt).input).cur as i32 != '>' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_GT_REQUIRED, 0 as *const i8);
    } else {
        let fresh357 = &mut ((*(*ctxt).input).col);
        *fresh357 += 1;
        let fresh358 = &mut ((*(*ctxt).input).cur);
        *fresh358 = (*fresh358).offset(1);
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
    }
    if name != 1 as i32 as *mut xmlChar as *const xmlChar {
        if name.is_null() {
            name = b"unparsable\0" as *const u8 as *const i8 as *mut xmlChar;
        }
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_TAG_NAME_MISMATCH,
            b"Opening and ending tag mismatch: %s line %d and %s\n\0" as *const u8
                as *const i8,
            (*ctxt).name,
            line,
            name,
        );
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElement).is_some()
        && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).endElement)
            .expect("non-null function pointer")((*ctxt).userData, (*ctxt).name);
    }
    namePop(ctxt);
    spacePop(ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEndTag(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    xmlParseEndTag1(ctxt, 0 as i32);
}
unsafe extern "C" fn xmlGetNamespace(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut prefix: * const u8,
) -> * const u8 {
    let mut i: i32 = 0;
    if prefix == (*ctxt).str_xml {
        return (*ctxt).str_xml_ns;
    }
    i = (*ctxt).nsNr - 2 as i32;
    while i >= 0 as i32 {
        if *((*ctxt).nsTab).offset(i as isize) == prefix {
            if prefix.is_null()
                && **((*ctxt).nsTab).offset((i + 1 as i32) as isize)
                    as i32 == 0 as i32
            {
                return 0 as *const xmlChar;
            }
            return *((*ctxt).nsTab).offset((i + 1 as i32) as isize);
        }
        i -= 2 as i32;
    }
    return 0 as *const xmlChar;
}
unsafe extern "C" fn xmlParseQName<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut prefix: Option<&'a1 mut * const u8>,
) -> * const u8 {
    let mut l: * const u8 = 0 as *const xmlChar;
    let mut p: * const u8 = 0 as *const xmlChar;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    l = xmlParseNCName(ctxt);
    if l.is_null() {
        if *(*(*ctxt).input).cur as i32 == ':' as i32 {
            l = xmlParseName(ctxt);
            if !l.is_null() {
                xmlNsErr(
                    ctxt,
                    XML_NS_ERR_QNAME,
                    b"Failed to parse QName '%s'\n\0" as *const u8
                        as *const i8,
                    l,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                *(borrow_mut(&mut prefix)).unwrap() = 0 as *const xmlChar;
                return l;
            }
        }
        return 0 as *const xmlChar;
    }
    if *(*(*ctxt).input).cur as i32 == ':' as i32 {
        xmlNextChar(ctxt);
        p = l;
        l = xmlParseNCName(ctxt);
        if l.is_null() {
            let mut tmp: * mut u8 = 0 as *mut xmlChar;
            if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                return 0 as *const xmlChar;
            }
            xmlNsErr(
                ctxt,
                XML_NS_ERR_QNAME,
                b"Failed to parse QName '%s:'\n\0" as *const u8 as *const i8,
                p,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            l = xmlParseNmtoken(ctxt);
            if l.is_null() {
                if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *const xmlChar;
                }
                tmp = xmlBuildQName(
                    b"\0" as *const u8 as *const i8 as *mut xmlChar,
                    p,
                    0 as *mut xmlChar,
                    0 as i32,
                );
            } else {
                tmp = xmlBuildQName(l, p, 0 as *mut xmlChar, 0 as i32);
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(l as *mut i8 as *mut libc::c_void);
            }
            p = xmlDictLookup((*ctxt).dict, tmp, -(1 as i32));
            if !tmp.is_null() {
                xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void);
            }
            *(borrow_mut(&mut prefix)).unwrap() = 0 as *const xmlChar;
            return p;
        }
        if *(*(*ctxt).input).cur as i32 == ':' as i32 {
            let mut tmp_0: * mut u8 = 0 as *mut xmlChar;
            xmlNsErr(
                ctxt,
                XML_NS_ERR_QNAME,
                b"Failed to parse QName '%s:%s:'\n\0" as *const u8
                    as *const i8,
                p,
                l,
                0 as *const xmlChar,
            );
            xmlNextChar(ctxt);
            tmp_0 = xmlParseName(ctxt) as *mut xmlChar;
            if !tmp_0.is_null() {
                tmp_0 = xmlBuildQName(tmp_0, l, 0 as *mut xmlChar, 0 as i32);
                l = xmlDictLookup((*ctxt).dict, tmp_0, -(1 as i32));
                if !tmp_0.is_null() {
                    xmlFree
                        .expect("non-null function pointer")(tmp_0 as *mut libc::c_void);
                }
                *(borrow_mut(&mut prefix)).unwrap() = p;
                return l;
            }
            if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                return 0 as *const xmlChar;
            }
            tmp_0 = xmlBuildQName(
                b"\0" as *const u8 as *const i8 as *mut xmlChar,
                l,
                0 as *mut xmlChar,
                0 as i32,
            );
            l = xmlDictLookup((*ctxt).dict, tmp_0, -(1 as i32));
            if !tmp_0.is_null() {
                xmlFree.expect("non-null function pointer")(tmp_0 as *mut libc::c_void);
            }
            *(borrow_mut(&mut prefix)).unwrap() = p;
            return l;
        }
        *(borrow_mut(&mut prefix)).unwrap() = p;
    } else {
        *(borrow_mut(&mut prefix)).unwrap() = 0 as *const xmlChar;
    }
    return l;
}
unsafe extern "C" fn xmlParseQNameAndCompare(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut name: * const u8,
    mut prefix: * const u8,
) -> * const u8 {
    let mut cmp: * const u8 = 0 as *const xmlChar;
    let mut in_0: * const u8 = 0 as *const xmlChar;
    let mut ret: * const u8 = 0 as *const xmlChar;
    let mut prefix2: * const u8 = 0 as *const xmlChar;
    if prefix.is_null() {
        return xmlParseNameAndCompare(ctxt, name);
    }
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    in_0 = (*(*ctxt).input).cur;
    cmp = prefix;
    while *in_0 as i32 != 0 as i32
        && *in_0 as i32 == *cmp as i32
    {
        in_0 = in_0.offset(1);
        cmp = cmp.offset(1);
    }
    if *cmp as i32 == 0 as i32 && *in_0 as i32 == ':' as i32 {
        in_0 = in_0.offset(1);
        cmp = name;
        while *in_0 as i32 != 0 as i32
            && *in_0 as i32 == *cmp as i32
        {
            in_0 = in_0.offset(1);
            cmp = cmp.offset(1);
        }
        if *cmp as i32 == 0 as i32
            && (*in_0 as i32 == '>' as i32
                || (*in_0 as i32 == 0x20 as i32
                    || 0x9 as i32 <= *in_0 as i32
                        && *in_0 as i32 <= 0xa as i32
                    || *in_0 as i32 == 0xd as i32))
        {
            let fresh359 = &mut ((*(*ctxt).input).col);
            *fresh359 = (*fresh359 as i64
                + in_0.offset_from((*(*ctxt).input).cur) as i64) as i32;
            let fresh360 = &mut ((*(*ctxt).input).cur);
            *fresh360 = in_0;
            return 1 as i32 as *const xmlChar;
        }
    }
    ret = xmlParseQName(ctxt, Some(&mut prefix2));
    if ret == name && prefix == prefix2 {
        return 1 as i32 as *const xmlChar;
    }
    return ret;
}
unsafe extern "C" fn xmlParseAttValueInternal<'a1, 'a2>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut len: Option<&'a1 mut i32>,
    mut alloc: Option<&'a2 mut i32>,
    mut normalize: i32,
) -> * mut u8 {
    let mut current_block: u64;
    let mut limit: u8 = 0 as i32 as xmlChar;
    let mut in_0: * const u8 = 0 as *const xmlChar;
    let mut start: * const u8 = 0 as *const xmlChar;
    let mut end: * const u8 = 0 as *const xmlChar;
    let mut last: * const u8 = 0 as *const xmlChar;
    let mut ret: * mut u8 = 0 as *mut xmlChar;
    let mut line: i32 = 0;
    let mut col: i32 = 0;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    in_0 = (*(*ctxt).input).cur as *mut xmlChar;
    line = (*(*ctxt).input).line;
    col = (*(*ctxt).input).col;
    if *in_0 as i32 != '"' as i32 && *in_0 as i32 != '\'' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ATTRIBUTE_NOT_STARTED, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    (*ctxt).instate = XML_PARSER_ATTRIBUTE_VALUE;
    let mut fresh361 = in_0;
    in_0 = in_0.offset(1);
    limit = *fresh361;
    col += 1;
    end = (*(*ctxt).input).end;
    start = in_0;
    if in_0 >= end {
        let mut oldbase: * const u8 = (*(*ctxt).input).base;
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
            return 0 as *mut xmlChar;
        }
        if oldbase != (*(*ctxt).input).base {
            let mut delta: i64 = ((*(*ctxt).input).base).offset_from(oldbase)
                as i64;
            start = start.offset(delta as isize);
            in_0 = in_0.offset(delta as isize);
        }
        end = (*(*ctxt).input).end;
    }
    if normalize != 0 {
        while in_0 < end && *in_0 as i32 != limit as i32
            && (*in_0 as i32 == 0x20 as i32
                || *in_0 as i32 == 0x9 as i32
                || *in_0 as i32 == 0xa as i32
                || *in_0 as i32 == 0xd as i32)
        {
            if *in_0 as i32 == 0xa as i32 {
                line += 1;
                col = 1 as i32;
            } else {
                col += 1;
            }
            in_0 = in_0.offset(1);
            start = in_0;
            if in_0 >= end {
                let mut oldbase_0: * const u8 = (*(*ctxt).input).base;
                if (*ctxt).progressive == 0 as i32
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64) < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *mut xmlChar;
                }
                if oldbase_0 != (*(*ctxt).input).base {
                    let mut delta_0: i64 = ((*(*ctxt).input).base)
                        .offset_from(oldbase_0) as i64;
                    start = start.offset(delta_0 as isize);
                    in_0 = in_0.offset(delta_0 as isize);
                }
                end = (*(*ctxt).input).end;
                if in_0.offset_from(start) as i64
                    > 10000000 as i32 as i64
                    && (*ctxt).options & XML_PARSE_HUGE as i32
                        == 0 as i32
                {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ATTRIBUTE_NOT_FINISHED,
                        b"AttValue length too long\n\0" as *const u8
                            as *const i8,
                    );
                    return 0 as *mut xmlChar;
                }
            }
        }
        while in_0 < end && *in_0 as i32 != limit as i32
            && *in_0 as i32 >= 0x20 as i32
            && *in_0 as i32 <= 0x7f as i32
            && *in_0 as i32 != '&' as i32 && *in_0 as i32 != '<' as i32
        {
            col += 1;
            let mut fresh362 = in_0;
            in_0 = in_0.offset(1);
            if *fresh362 as i32 == 0x20 as i32
                && *in_0 as i32 == 0x20 as i32
            {
                break;
            }
            if in_0 >= end {
                let mut oldbase_1: * const u8 = (*(*ctxt).input).base;
                if (*ctxt).progressive == 0 as i32
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64) < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *mut xmlChar;
                }
                if oldbase_1 != (*(*ctxt).input).base {
                    let mut delta_1: i64 = ((*(*ctxt).input).base)
                        .offset_from(oldbase_1) as i64;
                    start = start.offset(delta_1 as isize);
                    in_0 = in_0.offset(delta_1 as isize);
                }
                end = (*(*ctxt).input).end;
                if in_0.offset_from(start) as i64
                    > 10000000 as i32 as i64
                    && (*ctxt).options & XML_PARSE_HUGE as i32
                        == 0 as i32
                {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ATTRIBUTE_NOT_FINISHED,
                        b"AttValue length too long\n\0" as *const u8
                            as *const i8,
                    );
                    return 0 as *mut xmlChar;
                }
            }
        }
        last = in_0;
        while *last.offset(-(1 as i32) as isize) as i32
            == 0x20 as i32 && last > start
        {
            last = last.offset(-1);
        }
        while in_0 < end && *in_0 as i32 != limit as i32
            && (*in_0 as i32 == 0x20 as i32
                || *in_0 as i32 == 0x9 as i32
                || *in_0 as i32 == 0xa as i32
                || *in_0 as i32 == 0xd as i32)
        {
            if *in_0 as i32 == 0xa as i32 {
                line += 1;
                col = 1 as i32;
            } else {
                col += 1;
            }
            in_0 = in_0.offset(1);
            if in_0 >= end {
                let mut oldbase_2: * const u8 = (*(*ctxt).input).base;
                if (*ctxt).progressive == 0 as i32
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64) < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *mut xmlChar;
                }
                if oldbase_2 != (*(*ctxt).input).base {
                    let mut delta_2: i64 = ((*(*ctxt).input).base)
                        .offset_from(oldbase_2) as i64;
                    start = start.offset(delta_2 as isize);
                    in_0 = in_0.offset(delta_2 as isize);
                    last = last.offset(delta_2 as isize);
                }
                end = (*(*ctxt).input).end;
                if in_0.offset_from(start) as i64
                    > 10000000 as i32 as i64
                    && (*ctxt).options & XML_PARSE_HUGE as i32
                        == 0 as i32
                {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ATTRIBUTE_NOT_FINISHED,
                        b"AttValue length too long\n\0" as *const u8
                            as *const i8,
                    );
                    return 0 as *mut xmlChar;
                }
            }
        }
        if in_0.offset_from(start) as i64
            > 10000000 as i32 as i64
            && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_ATTRIBUTE_NOT_FINISHED,
                b"AttValue length too long\n\0" as *const u8 as *const i8,
            );
            return 0 as *mut xmlChar;
        }
        if *in_0 as i32 != limit as i32 {
            current_block = 9760041004302091864;
        } else {
            current_block = 17736998403848444560;
        }
    } else {
        while in_0 < end && *in_0 as i32 != limit as i32
            && *in_0 as i32 >= 0x20 as i32
            && *in_0 as i32 <= 0x7f as i32
            && *in_0 as i32 != '&' as i32 && *in_0 as i32 != '<' as i32
        {
            in_0 = in_0.offset(1);
            col += 1;
            if in_0 >= end {
                let mut oldbase_3: * const u8 = (*(*ctxt).input).base;
                if (*ctxt).progressive == 0 as i32
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64) < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *mut xmlChar;
                }
                if oldbase_3 != (*(*ctxt).input).base {
                    let mut delta_3: i64 = ((*(*ctxt).input).base)
                        .offset_from(oldbase_3) as i64;
                    start = start.offset(delta_3 as isize);
                    in_0 = in_0.offset(delta_3 as isize);
                }
                end = (*(*ctxt).input).end;
                if in_0.offset_from(start) as i64
                    > 10000000 as i32 as i64
                    && (*ctxt).options & XML_PARSE_HUGE as i32
                        == 0 as i32
                {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ATTRIBUTE_NOT_FINISHED,
                        b"AttValue length too long\n\0" as *const u8
                            as *const i8,
                    );
                    return 0 as *mut xmlChar;
                }
            }
        }
        last = in_0;
        if in_0.offset_from(start) as i64
            > 10000000 as i32 as i64
            && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_ATTRIBUTE_NOT_FINISHED,
                b"AttValue length too long\n\0" as *const u8 as *const i8,
            );
            return 0 as *mut xmlChar;
        }
        if *in_0 as i32 != limit as i32 {
            current_block = 9760041004302091864;
        } else {
            current_block = 17736998403848444560;
        }
    }
    match current_block {
        9760041004302091864 => {
            if !borrow(& alloc).is_none() {
                *(borrow_mut(&mut alloc)).unwrap() = 1 as i32;
            }
            return xmlParseAttValueComplex(ctxt, borrow_mut(&mut len), normalize);
        }
        _ => {
            in_0 = in_0.offset(1);
            col += 1;
            if !borrow(& len).is_none() {
                *(borrow_mut(&mut len)).unwrap() = last.offset_from(start) as i64 as i32;
                ret = start as *mut xmlChar;
            } else {
                if !borrow(& alloc).is_none() {
                    *(borrow_mut(&mut alloc)).unwrap() = 1 as i32;
                }
                ret = xmlStrndup(
                    start,
                    last.offset_from(start) as i64 as i32,
                );
            }
            let fresh363 = &mut ((*(*ctxt).input).cur);
            *fresh363 = in_0;
            (*(*ctxt).input).line = line;
            (*(*ctxt).input).col = col;
            if !borrow(& alloc).is_none() {
                *(borrow_mut(&mut alloc)).unwrap() = 0 as i32;
            }
            return ret;
        }
    };
}
unsafe extern "C" fn xmlParseAttribute2<'a1, 'a2, 'a3, 'a4>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut pref: * const u8,
    mut elem: * const u8,
    mut prefix: Option<&'a1 mut * const u8>,
    mut value: Option<&'a2 mut * mut u8>,
    mut len: Option<&'a3 mut i32>,
    mut alloc: Option<&'a4 mut i32>,
) -> * const u8 {
    let mut name: * const u8 = 0 as *const xmlChar;
    let mut val: * mut u8 = 0 as *mut xmlChar;
    let mut internal_val: * mut u8 = 0 as *mut xmlChar;
    let mut normalize: i32 = 0 as i32;
    *(borrow_mut(&mut value)).unwrap() = 0 as *mut xmlChar;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    name = xmlParseQName(ctxt, borrow_mut(&mut prefix));
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"error parsing attribute name\n\0" as *const u8 as *const i8,
        );
        return 0 as *const xmlChar;
    }
    if !((*ctxt).attsSpecial).is_null() {
        let mut type_0: i32 = 0;
        type_0 = xmlHashQLookup2((*ctxt).attsSpecial, pref, elem, *(borrow(& prefix)).unwrap(), name)
            as ptrdiff_t as i32;
        if type_0 != 0 as i32 {
            normalize = 1 as i32;
        }
    }
    xmlSkipBlankChars(ctxt);
    if *(*(*ctxt).input).cur as i32 == '=' as i32 {
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        val = xmlParseAttValueInternal(ctxt, borrow_mut(&mut len), borrow_mut(&mut alloc), normalize);
        if normalize != 0 {
            if *(borrow(& alloc)).unwrap() != 0 {
                let mut val2: * const u8 = 0 as *const xmlChar;
                val2 = xmlAttrNormalizeSpace2(ctxt, val, borrow_mut(&mut len));
                if !val2.is_null() && val2 != val as *const xmlChar {
                    xmlFree
                        .expect("non-null function pointer")(val as *mut libc::c_void);
                    val = val2 as *mut xmlChar;
                }
            }
        }
        (*ctxt).instate = XML_PARSER_CONTENT;
    } else {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ATTRIBUTE_WITHOUT_VALUE,
            b"Specification mandates value for attribute %s\n\0" as *const u8
                as *const i8,
            name,
        );
        return 0 as *const xmlChar;
    }
    if *(borrow(& prefix)).unwrap() == (*ctxt).str_xml {
        if (*ctxt).pedantic != 0
            && xmlStrEqual(
                name,
                b"lang\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
        {
            internal_val = xmlStrndup(val, *(borrow_mut(&mut len)).unwrap());
            if xmlCheckLanguageID(internal_val) == 0 {
                xmlWarningMsg(
                    ctxt,
                    XML_WAR_LANG_VALUE,
                    b"Malformed value for xml:lang : %s\n\0" as *const u8
                        as *const i8,
                    internal_val,
                    0 as *const xmlChar,
                );
            }
        }
        if xmlStrEqual(
            name,
            b"space\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
        {
            internal_val = xmlStrndup(val, *(borrow_mut(&mut len)).unwrap());
            if xmlStrEqual(
                internal_val,
                b"default\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                *(*ctxt).space = 0 as i32;
            } else if xmlStrEqual(
                    internal_val,
                    b"preserve\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
                {
                *(*ctxt).space = 1 as i32;
            } else {
                xmlWarningMsg(
                    ctxt,
                    XML_WAR_SPACE_VALUE,
                    b"Invalid value \"%s\" for xml:space : \"default\" or \"preserve\" expected\n\0"
                        as *const u8 as *const i8,
                    internal_val,
                    0 as *const xmlChar,
                );
            }
        }
        if !internal_val.is_null() {
            xmlFree
                .expect("non-null function pointer")(internal_val as *mut libc::c_void);
        }
    }
    *(borrow_mut(&mut value)).unwrap() = val;
    return name;
}
unsafe extern "C" fn xmlParseStartTag2<'a1, 'a2, 'a3>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut pref: Option<&'a1 mut * const u8>,
    mut URI: Option<&'a2 mut * const u8>,
    mut tlen: Option<&'a3 mut i32>,
) -> * const u8 {
    let mut current_block: u64;
    let mut localname: * const u8 = 0 as *const xmlChar;
    let mut prefix: * const u8 = 0 as *const xmlChar;
    let mut attname: * const u8 = 0 as *const xmlChar;
    let mut aprefix: * const u8 = 0 as *const xmlChar;
    let mut nsname: * const u8 = 0 as *const xmlChar;
    let mut attvalue: * mut u8 = 0 as *mut xmlChar;
    let mut atts: * mut * const u8 = (*ctxt).atts;
    let mut maxatts: i32 = (*ctxt).maxatts;
    let mut nratts: i32 = 0;
    let mut nbatts: i32 = 0;
    let mut nbdef: i32 = 0;
    let mut inputid: i32 = 0;
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    let mut nbNs: i32 = 0;
    let mut attval: i32 = 0;
    let mut cur: u64 = 0;
    let mut nsNr: i32 = (*ctxt).nsNr;
    if *(*(*ctxt).input).cur as i32 != '<' as i32 {
        return 0 as *const xmlChar;
    }
    let fresh364 = &mut ((*(*ctxt).input).col);
    *fresh364 += 1;
    let fresh365 = &mut ((*(*ctxt).input).cur);
    *fresh365 = (*fresh365).offset(1);
    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
        xmlParserInputGrow((*ctxt).input, 250 as i32);
    }
    if (*ctxt).progressive == 0 as i32
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
            > (2 as i32 * 250 as i32) as i64
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    cur = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
        as u64;
    inputid = (*(*ctxt).input).id;
    nbatts = 0 as i32;
    nratts = 0 as i32;
    nbdef = 0 as i32;
    nbNs = 0 as i32;
    attval = 0 as i32;
    (*ctxt).nsNr = nsNr;
    localname = xmlParseQName(ctxt, Some(&mut prefix));
    if localname.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"StartTag: invalid element name\n\0" as *const u8 as *const i8,
        );
        return 0 as *const xmlChar;
    }
    *(borrow_mut(&mut tlen)).unwrap() = (((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
        as u64)
        .wrapping_sub(cur) as i32;
    xmlSkipBlankChars(ctxt);
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    loop {
        if !(*(*(*ctxt).input).cur as i32 != '>' as i32
            && (*(*(*ctxt).input).cur as i32 != '/' as i32
                || *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 != '>' as i32)
            && (0x9 as i32 <= *(*(*ctxt).input).cur as i32
                && *(*(*ctxt).input).cur as i32 <= 0xa as i32
                || *(*(*ctxt).input).cur as i32 == 0xd as i32
                || 0x20 as i32 <= *(*(*ctxt).input).cur as i32)
            && (*ctxt).instate as i32 != XML_PARSER_EOF as i32)
        {
            current_block = 9587810615301548814;
            break;
        }
        let mut id: i32 = (*(*ctxt).input).id;
        let mut cons: u64 = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
                    as u64,
            );
        let mut len: i32 = -(1 as i32);
        let mut alloc: i32 = 0 as i32;
        attname = xmlParseAttribute2(
            ctxt,
            prefix,
            localname,
            Some(&mut aprefix),
            Some(&mut attvalue),
            Some(&mut len),
            Some(&mut alloc),
        );
        if !(attname.is_null() || attvalue.is_null()) {
            if len < 0 as i32 {
                len = xmlStrlen(attvalue);
            }
            if attname == (*ctxt).str_xmlns && aprefix.is_null() {
                let mut URL: * const u8 = xmlDictLookup((*ctxt).dict, attvalue, len);
                let mut uri: * mut crate::src::SAX2::_xmlURI = 0 as *mut xmlURI;
                if URL.is_null() {
                    xmlErrMemory(
                        ctxt,
                        b"dictionary allocation failure\0" as *const u8
                            as *const i8,
                    );
                    if !attvalue.is_null() && alloc != 0 as i32 {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(attvalue as *mut libc::c_void);
                    }
                    localname = 0 as *const xmlChar;
                    current_block = 11274969702264896952;
                    break;
                } else {
                    if *URL as i32 != 0 as i32 {
                        uri = xmlParseURI(URL as *const i8);
                        if uri.is_null() {
                            xmlNsErr(
                                ctxt,
                                XML_WAR_NS_URI,
                                b"xmlns: '%s' is not a valid URI\n\0" as *const u8
                                    as *const i8,
                                URL,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                            );
                        } else {
                            if ((*uri).scheme).is_null() {
                                xmlNsWarn(
                                    ctxt,
                                    XML_WAR_NS_URI_RELATIVE,
                                    b"xmlns: URI %s is not absolute\n\0" as *const u8
                                        as *const i8,
                                    URL,
                                    0 as *const xmlChar,
                                    0 as *const xmlChar,
                                );
                            }
                            xmlFreeURI(uri);
                        }
                        if URL == (*ctxt).str_xml_ns {
                            if attname != (*ctxt).str_xml {
                                xmlNsErr(
                                    ctxt,
                                    XML_NS_ERR_XML_NAMESPACE,
                                    b"xml namespace URI cannot be the default namespace\n\0"
                                        as *const u8 as *const i8,
                                    0 as *const xmlChar,
                                    0 as *const xmlChar,
                                    0 as *const xmlChar,
                                );
                            }
                            current_block = 7554104004771910880;
                        } else if len == 29 as i32
                                && xmlStrEqual(
                                    URL,
                                    b"http://www.w3.org/2000/xmlns/\0" as *const u8
                                        as *const i8 as *mut xmlChar,
                                ) != 0
                            {
                            xmlNsErr(
                                ctxt,
                                XML_NS_ERR_XML_NAMESPACE,
                                b"reuse of the xmlns namespace name is forbidden\n\0"
                                    as *const u8 as *const i8,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                            );
                            current_block = 7554104004771910880;
                        } else {
                            current_block = 1623252117315916725;
                        }
                    } else {
                        current_block = 1623252117315916725;
                    }
                    match current_block {
                        7554104004771910880 => {}
                        _ => {
                            j = 1 as i32;
                            while j <= nbNs {
                                if (*((*ctxt).nsTab)
                                    .offset(((*ctxt).nsNr - 2 as i32 * j) as isize))
                                    .is_null()
                                {
                                    break;
                                }
                                j += 1;
                            }
                            if j <= nbNs {
                                xmlErrAttributeDup(ctxt, 0 as *const xmlChar, attname);
                            } else if nsPush(ctxt, 0 as *const xmlChar, URL)
                                    > 0 as i32
                                {
                                nbNs += 1;
                            }
                        }
                    }
                }
            } else if aprefix == (*ctxt).str_xmlns {
                let mut URL_0: * const u8 = xmlDictLookup(
                    (*ctxt).dict,
                    attvalue,
                    len,
                );
                let mut uri_0: * mut crate::src::SAX2::_xmlURI = 0 as *mut xmlURI;
                if attname == (*ctxt).str_xml {
                    if URL_0 != (*ctxt).str_xml_ns {
                        xmlNsErr(
                            ctxt,
                            XML_NS_ERR_XML_NAMESPACE,
                            b"xml namespace prefix mapped to wrong URI\n\0" as *const u8
                                as *const i8,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                    }
                } else if URL_0 == (*ctxt).str_xml_ns {
                    if attname != (*ctxt).str_xml {
                        xmlNsErr(
                            ctxt,
                            XML_NS_ERR_XML_NAMESPACE,
                            b"xml namespace URI mapped to wrong prefix\n\0" as *const u8
                                as *const i8,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                    }
                } else if attname == (*ctxt).str_xmlns {
                    xmlNsErr(
                        ctxt,
                        XML_NS_ERR_XML_NAMESPACE,
                        b"redefinition of the xmlns prefix is forbidden\n\0" as *const u8
                            as *const i8,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                } else if len == 29 as i32
                        && xmlStrEqual(
                            URL_0,
                            b"http://www.w3.org/2000/xmlns/\0" as *const u8
                                as *const i8 as *mut xmlChar,
                        ) != 0
                    {
                    xmlNsErr(
                        ctxt,
                        XML_NS_ERR_XML_NAMESPACE,
                        b"reuse of the xmlns namespace name is forbidden\n\0"
                            as *const u8 as *const i8,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                } else if URL_0.is_null()
                        || *URL_0.offset(0 as i32 as isize) as i32
                            == 0 as i32
                    {
                    xmlNsErr(
                        ctxt,
                        XML_NS_ERR_XML_NAMESPACE,
                        b"xmlns:%s: Empty XML namespace is not allowed\n\0" as *const u8
                            as *const i8,
                        attname,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                } else {
                    uri_0 = xmlParseURI(URL_0 as *const i8);
                    if uri_0.is_null() {
                        xmlNsErr(
                            ctxt,
                            XML_WAR_NS_URI,
                            b"xmlns:%s: '%s' is not a valid URI\n\0" as *const u8
                                as *const i8,
                            attname,
                            URL_0,
                            0 as *const xmlChar,
                        );
                    } else {
                        if (*ctxt).pedantic != 0 && ((*uri_0).scheme).is_null() {
                            xmlNsWarn(
                                ctxt,
                                XML_WAR_NS_URI_RELATIVE,
                                b"xmlns:%s: URI %s is not absolute\n\0" as *const u8
                                    as *const i8,
                                attname,
                                URL_0,
                                0 as *const xmlChar,
                            );
                        }
                        xmlFreeURI(uri_0);
                    }
                    j = 1 as i32;
                    while j <= nbNs {
                        if *((*ctxt).nsTab)
                            .offset(((*ctxt).nsNr - 2 as i32 * j) as isize)
                            == attname
                        {
                            break;
                        }
                        j += 1;
                    }
                    if j <= nbNs {
                        xmlErrAttributeDup(ctxt, aprefix, attname);
                    } else if nsPush(ctxt, attname, URL_0) > 0 as i32 {
                        nbNs += 1;
                    }
                }
            } else {
                if atts.is_null() || nbatts + 5 as i32 > maxatts {
                    if xmlCtxtGrowAttrs(ctxt, nbatts + 5 as i32)
                        < 0 as i32
                    {
                        current_block = 7554104004771910880;
                    } else {
                        maxatts = (*ctxt).maxatts;
                        atts = (*ctxt).atts;
                        current_block = 2463987395154258233;
                    }
                } else {
                    current_block = 2463987395154258233;
                }
                match current_block {
                    7554104004771910880 => {}
                    _ => {
                        let mut fresh366 = nratts;
                        nratts = nratts + 1;
                        *((*ctxt).attallocs).offset(fresh366 as isize) = alloc;
                        let mut fresh367 = nbatts;
                        nbatts = nbatts + 1;
                        let fresh368 = &mut (*atts.offset(fresh367 as isize));
                        *fresh368 = attname;
                        let mut fresh369 = nbatts;
                        nbatts = nbatts + 1;
                        let fresh370 = &mut (*atts.offset(fresh369 as isize));
                        *fresh370 = aprefix;
                        if alloc != 0 {
                            let mut fresh371 = nbatts;
                            nbatts = nbatts + 1;
                            let fresh372 = &mut (*atts.offset(fresh371 as isize));
                            *fresh372 = 0 as *const xmlChar;
                        } else {
                            let mut fresh373 = nbatts;
                            nbatts = nbatts + 1;
                            let fresh374 = &mut (*atts.offset(fresh373 as isize));
                            *fresh374 = (*(*ctxt).input).base;
                        }
                        let mut fresh375 = nbatts;
                        nbatts = nbatts + 1;
                        let fresh376 = &mut (*atts.offset(fresh375 as isize));
                        *fresh376 = attvalue;
                        attvalue = attvalue.offset(len as isize);
                        let mut fresh377 = nbatts;
                        nbatts = nbatts + 1;
                        let fresh378 = &mut (*atts.offset(fresh377 as isize));
                        *fresh378 = attvalue;
                        if alloc != 0 as i32 {
                            attval = 1 as i32;
                        }
                        attvalue = 0 as *mut xmlChar;
                    }
                }
            }
        }
        if !attvalue.is_null() && alloc != 0 as i32 {
            xmlFree.expect("non-null function pointer")(attvalue as *mut libc::c_void);
            attvalue = 0 as *mut xmlChar;
        }
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
            current_block = 9587810615301548814;
            break;
        }
        if *(*(*ctxt).input).cur as i32 == '>' as i32
            || *(*(*ctxt).input).cur as i32 == '/' as i32
                && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == '>' as i32
        {
            current_block = 9587810615301548814;
            break;
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"attributes construct error\n\0" as *const u8 as *const i8,
            );
            current_block = 9587810615301548814;
            break;
        } else if cons
                == ((*(*ctxt).input).consumed)
                    .wrapping_add(
                        ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as i64 as u64,
                    ) && id == (*(*ctxt).input).id && attname.is_null()
                && attvalue.is_null()
            {
            xmlFatalErr(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"xmlParseStartTag: problem parsing attributes\n\0" as *const u8
                    as *const i8,
            );
            current_block = 9587810615301548814;
            break;
        } else if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
            xmlGROW(ctxt);
        }
    }
    match current_block {
        9587810615301548814 => {
            if (*(*ctxt).input).id != inputid {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_INTERNAL_ERROR,
                    b"Unexpected change of input\n\0" as *const u8 as *const i8,
                );
                localname = 0 as *const xmlChar;
            } else {
                i = 0 as i32;
                j = 0 as i32;
                while j < nratts {
                    if !(*atts.offset((i + 2 as i32) as isize)).is_null() {
                        let mut offset: i64 = ((*(*ctxt).input).base)
                            .offset_from(*atts.offset((i + 2 as i32) as isize))
                            as i64;
                        let fresh379 = &mut (*atts
                            .offset((i + 2 as i32) as isize));
                        *fresh379 = 0 as *const xmlChar;
                        let fresh380 = &mut (*atts
                            .offset((i + 3 as i32) as isize));
                        *fresh380 = (*fresh380).offset(offset as isize);
                        let fresh381 = &mut (*atts
                            .offset((i + 4 as i32) as isize));
                        *fresh381 = (*fresh381).offset(offset as isize);
                    }
                    i += 5 as i32;
                    j += 1;
                }
                if !((*ctxt).attsDefault).is_null() {
                    let mut defaults: * mut crate::src::parser::_xmlDefAttrs = (0 as * mut crate::src::parser::_xmlDefAttrs);
                    defaults = xmlHashLookup2((*ctxt).attsDefault, localname, prefix)
                        as xmlDefAttrsPtr;
                    if !defaults.is_null() {
                        i = 0 as i32;
                        loop {
                            if !(i < (*defaults).nbAttrs) {
                                current_block = 981657943452992752;
                                break;
                            }
                            attname = (*crate::__laertes_array::Get::<&_>::get_offset(((*defaults).values).as_ref().unwrap(), ((5 as i32 * i) as isize)));
                            aprefix = (*crate::__laertes_array::Get::<&_>::get_offset(((*defaults).values).as_ref().unwrap(), ((5 as i32 * i + 1 as i32) as isize)));
                            if attname == (*ctxt).str_xmlns && aprefix.is_null() {
                                j = 1 as i32;
                                while j <= nbNs {
                                    if (*((*ctxt).nsTab)
                                        .offset(((*ctxt).nsNr - 2 as i32 * j) as isize))
                                        .is_null()
                                    {
                                        break;
                                    }
                                    j += 1;
                                }
                                if !(j <= nbNs) {
                                    nsname = xmlGetNamespace(ctxt, 0 as *const xmlChar);
                                    if nsname
                                        != (*crate::__laertes_array::Get::<&_>::get_offset(((*defaults).values).as_ref().unwrap(), ((5 as i32 * i + 2 as i32) as isize)))
                                    {
                                        if nsPush(
                                            ctxt,
                                            0 as *const xmlChar,
                                            (*crate::__laertes_array::Get::<&_>::get_offset(((*defaults).values).as_ref().unwrap(), ((5 as i32 * i + 2 as i32) as isize))),
                                        ) > 0 as i32
                                        {
                                            nbNs += 1;
                                        }
                                    }
                                }
                            } else if aprefix == (*ctxt).str_xmlns {
                                j = 1 as i32;
                                while j <= nbNs {
                                    if *((*ctxt).nsTab)
                                        .offset(((*ctxt).nsNr - 2 as i32 * j) as isize)
                                        == attname
                                    {
                                        break;
                                    }
                                    j += 1;
                                }
                                if !(j <= nbNs) {
                                    nsname = xmlGetNamespace(ctxt, attname);
                                    if nsname
                                        != (*crate::__laertes_array::Get::<&_>::get_offset(((*defaults).values).as_ref().unwrap(), (2 as i32 as isize)))
                                    {
                                        if nsPush(
                                            ctxt,
                                            attname,
                                            (*crate::__laertes_array::Get::<&_>::get_offset(((*defaults).values).as_ref().unwrap(), ((5 as i32 * i + 2 as i32) as isize))),
                                        ) > 0 as i32
                                        {
                                            nbNs += 1;
                                        }
                                    }
                                }
                            } else {
                                j = 0 as i32;
                                while j < nbatts {
                                    if attname == *atts.offset(j as isize)
                                        && aprefix == *atts.offset((j + 1 as i32) as isize)
                                    {
                                        break;
                                    }
                                    j += 5 as i32;
                                }
                                if !(j < nbatts) {
                                    if atts.is_null() || nbatts + 5 as i32 > maxatts {
                                        if xmlCtxtGrowAttrs(ctxt, nbatts + 5 as i32)
                                            < 0 as i32
                                        {
                                            localname = 0 as *const xmlChar;
                                            current_block = 11274969702264896952;
                                            break;
                                        } else {
                                            maxatts = (*ctxt).maxatts;
                                            atts = (*ctxt).atts;
                                        }
                                    }
                                    let mut fresh382 = nbatts;
                                    nbatts = nbatts + 1;
                                    let fresh383 = &mut (*atts.offset(fresh382 as isize));
                                    *fresh383 = attname;
                                    let mut fresh384 = nbatts;
                                    nbatts = nbatts + 1;
                                    let fresh385 = &mut (*atts.offset(fresh384 as isize));
                                    *fresh385 = aprefix;
                                    if aprefix.is_null() {
                                        let mut fresh386 = nbatts;
                                        nbatts = nbatts + 1;
                                        let fresh387 = &mut (*atts.offset(fresh386 as isize));
                                        *fresh387 = 0 as *const xmlChar;
                                    } else {
                                        let mut fresh388 = nbatts;
                                        nbatts = nbatts + 1;
                                        let fresh389 = &mut (*atts.offset(fresh388 as isize));
                                        *fresh389 = xmlGetNamespace(ctxt, aprefix);
                                    }
                                    let mut fresh390 = nbatts;
                                    nbatts = nbatts + 1;
                                    let fresh391 = &mut (*atts.offset(fresh390 as isize));
                                    *fresh391 = (*crate::__laertes_array::Get::<&_>::get_offset(((*defaults).values).as_ref().unwrap(), ((5 as i32 * i + 2 as i32) as isize)));
                                    let mut fresh392 = nbatts;
                                    nbatts = nbatts + 1;
                                    let fresh393 = &mut (*atts.offset(fresh392 as isize));
                                    *fresh393 = (*crate::__laertes_array::Get::<&_>::get_offset(((*defaults).values).as_ref().unwrap(), ((5 as i32 * i + 3 as i32) as isize)));
                                    if (*ctxt).standalone == 1 as i32
                                        && !(*crate::__laertes_array::Get::<&_>::get_offset(((*defaults).values).as_ref().unwrap(), ((5 as i32 * i + 4 as i32) as isize)))
                                            .is_null()
                                    {
                                        xmlValidityError(
                                            ctxt,
                                            XML_DTD_STANDALONE_DEFAULTED,
                                            b"standalone: attribute %s on %s defaulted from external subset\n\0"
                                                as *const u8 as *const i8,
                                            attname,
                                            localname,
                                        );
                                    }
                                    nbdef += 1;
                                }
                            }
                            i += 1;
                        }
                    } else {
                        current_block = 981657943452992752;
                    }
                } else {
                    current_block = 981657943452992752;
                }
                match current_block {
                    11274969702264896952 => {}
                    _ => {
                        i = 0 as i32;
                        while i < nbatts {
                            if !(*atts.offset((i + 1 as i32) as isize)).is_null()
                            {
                                nsname = xmlGetNamespace(
                                    ctxt,
                                    *atts.offset((i + 1 as i32) as isize),
                                );
                                if nsname.is_null() {
                                    xmlNsErr(
                                        ctxt,
                                        XML_NS_ERR_UNDEFINED_NAMESPACE,
                                        b"Namespace prefix %s for %s on %s is not defined\n\0"
                                            as *const u8 as *const i8,
                                        *atts.offset((i + 1 as i32) as isize),
                                        *atts.offset(i as isize),
                                        localname,
                                    );
                                }
                                let fresh394 = &mut (*atts
                                    .offset((i + 2 as i32) as isize));
                                *fresh394 = nsname;
                            } else {
                                nsname = 0 as *const xmlChar;
                            }
                            j = 0 as i32;
                            while j < i {
                                if *atts.offset(i as isize) == *atts.offset(j as isize) {
                                    if *atts.offset((i + 1 as i32) as isize)
                                        == *atts.offset((j + 1 as i32) as isize)
                                    {
                                        xmlErrAttributeDup(
                                            ctxt,
                                            *atts.offset((i + 1 as i32) as isize),
                                            *atts.offset(i as isize),
                                        );
                                        break;
                                    } else if !nsname.is_null()
                                            && *atts.offset((j + 2 as i32) as isize) == nsname
                                        {
                                        xmlNsErr(
                                            ctxt,
                                            XML_NS_ERR_ATTRIBUTE_REDEFINED,
                                            b"Namespaced Attribute %s in '%s' redefined\n\0"
                                                as *const u8 as *const i8,
                                            *atts.offset(i as isize),
                                            nsname,
                                            0 as *const xmlChar,
                                        );
                                        break;
                                    }
                                }
                                j += 5 as i32;
                            }
                            i += 5 as i32;
                        }
                        nsname = xmlGetNamespace(ctxt, prefix);
                        if !prefix.is_null() && nsname.is_null() {
                            xmlNsErr(
                                ctxt,
                                XML_NS_ERR_UNDEFINED_NAMESPACE,
                                b"Namespace prefix %s on %s is not defined\n\0" as *const u8
                                    as *const i8,
                                prefix,
                                localname,
                                0 as *const xmlChar,
                            );
                        }
                        *(borrow_mut(&mut pref)).unwrap() = prefix;
                        *(borrow_mut(&mut URI)).unwrap() = nsname;
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).startElementNs).is_some()
                            && (*ctxt).disableSAX == 0
                        {
                            if nbNs > 0 as i32 {
                                ((*(*ctxt).sax).startElementNs)
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    (*ctxt).userData,
                                    localname,
                                    prefix,
                                    nsname,
                                    nbNs,
                                    &mut *((*ctxt).nsTab)
                                        .offset(((*ctxt).nsNr - 2 as i32 * nbNs) as isize),
                                    nbatts / 5 as i32,
                                    nbdef,
                                    atts,
                                );
                            } else {
                                ((*(*ctxt).sax).startElementNs)
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    (*ctxt).userData,
                                    localname,
                                    prefix,
                                    nsname,
                                    0 as i32,
                                    0 as *mut *const xmlChar,
                                    nbatts / 5 as i32,
                                    nbdef,
                                    atts,
                                );
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    if attval != 0 as i32 {
        i = 3 as i32;
        j = 0 as i32;
        while j < nratts {
            if *((*ctxt).attallocs).offset(j as isize) != 0 as i32
                && !(*atts.offset(i as isize)).is_null()
            {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(*atts.offset(i as isize) as *mut xmlChar as *mut libc::c_void);
            }
            i += 5 as i32;
            j += 1;
        }
    }
    return localname;
}
unsafe extern "C" fn xmlParseEndTag2<'a1>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut tag: Option<&'a1 crate::src::parser::_xmlStartTag>,
) {
    let mut name: * const u8 = 0 as *const xmlChar;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if *(*(*ctxt).input).cur as i32 != '<' as i32
        || *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            != '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_LTSLASH_REQUIRED, 0 as *const i8);
        return;
    }
    let fresh395 = &mut ((*(*ctxt).input).cur);
    *fresh395 = (*fresh395).offset(2 as i32 as isize);
    (*(*ctxt).input).col += 2 as i32;
    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
        xmlParserInputGrow((*ctxt).input, 250 as i32);
    }
    if ((*(tag).unwrap()).prefix).is_null() {
        name = xmlParseNameAndCompare(ctxt, (*ctxt).name);
    } else {
        name = xmlParseQNameAndCompare(ctxt, (*ctxt).name, (*((tag).clone()).unwrap()).prefix);
    }
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return;
    }
    xmlSkipBlankChars(ctxt);
    if !(0x9 as i32 <= *(*(*ctxt).input).cur as i32
        && *(*(*ctxt).input).cur as i32 <= 0xa as i32
        || *(*(*ctxt).input).cur as i32 == 0xd as i32
        || 0x20 as i32 <= *(*(*ctxt).input).cur as i32)
        || *(*(*ctxt).input).cur as i32 != '>' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_GT_REQUIRED, 0 as *const i8);
    } else {
        let fresh396 = &mut ((*(*ctxt).input).col);
        *fresh396 += 1;
        let fresh397 = &mut ((*(*ctxt).input).cur);
        *fresh397 = (*fresh397).offset(1);
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
    }
    if name != 1 as i32 as *mut xmlChar as *const xmlChar {
        if name.is_null() {
            name = b"unparsable\0" as *const u8 as *const i8 as *mut xmlChar;
        }
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_TAG_NAME_MISMATCH,
            b"Opening and ending tag mismatch: %s line %d and %s\n\0" as *const u8
                as *const i8,
            (*ctxt).name,
            (*(tag).unwrap()).line,
            name,
        );
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElementNs).is_some()
        && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).endElementNs)
            .expect(
                "non-null function pointer",
            )((*ctxt).userData, (*ctxt).name, (*((tag).clone()).unwrap()).prefix, (*((tag).clone()).unwrap()).URI);
    }
    spacePop(ctxt);
    if (*((tag).clone()).unwrap()).nsNr != 0 as i32 {
        nsPop(ctxt, (*(tag).unwrap()).nsNr);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseCDSect(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut buf: * mut u8 = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 100 as i32;
    let mut r: i32 = 0;
    let mut rl: i32 = 0;
    let mut s: i32 = 0;
    let mut sl: i32 = 0;
    let mut cur: i32 = 0;
    let mut l: i32 = 0;
    let mut count: i32 = 0 as i32;
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '<' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == '!' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == '[' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'C' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'D' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'A' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(7 as i32 as isize) as i32 == 'A' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(8 as i32 as isize) as i32 == '[' as i32
    {
        let fresh398 = &mut ((*(*ctxt).input).cur);
        *fresh398 = (*fresh398).offset(9 as i32 as isize);
        (*(*ctxt).input).col += 9 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
    } else {
        return
    }
    (*ctxt).instate = XML_PARSER_CDATA_SECTION;
    r = xmlCurrentChar(ctxt, Some(&mut rl));
    if if r < 0x100 as i32 {
        (0x9 as i32 <= r && r <= 0xa as i32 || r == 0xd as i32
            || 0x20 as i32 <= r) as i32
    } else {
        (0x100 as i32 <= r && r <= 0xd7ff as i32
            || 0xe000 as i32 <= r && r <= 0xfffd as i32
            || 0x10000 as i32 <= r && r <= 0x10ffff as i32)
            as i32
    } == 0
    {
        xmlFatalErr(ctxt, XML_ERR_CDATA_NOT_FINISHED, 0 as *const i8);
        (*ctxt).instate = XML_PARSER_CONTENT;
        return;
    }
    if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
        let fresh399 = &mut ((*(*ctxt).input).line);
        *fresh399 += 1;
        (*(*ctxt).input).col = 1 as i32;
    } else {
        let fresh400 = &mut ((*(*ctxt).input).col);
        *fresh400 += 1;
    }
    let fresh401 = &mut ((*(*ctxt).input).cur);
    *fresh401 = (*fresh401).offset(rl as isize);
    s = xmlCurrentChar(ctxt, Some(&mut sl));
    if if s < 0x100 as i32 {
        (0x9 as i32 <= s && s <= 0xa as i32 || s == 0xd as i32
            || 0x20 as i32 <= s) as i32
    } else {
        (0x100 as i32 <= s && s <= 0xd7ff as i32
            || 0xe000 as i32 <= s && s <= 0xfffd as i32
            || 0x10000 as i32 <= s && s <= 0x10ffff as i32)
            as i32
    } == 0
    {
        xmlFatalErr(ctxt, XML_ERR_CDATA_NOT_FINISHED, 0 as *const i8);
        (*ctxt).instate = XML_PARSER_CONTENT;
        return;
    }
    if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
        let fresh402 = &mut ((*(*ctxt).input).line);
        *fresh402 += 1;
        (*(*ctxt).input).col = 1 as i32;
    } else {
        let fresh403 = &mut ((*(*ctxt).input).col);
        *fresh403 += 1;
    }
    let fresh404 = &mut ((*(*ctxt).input).cur);
    *fresh404 = (*fresh404).offset(sl as isize);
    cur = xmlCurrentChar(ctxt, Some(&mut l));
    buf = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (size as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) as *mut xmlChar;
    if buf.is_null() {
        xmlErrMemory(ctxt, 0 as *const i8);
        return;
    }
    while (if cur < 0x100 as i32 {
        (0x9 as i32 <= cur && cur <= 0xa as i32
            || cur == 0xd as i32 || 0x20 as i32 <= cur) as i32
    } else {
        (0x100 as i32 <= cur && cur <= 0xd7ff as i32
            || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
            || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32)
            as i32
    }) != 0 && (r != ']' as i32 || s != ']' as i32 || cur != '>' as i32)
    {
        if len + 5 as i32 >= size {
            let mut tmp: * mut u8 = 0 as *mut xmlChar;
            if size > 10000000 as i32
                && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
            {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_CDATA_NOT_FINISHED,
                    b"CData section too big found\0" as *const u8 as *const i8,
                    0 as *const xmlChar,
                );
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return;
            }
            tmp = xmlRealloc
                .expect(
                    "non-null function pointer",
                )(
                buf as *mut libc::c_void,
                ((size * 2 as i32) as u64)
                    .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) as *mut xmlChar;
            if tmp.is_null() {
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                xmlErrMemory(ctxt, 0 as *const i8);
                return;
            }
            buf = tmp;
            size *= 2 as i32;
        }
        if rl == 1 as i32 {
            let mut fresh405 = len;
            len = len + 1;
            *buf.offset(fresh405 as isize) = r as xmlChar;
        } else {
            len += xmlCopyCharMultiByte(&mut *buf.offset(len as isize), r);
        }
        r = s;
        rl = sl;
        s = cur;
        sl = l;
        count += 1;
        if count > 50 as i32 {
            if (*ctxt).progressive == 0 as i32
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as i64
                    > (2 as i32 * 250 as i32) as i64
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            if (*ctxt).progressive == 0 as i32
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return;
            }
            count = 0 as i32;
        }
        if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
            let fresh406 = &mut ((*(*ctxt).input).line);
            *fresh406 += 1;
            (*(*ctxt).input).col = 1 as i32;
        } else {
            let fresh407 = &mut ((*(*ctxt).input).col);
            *fresh407 += 1;
        }
        let fresh408 = &mut ((*(*ctxt).input).cur);
        *fresh408 = (*fresh408).offset(l as isize);
        cur = xmlCurrentChar(ctxt, Some(&mut l));
    }
    *buf.offset(len as isize) = 0 as i32 as xmlChar;
    (*ctxt).instate = XML_PARSER_CONTENT;
    if cur != '>' as i32 {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_CDATA_NOT_FINISHED,
            b"CData section not finished\n%.50s\n\0" as *const u8 as *const i8,
            buf,
        );
        xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
        return;
    }
    if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
        let fresh409 = &mut ((*(*ctxt).input).line);
        *fresh409 += 1;
        (*(*ctxt).input).col = 1 as i32;
    } else {
        let fresh410 = &mut ((*(*ctxt).input).col);
        *fresh410 += 1;
    }
    let fresh411 = &mut ((*(*ctxt).input).cur);
    *fresh411 = (*fresh411).offset(l as isize);
    if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0 {
        if ((*(*ctxt).sax).cdataBlock).is_some() {
            ((*(*ctxt).sax).cdataBlock)
                .expect("non-null function pointer")((*ctxt).userData, buf, len);
        } else if ((*(*ctxt).sax).characters).is_some() {
            ((*(*ctxt).sax).characters)
                .expect("non-null function pointer")((*ctxt).userData, buf, len);
        }
    }
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
}
unsafe extern "C" fn xmlParseContentInternal(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut nameNr: i32 = (*ctxt).nameNr;
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    while *(*(*ctxt).input).cur as i32 != 0 as i32
        && (*ctxt).instate as i32 != XML_PARSER_EOF as i32
    {
        let mut id: i32 = (*(*ctxt).input).id;
        let mut cons: u64 = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
                    as u64,
            );
        let mut cur: * const u8 = (*(*ctxt).input).cur;
        if *cur as i32 == '<' as i32
            && *cur.offset(1 as i32 as isize) as i32 == '?' as i32
        {
            xmlParsePI(ctxt);
        } else if *((*(*ctxt).input).cur as *mut u8)
                .offset(0 as i32 as isize) as i32 == '<' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(1 as i32 as isize) as i32 == '!' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(2 as i32 as isize) as i32 == '[' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(3 as i32 as isize) as i32 == 'C' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(4 as i32 as isize) as i32 == 'D' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(5 as i32 as isize) as i32 == 'A' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(6 as i32 as isize) as i32 == 'T' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(7 as i32 as isize) as i32 == 'A' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(8 as i32 as isize) as i32 == '[' as i32
            {
            xmlParseCDSect(ctxt);
        } else if *cur as i32 == '<' as i32
                && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == '!' as i32
                && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                    as i32 == '-' as i32
                && *((*(*ctxt).input).cur).offset(3 as i32 as isize)
                    as i32 == '-' as i32
            {
            xmlParseComment(ctxt);
            (*ctxt).instate = XML_PARSER_CONTENT;
        } else if *cur as i32 == '<' as i32 {
            if *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
                == '/' as i32
            {
                if (*ctxt).nameNr <= nameNr {
                    break;
                }
                xmlParseElementEnd(ctxt);
            } else {
                xmlParseElementStart(ctxt);
            }
        } else if *cur as i32 == '&' as i32 {
            xmlParseReference(ctxt);
        } else {
            xmlParseCharData(ctxt, 0 as i32);
        }
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if (*ctxt).progressive == 0 as i32
            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
                > (2 as i32 * 250 as i32) as i64
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < (2 as i32 * 250 as i32) as i64
        {
            xmlSHRINK(ctxt);
        }
        if !(cons
            == ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as i64 as u64,
                ) && id == (*(*ctxt).input).id)
        {
            continue;
        }
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"detected an error in element content\n\0" as *const u8
                as *const i8,
        );
        xmlHaltParser(ctxt);
        break;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseContent(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut nameNr: i32 = (*ctxt).nameNr;
    xmlParseContentInternal(ctxt);
    if (*ctxt).instate as i32 != XML_PARSER_EOF as i32
        && (*ctxt).nameNr > nameNr
    {
        let mut name: * const u8 = *((*ctxt).nameTab)
            .offset(((*ctxt).nameNr - 1 as i32) as isize);
        let mut line: i32 = (*((*ctxt).pushTab)
            .offset(((*ctxt).nameNr - 1 as i32) as isize))
            .line;
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_TAG_NOT_FINISHED,
            b"Premature end of data in tag %s line %d\n\0" as *const u8
                as *const i8,
            name,
            line,
            0 as *const xmlChar,
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseElement(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    if xmlParseElementStart(ctxt) != 0 as i32 {
        return;
    }
    xmlParseContentInternal(ctxt);
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return;
    }
    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
        let mut name: * const u8 = *((*ctxt).nameTab)
            .offset(((*ctxt).nameNr - 1 as i32) as isize);
        let mut line: i32 = (*((*ctxt).pushTab)
            .offset(((*ctxt).nameNr - 1 as i32) as isize))
            .line;
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_TAG_NOT_FINISHED,
            b"Premature end of data in tag %s line %d\n\0" as *const u8
                as *const i8,
            name,
            line,
            0 as *const xmlChar,
        );
        return;
    }
    xmlParseElementEnd(ctxt);
}
unsafe extern "C" fn xmlParseElementStart(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> i32 {
    let mut name: * const u8 = 0 as *const xmlChar;
    let mut prefix: * const u8 = 0 as *const xmlChar;
    let mut URI: * const u8 = 0 as *const xmlChar;
    let mut node_info: crate::src::HTMLparser::_xmlParserNodeInfo = xmlParserNodeInfo {
        node: 0 as *const _xmlNode,
        begin_pos: 0,
        begin_line: 0,
        end_pos: 0,
        end_line: 0,
    };
    let mut line: i32 = 0;
    let mut tlen: i32 = 0 as i32;
    let mut ret: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    let mut nsNr: i32 = (*ctxt).nsNr;
    if (*ctxt).nameNr as u32 > xmlParserMaxDepth
        && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
    {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"Excessive depth in document: %d use XML_PARSE_HUGE option\n\0" as *const u8
                as *const i8,
            xmlParserMaxDepth as i32,
        );
        xmlHaltParser(ctxt);
        return -(1 as i32);
    }
    if (*ctxt).record_info != 0 {
        node_info
            .begin_pos = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
                    as u64,
            );
        node_info.begin_line = (*(*ctxt).input).line as u64;
    }
    if (*ctxt).spaceNr == 0 as i32 {
        spacePush(ctxt, -(1 as i32));
    } else if *(*ctxt).space == -(2 as i32) {
        spacePush(ctxt, -(1 as i32));
    } else {
        spacePush(ctxt, *(*ctxt).space);
    }
    line = (*(*ctxt).input).line;
    if (*ctxt).sax2 != 0 {
        name = xmlParseStartTag2(ctxt, Some(&mut prefix), Some(&mut URI), Some(&mut tlen));
    } else {
        name = xmlParseStartTag(ctxt);
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    if name.is_null() {
        spacePop(ctxt);
        return -(1 as i32);
    }
    nameNsPush(ctxt, name, prefix, URI, line, (*ctxt).nsNr - nsNr);
    ret = (*ctxt).node;
    if (*ctxt).validate != 0 && (*ctxt).wellFormed != 0 && !((*ctxt).myDoc).is_null()
        && !((*ctxt).node).is_null() && (*ctxt).node == (*(*ctxt).myDoc).children
    {
        (*ctxt).valid &= xmlValidateRoot(&mut (*ctxt).vctxt, (*ctxt).myDoc);
    }
    if *(*(*ctxt).input).cur as i32 == '/' as i32
        && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            == '>' as i32
    {
        let fresh412 = &mut ((*(*ctxt).input).cur);
        *fresh412 = (*fresh412).offset(2 as i32 as isize);
        (*(*ctxt).input).col += 2 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        if (*ctxt).sax2 != 0 {
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElementNs).is_some()
                && (*ctxt).disableSAX == 0
            {
                ((*(*ctxt).sax).endElementNs)
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).userData, name, prefix, URI);
            }
        } else if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElement).is_some()
                && (*ctxt).disableSAX == 0
            {
            ((*(*ctxt).sax).endElement)
                .expect("non-null function pointer")((*ctxt).userData, name);
        }
        namePop(ctxt);
        spacePop(ctxt);
        if nsNr != (*ctxt).nsNr {
            nsPop(ctxt, (*ctxt).nsNr - nsNr);
        }
        if !ret.is_null() && (*ctxt).record_info != 0 {
            node_info
                .end_pos = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as i64 as u64,
                );
            node_info.end_line = (*(*ctxt).input).line as u64;
            node_info.node = ret as *const _xmlNode;
            xmlParserAddNodeInfo(ctxt, &mut node_info);
        }
        return 1 as i32;
    }
    if *(*(*ctxt).input).cur as i32 == '>' as i32 {
        let fresh413 = &mut ((*(*ctxt).input).col);
        *fresh413 += 1;
        let fresh414 = &mut ((*(*ctxt).input).cur);
        *fresh414 = (*fresh414).offset(1);
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
    } else {
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_GT_REQUIRED,
            b"Couldn't find end of Start Tag %s line %d\n\0" as *const u8
                as *const i8,
            name,
            line,
            0 as *const xmlChar,
        );
        nodePop(ctxt);
        namePop(ctxt);
        spacePop(ctxt);
        if nsNr != (*ctxt).nsNr {
            nsPop(ctxt, (*ctxt).nsNr - nsNr);
        }
        if !ret.is_null() && (*ctxt).record_info != 0 {
            node_info
                .end_pos = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as i64 as u64,
                );
            node_info.end_line = (*(*ctxt).input).line as u64;
            node_info.node = ret as *const _xmlNode;
            xmlParserAddNodeInfo(ctxt, &mut node_info);
        }
        return -(1 as i32);
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlParseElementEnd(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut node_info: crate::src::HTMLparser::_xmlParserNodeInfo = xmlParserNodeInfo {
        node: 0 as *const _xmlNode,
        begin_pos: 0,
        begin_line: 0,
        end_pos: 0,
        end_line: 0,
    };
    let mut ret: * mut crate::src::HTMLparser::_xmlNode = (*ctxt).node;
    if (*ctxt).nameNr <= 0 as i32 {
        return;
    }
    if (*ctxt).sax2 != 0 {
        xmlParseEndTag2(
            ctxt,
            Some(&mut *((*ctxt).pushTab).offset(((*ctxt).nameNr - 1 as i32) as isize)),
        );
        namePop(ctxt);
    } else {
        xmlParseEndTag1(ctxt, 0 as i32);
    }
    if !ret.is_null() && (*ctxt).record_info != 0 {
        node_info
            .end_pos = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
                    as u64,
            );
        node_info.end_line = (*(*ctxt).input).line as u64;
        node_info.node = ret as *const _xmlNode;
        xmlParserAddNodeInfo(ctxt, &mut node_info);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseVersionNum(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * mut u8 {
    let mut buf: * mut u8 = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 10 as i32;
    let mut cur: u8 = 0;
    buf = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (size as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) as *mut xmlChar;
    if buf.is_null() {
        xmlErrMemory(ctxt, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    cur = *(*(*ctxt).input).cur;
    if !(cur as i32 >= '0' as i32 && cur as i32 <= '9' as i32) {
        xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
        return 0 as *mut xmlChar;
    }
    let mut fresh415 = len;
    len = len + 1;
    *buf.offset(fresh415 as isize) = cur;
    xmlNextChar(ctxt);
    cur = *(*(*ctxt).input).cur;
    if cur as i32 != '.' as i32 {
        xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
        return 0 as *mut xmlChar;
    }
    let mut fresh416 = len;
    len = len + 1;
    *buf.offset(fresh416 as isize) = cur;
    xmlNextChar(ctxt);
    cur = *(*(*ctxt).input).cur;
    while cur as i32 >= '0' as i32 && cur as i32 <= '9' as i32 {
        if len + 1 as i32 >= size {
            let mut tmp: * mut u8 = 0 as *mut xmlChar;
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
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                xmlErrMemory(ctxt, 0 as *const i8);
                return 0 as *mut xmlChar;
            }
            buf = tmp;
        }
        let mut fresh417 = len;
        len = len + 1;
        *buf.offset(fresh417 as isize) = cur;
        xmlNextChar(ctxt);
        cur = *(*(*ctxt).input).cur;
    }
    *buf.offset(len as isize) = 0 as i32 as xmlChar;
    return buf;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseVersionInfo(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
) -> * mut u8 {
    let mut version: * mut u8 = 0 as *mut xmlChar;
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == 'v' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == 'e' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'r' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 's' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'i' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'o' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'n' as i32
    {
        let fresh418 = &mut ((*(*ctxt).input).cur);
        *fresh418 = (*fresh418).offset(7 as i32 as isize);
        (*(*ctxt).input).col += 7 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as i32 != '=' as i32 {
            xmlFatalErr(ctxt, XML_ERR_EQUAL_REQUIRED, 0 as *const i8);
            return 0 as *mut xmlChar;
        }
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as i32 == '"' as i32 {
            xmlNextChar(ctxt);
            version = xmlParseVersionNum(ctxt);
            if *(*(*ctxt).input).cur as i32 != '"' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const i8);
            } else {
                xmlNextChar(ctxt);
            }
        } else if *(*(*ctxt).input).cur as i32 == '\'' as i32 {
            xmlNextChar(ctxt);
            version = xmlParseVersionNum(ctxt);
            if *(*(*ctxt).input).cur as i32 != '\'' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const i8);
            } else {
                xmlNextChar(ctxt);
            }
        } else {
            xmlFatalErr(ctxt, XML_ERR_STRING_NOT_STARTED, 0 as *const i8);
        }
    }
    return version;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEncName(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> * mut u8 {
    let mut buf: * mut u8 = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 10 as i32;
    let mut cur: u8 = 0;
    cur = *(*(*ctxt).input).cur;
    if cur as i32 >= 'a' as i32 && cur as i32 <= 'z' as i32
        || cur as i32 >= 'A' as i32 && cur as i32 <= 'Z' as i32
    {
        buf = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )(
            (size as u64)
                .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        ) as *mut xmlChar;
        if buf.is_null() {
            xmlErrMemory(ctxt, 0 as *const i8);
            return 0 as *mut xmlChar;
        }
        let mut fresh419 = len;
        len = len + 1;
        *buf.offset(fresh419 as isize) = cur;
        xmlNextChar(ctxt);
        cur = *(*(*ctxt).input).cur;
        while cur as i32 >= 'a' as i32 && cur as i32 <= 'z' as i32
            || cur as i32 >= 'A' as i32 && cur as i32 <= 'Z' as i32
            || cur as i32 >= '0' as i32 && cur as i32 <= '9' as i32
            || cur as i32 == '.' as i32 || cur as i32 == '_' as i32
            || cur as i32 == '-' as i32
        {
            if len + 1 as i32 >= size {
                let mut tmp: * mut u8 = 0 as *mut xmlChar;
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
                    xmlErrMemory(ctxt, 0 as *const i8);
                    xmlFree
                        .expect("non-null function pointer")(buf as *mut libc::c_void);
                    return 0 as *mut xmlChar;
                }
                buf = tmp;
            }
            let mut fresh420 = len;
            len = len + 1;
            *buf.offset(fresh420 as isize) = cur;
            xmlNextChar(ctxt);
            cur = *(*(*ctxt).input).cur;
            if cur as i32 == 0 as i32 {
                if (*ctxt).progressive == 0 as i32
                    && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as i64
                        > (2 as i32 * 250 as i32) as i64
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64)
                        < (2 as i32 * 250 as i32) as i64
                {
                    xmlSHRINK(ctxt);
                }
                if (*ctxt).progressive == 0 as i32
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as i64) < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                cur = *(*(*ctxt).input).cur;
            }
        }
        *buf.offset(len as isize) = 0 as i32 as xmlChar;
    } else {
        xmlFatalErr(ctxt, XML_ERR_ENCODING_NAME, 0 as *const i8);
    }
    return buf;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEncodingDecl(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
) -> * const u8 {
    let mut encoding: * mut u8 = 0 as *mut xmlChar;
    xmlSkipBlankChars(ctxt);
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == 'e' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == 'n' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'c' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'o' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'd' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'i' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'n' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(7 as i32 as isize) as i32 == 'g' as i32
    {
        let fresh421 = &mut ((*(*ctxt).input).cur);
        *fresh421 = (*fresh421).offset(8 as i32 as isize);
        (*(*ctxt).input).col += 8 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as i32 != '=' as i32 {
            xmlFatalErr(ctxt, XML_ERR_EQUAL_REQUIRED, 0 as *const i8);
            return 0 as *const xmlChar;
        }
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as i32 == '"' as i32 {
            xmlNextChar(ctxt);
            encoding = xmlParseEncName(ctxt);
            if *(*(*ctxt).input).cur as i32 != '"' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const i8);
                xmlFree
                    .expect("non-null function pointer")(encoding as *mut libc::c_void);
                return 0 as *const xmlChar;
            } else {
                xmlNextChar(ctxt);
            }
        } else if *(*(*ctxt).input).cur as i32 == '\'' as i32 {
            xmlNextChar(ctxt);
            encoding = xmlParseEncName(ctxt);
            if *(*(*ctxt).input).cur as i32 != '\'' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const i8);
                xmlFree
                    .expect("non-null function pointer")(encoding as *mut libc::c_void);
                return 0 as *const xmlChar;
            } else {
                xmlNextChar(ctxt);
            }
        } else {
            xmlFatalErr(ctxt, XML_ERR_STRING_NOT_STARTED, 0 as *const i8);
        }
        if (*ctxt).options & XML_PARSE_IGNORE_ENC as i32 != 0 {
            xmlFree.expect("non-null function pointer")(encoding as *mut libc::c_void);
            return 0 as *const xmlChar;
        }
        if !encoding.is_null()
            && (xmlStrcasecmp(
                encoding,
                b"UTF-16\0" as *const u8 as *const i8 as *mut xmlChar,
            ) == 0
                || xmlStrcasecmp(
                    encoding,
                    b"UTF16\0" as *const u8 as *const i8 as *mut xmlChar,
                ) == 0)
        {
            if ((*ctxt).encoding).is_null() && !((*(*ctxt).input).buf).is_null()
                && ((*(*(*ctxt).input).buf).encoder).is_null()
            {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_INVALID_ENCODING,
                    b"Document labelled UTF-16 but has UTF-8 content\n\0" as *const u8
                        as *const i8,
                );
            }
            if !((*ctxt).encoding).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).encoding as *mut xmlChar as *mut libc::c_void);
            }
            let fresh422 = &mut ((*ctxt).encoding);
            *fresh422 = encoding;
        } else if !encoding.is_null()
                && (xmlStrcasecmp(
                    encoding,
                    b"UTF-8\0" as *const u8 as *const i8 as *mut xmlChar,
                ) == 0
                    || xmlStrcasecmp(
                        encoding,
                        b"UTF8\0" as *const u8 as *const i8 as *mut xmlChar,
                    ) == 0)
            {
            if !((*ctxt).encoding).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).encoding as *mut xmlChar as *mut libc::c_void);
            }
            let fresh423 = &mut ((*ctxt).encoding);
            *fresh423 = encoding;
        } else if !encoding.is_null() {
            let mut handler: * mut crate::src::HTMLparser::_xmlCharEncodingHandler = 0
                as *mut xmlCharEncodingHandler;
            if !((*(*ctxt).input).encoding).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*(*ctxt).input).encoding as *mut xmlChar as *mut libc::c_void);
            }
            let fresh424 = &mut ((*(*ctxt).input).encoding);
            *fresh424 = encoding;
            handler = xmlFindCharEncodingHandler(encoding as *const i8);
            if !handler.is_null() {
                if xmlSwitchToEncoding(ctxt, handler) < 0 as i32 {
                    (*ctxt).errNo = XML_ERR_UNSUPPORTED_ENCODING as i32;
                    return 0 as *const xmlChar;
                }
            } else {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_UNSUPPORTED_ENCODING,
                    b"Unsupported encoding %s\n\0" as *const u8 as *const i8,
                    encoding,
                );
                return 0 as *const xmlChar;
            }
        }
    }
    return encoding;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseSDDecl(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> i32 {
    let mut standalone: i32 = -(2 as i32);
    xmlSkipBlankChars(ctxt);
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == 's' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == 't' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'a' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'n' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'd' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'a' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'l' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(7 as i32 as isize) as i32 == 'o' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(8 as i32 as isize) as i32 == 'n' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(9 as i32 as isize) as i32 == 'e' as i32
    {
        let fresh425 = &mut ((*(*ctxt).input).cur);
        *fresh425 = (*fresh425).offset(10 as i32 as isize);
        (*(*ctxt).input).col += 10 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as i32 != '=' as i32 {
            xmlFatalErr(ctxt, XML_ERR_EQUAL_REQUIRED, 0 as *const i8);
            return standalone;
        }
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as i32 == '\'' as i32 {
            xmlNextChar(ctxt);
            if *(*(*ctxt).input).cur as i32 == 'n' as i32
                && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == 'o' as i32
            {
                standalone = 0 as i32;
                let fresh426 = &mut ((*(*ctxt).input).cur);
                *fresh426 = (*fresh426).offset(2 as i32 as isize);
                (*(*ctxt).input).col += 2 as i32;
                if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                    xmlParserInputGrow((*ctxt).input, 250 as i32);
                }
            } else if *(*(*ctxt).input).cur as i32 == 'y' as i32
                    && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                        as i32 == 'e' as i32
                    && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                        as i32 == 's' as i32
                {
                standalone = 1 as i32;
                let fresh427 = &mut ((*(*ctxt).input).cur);
                *fresh427 = (*fresh427).offset(3 as i32 as isize);
                (*(*ctxt).input).col += 3 as i32;
                if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                    xmlParserInputGrow((*ctxt).input, 250 as i32);
                }
            } else {
                xmlFatalErr(ctxt, XML_ERR_STANDALONE_VALUE, 0 as *const i8);
            }
            if *(*(*ctxt).input).cur as i32 != '\'' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const i8);
            } else {
                xmlNextChar(ctxt);
            }
        } else if *(*(*ctxt).input).cur as i32 == '"' as i32 {
            xmlNextChar(ctxt);
            if *(*(*ctxt).input).cur as i32 == 'n' as i32
                && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == 'o' as i32
            {
                standalone = 0 as i32;
                let fresh428 = &mut ((*(*ctxt).input).cur);
                *fresh428 = (*fresh428).offset(2 as i32 as isize);
                (*(*ctxt).input).col += 2 as i32;
                if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                    xmlParserInputGrow((*ctxt).input, 250 as i32);
                }
            } else if *(*(*ctxt).input).cur as i32 == 'y' as i32
                    && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                        as i32 == 'e' as i32
                    && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                        as i32 == 's' as i32
                {
                standalone = 1 as i32;
                let fresh429 = &mut ((*(*ctxt).input).cur);
                *fresh429 = (*fresh429).offset(3 as i32 as isize);
                (*(*ctxt).input).col += 3 as i32;
                if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                    xmlParserInputGrow((*ctxt).input, 250 as i32);
                }
            } else {
                xmlFatalErr(ctxt, XML_ERR_STANDALONE_VALUE, 0 as *const i8);
            }
            if *(*(*ctxt).input).cur as i32 != '"' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const i8);
            } else {
                xmlNextChar(ctxt);
            }
        } else {
            xmlFatalErr(ctxt, XML_ERR_STRING_NOT_STARTED, 0 as *const i8);
        }
    }
    return standalone;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseXMLDecl(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut version: * mut u8 = 0 as *mut xmlChar;
    (*(*ctxt).input).standalone = -(2 as i32);
    let fresh430 = &mut ((*(*ctxt).input).cur);
    *fresh430 = (*fresh430).offset(5 as i32 as isize);
    (*(*ctxt).input).col += 5 as i32;
    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
        xmlParserInputGrow((*ctxt).input, 250 as i32);
    }
    if !(*(*(*ctxt).input).cur as i32 == 0x20 as i32
        || 0x9 as i32 <= *(*(*ctxt).input).cur as i32
            && *(*(*ctxt).input).cur as i32 <= 0xa as i32
        || *(*(*ctxt).input).cur as i32 == 0xd as i32)
    {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_SPACE_REQUIRED,
            b"Blank needed after '<?xml'\n\0" as *const u8 as *const i8,
        );
    }
    xmlSkipBlankChars(ctxt);
    version = xmlParseVersionInfo(ctxt);
    if version.is_null() {
        xmlFatalErr(ctxt, XML_ERR_VERSION_MISSING, 0 as *const i8);
    } else {
        if xmlStrEqual(
            version,
            b"1.0\0" as *const u8 as *const i8 as *const xmlChar,
        ) == 0
        {
            if (*ctxt).options & XML_PARSE_OLD10 as i32 != 0 {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_UNKNOWN_VERSION,
                    b"Unsupported version '%s'\n\0" as *const u8 as *const i8,
                    version,
                );
            } else if *version.offset(0 as i32 as isize) as i32
                    == '1' as i32
                    && *version.offset(1 as i32 as isize) as i32
                        == '.' as i32
                {
                xmlWarningMsg(
                    ctxt,
                    XML_WAR_UNKNOWN_VERSION,
                    b"Unsupported version '%s'\n\0" as *const u8 as *const i8,
                    version,
                    0 as *const xmlChar,
                );
            } else {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_UNKNOWN_VERSION,
                    b"Unsupported version '%s'\n\0" as *const u8 as *const i8,
                    version,
                );
            }
        }
        if !((*ctxt).version).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).version as *mut libc::c_void);
        }
        let fresh431 = &mut ((*ctxt).version);
        *fresh431 = version;
    }
    if !(*(*(*ctxt).input).cur as i32 == 0x20 as i32
        || 0x9 as i32 <= *(*(*ctxt).input).cur as i32
            && *(*(*ctxt).input).cur as i32 <= 0xa as i32
        || *(*(*ctxt).input).cur as i32 == 0xd as i32)
    {
        if *(*(*ctxt).input).cur as i32 == '?' as i32
            && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
                == '>' as i32
        {
            let fresh432 = &mut ((*(*ctxt).input).cur);
            *fresh432 = (*fresh432).offset(2 as i32 as isize);
            (*(*ctxt).input).col += 2 as i32;
            if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                xmlParserInputGrow((*ctxt).input, 250 as i32);
            }
            return;
        }
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_SPACE_REQUIRED,
            b"Blank needed here\n\0" as *const u8 as *const i8,
        );
    }
    xmlParseEncodingDecl(ctxt);
    if (*ctxt).errNo == XML_ERR_UNSUPPORTED_ENCODING as i32
        || (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !((*(*ctxt).input).encoding).is_null()
        && !(*(*(*ctxt).input).cur as i32 == 0x20 as i32
            || 0x9 as i32 <= *(*(*ctxt).input).cur as i32
                && *(*(*ctxt).input).cur as i32 <= 0xa as i32
            || *(*(*ctxt).input).cur as i32 == 0xd as i32)
    {
        if *(*(*ctxt).input).cur as i32 == '?' as i32
            && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
                == '>' as i32
        {
            let fresh433 = &mut ((*(*ctxt).input).cur);
            *fresh433 = (*fresh433).offset(2 as i32 as isize);
            (*(*ctxt).input).col += 2 as i32;
            if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                xmlParserInputGrow((*ctxt).input, 250 as i32);
            }
            return;
        }
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_SPACE_REQUIRED,
            b"Blank needed here\n\0" as *const u8 as *const i8,
        );
    }
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    xmlSkipBlankChars(ctxt);
    (*(*ctxt).input).standalone = xmlParseSDDecl(ctxt);
    xmlSkipBlankChars(ctxt);
    if *(*(*ctxt).input).cur as i32 == '?' as i32
        && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            == '>' as i32
    {
        let fresh434 = &mut ((*(*ctxt).input).cur);
        *fresh434 = (*fresh434).offset(2 as i32 as isize);
        (*(*ctxt).input).col += 2 as i32;
        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
            xmlParserInputGrow((*ctxt).input, 250 as i32);
        }
    } else if *(*(*ctxt).input).cur as i32 == '>' as i32 {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, 0 as *const i8);
        xmlNextChar(ctxt);
    } else {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, 0 as *const i8);
        while *(*(*ctxt).input).cur as i32 != 0
            && *(*(*ctxt).input).cur as i32 != '>' as i32
        {
            let fresh435 = &mut ((*(*ctxt).input).cur);
            *fresh435 = (*fresh435).offset(1);
        }
        xmlNextChar(ctxt);
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseMisc(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    while (*ctxt).instate as i32 != XML_PARSER_EOF as i32 {
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if *(*(*ctxt).input).cur as i32 == '<' as i32
            && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
                == '?' as i32
        {
            xmlParsePI(ctxt);
        } else {
            if !(*((*(*ctxt).input).cur as *mut u8)
                .offset(0 as i32 as isize) as i32 == '<' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(1 as i32 as isize) as i32 == '!' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(2 as i32 as isize) as i32 == '-' as i32
                && *((*(*ctxt).input).cur as *mut u8)
                    .offset(3 as i32 as isize) as i32 == '-' as i32)
            {
                break;
            }
            xmlParseComment(ctxt);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseDocument(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) -> i32 {
    let mut start: [u8; 4] = [0; 4];
    let mut enc: i32 = XML_CHAR_ENCODING_NONE;
    xmlInitParser();
    if ctxt.is_null() || ((*ctxt).input).is_null() {
        return -(1 as i32);
    }
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    xmlDetectSAX2(ctxt);
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).setDocumentLocator).is_some() {
        ((*(*ctxt).sax).setDocumentLocator)
            .expect(
                "non-null function pointer",
            )((*ctxt).userData, __xmlDefaultSAXLocator());
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    if ((*ctxt).encoding).is_null()
        && ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64
            >= 4 as i32 as i64
    {
        start[0 as i32 as usize] = *(*(*ctxt).input).cur;
        start[1 as i32
            as usize] = *((*(*ctxt).input).cur).offset(1 as i32 as isize);
        start[2 as i32
            as usize] = *((*(*ctxt).input).cur).offset(2 as i32 as isize);
        start[3 as i32
            as usize] = *((*(*ctxt).input).cur).offset(3 as i32 as isize);
        enc = xmlDetectCharEncoding(
            &mut *start.as_mut_ptr().offset(0 as i32 as isize),
            4 as i32,
        );
        if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
            xmlSwitchEncoding(ctxt, enc);
        }
    }
    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_DOCUMENT_EMPTY, 0 as *const i8);
        return -(1 as i32);
    }
    if (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
        < 35 as i32 as i64
    {
        if (*ctxt).progressive == 0 as i32
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
    }
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '<' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == '?' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'x' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'm' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'l' as i32
        && (*((*(*ctxt).input).cur).offset(5 as i32 as isize) as i32
            == 0x20 as i32
            || 0x9 as i32
                <= *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                    as i32
                && *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                    as i32 <= 0xa as i32
            || *((*(*ctxt).input).cur).offset(5 as i32 as isize) as i32
                == 0xd as i32)
    {
        xmlParseXMLDecl(ctxt);
        if (*ctxt).errNo == XML_ERR_UNSUPPORTED_ENCODING as i32
            || (*ctxt).instate as i32 == XML_PARSER_EOF as i32
        {
            return -(1 as i32);
        }
        (*ctxt).standalone = (*(*ctxt).input).standalone;
        xmlSkipBlankChars(ctxt);
    } else {
        let fresh436 = &mut ((*ctxt).version);
        *fresh436 = xmlCharStrdup(b"1.0\0" as *const u8 as *const i8);
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).startDocument).is_some()
        && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).startDocument)
            .expect("non-null function pointer")((*ctxt).userData);
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    if !((*ctxt).myDoc).is_null() && !((*ctxt).input).is_null()
        && !((*(*ctxt).input).buf).is_null()
        && (*(*(*ctxt).input).buf).compressed >= 0 as i32
    {
        (*(*ctxt).myDoc).compression = (*(*(*ctxt).input).buf).compressed;
    }
    xmlParseMisc(ctxt);
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '<' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == '!' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'D' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'O' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'C' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(5 as i32 as isize) as i32 == 'T' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(6 as i32 as isize) as i32 == 'Y' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(7 as i32 as isize) as i32 == 'P' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(8 as i32 as isize) as i32 == 'E' as i32
    {
        (*ctxt).inSubset = 1 as i32;
        xmlParseDocTypeDecl(ctxt);
        if *(*(*ctxt).input).cur as i32 == '[' as i32 {
            (*ctxt).instate = XML_PARSER_DTD;
            xmlParseInternalSubset(ctxt);
            if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                return -(1 as i32);
            }
        }
        (*ctxt).inSubset = 2 as i32;
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).externalSubset).is_some()
            && (*ctxt).disableSAX == 0
        {
            ((*(*ctxt).sax).externalSubset)
                .expect(
                    "non-null function pointer",
                )(
                (*ctxt).userData,
                (*ctxt).intSubName,
                (*ctxt).extSubSystem,
                (*ctxt).extSubURI,
            );
        }
        if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
            return -(1 as i32);
        }
        (*ctxt).inSubset = 0 as i32;
        xmlCleanSpecialAttr(ctxt);
        (*ctxt).instate = XML_PARSER_PROLOG;
        xmlParseMisc(ctxt);
    }
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if *(*(*ctxt).input).cur as i32 != '<' as i32 {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_DOCUMENT_EMPTY,
            b"Start tag expected, '<' not found\n\0" as *const u8 as *const i8,
        );
    } else {
        (*ctxt).instate = XML_PARSER_CONTENT;
        xmlParseElement(ctxt);
        (*ctxt).instate = XML_PARSER_EPILOG;
        xmlParseMisc(ctxt);
        if *(*(*ctxt).input).cur as i32 != 0 as i32 {
            xmlFatalErr(ctxt, XML_ERR_DOCUMENT_END, 0 as *const i8);
        }
        (*ctxt).instate = XML_PARSER_EOF;
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some() {
        ((*(*ctxt).sax).endDocument)
            .expect("non-null function pointer")((*ctxt).userData);
    }
    if !((*ctxt).myDoc).is_null()
        && xmlStrEqual(
            (*(*ctxt).myDoc).version,
            b"SAX compatibility mode document\0" as *const u8 as *const i8
                as *mut xmlChar,
        ) != 0
    {
        xmlFreeDoc((*ctxt).myDoc);
        let fresh437 = &mut ((*ctxt).myDoc);
        *fresh437 = 0 as xmlDocPtr;
    }
    if (*ctxt).wellFormed != 0 && !((*ctxt).myDoc).is_null() {
        (*(*ctxt).myDoc).properties |= XML_DOC_WELLFORMED as i32;
        if (*ctxt).valid != 0 {
            (*(*ctxt).myDoc).properties |= XML_DOC_DTDVALID as i32;
        }
        if (*ctxt).nsWellFormed != 0 {
            (*(*ctxt).myDoc).properties |= XML_DOC_NSVALID as i32;
        }
        if (*ctxt).options & XML_PARSE_OLD10 as i32 != 0 {
            (*(*ctxt).myDoc).properties |= XML_DOC_OLD10 as i32;
        }
    }
    if (*ctxt).wellFormed == 0 {
        (*ctxt).valid = 0 as i32;
        return -(1 as i32);
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseExtParsedEnt(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
) -> i32 {
    let mut start: [u8; 4] = [0; 4];
    let mut enc: i32 = XML_CHAR_ENCODING_NONE;
    if ctxt.is_null() || ((*ctxt).input).is_null() {
        return -(1 as i32);
    }
    xmlDetectSAX2(ctxt);
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).setDocumentLocator).is_some() {
        ((*(*ctxt).sax).setDocumentLocator)
            .expect(
                "non-null function pointer",
            )((*ctxt).userData, __xmlDefaultSAXLocator());
    }
    if ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64
        >= 4 as i32 as i64
    {
        start[0 as i32 as usize] = *(*(*ctxt).input).cur;
        start[1 as i32
            as usize] = *((*(*ctxt).input).cur).offset(1 as i32 as isize);
        start[2 as i32
            as usize] = *((*(*ctxt).input).cur).offset(2 as i32 as isize);
        start[3 as i32
            as usize] = *((*(*ctxt).input).cur).offset(3 as i32 as isize);
        enc = xmlDetectCharEncoding(start.as_mut_ptr(), 4 as i32);
        if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
            xmlSwitchEncoding(ctxt, enc);
        }
    }
    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_DOCUMENT_EMPTY, 0 as *const i8);
    }
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '<' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == '?' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'x' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'm' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'l' as i32
        && (*((*(*ctxt).input).cur).offset(5 as i32 as isize) as i32
            == 0x20 as i32
            || 0x9 as i32
                <= *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                    as i32
                && *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                    as i32 <= 0xa as i32
            || *((*(*ctxt).input).cur).offset(5 as i32 as isize) as i32
                == 0xd as i32)
    {
        xmlParseXMLDecl(ctxt);
        if (*ctxt).errNo == XML_ERR_UNSUPPORTED_ENCODING as i32 {
            return -(1 as i32);
        }
        xmlSkipBlankChars(ctxt);
    } else {
        let fresh438 = &mut ((*ctxt).version);
        *fresh438 = xmlCharStrdup(b"1.0\0" as *const u8 as *const i8);
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).startDocument).is_some()
        && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).startDocument)
            .expect("non-null function pointer")((*ctxt).userData);
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    (*ctxt).instate = XML_PARSER_CONTENT;
    (*ctxt).validate = 0 as i32;
    (*ctxt).loadsubset = 0 as i32;
    (*ctxt).depth = 0 as i32;
    xmlParseContent(ctxt);
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    if *(*(*ctxt).input).cur as i32 == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    } else if *(*(*ctxt).input).cur as i32 != 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const i8);
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some() {
        ((*(*ctxt).sax).endDocument)
            .expect("non-null function pointer")((*ctxt).userData);
    }
    if (*ctxt).wellFormed == 0 {
        return -(1 as i32);
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlParseLookupSequence(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut first: u8,
    mut next: u8,
    mut third: u8,
) -> i32 {
    let mut base: i32 = 0;
    let mut len: i32 = 0;
    let mut in_0: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut buf: * const u8 = 0 as *const xmlChar;
    in_0 = (*ctxt).input;
    if in_0.is_null() {
        return -(1 as i32);
    }
    base = ((*in_0).cur).offset_from((*in_0).base) as i64 as i32;
    if base < 0 as i32 {
        return -(1 as i32);
    }
    if (*ctxt).checkIndex > base as i64 {
        base = (*ctxt).checkIndex as i32;
    }
    if ((*in_0).buf).is_null() {
        buf = (*in_0).base;
        len = (*in_0).length;
    } else {
        buf = xmlBufContent((*(*in_0).buf).buffer as *const xmlBuf);
        len = xmlBufUse((*(*in_0).buf).buffer) as i32;
    }
    if third != 0 {
        len -= 2 as i32;
    } else if next != 0 {
        len -= 1;
    }
    let mut current_block_20: u64;
    while base < len {
        if *buf.offset(base as isize) as i32 == first as i32 {
            if third as i32 != 0 as i32 {
                if *buf.offset((base + 1 as i32) as isize) as i32
                    != next as i32
                    || *buf.offset((base + 2 as i32) as isize) as i32
                        != third as i32
                {
                    current_block_20 = 2370887241019905314;
                } else {
                    current_block_20 = 18386322304582297246;
                }
            } else if next as i32 != 0 as i32 {
                if *buf.offset((base + 1 as i32) as isize) as i32
                    != next as i32
                {
                    current_block_20 = 2370887241019905314;
                } else {
                    current_block_20 = 18386322304582297246;
                }
            } else {
                current_block_20 = 18386322304582297246;
            }
            match current_block_20 {
                2370887241019905314 => {}
                _ => {
                    (*ctxt).checkIndex = 0 as i32 as i64;
                    return (base as i64
                        - ((*in_0).cur).offset_from((*in_0).base) as i64)
                        as i32;
                }
            }
        }
        base += 1;
    }
    (*ctxt).checkIndex = base as i64;
    return -(1 as i32);
}
unsafe extern "C" fn xmlParseGetLasts<'a1, 'a2>(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut lastlt: Option<&'a1 mut * const u8>,
    mut lastgt: Option<&'a2 mut * const u8>,
) {
    let mut tmp: * const u8 = 0 as *const xmlChar;
    if ctxt.is_null() || borrow(& lastlt).is_none() || borrow(& lastgt).is_none() {
        (*(borrow(& __xmlGenericError())).unwrap())
            .expect(
                "non-null function pointer",
            )(
            *(__xmlGenericErrorContext()).unwrap(),
            b"Internal error: xmlParseGetLasts\n\0" as *const u8 as *const i8,
        );
        return;
    }
    if (*ctxt).progressive != 0 as i32 && (*ctxt).inputNr == 1 as i32 {
        tmp = (*(*ctxt).input).end;
        tmp = tmp.offset(-1);
        while tmp >= (*(*ctxt).input).base && *tmp as i32 != '<' as i32 {
            tmp = tmp.offset(-1);
        }
        if tmp < (*(*ctxt).input).base {
            *(borrow_mut(&mut lastlt)).unwrap() = 0 as *const xmlChar;
            *(borrow_mut(&mut lastgt)).unwrap() = 0 as *const xmlChar;
        } else {
            *(borrow_mut(&mut lastlt)).unwrap() = tmp;
            tmp = tmp.offset(1);
            while tmp < (*(*ctxt).input).end && *tmp as i32 != '>' as i32 {
                if *tmp as i32 == '\'' as i32 {
                    tmp = tmp.offset(1);
                    while tmp < (*(*ctxt).input).end
                        && *tmp as i32 != '\'' as i32
                    {
                        tmp = tmp.offset(1);
                    }
                    if tmp < (*(*ctxt).input).end {
                        tmp = tmp.offset(1);
                    }
                } else if *tmp as i32 == '"' as i32 {
                    tmp = tmp.offset(1);
                    while tmp < (*(*ctxt).input).end && *tmp as i32 != '"' as i32
                    {
                        tmp = tmp.offset(1);
                    }
                    if tmp < (*(*ctxt).input).end {
                        tmp = tmp.offset(1);
                    }
                } else {
                    tmp = tmp.offset(1);
                }
            }
            if tmp < (*(*ctxt).input).end {
                *(borrow_mut(&mut lastgt)).unwrap() = tmp;
            } else {
                tmp = *(borrow(& lastlt)).unwrap();
                tmp = tmp.offset(-1);
                while tmp >= (*(*ctxt).input).base && *tmp as i32 != '>' as i32 {
                    tmp = tmp.offset(-1);
                }
                if tmp >= (*(*ctxt).input).base {
                    *(borrow_mut(&mut lastgt)).unwrap() = tmp;
                } else {
                    *(borrow_mut(&mut lastgt)).unwrap() = 0 as *const xmlChar;
                }
            }
        }
    } else {
        *(borrow_mut(&mut lastlt)).unwrap() = 0 as *const xmlChar;
        *(borrow_mut(&mut lastgt)).unwrap() = 0 as *const xmlChar;
    };
}
unsafe extern "C" fn xmlCheckCdataPush(
    mut utf: * const u8,
    mut len: i32,
    mut complete: i32,
) -> i32 {
    let mut ix: i32 = 0;
    let mut c: u8 = 0;
    let mut codepoint: i32 = 0;
    if utf.is_null() || len <= 0 as i32 {
        return 0 as i32;
    }
    ix = 0 as i32;
    while ix < len {
        c = *utf.offset(ix as isize);
        if c as i32 & 0x80 as i32 == 0 as i32 {
            if c as i32 >= 0x20 as i32 {
                ix += 1;
            } else if c as i32 == 0xa as i32
                    || c as i32 == 0xd as i32
                    || c as i32 == 0x9 as i32
                {
                ix += 1;
            } else {
                return -ix
            }
        } else if c as i32 & 0xe0 as i32 == 0xc0 as i32 {
            if ix + 2 as i32 > len {
                return if complete != 0 { -ix } else { ix };
            }
            if *utf.offset((ix + 1 as i32) as isize) as i32
                & 0xc0 as i32 != 0x80 as i32
            {
                return -ix;
            }
            codepoint = (*utf.offset(ix as isize) as i32 & 0x1f as i32)
                << 6 as i32;
            codepoint
                |= *utf.offset((ix + 1 as i32) as isize) as i32
                    & 0x3f as i32;
            if if codepoint < 0x100 as i32 {
                (0x9 as i32 <= codepoint && codepoint <= 0xa as i32
                    || codepoint == 0xd as i32
                    || 0x20 as i32 <= codepoint) as i32
            } else {
                (0x100 as i32 <= codepoint && codepoint <= 0xd7ff as i32
                    || 0xe000 as i32 <= codepoint
                        && codepoint <= 0xfffd as i32
                    || 0x10000 as i32 <= codepoint
                        && codepoint <= 0x10ffff as i32) as i32
            } == 0
            {
                return -ix;
            }
            ix += 2 as i32;
        } else if c as i32 & 0xf0 as i32 == 0xe0 as i32 {
            if ix + 3 as i32 > len {
                return if complete != 0 { -ix } else { ix };
            }
            if *utf.offset((ix + 1 as i32) as isize) as i32
                & 0xc0 as i32 != 0x80 as i32
                || *utf.offset((ix + 2 as i32) as isize) as i32
                    & 0xc0 as i32 != 0x80 as i32
            {
                return -ix;
            }
            codepoint = (*utf.offset(ix as isize) as i32 & 0xf as i32)
                << 12 as i32;
            codepoint
                |= (*utf.offset((ix + 1 as i32) as isize) as i32
                    & 0x3f as i32) << 6 as i32;
            codepoint
                |= *utf.offset((ix + 2 as i32) as isize) as i32
                    & 0x3f as i32;
            if if codepoint < 0x100 as i32 {
                (0x9 as i32 <= codepoint && codepoint <= 0xa as i32
                    || codepoint == 0xd as i32
                    || 0x20 as i32 <= codepoint) as i32
            } else {
                (0x100 as i32 <= codepoint && codepoint <= 0xd7ff as i32
                    || 0xe000 as i32 <= codepoint
                        && codepoint <= 0xfffd as i32
                    || 0x10000 as i32 <= codepoint
                        && codepoint <= 0x10ffff as i32) as i32
            } == 0
            {
                return -ix;
            }
            ix += 3 as i32;
        } else if c as i32 & 0xf8 as i32 == 0xf0 as i32 {
            if ix + 4 as i32 > len {
                return if complete != 0 { -ix } else { ix };
            }
            if *utf.offset((ix + 1 as i32) as isize) as i32
                & 0xc0 as i32 != 0x80 as i32
                || *utf.offset((ix + 2 as i32) as isize) as i32
                    & 0xc0 as i32 != 0x80 as i32
                || *utf.offset((ix + 3 as i32) as isize) as i32
                    & 0xc0 as i32 != 0x80 as i32
            {
                return -ix;
            }
            codepoint = (*utf.offset(ix as isize) as i32 & 0x7 as i32)
                << 18 as i32;
            codepoint
                |= (*utf.offset((ix + 1 as i32) as isize) as i32
                    & 0x3f as i32) << 12 as i32;
            codepoint
                |= (*utf.offset((ix + 2 as i32) as isize) as i32
                    & 0x3f as i32) << 6 as i32;
            codepoint
                |= *utf.offset((ix + 3 as i32) as isize) as i32
                    & 0x3f as i32;
            if if codepoint < 0x100 as i32 {
                (0x9 as i32 <= codepoint && codepoint <= 0xa as i32
                    || codepoint == 0xd as i32
                    || 0x20 as i32 <= codepoint) as i32
            } else {
                (0x100 as i32 <= codepoint && codepoint <= 0xd7ff as i32
                    || 0xe000 as i32 <= codepoint
                        && codepoint <= 0xfffd as i32
                    || 0x10000 as i32 <= codepoint
                        && codepoint <= 0x10ffff as i32) as i32
            } == 0
            {
                return -ix;
            }
            ix += 4 as i32;
        } else {
            return -ix
        }
    }
    return ix;
}
unsafe extern "C" fn xmlParseTryOrFinish(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut terminate: i32,
) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 0 as i32;
    let mut avail: i32 = 0;
    let mut tlen: i32 = 0;
    let mut cur: u8 = 0;
    let mut next: u8 = 0;
    let mut lastlt: * const u8 = 0 as *const xmlChar;
    let mut lastgt: * const u8 = 0 as *const xmlChar;
    if ((*ctxt).input).is_null() {
        return 0 as i32;
    }
    if !((*ctxt).input).is_null()
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
            > 4096 as i32 as i64
    {
        xmlSHRINK(ctxt);
        (*ctxt).checkIndex = 0 as i32 as i64;
    }
    xmlParseGetLasts(ctxt, Some(&mut lastlt), Some(&mut lastgt));
    loop {
        if !((*ctxt).instate as i32 != XML_PARSER_EOF as i32) {
            current_block = 2814621064645850728;
            break;
        }
        if (*ctxt).errNo != XML_ERR_OK as i32
            && (*ctxt).disableSAX == 1 as i32
        {
            return 0 as i32;
        }
        if ((*ctxt).input).is_null() {
            current_block = 2814621064645850728;
            break;
        }
        if ((*(*ctxt).input).buf).is_null() {
            avail = ((*(*ctxt).input).length as i64
                - ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as i64) as i32;
        } else {
            if (*ctxt).instate as i32 != XML_PARSER_START as i32
                && !((*(*(*ctxt).input).buf).raw).is_null()
                && xmlBufIsEmpty((*(*(*ctxt).input).buf).raw) == 0 as i32
            {
                let mut base: u64 = xmlBufGetInputBase(
                    (*(*(*ctxt).input).buf).buffer,
                    (*ctxt).input,
                );
                let mut current: u64 = ((*(*ctxt).input).cur)
                    .offset_from((*(*ctxt).input).base) as i64 as size_t;
                xmlParserInputBufferPush(
                    (*(*ctxt).input).buf,
                    0 as i32,
                    b"\0" as *const u8 as *const i8,
                );
                xmlBufSetInputBaseCur(
                    (*(*(*ctxt).input).buf).buffer,
                    (*ctxt).input,
                    base,
                    current,
                );
            }
            avail = (xmlBufUse((*(*(*ctxt).input).buf).buffer))
                .wrapping_sub(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as i64 as u64,
                ) as i32;
        }
        if avail < 1 as i32 {
            current_block = 2814621064645850728;
            break;
        }
        match (*ctxt).instate as i32 {
            -1 => {
                current_block = 2814621064645850728;
                break;
            }
            0 => {
                if (*ctxt).charset == XML_CHAR_ENCODING_NONE as i32 {
                    let mut start: [u8; 4] = [0; 4];
                    let mut enc: i32 = XML_CHAR_ENCODING_NONE;
                    if avail < 4 as i32 {
                        current_block = 2814621064645850728;
                        break;
                    }
                    start[0 as i32 as usize] = *(*(*ctxt).input).cur;
                    start[1 as i32
                        as usize] = *((*(*ctxt).input).cur)
                        .offset(1 as i32 as isize);
                    start[2 as i32
                        as usize] = *((*(*ctxt).input).cur)
                        .offset(2 as i32 as isize);
                    start[3 as i32
                        as usize] = *((*(*ctxt).input).cur)
                        .offset(3 as i32 as isize);
                    enc = xmlDetectCharEncoding(start.as_mut_ptr(), 4 as i32);
                    xmlSwitchEncoding(ctxt, enc);
                } else {
                    if avail < 2 as i32 {
                        current_block = 2814621064645850728;
                        break;
                    }
                    cur = *((*(*ctxt).input).cur).offset(0 as i32 as isize);
                    next = *((*(*ctxt).input).cur).offset(1 as i32 as isize);
                    if cur as i32 == 0 as i32 {
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).setDocumentLocator).is_some()
                        {
                            ((*(*ctxt).sax).setDocumentLocator)
                                .expect(
                                    "non-null function pointer",
                                )((*ctxt).userData, __xmlDefaultSAXLocator());
                        }
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_DOCUMENT_EMPTY,
                            0 as *const i8,
                        );
                        xmlHaltParser(ctxt);
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).endDocument).is_some()
                        {
                            ((*(*ctxt).sax).endDocument)
                                .expect("non-null function pointer")((*ctxt).userData);
                        }
                        current_block = 2814621064645850728;
                        break;
                    } else if cur as i32 == '<' as i32
                            && next as i32 == '?' as i32
                        {
                        if avail < 5 as i32 {
                            return ret;
                        }
                        if terminate == 0
                            && xmlParseLookupSequence(
                                ctxt,
                                '?' as i32 as xmlChar,
                                '>' as i32 as xmlChar,
                                0 as i32 as xmlChar,
                            ) < 0 as i32
                        {
                            return ret;
                        }
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).setDocumentLocator).is_some()
                        {
                            ((*(*ctxt).sax).setDocumentLocator)
                                .expect(
                                    "non-null function pointer",
                                )((*ctxt).userData, __xmlDefaultSAXLocator());
                        }
                        if *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                            as i32 == 'x' as i32
                            && *((*(*ctxt).input).cur).offset(3 as i32 as isize)
                                as i32 == 'm' as i32
                            && *((*(*ctxt).input).cur).offset(4 as i32 as isize)
                                as i32 == 'l' as i32
                            && (*((*(*ctxt).input).cur).offset(5 as i32 as isize)
                                as i32 == 0x20 as i32
                                || 0x9 as i32
                                    <= *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                                        as i32
                                    && *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                                        as i32 <= 0xa as i32
                                || *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                                    as i32 == 0xd as i32)
                        {
                            ret += 5 as i32;
                            xmlParseXMLDecl(ctxt);
                            if (*ctxt).errNo
                                == XML_ERR_UNSUPPORTED_ENCODING as i32
                            {
                                xmlHaltParser(ctxt);
                                return 0 as i32;
                            }
                            (*ctxt).standalone = (*(*ctxt).input).standalone;
                            if ((*ctxt).encoding).is_null()
                                && !((*(*ctxt).input).encoding).is_null()
                            {
                                let fresh439 = &mut ((*ctxt).encoding);
                                *fresh439 = xmlStrdup((*(*ctxt).input).encoding);
                            }
                            if !((*ctxt).sax).is_null()
                                && ((*(*ctxt).sax).startDocument).is_some()
                                && (*ctxt).disableSAX == 0
                            {
                                ((*(*ctxt).sax).startDocument)
                                    .expect("non-null function pointer")((*ctxt).userData);
                            }
                            (*ctxt).instate = XML_PARSER_MISC;
                        } else {
                            let fresh440 = &mut ((*ctxt).version);
                            *fresh440 = xmlCharStrdup(
                                b"1.0\0" as *const u8 as *const i8,
                            );
                            if !((*ctxt).sax).is_null()
                                && ((*(*ctxt).sax).startDocument).is_some()
                                && (*ctxt).disableSAX == 0
                            {
                                ((*(*ctxt).sax).startDocument)
                                    .expect("non-null function pointer")((*ctxt).userData);
                            }
                            (*ctxt).instate = XML_PARSER_MISC;
                        }
                    } else {
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).setDocumentLocator).is_some()
                        {
                            ((*(*ctxt).sax).setDocumentLocator)
                                .expect(
                                    "non-null function pointer",
                                )((*ctxt).userData, __xmlDefaultSAXLocator());
                        }
                        let fresh441 = &mut ((*ctxt).version);
                        *fresh441 = xmlCharStrdup(
                            b"1.0\0" as *const u8 as *const i8,
                        );
                        if ((*ctxt).version).is_null() {
                            xmlErrMemory(ctxt, 0 as *const i8);
                        } else {
                            if !((*ctxt).sax).is_null()
                                && ((*(*ctxt).sax).startDocument).is_some()
                                && (*ctxt).disableSAX == 0
                            {
                                ((*(*ctxt).sax).startDocument)
                                    .expect("non-null function pointer")((*ctxt).userData);
                            }
                            (*ctxt).instate = XML_PARSER_MISC;
                        }
                    }
                }
            }
            6 => {
                let mut name: * const u8 = 0 as *const xmlChar;
                let mut prefix: * const u8 = 0 as *const xmlChar;
                let mut URI: * const u8 = 0 as *const xmlChar;
                let mut line: i32 = (*(*ctxt).input).line;
                let mut nsNr: i32 = (*ctxt).nsNr;
                if avail < 2 as i32 && (*ctxt).inputNr == 1 as i32 {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = *((*(*ctxt).input).cur).offset(0 as i32 as isize);
                if cur as i32 != '<' as i32 {
                    xmlFatalErr(ctxt, XML_ERR_DOCUMENT_EMPTY, 0 as *const i8);
                    xmlHaltParser(ctxt);
                    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some()
                    {
                        ((*(*ctxt).sax).endDocument)
                            .expect("non-null function pointer")((*ctxt).userData);
                    }
                    current_block = 2814621064645850728;
                    break;
                } else {
                    if terminate == 0 {
                        if (*ctxt).progressive != 0 {
                            if lastgt.is_null() || (*(*ctxt).input).cur >= lastgt {
                                current_block = 2814621064645850728;
                                break;
                            }
                        } else if xmlParseLookupSequence(
                                ctxt,
                                '>' as i32 as xmlChar,
                                0 as i32 as xmlChar,
                                0 as i32 as xmlChar,
                            ) < 0 as i32
                            {
                            current_block = 2814621064645850728;
                            break;
                        }
                    }
                    if (*ctxt).spaceNr == 0 as i32 {
                        spacePush(ctxt, -(1 as i32));
                    } else if *(*ctxt).space == -(2 as i32) {
                        spacePush(ctxt, -(1 as i32));
                    } else {
                        spacePush(ctxt, *(*ctxt).space);
                    }
                    if (*ctxt).sax2 != 0 {
                        name = xmlParseStartTag2(ctxt, Some(&mut prefix), Some(&mut URI), Some(&mut tlen));
                    } else {
                        name = xmlParseStartTag(ctxt);
                    }
                    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
                        current_block = 2814621064645850728;
                        break;
                    }
                    if name.is_null() {
                        spacePop(ctxt);
                        xmlHaltParser(ctxt);
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).endDocument).is_some()
                        {
                            ((*(*ctxt).sax).endDocument)
                                .expect("non-null function pointer")((*ctxt).userData);
                        }
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        if (*ctxt).validate != 0 && (*ctxt).wellFormed != 0
                            && !((*ctxt).myDoc).is_null() && !((*ctxt).node).is_null()
                            && (*ctxt).node == (*(*ctxt).myDoc).children
                        {
                            (*ctxt).valid
                                &= xmlValidateRoot(&mut (*ctxt).vctxt, (*ctxt).myDoc);
                        }
                        if *(*(*ctxt).input).cur as i32 == '/' as i32
                            && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                                as i32 == '>' as i32
                        {
                            let fresh442 = &mut ((*(*ctxt).input).cur);
                            *fresh442 = (*fresh442).offset(2 as i32 as isize);
                            (*(*ctxt).input).col += 2 as i32;
                            if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                                xmlParserInputGrow((*ctxt).input, 250 as i32);
                            }
                            if (*ctxt).sax2 != 0 {
                                if !((*ctxt).sax).is_null()
                                    && ((*(*ctxt).sax).endElementNs).is_some()
                                    && (*ctxt).disableSAX == 0
                                {
                                    ((*(*ctxt).sax).endElementNs)
                                        .expect(
                                            "non-null function pointer",
                                        )((*ctxt).userData, name, prefix, URI);
                                }
                                if (*ctxt).nsNr - nsNr > 0 as i32 {
                                    nsPop(ctxt, (*ctxt).nsNr - nsNr);
                                }
                            } else if !((*ctxt).sax).is_null()
                                    && ((*(*ctxt).sax).endElement).is_some()
                                    && (*ctxt).disableSAX == 0
                                {
                                ((*(*ctxt).sax).endElement)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, name);
                            }
                            if (*ctxt).instate as i32
                                == XML_PARSER_EOF as i32
                            {
                                current_block = 2814621064645850728;
                                break;
                            }
                            spacePop(ctxt);
                            if (*ctxt).nameNr == 0 as i32 {
                                (*ctxt).instate = XML_PARSER_EPILOG;
                            } else {
                                (*ctxt).instate = XML_PARSER_CONTENT;
                            }
                            (*ctxt).progressive = 1 as i32;
                        } else {
                            if *(*(*ctxt).input).cur as i32 == '>' as i32 {
                                xmlNextChar(ctxt);
                            } else {
                                xmlFatalErrMsgStr(
                                    ctxt,
                                    XML_ERR_GT_REQUIRED,
                                    b"Couldn't find end of Start Tag %s\n\0" as *const u8
                                        as *const i8,
                                    name,
                                );
                                nodePop(ctxt);
                                spacePop(ctxt);
                            }
                            nameNsPush(
                                ctxt,
                                name,
                                prefix,
                                URI,
                                line,
                                (*ctxt).nsNr - nsNr,
                            );
                            (*ctxt).instate = XML_PARSER_CONTENT;
                            (*ctxt).progressive = 1 as i32;
                        }
                    }
                }
            }
            7 => {
                let mut id: i32 = 0;
                let mut cons: u64 = 0;
                if avail < 2 as i32 && (*ctxt).inputNr == 1 as i32 {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = *((*(*ctxt).input).cur).offset(0 as i32 as isize);
                next = *((*(*ctxt).input).cur).offset(1 as i32 as isize);
                id = (*(*ctxt).input).id;
                cons = ((*(*ctxt).input).consumed)
                    .wrapping_add(
                        ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as i64 as u64,
                    );
                if cur as i32 == '<' as i32 && next as i32 == '/' as i32
                {
                    (*ctxt).instate = XML_PARSER_END_TAG;
                } else {
                    if cur as i32 == '<' as i32
                        && next as i32 == '?' as i32
                    {
                        if terminate == 0
                            && xmlParseLookupSequence(
                                ctxt,
                                '?' as i32 as xmlChar,
                                '>' as i32 as xmlChar,
                                0 as i32 as xmlChar,
                            ) < 0 as i32
                        {
                            (*ctxt).progressive = XML_PARSER_PI as i32;
                            current_block = 2814621064645850728;
                            break;
                        } else {
                            xmlParsePI(ctxt);
                            (*ctxt).instate = XML_PARSER_CONTENT;
                            (*ctxt).progressive = 1 as i32;
                        }
                    } else if cur as i32 == '<' as i32
                            && next as i32 != '!' as i32
                        {
                        (*ctxt).instate = XML_PARSER_START_TAG;
                        continue;
                    } else if cur as i32 == '<' as i32
                            && next as i32 == '!' as i32
                            && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                                as i32 == '-' as i32
                            && *((*(*ctxt).input).cur).offset(3 as i32 as isize)
                                as i32 == '-' as i32
                        {
                        let mut term: i32 = 0;
                        if avail < 4 as i32 {
                            current_block = 2814621064645850728;
                            break;
                        }
                        let fresh443 = &mut ((*(*ctxt).input).cur);
                        *fresh443 = (*fresh443).offset(4 as i32 as isize);
                        term = xmlParseLookupSequence(
                            ctxt,
                            '-' as i32 as xmlChar,
                            '-' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                        );
                        let fresh444 = &mut ((*(*ctxt).input).cur);
                        *fresh444 = (*fresh444).offset(-(4 as i32 as isize));
                        if terminate == 0 && term < 0 as i32 {
                            (*ctxt).progressive = XML_PARSER_COMMENT as i32;
                            current_block = 2814621064645850728;
                            break;
                        } else {
                            xmlParseComment(ctxt);
                            (*ctxt).instate = XML_PARSER_CONTENT;
                            (*ctxt).progressive = 1 as i32;
                        }
                    } else if cur as i32 == '<' as i32
                            && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                                as i32 == '!' as i32
                            && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                                as i32 == '[' as i32
                            && *((*(*ctxt).input).cur).offset(3 as i32 as isize)
                                as i32 == 'C' as i32
                            && *((*(*ctxt).input).cur).offset(4 as i32 as isize)
                                as i32 == 'D' as i32
                            && *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                                as i32 == 'A' as i32
                            && *((*(*ctxt).input).cur).offset(6 as i32 as isize)
                                as i32 == 'T' as i32
                            && *((*(*ctxt).input).cur).offset(7 as i32 as isize)
                                as i32 == 'A' as i32
                            && *((*(*ctxt).input).cur).offset(8 as i32 as isize)
                                as i32 == '[' as i32
                        {
                        let fresh445 = &mut ((*(*ctxt).input).cur);
                        *fresh445 = (*fresh445).offset(9 as i32 as isize);
                        (*(*ctxt).input).col += 9 as i32;
                        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                            xmlParserInputGrow((*ctxt).input, 250 as i32);
                        }
                        (*ctxt).instate = XML_PARSER_CDATA_SECTION;
                        continue;
                    } else {
                        if cur as i32 == '<' as i32
                            && next as i32 == '!' as i32
                            && avail < 9 as i32
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        if cur as i32 == '&' as i32 {
                            if terminate == 0
                                && xmlParseLookupSequence(
                                    ctxt,
                                    ';' as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                ) < 0 as i32
                            {
                                current_block = 2814621064645850728;
                                break;
                            }
                            xmlParseReference(ctxt);
                        } else {
                            if (*ctxt).inputNr == 1 as i32
                                && avail < 300 as i32
                            {
                                if terminate == 0 {
                                    if (*ctxt).progressive != 0 {
                                        if lastlt.is_null() || (*(*ctxt).input).cur > lastlt {
                                            current_block = 2814621064645850728;
                                            break;
                                        }
                                    } else if xmlParseLookupSequence(
                                            ctxt,
                                            '<' as i32 as xmlChar,
                                            0 as i32 as xmlChar,
                                            0 as i32 as xmlChar,
                                        ) < 0 as i32
                                        {
                                        current_block = 2814621064645850728;
                                        break;
                                    }
                                }
                            }
                            (*ctxt).checkIndex = 0 as i32 as i64;
                            xmlParseCharData(ctxt, 0 as i32);
                        }
                    }
                    if !(cons
                        == ((*(*ctxt).input).consumed)
                            .wrapping_add(
                                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                    as i64 as u64,
                            ) && id == (*(*ctxt).input).id)
                    {
                        continue;
                    }
                    xmlFatalErr(
                        ctxt,
                        XML_ERR_INTERNAL_ERROR,
                        b"detected an error in element content\n\0" as *const u8
                            as *const i8,
                    );
                    xmlHaltParser(ctxt);
                }
            }
            9 => {
                if avail < 2 as i32 {
                    current_block = 2814621064645850728;
                    break;
                }
                if terminate == 0 {
                    if (*ctxt).progressive != 0 {
                        if lastgt.is_null() || (*(*ctxt).input).cur >= lastgt {
                            current_block = 2814621064645850728;
                            break;
                        }
                    } else if xmlParseLookupSequence(
                            ctxt,
                            '>' as i32 as xmlChar,
                            0 as i32 as xmlChar,
                            0 as i32 as xmlChar,
                        ) < 0 as i32
                        {
                        current_block = 2814621064645850728;
                        break;
                    }
                }
                if (*ctxt).sax2 != 0 {
                    xmlParseEndTag2(
                        ctxt,
                        Some(&mut *((*ctxt).pushTab)
                            .offset(((*ctxt).nameNr - 1 as i32) as isize)),
                    );
                    nameNsPop(ctxt);
                } else {
                    xmlParseEndTag1(ctxt, 0 as i32);
                }
                if !((*ctxt).instate as i32 == XML_PARSER_EOF as i32) {
                    if (*ctxt).nameNr == 0 as i32 {
                        (*ctxt).instate = XML_PARSER_EPILOG;
                    } else {
                        (*ctxt).instate = XML_PARSER_CONTENT;
                    }
                }
            }
            8 => {
                let mut base_0: i32 = 0;
                base_0 = xmlParseLookupSequence(
                    ctxt,
                    ']' as i32 as xmlChar,
                    ']' as i32 as xmlChar,
                    '>' as i32 as xmlChar,
                );
                if base_0 < 0 as i32 {
                    if !(avail >= 300 as i32 + 2 as i32) {
                        current_block = 2814621064645850728;
                        break;
                    }
                    let mut tmp: i32 = 0;
                    tmp = xmlCheckCdataPush(
                        (*(*ctxt).input).cur,
                        300 as i32,
                        0 as i32,
                    );
                    if tmp < 0 as i32 {
                        tmp = -tmp;
                        let fresh446 = &mut ((*(*ctxt).input).cur);
                        *fresh446 = (*fresh446).offset(tmp as isize);
                        current_block = 2885357499145876431;
                        break;
                    } else {
                        if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0 {
                            if ((*(*ctxt).sax).cdataBlock).is_some() {
                                ((*(*ctxt).sax).cdataBlock)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, (*(*ctxt).input).cur, tmp);
                            } else if ((*(*ctxt).sax).characters).is_some() {
                                ((*(*ctxt).sax).characters)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, (*(*ctxt).input).cur, tmp);
                            }
                        }
                        if (*ctxt).instate as i32
                            == XML_PARSER_EOF as i32
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        let mut skipl: i32 = 0;
                        skipl = 0 as i32;
                        while skipl < tmp {
                            if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
                                let fresh447 = &mut ((*(*ctxt).input).line);
                                *fresh447 += 1;
                                (*(*ctxt).input).col = 1 as i32;
                            } else {
                                let fresh448 = &mut ((*(*ctxt).input).col);
                                *fresh448 += 1;
                            }
                            let fresh449 = &mut ((*(*ctxt).input).cur);
                            *fresh449 = (*fresh449).offset(1);
                            skipl += 1;
                        }
                        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                            xmlParserInputGrow((*ctxt).input, 250 as i32);
                        }
                        (*ctxt).checkIndex = 0 as i32 as i64;
                        current_block = 2814621064645850728;
                        break;
                    }
                } else {
                    let mut tmp_0: i32 = 0;
                    tmp_0 = xmlCheckCdataPush(
                        (*(*ctxt).input).cur,
                        base_0,
                        1 as i32,
                    );
                    if tmp_0 < 0 as i32 || tmp_0 != base_0 {
                        tmp_0 = -tmp_0;
                        let fresh450 = &mut ((*(*ctxt).input).cur);
                        *fresh450 = (*fresh450).offset(tmp_0 as isize);
                        current_block = 2885357499145876431;
                        break;
                    } else {
                        if !((*ctxt).sax).is_null() && base_0 == 0 as i32
                            && ((*(*ctxt).sax).cdataBlock).is_some()
                            && (*ctxt).disableSAX == 0
                        {
                            if ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as i64 >= 9 as i32 as i64
                                && strncmp(
                                    &*((*(*ctxt).input).cur)
                                        .offset(-(9 as i32) as isize) as *const xmlChar
                                        as *const i8,
                                    b"<![CDATA[\0" as *const u8 as *const i8,
                                    9 as i32 as u64,
                                ) == 0
                            {
                                ((*(*ctxt).sax).cdataBlock)
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    (*ctxt).userData,
                                    b"\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as i32,
                                );
                            }
                        } else if !((*ctxt).sax).is_null() && base_0 > 0 as i32
                                && (*ctxt).disableSAX == 0
                            {
                            if ((*(*ctxt).sax).cdataBlock).is_some() {
                                ((*(*ctxt).sax).cdataBlock)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, (*(*ctxt).input).cur, base_0);
                            } else if ((*(*ctxt).sax).characters).is_some() {
                                ((*(*ctxt).sax).characters)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, (*(*ctxt).input).cur, base_0);
                            }
                        }
                        if (*ctxt).instate as i32
                            == XML_PARSER_EOF as i32
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        let mut skipl_0: i32 = 0;
                        skipl_0 = 0 as i32;
                        while skipl_0 < base_0 + 3 as i32 {
                            if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
                                let fresh451 = &mut ((*(*ctxt).input).line);
                                *fresh451 += 1;
                                (*(*ctxt).input).col = 1 as i32;
                            } else {
                                let fresh452 = &mut ((*(*ctxt).input).col);
                                *fresh452 += 1;
                            }
                            let fresh453 = &mut ((*(*ctxt).input).cur);
                            *fresh453 = (*fresh453).offset(1);
                            skipl_0 += 1;
                        }
                        if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                            xmlParserInputGrow((*ctxt).input, 250 as i32);
                        }
                        (*ctxt).checkIndex = 0 as i32 as i64;
                        (*ctxt).instate = XML_PARSER_CONTENT;
                    }
                }
            }
            1 => {
                xmlSkipBlankChars(ctxt);
                if ((*(*ctxt).input).buf).is_null() {
                    avail = ((*(*ctxt).input).length as i64
                        - ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as i64) as i32;
                } else {
                    avail = (xmlBufUse((*(*(*ctxt).input).buf).buffer))
                        .wrapping_sub(
                            ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as i64 as u64,
                        ) as i32;
                }
                if avail < 2 as i32 {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = *((*(*ctxt).input).cur).offset(0 as i32 as isize);
                next = *((*(*ctxt).input).cur).offset(1 as i32 as isize);
                if cur as i32 == '<' as i32 && next as i32 == '?' as i32
                {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '?' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                            0 as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (*ctxt).progressive = XML_PARSER_PI as i32;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParsePI(ctxt);
                        if (*ctxt).instate as i32
                            == XML_PARSER_EOF as i32
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_MISC;
                        (*ctxt).progressive = 1 as i32;
                        (*ctxt).checkIndex = 0 as i32 as i64;
                    }
                } else if cur as i32 == '<' as i32
                        && next as i32 == '!' as i32
                        && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                            as i32 == '-' as i32
                        && *((*(*ctxt).input).cur).offset(3 as i32 as isize)
                            as i32 == '-' as i32
                    {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '-' as i32 as xmlChar,
                            '-' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (*ctxt).progressive = XML_PARSER_COMMENT as i32;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParseComment(ctxt);
                        if (*ctxt).instate as i32
                            == XML_PARSER_EOF as i32
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_MISC;
                        (*ctxt).progressive = 1 as i32;
                        (*ctxt).checkIndex = 0 as i32 as i64;
                    }
                } else if cur as i32 == '<' as i32
                        && next as i32 == '!' as i32
                        && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                            as i32 == 'D' as i32
                        && *((*(*ctxt).input).cur).offset(3 as i32 as isize)
                            as i32 == 'O' as i32
                        && *((*(*ctxt).input).cur).offset(4 as i32 as isize)
                            as i32 == 'C' as i32
                        && *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                            as i32 == 'T' as i32
                        && *((*(*ctxt).input).cur).offset(6 as i32 as isize)
                            as i32 == 'Y' as i32
                        && *((*(*ctxt).input).cur).offset(7 as i32 as isize)
                            as i32 == 'P' as i32
                        && *((*(*ctxt).input).cur).offset(8 as i32 as isize)
                            as i32 == 'E' as i32
                    {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '>' as i32 as xmlChar,
                            0 as i32 as xmlChar,
                            0 as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (*ctxt).progressive = XML_PARSER_DTD as i32;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        (*ctxt).inSubset = 1 as i32;
                        (*ctxt).progressive = 0 as i32;
                        (*ctxt).checkIndex = 0 as i32 as i64;
                        xmlParseDocTypeDecl(ctxt);
                        if (*ctxt).instate as i32
                            == XML_PARSER_EOF as i32
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        if *(*(*ctxt).input).cur as i32 == '[' as i32 {
                            (*ctxt).instate = XML_PARSER_DTD;
                        } else {
                            (*ctxt).inSubset = 2 as i32;
                            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                                && ((*(*ctxt).sax).externalSubset).is_some()
                            {
                                ((*(*ctxt).sax).externalSubset)
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    (*ctxt).userData,
                                    (*ctxt).intSubName,
                                    (*ctxt).extSubSystem,
                                    (*ctxt).extSubURI,
                                );
                            }
                            (*ctxt).inSubset = 0 as i32;
                            xmlCleanSpecialAttr(ctxt);
                            (*ctxt).instate = XML_PARSER_PROLOG;
                        }
                    }
                } else {
                    if cur as i32 == '<' as i32
                        && next as i32 == '!' as i32 && avail < 9 as i32
                    {
                        current_block = 2814621064645850728;
                        break;
                    }
                    (*ctxt).instate = XML_PARSER_START_TAG;
                    (*ctxt).progressive = XML_PARSER_START_TAG as i32;
                    xmlParseGetLasts(ctxt, Some(&mut lastlt), Some(&mut lastgt));
                }
            }
            4 => {
                xmlSkipBlankChars(ctxt);
                if ((*(*ctxt).input).buf).is_null() {
                    avail = ((*(*ctxt).input).length as i64
                        - ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as i64) as i32;
                } else {
                    avail = (xmlBufUse((*(*(*ctxt).input).buf).buffer))
                        .wrapping_sub(
                            ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as i64 as u64,
                        ) as i32;
                }
                if avail < 2 as i32 {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = *((*(*ctxt).input).cur).offset(0 as i32 as isize);
                next = *((*(*ctxt).input).cur).offset(1 as i32 as isize);
                if cur as i32 == '<' as i32 && next as i32 == '?' as i32
                {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '?' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                            0 as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (*ctxt).progressive = XML_PARSER_PI as i32;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParsePI(ctxt);
                        if (*ctxt).instate as i32
                            == XML_PARSER_EOF as i32
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_PROLOG;
                        (*ctxt).progressive = 1 as i32;
                    }
                } else if cur as i32 == '<' as i32
                        && next as i32 == '!' as i32
                        && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                            as i32 == '-' as i32
                        && *((*(*ctxt).input).cur).offset(3 as i32 as isize)
                            as i32 == '-' as i32
                    {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '-' as i32 as xmlChar,
                            '-' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (*ctxt).progressive = XML_PARSER_COMMENT as i32;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParseComment(ctxt);
                        if (*ctxt).instate as i32
                            == XML_PARSER_EOF as i32
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_PROLOG;
                        (*ctxt).progressive = 1 as i32;
                    }
                } else {
                    if cur as i32 == '<' as i32
                        && next as i32 == '!' as i32 && avail < 4 as i32
                    {
                        current_block = 2814621064645850728;
                        break;
                    }
                    (*ctxt).instate = XML_PARSER_START_TAG;
                    if (*ctxt).progressive == 0 as i32 {
                        (*ctxt).progressive = XML_PARSER_START_TAG as i32;
                    }
                    xmlParseGetLasts(ctxt, Some(&mut lastlt), Some(&mut lastgt));
                }
            }
            14 => {
                xmlSkipBlankChars(ctxt);
                if ((*(*ctxt).input).buf).is_null() {
                    avail = ((*(*ctxt).input).length as i64
                        - ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as i64) as i32;
                } else {
                    avail = (xmlBufUse((*(*(*ctxt).input).buf).buffer))
                        .wrapping_sub(
                            ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as i64 as u64,
                        ) as i32;
                }
                if avail < 2 as i32 {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = *((*(*ctxt).input).cur).offset(0 as i32 as isize);
                next = *((*(*ctxt).input).cur).offset(1 as i32 as isize);
                if cur as i32 == '<' as i32 && next as i32 == '?' as i32
                {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '?' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                            0 as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (*ctxt).progressive = XML_PARSER_PI as i32;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParsePI(ctxt);
                        if (*ctxt).instate as i32
                            == XML_PARSER_EOF as i32
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_EPILOG;
                        (*ctxt).progressive = 1 as i32;
                    }
                } else if cur as i32 == '<' as i32
                        && next as i32 == '!' as i32
                        && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                            as i32 == '-' as i32
                        && *((*(*ctxt).input).cur).offset(3 as i32 as isize)
                            as i32 == '-' as i32
                    {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '-' as i32 as xmlChar,
                            '-' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (*ctxt).progressive = XML_PARSER_COMMENT as i32;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParseComment(ctxt);
                        if (*ctxt).instate as i32
                            == XML_PARSER_EOF as i32
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_EPILOG;
                        (*ctxt).progressive = 1 as i32;
                    }
                } else {
                    if cur as i32 == '<' as i32
                        && next as i32 == '!' as i32 && avail < 4 as i32
                    {
                        current_block = 2814621064645850728;
                        break;
                    }
                    xmlFatalErr(ctxt, XML_ERR_DOCUMENT_END, 0 as *const i8);
                    xmlHaltParser(ctxt);
                    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some()
                    {
                        ((*(*ctxt).sax).endDocument)
                            .expect("non-null function pointer")((*ctxt).userData);
                    }
                    current_block = 2814621064645850728;
                    break;
                }
            }
            3 => {
                let mut base_1: i32 = 0;
                let mut i: i32 = 0;
                let mut buf: * mut u8 = 0 as *mut xmlChar;
                let mut quote: u8 = 0 as i32 as xmlChar;
                let mut use_0: u64 = 0;
                base_1 = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as i64 as i32;
                if base_1 < 0 as i32 {
                    return 0 as i32;
                }
                if (*ctxt).checkIndex > base_1 as i64 {
                    base_1 = (*ctxt).checkIndex as i32;
                }
                buf = xmlBufContent((*(*(*ctxt).input).buf).buffer as *const xmlBuf);
                use_0 = xmlBufUse((*(*(*ctxt).input).buf).buffer);
                's_1946: loop {
                    if !((base_1 as u32 as u64) < use_0) {
                        current_block = 10059826840140668507;
                        break;
                    }
                    if quote as i32 != 0 as i32 {
                        if *buf.offset(base_1 as isize) as i32
                            == quote as i32
                        {
                            quote = 0 as i32 as xmlChar;
                        }
                    } else {
                        if quote as i32 == 0 as i32
                            && *buf.offset(base_1 as isize) as i32 == '<' as i32
                        {
                            let mut found: i32 = 0 as i32;
                            if ((base_1 as u32)
                                .wrapping_add(4 as i32 as u32)
                                as u64) < use_0
                                && *buf.offset((base_1 + 1 as i32) as isize)
                                    as i32 == '!' as i32
                                && *buf.offset((base_1 + 2 as i32) as isize)
                                    as i32 == '-' as i32
                                && *buf.offset((base_1 + 3 as i32) as isize)
                                    as i32 == '-' as i32
                            {
                                while ((base_1 as u32)
                                    .wrapping_add(3 as i32 as u32)
                                    as u64) < use_0
                                {
                                    if *buf.offset(base_1 as isize) as i32 == '-' as i32
                                        && *buf.offset((base_1 + 1 as i32) as isize)
                                            as i32 == '-' as i32
                                        && *buf.offset((base_1 + 2 as i32) as isize)
                                            as i32 == '>' as i32
                                    {
                                        found = 1 as i32;
                                        base_1 += 2 as i32;
                                        break;
                                    } else {
                                        base_1 += 1;
                                    }
                                }
                                if found == 0 {
                                    current_block = 10059826840140668507;
                                    break;
                                }
                                current_block = 16936879297222305916;
                            } else {
                                current_block = 9828016697359808143;
                            }
                        } else {
                            current_block = 9828016697359808143;
                        }
                        match current_block {
                            16936879297222305916 => {}
                            _ => {
                                if *buf.offset(base_1 as isize) as i32 == '"' as i32
                                {
                                    quote = '"' as i32 as xmlChar;
                                } else if *buf.offset(base_1 as isize) as i32
                                        == '\'' as i32
                                    {
                                    quote = '\'' as i32 as xmlChar;
                                } else if *buf.offset(base_1 as isize) as i32
                                        == ']' as i32
                                    {
                                    if (base_1 as u32)
                                        .wrapping_add(1 as i32 as u32)
                                        as u64 >= use_0
                                    {
                                        current_block = 10059826840140668507;
                                        break;
                                    }
                                    if *buf.offset((base_1 + 1 as i32) as isize)
                                        as i32 == ']' as i32
                                    {
                                        base_1 += 1;
                                    } else {
                                        i = 1 as i32;
                                        loop {
                                            if !(((base_1 as u32)
                                                .wrapping_add(i as u32) as u64) < use_0)
                                            {
                                                current_block = 10059826840140668507;
                                                break 's_1946;
                                            }
                                            if *buf.offset((base_1 + i) as isize) as i32
                                                == '>' as i32
                                            {
                                                current_block = 16939792823138094123;
                                                break 's_1946;
                                            }
                                            if !(*buf.offset((base_1 + i) as isize) as i32
                                                == 0x20 as i32
                                                || 0x9 as i32
                                                    <= *buf.offset((base_1 + i) as isize) as i32
                                                    && *buf.offset((base_1 + i) as isize) as i32
                                                        <= 0xa as i32
                                                || *buf.offset((base_1 + i) as isize) as i32
                                                    == 0xd as i32)
                                            {
                                                break;
                                            }
                                            i += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    base_1 += 1;
                }
                match current_block {
                    10059826840140668507 => {
                        if quote as i32 == 0 as i32 {
                            (*ctxt).checkIndex = base_1 as i64;
                        } else {
                            (*ctxt).checkIndex = 0 as i32 as i64;
                        }
                        current_block = 2814621064645850728;
                        break;
                    }
                    _ => {
                        (*ctxt).checkIndex = 0 as i32 as i64;
                        xmlParseInternalSubset(ctxt);
                        if (*ctxt).instate as i32
                            == XML_PARSER_EOF as i32
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).inSubset = 2 as i32;
                        if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                            && ((*(*ctxt).sax).externalSubset).is_some()
                        {
                            ((*(*ctxt).sax).externalSubset)
                                .expect(
                                    "non-null function pointer",
                                )(
                                (*ctxt).userData,
                                (*ctxt).intSubName,
                                (*ctxt).extSubSystem,
                                (*ctxt).extSubURI,
                            );
                        }
                        (*ctxt).inSubset = 0 as i32;
                        xmlCleanSpecialAttr(ctxt);
                        if (*ctxt).instate as i32
                            == XML_PARSER_EOF as i32
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_PROLOG;
                        (*ctxt).checkIndex = 0 as i32 as i64;
                    }
                }
            }
            5 => {
                (*(borrow(& __xmlGenericError())).unwrap())
                    .expect(
                        "non-null function pointer",
                    )(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"PP: internal error, state == COMMENT\n\0" as *const u8
                        as *const i8,
                );
                (*ctxt).instate = XML_PARSER_CONTENT;
            }
            15 => {
                (*(borrow(& __xmlGenericError())).unwrap())
                    .expect(
                        "non-null function pointer",
                    )(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"PP: internal error, state == IGNORE\0" as *const u8
                        as *const i8,
                );
                (*ctxt).instate = XML_PARSER_DTD;
            }
            2 => {
                (*(borrow(& __xmlGenericError())).unwrap())
                    .expect(
                        "non-null function pointer",
                    )(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"PP: internal error, state == PI\n\0" as *const u8
                        as *const i8,
                );
                (*ctxt).instate = XML_PARSER_CONTENT;
            }
            10 => {
                (*(borrow(& __xmlGenericError())).unwrap())
                    .expect(
                        "non-null function pointer",
                    )(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"PP: internal error, state == ENTITY_DECL\n\0" as *const u8
                        as *const i8,
                );
                (*ctxt).instate = XML_PARSER_DTD;
            }
            11 => {
                (*(borrow(& __xmlGenericError())).unwrap())
                    .expect(
                        "non-null function pointer",
                    )(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"PP: internal error, state == ENTITY_VALUE\n\0" as *const u8
                        as *const i8,
                );
                (*ctxt).instate = XML_PARSER_CONTENT;
            }
            12 => {
                (*(borrow(& __xmlGenericError())).unwrap())
                    .expect(
                        "non-null function pointer",
                    )(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"PP: internal error, state == ATTRIBUTE_VALUE\n\0" as *const u8
                        as *const i8,
                );
                (*ctxt).instate = XML_PARSER_START_TAG;
            }
            13 => {
                (*(borrow(& __xmlGenericError())).unwrap())
                    .expect(
                        "non-null function pointer",
                    )(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"PP: internal error, state == SYSTEM_LITERAL\n\0" as *const u8
                        as *const i8,
                );
                (*ctxt).instate = XML_PARSER_START_TAG;
            }
            16 => {
                (*(borrow(& __xmlGenericError())).unwrap())
                    .expect(
                        "non-null function pointer",
                    )(
                    *(__xmlGenericErrorContext()).unwrap(),
                    b"PP: internal error, state == PUBLIC_LITERAL\n\0" as *const u8
                        as *const i8,
                );
                (*ctxt).instate = XML_PARSER_START_TAG;
            }
            _ => {}
        }
    }
    match current_block {
        2814621064645850728 => return ret,
        _ => {
            let mut buffer: [i8; 150] = [0; 150];
            snprintf(
                buffer.as_mut_ptr(),
                149 as i32 as u64,
                b"Bytes: 0x%02X 0x%02X 0x%02X 0x%02X\n\0" as *const u8
                    as *const i8,
                *((*(*ctxt).input).cur).offset(0 as i32 as isize) as i32,
                *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32,
                *((*(*ctxt).input).cur).offset(2 as i32 as isize) as i32,
                *((*(*ctxt).input).cur).offset(3 as i32 as isize) as i32,
            );
            __xmlErrEncoding(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"Input is not proper UTF-8, indicate encoding !\n%s\0" as *const u8
                    as *const i8,
                buffer.as_mut_ptr() as *mut xmlChar,
                0 as *const xmlChar,
            );
            return 0 as i32;
        }
    };
}
unsafe extern "C" fn xmlParseCheckTransition(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut chunk: * const i8,
    mut size: i32,
) -> i32 {
    if ctxt.is_null() || chunk.is_null() || size < 0 as i32 {
        return -(1 as i32);
    }
    if (*ctxt).instate as i32 == XML_PARSER_START_TAG as i32 {
        if !(memchr(chunk as *const libc::c_void, '>' as i32, size as u64))
            .is_null()
        {
            return 1 as i32;
        }
        return 0 as i32;
    }
    if (*ctxt).progressive == XML_PARSER_COMMENT as i32 {
        if !(memchr(chunk as *const libc::c_void, '>' as i32, size as u64))
            .is_null()
        {
            return 1 as i32;
        }
        return 0 as i32;
    }
    if (*ctxt).instate as i32 == XML_PARSER_CDATA_SECTION as i32 {
        if !(memchr(chunk as *const libc::c_void, '>' as i32, size as u64))
            .is_null()
        {
            return 1 as i32;
        }
        return 0 as i32;
    }
    if (*ctxt).progressive == XML_PARSER_PI as i32 {
        if !(memchr(chunk as *const libc::c_void, '>' as i32, size as u64))
            .is_null()
        {
            return 1 as i32;
        }
        return 0 as i32;
    }
    if (*ctxt).instate as i32 == XML_PARSER_END_TAG as i32 {
        if !(memchr(chunk as *const libc::c_void, '>' as i32, size as u64))
            .is_null()
        {
            return 1 as i32;
        }
        return 0 as i32;
    }
    if (*ctxt).progressive == XML_PARSER_DTD as i32
        || (*ctxt).instate as i32 == XML_PARSER_DTD as i32
    {
        if !(memchr(chunk as *const libc::c_void, '>' as i32, size as u64))
            .is_null()
        {
            return 1 as i32;
        }
        return 0 as i32;
    }
    return 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseChunk(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut chunk: * const i8,
    mut size: i32,
    mut terminate: i32,
) -> i32 {
    let mut end_in_lf: i32 = 0 as i32;
    let mut remain: i32 = 0 as i32;
    let mut old_avail: u64 = 0 as i32 as size_t;
    let mut avail: u64 = 0 as i32 as size_t;
    if ctxt.is_null() {
        return XML_ERR_INTERNAL_ERROR as i32;
    }
    if (*ctxt).errNo != XML_ERR_OK as i32
        && (*ctxt).disableSAX == 1 as i32
    {
        return (*ctxt).errNo;
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    if (*ctxt).instate as i32 == XML_PARSER_START as i32 {
        xmlDetectSAX2(ctxt);
    }
    if size > 0 as i32 && !chunk.is_null() && terminate == 0
        && *chunk.offset((size - 1 as i32) as isize) as i32
            == '\r' as i32
    {
        end_in_lf = 1 as i32;
        size -= 1;
    }
    loop {
        if size > 0 as i32 && !chunk.is_null() && !((*ctxt).input).is_null()
            && !((*(*ctxt).input).buf).is_null()
            && (*ctxt).instate as i32 != XML_PARSER_EOF as i32
        {
            let mut base: u64 = xmlBufGetInputBase(
                (*(*(*ctxt).input).buf).buffer,
                (*ctxt).input,
            );
            let mut cur: u64 = ((*(*ctxt).input).cur)
                .offset_from((*(*ctxt).input).base) as i64 as size_t;
            let mut res: i32 = 0;
            old_avail = xmlBufUse((*(*(*ctxt).input).buf).buffer);
            if (*ctxt).instate as i32 == XML_PARSER_START as i32
                && !((*ctxt).input).is_null() && !((*(*ctxt).input).buf).is_null()
                && !((*(*(*ctxt).input).buf).encoder).is_null()
            {
                let mut len: u32 = 45 as i32 as u32;
                if !(xmlStrcasestr(
                    (*(*(*(*ctxt).input).buf).encoder).name as *mut xmlChar,
                    b"UTF-16\0" as *const u8 as *const i8 as *mut xmlChar,
                ))
                    .is_null()
                    || !(xmlStrcasestr(
                        (*(*(*(*ctxt).input).buf).encoder).name as *mut xmlChar,
                        b"UTF16\0" as *const u8 as *const i8 as *mut xmlChar,
                    ))
                        .is_null()
                {
                    len = 90 as i32 as u32;
                } else if !(xmlStrcasestr(
                        (*(*(*(*ctxt).input).buf).encoder).name as *mut xmlChar,
                        b"UCS-4\0" as *const u8 as *const i8 as *mut xmlChar,
                    ))
                        .is_null()
                        || !(xmlStrcasestr(
                            (*(*(*(*ctxt).input).buf).encoder).name as *mut xmlChar,
                            b"UCS4\0" as *const u8 as *const i8 as *mut xmlChar,
                        ))
                            .is_null()
                    {
                    len = 180 as i32 as u32;
                }
                if (*(*(*ctxt).input).buf).rawconsumed < len as u64 {
                    len = (len as u64)
                        .wrapping_sub((*(*(*ctxt).input).buf).rawconsumed)
                        as u32 as u32;
                }
                if size as u32 > len {
                    remain = (size as u32).wrapping_sub(len) as i32;
                    size = len as i32;
                } else {
                    remain = 0 as i32;
                }
            }
            res = xmlParserInputBufferPush((*(*ctxt).input).buf, size, chunk);
            xmlBufSetInputBaseCur(
                (*(*(*ctxt).input).buf).buffer,
                (*ctxt).input,
                base,
                cur,
            );
            if res < 0 as i32 {
                (*ctxt).errNo = XML_PARSER_EOF as i32;
                xmlHaltParser(ctxt);
                return XML_PARSER_EOF as i32;
            }
        } else if (*ctxt).instate as i32 != XML_PARSER_EOF as i32 {
            if !((*ctxt).input).is_null() && !((*(*ctxt).input).buf).is_null() {
                let mut in_0: * mut crate::src::HTMLparser::_xmlParserInputBuffer = (*(*ctxt).input).buf;
                if !((*in_0).encoder).is_null() && !((*in_0).buffer).is_null()
                    && !((*in_0).raw).is_null()
                {
                    let mut nbchars: i32 = 0;
                    let mut base_0: u64 = xmlBufGetInputBase(
                        (*in_0).buffer,
                        (*ctxt).input,
                    );
                    let mut current: u64 = ((*(*ctxt).input).cur)
                        .offset_from((*(*ctxt).input).base) as i64 as size_t;
                    nbchars = xmlCharEncInput(in_0, terminate);
                    xmlBufSetInputBaseCur(
                        (*in_0).buffer,
                        (*ctxt).input,
                        base_0,
                        current,
                    );
                    if nbchars < 0 as i32 {
                        (*(borrow(& __xmlGenericError())).unwrap())
                            .expect(
                                "non-null function pointer",
                            )(
                            *(__xmlGenericErrorContext()).unwrap(),
                            b"xmlParseChunk: encoder error\n\0" as *const u8
                                as *const i8,
                        );
                        xmlHaltParser(ctxt);
                        return XML_ERR_INVALID_ENCODING as i32;
                    }
                }
            }
        }
        if remain != 0 as i32 {
            xmlParseTryOrFinish(ctxt, 0 as i32);
        } else {
            if !((*ctxt).input).is_null() && !((*(*ctxt).input).buf).is_null() {
                avail = xmlBufUse((*(*(*ctxt).input).buf).buffer);
            }
            if terminate != 0 || avail > 10000000 as i32 as u64
                || old_avail == 0 as i32 as u64
                || avail == 0 as i32 as u64
                || xmlParseCheckTransition(
                    ctxt,
                    &*((*(*ctxt).input).base).offset(old_avail as isize)
                        as *const xmlChar as *const i8,
                    avail.wrapping_sub(old_avail) as i32,
                ) != 0
            {
                xmlParseTryOrFinish(ctxt, terminate);
            }
        }
        if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
            return (*ctxt).errNo;
        }
        if !((*ctxt).input).is_null()
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64
                > 10000000 as i32 as i64
                || ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as i64 > 10000000 as i32 as i64)
            && (*ctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
        {
            xmlFatalErr(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"Huge input lookup\0" as *const u8 as *const i8,
            );
            xmlHaltParser(ctxt);
        }
        if (*ctxt).errNo != XML_ERR_OK as i32
            && (*ctxt).disableSAX == 1 as i32
        {
            return (*ctxt).errNo;
        }
        if !(remain != 0 as i32) {
            break;
        }
        chunk = chunk.offset(size as isize);
        size = remain;
        remain = 0 as i32;
    }
    if end_in_lf == 1 as i32 && !((*ctxt).input).is_null()
        && !((*(*ctxt).input).buf).is_null()
    {
        let mut base_1: u64 = xmlBufGetInputBase(
            (*(*(*ctxt).input).buf).buffer,
            (*ctxt).input,
        );
        let mut current_0: u64 = ((*(*ctxt).input).cur)
            .offset_from((*(*ctxt).input).base) as i64 as size_t;
        xmlParserInputBufferPush(
            (*(*ctxt).input).buf,
            1 as i32,
            b"\r\0" as *const u8 as *const i8,
        );
        xmlBufSetInputBaseCur(
            (*(*(*ctxt).input).buf).buffer,
            (*ctxt).input,
            base_1,
            current_0,
        );
    }
    if terminate != 0 {
        let mut cur_avail: i32 = 0 as i32;
        if !((*ctxt).input).is_null() {
            if ((*(*ctxt).input).buf).is_null() {
                cur_avail = ((*(*ctxt).input).length as i64
                    - ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as i64) as i32;
            } else {
                cur_avail = (xmlBufUse((*(*(*ctxt).input).buf).buffer))
                    .wrapping_sub(
                        ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as i64 as u64,
                    ) as i32;
            }
        }
        if (*ctxt).instate as i32 != XML_PARSER_EOF as i32
            && (*ctxt).instate as i32 != XML_PARSER_EPILOG as i32
        {
            xmlFatalErr(ctxt, XML_ERR_DOCUMENT_END, 0 as *const i8);
        }
        if (*ctxt).instate as i32 == XML_PARSER_EPILOG as i32
            && cur_avail > 0 as i32
        {
            xmlFatalErr(ctxt, XML_ERR_DOCUMENT_END, 0 as *const i8);
        }
        if (*ctxt).instate as i32 != XML_PARSER_EOF as i32 {
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some() {
                ((*(*ctxt).sax).endDocument)
                    .expect("non-null function pointer")((*ctxt).userData);
            }
        }
        (*ctxt).instate = XML_PARSER_EOF;
    }
    if (*ctxt).wellFormed == 0 as i32 {
        return (*ctxt).errNo as xmlParserErrors as i32
    } else {
        return 0 as i32
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreatePushParserCtxt(
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut user_data: * mut core::ffi::c_void,
    mut chunk: * const i8,
    mut size: i32,
    mut filename: * const i8,
) -> * mut crate::src::HTMLparser::_xmlParserCtxt {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut inputStream: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut buf: * mut crate::src::HTMLparser::_xmlParserInputBuffer = 0 as *mut xmlParserInputBuffer;
    let mut enc: i32 = XML_CHAR_ENCODING_NONE;
    if !chunk.is_null() && size >= 4 as i32 {
        enc = xmlDetectCharEncoding(chunk as *const xmlChar, size);
    }
    buf = xmlAllocParserInputBuffer(enc);
    if buf.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"creating parser: out of memory\n\0" as *const u8 as *const i8,
        );
        xmlFreeParserInputBuffer(buf);
        return 0 as xmlParserCtxtPtr;
    }
    (*ctxt).dictNames = 1 as i32;
    if !sax.is_null() {
        if (*ctxt).sax != __xmlDefaultSAXHandler() as xmlSAXHandlerPtr {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let fresh454 = &mut ((*ctxt).sax);
        *fresh454 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlSAXHandler>() as u64)
            as xmlSAXHandlerPtr;
        if ((*ctxt).sax).is_null() {
            xmlErrMemory(ctxt, 0 as *const i8);
            xmlFreeParserInputBuffer(buf);
            xmlFreeParserCtxt(ctxt);
            return 0 as xmlParserCtxtPtr;
        }
        memset(
            (*ctxt).sax as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlSAXHandler>() as u64,
        );
        if (*sax).initialized == 0xdeedbeaf as u32 {
            memcpy(
                (*ctxt).sax as *mut libc::c_void,
                sax as *const libc::c_void,
                ::std::mem::size_of::<xmlSAXHandler>() as u64,
            );
        } else {
            memcpy(
                (*ctxt).sax as *mut libc::c_void,
                sax as *const libc::c_void,
                ::std::mem::size_of::<xmlSAXHandlerV1>() as u64,
            );
        }
        if !user_data.is_null() {
            let fresh455 = &mut ((*ctxt).userData);
            *fresh455 = user_data;
        }
    }
    if filename.is_null() {
        let fresh456 = &mut ((*ctxt).directory);
        *fresh456 = 0 as *mut i8;
    } else {
        let fresh457 = &mut ((*ctxt).directory);
        *fresh457 = xmlParserGetDirectory(filename);
    }
    inputStream = xmlNewInputStream(ctxt);
    if inputStream.is_null() {
        xmlFreeParserCtxt(ctxt);
        xmlFreeParserInputBuffer(buf);
        return 0 as xmlParserCtxtPtr;
    }
    if filename.is_null() {
        let fresh458 = &mut ((*inputStream).filename);
        *fresh458 = 0 as *const i8;
    } else {
        let fresh459 = &mut ((*inputStream).filename);
        *fresh459 = xmlCanonicPath(filename as *const xmlChar) as *mut i8;
        if ((*inputStream).filename).is_null() {
            xmlFreeParserCtxt(ctxt);
            xmlFreeParserInputBuffer(buf);
            return 0 as xmlParserCtxtPtr;
        }
    }
    let fresh460 = &mut ((*inputStream).buf);
    *fresh460 = buf;
    xmlBufResetInput((*(*inputStream).buf).buffer, inputStream);
    inputPush(ctxt, inputStream);
    if size == 0 as i32 || chunk.is_null() {
        (*ctxt).charset = XML_CHAR_ENCODING_NONE as i32;
    } else if !((*ctxt).input).is_null() && !((*(*ctxt).input).buf).is_null() {
        let mut base: u64 = xmlBufGetInputBase(
            (*(*(*ctxt).input).buf).buffer,
            (*ctxt).input,
        );
        let mut cur: u64 = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
            as i64 as size_t;
        xmlParserInputBufferPush((*(*ctxt).input).buf, size, chunk);
        xmlBufSetInputBaseCur((*(*(*ctxt).input).buf).buffer, (*ctxt).input, base, cur);
    }
    if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
        xmlSwitchEncoding(ctxt, enc);
    }
    return ctxt;
}
unsafe extern "C" fn xmlHaltParser(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    if ctxt.is_null() {
        return;
    }
    (*ctxt).instate = XML_PARSER_EOF;
    (*ctxt).disableSAX = 1 as i32;
    while (*ctxt).inputNr > 1 as i32 {
        xmlFreeInputStream(inputPop(ctxt));
    }
    if !((*ctxt).input).is_null() {
        if ((*(*ctxt).input).free).is_some() {
            ((*(*ctxt).input).free)
                .expect(
                    "non-null function pointer",
                )((*(*ctxt).input).base as *mut xmlChar);
            let fresh461 = &mut ((*(*ctxt).input).free);
            *fresh461 = None;
        }
        if !((*(*ctxt).input).buf).is_null() {
            xmlFreeParserInputBuffer((*(*ctxt).input).buf);
            let fresh462 = &mut ((*(*ctxt).input).buf);
            *fresh462 = 0 as xmlParserInputBufferPtr;
        }
        let fresh463 = &mut ((*(*ctxt).input).cur);
        *fresh463 = b"\0" as *const u8 as *const i8 as *mut xmlChar;
        (*(*ctxt).input).length = 0 as i32;
        let fresh464 = &mut ((*(*ctxt).input).base);
        *fresh464 = (*(*ctxt).input).cur;
        let fresh465 = &mut ((*(*ctxt).input).end);
        *fresh465 = (*(*ctxt).input).cur;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlStopParser(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    if ctxt.is_null() {
        return;
    }
    xmlHaltParser(ctxt);
    (*ctxt).errNo = XML_ERR_USER_STOP as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateIOParserCtxt(
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut user_data: * mut core::ffi::c_void,
    mut ioread: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut i8,_: i32,) -> i32>,
    mut ioclose: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>,
    mut ioctx: * mut core::ffi::c_void,
    mut enc: i32,
) -> * mut crate::src::HTMLparser::_xmlParserCtxt {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut inputStream: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut buf: * mut crate::src::HTMLparser::_xmlParserInputBuffer = 0 as *mut xmlParserInputBuffer;
    if ioread.is_none() {
        return 0 as xmlParserCtxtPtr;
    }
    buf = xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, enc);
    if buf.is_null() {
        if ioclose.is_some() {
            ioclose.expect("non-null function pointer")(ioctx);
        }
        return 0 as xmlParserCtxtPtr;
    }
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        xmlFreeParserInputBuffer(buf);
        return 0 as xmlParserCtxtPtr;
    }
    if !sax.is_null() {
        if (*ctxt).sax != __xmlDefaultSAXHandler() as xmlSAXHandlerPtr {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let fresh466 = &mut ((*ctxt).sax);
        *fresh466 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlSAXHandler>() as u64)
            as xmlSAXHandlerPtr;
        if ((*ctxt).sax).is_null() {
            xmlFreeParserInputBuffer(buf);
            xmlErrMemory(ctxt, 0 as *const i8);
            xmlFreeParserCtxt(ctxt);
            return 0 as xmlParserCtxtPtr;
        }
        memset(
            (*ctxt).sax as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlSAXHandler>() as u64,
        );
        if (*sax).initialized == 0xdeedbeaf as u32 {
            memcpy(
                (*ctxt).sax as *mut libc::c_void,
                sax as *const libc::c_void,
                ::std::mem::size_of::<xmlSAXHandler>() as u64,
            );
        } else {
            memcpy(
                (*ctxt).sax as *mut libc::c_void,
                sax as *const libc::c_void,
                ::std::mem::size_of::<xmlSAXHandlerV1>() as u64,
            );
        }
        if !user_data.is_null() {
            let fresh467 = &mut ((*ctxt).userData);
            *fresh467 = user_data;
        }
    }
    inputStream = xmlNewIOInputStream(ctxt, buf, enc);
    if inputStream.is_null() {
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlParserCtxtPtr;
    }
    inputPush(ctxt, inputStream);
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn xmlIOParseDTD(
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut input: * mut crate::src::HTMLparser::_xmlParserInputBuffer,
    mut enc: i32,
) -> * mut crate::src::HTMLparser::_xmlDtd {
    let mut ret: * mut crate::src::HTMLparser::_xmlDtd = 0 as xmlDtdPtr;
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut pinput: * mut crate::src::HTMLparser::_xmlParserInput = 0 as xmlParserInputPtr;
    let mut start: [u8; 4] = [0; 4];
    if input.is_null() {
        return 0 as xmlDtdPtr;
    }
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as xmlDtdPtr;
    }
    (*ctxt).options |= XML_PARSE_DTDLOAD as i32;
    if !sax.is_null() {
        if !((*ctxt).sax).is_null() {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let fresh468 = &mut ((*ctxt).sax);
        *fresh468 = sax;
        let fresh469 = &mut ((*ctxt).userData);
        *fresh469 = ctxt as *mut libc::c_void;
    }
    xmlDetectSAX2(ctxt);
    pinput = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if pinput.is_null() {
        if !sax.is_null() {
            let fresh470 = &mut ((*ctxt).sax);
            *fresh470 = 0 as *mut _xmlSAXHandler;
        }
        xmlFreeParserInputBuffer(input);
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDtdPtr;
    }
    if xmlPushInput(ctxt, pinput) < 0 as i32 {
        if !sax.is_null() {
            let fresh471 = &mut ((*ctxt).sax);
            *fresh471 = 0 as *mut _xmlSAXHandler;
        }
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDtdPtr;
    }
    if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
        xmlSwitchEncoding(ctxt, enc);
    }
    let fresh472 = &mut ((*pinput).filename);
    *fresh472 = 0 as *const i8;
    (*pinput).line = 1 as i32;
    (*pinput).col = 1 as i32;
    let fresh473 = &mut ((*pinput).base);
    *fresh473 = (*(*ctxt).input).cur;
    let fresh474 = &mut ((*pinput).cur);
    *fresh474 = (*(*ctxt).input).cur;
    let fresh475 = &mut ((*pinput).free);
    *fresh475 = None;
    (*ctxt).inSubset = 2 as i32;
    let fresh476 = &mut ((*ctxt).myDoc);
    *fresh476 = xmlNewDoc(b"1.0\0" as *const u8 as *const i8 as *mut xmlChar);
    if ((*ctxt).myDoc).is_null() {
        xmlErrMemory(ctxt, b"New Doc failed\0" as *const u8 as *const i8);
        return 0 as xmlDtdPtr;
    }
    (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as i32;
    let fresh477 = &mut ((*(*ctxt).myDoc).extSubset);
    *fresh477 = xmlNewDtd(
        (*ctxt).myDoc,
        b"none\0" as *const u8 as *const i8 as *mut xmlChar,
        b"none\0" as *const u8 as *const i8 as *mut xmlChar,
        b"none\0" as *const u8 as *const i8 as *mut xmlChar,
    );
    if enc as i32 == XML_CHAR_ENCODING_NONE as i32
        && ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64
            >= 4 as i32 as i64
    {
        start[0 as i32 as usize] = *(*(*ctxt).input).cur;
        start[1 as i32
            as usize] = *((*(*ctxt).input).cur).offset(1 as i32 as isize);
        start[2 as i32
            as usize] = *((*(*ctxt).input).cur).offset(2 as i32 as isize);
        start[3 as i32
            as usize] = *((*(*ctxt).input).cur).offset(3 as i32 as isize);
        enc = xmlDetectCharEncoding(start.as_mut_ptr(), 4 as i32);
        if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
            xmlSwitchEncoding(ctxt, enc);
        }
    }
    xmlParseExternalSubset(
        ctxt,
        b"none\0" as *const u8 as *const i8 as *mut xmlChar,
        b"none\0" as *const u8 as *const i8 as *mut xmlChar,
    );
    if !((*ctxt).myDoc).is_null() {
        if (*ctxt).wellFormed != 0 {
            ret = (*(*ctxt).myDoc).extSubset;
            let fresh478 = &mut ((*(*ctxt).myDoc).extSubset);
            *fresh478 = 0 as *mut _xmlDtd;
            if !ret.is_null() {
                let mut tmp: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
                let fresh479 = &mut ((*ret).doc);
                *fresh479 = 0 as *mut _xmlDoc;
                tmp = (*ret).children;
                while !tmp.is_null() {
                    let fresh480 = &mut ((*tmp).doc);
                    *fresh480 = 0 as *mut _xmlDoc;
                    tmp = (*tmp).next;
                }
            }
        } else {
            ret = 0 as xmlDtdPtr;
        }
        xmlFreeDoc((*ctxt).myDoc);
        let fresh481 = &mut ((*ctxt).myDoc);
        *fresh481 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let fresh482 = &mut ((*ctxt).sax);
        *fresh482 = 0 as *mut _xmlSAXHandler;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseDTD(
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut ExternalID: * const u8,
    mut SystemID: * const u8,
) -> * mut crate::src::HTMLparser::_xmlDtd {
    let mut ret: * mut crate::src::HTMLparser::_xmlDtd = 0 as xmlDtdPtr;
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut input: * mut crate::src::HTMLparser::_xmlParserInput = 0 as xmlParserInputPtr;
    let mut enc: i32 = XML_CHAR_ENCODING_NONE;
    let mut systemIdCanonic: * mut u8 = 0 as *mut xmlChar;
    if ExternalID.is_null() && SystemID.is_null() {
        return 0 as xmlDtdPtr;
    }
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        return 0 as xmlDtdPtr;
    }
    (*ctxt).options |= XML_PARSE_DTDLOAD as i32;
    if !sax.is_null() {
        if !((*ctxt).sax).is_null() {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let fresh483 = &mut ((*ctxt).sax);
        *fresh483 = sax;
        let fresh484 = &mut ((*ctxt).userData);
        *fresh484 = ctxt as *mut libc::c_void;
    }
    systemIdCanonic = xmlCanonicPath(SystemID);
    if !SystemID.is_null() && systemIdCanonic.is_null() {
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDtdPtr;
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).resolveEntity).is_some() {
        input = ((*(*ctxt).sax).resolveEntity)
            .expect(
                "non-null function pointer",
            )((*ctxt).userData, ExternalID, systemIdCanonic);
    }
    if input.is_null() {
        if !sax.is_null() {
            let fresh485 = &mut ((*ctxt).sax);
            *fresh485 = 0 as *mut _xmlSAXHandler;
        }
        xmlFreeParserCtxt(ctxt);
        if !systemIdCanonic.is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )(systemIdCanonic as *mut libc::c_void);
        }
        return 0 as xmlDtdPtr;
    }
    if xmlPushInput(ctxt, input) < 0 as i32 {
        if !sax.is_null() {
            let fresh486 = &mut ((*ctxt).sax);
            *fresh486 = 0 as *mut _xmlSAXHandler;
        }
        xmlFreeParserCtxt(ctxt);
        if !systemIdCanonic.is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )(systemIdCanonic as *mut libc::c_void);
        }
        return 0 as xmlDtdPtr;
    }
    if ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64
        >= 4 as i32 as i64
    {
        enc = xmlDetectCharEncoding((*(*ctxt).input).cur, 4 as i32);
        xmlSwitchEncoding(ctxt, enc);
    }
    if ((*input).filename).is_null() {
        let fresh487 = &mut ((*input).filename);
        *fresh487 = systemIdCanonic as *mut i8;
    } else {
        xmlFree
            .expect("non-null function pointer")(systemIdCanonic as *mut libc::c_void);
    }
    (*input).line = 1 as i32;
    (*input).col = 1 as i32;
    let fresh488 = &mut ((*input).base);
    *fresh488 = (*(*ctxt).input).cur;
    let fresh489 = &mut ((*input).cur);
    *fresh489 = (*(*ctxt).input).cur;
    let fresh490 = &mut ((*input).free);
    *fresh490 = None;
    (*ctxt).inSubset = 2 as i32;
    let fresh491 = &mut ((*ctxt).myDoc);
    *fresh491 = xmlNewDoc(b"1.0\0" as *const u8 as *const i8 as *mut xmlChar);
    if ((*ctxt).myDoc).is_null() {
        xmlErrMemory(ctxt, b"New Doc failed\0" as *const u8 as *const i8);
        if !sax.is_null() {
            let fresh492 = &mut ((*ctxt).sax);
            *fresh492 = 0 as *mut _xmlSAXHandler;
        }
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDtdPtr;
    }
    (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as i32;
    let fresh493 = &mut ((*(*ctxt).myDoc).extSubset);
    *fresh493 = xmlNewDtd(
        (*ctxt).myDoc,
        b"none\0" as *const u8 as *const i8 as *mut xmlChar,
        ExternalID,
        SystemID,
    );
    xmlParseExternalSubset(ctxt, ExternalID, SystemID);
    if !((*ctxt).myDoc).is_null() {
        if (*ctxt).wellFormed != 0 {
            ret = (*(*ctxt).myDoc).extSubset;
            let fresh494 = &mut ((*(*ctxt).myDoc).extSubset);
            *fresh494 = 0 as *mut _xmlDtd;
            if !ret.is_null() {
                let mut tmp: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
                let fresh495 = &mut ((*ret).doc);
                *fresh495 = 0 as *mut _xmlDoc;
                tmp = (*ret).children;
                while !tmp.is_null() {
                    let fresh496 = &mut ((*tmp).doc);
                    *fresh496 = 0 as *mut _xmlDoc;
                    tmp = (*tmp).next;
                }
            }
        } else {
            ret = 0 as xmlDtdPtr;
        }
        xmlFreeDoc((*ctxt).myDoc);
        let fresh497 = &mut ((*ctxt).myDoc);
        *fresh497 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let fresh498 = &mut ((*ctxt).sax);
        *fresh498 = 0 as *mut _xmlSAXHandler;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseDTD(
    mut ExternalID: * const u8,
    mut SystemID: * const u8,
) -> * mut crate::src::HTMLparser::_xmlDtd {
    return xmlSAXParseDTD(0 as xmlSAXHandlerPtr, ExternalID, SystemID);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseCtxtExternalEntity<'a1>(
    mut ctx: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut URL: * const u8,
    mut ID: * const u8,
    mut lst: Option<&'a1 mut * mut crate::src::HTMLparser::_xmlNode>,
) -> i32 {
    let mut userData: * mut core::ffi::c_void = 0 as *mut libc::c_void;
    if ctx.is_null() {
        return -(1 as i32);
    }
    if (*ctx).userData == ctx as *mut libc::c_void {
        userData = 0 as *mut libc::c_void;
    } else {
        userData = (*ctx).userData;
    }
    return xmlParseExternalEntityPrivate(
        (*ctx).myDoc,
        ctx,
        (*ctx).sax,
        userData,
        (*ctx).depth + 1 as i32,
        URL,
        ID,
        borrow_mut(&mut lst),
    ) as i32;
}
unsafe extern "C" fn xmlParseExternalEntityPrivate<'a1>(
    mut doc: * mut crate::src::HTMLparser::_xmlDoc,
    mut oldctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut user_data: * mut core::ffi::c_void,
    mut depth: i32,
    mut URL: * const u8,
    mut ID: * const u8,
    mut list: Option<&'a1 mut * mut crate::src::HTMLparser::_xmlNode>,
) -> u32 {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut newDoc: * mut crate::src::HTMLparser::_xmlDoc = 0 as *mut xmlDoc;
    let mut newRoot: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    let mut oldsax: * mut crate::src::HTMLparser::_xmlSAXHandler = 0 as xmlSAXHandlerPtr;
    let mut ret: u32 = XML_ERR_OK;
    let mut start: [u8; 4] = [0; 4];
    let mut enc: i32 = XML_CHAR_ENCODING_NONE;
    if depth > 40 as i32
        && (oldctxt.is_null()
            || (*oldctxt).options & XML_PARSE_HUGE as i32 == 0 as i32)
        || depth > 1024 as i32
    {
        return XML_ERR_ENTITY_LOOP;
    }
    if !borrow(& list).is_none() {
        *(borrow_mut(&mut list)).unwrap() = 0 as xmlNodePtr;
    }
    if URL.is_null() && ID.is_null() {
        return XML_ERR_INTERNAL_ERROR;
    }
    if doc.is_null() {
        return XML_ERR_INTERNAL_ERROR;
    }
    ctxt = xmlCreateEntityParserCtxtInternal(URL, ID, 0 as *const xmlChar, oldctxt);
    if ctxt.is_null() {
        return XML_WAR_UNDECLARED_ENTITY;
    }
    let fresh499 = &mut ((*ctxt).userData);
    *fresh499 = ctxt as *mut libc::c_void;
    if !sax.is_null() {
        oldsax = (*ctxt).sax;
        let fresh500 = &mut ((*ctxt).sax);
        *fresh500 = sax;
        if !user_data.is_null() {
            let fresh501 = &mut ((*ctxt).userData);
            *fresh501 = user_data;
        }
    }
    xmlDetectSAX2(ctxt);
    newDoc = xmlNewDoc(b"1.0\0" as *const u8 as *const i8 as *mut xmlChar);
    if newDoc.is_null() {
        xmlFreeParserCtxt(ctxt);
        return XML_ERR_INTERNAL_ERROR;
    }
    (*newDoc).properties = XML_DOC_INTERNAL as i32;
    if !doc.is_null() {
        let fresh502 = &mut ((*newDoc).intSubset);
        *fresh502 = (*doc).intSubset;
        let fresh503 = &mut ((*newDoc).extSubset);
        *fresh503 = (*doc).extSubset;
        if !((*doc).dict).is_null() {
            let fresh504 = &mut ((*newDoc).dict);
            *fresh504 = (*doc).dict;
            xmlDictReference((*newDoc).dict);
        }
        if !((*doc).URL).is_null() {
            let fresh505 = &mut ((*newDoc).URL);
            *fresh505 = xmlStrdup((*doc).URL);
        }
    }
    newRoot = xmlNewDocNode(
        newDoc,
        0 as xmlNsPtr,
        b"pseudoroot\0" as *const u8 as *const i8 as *mut xmlChar,
        0 as *const xmlChar,
    );
    if newRoot.is_null() {
        if !sax.is_null() {
            let fresh506 = &mut ((*ctxt).sax);
            *fresh506 = oldsax;
        }
        xmlFreeParserCtxt(ctxt);
        let fresh507 = &mut ((*newDoc).intSubset);
        *fresh507 = 0 as *mut _xmlDtd;
        let fresh508 = &mut ((*newDoc).extSubset);
        *fresh508 = 0 as *mut _xmlDtd;
        xmlFreeDoc(newDoc);
        return XML_ERR_INTERNAL_ERROR;
    }
    xmlAddChild(newDoc as xmlNodePtr, newRoot);
    nodePush(ctxt, (*newDoc).children);
    if doc.is_null() {
        let fresh509 = &mut ((*ctxt).myDoc);
        *fresh509 = newDoc;
    } else {
        let fresh510 = &mut ((*ctxt).myDoc);
        *fresh510 = doc;
        let fresh511 = &mut ((*newRoot).doc);
        *fresh511 = doc;
    }
    if (*ctxt).progressive == 0 as i32
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
            < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64
        >= 4 as i32 as i64
    {
        start[0 as i32 as usize] = *(*(*ctxt).input).cur;
        start[1 as i32
            as usize] = *((*(*ctxt).input).cur).offset(1 as i32 as isize);
        start[2 as i32
            as usize] = *((*(*ctxt).input).cur).offset(2 as i32 as isize);
        start[3 as i32
            as usize] = *((*(*ctxt).input).cur).offset(3 as i32 as isize);
        enc = xmlDetectCharEncoding(start.as_mut_ptr(), 4 as i32);
        if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
            xmlSwitchEncoding(ctxt, enc);
        }
    }
    if *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize)
        as i32 == '<' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(1 as i32 as isize) as i32 == '?' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(2 as i32 as isize) as i32 == 'x' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(3 as i32 as isize) as i32 == 'm' as i32
        && *((*(*ctxt).input).cur as *mut u8)
            .offset(4 as i32 as isize) as i32 == 'l' as i32
        && (*((*(*ctxt).input).cur).offset(5 as i32 as isize) as i32
            == 0x20 as i32
            || 0x9 as i32
                <= *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                    as i32
                && *((*(*ctxt).input).cur).offset(5 as i32 as isize)
                    as i32 <= 0xa as i32
            || *((*(*ctxt).input).cur).offset(5 as i32 as isize) as i32
                == 0xd as i32)
    {
        xmlParseTextDecl(ctxt);
        if xmlStrEqual(
            (*oldctxt).version,
            b"1.0\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
            && xmlStrEqual(
                (*(*ctxt).input).version,
                b"1.0\0" as *const u8 as *const i8 as *mut xmlChar,
            ) == 0
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_VERSION_MISMATCH,
                b"Version mismatch between document and entity\n\0" as *const u8
                    as *const i8,
            );
        }
    }
    (*ctxt).instate = XML_PARSER_CONTENT;
    (*ctxt).depth = depth;
    if !oldctxt.is_null() {
        let fresh512 = &mut ((*ctxt)._private);
        *fresh512 = (*oldctxt)._private;
        (*ctxt).loadsubset = (*oldctxt).loadsubset;
        (*ctxt).validate = (*oldctxt).validate;
        (*ctxt).valid = (*oldctxt).valid;
        (*ctxt).replaceEntities = (*oldctxt).replaceEntities;
        if (*oldctxt).validate != 0 {
            let fresh513 = &mut ((*ctxt).vctxt.error);
            *fresh513 = (*oldctxt).vctxt.error;
            let fresh514 = &mut ((*ctxt).vctxt.warning);
            *fresh514 = (*oldctxt).vctxt.warning;
            let fresh515 = &mut ((*ctxt).vctxt.userData);
            *fresh515 = (*oldctxt).vctxt.userData;
        }
        (*ctxt).external = (*oldctxt).external;
        if !((*ctxt).dict).is_null() {
            xmlDictFree((*ctxt).dict);
        }
        let fresh516 = &mut ((*ctxt).dict);
        *fresh516 = (*oldctxt).dict;
        let fresh517 = &mut ((*ctxt).str_xml);
        *fresh517 = xmlDictLookup(
            (*ctxt).dict,
            b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
            3 as i32,
        );
        let fresh518 = &mut ((*ctxt).str_xmlns);
        *fresh518 = xmlDictLookup(
            (*ctxt).dict,
            b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
            5 as i32,
        );
        let fresh519 = &mut ((*ctxt).str_xml_ns);
        *fresh519 = xmlDictLookup(
            (*ctxt).dict,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                as *const xmlChar,
            36 as i32,
        );
        (*ctxt).dictNames = (*oldctxt).dictNames;
        let fresh520 = &mut ((*ctxt).attsDefault);
        *fresh520 = (*oldctxt).attsDefault;
        let fresh521 = &mut ((*ctxt).attsSpecial);
        *fresh521 = (*oldctxt).attsSpecial;
        (*ctxt).linenumbers = (*oldctxt).linenumbers;
        (*ctxt).record_info = (*oldctxt).record_info;
        (*ctxt).node_seq.maximum = (*oldctxt).node_seq.maximum;
        (*ctxt).node_seq.length = (*oldctxt).node_seq.length;
        let fresh522 = &mut ((*ctxt).node_seq.buffer);
        *fresh522 = (*oldctxt).node_seq.buffer;
    } else {
        let fresh523 = &mut ((*ctxt)._private);
        *fresh523 = 0 as *mut libc::c_void;
        (*ctxt).validate = 0 as i32;
        (*ctxt).external = 2 as i32;
        (*ctxt).loadsubset = 0 as i32;
    }
    xmlParseContent(ctxt);
    if *(*(*ctxt).input).cur as i32 == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    } else if *(*(*ctxt).input).cur as i32 != 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const i8);
    }
    if (*ctxt).node != (*newDoc).children {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    }
    if (*ctxt).wellFormed == 0 {
        if (*ctxt).errNo == 0 as i32 {
            ret = XML_ERR_INTERNAL_ERROR;
        } else {
            ret = (*ctxt).errNo as xmlParserErrors;
        }
    } else {
        if !borrow(& list).is_none() {
            let mut cur: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
            cur = (*(*newDoc).children).children;
            *(borrow_mut(&mut list)).unwrap() = cur;
            while !cur.is_null() {
                let fresh524 = &mut ((*cur).parent);
                *fresh524 = 0 as *mut _xmlNode;
                cur = (*cur).next;
            }
            let fresh525 = &mut ((*(*newDoc).children).children);
            *fresh525 = 0 as *mut _xmlNode;
        }
        ret = XML_ERR_OK;
    }
    if !oldctxt.is_null() {
        let fresh526 = &mut ((*oldctxt).nbentities);
        *fresh526 = (*fresh526).wrapping_add((*ctxt).nbentities);
    }
    if !((*ctxt).input).is_null() && !oldctxt.is_null() {
        let fresh527 = &mut ((*oldctxt).sizeentities);
        *fresh527 = (*fresh527).wrapping_add((*(*ctxt).input).consumed);
        let fresh528 = &mut ((*oldctxt).sizeentities);
        *fresh528 = (*fresh528)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64
                    as u64,
            );
    }
    if !oldctxt.is_null() && (*ctxt).lastError.code != XML_ERR_OK as i32 {
        xmlCopyError(&mut (*ctxt).lastError, &mut (*oldctxt).lastError);
    }
    if !sax.is_null() {
        let fresh529 = &mut ((*ctxt).sax);
        *fresh529 = oldsax;
    }
    if !oldctxt.is_null() {
        let fresh530 = &mut ((*ctxt).dict);
        *fresh530 = 0 as xmlDictPtr;
        let fresh531 = &mut ((*ctxt).attsDefault);
        *fresh531 = 0 as xmlHashTablePtr;
        let fresh532 = &mut ((*ctxt).attsSpecial);
        *fresh532 = 0 as xmlHashTablePtr;
        (*oldctxt).validate = (*ctxt).validate;
        (*oldctxt).valid = (*ctxt).valid;
        (*oldctxt).node_seq.maximum = (*ctxt).node_seq.maximum;
        (*oldctxt).node_seq.length = (*ctxt).node_seq.length;
        let fresh533 = &mut ((*oldctxt).node_seq.buffer);
        *fresh533 = (*ctxt).node_seq.buffer;
    }
    (*ctxt).node_seq.maximum = 0 as i32 as u64;
    (*ctxt).node_seq.length = 0 as i32 as u64;
    let fresh534 = &mut ((*ctxt).node_seq.buffer);
    *fresh534 = 0 as *mut xmlParserNodeInfo;
    xmlFreeParserCtxt(ctxt);
    let fresh535 = &mut ((*newDoc).intSubset);
    *fresh535 = 0 as *mut _xmlDtd;
    let fresh536 = &mut ((*newDoc).extSubset);
    *fresh536 = 0 as *mut _xmlDtd;
    xmlFreeDoc(newDoc);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseExternalEntity<'a1>(
    mut doc: * mut crate::src::HTMLparser::_xmlDoc,
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut user_data: * mut core::ffi::c_void,
    mut depth: i32,
    mut URL: * const u8,
    mut ID: * const u8,
    mut lst: Option<&'a1 mut * mut crate::src::HTMLparser::_xmlNode>,
) -> i32 {
    return xmlParseExternalEntityPrivate(
        doc,
        0 as xmlParserCtxtPtr,
        sax,
        user_data,
        depth,
        URL,
        ID,
        borrow_mut(&mut lst),
    ) as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseBalancedChunkMemory<'a1>(
    mut doc: * mut crate::src::HTMLparser::_xmlDoc,
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut user_data: * mut core::ffi::c_void,
    mut depth: i32,
    mut string: * const u8,
    mut lst: Option<&'a1 mut * mut crate::src::HTMLparser::_xmlNode>,
) -> i32 {
    return xmlParseBalancedChunkMemoryRecover(
        doc,
        sax,
        user_data,
        depth,
        string,
        borrow_mut(&mut lst),
        0 as i32,
    );
}
unsafe extern "C" fn xmlParseBalancedChunkMemoryInternal<'a1>(
    mut oldctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut string: * const u8,
    mut user_data: * mut core::ffi::c_void,
    mut lst: Option<&'a1 mut * mut crate::src::HTMLparser::_xmlNode>,
) -> u32 {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut newDoc: * mut crate::src::HTMLparser::_xmlDoc = 0 as xmlDocPtr;
    let mut newRoot: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    let mut oldsax: * mut crate::src::HTMLparser::_xmlSAXHandler = 0 as xmlSAXHandlerPtr;
    let mut content: * mut crate::src::HTMLparser::_xmlNode = 0 as xmlNodePtr;
    let mut last: * mut crate::src::HTMLparser::_xmlNode = 0 as xmlNodePtr;
    let mut size: i32 = 0;
    let mut ret: u32 = XML_ERR_OK;
    let mut i: i32 = 0;
    if (*oldctxt).depth > 40 as i32
        && (*oldctxt).options & XML_PARSE_HUGE as i32 == 0 as i32
        || (*oldctxt).depth > 1024 as i32
    {
        return XML_ERR_ENTITY_LOOP;
    }
    if !borrow(& lst).is_none() {
        *(borrow_mut(&mut lst)).unwrap() = 0 as xmlNodePtr;
    }
    if string.is_null() {
        return XML_ERR_INTERNAL_ERROR;
    }
    size = xmlStrlen(string);
    ctxt = xmlCreateMemoryParserCtxt(string as *mut i8, size);
    if ctxt.is_null() {
        return XML_WAR_UNDECLARED_ENTITY;
    }
    if !user_data.is_null() {
        let fresh537 = &mut ((*ctxt).userData);
        *fresh537 = user_data;
    } else {
        let fresh538 = &mut ((*ctxt).userData);
        *fresh538 = ctxt as *mut libc::c_void;
    }
    if !((*ctxt).dict).is_null() {
        xmlDictFree((*ctxt).dict);
    }
    let fresh539 = &mut ((*ctxt).dict);
    *fresh539 = (*oldctxt).dict;
    (*ctxt).input_id = (*oldctxt).input_id + 1 as i32;
    let fresh540 = &mut ((*ctxt).str_xml);
    *fresh540 = xmlDictLookup(
        (*ctxt).dict,
        b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
        3 as i32,
    );
    let fresh541 = &mut ((*ctxt).str_xmlns);
    *fresh541 = xmlDictLookup(
        (*ctxt).dict,
        b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
        5 as i32,
    );
    let fresh542 = &mut ((*ctxt).str_xml_ns);
    *fresh542 = xmlDictLookup(
        (*ctxt).dict,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
            as *const xmlChar,
        36 as i32,
    );
    i = 0 as i32;
    while i < (*oldctxt).nsNr {
        nsPush(
            ctxt,
            *((*oldctxt).nsTab).offset(i as isize),
            *((*oldctxt).nsTab).offset((i + 1 as i32) as isize),
        );
        i += 2 as i32;
    }
    oldsax = (*ctxt).sax;
    let fresh543 = &mut ((*ctxt).sax);
    *fresh543 = (*oldctxt).sax;
    xmlDetectSAX2(ctxt);
    (*ctxt).replaceEntities = (*oldctxt).replaceEntities;
    (*ctxt).options = (*oldctxt).options;
    let fresh544 = &mut ((*ctxt)._private);
    *fresh544 = (*oldctxt)._private;
    if ((*oldctxt).myDoc).is_null() {
        newDoc = xmlNewDoc(b"1.0\0" as *const u8 as *const i8 as *mut xmlChar);
        if newDoc.is_null() {
            let fresh545 = &mut ((*ctxt).sax);
            *fresh545 = oldsax;
            let fresh546 = &mut ((*ctxt).dict);
            *fresh546 = 0 as xmlDictPtr;
            xmlFreeParserCtxt(ctxt);
            return XML_ERR_INTERNAL_ERROR;
        }
        (*newDoc).properties = XML_DOC_INTERNAL as i32;
        let fresh547 = &mut ((*newDoc).dict);
        *fresh547 = (*ctxt).dict;
        xmlDictReference((*newDoc).dict);
        let fresh548 = &mut ((*ctxt).myDoc);
        *fresh548 = newDoc;
    } else {
        let fresh549 = &mut ((*ctxt).myDoc);
        *fresh549 = (*oldctxt).myDoc;
        content = (*(*ctxt).myDoc).children;
        last = (*(*ctxt).myDoc).last;
    }
    newRoot = xmlNewDocNode(
        (*ctxt).myDoc,
        0 as xmlNsPtr,
        b"pseudoroot\0" as *const u8 as *const i8 as *mut xmlChar,
        0 as *const xmlChar,
    );
    if newRoot.is_null() {
        let fresh550 = &mut ((*ctxt).sax);
        *fresh550 = oldsax;
        let fresh551 = &mut ((*ctxt).dict);
        *fresh551 = 0 as xmlDictPtr;
        xmlFreeParserCtxt(ctxt);
        if !newDoc.is_null() {
            xmlFreeDoc(newDoc);
        }
        return XML_ERR_INTERNAL_ERROR;
    }
    let fresh552 = &mut ((*(*ctxt).myDoc).children);
    *fresh552 = 0 as *mut _xmlNode;
    let fresh553 = &mut ((*(*ctxt).myDoc).last);
    *fresh553 = 0 as *mut _xmlNode;
    xmlAddChild((*ctxt).myDoc as xmlNodePtr, newRoot);
    nodePush(ctxt, (*(*ctxt).myDoc).children);
    (*ctxt).instate = XML_PARSER_CONTENT;
    (*ctxt).depth = (*oldctxt).depth + 1 as i32;
    (*ctxt).validate = 0 as i32;
    (*ctxt).loadsubset = (*oldctxt).loadsubset;
    if (*oldctxt).validate != 0 || (*oldctxt).replaceEntities != 0 as i32 {
        (*ctxt).loadsubset |= 8 as i32;
    }
    (*ctxt).dictNames = (*oldctxt).dictNames;
    let fresh554 = &mut ((*ctxt).attsDefault);
    *fresh554 = (*oldctxt).attsDefault;
    let fresh555 = &mut ((*ctxt).attsSpecial);
    *fresh555 = (*oldctxt).attsSpecial;
    xmlParseContent(ctxt);
    if *(*(*ctxt).input).cur as i32 == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    } else if *(*(*ctxt).input).cur as i32 != 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const i8);
    }
    if (*ctxt).node != (*(*ctxt).myDoc).children {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    }
    if (*ctxt).wellFormed == 0 {
        if (*ctxt).errNo == 0 as i32 {
            ret = XML_ERR_INTERNAL_ERROR;
        } else {
            ret = (*ctxt).errNo as xmlParserErrors;
        }
    } else {
        ret = XML_ERR_OK;
    }
    if !borrow(& lst).is_none() && ret as u32 == XML_ERR_OK as i32 as u32
    {
        let mut cur: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
        cur = (*(*(*ctxt).myDoc).children).children;
        *(borrow_mut(&mut lst)).unwrap() = cur;
        while !cur.is_null() {
            if (*oldctxt).validate != 0 && (*oldctxt).wellFormed != 0
                && !((*oldctxt).myDoc).is_null()
                && !((*(*oldctxt).myDoc).intSubset).is_null()
                && (*cur).type_0 as u32
                    == XML_ELEMENT_NODE as i32 as u32
            {
                (*oldctxt).valid
                    &= xmlValidateElement(&mut (*oldctxt).vctxt, (*oldctxt).myDoc, cur);
            }
            let fresh556 = &mut ((*cur).parent);
            *fresh556 = 0 as *mut _xmlNode;
            cur = (*cur).next;
        }
        let fresh557 = &mut ((*(*(*ctxt).myDoc).children).children);
        *fresh557 = 0 as *mut _xmlNode;
    }
    if !((*ctxt).myDoc).is_null() {
        xmlFreeNode((*(*ctxt).myDoc).children);
        let fresh558 = &mut ((*(*ctxt).myDoc).children);
        *fresh558 = content;
        let fresh559 = &mut ((*(*ctxt).myDoc).last);
        *fresh559 = last;
    }
    if !oldctxt.is_null() {
        let fresh560 = &mut ((*oldctxt).nbentities);
        *fresh560 = (*fresh560).wrapping_add((*ctxt).nbentities);
    }
    if (*ctxt).lastError.code != XML_ERR_OK as i32 {
        xmlCopyError(&mut (*ctxt).lastError, &mut (*oldctxt).lastError);
    }
    let fresh561 = &mut ((*ctxt).sax);
    *fresh561 = oldsax;
    let fresh562 = &mut ((*ctxt).dict);
    *fresh562 = 0 as xmlDictPtr;
    let fresh563 = &mut ((*ctxt).attsDefault);
    *fresh563 = 0 as xmlHashTablePtr;
    let fresh564 = &mut ((*ctxt).attsSpecial);
    *fresh564 = 0 as xmlHashTablePtr;
    xmlFreeParserCtxt(ctxt);
    if !newDoc.is_null() {
        xmlFreeDoc(newDoc);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseInNodeContext<'a1>(
    mut node: * mut crate::src::HTMLparser::_xmlNode,
    mut data: * const i8,
    mut datalen: i32,
    mut options: i32,
    mut lst: Option<&'a1 mut * mut crate::src::HTMLparser::_xmlNode>,
) -> u32 {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut doc: * mut crate::src::HTMLparser::_xmlDoc = 0 as xmlDocPtr;
    let mut fake: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    let mut cur: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    let mut nsnr: i32 = 0 as i32;
    let mut ret: u32 = XML_ERR_OK;
    if borrow(& lst).is_none() || node.is_null() || data.is_null() || datalen < 0 as i32 {
        return XML_ERR_INTERNAL_ERROR;
    }
    match (*node).type_0 as u32 {
        1 | 2 | 3 | 4 | 5 | 7 | 8 | 9 | 13 => {}
        _ => return XML_ERR_INTERNAL_ERROR,
    }
    while !node.is_null()
        && (*node).type_0 as u32
            != XML_ELEMENT_NODE as i32 as u32
        && (*node).type_0 as u32
            != XML_DOCUMENT_NODE as i32 as u32
        && (*node).type_0 as u32
            != XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        node = (*node).parent;
    }
    if node.is_null() {
        return XML_ERR_INTERNAL_ERROR;
    }
    if (*node).type_0 as u32 == XML_ELEMENT_NODE as i32 as u32
    {
        doc = (*node).doc;
    } else {
        doc = node as xmlDocPtr;
    }
    if doc.is_null() {
        return XML_ERR_INTERNAL_ERROR;
    }
    if (*doc).type_0 as u32 == XML_DOCUMENT_NODE as i32 as u32
    {
        ctxt = xmlCreateMemoryParserCtxt(data as *mut i8, datalen);
    } else if (*doc).type_0 as u32
            == XML_HTML_DOCUMENT_NODE as i32 as u32
        {
        ctxt = htmlCreateMemoryParserCtxt(data as *mut i8, datalen);
        options |= HTML_PARSE_NOIMPLIED as i32;
    } else {
        return XML_ERR_INTERNAL_ERROR
    }
    if ctxt.is_null() {
        return XML_ERR_NO_MEMORY;
    }
    if !((*doc).dict).is_null() {
        if !((*ctxt).dict).is_null() {
            xmlDictFree((*ctxt).dict);
        }
        let fresh565 = &mut ((*ctxt).dict);
        *fresh565 = (*doc).dict;
    } else {
        options |= XML_PARSE_NODICT as i32;
    }
    if !((*doc).encoding).is_null() {
        let mut hdlr: * mut crate::src::HTMLparser::_xmlCharEncodingHandler = 0 as *mut xmlCharEncodingHandler;
        if !((*ctxt).encoding).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).encoding as *mut xmlChar as *mut libc::c_void);
        }
        let fresh566 = &mut ((*ctxt).encoding);
        *fresh566 = xmlStrdup((*doc).encoding);
        hdlr = xmlFindCharEncodingHandler((*doc).encoding as *const i8);
        if !hdlr.is_null() {
            xmlSwitchToEncoding(ctxt, hdlr);
        } else {
            return XML_ERR_UNSUPPORTED_ENCODING
        }
    }
    xmlCtxtUseOptionsInternal(ctxt, options, 0 as *const i8);
    xmlDetectSAX2(ctxt);
    let fresh567 = &mut ((*ctxt).myDoc);
    *fresh567 = doc;
    (*ctxt).input_id = 2 as i32;
    (*ctxt).instate = XML_PARSER_CONTENT;
    fake = xmlNewDocComment((*node).doc, 0 as *const xmlChar);
    if fake.is_null() {
        xmlFreeParserCtxt(ctxt);
        return XML_ERR_NO_MEMORY;
    }
    xmlAddChild(node, fake);
    if (*node).type_0 as u32 == XML_ELEMENT_NODE as i32 as u32
    {
        nodePush(ctxt, node);
        cur = node;
        while !cur.is_null()
            && (*cur).type_0 as u32
                == XML_ELEMENT_NODE as i32 as u32
        {
            let mut ns: * mut crate::src::HTMLparser::_xmlNs = (*cur).nsDef;
            let mut iprefix: * const u8 = 0 as *const xmlChar;
            let mut ihref: * const u8 = 0 as *const xmlChar;
            while !ns.is_null() {
                if !((*ctxt).dict).is_null() {
                    iprefix = xmlDictLookup(
                        (*ctxt).dict,
                        (*ns).prefix,
                        -(1 as i32),
                    );
                    ihref = xmlDictLookup((*ctxt).dict, (*ns).href, -(1 as i32));
                } else {
                    iprefix = (*ns).prefix;
                    ihref = (*ns).href;
                }
                if (xmlGetNamespace(ctxt, iprefix)).is_null() {
                    nsPush(ctxt, iprefix, ihref);
                    nsnr += 1;
                }
                ns = (*ns).next;
            }
            cur = (*cur).parent;
        }
    }
    if (*ctxt).validate != 0 || (*ctxt).replaceEntities != 0 as i32 {
        (*ctxt).loadsubset |= 8 as i32;
    }
    if (*doc).type_0 as u32
        == XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        __htmlParseContent(ctxt as *mut libc::c_void);
    } else {
        xmlParseContent(ctxt);
    }
    nsPop(ctxt, nsnr);
    if *(*(*ctxt).input).cur as i32 == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    } else if *(*(*ctxt).input).cur as i32 != 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const i8);
    }
    if !((*ctxt).node).is_null() && (*ctxt).node != node {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
        (*ctxt).wellFormed = 0 as i32;
    }
    if (*ctxt).wellFormed == 0 {
        if (*ctxt).errNo == 0 as i32 {
            ret = XML_ERR_INTERNAL_ERROR;
        } else {
            ret = (*ctxt).errNo as xmlParserErrors;
        }
    } else {
        ret = XML_ERR_OK;
    }
    cur = (*fake).next;
    let fresh568 = &mut ((*fake).next);
    *fresh568 = 0 as *mut _xmlNode;
    let fresh569 = &mut ((*node).last);
    *fresh569 = fake;
    if !cur.is_null() {
        let fresh570 = &mut ((*cur).prev);
        *fresh570 = 0 as *mut _xmlNode;
    }
    *(borrow_mut(&mut lst)).unwrap() = cur;
    while !cur.is_null() {
        let fresh571 = &mut ((*cur).parent);
        *fresh571 = 0 as *mut _xmlNode;
        cur = (*cur).next;
    }
    xmlUnlinkNode(fake);
    xmlFreeNode(fake);
    if ret as u32 != XML_ERR_OK as i32 as u32 {
        xmlFreeNodeList(*(borrow_mut(&mut lst)).unwrap());
        *(borrow_mut(&mut lst)).unwrap() = 0 as xmlNodePtr;
    }
    if !((*doc).dict).is_null() {
        let fresh572 = &mut ((*ctxt).dict);
        *fresh572 = 0 as xmlDictPtr;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseBalancedChunkMemoryRecover<'a1>(
    mut doc: * mut crate::src::HTMLparser::_xmlDoc,
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut user_data: * mut core::ffi::c_void,
    mut depth: i32,
    mut string: * const u8,
    mut lst: Option<&'a1 mut * mut crate::src::HTMLparser::_xmlNode>,
    mut recover: i32,
) -> i32 {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut newDoc: * mut crate::src::HTMLparser::_xmlDoc = 0 as *mut xmlDoc;
    let mut oldsax: * mut crate::src::HTMLparser::_xmlSAXHandler = 0 as xmlSAXHandlerPtr;
    let mut content: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    let mut newRoot: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    let mut size: i32 = 0;
    let mut ret: i32 = 0 as i32;
    if depth > 40 as i32 {
        return XML_ERR_ENTITY_LOOP as i32;
    }
    if !borrow(& lst).is_none() {
        *(borrow_mut(&mut lst)).unwrap() = 0 as xmlNodePtr;
    }
    if string.is_null() {
        return -(1 as i32);
    }
    size = xmlStrlen(string);
    ctxt = xmlCreateMemoryParserCtxt(string as *mut i8, size);
    if ctxt.is_null() {
        return -(1 as i32);
    }
    let fresh573 = &mut ((*ctxt).userData);
    *fresh573 = ctxt as *mut libc::c_void;
    if !sax.is_null() {
        oldsax = (*ctxt).sax;
        let fresh574 = &mut ((*ctxt).sax);
        *fresh574 = sax;
        if !user_data.is_null() {
            let fresh575 = &mut ((*ctxt).userData);
            *fresh575 = user_data;
        }
    }
    newDoc = xmlNewDoc(b"1.0\0" as *const u8 as *const i8 as *mut xmlChar);
    if newDoc.is_null() {
        xmlFreeParserCtxt(ctxt);
        return -(1 as i32);
    }
    (*newDoc).properties = XML_DOC_INTERNAL as i32;
    if !doc.is_null() && !((*doc).dict).is_null() {
        xmlDictFree((*ctxt).dict);
        let fresh576 = &mut ((*ctxt).dict);
        *fresh576 = (*doc).dict;
        xmlDictReference((*ctxt).dict);
        let fresh577 = &mut ((*ctxt).str_xml);
        *fresh577 = xmlDictLookup(
            (*ctxt).dict,
            b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
            3 as i32,
        );
        let fresh578 = &mut ((*ctxt).str_xmlns);
        *fresh578 = xmlDictLookup(
            (*ctxt).dict,
            b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
            5 as i32,
        );
        let fresh579 = &mut ((*ctxt).str_xml_ns);
        *fresh579 = xmlDictLookup(
            (*ctxt).dict,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                as *const xmlChar,
            36 as i32,
        );
        (*ctxt).dictNames = 1 as i32;
    } else {
        xmlCtxtUseOptionsInternal(
            ctxt,
            XML_PARSE_NODICT as i32,
            0 as *const i8,
        );
    }
    if !doc.is_null() {
        let fresh580 = &mut ((*newDoc).intSubset);
        *fresh580 = (*doc).intSubset;
        let fresh581 = &mut ((*newDoc).extSubset);
        *fresh581 = (*doc).extSubset;
    }
    newRoot = xmlNewDocNode(
        newDoc,
        0 as xmlNsPtr,
        b"pseudoroot\0" as *const u8 as *const i8 as *mut xmlChar,
        0 as *const xmlChar,
    );
    if newRoot.is_null() {
        if !sax.is_null() {
            let fresh582 = &mut ((*ctxt).sax);
            *fresh582 = oldsax;
        }
        xmlFreeParserCtxt(ctxt);
        let fresh583 = &mut ((*newDoc).intSubset);
        *fresh583 = 0 as *mut _xmlDtd;
        let fresh584 = &mut ((*newDoc).extSubset);
        *fresh584 = 0 as *mut _xmlDtd;
        xmlFreeDoc(newDoc);
        return -(1 as i32);
    }
    xmlAddChild(newDoc as xmlNodePtr, newRoot);
    nodePush(ctxt, newRoot);
    if doc.is_null() {
        let fresh585 = &mut ((*ctxt).myDoc);
        *fresh585 = newDoc;
    } else {
        let fresh586 = &mut ((*ctxt).myDoc);
        *fresh586 = newDoc;
        let fresh587 = &mut ((*(*newDoc).children).doc);
        *fresh587 = doc;
        xmlSearchNsByHref(
            doc,
            doc as xmlNodePtr,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                as *const xmlChar,
        );
        let fresh588 = &mut ((*newDoc).oldNs);
        *fresh588 = (*doc).oldNs;
    }
    (*ctxt).instate = XML_PARSER_CONTENT;
    (*ctxt).input_id = 2 as i32;
    (*ctxt).depth = depth;
    (*ctxt).validate = 0 as i32;
    (*ctxt).loadsubset = 0 as i32;
    xmlDetectSAX2(ctxt);
    if !doc.is_null() {
        content = (*doc).children;
        let fresh589 = &mut ((*doc).children);
        *fresh589 = 0 as *mut _xmlNode;
        xmlParseContent(ctxt);
        let fresh590 = &mut ((*doc).children);
        *fresh590 = content;
    } else {
        xmlParseContent(ctxt);
    }
    if *(*(*ctxt).input).cur as i32 == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
            == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    } else if *(*(*ctxt).input).cur as i32 != 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const i8);
    }
    if (*ctxt).node != (*newDoc).children {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    }
    if (*ctxt).wellFormed == 0 {
        if (*ctxt).errNo == 0 as i32 {
            ret = 1 as i32;
        } else {
            ret = (*ctxt).errNo;
        }
    } else {
        ret = 0 as i32;
    }
    if !borrow(& lst).is_none() && (ret == 0 as i32 || recover == 1 as i32) {
        let mut cur: * mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
        cur = (*(*newDoc).children).children;
        *(borrow_mut(&mut lst)).unwrap() = cur;
        while !cur.is_null() {
            xmlSetTreeDoc(cur, doc);
            let fresh591 = &mut ((*cur).parent);
            *fresh591 = 0 as *mut _xmlNode;
            cur = (*cur).next;
        }
        let fresh592 = &mut ((*(*newDoc).children).children);
        *fresh592 = 0 as *mut _xmlNode;
    }
    if !sax.is_null() {
        let fresh593 = &mut ((*ctxt).sax);
        *fresh593 = oldsax;
    }
    xmlFreeParserCtxt(ctxt);
    let fresh594 = &mut ((*newDoc).intSubset);
    *fresh594 = 0 as *mut _xmlDtd;
    let fresh595 = &mut ((*newDoc).extSubset);
    *fresh595 = 0 as *mut _xmlDtd;
    let fresh596 = &mut ((*newDoc).oldNs);
    *fresh596 = 0 as *mut _xmlNs;
    xmlFreeDoc(newDoc);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseEntity(
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut filename: * const i8,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut ret: * mut crate::src::HTMLparser::_xmlDoc = 0 as *mut xmlDoc;
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    ctxt = xmlCreateFileParserCtxt(filename);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        if !((*ctxt).sax).is_null() {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let fresh597 = &mut ((*ctxt).sax);
        *fresh597 = sax;
        let fresh598 = &mut ((*ctxt).userData);
        *fresh598 = 0 as *mut libc::c_void;
    }
    xmlParseExtParsedEnt(ctxt);
    if (*ctxt).wellFormed != 0 {
        ret = (*ctxt).myDoc;
    } else {
        ret = 0 as xmlDocPtr;
        xmlFreeDoc((*ctxt).myDoc);
        let fresh599 = &mut ((*ctxt).myDoc);
        *fresh599 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let fresh600 = &mut ((*ctxt).sax);
        *fresh600 = 0 as *mut _xmlSAXHandler;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEntity(mut filename: * const i8) -> * mut crate::src::HTMLparser::_xmlDoc {
    return xmlSAXParseEntity(0 as xmlSAXHandlerPtr, filename);
}
unsafe extern "C" fn xmlCreateEntityParserCtxtInternal(
    mut URL: * const u8,
    mut ID: * const u8,
    mut base: * const u8,
    mut pctx: * mut crate::src::HTMLparser::_xmlParserCtxt,
) -> * mut crate::src::HTMLparser::_xmlParserCtxt {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut inputStream: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut directory: * mut i8 = 0 as *mut i8;
    let mut uri: * mut u8 = 0 as *mut xmlChar;
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    if !pctx.is_null() {
        (*ctxt).options = (*pctx).options;
        let fresh601 = &mut ((*ctxt)._private);
        *fresh601 = (*pctx)._private;
        (*ctxt).input_id = (*pctx).input_id + 1 as i32;
    }
    if xmlStrcmp(URL, b"-\0" as *const u8 as *const i8 as *mut xmlChar)
        == 0 as i32
    {
        URL = b"./-\0" as *const u8 as *const i8 as *mut xmlChar;
    }
    uri = xmlBuildURI(URL, base);
    if uri.is_null() {
        inputStream = xmlLoadExternalEntity(
            URL as *mut i8,
            ID as *mut i8,
            ctxt,
        );
        if inputStream.is_null() {
            xmlFreeParserCtxt(ctxt);
            return 0 as xmlParserCtxtPtr;
        }
        inputPush(ctxt, inputStream);
        if ((*ctxt).directory).is_null() && directory.is_null() {
            directory = xmlParserGetDirectory(URL as *mut i8);
        }
        if ((*ctxt).directory).is_null() && !directory.is_null() {
            let fresh602 = &mut ((*ctxt).directory);
            *fresh602 = directory;
        }
    } else {
        inputStream = xmlLoadExternalEntity(
            uri as *mut i8,
            ID as *mut i8,
            ctxt,
        );
        if inputStream.is_null() {
            xmlFree.expect("non-null function pointer")(uri as *mut libc::c_void);
            xmlFreeParserCtxt(ctxt);
            return 0 as xmlParserCtxtPtr;
        }
        inputPush(ctxt, inputStream);
        if ((*ctxt).directory).is_null() && directory.is_null() {
            directory = xmlParserGetDirectory(uri as *mut i8);
        }
        if ((*ctxt).directory).is_null() && !directory.is_null() {
            let fresh603 = &mut ((*ctxt).directory);
            *fresh603 = directory;
        }
        xmlFree.expect("non-null function pointer")(uri as *mut libc::c_void);
    }
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateEntityParserCtxt(
    mut URL: * const u8,
    mut ID: * const u8,
    mut base: * const u8,
) -> * mut crate::src::HTMLparser::_xmlParserCtxt {
    return xmlCreateEntityParserCtxtInternal(URL, ID, base, 0 as xmlParserCtxtPtr);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateURLParserCtxt(
    mut filename: * const i8,
    mut options: i32,
) -> * mut crate::src::HTMLparser::_xmlParserCtxt {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut inputStream: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut directory: * mut i8 = 0 as *mut i8;
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"cannot allocate parser context\0" as *const u8 as *const i8,
        );
        return 0 as xmlParserCtxtPtr;
    }
    if options != 0 {
        xmlCtxtUseOptionsInternal(ctxt, options, 0 as *const i8);
    }
    (*ctxt).linenumbers = 1 as i32;
    inputStream = xmlLoadExternalEntity(filename, 0 as *const i8, ctxt);
    if inputStream.is_null() {
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlParserCtxtPtr;
    }
    inputPush(ctxt, inputStream);
    if ((*ctxt).directory).is_null() && directory.is_null() {
        directory = xmlParserGetDirectory(filename);
    }
    if ((*ctxt).directory).is_null() && !directory.is_null() {
        let fresh604 = &mut ((*ctxt).directory);
        *fresh604 = directory;
    }
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateFileParserCtxt(
    mut filename: * const i8,
) -> * mut crate::src::HTMLparser::_xmlParserCtxt {
    return xmlCreateURLParserCtxt(filename, 0 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseFileWithData(
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut filename: * const i8,
    mut recovery: i32,
    mut data: * mut core::ffi::c_void,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut ret: * mut crate::src::HTMLparser::_xmlDoc = 0 as *mut xmlDoc;
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateFileParserCtxt(filename);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        if !((*ctxt).sax).is_null() {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let fresh605 = &mut ((*ctxt).sax);
        *fresh605 = sax;
    }
    xmlDetectSAX2(ctxt);
    if !data.is_null() {
        let fresh606 = &mut ((*ctxt)._private);
        *fresh606 = data;
    }
    if ((*ctxt).directory).is_null() {
        let fresh607 = &mut ((*ctxt).directory);
        *fresh607 = xmlParserGetDirectory(filename);
    }
    (*ctxt).recovery = recovery;
    xmlParseDocument(ctxt);
    if (*ctxt).wellFormed != 0 || recovery != 0 {
        ret = (*ctxt).myDoc;
        if !ret.is_null() && !((*(*ctxt).input).buf).is_null() {
            if (*(*(*ctxt).input).buf).compressed > 0 as i32 {
                (*ret).compression = 9 as i32;
            } else {
                (*ret).compression = (*(*(*ctxt).input).buf).compressed;
            }
        }
    } else {
        ret = 0 as xmlDocPtr;
        xmlFreeDoc((*ctxt).myDoc);
        let fresh608 = &mut ((*ctxt).myDoc);
        *fresh608 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let fresh609 = &mut ((*ctxt).sax);
        *fresh609 = 0 as *mut _xmlSAXHandler;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseFile(
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut filename: * const i8,
    mut recovery: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    return xmlSAXParseFileWithData(sax, filename, recovery, 0 as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlRecoverDoc(mut cur: * const u8) -> * mut crate::src::HTMLparser::_xmlDoc {
    return xmlSAXParseDoc(0 as xmlSAXHandlerPtr, cur, 1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseFile(mut filename: * const i8) -> * mut crate::src::HTMLparser::_xmlDoc {
    return xmlSAXParseFile(0 as xmlSAXHandlerPtr, filename, 0 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlRecoverFile(mut filename: * const i8) -> * mut crate::src::HTMLparser::_xmlDoc {
    return xmlSAXParseFile(0 as xmlSAXHandlerPtr, filename, 1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetupParserForBuffer(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut buffer: * const u8,
    mut filename: * const i8,
) {
    let mut input: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    if ctxt.is_null() || buffer.is_null() {
        return;
    }
    input = xmlNewInputStream(ctxt);
    if input.is_null() {
        xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"parsing new buffer: out of memory\n\0" as *const u8 as *const i8,
        );
        xmlClearParserCtxt(ctxt);
        return;
    }
    xmlClearParserCtxt(ctxt);
    if !filename.is_null() {
        let fresh610 = &mut ((*input).filename);
        *fresh610 = xmlCanonicPath(filename as *const xmlChar) as *mut i8;
    }
    let fresh611 = &mut ((*input).base);
    *fresh611 = buffer;
    let fresh612 = &mut ((*input).cur);
    *fresh612 = buffer;
    let fresh613 = &mut ((*input).end);
    *fresh613 = &*buffer
        .offset(
            (xmlStrlen)(buffer)
                as isize,
        ) as *const xmlChar;
    inputPush(ctxt, input);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXUserParseFile(
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut user_data: * mut core::ffi::c_void,
    mut filename: * const i8,
) -> i32 {
    let mut ret: i32 = 0 as i32;
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    ctxt = xmlCreateFileParserCtxt(filename);
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if (*ctxt).sax != __xmlDefaultSAXHandler() as xmlSAXHandlerPtr {
        xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
    }
    let fresh614 = &mut ((*ctxt).sax);
    *fresh614 = sax;
    xmlDetectSAX2(ctxt);
    if !user_data.is_null() {
        let fresh615 = &mut ((*ctxt).userData);
        *fresh615 = user_data;
    }
    xmlParseDocument(ctxt);
    if (*ctxt).wellFormed != 0 {
        ret = 0 as i32;
    } else if (*ctxt).errNo != 0 as i32 {
        ret = (*ctxt).errNo;
    } else {
        ret = -(1 as i32);
    }
    if !sax.is_null() {
        let fresh616 = &mut ((*ctxt).sax);
        *fresh616 = 0 as *mut _xmlSAXHandler;
    }
    if !((*ctxt).myDoc).is_null() {
        xmlFreeDoc((*ctxt).myDoc);
        let fresh617 = &mut ((*ctxt).myDoc);
        *fresh617 = 0 as xmlDocPtr;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateMemoryParserCtxt(
    mut buffer: * const i8,
    mut size: i32,
) -> * mut crate::src::HTMLparser::_xmlParserCtxt {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut input: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut buf: * mut crate::src::HTMLparser::_xmlParserInputBuffer = 0 as *mut xmlParserInputBuffer;
    if buffer.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    if size <= 0 as i32 {
        return 0 as xmlParserCtxtPtr;
    }
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    buf = xmlParserInputBufferCreateMem(buffer, size, XML_CHAR_ENCODING_NONE);
    if buf.is_null() {
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlParserCtxtPtr;
    }
    input = xmlNewInputStream(ctxt);
    if input.is_null() {
        xmlFreeParserInputBuffer(buf);
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlParserCtxtPtr;
    }
    let fresh618 = &mut ((*input).filename);
    *fresh618 = 0 as *const i8;
    let fresh619 = &mut ((*input).buf);
    *fresh619 = buf;
    xmlBufResetInput((*(*input).buf).buffer, input);
    inputPush(ctxt, input);
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseMemoryWithData(
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut buffer: * const i8,
    mut size: i32,
    mut recovery: i32,
    mut data: * mut core::ffi::c_void,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut ret: * mut crate::src::HTMLparser::_xmlDoc = 0 as *mut xmlDoc;
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        if !((*ctxt).sax).is_null() {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let fresh620 = &mut ((*ctxt).sax);
        *fresh620 = sax;
    }
    xmlDetectSAX2(ctxt);
    if !data.is_null() {
        let fresh621 = &mut ((*ctxt)._private);
        *fresh621 = data;
    }
    (*ctxt).recovery = recovery;
    xmlParseDocument(ctxt);
    if (*ctxt).wellFormed != 0 || recovery != 0 {
        ret = (*ctxt).myDoc;
    } else {
        ret = 0 as xmlDocPtr;
        xmlFreeDoc((*ctxt).myDoc);
        let fresh622 = &mut ((*ctxt).myDoc);
        *fresh622 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let fresh623 = &mut ((*ctxt).sax);
        *fresh623 = 0 as *mut _xmlSAXHandler;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseMemory(
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut buffer: * const i8,
    mut size: i32,
    mut recovery: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    return xmlSAXParseMemoryWithData(
        sax,
        buffer,
        size,
        recovery,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseMemory(
    mut buffer: * const i8,
    mut size: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    return xmlSAXParseMemory(0 as xmlSAXHandlerPtr, buffer, size, 0 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlRecoverMemory(
    mut buffer: * const i8,
    mut size: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    return xmlSAXParseMemory(0 as xmlSAXHandlerPtr, buffer, size, 1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXUserParseMemory(
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut user_data: * mut core::ffi::c_void,
    mut buffer: * const i8,
    mut size: i32,
) -> i32 {
    let mut ret: i32 = 0 as i32;
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if (*ctxt).sax != __xmlDefaultSAXHandler() as xmlSAXHandlerPtr {
        xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
    }
    let fresh624 = &mut ((*ctxt).sax);
    *fresh624 = sax;
    xmlDetectSAX2(ctxt);
    if !user_data.is_null() {
        let fresh625 = &mut ((*ctxt).userData);
        *fresh625 = user_data;
    }
    xmlParseDocument(ctxt);
    if (*ctxt).wellFormed != 0 {
        ret = 0 as i32;
    } else if (*ctxt).errNo != 0 as i32 {
        ret = (*ctxt).errNo;
    } else {
        ret = -(1 as i32);
    }
    if !sax.is_null() {
        let fresh626 = &mut ((*ctxt).sax);
        *fresh626 = 0 as *mut _xmlSAXHandler;
    }
    if !((*ctxt).myDoc).is_null() {
        xmlFreeDoc((*ctxt).myDoc);
        let fresh627 = &mut ((*ctxt).myDoc);
        *fresh627 = 0 as xmlDocPtr;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateDocParserCtxt(
    mut cur: * const u8,
) -> * mut crate::src::HTMLparser::_xmlParserCtxt {
    let mut len: i32 = 0;
    if cur.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    len = xmlStrlen(cur);
    return xmlCreateMemoryParserCtxt(cur as *const i8, len);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseDoc(
    mut sax: * mut crate::src::HTMLparser::_xmlSAXHandler,
    mut cur: * const u8,
    mut recovery: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut ret: * mut crate::src::HTMLparser::_xmlDoc = 0 as *mut xmlDoc;
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut oldsax: * mut crate::src::HTMLparser::_xmlSAXHandler = 0 as xmlSAXHandlerPtr;
    if cur.is_null() {
        return 0 as xmlDocPtr;
    }
    ctxt = xmlCreateDocParserCtxt(cur);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        oldsax = (*ctxt).sax;
        let fresh628 = &mut ((*ctxt).sax);
        *fresh628 = sax;
        let fresh629 = &mut ((*ctxt).userData);
        *fresh629 = 0 as *mut libc::c_void;
    }
    xmlDetectSAX2(ctxt);
    xmlParseDocument(ctxt);
    if (*ctxt).wellFormed != 0 || recovery != 0 {
        ret = (*ctxt).myDoc;
    } else {
        ret = 0 as xmlDocPtr;
        xmlFreeDoc((*ctxt).myDoc);
        let fresh630 = &mut ((*ctxt).myDoc);
        *fresh630 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let fresh631 = &mut ((*ctxt).sax);
        *fresh631 = oldsax;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseDoc(mut cur: * const u8) -> * mut crate::src::HTMLparser::_xmlDoc {
    return xmlSAXParseDoc(0 as xmlSAXHandlerPtr, cur, 0 as i32);
}
static mut xmlEntityRefFunc: Option<unsafe extern "C"  fn(_: * mut crate::src::HTMLparser::_xmlEntity,_: * mut crate::src::HTMLparser::_xmlNode,_: * mut crate::src::HTMLparser::_xmlNode,) -> ()> = None;
unsafe extern "C" fn xmlAddEntityReference(
    mut ent: * mut crate::src::HTMLparser::_xmlEntity,
    mut firstNode: * mut crate::src::HTMLparser::_xmlNode,
    mut lastNode: * mut crate::src::HTMLparser::_xmlNode,
) {
    if xmlEntityRefFunc.is_some() {
        (Some(xmlEntityRefFunc.expect("non-null function pointer")))
            .expect("non-null function pointer")(ent, firstNode, lastNode);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetEntityReferenceFunc(mut func: Option<unsafe extern "C"  fn(_: * mut crate::src::HTMLparser::_xmlEntity,_: * mut crate::src::HTMLparser::_xmlNode,_: * mut crate::src::HTMLparser::_xmlNode,) -> ()>) {
    xmlEntityRefFunc = func;
}
static mut xmlParserInitialized: i32 = 0 as i32;
#[no_mangle]
pub unsafe extern "C" fn xmlInitParser() {
    if xmlParserInitialized != 0 as i32 {
        return;
    }
    __xmlGlobalInitMutexLock();
    if xmlParserInitialized == 0 as i32 {
        xmlInitThreads();
        xmlInitGlobals();
        if (*(borrow(& __xmlGenericError())).unwrap()
            ).map(|f| f as usize) == ( Some(
                xmlGenericErrorDefaultFunc,
            )).map(|f| f as usize) || (*(borrow(& __xmlGenericError())).unwrap()).is_none()
        {
            initGenericErrorDefaultFunc(Option::<&'_ mut Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>>::None);
        }
        xmlInitMemory();
        xmlInitializeDict();
        xmlInitCharEncodingHandlers();
        xmlDefaultSAXHandlerInit();
        xmlRegisterDefaultInputCallbacks();
        xmlRegisterDefaultOutputCallbacks();
        htmlInitAutoClose();
        htmlDefaultSAXHandlerInit();
        xmlXPathInit();
        xmlParserInitialized = 1 as i32;
    }
    __xmlGlobalInitMutexUnlock();
}
#[no_mangle]
pub unsafe extern "C" fn xmlCleanupParser() {
    if xmlParserInitialized == 0 {
        return;
    }
    xmlCleanupCharEncodingHandlers();
    xmlCatalogCleanup();
    xmlDictCleanup();
    xmlCleanupInputCallbacks();
    xmlCleanupOutputCallbacks();
    xmlSchemaCleanupTypes();
    xmlRelaxNGCleanupTypes();
    xmlCleanupGlobals();
    xmlCleanupThreads();
    xmlCleanupMemory();
    xmlParserInitialized = 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtReset(mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt) {
    let mut input: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut dict: * mut crate::src::dict::_xmlDict = 0 as *mut xmlDict;
    if ctxt.is_null() {
        return;
    }
    dict = (*ctxt).dict;
    loop {
        input = inputPop(ctxt);
        if input.is_null() {
            break;
        }
        xmlFreeInputStream(input);
    }
    (*ctxt).inputNr = 0 as i32;
    let fresh632 = &mut ((*ctxt).input);
    *fresh632 = 0 as xmlParserInputPtr;
    (*ctxt).spaceNr = 0 as i32;
    if !((*ctxt).spaceTab).is_null() {
        *((*ctxt).spaceTab).offset(0 as i32 as isize) = -(1 as i32);
        let fresh633 = &mut ((*ctxt).space);
        *fresh633 = &mut *((*ctxt).spaceTab).offset(0 as i32 as isize)
            as *mut i32;
    } else {
        let fresh634 = &mut ((*ctxt).space);
        *fresh634 = 0 as *mut i32;
    }
    (*ctxt).nodeNr = 0 as i32;
    let fresh635 = &mut ((*ctxt).node);
    *fresh635 = 0 as xmlNodePtr;
    (*ctxt).nameNr = 0 as i32;
    let fresh636 = &mut ((*ctxt).name);
    *fresh636 = 0 as *const xmlChar;
    (*ctxt).nsNr = 0 as i32;
    if !((*ctxt).version).is_null()
        && (dict.is_null() || xmlDictOwns(dict, (*ctxt).version) == 0 as i32)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).version as *mut i8 as *mut libc::c_void);
    }
    let fresh637 = &mut ((*ctxt).version);
    *fresh637 = 0 as *const xmlChar;
    if !((*ctxt).encoding).is_null()
        && (dict.is_null() || xmlDictOwns(dict, (*ctxt).encoding) == 0 as i32)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).encoding as *mut i8 as *mut libc::c_void);
    }
    let fresh638 = &mut ((*ctxt).encoding);
    *fresh638 = 0 as *const xmlChar;
    if !((*ctxt).directory).is_null()
        && (dict.is_null()
            || xmlDictOwns(dict, (*ctxt).directory as *const xmlChar)
                == 0 as i32)
    {
        xmlFree
            .expect("non-null function pointer")((*ctxt).directory as *mut libc::c_void);
    }
    let fresh639 = &mut ((*ctxt).directory);
    *fresh639 = 0 as *mut i8;
    if !((*ctxt).extSubURI).is_null()
        && (dict.is_null()
            || xmlDictOwns(dict, (*ctxt).extSubURI as *const xmlChar)
                == 0 as i32)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).extSubURI as *mut i8 as *mut libc::c_void);
    }
    let fresh640 = &mut ((*ctxt).extSubURI);
    *fresh640 = 0 as *mut xmlChar;
    if !((*ctxt).extSubSystem).is_null()
        && (dict.is_null()
            || xmlDictOwns(dict, (*ctxt).extSubSystem as *const xmlChar)
                == 0 as i32)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).extSubSystem as *mut i8 as *mut libc::c_void);
    }
    let fresh641 = &mut ((*ctxt).extSubSystem);
    *fresh641 = 0 as *mut xmlChar;
    if !((*ctxt).myDoc).is_null() {
        xmlFreeDoc((*ctxt).myDoc);
    }
    let fresh642 = &mut ((*ctxt).myDoc);
    *fresh642 = 0 as xmlDocPtr;
    (*ctxt).standalone = -(1 as i32);
    (*ctxt).hasExternalSubset = 0 as i32;
    (*ctxt).hasPErefs = 0 as i32;
    (*ctxt).html = 0 as i32;
    (*ctxt).external = 0 as i32;
    (*ctxt).instate = XML_PARSER_START;
    (*ctxt).token = 0 as i32;
    (*ctxt).wellFormed = 1 as i32;
    (*ctxt).nsWellFormed = 1 as i32;
    (*ctxt).disableSAX = 0 as i32;
    (*ctxt).valid = 1 as i32;
    (*ctxt).record_info = 0 as i32;
    (*ctxt).checkIndex = 0 as i32 as i64;
    (*ctxt).inSubset = 0 as i32;
    (*ctxt).errNo = XML_ERR_OK as i32;
    (*ctxt).depth = 0 as i32;
    (*ctxt).charset = XML_CHAR_ENCODING_UTF8 as i32;
    let fresh643 = &mut ((*ctxt).catalogs);
    *fresh643 = 0 as *mut libc::c_void;
    (*ctxt).nbentities = 0 as i32 as u64;
    (*ctxt).sizeentities = 0 as i32 as u64;
    (*ctxt).sizeentcopy = 0 as i32 as u64;
    xmlInitNodeInfoSeq(Some(&mut (*ctxt).node_seq));
    if !((*ctxt).attsDefault).is_null() {
        xmlHashFree(
            (*ctxt).attsDefault,
            Some(
                xmlHashDefaultDeallocator,
            ),
        );
        let fresh644 = &mut ((*ctxt).attsDefault);
        *fresh644 = 0 as xmlHashTablePtr;
    }
    if !((*ctxt).attsSpecial).is_null() {
        xmlHashFree((*ctxt).attsSpecial, None);
        let fresh645 = &mut ((*ctxt).attsSpecial);
        *fresh645 = 0 as xmlHashTablePtr;
    }
    if !((*ctxt).catalogs).is_null() {
        xmlCatalogFreeLocal((*ctxt).catalogs);
    }
    if (*ctxt).lastError.code != XML_ERR_OK as i32 {
        xmlResetError(&mut (*ctxt).lastError);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtResetPush(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut chunk: * const i8,
    mut size: i32,
    mut filename: * const i8,
    mut encoding: * const i8,
) -> i32 {
    let mut inputStream: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut buf: * mut crate::src::HTMLparser::_xmlParserInputBuffer = 0 as *mut xmlParserInputBuffer;
    let mut enc: i32 = XML_CHAR_ENCODING_NONE;
    if ctxt.is_null() {
        return 1 as i32;
    }
    if encoding.is_null() && !chunk.is_null() && size >= 4 as i32 {
        enc = xmlDetectCharEncoding(chunk as *const xmlChar, size);
    }
    buf = xmlAllocParserInputBuffer(enc);
    if buf.is_null() {
        return 1 as i32;
    }
    if ctxt.is_null() {
        xmlFreeParserInputBuffer(buf);
        return 1 as i32;
    }
    xmlCtxtReset(ctxt);
    if filename.is_null() {
        let fresh646 = &mut ((*ctxt).directory);
        *fresh646 = 0 as *mut i8;
    } else {
        let fresh647 = &mut ((*ctxt).directory);
        *fresh647 = xmlParserGetDirectory(filename);
    }
    inputStream = xmlNewInputStream(ctxt);
    if inputStream.is_null() {
        xmlFreeParserInputBuffer(buf);
        return 1 as i32;
    }
    if filename.is_null() {
        let fresh648 = &mut ((*inputStream).filename);
        *fresh648 = 0 as *const i8;
    } else {
        let fresh649 = &mut ((*inputStream).filename);
        *fresh649 = xmlCanonicPath(filename as *const xmlChar) as *mut i8;
    }
    let fresh650 = &mut ((*inputStream).buf);
    *fresh650 = buf;
    xmlBufResetInput((*buf).buffer, inputStream);
    inputPush(ctxt, inputStream);
    if size > 0 as i32 && !chunk.is_null() && !((*ctxt).input).is_null()
        && !((*(*ctxt).input).buf).is_null()
    {
        let mut base: u64 = xmlBufGetInputBase(
            (*(*(*ctxt).input).buf).buffer,
            (*ctxt).input,
        );
        let mut cur: u64 = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
            as i64 as size_t;
        xmlParserInputBufferPush((*(*ctxt).input).buf, size, chunk);
        xmlBufSetInputBaseCur((*(*(*ctxt).input).buf).buffer, (*ctxt).input, base, cur);
    }
    if !encoding.is_null() {
        let mut hdlr: * mut crate::src::HTMLparser::_xmlCharEncodingHandler = 0 as *mut xmlCharEncodingHandler;
        if !((*ctxt).encoding).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).encoding as *mut xmlChar as *mut libc::c_void);
        }
        let fresh651 = &mut ((*ctxt).encoding);
        *fresh651 = xmlStrdup(encoding as *const xmlChar);
        hdlr = xmlFindCharEncodingHandler(encoding);
        if !hdlr.is_null() {
            xmlSwitchToEncoding(ctxt, hdlr);
        } else {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNSUPPORTED_ENCODING,
                b"Unsupported encoding %s\n\0" as *const u8 as *const i8,
                encoding as *mut xmlChar,
            );
        }
    } else if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
        xmlSwitchEncoding(ctxt, enc);
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlCtxtUseOptionsInternal(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut options: i32,
    mut encoding: * const i8,
) -> i32 {
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if !encoding.is_null() {
        if !((*ctxt).encoding).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).encoding as *mut xmlChar as *mut libc::c_void);
        }
        let fresh652 = &mut ((*ctxt).encoding);
        *fresh652 = xmlStrdup(encoding as *const xmlChar);
    }
    if options & XML_PARSE_RECOVER as i32 != 0 {
        (*ctxt).recovery = 1 as i32;
        options -= XML_PARSE_RECOVER as i32;
        (*ctxt).options |= XML_PARSE_RECOVER as i32;
    } else {
        (*ctxt).recovery = 0 as i32;
    }
    if options & XML_PARSE_DTDLOAD as i32 != 0 {
        (*ctxt).loadsubset = 2 as i32;
        options -= XML_PARSE_DTDLOAD as i32;
        (*ctxt).options |= XML_PARSE_DTDLOAD as i32;
    } else {
        (*ctxt).loadsubset = 0 as i32;
    }
    if options & XML_PARSE_DTDATTR as i32 != 0 {
        (*ctxt).loadsubset |= 4 as i32;
        options -= XML_PARSE_DTDATTR as i32;
        (*ctxt).options |= XML_PARSE_DTDATTR as i32;
    }
    if options & XML_PARSE_NOENT as i32 != 0 {
        (*ctxt).replaceEntities = 1 as i32;
        options -= XML_PARSE_NOENT as i32;
        (*ctxt).options |= XML_PARSE_NOENT as i32;
    } else {
        (*ctxt).replaceEntities = 0 as i32;
    }
    if options & XML_PARSE_PEDANTIC as i32 != 0 {
        (*ctxt).pedantic = 1 as i32;
        options -= XML_PARSE_PEDANTIC as i32;
        (*ctxt).options |= XML_PARSE_PEDANTIC as i32;
    } else {
        (*ctxt).pedantic = 0 as i32;
    }
    if options & XML_PARSE_NOBLANKS as i32 != 0 {
        (*ctxt).keepBlanks = 0 as i32;
        let fresh653 = &mut ((*(*ctxt).sax).ignorableWhitespace);
        *fresh653 = Some(
            xmlSAX2IgnorableWhitespace,
        );
        options -= XML_PARSE_NOBLANKS as i32;
        (*ctxt).options |= XML_PARSE_NOBLANKS as i32;
    } else {
        (*ctxt).keepBlanks = 1 as i32;
    }
    if options & XML_PARSE_DTDVALID as i32 != 0 {
        (*ctxt).validate = 1 as i32;
        if options & XML_PARSE_NOWARNING as i32 != 0 {
            let fresh654 = &mut ((*ctxt).vctxt.warning);
            *fresh654 = None;
        }
        if options & XML_PARSE_NOERROR as i32 != 0 {
            let fresh655 = &mut ((*ctxt).vctxt.error);
            *fresh655 = None;
        }
        options -= XML_PARSE_DTDVALID as i32;
        (*ctxt).options |= XML_PARSE_DTDVALID as i32;
    } else {
        (*ctxt).validate = 0 as i32;
    }
    if options & XML_PARSE_NOWARNING as i32 != 0 {
        let fresh656 = &mut ((*(*ctxt).sax).warning);
        *fresh656 = None;
        options -= XML_PARSE_NOWARNING as i32;
    }
    if options & XML_PARSE_NOERROR as i32 != 0 {
        let fresh657 = &mut ((*(*ctxt).sax).error);
        *fresh657 = None;
        let fresh658 = &mut ((*(*ctxt).sax).fatalError);
        *fresh658 = None;
        options -= XML_PARSE_NOERROR as i32;
    }
    if options & XML_PARSE_SAX1 as i32 != 0 {
        let fresh659 = &mut ((*(*ctxt).sax).startElement);
        *fresh659 = Some(
            xmlSAX2StartElement,
        );
        let fresh660 = &mut ((*(*ctxt).sax).endElement);
        *fresh660 = Some(
            xmlSAX2EndElement,
        );
        let fresh661 = &mut ((*(*ctxt).sax).startElementNs);
        *fresh661 = None;
        let fresh662 = &mut ((*(*ctxt).sax).endElementNs);
        *fresh662 = None;
        (*(*ctxt).sax).initialized = 1 as i32 as u32;
        options -= XML_PARSE_SAX1 as i32;
        (*ctxt).options |= XML_PARSE_SAX1 as i32;
    }
    if options & XML_PARSE_NODICT as i32 != 0 {
        (*ctxt).dictNames = 0 as i32;
        options -= XML_PARSE_NODICT as i32;
        (*ctxt).options |= XML_PARSE_NODICT as i32;
    } else {
        (*ctxt).dictNames = 1 as i32;
    }
    if options & XML_PARSE_NOCDATA as i32 != 0 {
        let fresh663 = &mut ((*(*ctxt).sax).cdataBlock);
        *fresh663 = None;
        options -= XML_PARSE_NOCDATA as i32;
        (*ctxt).options |= XML_PARSE_NOCDATA as i32;
    }
    if options & XML_PARSE_NSCLEAN as i32 != 0 {
        (*ctxt).options |= XML_PARSE_NSCLEAN as i32;
        options -= XML_PARSE_NSCLEAN as i32;
    }
    if options & XML_PARSE_NONET as i32 != 0 {
        (*ctxt).options |= XML_PARSE_NONET as i32;
        options -= XML_PARSE_NONET as i32;
    }
    if options & XML_PARSE_COMPACT as i32 != 0 {
        (*ctxt).options |= XML_PARSE_COMPACT as i32;
        options -= XML_PARSE_COMPACT as i32;
    }
    if options & XML_PARSE_OLD10 as i32 != 0 {
        (*ctxt).options |= XML_PARSE_OLD10 as i32;
        options -= XML_PARSE_OLD10 as i32;
    }
    if options & XML_PARSE_NOBASEFIX as i32 != 0 {
        (*ctxt).options |= XML_PARSE_NOBASEFIX as i32;
        options -= XML_PARSE_NOBASEFIX as i32;
    }
    if options & XML_PARSE_HUGE as i32 != 0 {
        (*ctxt).options |= XML_PARSE_HUGE as i32;
        options -= XML_PARSE_HUGE as i32;
        if !((*ctxt).dict).is_null() {
            xmlDictSetLimit((*ctxt).dict, 0 as i32 as size_t);
        }
    }
    if options & XML_PARSE_OLDSAX as i32 != 0 {
        (*ctxt).options |= XML_PARSE_OLDSAX as i32;
        options -= XML_PARSE_OLDSAX as i32;
    }
    if options & XML_PARSE_IGNORE_ENC as i32 != 0 {
        (*ctxt).options |= XML_PARSE_IGNORE_ENC as i32;
        options -= XML_PARSE_IGNORE_ENC as i32;
    }
    if options & XML_PARSE_BIG_LINES as i32 != 0 {
        (*ctxt).options |= XML_PARSE_BIG_LINES as i32;
        options -= XML_PARSE_BIG_LINES as i32;
    }
    (*ctxt).linenumbers = 1 as i32;
    return options;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtUseOptions(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut options: i32,
) -> i32 {
    return xmlCtxtUseOptionsInternal(ctxt, options, 0 as *const i8);
}
unsafe extern "C" fn xmlDoRead(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut URL: * const i8,
    mut encoding: * const i8,
    mut options: i32,
    mut reuse: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut ret: * mut crate::src::HTMLparser::_xmlDoc = 0 as *mut xmlDoc;
    xmlCtxtUseOptionsInternal(ctxt, options, encoding);
    if !encoding.is_null() {
        let mut hdlr: * mut crate::src::HTMLparser::_xmlCharEncodingHandler = 0 as *mut xmlCharEncodingHandler;
        hdlr = xmlFindCharEncodingHandler(encoding);
        if !hdlr.is_null() {
            xmlSwitchToEncoding(ctxt, hdlr);
        }
    }
    if !URL.is_null() && !((*ctxt).input).is_null()
        && ((*(*ctxt).input).filename).is_null()
    {
        let fresh664 = &mut ((*(*ctxt).input).filename);
        *fresh664 = xmlStrdup(URL as *const xmlChar) as *mut i8;
    }
    xmlParseDocument(ctxt);
    if (*ctxt).wellFormed != 0 || (*ctxt).recovery != 0 {
        ret = (*ctxt).myDoc;
    } else {
        ret = 0 as xmlDocPtr;
        if !((*ctxt).myDoc).is_null() {
            xmlFreeDoc((*ctxt).myDoc);
        }
    }
    let fresh665 = &mut ((*ctxt).myDoc);
    *fresh665 = 0 as xmlDocPtr;
    if reuse == 0 {
        xmlFreeParserCtxt(ctxt);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlReadDoc(
    mut cur: * const u8,
    mut URL: * const i8,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    if cur.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    ctxt = xmlCreateDocParserCtxt(cur);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    return xmlDoRead(ctxt, URL, encoding, options, 0 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlReadFile(
    mut filename: * const i8,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateURLParserCtxt(filename, options);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    return xmlDoRead(
        ctxt,
        0 as *const i8,
        encoding,
        options,
        0 as i32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlReadMemory(
    mut buffer: * const i8,
    mut size: i32,
    mut URL: * const i8,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    return xmlDoRead(ctxt, URL, encoding, options, 0 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlReadFd(
    mut fd: i32,
    mut URL: * const i8,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut input: * mut crate::src::HTMLparser::_xmlParserInputBuffer = 0 as *mut xmlParserInputBuffer;
    let mut stream: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    if fd < 0 as i32 {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    input = xmlParserInputBufferCreateFd(fd, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        return 0 as xmlDocPtr;
    }
    let fresh666 = &mut ((*input).closecallback);
    *fresh666 = None;
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as xmlDocPtr;
    }
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 0 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlReadIO(
    mut ioread: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut i8,_: i32,) -> i32>,
    mut ioclose: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>,
    mut ioctx: * mut core::ffi::c_void,
    mut URL: * const i8,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    let mut input: * mut crate::src::HTMLparser::_xmlParserInputBuffer = 0 as *mut xmlParserInputBuffer;
    let mut stream: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    if ioread.is_none() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    input = xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        if ioclose.is_some() {
            ioclose.expect("non-null function pointer")(ioctx);
        }
        return 0 as xmlDocPtr;
    }
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as xmlDocPtr;
    }
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 0 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtReadDoc(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut cur: * const u8,
    mut URL: * const i8,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut stream: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    if cur.is_null() {
        return 0 as xmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    stream = xmlNewStringInputStream(ctxt, cur);
    if stream.is_null() {
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtReadFile(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut filename: * const i8,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut stream: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    if filename.is_null() {
        return 0 as xmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    stream = xmlLoadExternalEntity(filename, 0 as *const i8, ctxt);
    if stream.is_null() {
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(
        ctxt,
        0 as *const i8,
        encoding,
        options,
        1 as i32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtReadMemory(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut buffer: * const i8,
    mut size: i32,
    mut URL: * const i8,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut input: * mut crate::src::HTMLparser::_xmlParserInputBuffer = 0 as *mut xmlParserInputBuffer;
    let mut stream: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if buffer.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    input = xmlParserInputBufferCreateMem(buffer, size, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        return 0 as xmlDocPtr;
    }
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtReadFd(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut fd: i32,
    mut URL: * const i8,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut input: * mut crate::src::HTMLparser::_xmlParserInputBuffer = 0 as *mut xmlParserInputBuffer;
    let mut stream: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    if fd < 0 as i32 {
        return 0 as xmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    input = xmlParserInputBufferCreateFd(fd, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        return 0 as xmlDocPtr;
    }
    let fresh667 = &mut ((*input).closecallback);
    *fresh667 = None;
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtReadIO(
    mut ctxt: * mut crate::src::HTMLparser::_xmlParserCtxt,
    mut ioread: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut i8,_: i32,) -> i32>,
    mut ioclose: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>,
    mut ioctx: * mut core::ffi::c_void,
    mut URL: * const i8,
    mut encoding: * const i8,
    mut options: i32,
) -> * mut crate::src::HTMLparser::_xmlDoc {
    let mut input: * mut crate::src::HTMLparser::_xmlParserInputBuffer = 0 as *mut xmlParserInputBuffer;
    let mut stream: * mut crate::src::HTMLparser::_xmlParserInput = 0 as *mut xmlParserInput;
    if ioread.is_none() {
        return 0 as xmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    input = xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        if ioclose.is_some() {
            ioclose.expect("non-null function pointer")(ioctx);
        }
        return 0 as xmlDocPtr;
    }
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 1 as i32);
}
use crate::laertes_rt::*;
