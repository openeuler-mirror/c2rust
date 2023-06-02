use :: libc;
extern "C" {
    pub type _xmlBuf;
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlStartTag;
    pub type _xmlAutomataState;
    pub type _xmlAutomata;
    pub type _xmlValidState;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrndup(cur: *const xmlChar, len: i32) -> *mut xmlChar;
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn xmlDictReference(dict: xmlDictPtr) -> i32;
    fn xmlDictFree(dict: xmlDictPtr);
    fn xmlDictLookup(dict: xmlDictPtr, name: *const xmlChar, len: i32) -> *const xmlChar;
    static mut xmlMalloc: xmlMallocFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlFree: xmlFreeFunc;
    fn xmlStringCurrentChar(ctxt: xmlParserCtxtPtr, cur: *const xmlChar, len: *mut i32) -> i32;
    fn xmlCharInRange(val: u32, group: *const xmlChRangeGroup) -> i32;
    static xmlIsBaseCharGroup: xmlChRangeGroup;
    static xmlIsCombiningGroup: xmlChRangeGroup;
    static xmlIsDigitGroup: xmlChRangeGroup;
    static xmlIsExtenderGroup: xmlChRangeGroup;
}
pub type xmlChar = u8;
pub type size_t = u64;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type xmlReallocFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInputBuffer {
    pub context: *mut libc::c_void,
    pub readcallback: xmlInputReadCallback,
    pub closecallback: xmlInputCloseCallback,
    pub encoder: xmlCharEncodingHandlerPtr,
    pub buffer: xmlBufPtr,
    pub raw: xmlBufPtr,
    pub compressed: i32,
    pub error: i32,
    pub rawconsumed: u64,
}
pub type xmlBufPtr = *mut xmlBuf;
pub type xmlBuf = _xmlBuf;
pub type xmlCharEncodingHandlerPtr = *mut xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = _xmlCharEncodingHandler;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlCharEncodingHandler {
    pub name: *mut i8,
    pub input: xmlCharEncodingInputFunc,
    pub output: xmlCharEncodingOutputFunc,
    pub iconv_in: iconv_t,
    pub iconv_out: iconv_t,
}
pub type iconv_t = *mut libc::c_void;
pub type xmlCharEncodingOutputFunc =
    Option<unsafe extern "C" fn(*mut u8, *mut i32, *const u8, *mut i32) -> i32>;
pub type xmlCharEncodingInputFunc =
    Option<unsafe extern "C" fn(*mut u8, *mut i32, *const u8, *mut i32) -> i32>;
pub type xmlInputCloseCallback = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type xmlInputReadCallback =
    Option<unsafe extern "C" fn(*mut libc::c_void, *mut i8, i32) -> i32>;
pub type xmlParserInputBuffer = _xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = *mut xmlParserInputBuffer;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInput {
    pub buf: xmlParserInputBufferPtr,
    pub filename: *const i8,
    pub directory: *const i8,
    pub base: *const xmlChar,
    pub cur: *const xmlChar,
    pub end: *const xmlChar,
    pub length: i32,
    pub line: i32,
    pub col: i32,
    pub consumed: u64,
    pub free: xmlParserInputDeallocate,
    pub encoding: *const xmlChar,
    pub version: *const xmlChar,
    pub standalone: i32,
    pub id: i32,
}
pub type xmlParserInputDeallocate = Option<unsafe extern "C" fn(*mut xmlChar) -> ()>;
pub type xmlParserInput = _xmlParserInput;
pub type xmlParserInputPtr = *mut xmlParserInput;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserCtxt {
    pub sax: *mut _xmlSAXHandler,
    pub userData: *mut libc::c_void,
    pub myDoc: xmlDocPtr,
    pub wellFormed: i32,
    pub replaceEntities: i32,
    pub version: *const xmlChar,
    pub encoding: *const xmlChar,
    pub standalone: i32,
    pub html: i32,
    pub input: xmlParserInputPtr,
    pub inputNr: i32,
    pub inputMax: i32,
    pub inputTab: *mut xmlParserInputPtr,
    pub node: xmlNodePtr,
    pub nodeNr: i32,
    pub nodeMax: i32,
    pub nodeTab: *mut xmlNodePtr,
    pub record_info: i32,
    pub node_seq: xmlParserNodeInfoSeq,
    pub errNo: i32,
    pub hasExternalSubset: i32,
    pub hasPErefs: i32,
    pub external: i32,
    pub valid: i32,
    pub validate: i32,
    pub vctxt: xmlValidCtxt,
    pub instate: xmlParserInputState,
    pub token: i32,
    pub directory: *mut i8,
    pub name: *const xmlChar,
    pub nameNr: i32,
    pub nameMax: i32,
    pub nameTab: *mut *const xmlChar,
    pub nbChars: i64,
    pub checkIndex: i64,
    pub keepBlanks: i32,
    pub disableSAX: i32,
    pub inSubset: i32,
    pub intSubName: *const xmlChar,
    pub extSubURI: *mut xmlChar,
    pub extSubSystem: *mut xmlChar,
    pub space: *mut i32,
    pub spaceNr: i32,
    pub spaceMax: i32,
    pub spaceTab: *mut i32,
    pub depth: i32,
    pub entity: xmlParserInputPtr,
    pub charset: i32,
    pub nodelen: i32,
    pub nodemem: i32,
    pub pedantic: i32,
    pub _private: *mut libc::c_void,
    pub loadsubset: i32,
    pub linenumbers: i32,
    pub catalogs: *mut libc::c_void,
    pub recovery: i32,
    pub progressive: i32,
    pub dict: xmlDictPtr,
    pub atts: *mut *const xmlChar,
    pub maxatts: i32,
    pub docdict: i32,
    pub str_xml: *const xmlChar,
    pub str_xmlns: *const xmlChar,
    pub str_xml_ns: *const xmlChar,
    pub sax2: i32,
    pub nsNr: i32,
    pub nsMax: i32,
    pub nsTab: *mut *const xmlChar,
    pub attallocs: *mut i32,
    pub pushTab: *mut xmlStartTag,
    pub attsDefault: xmlHashTablePtr,
    pub attsSpecial: xmlHashTablePtr,
    pub nsWellFormed: i32,
    pub options: i32,
    pub dictNames: i32,
    pub freeElemsNr: i32,
    pub freeElems: xmlNodePtr,
    pub freeAttrsNr: i32,
    pub freeAttrs: xmlAttrPtr,
    pub lastError: xmlError,
    pub parseMode: xmlParserMode,
    pub nbentities: u64,
    pub sizeentities: u64,
    pub nodeInfo: *mut xmlParserNodeInfo,
    pub nodeInfoNr: i32,
    pub nodeInfoMax: i32,
    pub nodeInfoTab: *mut xmlParserNodeInfo,
    pub input_id: i32,
    pub sizeentcopy: u64,
}
pub type xmlParserNodeInfo = _xmlParserNodeInfo;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserNodeInfo {
    pub node: *const _xmlNode,
    pub begin_pos: u64,
    pub begin_line: u64,
    pub end_pos: u64,
    pub end_line: u64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNode {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlNode,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub ns: *mut xmlNs,
    pub content: *mut xmlChar,
    pub properties: *mut _xmlAttr,
    pub nsDef: *mut xmlNs,
    pub psvi: *mut libc::c_void,
    pub line: u16,
    pub extra: u16,
}
pub type xmlNs = _xmlNs;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNs {
    pub next: *mut _xmlNs,
    pub type_0: xmlNsType,
    pub href: *const xmlChar,
    pub prefix: *const xmlChar,
    pub _private: *mut libc::c_void,
    pub context: *mut _xmlDoc,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDoc {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *mut i8,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlNode,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub compression: i32,
    pub standalone: i32,
    pub intSubset: *mut _xmlDtd,
    pub extSubset: *mut _xmlDtd,
    pub oldNs: *mut _xmlNs,
    pub version: *const xmlChar,
    pub encoding: *const xmlChar,
    pub ids: *mut libc::c_void,
    pub refs: *mut libc::c_void,
    pub URL: *const xmlChar,
    pub charset: i32,
    pub dict: *mut _xmlDict,
    pub psvi: *mut libc::c_void,
    pub parseFlags: i32,
    pub properties: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDtd {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlDoc,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub notations: *mut libc::c_void,
    pub elements: *mut libc::c_void,
    pub attributes: *mut libc::c_void,
    pub entities: *mut libc::c_void,
    pub ExternalID: *const xmlChar,
    pub SystemID: *const xmlChar,
    pub pentities: *mut libc::c_void,
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
pub type xmlNsType = xmlElementType;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlAttr {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlNode,
    pub next: *mut _xmlAttr,
    pub prev: *mut _xmlAttr,
    pub doc: *mut _xmlDoc,
    pub ns: *mut xmlNs,
    pub atype: xmlAttributeType,
    pub psvi: *mut libc::c_void,
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
pub type xmlParserMode = u32;
pub const XML_PARSE_READER: xmlParserMode = 5;
pub const XML_PARSE_PUSH_SAX: xmlParserMode = 4;
pub const XML_PARSE_PUSH_DOM: xmlParserMode = 3;
pub const XML_PARSE_SAX: xmlParserMode = 2;
pub const XML_PARSE_DOM: xmlParserMode = 1;
pub const XML_PARSE_UNKNOWN: xmlParserMode = 0;
pub type xmlError = _xmlError;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlError {
    pub domain: i32,
    pub code: i32,
    pub message: *mut i8,
    pub level: xmlErrorLevel,
    pub file: *mut i8,
    pub line: i32,
    pub str1: *mut i8,
    pub str2: *mut i8,
    pub str3: *mut i8,
    pub int1: i32,
    pub int2: i32,
    pub ctxt: *mut libc::c_void,
    pub node: *mut libc::c_void,
}
pub type xmlErrorLevel = u32;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlAttrPtr = *mut xmlAttr;
pub type xmlAttr = _xmlAttr;
pub type xmlNodePtr = *mut xmlNode;
pub type xmlNode = _xmlNode;
pub type xmlHashTablePtr = *mut xmlHashTable;
pub type xmlHashTable = _xmlHashTable;
pub type xmlStartTag = _xmlStartTag;
pub type xmlDictPtr = *mut xmlDict;
pub type xmlDict = _xmlDict;
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
pub type xmlValidCtxt = _xmlValidCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlValidCtxt {
    pub userData: *mut libc::c_void,
    pub error: xmlValidityErrorFunc,
    pub warning: xmlValidityWarningFunc,
    pub node: xmlNodePtr,
    pub nodeNr: i32,
    pub nodeMax: i32,
    pub nodeTab: *mut xmlNodePtr,
    pub flags: u32,
    pub doc: xmlDocPtr,
    pub valid: i32,
    pub vstate: *mut xmlValidState,
    pub vstateNr: i32,
    pub vstateMax: i32,
    pub vstateTab: *mut xmlValidState,
    pub am: xmlAutomataPtr,
    pub state: xmlAutomataStatePtr,
}
pub type xmlAutomataStatePtr = *mut xmlAutomataState;
pub type xmlAutomataState = _xmlAutomataState;
pub type xmlAutomataPtr = *mut xmlAutomata;
pub type xmlAutomata = _xmlAutomata;
pub type xmlValidState = _xmlValidState;
pub type xmlDocPtr = *mut xmlDoc;
pub type xmlDoc = _xmlDoc;
pub type xmlValidityWarningFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type xmlValidityErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type xmlParserNodeInfoSeq = _xmlParserNodeInfoSeq;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserNodeInfoSeq {
    pub maximum: u64,
    pub length: u64,
    pub buffer: *mut xmlParserNodeInfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXHandler {
    pub internalSubset: internalSubsetSAXFunc,
    pub isStandalone: isStandaloneSAXFunc,
    pub hasInternalSubset: hasInternalSubsetSAXFunc,
    pub hasExternalSubset: hasExternalSubsetSAXFunc,
    pub resolveEntity: resolveEntitySAXFunc,
    pub getEntity: getEntitySAXFunc,
    pub entityDecl: entityDeclSAXFunc,
    pub notationDecl: notationDeclSAXFunc,
    pub attributeDecl: attributeDeclSAXFunc,
    pub elementDecl: elementDeclSAXFunc,
    pub unparsedEntityDecl: unparsedEntityDeclSAXFunc,
    pub setDocumentLocator: setDocumentLocatorSAXFunc,
    pub startDocument: startDocumentSAXFunc,
    pub endDocument: endDocumentSAXFunc,
    pub startElement: startElementSAXFunc,
    pub endElement: endElementSAXFunc,
    pub reference: referenceSAXFunc,
    pub characters: charactersSAXFunc,
    pub ignorableWhitespace: ignorableWhitespaceSAXFunc,
    pub processingInstruction: processingInstructionSAXFunc,
    pub comment: commentSAXFunc,
    pub warning: warningSAXFunc,
    pub error: errorSAXFunc,
    pub fatalError: fatalErrorSAXFunc,
    pub getParameterEntity: getParameterEntitySAXFunc,
    pub cdataBlock: cdataBlockSAXFunc,
    pub externalSubset: externalSubsetSAXFunc,
    pub initialized: u32,
    pub _private: *mut libc::c_void,
    pub startElementNs: startElementNsSAX2Func,
    pub endElementNs: endElementNsSAX2Func,
    pub serror: xmlStructuredErrorFunc,
}
pub type xmlStructuredErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> ()>;
pub type xmlErrorPtr = *mut xmlError;
pub type endElementNsSAX2Func = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
pub type startElementNsSAX2Func = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
        i32,
        *mut *const xmlChar,
        i32,
        i32,
        *mut *const xmlChar,
    ) -> (),
>;
pub type externalSubsetSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
pub type cdataBlockSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> ()>;
pub type getParameterEntitySAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr>;
pub type xmlEntityPtr = *mut xmlEntity;
pub type xmlEntity = _xmlEntity;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlEntity {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlDtd,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub orig: *mut xmlChar,
    pub content: *mut xmlChar,
    pub length: i32,
    pub etype: xmlEntityType,
    pub ExternalID: *const xmlChar,
    pub SystemID: *const xmlChar,
    pub nexte: *mut _xmlEntity,
    pub URI: *const xmlChar,
    pub owner: i32,
    pub checked: i32,
}
pub type xmlEntityType = u32;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type errorSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type warningSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type commentSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type processingInstructionSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> ()>;
pub type ignorableWhitespaceSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> ()>;
pub type charactersSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> ()>;
pub type referenceSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type endElementSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type startElementSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *mut *const xmlChar) -> ()>;
pub type endDocumentSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type startDocumentSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type setDocumentLocatorSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> ()>;
pub type xmlSAXLocatorPtr = *mut xmlSAXLocator;
pub type xmlSAXLocator = _xmlSAXLocator;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXLocator {
    pub getPublicId: Option<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getSystemId: Option<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getLineNumber: Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>,
    pub getColumnNumber: Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>,
}
pub type unparsedEntityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type elementDeclSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32, xmlElementContentPtr) -> (),
>;
pub type xmlElementContentPtr = *mut xmlElementContent;
pub type xmlElementContent = _xmlElementContent;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlElementContent {
    pub type_0: xmlElementContentType,
    pub ocur: xmlElementContentOccur,
    pub name: *const xmlChar,
    pub c1: *mut _xmlElementContent,
    pub c2: *mut _xmlElementContent,
    pub parent: *mut _xmlElementContent,
    pub prefix: *const xmlChar,
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
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        i32,
        i32,
        *const xmlChar,
        xmlEnumerationPtr,
    ) -> (),
>;
pub type xmlEnumerationPtr = *mut xmlEnumeration;
pub type xmlEnumeration = _xmlEnumeration;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlEnumeration {
    pub next: *mut _xmlEnumeration,
    pub name: *const xmlChar,
}
pub type notationDeclSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
pub type entityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        i32,
        *const xmlChar,
        *const xmlChar,
        *mut xmlChar,
    ) -> (),
>;
pub type getEntitySAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr>;
pub type resolveEntitySAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> xmlParserInputPtr,
>;
pub type hasExternalSubsetSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type hasInternalSubsetSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type isStandaloneSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type internalSubsetSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
pub type xmlParserCtxt = _xmlParserCtxt;
pub type xmlParserCtxtPtr = *mut xmlParserCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChSRange {
    pub low: u16,
    pub high: u16,
}
pub type xmlChSRange = _xmlChSRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChLRange {
    pub low: u32,
    pub high: u32,
}
pub type xmlChLRange = _xmlChLRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChRangeGroup {
    pub nbShortRange: i32,
    pub nbLongRange: i32,
    pub shortRange: *const xmlChSRange,
    pub longRange: *const xmlChLRange,
}
pub type xmlChRangeGroup = _xmlChRangeGroup;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlPattern {
    pub data: *mut libc::c_void,
    pub dict: xmlDictPtr,
    pub next: *mut _xmlPattern,
    pub pattern: *const xmlChar,
    pub flags: i32,
    pub nbStep: i32,
    pub maxStep: i32,
    pub steps: xmlStepOpPtr,
    pub stream: xmlStreamCompPtr,
}
pub type xmlStreamCompPtr = *mut xmlStreamComp;
pub type xmlStreamComp = _xmlStreamComp;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStreamComp {
    pub dict: *mut xmlDict,
    pub nbStep: i32,
    pub maxStep: i32,
    pub steps: xmlStreamStepPtr,
    pub flags: i32,
}
pub type xmlStreamStepPtr = *mut xmlStreamStep;
pub type xmlStreamStep = _xmlStreamStep;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStreamStep {
    pub flags: i32,
    pub name: *const xmlChar,
    pub ns: *const xmlChar,
    pub nodeType: i32,
}
pub type xmlStepOpPtr = *mut xmlStepOp;
pub type xmlStepOp = _xmlStepOp;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStepOp {
    pub op: xmlPatOp,
    pub value: *const xmlChar,
    pub value2: *const xmlChar,
}
pub type xmlPatOp = u32;
pub const XML_OP_ALL: xmlPatOp = 8;
pub const XML_OP_NS: xmlPatOp = 7;
pub const XML_OP_ANCESTOR: xmlPatOp = 6;
pub const XML_OP_PARENT: xmlPatOp = 5;
pub const XML_OP_ATTR: xmlPatOp = 4;
pub const XML_OP_CHILD: xmlPatOp = 3;
pub const XML_OP_ELEM: xmlPatOp = 2;
pub const XML_OP_ROOT: xmlPatOp = 1;
pub const XML_OP_END: xmlPatOp = 0;
pub type xmlPattern = _xmlPattern;
pub type xmlPatternPtr = *mut xmlPattern;
pub type C2RustUnnamed = u32;
pub const XML_PATTERN_XSFIELD: C2RustUnnamed = 4;
pub const XML_PATTERN_XSSEL: C2RustUnnamed = 2;
pub const XML_PATTERN_XPATH: C2RustUnnamed = 1;
pub const XML_PATTERN_DEFAULT: C2RustUnnamed = 0;
pub type xmlPatParserContextPtr = *mut xmlPatParserContext;
pub type xmlPatParserContext = _xmlPatParserContext;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlPatParserContext {
    pub cur: *const xmlChar,
    pub base: *const xmlChar,
    pub error: i32,
    pub dict: xmlDictPtr,
    pub comp: xmlPatternPtr,
    pub elem: xmlNodePtr,
    pub namespaces: *mut *const xmlChar,
    pub nb_namespaces: i32,
}
pub type xmlStepStatePtr = *mut xmlStepState;
pub type xmlStepState = _xmlStepState;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStepState {
    pub step: i32,
    pub node: xmlNodePtr,
}
pub type xmlStepStates = _xmlStepStates;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStepStates {
    pub nbstates: i32,
    pub maxstates: i32,
    pub states: xmlStepStatePtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStreamCtxt {
    pub next: *mut _xmlStreamCtxt,
    pub comp: xmlStreamCompPtr,
    pub nbState: i32,
    pub maxState: i32,
    pub level: i32,
    pub states: *mut i32,
    pub flags: i32,
    pub blockLevel: i32,
}
pub type xmlStreamCtxt = _xmlStreamCtxt;
pub type xmlStreamCtxtPtr = *mut xmlStreamCtxt;
extern "C" fn xmlNewPattern() -> xmlPatternPtr {
    let mut cur: xmlPatternPtr = 0 as *mut xmlPattern;
    cur = (unsafe { xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlPattern>() as u64) })
        as xmlPatternPtr;
    if cur.is_null() {
        return 0 as xmlPatternPtr;
    }
    (unsafe { memset(
        cur as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlPattern>() as u64,
    ) });
    (unsafe { (*cur).maxStep = 10 as i32 });
    let fresh0 = unsafe { &mut ((*cur).steps) };
    *fresh0 = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ((*cur).maxStep as u64).wrapping_mul(::std::mem::size_of::<xmlStepOp>() as u64),
    ) }) as xmlStepOpPtr;
    if (unsafe { (*cur).steps }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
        return 0 as xmlPatternPtr;
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlFreePattern(mut comp: xmlPatternPtr) {
    xmlFreePatternList(comp);
}
extern "C" fn xmlFreePatternInternal(mut comp: xmlPatternPtr) {
    let mut op: xmlStepOpPtr = 0 as *mut xmlStepOp;
    let mut i: i32 = 0;
    if comp.is_null() {
        return;
    }
    if !(unsafe { (*comp).stream }).is_null() {
        xmlFreeStreamComp(unsafe { (*comp).stream });
    }
    if !(unsafe { (*comp).pattern }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(
            (*comp).pattern as *mut xmlChar as *mut libc::c_void,
        ) });
    }
    if !(unsafe { (*comp).steps }).is_null() {
        if (unsafe { (*comp).dict }).is_null() {
            i = 0 as i32;
            while i < (unsafe { (*comp).nbStep }) {
                op = (unsafe { &mut *((*comp).steps).offset(i as isize) }) as *mut xmlStepOp;
                if !(unsafe { (*op).value }).is_null() {
                    (unsafe { xmlFree.expect("non-null function pointer")(
                        (*op).value as *mut xmlChar as *mut libc::c_void,
                    ) });
                }
                if !(unsafe { (*op).value2 }).is_null() {
                    (unsafe { xmlFree.expect("non-null function pointer")(
                        (*op).value2 as *mut xmlChar as *mut libc::c_void,
                    ) });
                }
                i += 1;
            }
        }
        (unsafe { xmlFree.expect("non-null function pointer")((*comp).steps as *mut libc::c_void) });
    }
    if !(unsafe { (*comp).dict }).is_null() {
        (unsafe { xmlDictFree((*comp).dict) });
    }
    (unsafe { memset(
        comp as *mut libc::c_void,
        -(1 as i32),
        ::std::mem::size_of::<xmlPattern>() as u64,
    ) });
    (unsafe { xmlFree.expect("non-null function pointer")(comp as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlFreePatternList(mut comp: xmlPatternPtr) {
    let mut cur: xmlPatternPtr = 0 as *mut xmlPattern;
    while !comp.is_null() {
        cur = comp;
        comp = unsafe { (*comp).next };
        let fresh1 = unsafe { &mut ((*cur).next) };
        *fresh1 = 0 as *mut _xmlPattern;
        xmlFreePatternInternal(cur);
    }
}
extern "C" fn xmlNewPatParserContext(
    mut pattern: *const xmlChar,
    mut dict: xmlDictPtr,
    mut namespaces: *mut *const xmlChar,
) -> xmlPatParserContextPtr {
    let mut cur: xmlPatParserContextPtr = 0 as *mut xmlPatParserContext;
    if pattern.is_null() {
        return 0 as xmlPatParserContextPtr;
    }
    cur = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlPatParserContext>() as u64,
    ) }) as xmlPatParserContextPtr;
    if cur.is_null() {
        return 0 as xmlPatParserContextPtr;
    }
    (unsafe { memset(
        cur as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlPatParserContext>() as u64,
    ) });
    let fresh2 = unsafe { &mut ((*cur).dict) };
    *fresh2 = dict;
    let fresh3 = unsafe { &mut ((*cur).cur) };
    *fresh3 = pattern;
    let fresh4 = unsafe { &mut ((*cur).base) };
    *fresh4 = pattern;
    if !namespaces.is_null() {
        let mut i: i32 = 0;
        i = 0 as i32;
        while !(unsafe { *namespaces.offset((2 as i32 * i) as isize) }).is_null() {
            i += 1;
        }
        (unsafe { (*cur).nb_namespaces = i });
    } else {
        (unsafe { (*cur).nb_namespaces = 0 as i32 });
    }
    let fresh5 = unsafe { &mut ((*cur).namespaces) };
    *fresh5 = namespaces;
    return cur;
}
extern "C" fn xmlFreePatParserContext(mut ctxt: xmlPatParserContextPtr) {
    if ctxt.is_null() {
        return;
    }
    (unsafe { memset(
        ctxt as *mut libc::c_void,
        -(1 as i32),
        ::std::mem::size_of::<xmlPatParserContext>() as u64,
    ) });
    (unsafe { xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void) });
}
extern "C" fn xmlPatternAdd(
    mut _ctxt: xmlPatParserContextPtr,
    mut comp: xmlPatternPtr,
    mut op: xmlPatOp,
    mut value: *mut xmlChar,
    mut value2: *mut xmlChar,
) -> i32 {
    if (unsafe { (*comp).nbStep }) >= (unsafe { (*comp).maxStep }) {
        let mut temp: xmlStepOpPtr = 0 as *mut xmlStepOp;
        temp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*comp).steps as *mut libc::c_void,
            (((*comp).maxStep * 2 as i32) as u64)
                .wrapping_mul(::std::mem::size_of::<xmlStepOp>() as u64),
        ) }) as xmlStepOpPtr;
        if temp.is_null() {
            return -(1 as i32);
        }
        let fresh6 = unsafe { &mut ((*comp).steps) };
        *fresh6 = temp;
        (unsafe { (*comp).maxStep *= 2 as i32 });
    }
    (unsafe { (*((*comp).steps).offset((*comp).nbStep as isize)).op = op });
    let fresh7 = unsafe { &mut ((*((*comp).steps).offset((*comp).nbStep as isize)).value) };
    *fresh7 = value;
    let fresh8 = unsafe { &mut ((*((*comp).steps).offset((*comp).nbStep as isize)).value2) };
    *fresh8 = value2;
    let fresh9 = unsafe { &mut ((*comp).nbStep) };
    *fresh9 += 1;
    return 0 as i32;
}
extern "C" fn xmlReversePattern(mut comp: xmlPatternPtr) -> i32 {
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    if (unsafe { (*comp).nbStep }) > 0 as i32
        && (unsafe { (*((*comp).steps).offset(0 as i32 as isize)).op }) as u32 == XML_OP_ANCESTOR as i32 as u32
    {
        i = 0 as i32;
        j = 1 as i32;
        while j < (unsafe { (*comp).nbStep }) {
            let fresh10 = unsafe { &mut ((*((*comp).steps).offset(i as isize)).value) };
            *fresh10 = unsafe { (*((*comp).steps).offset(j as isize)).value };
            let fresh11 = unsafe { &mut ((*((*comp).steps).offset(i as isize)).value2) };
            *fresh11 = unsafe { (*((*comp).steps).offset(j as isize)).value2 };
            (unsafe { (*((*comp).steps).offset(i as isize)).op = (*((*comp).steps).offset(j as isize)).op });
            i += 1;
            j += 1;
        }
        let fresh12 = unsafe { &mut ((*comp).nbStep) };
        *fresh12 -= 1;
    }
    if (unsafe { (*comp).nbStep }) >= (unsafe { (*comp).maxStep }) {
        let mut temp: xmlStepOpPtr = 0 as *mut xmlStepOp;
        temp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*comp).steps as *mut libc::c_void,
            (((*comp).maxStep * 2 as i32) as u64)
                .wrapping_mul(::std::mem::size_of::<xmlStepOp>() as u64),
        ) }) as xmlStepOpPtr;
        if temp.is_null() {
            return -(1 as i32);
        }
        let fresh13 = unsafe { &mut ((*comp).steps) };
        *fresh13 = temp;
        (unsafe { (*comp).maxStep *= 2 as i32 });
    }
    i = 0 as i32;
    j = (unsafe { (*comp).nbStep }) - 1 as i32;
    while j > i {
        let mut tmp: *const xmlChar = 0 as *const xmlChar;
        let mut op: xmlPatOp = XML_OP_END;
        tmp = unsafe { (*((*comp).steps).offset(i as isize)).value };
        let fresh14 = unsafe { &mut ((*((*comp).steps).offset(i as isize)).value) };
        *fresh14 = unsafe { (*((*comp).steps).offset(j as isize)).value };
        let fresh15 = unsafe { &mut ((*((*comp).steps).offset(j as isize)).value) };
        *fresh15 = tmp;
        tmp = unsafe { (*((*comp).steps).offset(i as isize)).value2 };
        let fresh16 = unsafe { &mut ((*((*comp).steps).offset(i as isize)).value2) };
        *fresh16 = unsafe { (*((*comp).steps).offset(j as isize)).value2 };
        let fresh17 = unsafe { &mut ((*((*comp).steps).offset(j as isize)).value2) };
        *fresh17 = tmp;
        op = unsafe { (*((*comp).steps).offset(i as isize)).op };
        (unsafe { (*((*comp).steps).offset(i as isize)).op = (*((*comp).steps).offset(j as isize)).op });
        (unsafe { (*((*comp).steps).offset(j as isize)).op = op });
        j -= 1;
        i += 1;
    }
    let fresh18 = unsafe { &mut ((*((*comp).steps).offset((*comp).nbStep as isize)).value) };
    *fresh18 = 0 as *const xmlChar;
    let fresh19 = unsafe { &mut ((*((*comp).steps).offset((*comp).nbStep as isize)).value2) };
    *fresh19 = 0 as *const xmlChar;
    let fresh20 = unsafe { &mut ((*comp).nbStep) };
    let fresh21 = *fresh20;
    *fresh20 = *fresh20 + 1;
    (unsafe { (*((*comp).steps).offset(fresh21 as isize)).op = XML_OP_END });
    return 0 as i32;
}
extern "C" fn xmlPatPushState(
    mut states: *mut xmlStepStates,
    mut step: i32,
    mut node: xmlNodePtr,
) -> i32 {
    if (unsafe { (*states).states }).is_null() || (unsafe { (*states).maxstates }) <= 0 as i32 {
        (unsafe { (*states).maxstates = 4 as i32 });
        (unsafe { (*states).nbstates = 0 as i32 });
        let fresh22 = unsafe { &mut ((*states).states) };
        *fresh22 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            (4 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlStepState>() as u64),
        ) }) as xmlStepStatePtr;
    } else if (unsafe { (*states).maxstates }) <= (unsafe { (*states).nbstates }) {
        let mut tmp: *mut xmlStepState = 0 as *mut xmlStepState;
        tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*states).states as *mut libc::c_void,
            ((2 as i32 * (*states).maxstates) as u64)
                .wrapping_mul(::std::mem::size_of::<xmlStepState>() as u64),
        ) }) as xmlStepStatePtr;
        if tmp.is_null() {
            return -(1 as i32);
        }
        let fresh23 = unsafe { &mut ((*states).states) };
        *fresh23 = tmp;
        (unsafe { (*states).maxstates *= 2 as i32 });
    }
    (unsafe { (*((*states).states).offset((*states).nbstates as isize)).step = step });
    let fresh24 = unsafe { &mut ((*states).nbstates) };
    let fresh25 = *fresh24;
    *fresh24 = *fresh24 + 1;
    let fresh26 = unsafe { &mut ((*((*states).states).offset(fresh25 as isize)).node) };
    *fresh26 = node;
    return 0 as i32;
}
extern "C" fn xmlPatMatch(mut comp: xmlPatternPtr, mut node: xmlNodePtr) -> i32 {
    let mut current_block: u64;
    let mut i: i32 = 0;
    let mut step: xmlStepOpPtr = 0 as *mut xmlStepOp;
    let mut states: xmlStepStates = {
        let mut init = _xmlStepStates {
            nbstates: 0 as i32,
            maxstates: 0 as i32,
            states: 0 as xmlStepStatePtr,
        };
        init
    };
    if comp.is_null() || node.is_null() {
        return -(1 as i32);
    }
    i = 0 as i32;
    while i < (unsafe { (*comp).nbStep }) {
        step = (unsafe { &mut *((*comp).steps).offset(i as isize) }) as *mut xmlStepOp;
        match (unsafe { (*step).op }) as u32 {
            0 => {
                break;
            }
            1 => {
                if (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
                    current_block = 6451473480150109090;
                } else {
                    node = unsafe { (*node).parent };
                    if (unsafe { (*node).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
                        || (unsafe { (*node).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32
                    {
                        current_block = 820271813250567934;
                    } else {
                        current_block = 6451473480150109090;
                    }
                }
            }
            2 => {
                if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
                    current_block = 6451473480150109090;
                } else if (unsafe { (*step).value }).is_null() {
                    current_block = 820271813250567934;
                } else if (unsafe { *((*step).value).offset(0 as i32 as isize) }) as i32
                    != (unsafe { *((*node).name).offset(0 as i32 as isize) }) as i32
                {
                    current_block = 6451473480150109090;
                } else if (unsafe { xmlStrEqual((*step).value, (*node).name) }) == 0 {
                    current_block = 6451473480150109090;
                } else if (unsafe { (*node).ns }).is_null() {
                    if !(unsafe { (*step).value2 }).is_null() {
                        current_block = 6451473480150109090;
                    } else {
                        current_block = 820271813250567934;
                    }
                } else if !(unsafe { (*(*node).ns).href }).is_null() {
                    if (unsafe { (*step).value2 }).is_null() {
                        current_block = 6451473480150109090;
                    } else if (unsafe { xmlStrEqual((*step).value2, (*(*node).ns).href) }) == 0 {
                        current_block = 6451473480150109090;
                    } else {
                        current_block = 820271813250567934;
                    }
                } else {
                    current_block = 820271813250567934;
                }
            }
            3 => {
                let mut lst: xmlNodePtr = 0 as *mut xmlNode;
                if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
                    && (unsafe { (*node).type_0 }) as u32 != XML_DOCUMENT_NODE as i32 as u32
                    && (unsafe { (*node).type_0 }) as u32 != XML_HTML_DOCUMENT_NODE as i32 as u32
                {
                    current_block = 6451473480150109090;
                } else {
                    lst = unsafe { (*node).children };
                    if !(unsafe { (*step).value }).is_null() {
                        while !lst.is_null() {
                            if (unsafe { (*lst).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                                && (unsafe { *((*step).value).offset(0 as i32 as isize) }) as i32
                                    == (unsafe { *((*lst).name).offset(0 as i32 as isize) }) as i32
                                && (unsafe { xmlStrEqual((*step).value, (*lst).name) }) != 0
                            {
                                break;
                            }
                            lst = unsafe { (*lst).next };
                        }
                        if !lst.is_null() {
                            current_block = 820271813250567934;
                        } else {
                            current_block = 6451473480150109090;
                        }
                    } else {
                        current_block = 6451473480150109090;
                    }
                }
            }
            4 => {
                if (unsafe { (*node).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32 {
                    current_block = 6451473480150109090;
                } else {
                    if !(unsafe { (*step).value }).is_null() {
                        if (unsafe { *((*step).value).offset(0 as i32 as isize) }) as i32
                            != (unsafe { *((*node).name).offset(0 as i32 as isize) }) as i32
                        {
                            current_block = 6451473480150109090;
                        } else if (unsafe { xmlStrEqual((*step).value, (*node).name) }) == 0 {
                            current_block = 6451473480150109090;
                        } else {
                            current_block = 6450597802325118133;
                        }
                    } else {
                        current_block = 6450597802325118133;
                    }
                    match current_block {
                        6451473480150109090 => {}
                        _ => {
                            if (unsafe { (*node).ns }).is_null() {
                                if !(unsafe { (*step).value2 }).is_null() {
                                    current_block = 6451473480150109090;
                                } else {
                                    current_block = 820271813250567934;
                                }
                            } else if !(unsafe { (*step).value2 }).is_null() {
                                if (unsafe { xmlStrEqual((*step).value2, (*(*node).ns).href) }) == 0 {
                                    current_block = 6451473480150109090;
                                } else {
                                    current_block = 820271813250567934;
                                }
                            } else {
                                current_block = 820271813250567934;
                            }
                        }
                    }
                }
            }
            5 => {
                if (unsafe { (*node).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
                    || (unsafe { (*node).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32
                    || (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
                {
                    current_block = 6451473480150109090;
                } else {
                    node = unsafe { (*node).parent };
                    if node.is_null() {
                        current_block = 6451473480150109090;
                    } else if (unsafe { (*step).value }).is_null() {
                        current_block = 820271813250567934;
                    } else if (unsafe { *((*step).value).offset(0 as i32 as isize) }) as i32
                        != (unsafe { *((*node).name).offset(0 as i32 as isize) }) as i32
                    {
                        current_block = 6451473480150109090;
                    } else if (unsafe { xmlStrEqual((*step).value, (*node).name) }) == 0 {
                        current_block = 6451473480150109090;
                    } else if (unsafe { (*node).ns }).is_null() {
                        if !(unsafe { (*step).value2 }).is_null() {
                            current_block = 6451473480150109090;
                        } else {
                            current_block = 820271813250567934;
                        }
                    } else if !(unsafe { (*(*node).ns).href }).is_null() {
                        if (unsafe { (*step).value2 }).is_null() {
                            current_block = 6451473480150109090;
                        } else if (unsafe { xmlStrEqual((*step).value2, (*(*node).ns).href) }) == 0 {
                            current_block = 6451473480150109090;
                        } else {
                            current_block = 820271813250567934;
                        }
                    } else {
                        current_block = 820271813250567934;
                    }
                }
            }
            6 => {
                if (unsafe { (*step).value }).is_null() {
                    i += 1;
                    step = (unsafe { &mut *((*comp).steps).offset(i as isize) }) as *mut xmlStepOp;
                    if (unsafe { (*step).op }) as u32 == XML_OP_ROOT as i32 as u32 {
                        break;
                    }
                    if (unsafe { (*step).op }) as u32 != XML_OP_ELEM as i32 as u32 {
                        current_block = 6451473480150109090;
                    } else {
                        if (unsafe { (*step).value }).is_null() {
                            return -(1 as i32);
                        }
                        current_block = 10067844863897285902;
                    }
                } else {
                    current_block = 10067844863897285902;
                }
                match current_block {
                    6451473480150109090 => {}
                    _ => {
                        if node.is_null() {
                            current_block = 6451473480150109090;
                        } else if (unsafe { (*node).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
                            || (unsafe { (*node).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32
                            || (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
                        {
                            current_block = 6451473480150109090;
                        } else {
                            node = unsafe { (*node).parent };
                            while !node.is_null() {
                                if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                                    && (unsafe { *((*step).value).offset(0 as i32 as isize) }) as i32
                                        == (unsafe { *((*node).name).offset(0 as i32 as isize) }) as i32
                                    && (unsafe { xmlStrEqual((*step).value, (*node).name) }) != 0
                                {
                                    if (unsafe { (*node).ns }).is_null() {
                                        if (unsafe { (*step).value2 }).is_null() {
                                            break;
                                        }
                                    } else if !(unsafe { (*(*node).ns).href }).is_null() {
                                        if !(unsafe { (*step).value2 }).is_null()
                                            && (unsafe { xmlStrEqual((*step).value2, (*(*node).ns).href) }) != 0
                                        {
                                            break;
                                        }
                                    }
                                }
                                node = unsafe { (*node).parent };
                            }
                            if node.is_null() {
                                current_block = 6451473480150109090;
                            } else {
                                if (unsafe { (*step).op }) as u32 == XML_OP_ANCESTOR as i32 as u32 {
                                    xmlPatPushState(&mut states, i, node);
                                } else {
                                    xmlPatPushState(&mut states, i - 1 as i32, node);
                                }
                                current_block = 820271813250567934;
                            }
                        }
                    }
                }
            }
            7 => {
                if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
                    current_block = 6451473480150109090;
                } else if (unsafe { (*node).ns }).is_null() {
                    if !(unsafe { (*step).value }).is_null() {
                        current_block = 6451473480150109090;
                    } else {
                        current_block = 820271813250567934;
                    }
                } else if !(unsafe { (*(*node).ns).href }).is_null() {
                    if (unsafe { (*step).value }).is_null() {
                        current_block = 6451473480150109090;
                    } else if (unsafe { xmlStrEqual((*step).value, (*(*node).ns).href) }) == 0 {
                        current_block = 6451473480150109090;
                    } else {
                        current_block = 820271813250567934;
                    }
                } else {
                    current_block = 820271813250567934;
                }
            }
            8 => {
                if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
                    current_block = 6451473480150109090;
                } else {
                    current_block = 820271813250567934;
                }
            }
            _ => {
                current_block = 820271813250567934;
            }
        }
        match current_block {
            820271813250567934 => {
                i += 1;
            }
            _ => {
                if (states.states).is_null() {
                    return 0 as i32;
                }
                if states.nbstates <= 0 as i32 {
                    (unsafe { xmlFree.expect("non-null function pointer")(states.states as *mut libc::c_void) });
                    return 0 as i32;
                }
                states.nbstates -= 1;
                i = unsafe { (*(states.states).offset(states.nbstates as isize)).step };
                node = unsafe { (*(states.states).offset(states.nbstates as isize)).node };
            }
        }
    }
    if !(states.states).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(states.states as *mut libc::c_void) });
    }
    return 1 as i32;
}
extern "C" fn xmlPatScanName(mut ctxt: xmlPatParserContextPtr) -> *mut xmlChar {
    let mut q: *const xmlChar = 0 as *const xmlChar;
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: i32 = 0;
    let mut len: i32 = 0;
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh27 = unsafe { &mut ((*ctxt).cur) };
            *fresh27 = unsafe { (*fresh27).offset(1) };
        } else {
        };
    }
    q = unsafe { (*ctxt).cur };
    cur = q;
    val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
    if !((if val < 0x100 as i32 {
        (0x41 as i32 <= val && val <= 0x5a as i32
            || 0x61 as i32 <= val && val <= 0x7a as i32
            || 0xc0 as i32 <= val && val <= 0xd6 as i32
            || 0xd8 as i32 <= val && val <= 0xf6 as i32
            || 0xf8 as i32 <= val) as i32
    } else {
        unsafe { xmlCharInRange(val as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if val < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= val && val <= 0x9fa5 as i32
                || val == 0x3007 as i32
                || 0x3021 as i32 <= val && val <= 0x3029 as i32) as i32
        }) != 0)
        && val != '_' as i32
        && val != ':' as i32
    {
        return 0 as *mut xmlChar;
    }
    while (if val < 0x100 as i32 {
        (0x41 as i32 <= val && val <= 0x5a as i32
            || 0x61 as i32 <= val && val <= 0x7a as i32
            || 0xc0 as i32 <= val && val <= 0xd6 as i32
            || 0xd8 as i32 <= val && val <= 0xf6 as i32
            || 0xf8 as i32 <= val) as i32
    } else {
        unsafe { xmlCharInRange(val as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if val < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= val && val <= 0x9fa5 as i32
                || val == 0x3007 as i32
                || 0x3021 as i32 <= val && val <= 0x3029 as i32) as i32
        }) != 0
        || (if val < 0x100 as i32 {
            (0x30 as i32 <= val && val <= 0x39 as i32) as i32
        } else {
            unsafe { xmlCharInRange(val as u32, &xmlIsDigitGroup) }
        }) != 0
        || val == '.' as i32
        || val == '-' as i32
        || val == '_' as i32
        || (if val < 0x100 as i32 {
            0 as i32
        } else {
            unsafe { xmlCharInRange(val as u32, &xmlIsCombiningGroup) }
        }) != 0
        || (if val < 0x100 as i32 {
            (val == 0xb7 as i32) as i32
        } else {
            unsafe { xmlCharInRange(val as u32, &xmlIsExtenderGroup) }
        }) != 0
    {
        cur = unsafe { cur.offset(len as isize) };
        val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
    }
    if !(unsafe { (*ctxt).dict }).is_null() {
        ret = (unsafe { xmlDictLookup((*ctxt).dict, q, cur.offset_from(q) as i64 as i32) }) as *mut xmlChar;
    } else {
        ret = unsafe { xmlStrndup(q, cur.offset_from(q) as i64 as i32) };
    }
    let fresh28 = unsafe { &mut ((*ctxt).cur) };
    *fresh28 = cur;
    return ret;
}
extern "C" fn xmlPatScanNCName(mut ctxt: xmlPatParserContextPtr) -> *mut xmlChar {
    let mut q: *const xmlChar = 0 as *const xmlChar;
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: i32 = 0;
    let mut len: i32 = 0;
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh29 = unsafe { &mut ((*ctxt).cur) };
            *fresh29 = unsafe { (*fresh29).offset(1) };
        } else {
        };
    }
    q = unsafe { (*ctxt).cur };
    cur = q;
    val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
    if !((if val < 0x100 as i32 {
        (0x41 as i32 <= val && val <= 0x5a as i32
            || 0x61 as i32 <= val && val <= 0x7a as i32
            || 0xc0 as i32 <= val && val <= 0xd6 as i32
            || 0xd8 as i32 <= val && val <= 0xf6 as i32
            || 0xf8 as i32 <= val) as i32
    } else {
        unsafe { xmlCharInRange(val as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if val < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= val && val <= 0x9fa5 as i32
                || val == 0x3007 as i32
                || 0x3021 as i32 <= val && val <= 0x3029 as i32) as i32
        }) != 0)
        && val != '_' as i32
    {
        return 0 as *mut xmlChar;
    }
    while (if val < 0x100 as i32 {
        (0x41 as i32 <= val && val <= 0x5a as i32
            || 0x61 as i32 <= val && val <= 0x7a as i32
            || 0xc0 as i32 <= val && val <= 0xd6 as i32
            || 0xd8 as i32 <= val && val <= 0xf6 as i32
            || 0xf8 as i32 <= val) as i32
    } else {
        unsafe { xmlCharInRange(val as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if val < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= val && val <= 0x9fa5 as i32
                || val == 0x3007 as i32
                || 0x3021 as i32 <= val && val <= 0x3029 as i32) as i32
        }) != 0
        || (if val < 0x100 as i32 {
            (0x30 as i32 <= val && val <= 0x39 as i32) as i32
        } else {
            unsafe { xmlCharInRange(val as u32, &xmlIsDigitGroup) }
        }) != 0
        || val == '.' as i32
        || val == '-' as i32
        || val == '_' as i32
        || (if val < 0x100 as i32 {
            0 as i32
        } else {
            unsafe { xmlCharInRange(val as u32, &xmlIsCombiningGroup) }
        }) != 0
        || (if val < 0x100 as i32 {
            (val == 0xb7 as i32) as i32
        } else {
            unsafe { xmlCharInRange(val as u32, &xmlIsExtenderGroup) }
        }) != 0
    {
        cur = unsafe { cur.offset(len as isize) };
        val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
    }
    if !(unsafe { (*ctxt).dict }).is_null() {
        ret = (unsafe { xmlDictLookup((*ctxt).dict, q, cur.offset_from(q) as i64 as i32) }) as *mut xmlChar;
    } else {
        ret = unsafe { xmlStrndup(q, cur.offset_from(q) as i64 as i32) };
    }
    let fresh30 = unsafe { &mut ((*ctxt).cur) };
    *fresh30 = cur;
    return ret;
}
extern "C" fn xmlCompileAttributeTest(mut ctxt: xmlPatParserContextPtr) {
    let mut current_block: u64;
    let mut token: *mut xmlChar = 0 as *mut xmlChar;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut xmlChar = 0 as *mut xmlChar;
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh31 = unsafe { &mut ((*ctxt).cur) };
            *fresh31 = unsafe { (*fresh31).offset(1) };
        } else {
        };
    }
    name = xmlPatScanNCName(ctxt);
    if name.is_null() {
        if (unsafe { *(*ctxt).cur }) as i32 == '*' as i32 {
            if xmlPatternAdd(
                ctxt,
                unsafe { (*ctxt).comp },
                XML_OP_ATTR,
                0 as *mut xmlChar,
                0 as *mut xmlChar,
            ) != 0
            {
                current_block = 11331548824878167032;
            } else {
                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                    let fresh32 = unsafe { &mut ((*ctxt).cur) };
                    *fresh32 = unsafe { (*fresh32).offset(1) };
                } else {
                };
                current_block = 5399440093318478209;
            }
        } else {
            (unsafe { (*ctxt).error = 1 as i32 });
            current_block = 5399440093318478209;
        }
        match current_block {
            11331548824878167032 => {}
            _ => return,
        }
    } else {
        if (unsafe { *(*ctxt).cur }) as i32 == ':' as i32 {
            let mut i: i32 = 0;
            let mut prefix: *mut xmlChar = name;
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh33 = unsafe { &mut ((*ctxt).cur) };
                *fresh33 = unsafe { (*fresh33).offset(1) };
            } else {
            };
            if (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            {
                if (unsafe { (*(*ctxt).comp).dict }).is_null() {
                    (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
                }
                (unsafe { (*ctxt).error = 1 as i32 });
                current_block = 11331548824878167032;
            } else {
                token = xmlPatScanName(ctxt);
                if (unsafe { *prefix.offset(0 as i32 as isize) }) as i32 == 'x' as i32
                    && (unsafe { *prefix.offset(1 as i32 as isize) }) as i32 == 'm' as i32
                    && (unsafe { *prefix.offset(2 as i32 as isize) }) as i32 == 'l' as i32
                    && (unsafe { *prefix.offset(3 as i32 as isize) }) as i32 == 0 as i32
                {
                    if !(unsafe { (*(*ctxt).comp).dict }).is_null() {
                        URL = (unsafe { xmlDictLookup(
                            (*(*ctxt).comp).dict,
                            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                                as *const xmlChar as *mut xmlChar,
                            -(1 as i32),
                        ) }) as *mut xmlChar;
                    } else {
                        URL = unsafe { xmlStrdup(
                            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                                as *const xmlChar as *mut xmlChar,
                        ) };
                    }
                    current_block = 15512526488502093901;
                } else {
                    i = 0 as i32;
                    while i < (unsafe { (*ctxt).nb_namespaces }) {
                        if (unsafe { xmlStrEqual(
                            *((*ctxt).namespaces).offset((2 as i32 * i + 1 as i32) as isize),
                            prefix,
                        ) }) != 0
                        {
                            if !(unsafe { (*(*ctxt).comp).dict }).is_null() {
                                URL = (unsafe { xmlDictLookup(
                                    (*(*ctxt).comp).dict,
                                    *((*ctxt).namespaces).offset((2 as i32 * i) as isize)
                                        as *mut xmlChar,
                                    -(1 as i32),
                                ) }) as *mut xmlChar;
                            } else {
                                URL = unsafe { xmlStrdup(
                                    *((*ctxt).namespaces).offset((2 as i32 * i) as isize)
                                        as *mut xmlChar,
                                ) };
                            }
                            break;
                        } else {
                            i += 1;
                        }
                    }
                    if i >= (unsafe { (*ctxt).nb_namespaces }) {
                        if (unsafe { (*(*ctxt).comp).dict }).is_null() {
                            (unsafe { xmlFree.expect("non-null function pointer")(
                                prefix as *mut libc::c_void,
                            ) });
                        }
                        (unsafe { (*ctxt).error = 1 as i32 });
                        current_block = 11331548824878167032;
                    } else {
                        current_block = 15512526488502093901;
                    }
                }
                match current_block {
                    11331548824878167032 => {}
                    _ => {
                        if (unsafe { (*(*ctxt).comp).dict }).is_null() {
                            (unsafe { xmlFree.expect("non-null function pointer")(
                                prefix as *mut libc::c_void,
                            ) });
                        }
                        if token.is_null() {
                            if (unsafe { *(*ctxt).cur }) as i32 == '*' as i32 {
                                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                    let fresh34 = unsafe { &mut ((*ctxt).cur) };
                                    *fresh34 = unsafe { (*fresh34).offset(1) };
                                } else {
                                };
                                if xmlPatternAdd(
                                    ctxt,
                                    unsafe { (*ctxt).comp },
                                    XML_OP_ATTR,
                                    0 as *mut xmlChar,
                                    URL,
                                ) != 0
                                {
                                    current_block = 11331548824878167032;
                                } else {
                                    current_block = 9512719473022792396;
                                }
                            } else {
                                (unsafe { (*ctxt).error = 1 as i32 });
                                current_block = 11331548824878167032;
                            }
                        } else if xmlPatternAdd(ctxt, unsafe { (*ctxt).comp }, XML_OP_ATTR, token, URL) != 0 {
                            current_block = 11331548824878167032;
                        } else {
                            current_block = 9512719473022792396;
                        }
                    }
                }
            }
        } else if xmlPatternAdd(ctxt, unsafe { (*ctxt).comp }, XML_OP_ATTR, name, 0 as *mut xmlChar) != 0 {
            current_block = 11331548824878167032;
        } else {
            current_block = 9512719473022792396;
        }
        match current_block {
            11331548824878167032 => {}
            _ => return,
        }
    }
    if !URL.is_null() {
        if (unsafe { (*(*ctxt).comp).dict }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
        }
    }
    if !token.is_null() {
        if (unsafe { (*(*ctxt).comp).dict }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(token as *mut libc::c_void) });
        }
    }
}
extern "C" fn xmlCompileStepPattern(mut ctxt: xmlPatParserContextPtr) {
    let mut current_block: u64;
    let mut token: *mut xmlChar = 0 as *mut xmlChar;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut xmlChar = 0 as *mut xmlChar;
    let mut hasBlanks: i32 = 0 as i32;
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh35 = unsafe { &mut ((*ctxt).cur) };
            *fresh35 = unsafe { (*fresh35).offset(1) };
        } else {
        };
    }
    if (unsafe { *(*ctxt).cur }) as i32 == '.' as i32 {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh36 = unsafe { &mut ((*ctxt).cur) };
            *fresh36 = unsafe { (*fresh36).offset(1) };
        } else {
        };
        if !(xmlPatternAdd(
            ctxt,
            unsafe { (*ctxt).comp },
            XML_OP_ELEM,
            0 as *mut xmlChar,
            0 as *mut xmlChar,
        ) != 0)
        {
            return;
        }
    } else if (unsafe { *(*ctxt).cur }) as i32 == '@' as i32 {
        if (unsafe { (*(*ctxt).comp).flags }) & XML_PATTERN_XSSEL as i32 != 0 {
            (unsafe { (*ctxt).error = 1 as i32 });
            return;
        }
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh37 = unsafe { &mut ((*ctxt).cur) };
            *fresh37 = unsafe { (*fresh37).offset(1) };
        } else {
        };
        xmlCompileAttributeTest(ctxt);
        if !((unsafe { (*ctxt).error }) != 0 as i32) {
            return;
        }
    } else {
        name = xmlPatScanNCName(ctxt);
        if name.is_null() {
            if (unsafe { *(*ctxt).cur }) as i32 == '*' as i32 {
                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                    let fresh38 = unsafe { &mut ((*ctxt).cur) };
                    *fresh38 = unsafe { (*fresh38).offset(1) };
                } else {
                };
                if !(xmlPatternAdd(
                    ctxt,
                    unsafe { (*ctxt).comp },
                    XML_OP_ALL,
                    0 as *mut xmlChar,
                    0 as *mut xmlChar,
                ) != 0)
                {
                    return;
                }
            } else {
                (unsafe { (*ctxt).error = 1 as i32 });
                return;
            }
        } else {
            if (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            {
                hasBlanks = 1 as i32;
                while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                    || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                {
                    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                        let fresh39 = unsafe { &mut ((*ctxt).cur) };
                        *fresh39 = unsafe { (*fresh39).offset(1) };
                    } else {
                    };
                }
            }
            if (unsafe { *(*ctxt).cur }) as i32 == ':' as i32 {
                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                    let fresh40 = unsafe { &mut ((*ctxt).cur) };
                    *fresh40 = unsafe { (*fresh40).offset(1) };
                } else {
                };
                if (unsafe { *(*ctxt).cur }) as i32 != ':' as i32 {
                    let mut prefix: *mut xmlChar = name;
                    let mut i: i32 = 0;
                    if hasBlanks != 0
                        || ((unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32
                                && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32)
                    {
                        (unsafe { (*ctxt).error = 1 as i32 });
                        current_block = 15904406811757377787;
                    } else {
                        token = xmlPatScanName(ctxt);
                        if (unsafe { *prefix.offset(0 as i32 as isize) }) as i32 == 'x' as i32
                            && (unsafe { *prefix.offset(1 as i32 as isize) }) as i32 == 'm' as i32
                            && (unsafe { *prefix.offset(2 as i32 as isize) }) as i32 == 'l' as i32
                            && (unsafe { *prefix.offset(3 as i32 as isize) }) as i32 == 0 as i32
                        {
                            if !(unsafe { (*(*ctxt).comp).dict }).is_null() {
                                URL = (unsafe { xmlDictLookup(
                                    (*(*ctxt).comp).dict,
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const i8
                                        as *const xmlChar
                                        as *mut xmlChar,
                                    -(1 as i32),
                                ) }) as *mut xmlChar;
                            } else {
                                URL = unsafe { xmlStrdup(
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const i8
                                        as *const xmlChar
                                        as *mut xmlChar,
                                ) };
                            }
                            current_block = 13325891313334703151;
                        } else {
                            i = 0 as i32;
                            while i < (unsafe { (*ctxt).nb_namespaces }) {
                                if (unsafe { xmlStrEqual(
                                    *((*ctxt).namespaces)
                                        .offset((2 as i32 * i + 1 as i32) as isize),
                                    prefix,
                                ) }) != 0
                                {
                                    if !(unsafe { (*(*ctxt).comp).dict }).is_null() {
                                        URL = (unsafe { xmlDictLookup(
                                            (*(*ctxt).comp).dict,
                                            *((*ctxt).namespaces).offset((2 as i32 * i) as isize)
                                                as *mut xmlChar,
                                            -(1 as i32),
                                        ) })
                                            as *mut xmlChar;
                                    } else {
                                        URL = unsafe { xmlStrdup(
                                            *((*ctxt).namespaces).offset((2 as i32 * i) as isize)
                                                as *mut xmlChar,
                                        ) };
                                    }
                                    break;
                                } else {
                                    i += 1;
                                }
                            }
                            if i >= (unsafe { (*ctxt).nb_namespaces }) {
                                (unsafe { (*ctxt).error = 1 as i32 });
                                current_block = 15904406811757377787;
                            } else {
                                current_block = 13325891313334703151;
                            }
                        }
                        match current_block {
                            15904406811757377787 => {}
                            _ => {
                                if (unsafe { (*(*ctxt).comp).dict }).is_null() {
                                    (unsafe { xmlFree.expect("non-null function pointer")(
                                        prefix as *mut libc::c_void,
                                    ) });
                                }
                                name = 0 as *mut xmlChar;
                                if token.is_null() {
                                    if (unsafe { *(*ctxt).cur }) as i32 == '*' as i32 {
                                        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                            let fresh41 = unsafe { &mut ((*ctxt).cur) };
                                            *fresh41 = unsafe { (*fresh41).offset(1) };
                                        } else {
                                        };
                                        if xmlPatternAdd(
                                            ctxt,
                                            unsafe { (*ctxt).comp },
                                            XML_OP_NS,
                                            URL,
                                            0 as *mut xmlChar,
                                        ) != 0
                                        {
                                            current_block = 15904406811757377787;
                                        } else {
                                            current_block = 8880031775101799352;
                                        }
                                    } else {
                                        (unsafe { (*ctxt).error = 1 as i32 });
                                        current_block = 15904406811757377787;
                                    }
                                } else if xmlPatternAdd(ctxt, unsafe { (*ctxt).comp }, XML_OP_ELEM, token, URL)
                                    != 0
                                {
                                    current_block = 15904406811757377787;
                                } else {
                                    current_block = 8880031775101799352;
                                }
                            }
                        }
                    }
                } else {
                    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                        let fresh42 = unsafe { &mut ((*ctxt).cur) };
                        *fresh42 = unsafe { (*fresh42).offset(1) };
                    } else {
                    };
                    if (unsafe { xmlStrEqual(name, b"child\0" as *const u8 as *const i8 as *const xmlChar) })
                        != 0
                    {
                        if (unsafe { (*(*ctxt).comp).dict }).is_null() {
                            (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
                        }
                        name = xmlPatScanName(ctxt);
                        if name.is_null() {
                            if (unsafe { *(*ctxt).cur }) as i32 == '*' as i32 {
                                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                    let fresh43 = unsafe { &mut ((*ctxt).cur) };
                                    *fresh43 = unsafe { (*fresh43).offset(1) };
                                } else {
                                };
                                if !(xmlPatternAdd(
                                    ctxt,
                                    unsafe { (*ctxt).comp },
                                    XML_OP_ALL,
                                    0 as *mut xmlChar,
                                    0 as *mut xmlChar,
                                ) != 0)
                                {
                                    return;
                                }
                            } else {
                                (unsafe { (*ctxt).error = 1 as i32 });
                            }
                        } else {
                            if (unsafe { *(*ctxt).cur }) as i32 == ':' as i32 {
                                let mut prefix_0: *mut xmlChar = name;
                                let mut i_0: i32 = 0;
                                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                    let fresh44 = unsafe { &mut ((*ctxt).cur) };
                                    *fresh44 = unsafe { (*fresh44).offset(1) };
                                } else {
                                };
                                if (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                                    || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32
                                        && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                                    || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                                {
                                    (unsafe { (*ctxt).error = 1 as i32 });
                                    current_block = 15904406811757377787;
                                } else {
                                    token = xmlPatScanName(ctxt);
                                    if (unsafe { *prefix_0.offset(0 as i32 as isize) }) as i32 == 'x' as i32
                                        && (unsafe { *prefix_0.offset(1 as i32 as isize) }) as i32 == 'm' as i32
                                        && (unsafe { *prefix_0.offset(2 as i32 as isize) }) as i32 == 'l' as i32
                                        && (unsafe { *prefix_0.offset(3 as i32 as isize) }) as i32 == 0 as i32
                                    {
                                        if !(unsafe { (*(*ctxt).comp).dict }).is_null() {
                                            URL = (unsafe { xmlDictLookup(
                                                (*(*ctxt).comp).dict,
                                                b"http://www.w3.org/XML/1998/namespace\0"
                                                    as *const u8
                                                    as *const i8
                                                    as *const xmlChar
                                                    as *mut xmlChar,
                                                -(1 as i32),
                                            ) })
                                                as *mut xmlChar;
                                        } else {
                                            URL = unsafe { xmlStrdup(
                                                b"http://www.w3.org/XML/1998/namespace\0"
                                                    as *const u8
                                                    as *const i8
                                                    as *const xmlChar
                                                    as *mut xmlChar,
                                            ) };
                                        }
                                        current_block = 5706227035632243100;
                                    } else {
                                        i_0 = 0 as i32;
                                        while i_0 < (unsafe { (*ctxt).nb_namespaces }) {
                                            if (unsafe { xmlStrEqual(
                                                *((*ctxt).namespaces)
                                                    .offset((2 as i32 * i_0 + 1 as i32) as isize),
                                                prefix_0,
                                            ) }) != 0
                                            {
                                                if !(unsafe { (*(*ctxt).comp).dict }).is_null() {
                                                    URL = (unsafe { xmlDictLookup(
                                                        (*(*ctxt).comp).dict,
                                                        *((*ctxt).namespaces)
                                                            .offset((2 as i32 * i_0) as isize)
                                                            as *mut xmlChar,
                                                        -(1 as i32),
                                                    ) })
                                                        as *mut xmlChar;
                                                } else {
                                                    URL = unsafe { xmlStrdup(
                                                        *((*ctxt).namespaces)
                                                            .offset((2 as i32 * i_0) as isize)
                                                            as *mut xmlChar,
                                                    ) };
                                                }
                                                break;
                                            } else {
                                                i_0 += 1;
                                            }
                                        }
                                        if i_0 >= (unsafe { (*ctxt).nb_namespaces }) {
                                            (unsafe { (*ctxt).error = 1 as i32 });
                                            current_block = 15904406811757377787;
                                        } else {
                                            current_block = 5706227035632243100;
                                        }
                                    }
                                    match current_block {
                                        15904406811757377787 => {}
                                        _ => {
                                            if (unsafe { (*(*ctxt).comp).dict }).is_null() {
                                                (unsafe { xmlFree.expect("non-null function pointer")(
                                                    prefix_0 as *mut libc::c_void,
                                                ) });
                                            }
                                            name = 0 as *mut xmlChar;
                                            if token.is_null() {
                                                if (unsafe { *(*ctxt).cur }) as i32 == '*' as i32 {
                                                    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                                        let fresh45 = unsafe { &mut ((*ctxt).cur) };
                                                        *fresh45 = unsafe { (*fresh45).offset(1) };
                                                    } else {
                                                    };
                                                    if xmlPatternAdd(
                                                        ctxt,
                                                        unsafe { (*ctxt).comp },
                                                        XML_OP_NS,
                                                        URL,
                                                        0 as *mut xmlChar,
                                                    ) != 0
                                                    {
                                                        current_block = 15904406811757377787;
                                                    } else {
                                                        current_block = 7337917895049117968;
                                                    }
                                                } else {
                                                    (unsafe { (*ctxt).error = 1 as i32 });
                                                    current_block = 15904406811757377787;
                                                }
                                            } else if xmlPatternAdd(
                                                ctxt,
                                                unsafe { (*ctxt).comp },
                                                XML_OP_CHILD,
                                                token,
                                                URL,
                                            ) != 0
                                            {
                                                current_block = 15904406811757377787;
                                            } else {
                                                current_block = 7337917895049117968;
                                            }
                                        }
                                    }
                                }
                            } else if xmlPatternAdd(
                                ctxt,
                                unsafe { (*ctxt).comp },
                                XML_OP_CHILD,
                                name,
                                0 as *mut xmlChar,
                            ) != 0
                            {
                                current_block = 15904406811757377787;
                            } else {
                                current_block = 7337917895049117968;
                            }
                            match current_block {
                                15904406811757377787 => {}
                                _ => return,
                            }
                        }
                    } else if (unsafe { xmlStrEqual(
                        name,
                        b"attribute\0" as *const u8 as *const i8 as *const xmlChar,
                    ) }) != 0
                    {
                        if (unsafe { (*(*ctxt).comp).dict }).is_null() {
                            (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
                        }
                        name = 0 as *mut xmlChar;
                        if (unsafe { (*(*ctxt).comp).flags }) & XML_PATTERN_XSSEL as i32 != 0 {
                            (unsafe { (*ctxt).error = 1 as i32 });
                        } else {
                            xmlCompileAttributeTest(ctxt);
                            if !((unsafe { (*ctxt).error }) != 0 as i32) {
                                return;
                            }
                        }
                    } else {
                        (unsafe { (*ctxt).error = 1 as i32 });
                    }
                    current_block = 15904406811757377787;
                }
            } else if (unsafe { *(*ctxt).cur }) as i32 == '*' as i32 {
                if !name.is_null() {
                    (unsafe { (*ctxt).error = 1 as i32 });
                    current_block = 15904406811757377787;
                } else {
                    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                        let fresh46 = unsafe { &mut ((*ctxt).cur) };
                        *fresh46 = unsafe { (*fresh46).offset(1) };
                    } else {
                    };
                    if xmlPatternAdd(ctxt, unsafe { (*ctxt).comp }, XML_OP_ALL, token, 0 as *mut xmlChar) != 0
                    {
                        current_block = 15904406811757377787;
                    } else {
                        current_block = 8880031775101799352;
                    }
                }
            } else if xmlPatternAdd(ctxt, unsafe { (*ctxt).comp }, XML_OP_ELEM, name, 0 as *mut xmlChar) != 0 {
                current_block = 15904406811757377787;
            } else {
                current_block = 8880031775101799352;
            }
            match current_block {
                15904406811757377787 => {}
                _ => return,
            }
        }
    }
    if !URL.is_null() {
        if (unsafe { (*(*ctxt).comp).dict }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
        }
    }
    if !token.is_null() {
        if (unsafe { (*(*ctxt).comp).dict }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(token as *mut libc::c_void) });
        }
    }
    if !name.is_null() {
        if (unsafe { (*(*ctxt).comp).dict }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
        }
    }
}
extern "C" fn xmlCompilePathPattern(mut ctxt: xmlPatParserContextPtr) {
    let mut current_block: u64;
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh47 = unsafe { &mut ((*ctxt).cur) };
            *fresh47 = unsafe { (*fresh47).offset(1) };
        } else {
        };
    }
    if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32 {
        (unsafe { (*(*ctxt).comp).flags |= (1 as i32) << 8 as i32 });
    } else if (unsafe { *(*ctxt).cur }) as i32 == '.' as i32
        || (unsafe { (*(*ctxt).comp).flags })
            & (XML_PATTERN_XPATH as i32 | XML_PATTERN_XSSEL as i32 | XML_PATTERN_XSFIELD as i32)
            != 0
    {
        (unsafe { (*(*ctxt).comp).flags |= (1 as i32) << 9 as i32 });
    }
    if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32
        && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32
    {
        if xmlPatternAdd(
            ctxt,
            unsafe { (*ctxt).comp },
            XML_OP_ANCESTOR,
            0 as *mut xmlChar,
            0 as *mut xmlChar,
        ) != 0
        {
            current_block = 17489734837053406682;
        } else {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh48 = unsafe { &mut ((*ctxt).cur) };
                *fresh48 = unsafe { (*fresh48).offset(1) };
            } else {
            };
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh49 = unsafe { &mut ((*ctxt).cur) };
                *fresh49 = unsafe { (*fresh49).offset(1) };
            } else {
            };
            current_block = 11194104282611034094;
        }
    } else if (unsafe { *(*ctxt).cur }) as i32 == '.' as i32
        && (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32
        && (unsafe { *((*ctxt).cur).offset(2 as i32 as isize) }) as i32 == '/' as i32
    {
        if xmlPatternAdd(
            ctxt,
            unsafe { (*ctxt).comp },
            XML_OP_ANCESTOR,
            0 as *mut xmlChar,
            0 as *mut xmlChar,
        ) != 0
        {
            current_block = 17489734837053406682;
        } else {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh50 = unsafe { &mut ((*ctxt).cur) };
                *fresh50 = unsafe { (*fresh50).offset(1) };
            } else {
            };
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh51 = unsafe { &mut ((*ctxt).cur) };
                *fresh51 = unsafe { (*fresh51).offset(1) };
            } else {
            };
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh52 = unsafe { &mut ((*ctxt).cur) };
                *fresh52 = unsafe { (*fresh52).offset(1) };
            } else {
            };
            while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            {
                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                    let fresh53 = unsafe { &mut ((*ctxt).cur) };
                    *fresh53 = unsafe { (*fresh53).offset(1) };
                } else {
                };
            }
            if (unsafe { *(*ctxt).cur }) as i32 == 0 as i32 {
                (unsafe { (*ctxt).error = 1 as i32 });
                current_block = 17489734837053406682;
            } else {
                current_block = 11194104282611034094;
            }
        }
    } else {
        current_block = 11194104282611034094;
    }
    match current_block {
        11194104282611034094 => {
            if (unsafe { *(*ctxt).cur }) as i32 == '@' as i32 {
                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                    let fresh54 = unsafe { &mut ((*ctxt).cur) };
                    *fresh54 = unsafe { (*fresh54).offset(1) };
                } else {
                };
                xmlCompileAttributeTest(ctxt);
                while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                    || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                {
                    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                        let fresh55 = unsafe { &mut ((*ctxt).cur) };
                        *fresh55 = unsafe { (*fresh55).offset(1) };
                    } else {
                    };
                }
                if (unsafe { *(*ctxt).cur }) as i32 != 0 as i32 {
                    xmlCompileStepPattern(ctxt);
                    if (unsafe { (*ctxt).error }) != 0 as i32 {
                        current_block = 17489734837053406682;
                    } else {
                        current_block = 7189308829251266000;
                    }
                } else {
                    current_block = 7189308829251266000;
                }
            } else {
                if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32 {
                    if xmlPatternAdd(
                        ctxt,
                        unsafe { (*ctxt).comp },
                        XML_OP_ROOT,
                        0 as *mut xmlChar,
                        0 as *mut xmlChar,
                    ) != 0
                    {
                        current_block = 17489734837053406682;
                    } else {
                        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                            let fresh56 = unsafe { &mut ((*ctxt).cur) };
                            *fresh56 = unsafe { (*fresh56).offset(1) };
                        } else {
                        };
                        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32
                                && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                        {
                            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                let fresh57 = unsafe { &mut ((*ctxt).cur) };
                                *fresh57 = unsafe { (*fresh57).offset(1) };
                            } else {
                            };
                        }
                        if (unsafe { *(*ctxt).cur }) as i32 == 0 as i32 {
                            (unsafe { (*ctxt).error = 1 as i32 });
                            current_block = 17489734837053406682;
                        } else {
                            current_block = 15512526488502093901;
                        }
                    }
                } else {
                    current_block = 15512526488502093901;
                }
                match current_block {
                    17489734837053406682 => {}
                    _ => {
                        xmlCompileStepPattern(ctxt);
                        if (unsafe { (*ctxt).error }) != 0 as i32 {
                            current_block = 17489734837053406682;
                        } else {
                            while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                                || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32
                                    && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                                || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                            {
                                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                    let fresh58 = unsafe { &mut ((*ctxt).cur) };
                                    *fresh58 = unsafe { (*fresh58).offset(1) };
                                } else {
                                };
                            }
                            loop {
                                if !((unsafe { *(*ctxt).cur }) as i32 == '/' as i32) {
                                    current_block = 7189308829251266000;
                                    break;
                                }
                                if (unsafe { *((*ctxt).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32 {
                                    if xmlPatternAdd(
                                        ctxt,
                                        unsafe { (*ctxt).comp },
                                        XML_OP_ANCESTOR,
                                        0 as *mut xmlChar,
                                        0 as *mut xmlChar,
                                    ) != 0
                                    {
                                        current_block = 17489734837053406682;
                                        break;
                                    }
                                    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                        let fresh59 = unsafe { &mut ((*ctxt).cur) };
                                        *fresh59 = unsafe { (*fresh59).offset(1) };
                                    } else {
                                    };
                                    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                        let fresh60 = unsafe { &mut ((*ctxt).cur) };
                                        *fresh60 = unsafe { (*fresh60).offset(1) };
                                    } else {
                                    };
                                    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                                        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32
                                            && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                                        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                                    {
                                        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                            let fresh61 = unsafe { &mut ((*ctxt).cur) };
                                            *fresh61 = unsafe { (*fresh61).offset(1) };
                                        } else {
                                        };
                                    }
                                    xmlCompileStepPattern(ctxt);
                                    if (unsafe { (*ctxt).error }) != 0 as i32 {
                                        current_block = 17489734837053406682;
                                        break;
                                    }
                                } else {
                                    if xmlPatternAdd(
                                        ctxt,
                                        unsafe { (*ctxt).comp },
                                        XML_OP_PARENT,
                                        0 as *mut xmlChar,
                                        0 as *mut xmlChar,
                                    ) != 0
                                    {
                                        current_block = 17489734837053406682;
                                        break;
                                    }
                                    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                        let fresh62 = unsafe { &mut ((*ctxt).cur) };
                                        *fresh62 = unsafe { (*fresh62).offset(1) };
                                    } else {
                                    };
                                    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                                        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32
                                            && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                                        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                                    {
                                        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                            let fresh63 = unsafe { &mut ((*ctxt).cur) };
                                            *fresh63 = unsafe { (*fresh63).offset(1) };
                                        } else {
                                        };
                                    }
                                    if (unsafe { *(*ctxt).cur }) as i32 == 0 as i32 {
                                        (unsafe { (*ctxt).error = 1 as i32 });
                                        current_block = 17489734837053406682;
                                        break;
                                    } else {
                                        xmlCompileStepPattern(ctxt);
                                        if (unsafe { (*ctxt).error }) != 0 as i32 {
                                            current_block = 17489734837053406682;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            match current_block {
                17489734837053406682 => {}
                _ => {
                    if (unsafe { *(*ctxt).cur }) as i32 != 0 as i32 {
                        (unsafe { (*ctxt).error = 1 as i32 });
                    }
                }
            }
        }
        _ => {}
    };
}
extern "C" fn xmlCompileIDCXPathPath(mut ctxt: xmlPatParserContextPtr) {
    let mut current_block: u64;
    while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
    {
        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
            let fresh64 = unsafe { &mut ((*ctxt).cur) };
            *fresh64 = unsafe { (*fresh64).offset(1) };
        } else {
        };
    }
    if !((unsafe { *(*ctxt).cur }) as i32 == '/' as i32) {
        (unsafe { (*(*ctxt).comp).flags |= (1 as i32) << 9 as i32 });
        if (unsafe { *(*ctxt).cur }) as i32 == '.' as i32 {
            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                let fresh65 = unsafe { &mut ((*ctxt).cur) };
                *fresh65 = unsafe { (*fresh65).offset(1) };
            } else {
            };
            while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
            {
                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                    let fresh66 = unsafe { &mut ((*ctxt).cur) };
                    *fresh66 = unsafe { (*fresh66).offset(1) };
                } else {
                };
            }
            if (unsafe { *(*ctxt).cur }) as i32 == 0 as i32 {
                if xmlPatternAdd(
                    ctxt,
                    unsafe { (*ctxt).comp },
                    XML_OP_ELEM,
                    0 as *mut xmlChar,
                    0 as *mut xmlChar,
                ) != 0
                {
                    current_block = 10466991778982128886;
                } else {
                    return;
                }
            } else if (unsafe { *(*ctxt).cur }) as i32 != '/' as i32 {
                current_block = 10466991778982128886;
            } else {
                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                    let fresh67 = unsafe { &mut ((*ctxt).cur) };
                    *fresh67 = unsafe { (*fresh67).offset(1) };
                } else {
                };
                while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32 && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                    || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                {
                    if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                        let fresh68 = unsafe { &mut ((*ctxt).cur) };
                        *fresh68 = unsafe { (*fresh68).offset(1) };
                    } else {
                    };
                }
                if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32 {
                    if (unsafe { *((*ctxt).cur).offset(-(1 as i32) as isize) }) as i32 == 0x20 as i32
                        || 0x9 as i32 <= (unsafe { *((*ctxt).cur).offset(-(1 as i32) as isize) }) as i32
                            && (unsafe { *((*ctxt).cur).offset(-(1 as i32) as isize) }) as i32 <= 0xa as i32
                        || (unsafe { *((*ctxt).cur).offset(-(1 as i32) as isize) }) as i32 == 0xd as i32
                    {
                        current_block = 10466991778982128886;
                    } else if xmlPatternAdd(
                        ctxt,
                        unsafe { (*ctxt).comp },
                        XML_OP_ANCESTOR,
                        0 as *mut xmlChar,
                        0 as *mut xmlChar,
                    ) != 0
                    {
                        current_block = 10466991778982128886;
                    } else {
                        if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                            let fresh69 = unsafe { &mut ((*ctxt).cur) };
                            *fresh69 = unsafe { (*fresh69).offset(1) };
                        } else {
                        };
                        while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                            || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32
                                && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                            || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                        {
                            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                let fresh70 = unsafe { &mut ((*ctxt).cur) };
                                *fresh70 = unsafe { (*fresh70).offset(1) };
                            } else {
                            };
                        }
                        current_block = 14818589718467733107;
                    }
                } else {
                    current_block = 14818589718467733107;
                }
                match current_block {
                    10466991778982128886 => {}
                    _ => {
                        if (unsafe { *(*ctxt).cur }) as i32 == 0 as i32 {
                            current_block = 11874738112936171638;
                        } else {
                            current_block = 11932355480408055363;
                        }
                    }
                }
            }
        } else {
            current_block = 11932355480408055363;
        }
        match current_block {
            10466991778982128886 => {}
            _ => {
                loop {
                    match current_block {
                        11874738112936171638 => {
                            (unsafe { (*ctxt).error = 1 as i32 });
                            return;
                        }
                        _ => {
                            xmlCompileStepPattern(ctxt);
                            if (unsafe { (*ctxt).error }) != 0 as i32 {
                                current_block = 10466991778982128886;
                                break;
                            }
                            while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                                || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32
                                    && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                                || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                            {
                                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                    let fresh71 = unsafe { &mut ((*ctxt).cur) };
                                    *fresh71 = unsafe { (*fresh71).offset(1) };
                                } else {
                                };
                            }
                            if (unsafe { *(*ctxt).cur }) as i32 != '/' as i32 {
                                current_block = 15004371738079956865;
                                break;
                            }
                            if xmlPatternAdd(
                                ctxt,
                                unsafe { (*ctxt).comp },
                                XML_OP_PARENT,
                                0 as *mut xmlChar,
                                0 as *mut xmlChar,
                            ) != 0
                            {
                                current_block = 10466991778982128886;
                                break;
                            }
                            if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                let fresh72 = unsafe { &mut ((*ctxt).cur) };
                                *fresh72 = unsafe { (*fresh72).offset(1) };
                            } else {
                            };
                            while (unsafe { *(*ctxt).cur }) as i32 == 0x20 as i32
                                || 0x9 as i32 <= (unsafe { *(*ctxt).cur }) as i32
                                    && (unsafe { *(*ctxt).cur }) as i32 <= 0xa as i32
                                || (unsafe { *(*ctxt).cur }) as i32 == 0xd as i32
                            {
                                if (unsafe { *(*ctxt).cur }) as i32 != 0 {
                                    let fresh73 = unsafe { &mut ((*ctxt).cur) };
                                    *fresh73 = unsafe { (*fresh73).offset(1) };
                                } else {
                                };
                            }
                            if (unsafe { *(*ctxt).cur }) as i32 == '/' as i32 {
                                current_block = 10466991778982128886;
                                break;
                            }
                            if (unsafe { *(*ctxt).cur }) as i32 == 0 as i32 {
                                current_block = 11874738112936171638;
                                continue;
                            }
                            if (unsafe { *(*ctxt).cur }) as i32 != 0 as i32 {
                                current_block = 11932355480408055363;
                            } else {
                                current_block = 15004371738079956865;
                                break;
                            }
                        }
                    }
                }
                match current_block {
                    10466991778982128886 => {}
                    _ => {
                        if (unsafe { *(*ctxt).cur }) as i32 != 0 as i32 {
                            (unsafe { (*ctxt).error = 1 as i32 });
                        }
                        return;
                    }
                }
            }
        }
    }
    (unsafe { (*ctxt).error = 1 as i32 });
}
extern "C" fn xmlNewStreamComp(mut size: i32) -> xmlStreamCompPtr {
    let mut cur: xmlStreamCompPtr = 0 as *mut xmlStreamComp;
    if size < 4 as i32 {
        size = 4 as i32;
    }
    cur = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlStreamComp>() as u64
    ) }) as xmlStreamCompPtr;
    if cur.is_null() {
        return 0 as xmlStreamCompPtr;
    }
    (unsafe { memset(
        cur as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlStreamComp>() as u64,
    ) });
    let fresh74 = unsafe { &mut ((*cur).steps) };
    *fresh74 = (unsafe { xmlMalloc.expect("non-null function pointer")(
        (size as u64).wrapping_mul(::std::mem::size_of::<xmlStreamStep>() as u64),
    ) }) as xmlStreamStepPtr;
    if (unsafe { (*cur).steps }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
        return 0 as xmlStreamCompPtr;
    }
    (unsafe { (*cur).nbStep = 0 as i32 });
    (unsafe { (*cur).maxStep = size });
    return cur;
}
extern "C" fn xmlFreeStreamComp(mut comp: xmlStreamCompPtr) {
    if !comp.is_null() {
        if !(unsafe { (*comp).steps }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*comp).steps as *mut libc::c_void) });
        }
        if !(unsafe { (*comp).dict }).is_null() {
            (unsafe { xmlDictFree((*comp).dict) });
        }
        (unsafe { xmlFree.expect("non-null function pointer")(comp as *mut libc::c_void) });
    }
}
extern "C" fn xmlStreamCompAddStep(
    mut comp: xmlStreamCompPtr,
    mut name: *const xmlChar,
    mut ns: *const xmlChar,
    mut nodeType: i32,
    mut flags: i32,
) -> i32 {
    let mut cur: xmlStreamStepPtr = 0 as *mut xmlStreamStep;
    if (unsafe { (*comp).nbStep }) >= (unsafe { (*comp).maxStep }) {
        cur = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*comp).steps as *mut libc::c_void,
            (((*comp).maxStep * 2 as i32) as u64)
                .wrapping_mul(::std::mem::size_of::<xmlStreamStep>() as u64),
        ) }) as xmlStreamStepPtr;
        if cur.is_null() {
            return -(1 as i32);
        }
        let fresh75 = unsafe { &mut ((*comp).steps) };
        *fresh75 = cur;
        (unsafe { (*comp).maxStep *= 2 as i32 });
    }
    let fresh76 = unsafe { &mut ((*comp).nbStep) };
    let fresh77 = *fresh76;
    *fresh76 = *fresh76 + 1;
    cur = (unsafe { &mut *((*comp).steps).offset(fresh77 as isize) }) as *mut xmlStreamStep;
    (unsafe { (*cur).flags = flags });
    let fresh78 = unsafe { &mut ((*cur).name) };
    *fresh78 = name;
    let fresh79 = unsafe { &mut ((*cur).ns) };
    *fresh79 = ns;
    (unsafe { (*cur).nodeType = nodeType });
    return (unsafe { (*comp).nbStep }) - 1 as i32;
}
extern "C" fn xmlStreamCompile(mut comp: xmlPatternPtr) -> i32 {
    let mut current_block: u64;
    let mut stream: xmlStreamCompPtr = 0 as *mut xmlStreamComp;
    let mut i: i32 = 0;
    let mut s: i32 = 0 as i32;
    let mut root: i32 = 0 as i32;
    let mut flags: i32 = 0 as i32;
    let mut prevs: i32 = -(1 as i32);
    let mut step: xmlStepOp = xmlStepOp {
        op: XML_OP_END,
        value: 0 as *const xmlChar,
        value2: 0 as *const xmlChar,
    };
    if comp.is_null() || (unsafe { (*comp).steps }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*comp).nbStep }) == 1 as i32
        && (unsafe { (*((*comp).steps).offset(0 as i32 as isize)).op }) as u32 == XML_OP_ELEM as i32 as u32
        && (unsafe { (*((*comp).steps).offset(0 as i32 as isize)).value }).is_null()
        && (unsafe { (*((*comp).steps).offset(0 as i32 as isize)).value2 }).is_null()
    {
        stream = xmlNewStreamComp(0 as i32);
        if stream.is_null() {
            return -(1 as i32);
        }
        (unsafe { (*stream).flags |= (1 as i32) << 14 as i32 });
        let fresh80 = unsafe { &mut ((*comp).stream) };
        *fresh80 = stream;
        return 0 as i32;
    }
    stream = xmlNewStreamComp((unsafe { (*comp).nbStep }) / 2 as i32 + 1 as i32);
    if stream.is_null() {
        return -(1 as i32);
    }
    if !(unsafe { (*comp).dict }).is_null() {
        let fresh81 = unsafe { &mut ((*stream).dict) };
        *fresh81 = unsafe { (*comp).dict };
        (unsafe { xmlDictReference((*stream).dict) });
    }
    i = 0 as i32;
    if (unsafe { (*comp).flags }) & (1 as i32) << 8 as i32 != 0 {
        (unsafe { (*stream).flags |= (1 as i32) << 15 as i32 });
    }
    loop {
        if !(i < (unsafe { (*comp).nbStep })) {
            current_block = 12264624100856317061;
            break;
        }
        step = unsafe { *((*comp).steps).offset(i as isize) };
        match step.op as u32 {
            1 => {
                if i != 0 as i32 {
                    current_block = 9045084312945070449;
                    break;
                }
                root = 1 as i32;
            }
            7 => {
                s = xmlStreamCompAddStep(
                    stream,
                    0 as *const xmlChar,
                    step.value,
                    XML_ELEMENT_NODE as i32,
                    flags,
                );
                if s < 0 as i32 {
                    current_block = 9045084312945070449;
                    break;
                }
                prevs = s;
                flags = 0 as i32;
            }
            4 => {
                flags |= 8 as i32;
                prevs = -(1 as i32);
                s = xmlStreamCompAddStep(
                    stream,
                    step.value,
                    step.value2,
                    XML_ATTRIBUTE_NODE as i32,
                    flags,
                );
                flags = 0 as i32;
                if s < 0 as i32 {
                    current_block = 9045084312945070449;
                    break;
                }
            }
            2 => {
                if (step.value).is_null() && (step.value2).is_null() {
                    if (unsafe { (*comp).nbStep }) == i + 1 as i32 && flags & 1 as i32 != 0 {
                        if (unsafe { (*comp).nbStep }) == i + 1 as i32 {
                            (unsafe { (*stream).flags |= (1 as i32) << 14 as i32 });
                        }
                        flags |= 16 as i32;
                        s = xmlStreamCompAddStep(
                            stream,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                            100 as i32,
                            flags,
                        );
                        if s < 0 as i32 {
                            current_block = 9045084312945070449;
                            break;
                        }
                        flags = 0 as i32;
                        if prevs != -(1 as i32) {
                            (unsafe { (*((*stream).steps).offset(prevs as isize)).flags |= 32 as i32 });
                            prevs = -(1 as i32);
                        }
                    }
                } else {
                    s = xmlStreamCompAddStep(
                        stream,
                        step.value,
                        step.value2,
                        XML_ELEMENT_NODE as i32,
                        flags,
                    );
                    if s < 0 as i32 {
                        current_block = 9045084312945070449;
                        break;
                    }
                    prevs = s;
                    flags = 0 as i32;
                }
            }
            3 => {
                s = xmlStreamCompAddStep(
                    stream,
                    step.value,
                    step.value2,
                    XML_ELEMENT_NODE as i32,
                    flags,
                );
                if s < 0 as i32 {
                    current_block = 9045084312945070449;
                    break;
                }
                prevs = s;
                flags = 0 as i32;
            }
            8 => {
                s = xmlStreamCompAddStep(
                    stream,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    XML_ELEMENT_NODE as i32,
                    flags,
                );
                if s < 0 as i32 {
                    current_block = 9045084312945070449;
                    break;
                }
                prevs = s;
                flags = 0 as i32;
            }
            6 => {
                if !(flags & 1 as i32 != 0) {
                    flags |= 1 as i32;
                    if (unsafe { (*stream).flags }) & (1 as i32) << 16 as i32 == 0 as i32 {
                        (unsafe { (*stream).flags |= (1 as i32) << 16 as i32 });
                    }
                }
            }
            0 | 5 | _ => {}
        }
        i += 1;
    }
    match current_block {
        12264624100856317061 => {
            if root == 0
                && (unsafe { (*comp).flags })
                    & (XML_PATTERN_XPATH as i32
                        | XML_PATTERN_XSSEL as i32
                        | XML_PATTERN_XSFIELD as i32)
                    == 0 as i32
            {
                if (unsafe { (*stream).flags }) & (1 as i32) << 16 as i32 == 0 as i32 {
                    (unsafe { (*stream).flags |= (1 as i32) << 16 as i32 });
                }
                if (unsafe { (*stream).nbStep }) > 0 as i32 {
                    if (unsafe { (*((*stream).steps).offset(0 as i32 as isize)).flags }) & 1 as i32 == 0 as i32 {
                        (unsafe { (*((*stream).steps).offset(0 as i32 as isize)).flags |= 1 as i32 });
                    }
                }
            }
            if !((unsafe { (*stream).nbStep }) <= s) {
                (unsafe { (*((*stream).steps).offset(s as isize)).flags |= 2 as i32 });
                if root != 0 {
                    (unsafe { (*((*stream).steps).offset(0 as i32 as isize)).flags |= 4 as i32 });
                }
                let fresh82 = unsafe { &mut ((*comp).stream) };
                *fresh82 = stream;
                return 0 as i32;
            }
        }
        _ => {}
    }
    xmlFreeStreamComp(stream);
    return 0 as i32;
}
extern "C" fn xmlNewStreamCtxt(mut stream: xmlStreamCompPtr) -> xmlStreamCtxtPtr {
    let mut cur: xmlStreamCtxtPtr = 0 as *mut xmlStreamCtxt;
    cur = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlStreamCtxt>() as u64
    ) }) as xmlStreamCtxtPtr;
    if cur.is_null() {
        return 0 as xmlStreamCtxtPtr;
    }
    (unsafe { memset(
        cur as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlStreamCtxt>() as u64,
    ) });
    let fresh83 = unsafe { &mut ((*cur).states) };
    *fresh83 = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ((4 as i32 * 2 as i32) as u64).wrapping_mul(::std::mem::size_of::<i32>() as u64),
    ) }) as *mut i32;
    if (unsafe { (*cur).states }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
        return 0 as xmlStreamCtxtPtr;
    }
    (unsafe { (*cur).nbState = 0 as i32 });
    (unsafe { (*cur).maxState = 4 as i32 });
    (unsafe { (*cur).level = 0 as i32 });
    let fresh84 = unsafe { &mut ((*cur).comp) };
    *fresh84 = stream;
    (unsafe { (*cur).blockLevel = -(1 as i32) });
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlFreeStreamCtxt(mut stream: xmlStreamCtxtPtr) {
    let mut next: xmlStreamCtxtPtr = 0 as *mut xmlStreamCtxt;
    while !stream.is_null() {
        next = unsafe { (*stream).next };
        if !(unsafe { (*stream).states }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*stream).states as *mut libc::c_void) });
        }
        (unsafe { xmlFree.expect("non-null function pointer")(stream as *mut libc::c_void) });
        stream = next;
    }
}
extern "C" fn xmlStreamCtxtAddState(
    mut comp: xmlStreamCtxtPtr,
    mut idx: i32,
    mut level: i32,
) -> i32 {
    let mut i: i32 = 0;
    i = 0 as i32;
    while i < (unsafe { (*comp).nbState }) {
        if (unsafe { *((*comp).states).offset((2 as i32 * i) as isize) }) < 0 as i32 {
            (unsafe { *((*comp).states).offset((2 as i32 * i) as isize) = idx });
            (unsafe { *((*comp).states).offset((2 as i32 * i + 1 as i32) as isize) = level });
            return i;
        }
        i += 1;
    }
    if (unsafe { (*comp).nbState }) >= (unsafe { (*comp).maxState }) {
        let mut cur: *mut i32 = 0 as *mut i32;
        cur = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*comp).states as *mut libc::c_void,
            (((*comp).maxState * 4 as i32) as u64)
                .wrapping_mul(::std::mem::size_of::<i32>() as u64),
        ) }) as *mut i32;
        if cur.is_null() {
            return -(1 as i32);
        }
        let fresh85 = unsafe { &mut ((*comp).states) };
        *fresh85 = cur;
        (unsafe { (*comp).maxState *= 2 as i32 });
    }
    (unsafe { *((*comp).states).offset((2 as i32 * (*comp).nbState) as isize) = idx });
    let fresh86 = unsafe { &mut ((*comp).nbState) };
    let fresh87 = *fresh86;
    *fresh86 = *fresh86 + 1;
    (unsafe { *((*comp).states).offset((2 as i32 * fresh87 + 1 as i32) as isize) = level });
    return (unsafe { (*comp).nbState }) - 1 as i32;
}
extern "C" fn xmlStreamPushInternal(
    mut stream: xmlStreamCtxtPtr,
    mut name: *const xmlChar,
    mut ns: *const xmlChar,
    mut nodeType: i32,
) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 0 as i32;
    let mut err: i32 = 0 as i32;
    let mut final_0: i32 = 0 as i32;
    let mut tmp: i32 = 0;
    let mut i: i32 = 0;
    let mut m: i32 = 0;
    let mut match_0: i32 = 0;
    let mut stepNr: i32 = 0;
    let mut desc: i32 = 0;
    let mut comp: xmlStreamCompPtr = 0 as *mut xmlStreamComp;
    let mut step: xmlStreamStep = xmlStreamStep {
        flags: 0,
        name: 0 as *const xmlChar,
        ns: 0 as *const xmlChar,
        nodeType: 0,
    };
    if stream.is_null() || (unsafe { (*stream).nbState }) < 0 as i32 {
        return -(1 as i32);
    }
    while !stream.is_null() {
        comp = unsafe { (*stream).comp };
        if nodeType == XML_ELEMENT_NODE as i32 && name.is_null() && ns.is_null() {
            (unsafe { (*stream).nbState = 0 as i32 });
            (unsafe { (*stream).level = 0 as i32 });
            (unsafe { (*stream).blockLevel = -(1 as i32) });
            if (unsafe { (*comp).flags }) & (1 as i32) << 15 as i32 != 0 {
                if (unsafe { (*comp).nbStep }) == 0 as i32 {
                    ret = 1 as i32;
                } else if (unsafe { (*comp).nbStep }) == 1 as i32
                    && (unsafe { (*((*comp).steps).offset(0 as i32 as isize)).nodeType }) == 100 as i32
                    && (unsafe { (*((*comp).steps).offset(0 as i32 as isize)).flags }) & 1 as i32 != 0
                {
                    ret = 1 as i32;
                } else if (unsafe { (*((*comp).steps).offset(0 as i32 as isize)).flags }) & 4 as i32 != 0 {
                    tmp = xmlStreamCtxtAddState(stream, 0 as i32, 0 as i32);
                    if tmp < 0 as i32 {
                        err += 1;
                    }
                }
            }
            stream = unsafe { (*stream).next };
        } else {
            if (unsafe { (*comp).nbStep }) == 0 as i32 {
                if (unsafe { (*stream).flags }) & XML_PATTERN_XPATH as i32 != 0 {
                    stream = unsafe { (*stream).next };
                    continue;
                } else {
                    if nodeType != XML_ATTRIBUTE_NODE as i32
                        && ((unsafe { (*stream).flags })
                            & (XML_PATTERN_XPATH as i32
                                | XML_PATTERN_XSSEL as i32
                                | XML_PATTERN_XSFIELD as i32)
                            == 0 as i32
                            || (unsafe { (*stream).level }) == 0 as i32)
                    {
                        ret = 1 as i32;
                    }
                    let fresh88 = unsafe { &mut ((*stream).level) };
                    *fresh88 += 1;
                }
            } else if (unsafe { (*stream).blockLevel }) != -(1 as i32) {
                let fresh89 = unsafe { &mut ((*stream).level) };
                *fresh89 += 1;
            } else if nodeType != XML_ELEMENT_NODE as i32
                && nodeType != XML_ATTRIBUTE_NODE as i32
                && (unsafe { (*comp).flags }) & (1 as i32) << 14 as i32 == 0 as i32
            {
                let fresh90 = unsafe { &mut ((*stream).level) };
                *fresh90 += 1;
            } else {
                i = 0 as i32;
                m = unsafe { (*stream).nbState };
                while i < m {
                    if (unsafe { (*comp).flags }) & (1 as i32) << 16 as i32 == 0 as i32 {
                        stepNr = unsafe { *((*stream).states)
                            .offset((2 as i32 * ((*stream).nbState - 1 as i32)) as isize) };
                        if (unsafe { *((*stream).states)
                            .offset((2 as i32 * ((*stream).nbState - 1 as i32) + 1 as i32) as isize) })
                            < (unsafe { (*stream).level })
                        {
                            return -(1 as i32);
                        }
                        desc = 0 as i32;
                        i = m;
                        current_block = 2516253395664191498;
                    } else {
                        stepNr = unsafe { *((*stream).states).offset((2 as i32 * i) as isize) };
                        if stepNr < 0 as i32 {
                            current_block = 11581334008138293573;
                        } else {
                            tmp = unsafe { *((*stream).states).offset((2 as i32 * i + 1 as i32) as isize) };
                            if tmp > (unsafe { (*stream).level }) {
                                current_block = 11581334008138293573;
                            } else {
                                desc = (unsafe { (*((*comp).steps).offset(stepNr as isize)).flags }) & 1 as i32;
                                if tmp < (unsafe { (*stream).level }) && desc == 0 {
                                    current_block = 11581334008138293573;
                                } else {
                                    current_block = 2516253395664191498;
                                }
                            }
                        }
                    }
                    match current_block {
                        2516253395664191498 => {
                            step = unsafe { *((*comp).steps).offset(stepNr as isize) };
                            if step.nodeType != nodeType {
                                if step.nodeType == XML_ATTRIBUTE_NODE as i32 {
                                    if (unsafe { (*comp).flags }) & (1 as i32) << 16 as i32 == 0 as i32 {
                                        (unsafe { (*stream).blockLevel = (*stream).level + 1 as i32 });
                                    }
                                    current_block = 11581334008138293573;
                                } else if step.nodeType != 100 as i32 {
                                    current_block = 11581334008138293573;
                                } else {
                                    current_block = 4741994311446740739;
                                }
                            } else {
                                current_block = 4741994311446740739;
                            }
                            match current_block {
                                11581334008138293573 => {}
                                _ => {
                                    match_0 = 0 as i32;
                                    if step.nodeType == 100 as i32 {
                                        match_0 = 1 as i32;
                                    } else if (step.name).is_null() {
                                        if (step.ns).is_null() {
                                            match_0 = 1 as i32;
                                        } else if !ns.is_null() {
                                            match_0 = unsafe { xmlStrEqual(step.ns, ns) };
                                        }
                                    } else if (step.ns != 0 as *mut libc::c_void as *const xmlChar)
                                        as i32
                                        == (ns != 0 as *mut libc::c_void as *const xmlChar) as i32
                                        && !name.is_null()
                                        && (unsafe { *(step.name).offset(0 as i32 as isize) }) as i32
                                            == (unsafe { *name.offset(0 as i32 as isize) }) as i32
                                        && (unsafe { xmlStrEqual(step.name, name) }) != 0
                                        && (step.ns == ns || (unsafe { xmlStrEqual(step.ns, ns) }) != 0)
                                    {
                                        match_0 = 1 as i32;
                                    }
                                    if match_0 != 0 {
                                        final_0 = step.flags & 2 as i32;
                                        if desc != 0 {
                                            if final_0 != 0 {
                                                ret = 1 as i32;
                                            } else {
                                                xmlStreamCtxtAddState(
                                                    stream,
                                                    stepNr + 1 as i32,
                                                    (unsafe { (*stream).level }) + 1 as i32,
                                                );
                                            }
                                        } else if final_0 != 0 {
                                            ret = 1 as i32;
                                        } else {
                                            xmlStreamCtxtAddState(
                                                stream,
                                                stepNr + 1 as i32,
                                                (unsafe { (*stream).level }) + 1 as i32,
                                            );
                                        }
                                        if ret != 1 as i32 && step.flags & 32 as i32 != 0 {
                                            ret = 1 as i32;
                                        }
                                    }
                                    if (unsafe { (*comp).flags }) & (1 as i32) << 16 as i32 == 0 as i32
                                        && (match_0 == 0 || final_0 != 0)
                                    {
                                        (unsafe { (*stream).blockLevel = (*stream).level + 1 as i32 });
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                let fresh91 = unsafe { &mut ((*stream).level) };
                *fresh91 += 1;
                step = unsafe { *((*comp).steps).offset(0 as i32 as isize) };
                if !(step.flags & 4 as i32 != 0) {
                    desc = step.flags & 1 as i32;
                    if (unsafe { (*stream).flags })
                        & (XML_PATTERN_XPATH as i32
                            | XML_PATTERN_XSSEL as i32
                            | XML_PATTERN_XSFIELD as i32)
                        != 0
                    {
                        if (unsafe { (*stream).level }) == 1 as i32 {
                            if (unsafe { (*stream).flags })
                                & (XML_PATTERN_XSSEL as i32 | XML_PATTERN_XSFIELD as i32)
                                != 0
                            {
                                current_block = 9048011128714838703;
                            } else {
                                current_block = 14442360071374423104;
                            }
                        } else if desc != 0 {
                            current_block = 14442360071374423104;
                        } else if (unsafe { (*stream).level }) == 2 as i32
                            && (unsafe { (*stream).flags })
                                & (XML_PATTERN_XSSEL as i32 | XML_PATTERN_XSFIELD as i32)
                                != 0
                        {
                            current_block = 14442360071374423104;
                        } else {
                            current_block = 9048011128714838703;
                        }
                    } else {
                        current_block = 14442360071374423104;
                    }
                    match current_block {
                        9048011128714838703 => {}
                        _ => {
                            if step.nodeType != nodeType {
                                if nodeType == XML_ATTRIBUTE_NODE as i32 {
                                    current_block = 9048011128714838703;
                                } else if step.nodeType != 100 as i32 {
                                    current_block = 9048011128714838703;
                                } else {
                                    current_block = 11674240781755647963;
                                }
                            } else {
                                current_block = 11674240781755647963;
                            }
                            match current_block {
                                9048011128714838703 => {}
                                _ => {
                                    match_0 = 0 as i32;
                                    if step.nodeType == 100 as i32 {
                                        match_0 = 1 as i32;
                                    } else if (step.name).is_null() {
                                        if (step.ns).is_null() {
                                            match_0 = 1 as i32;
                                        } else if !ns.is_null() {
                                            match_0 = unsafe { xmlStrEqual(step.ns, ns) };
                                        }
                                    } else if (step.ns != 0 as *mut libc::c_void as *const xmlChar)
                                        as i32
                                        == (ns != 0 as *mut libc::c_void as *const xmlChar) as i32
                                        && !name.is_null()
                                        && (unsafe { *(step.name).offset(0 as i32 as isize) }) as i32
                                            == (unsafe { *name.offset(0 as i32 as isize) }) as i32
                                        && (unsafe { xmlStrEqual(step.name, name) }) != 0
                                        && (step.ns == ns || (unsafe { xmlStrEqual(step.ns, ns) }) != 0)
                                    {
                                        match_0 = 1 as i32;
                                    }
                                    final_0 = step.flags & 2 as i32;
                                    if match_0 != 0 {
                                        if final_0 != 0 {
                                            ret = 1 as i32;
                                        } else {
                                            xmlStreamCtxtAddState(
                                                stream,
                                                1 as i32,
                                                unsafe { (*stream).level },
                                            );
                                        }
                                        if ret != 1 as i32 && step.flags & 32 as i32 != 0 {
                                            ret = 1 as i32;
                                        }
                                    }
                                    if (unsafe { (*comp).flags }) & (1 as i32) << 16 as i32 == 0 as i32
                                        && (match_0 == 0 || final_0 != 0)
                                    {
                                        (unsafe { (*stream).blockLevel = (*stream).level });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            stream = unsafe { (*stream).next };
        }
    }
    if err > 0 as i32 {
        ret = -(1 as i32);
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlStreamPush(
    mut stream: xmlStreamCtxtPtr,
    mut name: *const xmlChar,
    mut ns: *const xmlChar,
) -> i32 {
    return xmlStreamPushInternal(stream, name, ns, XML_ELEMENT_NODE as i32);
}
#[no_mangle]
pub extern "C" fn xmlStreamPushNode(
    mut stream: xmlStreamCtxtPtr,
    mut name: *const xmlChar,
    mut ns: *const xmlChar,
    mut nodeType: i32,
) -> i32 {
    return xmlStreamPushInternal(stream, name, ns, nodeType);
}
#[no_mangle]
pub extern "C" fn xmlStreamPushAttr(
    mut stream: xmlStreamCtxtPtr,
    mut name: *const xmlChar,
    mut ns: *const xmlChar,
) -> i32 {
    return xmlStreamPushInternal(stream, name, ns, XML_ATTRIBUTE_NODE as i32);
}
#[no_mangle]
pub extern "C" fn xmlStreamPop(mut stream: xmlStreamCtxtPtr) -> i32 {
    let mut i: i32 = 0;
    let mut lev: i32 = 0;
    if stream.is_null() {
        return -(1 as i32);
    }
    while !stream.is_null() {
        if (unsafe { (*stream).blockLevel }) == (unsafe { (*stream).level }) {
            (unsafe { (*stream).blockLevel = -(1 as i32) });
        }
        if (unsafe { (*stream).level }) != 0 {
            let fresh92 = unsafe { &mut ((*stream).level) };
            *fresh92 -= 1;
        }
        i = (unsafe { (*stream).nbState }) - 1 as i32;
        while i >= 0 as i32 {
            lev = unsafe { *((*stream).states).offset((2 as i32 * i + 1 as i32) as isize) };
            if lev > (unsafe { (*stream).level }) {
                let fresh93 = unsafe { &mut ((*stream).nbState) };
                *fresh93 -= 1;
            }
            if lev <= (unsafe { (*stream).level }) {
                break;
            }
            i -= 1;
        }
        stream = unsafe { (*stream).next };
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlStreamWantsAnyNode(mut streamCtxt: xmlStreamCtxtPtr) -> i32 {
    if streamCtxt.is_null() {
        return -(1 as i32);
    }
    while !streamCtxt.is_null() {
        if (unsafe { (*(*streamCtxt).comp).flags }) & (1 as i32) << 14 as i32 != 0 {
            return 1 as i32;
        }
        streamCtxt = unsafe { (*streamCtxt).next };
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlPatterncompile(
    mut pattern: *const xmlChar,
    mut dict: *mut xmlDict,
    mut flags: i32,
    mut namespaces: *mut *const xmlChar,
) -> xmlPatternPtr {
    let mut current_block: u64;
    let mut ret: xmlPatternPtr = 0 as xmlPatternPtr;
    let mut cur: xmlPatternPtr = 0 as *mut xmlPattern;
    let mut ctxt: xmlPatParserContextPtr = 0 as xmlPatParserContextPtr;
    let mut or: *const xmlChar = 0 as *const xmlChar;
    let mut start: *const xmlChar = 0 as *const xmlChar;
    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
    let mut type_0: i32 = 0 as i32;
    let mut streamable: i32 = 1 as i32;
    if pattern.is_null() {
        return 0 as xmlPatternPtr;
    }
    start = pattern;
    or = start;
    loop {
        if !((unsafe { *or }) as i32 != 0 as i32) {
            current_block = 10380409671385728102;
            break;
        }
        tmp = 0 as *mut xmlChar;
        while (unsafe { *or }) as i32 != 0 as i32 && (unsafe { *or }) as i32 != '|' as i32 {
            or = unsafe { or.offset(1) };
        }
        if (unsafe { *or }) as i32 == 0 as i32 {
            ctxt = xmlNewPatParserContext(start, dict, namespaces);
        } else {
            tmp = unsafe { xmlStrndup(start, or.offset_from(start) as i64 as i32) };
            if !tmp.is_null() {
                ctxt = xmlNewPatParserContext(tmp, dict, namespaces);
            }
            or = unsafe { or.offset(1) };
        }
        if ctxt.is_null() {
            current_block = 13522574393598791978;
            break;
        }
        cur = xmlNewPattern();
        if cur.is_null() {
            current_block = 13522574393598791978;
            break;
        }
        if !dict.is_null() {
            let fresh94 = unsafe { &mut ((*cur).dict) };
            *fresh94 = dict;
            (unsafe { xmlDictReference(dict) });
        }
        if ret.is_null() {
            ret = cur;
        } else {
            let fresh95 = unsafe { &mut ((*cur).next) };
            *fresh95 = unsafe { (*ret).next };
            let fresh96 = unsafe { &mut ((*ret).next) };
            *fresh96 = cur;
        }
        (unsafe { (*cur).flags = flags });
        let fresh97 = unsafe { &mut ((*ctxt).comp) };
        *fresh97 = cur;
        if (unsafe { (*cur).flags }) & (XML_PATTERN_XSSEL as i32 | XML_PATTERN_XSFIELD as i32) != 0 {
            xmlCompileIDCXPathPath(ctxt);
        } else {
            xmlCompilePathPattern(ctxt);
        }
        if (unsafe { (*ctxt).error }) != 0 as i32 {
            current_block = 13522574393598791978;
            break;
        }
        xmlFreePatParserContext(ctxt);
        ctxt = 0 as xmlPatParserContextPtr;
        if streamable != 0 {
            if type_0 == 0 as i32 {
                type_0 = (unsafe { (*cur).flags }) & ((1 as i32) << 8 as i32 | (1 as i32) << 9 as i32);
            } else if type_0 == (1 as i32) << 8 as i32 {
                if (unsafe { (*cur).flags }) & (1 as i32) << 9 as i32 != 0 {
                    streamable = 0 as i32;
                }
            } else if type_0 == (1 as i32) << 9 as i32 {
                if (unsafe { (*cur).flags }) & (1 as i32) << 8 as i32 != 0 {
                    streamable = 0 as i32;
                }
            }
        }
        if streamable != 0 {
            xmlStreamCompile(cur);
        }
        if xmlReversePattern(cur) < 0 as i32 {
            current_block = 13522574393598791978;
            break;
        }
        if !tmp.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
            tmp = 0 as *mut xmlChar;
        }
        start = or;
    }
    match current_block {
        13522574393598791978 => {
            if !ctxt.is_null() {
                xmlFreePatParserContext(ctxt);
            }
            if !ret.is_null() {
                xmlFreePattern(ret);
            }
            if !tmp.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
            }
            return 0 as xmlPatternPtr;
        }
        _ => {
            if streamable == 0 as i32 {
                cur = ret;
                while !cur.is_null() {
                    if !(unsafe { (*cur).stream }).is_null() {
                        xmlFreeStreamComp(unsafe { (*cur).stream });
                        let fresh98 = unsafe { &mut ((*cur).stream) };
                        *fresh98 = 0 as xmlStreamCompPtr;
                    }
                    cur = unsafe { (*cur).next };
                }
            }
            return ret;
        }
    };
}
#[no_mangle]
pub extern "C" fn xmlPatternMatch(mut comp: xmlPatternPtr, mut node: xmlNodePtr) -> i32 {
    let mut ret: i32 = 0 as i32;
    if comp.is_null() || node.is_null() {
        return -(1 as i32);
    }
    while !comp.is_null() {
        ret = xmlPatMatch(comp, node);
        if ret != 0 as i32 {
            return ret;
        }
        comp = unsafe { (*comp).next };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlPatternGetStreamCtxt(mut comp: xmlPatternPtr) -> xmlStreamCtxtPtr {
    let mut current_block: u64;
    let mut ret: xmlStreamCtxtPtr = 0 as xmlStreamCtxtPtr;
    let mut cur: xmlStreamCtxtPtr = 0 as *mut xmlStreamCtxt;
    if comp.is_null() || (unsafe { (*comp).stream }).is_null() {
        return 0 as xmlStreamCtxtPtr;
    }
    loop {
        if comp.is_null() {
            current_block = 11050875288958768710;
            break;
        }
        if (unsafe { (*comp).stream }).is_null() {
            current_block = 11925268974377416611;
            break;
        }
        cur = xmlNewStreamCtxt(unsafe { (*comp).stream });
        if cur.is_null() {
            current_block = 11925268974377416611;
            break;
        }
        if ret.is_null() {
            ret = cur;
        } else {
            let fresh99 = unsafe { &mut ((*cur).next) };
            *fresh99 = unsafe { (*ret).next };
            let fresh100 = unsafe { &mut ((*ret).next) };
            *fresh100 = cur;
        }
        (unsafe { (*cur).flags = (*comp).flags });
        comp = unsafe { (*comp).next };
    }
    match current_block {
        11050875288958768710 => return ret,
        _ => {
            xmlFreeStreamCtxt(ret);
            return 0 as xmlStreamCtxtPtr;
        }
    };
}
#[no_mangle]
pub extern "C" fn xmlPatternStreamable(mut comp: xmlPatternPtr) -> i32 {
    if comp.is_null() {
        return -(1 as i32);
    }
    while !comp.is_null() {
        if (unsafe { (*comp).stream }).is_null() {
            return 0 as i32;
        }
        comp = unsafe { (*comp).next };
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlPatternMaxDepth(mut comp: xmlPatternPtr) -> i32 {
    let mut ret: i32 = 0 as i32;
    let mut i: i32 = 0;
    if comp.is_null() {
        return -(1 as i32);
    }
    while !comp.is_null() {
        if (unsafe { (*comp).stream }).is_null() {
            return -(1 as i32);
        }
        i = 0 as i32;
        while i < (unsafe { (*(*comp).stream).nbStep }) {
            if (unsafe { (*((*(*comp).stream).steps).offset(i as isize)).flags }) & 1 as i32 != 0 {
                return -(2 as i32);
            }
            i += 1;
        }
        if (unsafe { (*(*comp).stream).nbStep }) > ret {
            ret = unsafe { (*(*comp).stream).nbStep };
        }
        comp = unsafe { (*comp).next };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlPatternMinDepth(mut comp: xmlPatternPtr) -> i32 {
    let mut ret: i32 = 12345678 as i32;
    if comp.is_null() {
        return -(1 as i32);
    }
    while !comp.is_null() {
        if (unsafe { (*comp).stream }).is_null() {
            return -(1 as i32);
        }
        if (unsafe { (*(*comp).stream).nbStep }) < ret {
            ret = unsafe { (*(*comp).stream).nbStep };
        }
        if ret == 0 as i32 {
            return 0 as i32;
        }
        comp = unsafe { (*comp).next };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlPatternFromRoot(mut comp: xmlPatternPtr) -> i32 {
    if comp.is_null() {
        return -(1 as i32);
    }
    while !comp.is_null() {
        if (unsafe { (*comp).stream }).is_null() {
            return -(1 as i32);
        }
        if (unsafe { (*comp).flags }) & (1 as i32) << 8 as i32 != 0 {
            return 1 as i32;
        }
        comp = unsafe { (*comp).next };
    }
    return 0 as i32;
}
