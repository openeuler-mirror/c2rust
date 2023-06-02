use :: libc;
extern "C" {
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlStartTag;
    pub type _xmlBuf;
    pub type _xmlAutomataState;
    pub type _xmlAutomata;
    pub type _xmlValidState;
    fn vsnprintf(_: *mut i8, _: u64, _: *const i8, _: ::std::ffi::VaList) -> i32;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn strlen(_: *const i8) -> u64;
    static mut xmlFree: xmlFreeFunc;
    static mut xmlMalloc: xmlMallocFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlMallocAtomic: xmlMallocFunc;
    fn xmlErrMemory(ctxt: xmlParserCtxtPtr, extra: *const i8);
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: u32,
    pub fp_offset: u32,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type va_list = __builtin_va_list;
pub type xmlChar = u8;
pub type xmlParserCtxtPtr = *mut xmlParserCtxt;
pub type xmlParserCtxt = _xmlParserCtxt;
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
pub type xmlParserInputPtr = *mut xmlParserInput;
pub type xmlParserInput = _xmlParserInput;
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
pub type xmlParserInputBufferPtr = *mut xmlParserInputBuffer;
pub type xmlParserInputBuffer = _xmlParserInputBuffer;
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
pub type size_t = u64;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type xmlReallocFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void>;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
#[no_mangle]
pub extern "C" fn xmlStrndup(mut cur: *const xmlChar, mut len: i32) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if cur.is_null() || len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    ret = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
        (len as size_t)
            .wrapping_add(1 as i32 as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) }) as *mut xmlChar;
    if ret.is_null() {
        (unsafe { xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8) });
        return 0 as *mut xmlChar;
    }
    (unsafe { memcpy(
        ret as *mut libc::c_void,
        cur as *const libc::c_void,
        (len as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) });
    (unsafe { *ret.offset(len as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlStrdup(mut cur: *const xmlChar) -> *mut xmlChar {
    let mut p: *const xmlChar = cur;
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    while (unsafe { *p }) as i32 != 0 as i32 {
        p = unsafe { p.offset(1) };
    }
    return xmlStrndup(cur, (unsafe { p.offset_from(cur) }) as i64 as i32);
}
#[no_mangle]
pub extern "C" fn xmlCharStrndup(mut cur: *const i8, mut len: i32) -> *mut xmlChar {
    let mut i: i32 = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if cur.is_null() || len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    ret = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
        (len as size_t)
            .wrapping_add(1 as i32 as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) }) as *mut xmlChar;
    if ret.is_null() {
        (unsafe { xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8) });
        return 0 as *mut xmlChar;
    }
    i = 0 as i32;
    while i < len {
        (unsafe { *ret.offset(i as isize) = *cur.offset(i as isize) as xmlChar });
        if (unsafe { *ret.offset(i as isize) }) as i32 == 0 as i32 {
            return ret;
        }
        i += 1;
    }
    (unsafe { *ret.offset(len as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCharStrdup(mut cur: *const i8) -> *mut xmlChar {
    let mut p: *const i8 = cur;
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    while (unsafe { *p }) as i32 != '\u{0}' as i32 {
        p = unsafe { p.offset(1) };
    }
    return xmlCharStrndup(cur, (unsafe { p.offset_from(cur) }) as i64 as i32);
}
#[no_mangle]
pub extern "C" fn xmlStrcmp(mut str1: *const xmlChar, mut str2: *const xmlChar) -> i32 {
    if str1 == str2 {
        return 0 as i32;
    }
    if str1.is_null() {
        return -(1 as i32);
    }
    if str2.is_null() {
        return 1 as i32;
    }
    loop {
        let fresh0 = str1;
        str1 = unsafe { str1.offset(1) };
        let mut tmp: i32 = (unsafe { *fresh0 }) as i32 - (unsafe { *str2 }) as i32;
        if tmp != 0 as i32 {
            return tmp;
        }
        let fresh1 = str2;
        str2 = unsafe { str2.offset(1) };
        if !((unsafe { *fresh1 }) as i32 != 0 as i32) {
            break;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlStrEqual(mut str1: *const xmlChar, mut str2: *const xmlChar) -> i32 {
    if str1 == str2 {
        return 1 as i32;
    }
    if str1.is_null() {
        return 0 as i32;
    }
    if str2.is_null() {
        return 0 as i32;
    }
    loop {
        let fresh2 = str1;
        str1 = unsafe { str1.offset(1) };
        if (unsafe { *fresh2 }) as i32 != (unsafe { *str2 }) as i32 {
            return 0 as i32;
        }
        let fresh3 = str2;
        str2 = unsafe { str2.offset(1) };
        if !((unsafe { *fresh3 }) != 0) {
            break;
        }
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlStrQEqual(
    mut pref: *const xmlChar,
    mut name: *const xmlChar,
    mut str: *const xmlChar,
) -> i32 {
    if pref.is_null() {
        return xmlStrEqual(name, str);
    }
    if name.is_null() {
        return 0 as i32;
    }
    if str.is_null() {
        return 0 as i32;
    }
    loop {
        let fresh4 = pref;
        pref = unsafe { pref.offset(1) };
        if (unsafe { *fresh4 }) as i32 != (unsafe { *str }) as i32 {
            return 0 as i32;
        }
        let fresh5 = str;
        str = unsafe { str.offset(1) };
        if !((unsafe { *fresh5 }) as i32 != 0 && (unsafe { *pref }) as i32 != 0) {
            break;
        }
    }
    let fresh6 = str;
    str = unsafe { str.offset(1) };
    if (unsafe { *fresh6 }) as i32 != ':' as i32 {
        return 0 as i32;
    }
    loop {
        let fresh7 = name;
        name = unsafe { name.offset(1) };
        if (unsafe { *fresh7 }) as i32 != (unsafe { *str }) as i32 {
            return 0 as i32;
        }
        let fresh8 = str;
        str = unsafe { str.offset(1) };
        if !((unsafe { *fresh8 }) != 0) {
            break;
        }
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlStrncmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut len: i32,
) -> i32 {
    if len <= 0 as i32 {
        return 0 as i32;
    }
    if str1 == str2 {
        return 0 as i32;
    }
    if str1.is_null() {
        return -(1 as i32);
    }
    if str2.is_null() {
        return 1 as i32;
    }
    loop {
        let fresh9 = str1;
        str1 = unsafe { str1.offset(1) };
        let mut tmp: i32 = (unsafe { *fresh9 }) as i32 - (unsafe { *str2 }) as i32;
        if tmp != 0 as i32 || {
            len -= 1;
            len == 0 as i32
        } {
            return tmp;
        }
        let fresh10 = str2;
        str2 = unsafe { str2.offset(1) };
        if !((unsafe { *fresh10 }) as i32 != 0 as i32) {
            break;
        }
    }
    return 0 as i32;
}
static mut casemap: [xmlChar; 256] = [
    0 as i32 as xmlChar,
    0x1 as i32 as xmlChar,
    0x2 as i32 as xmlChar,
    0x3 as i32 as xmlChar,
    0x4 as i32 as xmlChar,
    0x5 as i32 as xmlChar,
    0x6 as i32 as xmlChar,
    0x7 as i32 as xmlChar,
    0x8 as i32 as xmlChar,
    0x9 as i32 as xmlChar,
    0xa as i32 as xmlChar,
    0xb as i32 as xmlChar,
    0xc as i32 as xmlChar,
    0xd as i32 as xmlChar,
    0xe as i32 as xmlChar,
    0xf as i32 as xmlChar,
    0x10 as i32 as xmlChar,
    0x11 as i32 as xmlChar,
    0x12 as i32 as xmlChar,
    0x13 as i32 as xmlChar,
    0x14 as i32 as xmlChar,
    0x15 as i32 as xmlChar,
    0x16 as i32 as xmlChar,
    0x17 as i32 as xmlChar,
    0x18 as i32 as xmlChar,
    0x19 as i32 as xmlChar,
    0x1a as i32 as xmlChar,
    0x1b as i32 as xmlChar,
    0x1c as i32 as xmlChar,
    0x1d as i32 as xmlChar,
    0x1e as i32 as xmlChar,
    0x1f as i32 as xmlChar,
    0x20 as i32 as xmlChar,
    0x21 as i32 as xmlChar,
    0x22 as i32 as xmlChar,
    0x23 as i32 as xmlChar,
    0x24 as i32 as xmlChar,
    0x25 as i32 as xmlChar,
    0x26 as i32 as xmlChar,
    0x27 as i32 as xmlChar,
    0x28 as i32 as xmlChar,
    0x29 as i32 as xmlChar,
    0x2a as i32 as xmlChar,
    0x2b as i32 as xmlChar,
    0x2c as i32 as xmlChar,
    0x2d as i32 as xmlChar,
    0x2e as i32 as xmlChar,
    0x2f as i32 as xmlChar,
    0x30 as i32 as xmlChar,
    0x31 as i32 as xmlChar,
    0x32 as i32 as xmlChar,
    0x33 as i32 as xmlChar,
    0x34 as i32 as xmlChar,
    0x35 as i32 as xmlChar,
    0x36 as i32 as xmlChar,
    0x37 as i32 as xmlChar,
    0x38 as i32 as xmlChar,
    0x39 as i32 as xmlChar,
    0x3a as i32 as xmlChar,
    0x3b as i32 as xmlChar,
    0x3c as i32 as xmlChar,
    0x3d as i32 as xmlChar,
    0x3e as i32 as xmlChar,
    0x3f as i32 as xmlChar,
    0x40 as i32 as xmlChar,
    0x61 as i32 as xmlChar,
    0x62 as i32 as xmlChar,
    0x63 as i32 as xmlChar,
    0x64 as i32 as xmlChar,
    0x65 as i32 as xmlChar,
    0x66 as i32 as xmlChar,
    0x67 as i32 as xmlChar,
    0x68 as i32 as xmlChar,
    0x69 as i32 as xmlChar,
    0x6a as i32 as xmlChar,
    0x6b as i32 as xmlChar,
    0x6c as i32 as xmlChar,
    0x6d as i32 as xmlChar,
    0x6e as i32 as xmlChar,
    0x6f as i32 as xmlChar,
    0x70 as i32 as xmlChar,
    0x71 as i32 as xmlChar,
    0x72 as i32 as xmlChar,
    0x73 as i32 as xmlChar,
    0x74 as i32 as xmlChar,
    0x75 as i32 as xmlChar,
    0x76 as i32 as xmlChar,
    0x77 as i32 as xmlChar,
    0x78 as i32 as xmlChar,
    0x79 as i32 as xmlChar,
    0x7a as i32 as xmlChar,
    0x7b as i32 as xmlChar,
    0x5c as i32 as xmlChar,
    0x5d as i32 as xmlChar,
    0x5e as i32 as xmlChar,
    0x5f as i32 as xmlChar,
    0x60 as i32 as xmlChar,
    0x61 as i32 as xmlChar,
    0x62 as i32 as xmlChar,
    0x63 as i32 as xmlChar,
    0x64 as i32 as xmlChar,
    0x65 as i32 as xmlChar,
    0x66 as i32 as xmlChar,
    0x67 as i32 as xmlChar,
    0x68 as i32 as xmlChar,
    0x69 as i32 as xmlChar,
    0x6a as i32 as xmlChar,
    0x6b as i32 as xmlChar,
    0x6c as i32 as xmlChar,
    0x6d as i32 as xmlChar,
    0x6e as i32 as xmlChar,
    0x6f as i32 as xmlChar,
    0x70 as i32 as xmlChar,
    0x71 as i32 as xmlChar,
    0x72 as i32 as xmlChar,
    0x73 as i32 as xmlChar,
    0x74 as i32 as xmlChar,
    0x75 as i32 as xmlChar,
    0x76 as i32 as xmlChar,
    0x77 as i32 as xmlChar,
    0x78 as i32 as xmlChar,
    0x79 as i32 as xmlChar,
    0x7a as i32 as xmlChar,
    0x7b as i32 as xmlChar,
    0x7c as i32 as xmlChar,
    0x7d as i32 as xmlChar,
    0x7e as i32 as xmlChar,
    0x7f as i32 as xmlChar,
    0x80 as i32 as xmlChar,
    0x81 as i32 as xmlChar,
    0x82 as i32 as xmlChar,
    0x83 as i32 as xmlChar,
    0x84 as i32 as xmlChar,
    0x85 as i32 as xmlChar,
    0x86 as i32 as xmlChar,
    0x87 as i32 as xmlChar,
    0x88 as i32 as xmlChar,
    0x89 as i32 as xmlChar,
    0x8a as i32 as xmlChar,
    0x8b as i32 as xmlChar,
    0x8c as i32 as xmlChar,
    0x8d as i32 as xmlChar,
    0x8e as i32 as xmlChar,
    0x8f as i32 as xmlChar,
    0x90 as i32 as xmlChar,
    0x91 as i32 as xmlChar,
    0x92 as i32 as xmlChar,
    0x93 as i32 as xmlChar,
    0x94 as i32 as xmlChar,
    0x95 as i32 as xmlChar,
    0x96 as i32 as xmlChar,
    0x97 as i32 as xmlChar,
    0x98 as i32 as xmlChar,
    0x99 as i32 as xmlChar,
    0x9a as i32 as xmlChar,
    0x9b as i32 as xmlChar,
    0x9c as i32 as xmlChar,
    0x9d as i32 as xmlChar,
    0x9e as i32 as xmlChar,
    0x9f as i32 as xmlChar,
    0xa0 as i32 as xmlChar,
    0xa1 as i32 as xmlChar,
    0xa2 as i32 as xmlChar,
    0xa3 as i32 as xmlChar,
    0xa4 as i32 as xmlChar,
    0xa5 as i32 as xmlChar,
    0xa6 as i32 as xmlChar,
    0xa7 as i32 as xmlChar,
    0xa8 as i32 as xmlChar,
    0xa9 as i32 as xmlChar,
    0xaa as i32 as xmlChar,
    0xab as i32 as xmlChar,
    0xac as i32 as xmlChar,
    0xad as i32 as xmlChar,
    0xae as i32 as xmlChar,
    0xaf as i32 as xmlChar,
    0xb0 as i32 as xmlChar,
    0xb1 as i32 as xmlChar,
    0xb2 as i32 as xmlChar,
    0xb3 as i32 as xmlChar,
    0xb4 as i32 as xmlChar,
    0xb5 as i32 as xmlChar,
    0xb6 as i32 as xmlChar,
    0xb7 as i32 as xmlChar,
    0xb8 as i32 as xmlChar,
    0xb9 as i32 as xmlChar,
    0xba as i32 as xmlChar,
    0xbb as i32 as xmlChar,
    0xbc as i32 as xmlChar,
    0xbd as i32 as xmlChar,
    0xbe as i32 as xmlChar,
    0xbf as i32 as xmlChar,
    0xc0 as i32 as xmlChar,
    0xc1 as i32 as xmlChar,
    0xc2 as i32 as xmlChar,
    0xc3 as i32 as xmlChar,
    0xc4 as i32 as xmlChar,
    0xc5 as i32 as xmlChar,
    0xc6 as i32 as xmlChar,
    0xc7 as i32 as xmlChar,
    0xc8 as i32 as xmlChar,
    0xc9 as i32 as xmlChar,
    0xca as i32 as xmlChar,
    0xcb as i32 as xmlChar,
    0xcc as i32 as xmlChar,
    0xcd as i32 as xmlChar,
    0xce as i32 as xmlChar,
    0xcf as i32 as xmlChar,
    0xd0 as i32 as xmlChar,
    0xd1 as i32 as xmlChar,
    0xd2 as i32 as xmlChar,
    0xd3 as i32 as xmlChar,
    0xd4 as i32 as xmlChar,
    0xd5 as i32 as xmlChar,
    0xd6 as i32 as xmlChar,
    0xd7 as i32 as xmlChar,
    0xd8 as i32 as xmlChar,
    0xd9 as i32 as xmlChar,
    0xda as i32 as xmlChar,
    0xdb as i32 as xmlChar,
    0xdc as i32 as xmlChar,
    0xdd as i32 as xmlChar,
    0xde as i32 as xmlChar,
    0xdf as i32 as xmlChar,
    0xe0 as i32 as xmlChar,
    0xe1 as i32 as xmlChar,
    0xe2 as i32 as xmlChar,
    0xe3 as i32 as xmlChar,
    0xe4 as i32 as xmlChar,
    0xe5 as i32 as xmlChar,
    0xe6 as i32 as xmlChar,
    0xe7 as i32 as xmlChar,
    0xe8 as i32 as xmlChar,
    0xe9 as i32 as xmlChar,
    0xea as i32 as xmlChar,
    0xeb as i32 as xmlChar,
    0xec as i32 as xmlChar,
    0xed as i32 as xmlChar,
    0xee as i32 as xmlChar,
    0xef as i32 as xmlChar,
    0xf0 as i32 as xmlChar,
    0xf1 as i32 as xmlChar,
    0xf2 as i32 as xmlChar,
    0xf3 as i32 as xmlChar,
    0xf4 as i32 as xmlChar,
    0xf5 as i32 as xmlChar,
    0xf6 as i32 as xmlChar,
    0xf7 as i32 as xmlChar,
    0xf8 as i32 as xmlChar,
    0xf9 as i32 as xmlChar,
    0xfa as i32 as xmlChar,
    0xfb as i32 as xmlChar,
    0xfc as i32 as xmlChar,
    0xfd as i32 as xmlChar,
    0xfe as i32 as xmlChar,
    0xff as i32 as xmlChar,
];
#[no_mangle]
pub extern "C" fn xmlStrcasecmp(mut str1: *const xmlChar, mut str2: *const xmlChar) -> i32 {
    let mut tmp: i32 = 0;
    if str1 == str2 {
        return 0 as i32;
    }
    if str1.is_null() {
        return -(1 as i32);
    }
    if str2.is_null() {
        return 1 as i32;
    }
    loop {
        let fresh11 = str1;
        str1 = unsafe { str1.offset(1) };
        tmp = (unsafe { casemap[*fresh11 as usize] }) as i32 - (unsafe { casemap[*str2 as usize] }) as i32;
        if tmp != 0 as i32 {
            return tmp;
        }
        let fresh12 = str2;
        str2 = unsafe { str2.offset(1) };
        if !((unsafe { *fresh12 }) as i32 != 0 as i32) {
            break;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlStrncasecmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut len: i32,
) -> i32 {
    let mut tmp: i32 = 0;
    if len <= 0 as i32 {
        return 0 as i32;
    }
    if str1 == str2 {
        return 0 as i32;
    }
    if str1.is_null() {
        return -(1 as i32);
    }
    if str2.is_null() {
        return 1 as i32;
    }
    loop {
        let fresh13 = str1;
        str1 = unsafe { str1.offset(1) };
        tmp = (unsafe { casemap[*fresh13 as usize] }) as i32 - (unsafe { casemap[*str2 as usize] }) as i32;
        if tmp != 0 as i32 || {
            len -= 1;
            len == 0 as i32
        } {
            return tmp;
        }
        let fresh14 = str2;
        str2 = unsafe { str2.offset(1) };
        if !((unsafe { *fresh14 }) as i32 != 0 as i32) {
            break;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlStrchr(mut str: *const xmlChar, mut val: xmlChar) -> *const xmlChar {
    if str.is_null() {
        return 0 as *const xmlChar;
    }
    while (unsafe { *str }) as i32 != 0 as i32 {
        if (unsafe { *str }) as i32 == val as i32 {
            return str as *mut xmlChar;
        }
        str = unsafe { str.offset(1) };
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlStrstr(mut str: *const xmlChar, mut val: *const xmlChar) -> *const xmlChar {
    let mut n: i32 = 0;
    if str.is_null() {
        return 0 as *const xmlChar;
    }
    if val.is_null() {
        return 0 as *const xmlChar;
    }
    n = xmlStrlen(val);
    if n == 0 as i32 {
        return str;
    }
    while (unsafe { *str }) as i32 != 0 as i32 {
        if (unsafe { *str }) as i32 == (unsafe { *val }) as i32 {
            if xmlStrncmp(str, val, n) == 0 {
                return str;
            }
        }
        str = unsafe { str.offset(1) };
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlStrcasestr(
    mut str: *const xmlChar,
    mut val: *const xmlChar,
) -> *const xmlChar {
    let mut n: i32 = 0;
    if str.is_null() {
        return 0 as *const xmlChar;
    }
    if val.is_null() {
        return 0 as *const xmlChar;
    }
    n = xmlStrlen(val);
    if n == 0 as i32 {
        return str;
    }
    while (unsafe { *str }) as i32 != 0 as i32 {
        if (unsafe { casemap[*str as usize] }) as i32 == (unsafe { casemap[*val as usize] }) as i32 {
            if xmlStrncasecmp(str, val, n) == 0 {
                return str;
            }
        }
        str = unsafe { str.offset(1) };
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlStrsub(mut str: *const xmlChar, mut start: i32, mut len: i32) -> *mut xmlChar {
    let mut i: i32 = 0;
    if str.is_null() {
        return 0 as *mut xmlChar;
    }
    if start < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    if len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    i = 0 as i32;
    while i < start {
        if (unsafe { *str }) as i32 == 0 as i32 {
            return 0 as *mut xmlChar;
        }
        str = unsafe { str.offset(1) };
        i += 1;
    }
    if (unsafe { *str }) as i32 == 0 as i32 {
        return 0 as *mut xmlChar;
    }
    return xmlStrndup(str, len);
}
#[no_mangle]
pub extern "C" fn xmlStrlen(mut str: *const xmlChar) -> i32 {
    let mut len: size_t = if !str.is_null() {
        unsafe { strlen(str as *const i8) }
    } else {
        0 as i32 as u64
    };
    return (if len > 2147483647 as i32 as u64 {
        0 as i32 as u64
    } else {
        len
    }) as i32;
}
#[no_mangle]
pub extern "C" fn xmlStrncat(
    mut cur: *mut xmlChar,
    mut add: *const xmlChar,
    mut len: i32,
) -> *mut xmlChar {
    let mut size: i32 = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if add.is_null() || len == 0 as i32 {
        return cur;
    }
    if len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    if cur.is_null() {
        return xmlStrndup(add, len);
    }
    size = xmlStrlen(cur as *const xmlChar);
    if size < 0 as i32 || size > 2147483647 as i32 - len {
        return 0 as *mut xmlChar;
    }
    ret = (unsafe { xmlRealloc.expect("non-null function pointer")(
        cur as *mut libc::c_void,
        (size as size_t)
            .wrapping_add(len as u64)
            .wrapping_add(1 as i32 as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) }) as *mut xmlChar;
    if ret.is_null() {
        (unsafe { xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8) });
        return cur;
    }
    (unsafe { memcpy(
        &mut *ret.offset(size as isize) as *mut xmlChar as *mut libc::c_void,
        add as *const libc::c_void,
        (len as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) });
    (unsafe { *ret.offset((size + len) as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlStrncatNew(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut len: i32,
) -> *mut xmlChar {
    let mut size: i32 = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if len < 0 as i32 {
        len = xmlStrlen(str2);
        if len < 0 as i32 {
            return 0 as *mut xmlChar;
        }
    }
    if str2.is_null() || len == 0 as i32 {
        return xmlStrdup(str1);
    }
    if str1.is_null() {
        return xmlStrndup(str2, len);
    }
    size = xmlStrlen(str1);
    if size < 0 as i32 || size > 2147483647 as i32 - len {
        return 0 as *mut xmlChar;
    }
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        (size as size_t)
            .wrapping_add(len as u64)
            .wrapping_add(1 as i32 as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) }) as *mut xmlChar;
    if ret.is_null() {
        (unsafe { xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8) });
        return xmlStrndup(str1, size);
    }
    (unsafe { memcpy(
        ret as *mut libc::c_void,
        str1 as *const libc::c_void,
        (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) });
    (unsafe { memcpy(
        &mut *ret.offset(size as isize) as *mut xmlChar as *mut libc::c_void,
        str2 as *const libc::c_void,
        (len as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) });
    (unsafe { *ret.offset((size + len) as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlStrcat(mut cur: *mut xmlChar, mut add: *const xmlChar) -> *mut xmlChar {
    let mut p: *const xmlChar = add;
    if add.is_null() {
        return cur;
    }
    if cur.is_null() {
        return xmlStrdup(add);
    }
    while (unsafe { *p }) as i32 != 0 as i32 {
        p = unsafe { p.offset(1) };
    }
    return xmlStrncat(cur, add, (unsafe { p.offset_from(add) }) as i64 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrPrintf(
    mut buf: *mut xmlChar,
    mut len: i32,
    mut msg: *const i8,
    mut args: ...
) -> i32 {
    let mut args_0: ::std::ffi::VaListImpl;
    let mut ret: i32 = 0;
    if buf.is_null() || msg.is_null() {
        return -(1 as i32);
    }
    args_0 = args.clone();
    ret = vsnprintf(buf as *mut i8, len as u64, msg, args_0.as_va_list());
    *buf.offset((len - 1 as i32) as isize) = 0 as i32 as xmlChar;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlStrVPrintf(
    mut buf: *mut xmlChar,
    mut len: i32,
    mut msg: *const i8,
    mut ap: ::std::ffi::VaList,
) -> i32 {
    let mut ret: i32 = 0;
    if buf.is_null() || msg.is_null() {
        return -(1 as i32);
    }
    ret = unsafe { vsnprintf(buf as *mut i8, len as u64, msg, ap.as_va_list()) };
    (unsafe { *buf.offset((len - 1 as i32) as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlUTF8Size(mut utf: *const xmlChar) -> i32 {
    let mut mask: xmlChar = 0;
    let mut len: i32 = 0;
    if utf.is_null() {
        return -(1 as i32);
    }
    if ((unsafe { *utf }) as i32) < 0x80 as i32 {
        return 1 as i32;
    }
    if (unsafe { *utf }) as i32 & 0x40 as i32 == 0 {
        return -(1 as i32);
    }
    len = 2 as i32;
    mask = 0x20 as i32 as xmlChar;
    while mask as i32 != 0 as i32 {
        if (unsafe { *utf }) as i32 & mask as i32 == 0 {
            return len;
        }
        len += 1;
        mask = (mask as i32 >> 1 as i32) as xmlChar;
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlUTF8Charcmp(mut utf1: *const xmlChar, mut utf2: *const xmlChar) -> i32 {
    if utf1.is_null() {
        if utf2.is_null() {
            return 0 as i32;
        }
        return -(1 as i32);
    }
    return xmlStrncmp(utf1, utf2, xmlUTF8Size(utf1));
}
#[no_mangle]
pub extern "C" fn xmlUTF8Strlen(mut utf: *const xmlChar) -> i32 {
    let mut ret: size_t = 0 as i32 as size_t;
    if utf.is_null() {
        return -(1 as i32);
    }
    while (unsafe { *utf }) as i32 != 0 as i32 {
        if (unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0x80 as i32 != 0 {
            if (unsafe { *utf.offset(1 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                return -(1 as i32);
            }
            if (unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0xe0 as i32 == 0xe0 as i32 {
                if (unsafe { *utf.offset(2 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                    return -(1 as i32);
                }
                if (unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0xf0 as i32 == 0xf0 as i32 {
                    if (unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0xf8 as i32 != 0xf0 as i32
                        || (unsafe { *utf.offset(3 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32
                    {
                        return -(1 as i32);
                    }
                    utf = unsafe { utf.offset(4 as i32 as isize) };
                } else {
                    utf = unsafe { utf.offset(3 as i32 as isize) };
                }
            } else {
                utf = unsafe { utf.offset(2 as i32 as isize) };
            }
        } else {
            utf = unsafe { utf.offset(1) };
        }
        ret = ret.wrapping_add(1);
    }
    return (if ret > 2147483647 as i32 as u64 {
        0 as i32 as u64
    } else {
        ret
    }) as i32;
}
#[no_mangle]
pub extern "C" fn xmlGetUTF8Char(mut utf: *const u8, mut len: *mut i32) -> i32 {
    let mut current_block: u64;
    let mut c: u32 = 0;
    if !utf.is_null() {
        if !len.is_null() {
            if !((unsafe { *len }) < 1 as i32) {
                c = (unsafe { *utf.offset(0 as i32 as isize) }) as u32;
                if c & 0x80 as i32 as u32 != 0 {
                    if (unsafe { *len }) < 2 as i32 {
                        current_block = 3966416321279884290;
                    } else if (unsafe { *utf.offset(1 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                        current_block = 3966416321279884290;
                    } else if c & 0xe0 as i32 as u32 == 0xe0 as i32 as u32 {
                        if (unsafe { *len }) < 3 as i32 {
                            current_block = 3966416321279884290;
                        } else if (unsafe { *utf.offset(2 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32
                        {
                            current_block = 3966416321279884290;
                        } else if c & 0xf0 as i32 as u32 == 0xf0 as i32 as u32 {
                            if (unsafe { *len }) < 4 as i32 {
                                current_block = 3966416321279884290;
                            } else if c & 0xf8 as i32 as u32 != 0xf0 as i32 as u32
                                || (unsafe { *utf.offset(3 as i32 as isize) }) as i32 & 0xc0 as i32
                                    != 0x80 as i32
                            {
                                current_block = 3966416321279884290;
                            } else {
                                (unsafe { *len = 4 as i32 });
                                c = (((unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0x7 as i32)
                                    << 18 as i32) as u32;
                                c |= (((unsafe { *utf.offset(1 as i32 as isize) }) as i32 & 0x3f as i32)
                                    << 12 as i32) as u32;
                                c |= (((unsafe { *utf.offset(2 as i32 as isize) }) as i32 & 0x3f as i32)
                                    << 6 as i32) as u32;
                                c |= ((unsafe { *utf.offset(3 as i32 as isize) }) as i32 & 0x3f as i32) as u32;
                                current_block = 11932355480408055363;
                            }
                        } else {
                            (unsafe { *len = 3 as i32 });
                            c = (((unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0xf as i32) << 12 as i32)
                                as u32;
                            c |= (((unsafe { *utf.offset(1 as i32 as isize) }) as i32 & 0x3f as i32) << 6 as i32)
                                as u32;
                            c |= ((unsafe { *utf.offset(2 as i32 as isize) }) as i32 & 0x3f as i32) as u32;
                            current_block = 11932355480408055363;
                        }
                    } else {
                        (unsafe { *len = 2 as i32 });
                        c = (((unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0x1f as i32) << 6 as i32)
                            as u32;
                        c |= ((unsafe { *utf.offset(1 as i32 as isize) }) as i32 & 0x3f as i32) as u32;
                        current_block = 11932355480408055363;
                    }
                } else {
                    (unsafe { *len = 1 as i32 });
                    current_block = 11932355480408055363;
                }
                match current_block {
                    3966416321279884290 => {}
                    _ => return c as i32,
                }
            }
        }
    }
    if !len.is_null() {
        (unsafe { *len = 0 as i32 });
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlCheckUTF8(mut utf: *const u8) -> i32 {
    let mut ix: i32 = 0;
    let mut c: u8 = 0;
    if utf.is_null() {
        return 0 as i32;
    }
    loop {
        c = unsafe { *utf.offset(0 as i32 as isize) };
        if !(c != 0) {
            break;
        }
        ix = 0 as i32;
        if c as i32 & 0x80 as i32 == 0 as i32 {
            ix = 1 as i32;
        } else if c as i32 & 0xe0 as i32 == 0xc0 as i32 {
            if (unsafe { *utf.offset(1 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                return 0 as i32;
            }
            ix = 2 as i32;
        } else if c as i32 & 0xf0 as i32 == 0xe0 as i32 {
            if (unsafe { *utf.offset(1 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32
                || (unsafe { *utf.offset(2 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32
            {
                return 0 as i32;
            }
            ix = 3 as i32;
        } else if c as i32 & 0xf8 as i32 == 0xf0 as i32 {
            if (unsafe { *utf.offset(1 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32
                || (unsafe { *utf.offset(2 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32
                || (unsafe { *utf.offset(3 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32
            {
                return 0 as i32;
            }
            ix = 4 as i32;
        } else {
            return 0 as i32;
        }
        utf = unsafe { utf.offset(ix as isize) };
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlUTF8Strsize(mut utf: *const xmlChar, mut len: i32) -> i32 {
    let mut ptr: *const xmlChar = utf;
    let mut ch: i32 = 0;
    let mut ret: size_t = 0;
    if utf.is_null() {
        return 0 as i32;
    }
    if len <= 0 as i32 {
        return 0 as i32;
    }
    loop {
        let fresh15 = len;
        len = len - 1;
        if !(fresh15 > 0 as i32) {
            break;
        }
        if (unsafe { *ptr }) == 0 {
            break;
        }
        let fresh16 = ptr;
        ptr = unsafe { ptr.offset(1) };
        ch = (unsafe { *fresh16 }) as i32;
        if ch & 0x80 as i32 != 0 {
            loop {
                ch <<= 1 as i32;
                if !(ch & 0x80 as i32 != 0) {
                    break;
                }
                if (unsafe { *ptr }) as i32 == 0 as i32 {
                    break;
                }
                ptr = unsafe { ptr.offset(1) };
            }
        }
    }
    ret = (unsafe { ptr.offset_from(utf) }) as i64 as size_t;
    return (if ret > 2147483647 as i32 as u64 {
        0 as i32 as u64
    } else {
        ret
    }) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUTF8Strndup(mut utf: *const xmlChar, mut len: i32) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut i: i32 = 0;
    if utf.is_null() || len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    i = xmlUTF8Strsize(utf, len);
    ret = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
        (i as size_t)
            .wrapping_add(1 as i32 as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) }) as *mut xmlChar;
    if ret.is_null() {
        return 0 as *mut xmlChar;
    }
    (unsafe { memcpy(
        ret as *mut libc::c_void,
        utf as *const libc::c_void,
        (i as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) });
    (unsafe { *ret.offset(i as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlUTF8Strpos(mut utf: *const xmlChar, mut pos: i32) -> *const xmlChar {
    let mut ch: i32 = 0;
    if utf.is_null() {
        return 0 as *const xmlChar;
    }
    if pos < 0 as i32 {
        return 0 as *const xmlChar;
    }
    loop {
        let fresh17 = pos;
        pos = pos - 1;
        if !(fresh17 != 0) {
            break;
        }
        let fresh18 = utf;
        utf = unsafe { utf.offset(1) };
        ch = (unsafe { *fresh18 }) as i32;
        if ch == 0 as i32 {
            return 0 as *const xmlChar;
        }
        if ch & 0x80 as i32 != 0 {
            if ch & 0xc0 as i32 != 0xc0 as i32 {
                return 0 as *const xmlChar;
            }
            loop {
                ch <<= 1 as i32;
                if !(ch & 0x80 as i32 != 0) {
                    break;
                }
                let fresh19 = utf;
                utf = unsafe { utf.offset(1) };
                if (unsafe { *fresh19 }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                    return 0 as *const xmlChar;
                }
            }
        }
    }
    return utf as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlUTF8Strloc(mut utf: *const xmlChar, mut utfchar: *const xmlChar) -> i32 {
    let mut i: size_t = 0;
    let mut size: i32 = 0;
    let mut ch: i32 = 0;
    if utf.is_null() || utfchar.is_null() {
        return -(1 as i32);
    }
    size = xmlUTF8Strsize(utfchar, 1 as i32);
    i = 0 as i32 as size_t;
    loop {
        ch = (unsafe { *utf }) as i32;
        if !(ch != 0 as i32) {
            break;
        }
        if xmlStrncmp(utf, utfchar, size) == 0 as i32 {
            return (if i > 2147483647 as i32 as u64 {
                0 as i32 as u64
            } else {
                i
            }) as i32;
        }
        utf = unsafe { utf.offset(1) };
        if ch & 0x80 as i32 != 0 {
            if ch & 0xc0 as i32 != 0xc0 as i32 {
                return -(1 as i32);
            }
            loop {
                ch <<= 1 as i32;
                if !(ch & 0x80 as i32 != 0) {
                    break;
                }
                let fresh20 = utf;
                utf = unsafe { utf.offset(1) };
                if (unsafe { *fresh20 }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                    return -(1 as i32);
                }
            }
        }
        i = i.wrapping_add(1);
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlUTF8Strsub(
    mut utf: *const xmlChar,
    mut start: i32,
    mut len: i32,
) -> *mut xmlChar {
    let mut i: i32 = 0;
    let mut ch: i32 = 0;
    if utf.is_null() {
        return 0 as *mut xmlChar;
    }
    if start < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    if len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    i = 0 as i32;
    while i < start {
        let fresh21 = utf;
        utf = unsafe { utf.offset(1) };
        ch = (unsafe { *fresh21 }) as i32;
        if ch == 0 as i32 {
            return 0 as *mut xmlChar;
        }
        if ch & 0x80 as i32 != 0 {
            if ch & 0xc0 as i32 != 0xc0 as i32 {
                return 0 as *mut xmlChar;
            }
            loop {
                ch <<= 1 as i32;
                if !(ch & 0x80 as i32 != 0) {
                    break;
                }
                let fresh22 = utf;
                utf = unsafe { utf.offset(1) };
                if (unsafe { *fresh22 }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                    return 0 as *mut xmlChar;
                }
            }
        }
        i += 1;
    }
    return xmlUTF8Strndup(utf, len);
}
#[no_mangle]
pub extern "C" fn xmlEscapeFormatString(mut msg: *mut *mut xmlChar) -> *mut xmlChar {
    let mut msgPtr: *mut xmlChar = 0 as *mut xmlChar;
    let mut result: *mut xmlChar = 0 as *mut xmlChar;
    let mut resultPtr: *mut xmlChar = 0 as *mut xmlChar;
    let mut count: size_t = 0 as i32 as size_t;
    let mut msgLen: size_t = 0 as i32 as size_t;
    let mut resultLen: size_t = 0 as i32 as size_t;
    if msg.is_null() || (unsafe { *msg }).is_null() {
        return 0 as *mut xmlChar;
    }
    msgPtr = unsafe { *msg };
    while (unsafe { *msgPtr }) as i32 != '\u{0}' as i32 {
        msgLen = msgLen.wrapping_add(1);
        if (unsafe { *msgPtr }) as i32 == '%' as i32 {
            count = count.wrapping_add(1);
        }
        msgPtr = unsafe { msgPtr.offset(1) };
    }
    if count == 0 as i32 as u64 {
        return unsafe { *msg };
    }
    if count > 2147483647 as i32 as u64 || msgLen > (2147483647 as i32 as u64).wrapping_sub(count) {
        return 0 as *mut xmlChar;
    }
    resultLen = msgLen.wrapping_add(count).wrapping_add(1 as i32 as u64);
    result = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
        resultLen.wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) }) as *mut xmlChar;
    if result.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(*msg as *mut libc::c_void) });
        (unsafe { *msg = 0 as *mut xmlChar });
        (unsafe { xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8) });
        return 0 as *mut xmlChar;
    }
    msgPtr = unsafe { *msg };
    resultPtr = result;
    while (unsafe { *msgPtr }) as i32 != '\u{0}' as i32 {
        (unsafe { *resultPtr = *msgPtr });
        if (unsafe { *msgPtr }) as i32 == '%' as i32 {
            resultPtr = unsafe { resultPtr.offset(1) };
            (unsafe { *resultPtr = '%' as i32 as xmlChar });
        }
        msgPtr = unsafe { msgPtr.offset(1) };
        resultPtr = unsafe { resultPtr.offset(1) };
    }
    (unsafe { *result.offset(resultLen.wrapping_sub(1 as i32 as u64) as isize) = '\u{0}' as i32 as xmlChar });
    (unsafe { xmlFree.expect("non-null function pointer")(*msg as *mut libc::c_void) });
    (unsafe { *msg = result });
    return unsafe { *msg };
}
