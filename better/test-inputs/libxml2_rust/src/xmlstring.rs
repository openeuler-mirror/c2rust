use ::libc;
extern "C" {
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlStartTag;
    pub type _xmlBuf;
    pub type _xmlAutomataState;
    pub type _xmlAutomata;
    pub type _xmlValidState;
    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::std::ffi::VaList,
    ) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    static mut xmlFree: xmlFreeFunc;
    static mut xmlMalloc: xmlMallocFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlMallocAtomic: xmlMallocFunc;
    fn xmlErrMemory(ctxt: xmlParserCtxtPtr, extra: *const libc::c_char);
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type va_list = __builtin_va_list;
pub type xmlChar = libc::c_uchar;
pub type xmlParserCtxtPtr = *mut xmlParserCtxt;
pub type xmlParserCtxt = _xmlParserCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserCtxt {
    pub sax: *mut _xmlSAXHandler,
    pub userData: *mut libc::c_void,
    pub myDoc: xmlDocPtr,
    pub wellFormed: libc::c_int,
    pub replaceEntities: libc::c_int,
    pub version: *const xmlChar,
    pub encoding: *const xmlChar,
    pub standalone: libc::c_int,
    pub html: libc::c_int,
    pub input: xmlParserInputPtr,
    pub inputNr: libc::c_int,
    pub inputMax: libc::c_int,
    pub inputTab: *mut xmlParserInputPtr,
    pub node: xmlNodePtr,
    pub nodeNr: libc::c_int,
    pub nodeMax: libc::c_int,
    pub nodeTab: *mut xmlNodePtr,
    pub record_info: libc::c_int,
    pub node_seq: xmlParserNodeInfoSeq,
    pub errNo: libc::c_int,
    pub hasExternalSubset: libc::c_int,
    pub hasPErefs: libc::c_int,
    pub external: libc::c_int,
    pub valid: libc::c_int,
    pub validate: libc::c_int,
    pub vctxt: xmlValidCtxt,
    pub instate: xmlParserInputState,
    pub token: libc::c_int,
    pub directory: *mut libc::c_char,
    pub name: *const xmlChar,
    pub nameNr: libc::c_int,
    pub nameMax: libc::c_int,
    pub nameTab: *mut *const xmlChar,
    pub nbChars: libc::c_long,
    pub checkIndex: libc::c_long,
    pub keepBlanks: libc::c_int,
    pub disableSAX: libc::c_int,
    pub inSubset: libc::c_int,
    pub intSubName: *const xmlChar,
    pub extSubURI: *mut xmlChar,
    pub extSubSystem: *mut xmlChar,
    pub space: *mut libc::c_int,
    pub spaceNr: libc::c_int,
    pub spaceMax: libc::c_int,
    pub spaceTab: *mut libc::c_int,
    pub depth: libc::c_int,
    pub entity: xmlParserInputPtr,
    pub charset: libc::c_int,
    pub nodelen: libc::c_int,
    pub nodemem: libc::c_int,
    pub pedantic: libc::c_int,
    pub _private: *mut libc::c_void,
    pub loadsubset: libc::c_int,
    pub linenumbers: libc::c_int,
    pub catalogs: *mut libc::c_void,
    pub recovery: libc::c_int,
    pub progressive: libc::c_int,
    pub dict: xmlDictPtr,
    pub atts: *mut *const xmlChar,
    pub maxatts: libc::c_int,
    pub docdict: libc::c_int,
    pub str_xml: *const xmlChar,
    pub str_xmlns: *const xmlChar,
    pub str_xml_ns: *const xmlChar,
    pub sax2: libc::c_int,
    pub nsNr: libc::c_int,
    pub nsMax: libc::c_int,
    pub nsTab: *mut *const xmlChar,
    pub attallocs: *mut libc::c_int,
    pub pushTab: *mut xmlStartTag,
    pub attsDefault: xmlHashTablePtr,
    pub attsSpecial: xmlHashTablePtr,
    pub nsWellFormed: libc::c_int,
    pub options: libc::c_int,
    pub dictNames: libc::c_int,
    pub freeElemsNr: libc::c_int,
    pub freeElems: xmlNodePtr,
    pub freeAttrsNr: libc::c_int,
    pub freeAttrs: xmlAttrPtr,
    pub lastError: xmlError,
    pub parseMode: xmlParserMode,
    pub nbentities: libc::c_ulong,
    pub sizeentities: libc::c_ulong,
    pub nodeInfo: *mut xmlParserNodeInfo,
    pub nodeInfoNr: libc::c_int,
    pub nodeInfoMax: libc::c_int,
    pub nodeInfoTab: *mut xmlParserNodeInfo,
    pub input_id: libc::c_int,
    pub sizeentcopy: libc::c_ulong,
}
pub type xmlParserNodeInfo = _xmlParserNodeInfo;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserNodeInfo {
    pub node: *const _xmlNode,
    pub begin_pos: libc::c_ulong,
    pub begin_line: libc::c_ulong,
    pub end_pos: libc::c_ulong,
    pub end_line: libc::c_ulong,
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
    pub line: libc::c_ushort,
    pub extra: libc::c_ushort,
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
    pub name: *mut libc::c_char,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlNode,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub compression: libc::c_int,
    pub standalone: libc::c_int,
    pub intSubset: *mut _xmlDtd,
    pub extSubset: *mut _xmlDtd,
    pub oldNs: *mut _xmlNs,
    pub version: *const xmlChar,
    pub encoding: *const xmlChar,
    pub ids: *mut libc::c_void,
    pub refs: *mut libc::c_void,
    pub URL: *const xmlChar,
    pub charset: libc::c_int,
    pub dict: *mut _xmlDict,
    pub psvi: *mut libc::c_void,
    pub parseFlags: libc::c_int,
    pub properties: libc::c_int,
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
pub type xmlElementType = libc::c_uint;
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
pub type xmlAttributeType = libc::c_uint;
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
pub type xmlParserMode = libc::c_uint;
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
    pub domain: libc::c_int,
    pub code: libc::c_int,
    pub message: *mut libc::c_char,
    pub level: xmlErrorLevel,
    pub file: *mut libc::c_char,
    pub line: libc::c_int,
    pub str1: *mut libc::c_char,
    pub str2: *mut libc::c_char,
    pub str3: *mut libc::c_char,
    pub int1: libc::c_int,
    pub int2: libc::c_int,
    pub ctxt: *mut libc::c_void,
    pub node: *mut libc::c_void,
}
pub type xmlErrorLevel = libc::c_uint;
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
    pub filename: *const libc::c_char,
    pub directory: *const libc::c_char,
    pub base: *const xmlChar,
    pub cur: *const xmlChar,
    pub end: *const xmlChar,
    pub length: libc::c_int,
    pub line: libc::c_int,
    pub col: libc::c_int,
    pub consumed: libc::c_ulong,
    pub free: xmlParserInputDeallocate,
    pub encoding: *const xmlChar,
    pub version: *const xmlChar,
    pub standalone: libc::c_int,
    pub id: libc::c_int,
}
pub type xmlParserInputDeallocate = Option::<unsafe extern "C" fn(*mut xmlChar) -> ()>;
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
    pub compressed: libc::c_int,
    pub error: libc::c_int,
    pub rawconsumed: libc::c_ulong,
}
pub type xmlBufPtr = *mut xmlBuf;
pub type xmlBuf = _xmlBuf;
pub type xmlCharEncodingHandlerPtr = *mut xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = _xmlCharEncodingHandler;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlCharEncodingHandler {
    pub name: *mut libc::c_char,
    pub input: xmlCharEncodingInputFunc,
    pub output: xmlCharEncodingOutputFunc,
    pub iconv_in: iconv_t,
    pub iconv_out: iconv_t,
}
pub type iconv_t = *mut libc::c_void;
pub type xmlCharEncodingOutputFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_uchar,
        *mut libc::c_int,
        *const libc::c_uchar,
        *mut libc::c_int,
    ) -> libc::c_int,
>;
pub type xmlCharEncodingInputFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_uchar,
        *mut libc::c_int,
        *const libc::c_uchar,
        *mut libc::c_int,
    ) -> libc::c_int,
>;
pub type xmlInputCloseCallback = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type xmlInputReadCallback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut libc::c_char,
        libc::c_int,
    ) -> libc::c_int,
>;
pub type xmlParserInputState = libc::c_int;
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
    pub nodeNr: libc::c_int,
    pub nodeMax: libc::c_int,
    pub nodeTab: *mut xmlNodePtr,
    pub flags: libc::c_uint,
    pub doc: xmlDocPtr,
    pub valid: libc::c_int,
    pub vstate: *mut xmlValidState,
    pub vstateNr: libc::c_int,
    pub vstateMax: libc::c_int,
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
pub type xmlValidityWarningFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type xmlValidityErrorFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type xmlParserNodeInfoSeq = _xmlParserNodeInfoSeq;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserNodeInfoSeq {
    pub maximum: libc::c_ulong,
    pub length: libc::c_ulong,
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
    pub initialized: libc::c_uint,
    pub _private: *mut libc::c_void,
    pub startElementNs: startElementNsSAX2Func,
    pub endElementNs: endElementNsSAX2Func,
    pub serror: xmlStructuredErrorFunc,
}
pub type xmlStructuredErrorFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> (),
>;
pub type xmlErrorPtr = *mut xmlError;
pub type endElementNsSAX2Func = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type startElementNsSAX2Func = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
        libc::c_int,
        *mut *const xmlChar,
        libc::c_int,
        libc::c_int,
        *mut *const xmlChar,
    ) -> (),
>;
pub type externalSubsetSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type cdataBlockSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
>;
pub type getParameterEntitySAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
>;
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
    pub length: libc::c_int,
    pub etype: xmlEntityType,
    pub ExternalID: *const xmlChar,
    pub SystemID: *const xmlChar,
    pub nexte: *mut _xmlEntity,
    pub URI: *const xmlChar,
    pub owner: libc::c_int,
    pub checked: libc::c_int,
}
pub type xmlEntityType = libc::c_uint;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type errorSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type warningSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type commentSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
>;
pub type processingInstructionSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> (),
>;
pub type ignorableWhitespaceSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
>;
pub type charactersSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
>;
pub type referenceSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
>;
pub type endElementSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
>;
pub type startElementSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *mut *const xmlChar) -> (),
>;
pub type endDocumentSAXFunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type startDocumentSAXFunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type setDocumentLocatorSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
>;
pub type xmlSAXLocatorPtr = *mut xmlSAXLocator;
pub type xmlSAXLocator = _xmlSAXLocator;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXLocator {
    pub getPublicId: Option::<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getSystemId: Option::<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getLineNumber: Option::<unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int>,
    pub getColumnNumber: Option::<
        unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    >,
}
pub type unparsedEntityDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type elementDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        libc::c_int,
        xmlElementContentPtr,
    ) -> (),
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
pub type xmlElementContentOccur = libc::c_uint;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub type xmlElementContentType = libc::c_uint;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub type attributeDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        libc::c_int,
        libc::c_int,
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
pub type notationDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type entityDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        libc::c_int,
        *const xmlChar,
        *const xmlChar,
        *mut xmlChar,
    ) -> (),
>;
pub type getEntitySAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
>;
pub type resolveEntitySAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
    ) -> xmlParserInputPtr,
>;
pub type hasExternalSubsetSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type hasInternalSubsetSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type isStandaloneSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type internalSubsetSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type size_t = libc::c_ulong;
pub type xmlMallocFunc = Option::<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type xmlReallocFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
>;
pub type xmlFreeFunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
#[no_mangle]
pub unsafe extern "C" fn xmlStrndup(
    mut cur: *const xmlChar,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if cur.is_null() || len < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    ret = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (len as size_t)
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if ret.is_null() {
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    memcpy(
        ret as *mut libc::c_void,
        cur as *const libc::c_void,
        (len as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    );
    *ret.offset(len as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrdup(mut cur: *const xmlChar) -> *mut xmlChar {
    let mut p: *const xmlChar = cur;
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    while *p as libc::c_int != 0 as libc::c_int {
        p = p.offset(1);
    }
    return xmlStrndup(cur, p.offset_from(cur) as libc::c_long as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCharStrndup(
    mut cur: *const libc::c_char,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut i: libc::c_int = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if cur.is_null() || len < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    ret = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (len as size_t)
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if ret.is_null() {
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    i = 0 as libc::c_int;
    while i < len {
        *ret.offset(i as isize) = *cur.offset(i as isize) as xmlChar;
        if *ret.offset(i as isize) as libc::c_int == 0 as libc::c_int {
            return ret;
        }
        i += 1;
    }
    *ret.offset(len as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCharStrdup(mut cur: *const libc::c_char) -> *mut xmlChar {
    let mut p: *const libc::c_char = cur;
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    while *p as libc::c_int != '\u{0}' as i32 {
        p = p.offset(1);
    }
    return xmlCharStrndup(cur, p.offset_from(cur) as libc::c_long as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrcmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) -> libc::c_int {
    if str1 == str2 {
        return 0 as libc::c_int;
    }
    if str1.is_null() {
        return -(1 as libc::c_int);
    }
    if str2.is_null() {
        return 1 as libc::c_int;
    }
    loop {
        let fresh0 = str1;
        str1 = str1.offset(1);
        let mut tmp: libc::c_int = *fresh0 as libc::c_int - *str2 as libc::c_int;
        if tmp != 0 as libc::c_int {
            return tmp;
        }
        let fresh1 = str2;
        str2 = str2.offset(1);
        if !(*fresh1 as libc::c_int != 0 as libc::c_int) {
            break;
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrEqual(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) -> libc::c_int {
    if str1 == str2 {
        return 1 as libc::c_int;
    }
    if str1.is_null() {
        return 0 as libc::c_int;
    }
    if str2.is_null() {
        return 0 as libc::c_int;
    }
    loop {
        let fresh2 = str1;
        str1 = str1.offset(1);
        if *fresh2 as libc::c_int != *str2 as libc::c_int {
            return 0 as libc::c_int;
        }
        let fresh3 = str2;
        str2 = str2.offset(1);
        if !(*fresh3 != 0) {
            break;
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrQEqual(
    mut pref: *const xmlChar,
    mut name: *const xmlChar,
    mut str: *const xmlChar,
) -> libc::c_int {
    if pref.is_null() {
        return xmlStrEqual(name, str);
    }
    if name.is_null() {
        return 0 as libc::c_int;
    }
    if str.is_null() {
        return 0 as libc::c_int;
    }
    loop {
        let fresh4 = pref;
        pref = pref.offset(1);
        if *fresh4 as libc::c_int != *str as libc::c_int {
            return 0 as libc::c_int;
        }
        let fresh5 = str;
        str = str.offset(1);
        if !(*fresh5 as libc::c_int != 0 && *pref as libc::c_int != 0) {
            break;
        }
    }
    let fresh6 = str;
    str = str.offset(1);
    if *fresh6 as libc::c_int != ':' as i32 {
        return 0 as libc::c_int;
    }
    loop {
        let fresh7 = name;
        name = name.offset(1);
        if *fresh7 as libc::c_int != *str as libc::c_int {
            return 0 as libc::c_int;
        }
        let fresh8 = str;
        str = str.offset(1);
        if !(*fresh8 != 0) {
            break;
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrncmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut len: libc::c_int,
) -> libc::c_int {
    if len <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if str1 == str2 {
        return 0 as libc::c_int;
    }
    if str1.is_null() {
        return -(1 as libc::c_int);
    }
    if str2.is_null() {
        return 1 as libc::c_int;
    }
    loop {
        let fresh9 = str1;
        str1 = str1.offset(1);
        let mut tmp: libc::c_int = *fresh9 as libc::c_int - *str2 as libc::c_int;
        if tmp != 0 as libc::c_int
            || {
                len -= 1;
                len == 0 as libc::c_int
            }
        {
            return tmp;
        }
        let fresh10 = str2;
        str2 = str2.offset(1);
        if !(*fresh10 as libc::c_int != 0 as libc::c_int) {
            break;
        }
    }
    return 0 as libc::c_int;
}
static mut casemap: [xmlChar; 256] = [
    0 as libc::c_int as xmlChar,
    0x1 as libc::c_int as xmlChar,
    0x2 as libc::c_int as xmlChar,
    0x3 as libc::c_int as xmlChar,
    0x4 as libc::c_int as xmlChar,
    0x5 as libc::c_int as xmlChar,
    0x6 as libc::c_int as xmlChar,
    0x7 as libc::c_int as xmlChar,
    0x8 as libc::c_int as xmlChar,
    0x9 as libc::c_int as xmlChar,
    0xa as libc::c_int as xmlChar,
    0xb as libc::c_int as xmlChar,
    0xc as libc::c_int as xmlChar,
    0xd as libc::c_int as xmlChar,
    0xe as libc::c_int as xmlChar,
    0xf as libc::c_int as xmlChar,
    0x10 as libc::c_int as xmlChar,
    0x11 as libc::c_int as xmlChar,
    0x12 as libc::c_int as xmlChar,
    0x13 as libc::c_int as xmlChar,
    0x14 as libc::c_int as xmlChar,
    0x15 as libc::c_int as xmlChar,
    0x16 as libc::c_int as xmlChar,
    0x17 as libc::c_int as xmlChar,
    0x18 as libc::c_int as xmlChar,
    0x19 as libc::c_int as xmlChar,
    0x1a as libc::c_int as xmlChar,
    0x1b as libc::c_int as xmlChar,
    0x1c as libc::c_int as xmlChar,
    0x1d as libc::c_int as xmlChar,
    0x1e as libc::c_int as xmlChar,
    0x1f as libc::c_int as xmlChar,
    0x20 as libc::c_int as xmlChar,
    0x21 as libc::c_int as xmlChar,
    0x22 as libc::c_int as xmlChar,
    0x23 as libc::c_int as xmlChar,
    0x24 as libc::c_int as xmlChar,
    0x25 as libc::c_int as xmlChar,
    0x26 as libc::c_int as xmlChar,
    0x27 as libc::c_int as xmlChar,
    0x28 as libc::c_int as xmlChar,
    0x29 as libc::c_int as xmlChar,
    0x2a as libc::c_int as xmlChar,
    0x2b as libc::c_int as xmlChar,
    0x2c as libc::c_int as xmlChar,
    0x2d as libc::c_int as xmlChar,
    0x2e as libc::c_int as xmlChar,
    0x2f as libc::c_int as xmlChar,
    0x30 as libc::c_int as xmlChar,
    0x31 as libc::c_int as xmlChar,
    0x32 as libc::c_int as xmlChar,
    0x33 as libc::c_int as xmlChar,
    0x34 as libc::c_int as xmlChar,
    0x35 as libc::c_int as xmlChar,
    0x36 as libc::c_int as xmlChar,
    0x37 as libc::c_int as xmlChar,
    0x38 as libc::c_int as xmlChar,
    0x39 as libc::c_int as xmlChar,
    0x3a as libc::c_int as xmlChar,
    0x3b as libc::c_int as xmlChar,
    0x3c as libc::c_int as xmlChar,
    0x3d as libc::c_int as xmlChar,
    0x3e as libc::c_int as xmlChar,
    0x3f as libc::c_int as xmlChar,
    0x40 as libc::c_int as xmlChar,
    0x61 as libc::c_int as xmlChar,
    0x62 as libc::c_int as xmlChar,
    0x63 as libc::c_int as xmlChar,
    0x64 as libc::c_int as xmlChar,
    0x65 as libc::c_int as xmlChar,
    0x66 as libc::c_int as xmlChar,
    0x67 as libc::c_int as xmlChar,
    0x68 as libc::c_int as xmlChar,
    0x69 as libc::c_int as xmlChar,
    0x6a as libc::c_int as xmlChar,
    0x6b as libc::c_int as xmlChar,
    0x6c as libc::c_int as xmlChar,
    0x6d as libc::c_int as xmlChar,
    0x6e as libc::c_int as xmlChar,
    0x6f as libc::c_int as xmlChar,
    0x70 as libc::c_int as xmlChar,
    0x71 as libc::c_int as xmlChar,
    0x72 as libc::c_int as xmlChar,
    0x73 as libc::c_int as xmlChar,
    0x74 as libc::c_int as xmlChar,
    0x75 as libc::c_int as xmlChar,
    0x76 as libc::c_int as xmlChar,
    0x77 as libc::c_int as xmlChar,
    0x78 as libc::c_int as xmlChar,
    0x79 as libc::c_int as xmlChar,
    0x7a as libc::c_int as xmlChar,
    0x7b as libc::c_int as xmlChar,
    0x5c as libc::c_int as xmlChar,
    0x5d as libc::c_int as xmlChar,
    0x5e as libc::c_int as xmlChar,
    0x5f as libc::c_int as xmlChar,
    0x60 as libc::c_int as xmlChar,
    0x61 as libc::c_int as xmlChar,
    0x62 as libc::c_int as xmlChar,
    0x63 as libc::c_int as xmlChar,
    0x64 as libc::c_int as xmlChar,
    0x65 as libc::c_int as xmlChar,
    0x66 as libc::c_int as xmlChar,
    0x67 as libc::c_int as xmlChar,
    0x68 as libc::c_int as xmlChar,
    0x69 as libc::c_int as xmlChar,
    0x6a as libc::c_int as xmlChar,
    0x6b as libc::c_int as xmlChar,
    0x6c as libc::c_int as xmlChar,
    0x6d as libc::c_int as xmlChar,
    0x6e as libc::c_int as xmlChar,
    0x6f as libc::c_int as xmlChar,
    0x70 as libc::c_int as xmlChar,
    0x71 as libc::c_int as xmlChar,
    0x72 as libc::c_int as xmlChar,
    0x73 as libc::c_int as xmlChar,
    0x74 as libc::c_int as xmlChar,
    0x75 as libc::c_int as xmlChar,
    0x76 as libc::c_int as xmlChar,
    0x77 as libc::c_int as xmlChar,
    0x78 as libc::c_int as xmlChar,
    0x79 as libc::c_int as xmlChar,
    0x7a as libc::c_int as xmlChar,
    0x7b as libc::c_int as xmlChar,
    0x7c as libc::c_int as xmlChar,
    0x7d as libc::c_int as xmlChar,
    0x7e as libc::c_int as xmlChar,
    0x7f as libc::c_int as xmlChar,
    0x80 as libc::c_int as xmlChar,
    0x81 as libc::c_int as xmlChar,
    0x82 as libc::c_int as xmlChar,
    0x83 as libc::c_int as xmlChar,
    0x84 as libc::c_int as xmlChar,
    0x85 as libc::c_int as xmlChar,
    0x86 as libc::c_int as xmlChar,
    0x87 as libc::c_int as xmlChar,
    0x88 as libc::c_int as xmlChar,
    0x89 as libc::c_int as xmlChar,
    0x8a as libc::c_int as xmlChar,
    0x8b as libc::c_int as xmlChar,
    0x8c as libc::c_int as xmlChar,
    0x8d as libc::c_int as xmlChar,
    0x8e as libc::c_int as xmlChar,
    0x8f as libc::c_int as xmlChar,
    0x90 as libc::c_int as xmlChar,
    0x91 as libc::c_int as xmlChar,
    0x92 as libc::c_int as xmlChar,
    0x93 as libc::c_int as xmlChar,
    0x94 as libc::c_int as xmlChar,
    0x95 as libc::c_int as xmlChar,
    0x96 as libc::c_int as xmlChar,
    0x97 as libc::c_int as xmlChar,
    0x98 as libc::c_int as xmlChar,
    0x99 as libc::c_int as xmlChar,
    0x9a as libc::c_int as xmlChar,
    0x9b as libc::c_int as xmlChar,
    0x9c as libc::c_int as xmlChar,
    0x9d as libc::c_int as xmlChar,
    0x9e as libc::c_int as xmlChar,
    0x9f as libc::c_int as xmlChar,
    0xa0 as libc::c_int as xmlChar,
    0xa1 as libc::c_int as xmlChar,
    0xa2 as libc::c_int as xmlChar,
    0xa3 as libc::c_int as xmlChar,
    0xa4 as libc::c_int as xmlChar,
    0xa5 as libc::c_int as xmlChar,
    0xa6 as libc::c_int as xmlChar,
    0xa7 as libc::c_int as xmlChar,
    0xa8 as libc::c_int as xmlChar,
    0xa9 as libc::c_int as xmlChar,
    0xaa as libc::c_int as xmlChar,
    0xab as libc::c_int as xmlChar,
    0xac as libc::c_int as xmlChar,
    0xad as libc::c_int as xmlChar,
    0xae as libc::c_int as xmlChar,
    0xaf as libc::c_int as xmlChar,
    0xb0 as libc::c_int as xmlChar,
    0xb1 as libc::c_int as xmlChar,
    0xb2 as libc::c_int as xmlChar,
    0xb3 as libc::c_int as xmlChar,
    0xb4 as libc::c_int as xmlChar,
    0xb5 as libc::c_int as xmlChar,
    0xb6 as libc::c_int as xmlChar,
    0xb7 as libc::c_int as xmlChar,
    0xb8 as libc::c_int as xmlChar,
    0xb9 as libc::c_int as xmlChar,
    0xba as libc::c_int as xmlChar,
    0xbb as libc::c_int as xmlChar,
    0xbc as libc::c_int as xmlChar,
    0xbd as libc::c_int as xmlChar,
    0xbe as libc::c_int as xmlChar,
    0xbf as libc::c_int as xmlChar,
    0xc0 as libc::c_int as xmlChar,
    0xc1 as libc::c_int as xmlChar,
    0xc2 as libc::c_int as xmlChar,
    0xc3 as libc::c_int as xmlChar,
    0xc4 as libc::c_int as xmlChar,
    0xc5 as libc::c_int as xmlChar,
    0xc6 as libc::c_int as xmlChar,
    0xc7 as libc::c_int as xmlChar,
    0xc8 as libc::c_int as xmlChar,
    0xc9 as libc::c_int as xmlChar,
    0xca as libc::c_int as xmlChar,
    0xcb as libc::c_int as xmlChar,
    0xcc as libc::c_int as xmlChar,
    0xcd as libc::c_int as xmlChar,
    0xce as libc::c_int as xmlChar,
    0xcf as libc::c_int as xmlChar,
    0xd0 as libc::c_int as xmlChar,
    0xd1 as libc::c_int as xmlChar,
    0xd2 as libc::c_int as xmlChar,
    0xd3 as libc::c_int as xmlChar,
    0xd4 as libc::c_int as xmlChar,
    0xd5 as libc::c_int as xmlChar,
    0xd6 as libc::c_int as xmlChar,
    0xd7 as libc::c_int as xmlChar,
    0xd8 as libc::c_int as xmlChar,
    0xd9 as libc::c_int as xmlChar,
    0xda as libc::c_int as xmlChar,
    0xdb as libc::c_int as xmlChar,
    0xdc as libc::c_int as xmlChar,
    0xdd as libc::c_int as xmlChar,
    0xde as libc::c_int as xmlChar,
    0xdf as libc::c_int as xmlChar,
    0xe0 as libc::c_int as xmlChar,
    0xe1 as libc::c_int as xmlChar,
    0xe2 as libc::c_int as xmlChar,
    0xe3 as libc::c_int as xmlChar,
    0xe4 as libc::c_int as xmlChar,
    0xe5 as libc::c_int as xmlChar,
    0xe6 as libc::c_int as xmlChar,
    0xe7 as libc::c_int as xmlChar,
    0xe8 as libc::c_int as xmlChar,
    0xe9 as libc::c_int as xmlChar,
    0xea as libc::c_int as xmlChar,
    0xeb as libc::c_int as xmlChar,
    0xec as libc::c_int as xmlChar,
    0xed as libc::c_int as xmlChar,
    0xee as libc::c_int as xmlChar,
    0xef as libc::c_int as xmlChar,
    0xf0 as libc::c_int as xmlChar,
    0xf1 as libc::c_int as xmlChar,
    0xf2 as libc::c_int as xmlChar,
    0xf3 as libc::c_int as xmlChar,
    0xf4 as libc::c_int as xmlChar,
    0xf5 as libc::c_int as xmlChar,
    0xf6 as libc::c_int as xmlChar,
    0xf7 as libc::c_int as xmlChar,
    0xf8 as libc::c_int as xmlChar,
    0xf9 as libc::c_int as xmlChar,
    0xfa as libc::c_int as xmlChar,
    0xfb as libc::c_int as xmlChar,
    0xfc as libc::c_int as xmlChar,
    0xfd as libc::c_int as xmlChar,
    0xfe as libc::c_int as xmlChar,
    0xff as libc::c_int as xmlChar,
];
#[no_mangle]
pub unsafe extern "C" fn xmlStrcasecmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) -> libc::c_int {
    let mut tmp: libc::c_int = 0;
    if str1 == str2 {
        return 0 as libc::c_int;
    }
    if str1.is_null() {
        return -(1 as libc::c_int);
    }
    if str2.is_null() {
        return 1 as libc::c_int;
    }
    loop {
        let fresh11 = str1;
        str1 = str1.offset(1);
        tmp = casemap[*fresh11 as usize] as libc::c_int
            - casemap[*str2 as usize] as libc::c_int;
        if tmp != 0 as libc::c_int {
            return tmp;
        }
        let fresh12 = str2;
        str2 = str2.offset(1);
        if !(*fresh12 as libc::c_int != 0 as libc::c_int) {
            break;
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrncasecmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut tmp: libc::c_int = 0;
    if len <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if str1 == str2 {
        return 0 as libc::c_int;
    }
    if str1.is_null() {
        return -(1 as libc::c_int);
    }
    if str2.is_null() {
        return 1 as libc::c_int;
    }
    loop {
        let fresh13 = str1;
        str1 = str1.offset(1);
        tmp = casemap[*fresh13 as usize] as libc::c_int
            - casemap[*str2 as usize] as libc::c_int;
        if tmp != 0 as libc::c_int
            || {
                len -= 1;
                len == 0 as libc::c_int
            }
        {
            return tmp;
        }
        let fresh14 = str2;
        str2 = str2.offset(1);
        if !(*fresh14 as libc::c_int != 0 as libc::c_int) {
            break;
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrchr(
    mut str: *const xmlChar,
    mut val: xmlChar,
) -> *const xmlChar {
    if str.is_null() {
        // type
        return 0 as *const libc::c_void as *const xmlChar;
    }
    while *str as libc::c_int != 0 as libc::c_int {
        if *str as libc::c_int == val as libc::c_int {
            return str as *mut xmlChar;
        }
        str = str.offset(1);
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrstr(
    mut str: *const xmlChar,
    mut val: *const xmlChar,
) -> *const xmlChar {
    let mut n: libc::c_int = 0;
    if str.is_null() {
        return 0 as *const xmlChar;
    }
    if val.is_null() {
        return 0 as *const xmlChar;
    }
    n = xmlStrlen(val);
    if n == 0 as libc::c_int {
        return str;
    }
    while *str as libc::c_int != 0 as libc::c_int {
        if *str as libc::c_int == *val as libc::c_int {
            if xmlStrncmp(str, val, n) == 0 {
                return str;
            }
        }
        str = str.offset(1);
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrcasestr(
    mut str: *const xmlChar,
    mut val: *const xmlChar,
) -> *const xmlChar {
    let mut n: libc::c_int = 0;
    if str.is_null() {
        return 0 as *const xmlChar;
    }
    if val.is_null() {
        return 0 as *const xmlChar;
    }
    n = xmlStrlen(val);
    if n == 0 as libc::c_int {
        return str;
    }
    while *str as libc::c_int != 0 as libc::c_int {
        if casemap[*str as usize] as libc::c_int == casemap[*val as usize] as libc::c_int
        {
            if xmlStrncasecmp(str, val, n) == 0 {
                return str;
            }
        }
        str = str.offset(1);
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrsub(
    mut str: *const xmlChar,
    mut start: libc::c_int,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut i: libc::c_int = 0;
    if str.is_null() {
        return 0 as *mut xmlChar;
    }
    if start < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    if len < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    i = 0 as libc::c_int;
    while i < start {
        if *str as libc::c_int == 0 as libc::c_int {
            return 0 as *mut xmlChar;
        }
        str = str.offset(1);
        i += 1;
    }
    if *str as libc::c_int == 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    return xmlStrndup(str, len);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrlen(mut str: *const xmlChar) -> libc::c_int {
    let mut len: size_t = if !str.is_null() {
        strlen(str as *const libc::c_char)
    } else {
        0 as libc::c_int as libc::c_ulong
    };
    return (if len > 2147483647 as libc::c_int as libc::c_ulong {
        0 as libc::c_int as libc::c_ulong
    } else {
        len
    }) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrncat(
    mut cur: *mut xmlChar,
    mut add: *const xmlChar,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut size: libc::c_int = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if add.is_null() || len == 0 as libc::c_int {
        return cur;
    }
    if len < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    if cur.is_null() {
        return xmlStrndup(add, len);
    }
    size = xmlStrlen(cur as *const xmlChar);
    if size < 0 as libc::c_int || size > 2147483647 as libc::c_int - len {
        return 0 as *mut xmlChar;
    }
    ret = xmlRealloc
        .expect(
            "non-null function pointer",
        )(
        cur as *mut libc::c_void,
        (size as size_t)
            .wrapping_add(len as libc::c_ulong)
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if ret.is_null() {
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const libc::c_char);
        return cur;
    }
    memcpy(
        &mut *ret.offset(size as isize) as *mut xmlChar as *mut libc::c_void,
        add as *const libc::c_void,
        (len as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    );
    *ret.offset((size + len) as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrncatNew(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut size: libc::c_int = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if len < 0 as libc::c_int {
        len = xmlStrlen(str2);
        if len < 0 as libc::c_int {
            return 0 as *mut xmlChar;
        }
    }
    if str2.is_null() || len == 0 as libc::c_int {
        return xmlStrdup(str1);
    }
    if str1.is_null() {
        return xmlStrndup(str2, len);
    }
    size = xmlStrlen(str1);
    if size < 0 as libc::c_int || size > 2147483647 as libc::c_int - len {
        return 0 as *mut xmlChar;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(
        (size as size_t)
            .wrapping_add(len as libc::c_ulong)
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if ret.is_null() {
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const libc::c_char);
        return xmlStrndup(str1, size);
    }
    memcpy(
        ret as *mut libc::c_void,
        str1 as *const libc::c_void,
        (size as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    );
    memcpy(
        &mut *ret.offset(size as isize) as *mut xmlChar as *mut libc::c_void,
        str2 as *const libc::c_void,
        (len as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    );
    *ret.offset((size + len) as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrcat(
    mut cur: *mut xmlChar,
    mut add: *const xmlChar,
) -> *mut xmlChar {
    let mut p: *const xmlChar = add;
    if add.is_null() {
        return cur;
    }
    if cur.is_null() {
        return xmlStrdup(add);
    }
    while *p as libc::c_int != 0 as libc::c_int {
        p = p.offset(1);
    }
    return xmlStrncat(cur, add, p.offset_from(add) as libc::c_long as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrPrintf(
    mut buf: *mut xmlChar,
    mut len: libc::c_int,
    mut msg: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut args_0: ::std::ffi::VaListImpl;
    let mut ret: libc::c_int = 0;
    if buf.is_null() || msg.is_null() {
        return -(1 as libc::c_int);
    }
    args_0 = args.clone();
    ret = vsnprintf(
        buf as *mut libc::c_char,
        len as libc::c_ulong,
        msg,
        args_0.as_va_list(),
    );
    *buf.offset((len - 1 as libc::c_int) as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrVPrintf(
    mut buf: *mut xmlChar,
    mut len: libc::c_int,
    mut msg: *const libc::c_char,
    mut ap: ::std::ffi::VaList,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    if buf.is_null() || msg.is_null() {
        return -(1 as libc::c_int);
    }
    ret = vsnprintf(
        buf as *mut libc::c_char,
        len as libc::c_ulong,
        msg,
        ap.as_va_list(),
    );
    *buf.offset((len - 1 as libc::c_int) as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Size(mut utf: *const xmlChar) -> libc::c_int {
    let mut mask: xmlChar = 0;
    let mut len: libc::c_int = 0;
    if utf.is_null() {
        return -(1 as libc::c_int);
    }
    if (*utf as libc::c_int) < 0x80 as libc::c_int {
        return 1 as libc::c_int;
    }
    if *utf as libc::c_int & 0x40 as libc::c_int == 0 {
        return -(1 as libc::c_int);
    }
    len = 2 as libc::c_int;
    mask = 0x20 as libc::c_int as xmlChar;
    while mask as libc::c_int != 0 as libc::c_int {
        if *utf as libc::c_int & mask as libc::c_int == 0 {
            return len;
        }
        len += 1;
        mask = (mask as libc::c_int >> 1 as libc::c_int) as xmlChar;
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Charcmp(
    mut utf1: *const xmlChar,
    mut utf2: *const xmlChar,
) -> libc::c_int {
    if utf1.is_null() {
        if utf2.is_null() {
            return 0 as libc::c_int;
        }
        return -(1 as libc::c_int);
    }
    return xmlStrncmp(utf1, utf2, xmlUTF8Size(utf1));
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strlen(mut utf: *const xmlChar) -> libc::c_int {
    let mut ret: size_t = 0 as libc::c_int as size_t;
    if utf.is_null() {
        return -(1 as libc::c_int);
    }
    while *utf as libc::c_int != 0 as libc::c_int {
        if *utf.offset(0 as libc::c_int as isize) as libc::c_int & 0x80 as libc::c_int
            != 0
        {
            if *utf.offset(1 as libc::c_int as isize) as libc::c_int
                & 0xc0 as libc::c_int != 0x80 as libc::c_int
            {
                return -(1 as libc::c_int);
            }
            if *utf.offset(0 as libc::c_int as isize) as libc::c_int
                & 0xe0 as libc::c_int == 0xe0 as libc::c_int
            {
                if *utf.offset(2 as libc::c_int as isize) as libc::c_int
                    & 0xc0 as libc::c_int != 0x80 as libc::c_int
                {
                    return -(1 as libc::c_int);
                }
                if *utf.offset(0 as libc::c_int as isize) as libc::c_int
                    & 0xf0 as libc::c_int == 0xf0 as libc::c_int
                {
                    if *utf.offset(0 as libc::c_int as isize) as libc::c_int
                        & 0xf8 as libc::c_int != 0xf0 as libc::c_int
                        || *utf.offset(3 as libc::c_int as isize) as libc::c_int
                            & 0xc0 as libc::c_int != 0x80 as libc::c_int
                    {
                        return -(1 as libc::c_int);
                    }
                    utf = utf.offset(4 as libc::c_int as isize);
                } else {
                    utf = utf.offset(3 as libc::c_int as isize);
                }
            } else {
                utf = utf.offset(2 as libc::c_int as isize);
            }
        } else {
            utf = utf.offset(1);
        }
        ret = ret.wrapping_add(1);
    }
    return (if ret > 2147483647 as libc::c_int as libc::c_ulong {
        0 as libc::c_int as libc::c_ulong
    } else {
        ret
    }) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetUTF8Char(
    mut utf: *const libc::c_uchar,
    mut len: *mut libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut c: libc::c_uint = 0;
    if !utf.is_null() {
        if !len.is_null() {
            if !(*len < 1 as libc::c_int) {
                c = *utf.offset(0 as libc::c_int as isize) as libc::c_uint;
                if c & 0x80 as libc::c_int as libc::c_uint != 0 {
                    if *len < 2 as libc::c_int {
                        current_block = 3966416321279884290;
                    } else if *utf.offset(1 as libc::c_int as isize) as libc::c_int
                            & 0xc0 as libc::c_int != 0x80 as libc::c_int
                        {
                        current_block = 3966416321279884290;
                    } else if c & 0xe0 as libc::c_int as libc::c_uint
                            == 0xe0 as libc::c_int as libc::c_uint
                        {
                        if *len < 3 as libc::c_int {
                            current_block = 3966416321279884290;
                        } else if *utf.offset(2 as libc::c_int as isize) as libc::c_int
                                & 0xc0 as libc::c_int != 0x80 as libc::c_int
                            {
                            current_block = 3966416321279884290;
                        } else if c & 0xf0 as libc::c_int as libc::c_uint
                                == 0xf0 as libc::c_int as libc::c_uint
                            {
                            if *len < 4 as libc::c_int {
                                current_block = 3966416321279884290;
                            } else if c & 0xf8 as libc::c_int as libc::c_uint
                                    != 0xf0 as libc::c_int as libc::c_uint
                                    || *utf.offset(3 as libc::c_int as isize) as libc::c_int
                                        & 0xc0 as libc::c_int != 0x80 as libc::c_int
                                {
                                current_block = 3966416321279884290;
                            } else {
                                *len = 4 as libc::c_int;
                                c = ((*utf.offset(0 as libc::c_int as isize) as libc::c_int
                                    & 0x7 as libc::c_int) << 18 as libc::c_int) as libc::c_uint;
                                c
                                    |= ((*utf.offset(1 as libc::c_int as isize) as libc::c_int
                                        & 0x3f as libc::c_int) << 12 as libc::c_int)
                                        as libc::c_uint;
                                c
                                    |= ((*utf.offset(2 as libc::c_int as isize) as libc::c_int
                                        & 0x3f as libc::c_int) << 6 as libc::c_int) as libc::c_uint;
                                c
                                    |= (*utf.offset(3 as libc::c_int as isize) as libc::c_int
                                        & 0x3f as libc::c_int) as libc::c_uint;
                                current_block = 11932355480408055363;
                            }
                        } else {
                            *len = 3 as libc::c_int;
                            c = ((*utf.offset(0 as libc::c_int as isize) as libc::c_int
                                & 0xf as libc::c_int) << 12 as libc::c_int) as libc::c_uint;
                            c
                                |= ((*utf.offset(1 as libc::c_int as isize) as libc::c_int
                                    & 0x3f as libc::c_int) << 6 as libc::c_int) as libc::c_uint;
                            c
                                |= (*utf.offset(2 as libc::c_int as isize) as libc::c_int
                                    & 0x3f as libc::c_int) as libc::c_uint;
                            current_block = 11932355480408055363;
                        }
                    } else {
                        *len = 2 as libc::c_int;
                        c = ((*utf.offset(0 as libc::c_int as isize) as libc::c_int
                            & 0x1f as libc::c_int) << 6 as libc::c_int) as libc::c_uint;
                        c
                            |= (*utf.offset(1 as libc::c_int as isize) as libc::c_int
                                & 0x3f as libc::c_int) as libc::c_uint;
                        current_block = 11932355480408055363;
                    }
                } else {
                    *len = 1 as libc::c_int;
                    current_block = 11932355480408055363;
                }
                match current_block {
                    3966416321279884290 => {}
                    _ => return c as libc::c_int,
                }
            }
        }
    }
    if !len.is_null() {
        *len = 0 as libc::c_int;
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCheckUTF8(mut utf: *const libc::c_uchar) -> libc::c_int {
    let mut ix: libc::c_int = 0;
    let mut c: libc::c_uchar = 0;
    if utf.is_null() {
        return 0 as libc::c_int;
    }
    loop {
        c = *utf.offset(0 as libc::c_int as isize);
        if !(c != 0) {
            break;
        }
        ix = 0 as libc::c_int;
        if c as libc::c_int & 0x80 as libc::c_int == 0 as libc::c_int {
            ix = 1 as libc::c_int;
        } else if c as libc::c_int & 0xe0 as libc::c_int == 0xc0 as libc::c_int {
            if *utf.offset(1 as libc::c_int as isize) as libc::c_int
                & 0xc0 as libc::c_int != 0x80 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            ix = 2 as libc::c_int;
        } else if c as libc::c_int & 0xf0 as libc::c_int == 0xe0 as libc::c_int {
            if *utf.offset(1 as libc::c_int as isize) as libc::c_int
                & 0xc0 as libc::c_int != 0x80 as libc::c_int
                || *utf.offset(2 as libc::c_int as isize) as libc::c_int
                    & 0xc0 as libc::c_int != 0x80 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            ix = 3 as libc::c_int;
        } else if c as libc::c_int & 0xf8 as libc::c_int == 0xf0 as libc::c_int {
            if *utf.offset(1 as libc::c_int as isize) as libc::c_int
                & 0xc0 as libc::c_int != 0x80 as libc::c_int
                || *utf.offset(2 as libc::c_int as isize) as libc::c_int
                    & 0xc0 as libc::c_int != 0x80 as libc::c_int
                || *utf.offset(3 as libc::c_int as isize) as libc::c_int
                    & 0xc0 as libc::c_int != 0x80 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            ix = 4 as libc::c_int;
        } else {
            return 0 as libc::c_int
        }
        utf = utf.offset(ix as isize);
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strsize(
    mut utf: *const xmlChar,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut ptr: *const xmlChar = utf;
    let mut ch: libc::c_int = 0;
    let mut ret: size_t = 0;
    if utf.is_null() {
        return 0 as libc::c_int;
    }
    if len <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    loop {
        let fresh15 = len;
        len = len - 1;
        if !(fresh15 > 0 as libc::c_int) {
            break;
        }
        if *ptr == 0 {
            break;
        }
        let fresh16 = ptr;
        ptr = ptr.offset(1);
        ch = *fresh16 as libc::c_int;
        if ch & 0x80 as libc::c_int != 0 {
            loop {
                ch <<= 1 as libc::c_int;
                if !(ch & 0x80 as libc::c_int != 0) {
                    break;
                }
                if *ptr as libc::c_int == 0 as libc::c_int {
                    break;
                }
                ptr = ptr.offset(1);
            }
        }
    }
    ret = ptr.offset_from(utf) as libc::c_long as size_t;
    return (if ret > 2147483647 as libc::c_int as libc::c_ulong {
        0 as libc::c_int as libc::c_ulong
    } else {
        ret
    }) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strndup(
    mut utf: *const xmlChar,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut i: libc::c_int = 0;
    if utf.is_null() || len < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    i = xmlUTF8Strsize(utf, len);
    ret = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (i as size_t)
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if ret.is_null() {
        return 0 as *mut xmlChar;
    }
    memcpy(
        ret as *mut libc::c_void,
        utf as *const libc::c_void,
        (i as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    );
    *ret.offset(i as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strpos(
    mut utf: *const xmlChar,
    mut pos: libc::c_int,
) -> *const xmlChar {
    let mut ch: libc::c_int = 0;
    if utf.is_null() {
        // type
        return 0 as *const libc::c_void as *const xmlChar;
    }
    if pos < 0 as libc::c_int {
        return 0 as *const xmlChar;
    }
    loop {
        let fresh17 = pos;
        pos = pos - 1;
        if !(fresh17 != 0) {
            break;
        }
        let fresh18 = utf;
        utf = utf.offset(1);
        ch = *fresh18 as libc::c_int;
        if ch == 0 as libc::c_int {
            return 0 as *const xmlChar;
        }
        if ch & 0x80 as libc::c_int != 0 {
            if ch & 0xc0 as libc::c_int != 0xc0 as libc::c_int {
                return 0 as *const xmlChar;
            }
            loop {
                ch <<= 1 as libc::c_int;
                if !(ch & 0x80 as libc::c_int != 0) {
                    break;
                }
                let fresh19 = utf;
                utf = utf.offset(1);
                if *fresh19 as libc::c_int & 0xc0 as libc::c_int != 0x80 as libc::c_int {
                    return 0 as *const xmlChar;
                }
            }
        }
    }
    return utf as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strloc(
    mut utf: *const xmlChar,
    mut utfchar: *const xmlChar,
) -> libc::c_int {
    let mut i: size_t = 0;
    let mut size: libc::c_int = 0;
    let mut ch: libc::c_int = 0;
    if utf.is_null() || utfchar.is_null() {
        return -(1 as libc::c_int);
    }
    size = xmlUTF8Strsize(utfchar, 1 as libc::c_int);
    i = 0 as libc::c_int as size_t;
    loop {
        ch = *utf as libc::c_int;
        if !(ch != 0 as libc::c_int) {
            break;
        }
        if xmlStrncmp(utf, utfchar, size) == 0 as libc::c_int {
            return (if i > 2147483647 as libc::c_int as libc::c_ulong {
                0 as libc::c_int as libc::c_ulong
            } else {
                i
            }) as libc::c_int;
        }
        utf = utf.offset(1);
        if ch & 0x80 as libc::c_int != 0 {
            if ch & 0xc0 as libc::c_int != 0xc0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            loop {
                ch <<= 1 as libc::c_int;
                if !(ch & 0x80 as libc::c_int != 0) {
                    break;
                }
                let fresh20 = utf;
                utf = utf.offset(1);
                if *fresh20 as libc::c_int & 0xc0 as libc::c_int != 0x80 as libc::c_int {
                    return -(1 as libc::c_int);
                }
            }
        }
        i = i.wrapping_add(1);
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strsub(
    mut utf: *const xmlChar,
    mut start: libc::c_int,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut i: libc::c_int = 0;
    let mut ch: libc::c_int = 0;
    if utf.is_null() {
        return 0 as *mut xmlChar;
    }
    if start < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    if len < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    i = 0 as libc::c_int;
    while i < start {
        let fresh21 = utf;
        utf = utf.offset(1);
        ch = *fresh21 as libc::c_int;
        if ch == 0 as libc::c_int {
            return 0 as *mut xmlChar;
        }
        if ch & 0x80 as libc::c_int != 0 {
            if ch & 0xc0 as libc::c_int != 0xc0 as libc::c_int {
                return 0 as *mut xmlChar;
            }
            loop {
                ch <<= 1 as libc::c_int;
                if !(ch & 0x80 as libc::c_int != 0) {
                    break;
                }
                let fresh22 = utf;
                utf = utf.offset(1);
                if *fresh22 as libc::c_int & 0xc0 as libc::c_int != 0x80 as libc::c_int {
                    return 0 as *mut xmlChar;
                }
            }
        }
        i += 1;
    }
    return xmlUTF8Strndup(utf, len);
}
#[no_mangle]
pub unsafe extern "C" fn xmlEscapeFormatString(
    mut msg: *mut *mut xmlChar,
) -> *mut xmlChar {
    let mut msgPtr: *mut xmlChar = 0 as *mut xmlChar;
    let mut result: *mut xmlChar = 0 as *mut xmlChar;
    let mut resultPtr: *mut xmlChar = 0 as *mut xmlChar;
    let mut count: size_t = 0 as libc::c_int as size_t;
    let mut msgLen: size_t = 0 as libc::c_int as size_t;
    let mut resultLen: size_t = 0 as libc::c_int as size_t;
    if msg.is_null() || (*msg).is_null() {
        return 0 as *mut xmlChar;
    }
    msgPtr = *msg;
    while *msgPtr as libc::c_int != '\u{0}' as i32 {
        msgLen = msgLen.wrapping_add(1);
        if *msgPtr as libc::c_int == '%' as i32 {
            count = count.wrapping_add(1);
        }
        msgPtr = msgPtr.offset(1);
    }
    if count == 0 as libc::c_int as libc::c_ulong {
        return *msg;
    }
    if count > 2147483647 as libc::c_int as libc::c_ulong
        || msgLen > (2147483647 as libc::c_int as libc::c_ulong).wrapping_sub(count)
    {
        return 0 as *mut xmlChar;
    }
    resultLen = msgLen
        .wrapping_add(count)
        .wrapping_add(1 as libc::c_int as libc::c_ulong);
    result = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(resultLen.wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong))
        as *mut xmlChar;
    if result.is_null() {
        xmlFree.expect("non-null function pointer")(*msg as *mut libc::c_void);
        *msg = 0 as *mut xmlChar;
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    msgPtr = *msg;
    resultPtr = result;
    while *msgPtr as libc::c_int != '\u{0}' as i32 {
        *resultPtr = *msgPtr;
        if *msgPtr as libc::c_int == '%' as i32 {
            resultPtr = resultPtr.offset(1);
            *resultPtr = '%' as i32 as xmlChar;
        }
        msgPtr = msgPtr.offset(1);
        resultPtr = resultPtr.offset(1);
    }
    *result
        .offset(
            resultLen.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
        ) = '\u{0}' as i32 as xmlChar;
    xmlFree.expect("non-null function pointer")(*msg as *mut libc::c_void);
    *msg = result;
    return *msg;
}
