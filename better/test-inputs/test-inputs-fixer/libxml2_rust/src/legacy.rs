use :: libc;
extern "C" {
    pub type _xmlBuf;
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlStartTag;
    pub type _xmlAutomataState;
    pub type _xmlAutomata;
    pub type _xmlValidState;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn __xmlGenericErrorContext() -> *mut *mut libc::c_void;
    fn __xmlGenericError() -> *mut xmlGenericErrorFunc;
    fn xmlParserValidityError(ctx: *mut libc::c_void, msg: *const i8, _: ...);
    fn xmlParserValidityWarning(ctx: *mut libc::c_void, msg: *const i8, _: ...);
    fn xmlSAX2GetPublicId(ctx: *mut libc::c_void) -> *const xmlChar;
    fn xmlSAX2GetSystemId(ctx: *mut libc::c_void) -> *const xmlChar;
    fn xmlSAX2GetLineNumber(ctx: *mut libc::c_void) -> i32;
    fn xmlSAX2GetColumnNumber(ctx: *mut libc::c_void) -> i32;
    fn xmlSAX2IsStandalone(ctx: *mut libc::c_void) -> i32;
    fn xmlSAX2HasInternalSubset(ctx: *mut libc::c_void) -> i32;
    fn xmlSAX2HasExternalSubset(ctx: *mut libc::c_void) -> i32;
    fn xmlSAX2InternalSubset(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    );
    fn xmlSAX2ExternalSubset(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    );
    fn xmlSAX2GetEntity(ctx: *mut libc::c_void, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlSAX2GetParameterEntity(ctx: *mut libc::c_void, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlSAX2ResolveEntity(
        ctx: *mut libc::c_void,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
    ) -> xmlParserInputPtr;
    fn xmlSAX2EntityDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: i32,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
        content: *mut xmlChar,
    );
    fn xmlSAX2AttributeDecl(
        ctx: *mut libc::c_void,
        elem: *const xmlChar,
        fullname: *const xmlChar,
        type_0: i32,
        def: i32,
        defaultValue: *const xmlChar,
        tree: xmlEnumerationPtr,
    );
    fn xmlSAX2ElementDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: i32,
        content: xmlElementContentPtr,
    );
    fn xmlSAX2NotationDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
    );
    fn xmlSAX2UnparsedEntityDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
        notationName: *const xmlChar,
    );
    fn xmlSAX2StartDocument(ctx: *mut libc::c_void);
    fn xmlSAX2EndDocument(ctx: *mut libc::c_void);
    fn xmlSAX2StartElement(
        ctx: *mut libc::c_void,
        fullname: *const xmlChar,
        atts: *mut *const xmlChar,
    );
    fn xmlSAX2EndElement(ctx: *mut libc::c_void, name: *const xmlChar);
    fn xmlSAX2Reference(ctx: *mut libc::c_void, name: *const xmlChar);
    fn xmlSAX2Characters(ctx: *mut libc::c_void, ch: *const xmlChar, len: i32);
    fn xmlSAX2ProcessingInstruction(
        ctx: *mut libc::c_void,
        target: *const xmlChar,
        data: *const xmlChar,
    );
    fn xmlSAX2Comment(ctx: *mut libc::c_void, value: *const xmlChar);
    fn xmlSAX2CDataBlock(ctx: *mut libc::c_void, value: *const xmlChar, len: i32);
}
pub type xmlChar = u8;
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
pub type xmlSAXHandler = _xmlSAXHandler;
pub type xmlSAXHandlerPtr = *mut xmlSAXHandler;
pub type xmlNsPtr = *mut xmlNs;
pub type xmlGenericErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type htmlParserCtxtPtr = xmlParserCtxtPtr;
#[no_mangle]
pub extern "C" fn htmlDecodeEntities(
    mut _ctxt: htmlParserCtxtPtr,
    mut _len: i32,
    mut _end: xmlChar,
    mut _end2: xmlChar,
    mut _end3: xmlChar,
) -> *mut xmlChar {
    static mut deprecated: i32 = 0 as i32;
    if (unsafe { deprecated }) == 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"htmlDecodeEntities() deprecated function reached\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { deprecated = 1 as i32 });
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlInitializePredefinedEntities() {}
#[no_mangle]
pub extern "C" fn xmlCleanupPredefinedEntities() {}
static mut xmlFeaturesList: [*const i8; 42] = [
    b"validate\0" as *const u8 as *const i8,
    b"load subset\0" as *const u8 as *const i8,
    b"keep blanks\0" as *const u8 as *const i8,
    b"disable SAX\0" as *const u8 as *const i8,
    b"fetch external entities\0" as *const u8 as *const i8,
    b"substitute entities\0" as *const u8 as *const i8,
    b"gather line info\0" as *const u8 as *const i8,
    b"user data\0" as *const u8 as *const i8,
    b"is html\0" as *const u8 as *const i8,
    b"is standalone\0" as *const u8 as *const i8,
    b"stop parser\0" as *const u8 as *const i8,
    b"document\0" as *const u8 as *const i8,
    b"is well formed\0" as *const u8 as *const i8,
    b"is valid\0" as *const u8 as *const i8,
    b"SAX block\0" as *const u8 as *const i8,
    b"SAX function internalSubset\0" as *const u8 as *const i8,
    b"SAX function isStandalone\0" as *const u8 as *const i8,
    b"SAX function hasInternalSubset\0" as *const u8 as *const i8,
    b"SAX function hasExternalSubset\0" as *const u8 as *const i8,
    b"SAX function resolveEntity\0" as *const u8 as *const i8,
    b"SAX function getEntity\0" as *const u8 as *const i8,
    b"SAX function entityDecl\0" as *const u8 as *const i8,
    b"SAX function notationDecl\0" as *const u8 as *const i8,
    b"SAX function attributeDecl\0" as *const u8 as *const i8,
    b"SAX function elementDecl\0" as *const u8 as *const i8,
    b"SAX function unparsedEntityDecl\0" as *const u8 as *const i8,
    b"SAX function setDocumentLocator\0" as *const u8 as *const i8,
    b"SAX function startDocument\0" as *const u8 as *const i8,
    b"SAX function endDocument\0" as *const u8 as *const i8,
    b"SAX function startElement\0" as *const u8 as *const i8,
    b"SAX function endElement\0" as *const u8 as *const i8,
    b"SAX function reference\0" as *const u8 as *const i8,
    b"SAX function characters\0" as *const u8 as *const i8,
    b"SAX function ignorableWhitespace\0" as *const u8 as *const i8,
    b"SAX function processingInstruction\0" as *const u8 as *const i8,
    b"SAX function comment\0" as *const u8 as *const i8,
    b"SAX function warning\0" as *const u8 as *const i8,
    b"SAX function error\0" as *const u8 as *const i8,
    b"SAX function fatalError\0" as *const u8 as *const i8,
    b"SAX function getParameterEntity\0" as *const u8 as *const i8,
    b"SAX function cdataBlock\0" as *const u8 as *const i8,
    b"SAX function externalSubset\0" as *const u8 as *const i8,
];
#[no_mangle]
pub extern "C" fn xmlGetFeaturesList(mut len: *mut i32, mut result: *mut *const i8) -> i32 {
    let mut ret: i32 = 0;
    let mut i: i32 = 0;
    ret = (::std::mem::size_of::<[*const i8; 42]>() as u64)
        .wrapping_div(::std::mem::size_of::<*const i8>() as u64) as i32;
    if len.is_null() || result.is_null() {
        return ret;
    }
    if (unsafe { *len }) < 0 as i32 || (unsafe { *len }) >= 1000 as i32 {
        return -(1 as i32);
    }
    if (unsafe { *len }) > ret {
        (unsafe { *len = ret });
    }
    i = 0 as i32;
    while i < (unsafe { *len }) {
        let fresh0 = unsafe { &mut (*result.offset(i as isize)) };
        *fresh0 = unsafe { xmlFeaturesList[i as usize] };
        i += 1;
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlGetFeature(
    mut ctxt: xmlParserCtxtPtr,
    mut name: *const i8,
    mut result: *mut libc::c_void,
) -> i32 {
    if ctxt.is_null() || name.is_null() || result.is_null() {
        return -(1 as i32);
    }
    if (unsafe { strcmp(name, b"validate\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { *(result as *mut i32) = (*ctxt).validate });
    } else if (unsafe { strcmp(name, b"keep blanks\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { *(result as *mut i32) = (*ctxt).keepBlanks });
    } else if (unsafe { strcmp(name, b"disable SAX\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { *(result as *mut i32) = (*ctxt).disableSAX });
    } else if (unsafe { strcmp(name, b"fetch external entities\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { *(result as *mut i32) = (*ctxt).loadsubset });
    } else if (unsafe { strcmp(name, b"substitute entities\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { *(result as *mut i32) = (*ctxt).replaceEntities });
    } else if (unsafe { strcmp(name, b"gather line info\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { *(result as *mut i32) = (*ctxt).record_info });
    } else if (unsafe { strcmp(name, b"user data\0" as *const u8 as *const i8) }) == 0 {
        let fresh1 = unsafe { &mut (*(result as *mut *mut libc::c_void)) };
        *fresh1 = unsafe { (*ctxt).userData };
    } else if (unsafe { strcmp(name, b"is html\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { *(result as *mut i32) = (*ctxt).html });
    } else if (unsafe { strcmp(name, b"is standalone\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { *(result as *mut i32) = (*ctxt).standalone });
    } else if (unsafe { strcmp(name, b"document\0" as *const u8 as *const i8) }) == 0 {
        let fresh2 = unsafe { &mut (*(result as *mut xmlDocPtr)) };
        *fresh2 = unsafe { (*ctxt).myDoc };
    } else if (unsafe { strcmp(name, b"is well formed\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { *(result as *mut i32) = (*ctxt).wellFormed });
    } else if (unsafe { strcmp(name, b"is valid\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { *(result as *mut i32) = (*ctxt).valid });
    } else if (unsafe { strcmp(name, b"SAX block\0" as *const u8 as *const i8) }) == 0 {
        let fresh3 = unsafe { &mut (*(result as *mut xmlSAXHandlerPtr)) };
        *fresh3 = unsafe { (*ctxt).sax };
    } else if (unsafe { strcmp(
        name,
        b"SAX function internalSubset\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh4 = unsafe { &mut (*(result as *mut internalSubsetSAXFunc)) };
        *fresh4 = unsafe { (*(*ctxt).sax).internalSubset };
    } else if (unsafe { strcmp(
        name,
        b"SAX function isStandalone\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh5 = unsafe { &mut (*(result as *mut isStandaloneSAXFunc)) };
        *fresh5 = unsafe { (*(*ctxt).sax).isStandalone };
    } else if (unsafe { strcmp(
        name,
        b"SAX function hasInternalSubset\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh6 = unsafe { &mut (*(result as *mut hasInternalSubsetSAXFunc)) };
        *fresh6 = unsafe { (*(*ctxt).sax).hasInternalSubset };
    } else if (unsafe { strcmp(
        name,
        b"SAX function hasExternalSubset\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh7 = unsafe { &mut (*(result as *mut hasExternalSubsetSAXFunc)) };
        *fresh7 = unsafe { (*(*ctxt).sax).hasExternalSubset };
    } else if (unsafe { strcmp(
        name,
        b"SAX function resolveEntity\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh8 = unsafe { &mut (*(result as *mut resolveEntitySAXFunc)) };
        *fresh8 = unsafe { (*(*ctxt).sax).resolveEntity };
    } else if (unsafe { strcmp(name, b"SAX function getEntity\0" as *const u8 as *const i8) }) == 0 {
        let fresh9 = unsafe { &mut (*(result as *mut getEntitySAXFunc)) };
        *fresh9 = unsafe { (*(*ctxt).sax).getEntity };
    } else if (unsafe { strcmp(name, b"SAX function entityDecl\0" as *const u8 as *const i8) }) == 0 {
        let fresh10 = unsafe { &mut (*(result as *mut entityDeclSAXFunc)) };
        *fresh10 = unsafe { (*(*ctxt).sax).entityDecl };
    } else if (unsafe { strcmp(
        name,
        b"SAX function notationDecl\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh11 = unsafe { &mut (*(result as *mut notationDeclSAXFunc)) };
        *fresh11 = unsafe { (*(*ctxt).sax).notationDecl };
    } else if (unsafe { strcmp(
        name,
        b"SAX function attributeDecl\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh12 = unsafe { &mut (*(result as *mut attributeDeclSAXFunc)) };
        *fresh12 = unsafe { (*(*ctxt).sax).attributeDecl };
    } else if (unsafe { strcmp(
        name,
        b"SAX function elementDecl\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh13 = unsafe { &mut (*(result as *mut elementDeclSAXFunc)) };
        *fresh13 = unsafe { (*(*ctxt).sax).elementDecl };
    } else if (unsafe { strcmp(
        name,
        b"SAX function unparsedEntityDecl\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh14 = unsafe { &mut (*(result as *mut unparsedEntityDeclSAXFunc)) };
        *fresh14 = unsafe { (*(*ctxt).sax).unparsedEntityDecl };
    } else if (unsafe { strcmp(
        name,
        b"SAX function setDocumentLocator\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh15 = unsafe { &mut (*(result as *mut setDocumentLocatorSAXFunc)) };
        *fresh15 = unsafe { (*(*ctxt).sax).setDocumentLocator };
    } else if (unsafe { strcmp(
        name,
        b"SAX function startDocument\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh16 = unsafe { &mut (*(result as *mut startDocumentSAXFunc)) };
        *fresh16 = unsafe { (*(*ctxt).sax).startDocument };
    } else if (unsafe { strcmp(
        name,
        b"SAX function endDocument\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh17 = unsafe { &mut (*(result as *mut endDocumentSAXFunc)) };
        *fresh17 = unsafe { (*(*ctxt).sax).endDocument };
    } else if (unsafe { strcmp(
        name,
        b"SAX function startElement\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh18 = unsafe { &mut (*(result as *mut startElementSAXFunc)) };
        *fresh18 = unsafe { (*(*ctxt).sax).startElement };
    } else if (unsafe { strcmp(name, b"SAX function endElement\0" as *const u8 as *const i8) }) == 0 {
        let fresh19 = unsafe { &mut (*(result as *mut endElementSAXFunc)) };
        *fresh19 = unsafe { (*(*ctxt).sax).endElement };
    } else if (unsafe { strcmp(name, b"SAX function reference\0" as *const u8 as *const i8) }) == 0 {
        let fresh20 = unsafe { &mut (*(result as *mut referenceSAXFunc)) };
        *fresh20 = unsafe { (*(*ctxt).sax).reference };
    } else if (unsafe { strcmp(name, b"SAX function characters\0" as *const u8 as *const i8) }) == 0 {
        let fresh21 = unsafe { &mut (*(result as *mut charactersSAXFunc)) };
        *fresh21 = unsafe { (*(*ctxt).sax).characters };
    } else if (unsafe { strcmp(
        name,
        b"SAX function ignorableWhitespace\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh22 = unsafe { &mut (*(result as *mut ignorableWhitespaceSAXFunc)) };
        *fresh22 = unsafe { (*(*ctxt).sax).ignorableWhitespace };
    } else if (unsafe { strcmp(
        name,
        b"SAX function processingInstruction\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh23 = unsafe { &mut (*(result as *mut processingInstructionSAXFunc)) };
        *fresh23 = unsafe { (*(*ctxt).sax).processingInstruction };
    } else if (unsafe { strcmp(name, b"SAX function comment\0" as *const u8 as *const i8) }) == 0 {
        let fresh24 = unsafe { &mut (*(result as *mut commentSAXFunc)) };
        *fresh24 = unsafe { (*(*ctxt).sax).comment };
    } else if (unsafe { strcmp(name, b"SAX function warning\0" as *const u8 as *const i8) }) == 0 {
        let fresh25 = unsafe { &mut (*(result as *mut warningSAXFunc)) };
        *fresh25 = unsafe { (*(*ctxt).sax).warning };
    } else if (unsafe { strcmp(name, b"SAX function error\0" as *const u8 as *const i8) }) == 0 {
        let fresh26 = unsafe { &mut (*(result as *mut errorSAXFunc)) };
        *fresh26 = unsafe { (*(*ctxt).sax).error };
    } else if (unsafe { strcmp(name, b"SAX function fatalError\0" as *const u8 as *const i8) }) == 0 {
        let fresh27 = unsafe { &mut (*(result as *mut fatalErrorSAXFunc)) };
        *fresh27 = unsafe { (*(*ctxt).sax).fatalError };
    } else if (unsafe { strcmp(
        name,
        b"SAX function getParameterEntity\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh28 = unsafe { &mut (*(result as *mut getParameterEntitySAXFunc)) };
        *fresh28 = unsafe { (*(*ctxt).sax).getParameterEntity };
    } else if (unsafe { strcmp(name, b"SAX function cdataBlock\0" as *const u8 as *const i8) }) == 0 {
        let fresh29 = unsafe { &mut (*(result as *mut cdataBlockSAXFunc)) };
        *fresh29 = unsafe { (*(*ctxt).sax).cdataBlock };
    } else if (unsafe { strcmp(
        name,
        b"SAX function externalSubset\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh30 = unsafe { &mut (*(result as *mut externalSubsetSAXFunc)) };
        *fresh30 = unsafe { (*(*ctxt).sax).externalSubset };
    } else {
        return -(1 as i32);
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlSetFeature(
    mut ctxt: xmlParserCtxtPtr,
    mut name: *const i8,
    mut value: *mut libc::c_void,
) -> i32 {
    if ctxt.is_null() || name.is_null() || value.is_null() {
        return -(1 as i32);
    }
    if (unsafe { strcmp(name, b"validate\0" as *const u8 as *const i8) }) == 0 {
        let mut newvalidate: i32 = unsafe { *(value as *mut i32) };
        if (unsafe { (*ctxt).validate }) == 0 && newvalidate != 0 as i32 {
            if unsafe { ((*ctxt).vctxt.warning).is_none() } {
                let fresh31 = unsafe { &mut ((*ctxt).vctxt.warning) };
                *fresh31 = Some(
                    xmlParserValidityWarning
                        as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
                );
            }
            if unsafe { ((*ctxt).vctxt.error).is_none() } {
                let fresh32 = unsafe { &mut ((*ctxt).vctxt.error) };
                *fresh32 = Some(
                    xmlParserValidityError
                        as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
                );
            }
            (unsafe { (*ctxt).vctxt.nodeMax = 0 as i32 });
        }
        (unsafe { (*ctxt).validate = newvalidate });
    } else if (unsafe { strcmp(name, b"keep blanks\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { (*ctxt).keepBlanks = *(value as *mut i32) });
    } else if (unsafe { strcmp(name, b"disable SAX\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { (*ctxt).disableSAX = *(value as *mut i32) });
    } else if (unsafe { strcmp(name, b"fetch external entities\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { (*ctxt).loadsubset = *(value as *mut i32) });
    } else if (unsafe { strcmp(name, b"substitute entities\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { (*ctxt).replaceEntities = *(value as *mut i32) });
    } else if (unsafe { strcmp(name, b"gather line info\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { (*ctxt).record_info = *(value as *mut i32) });
    } else if (unsafe { strcmp(name, b"user data\0" as *const u8 as *const i8) }) == 0 {
        let fresh33 = unsafe { &mut ((*ctxt).userData) };
        *fresh33 = unsafe { *(value as *mut *mut libc::c_void) };
    } else if (unsafe { strcmp(name, b"is html\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { (*ctxt).html = *(value as *mut i32) });
    } else if (unsafe { strcmp(name, b"is standalone\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { (*ctxt).standalone = *(value as *mut i32) });
    } else if (unsafe { strcmp(name, b"document\0" as *const u8 as *const i8) }) == 0 {
        let fresh34 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh34 = unsafe { *(value as *mut xmlDocPtr) };
    } else if (unsafe { strcmp(name, b"is well formed\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { (*ctxt).wellFormed = *(value as *mut i32) });
    } else if (unsafe { strcmp(name, b"is valid\0" as *const u8 as *const i8) }) == 0 {
        (unsafe { (*ctxt).valid = *(value as *mut i32) });
    } else if (unsafe { strcmp(name, b"SAX block\0" as *const u8 as *const i8) }) == 0 {
        let fresh35 = unsafe { &mut ((*ctxt).sax) };
        *fresh35 = unsafe { *(value as *mut xmlSAXHandlerPtr) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function internalSubset\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh36 = unsafe { &mut ((*(*ctxt).sax).internalSubset) };
        *fresh36 = unsafe { *(value as *mut internalSubsetSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function isStandalone\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh37 = unsafe { &mut ((*(*ctxt).sax).isStandalone) };
        *fresh37 = unsafe { *(value as *mut isStandaloneSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function hasInternalSubset\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh38 = unsafe { &mut ((*(*ctxt).sax).hasInternalSubset) };
        *fresh38 = unsafe { *(value as *mut hasInternalSubsetSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function hasExternalSubset\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh39 = unsafe { &mut ((*(*ctxt).sax).hasExternalSubset) };
        *fresh39 = unsafe { *(value as *mut hasExternalSubsetSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function resolveEntity\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh40 = unsafe { &mut ((*(*ctxt).sax).resolveEntity) };
        *fresh40 = unsafe { *(value as *mut resolveEntitySAXFunc) };
    } else if (unsafe { strcmp(name, b"SAX function getEntity\0" as *const u8 as *const i8) }) == 0 {
        let fresh41 = unsafe { &mut ((*(*ctxt).sax).getEntity) };
        *fresh41 = unsafe { *(value as *mut getEntitySAXFunc) };
    } else if (unsafe { strcmp(name, b"SAX function entityDecl\0" as *const u8 as *const i8) }) == 0 {
        let fresh42 = unsafe { &mut ((*(*ctxt).sax).entityDecl) };
        *fresh42 = unsafe { *(value as *mut entityDeclSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function notationDecl\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh43 = unsafe { &mut ((*(*ctxt).sax).notationDecl) };
        *fresh43 = unsafe { *(value as *mut notationDeclSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function attributeDecl\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh44 = unsafe { &mut ((*(*ctxt).sax).attributeDecl) };
        *fresh44 = unsafe { *(value as *mut attributeDeclSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function elementDecl\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh45 = unsafe { &mut ((*(*ctxt).sax).elementDecl) };
        *fresh45 = unsafe { *(value as *mut elementDeclSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function unparsedEntityDecl\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh46 = unsafe { &mut ((*(*ctxt).sax).unparsedEntityDecl) };
        *fresh46 = unsafe { *(value as *mut unparsedEntityDeclSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function setDocumentLocator\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh47 = unsafe { &mut ((*(*ctxt).sax).setDocumentLocator) };
        *fresh47 = unsafe { *(value as *mut setDocumentLocatorSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function startDocument\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh48 = unsafe { &mut ((*(*ctxt).sax).startDocument) };
        *fresh48 = unsafe { *(value as *mut startDocumentSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function endDocument\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh49 = unsafe { &mut ((*(*ctxt).sax).endDocument) };
        *fresh49 = unsafe { *(value as *mut endDocumentSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function startElement\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh50 = unsafe { &mut ((*(*ctxt).sax).startElement) };
        *fresh50 = unsafe { *(value as *mut startElementSAXFunc) };
    } else if (unsafe { strcmp(name, b"SAX function endElement\0" as *const u8 as *const i8) }) == 0 {
        let fresh51 = unsafe { &mut ((*(*ctxt).sax).endElement) };
        *fresh51 = unsafe { *(value as *mut endElementSAXFunc) };
    } else if (unsafe { strcmp(name, b"SAX function reference\0" as *const u8 as *const i8) }) == 0 {
        let fresh52 = unsafe { &mut ((*(*ctxt).sax).reference) };
        *fresh52 = unsafe { *(value as *mut referenceSAXFunc) };
    } else if (unsafe { strcmp(name, b"SAX function characters\0" as *const u8 as *const i8) }) == 0 {
        let fresh53 = unsafe { &mut ((*(*ctxt).sax).characters) };
        *fresh53 = unsafe { *(value as *mut charactersSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function ignorableWhitespace\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh54 = unsafe { &mut ((*(*ctxt).sax).ignorableWhitespace) };
        *fresh54 = unsafe { *(value as *mut ignorableWhitespaceSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function processingInstruction\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh55 = unsafe { &mut ((*(*ctxt).sax).processingInstruction) };
        *fresh55 = unsafe { *(value as *mut processingInstructionSAXFunc) };
    } else if (unsafe { strcmp(name, b"SAX function comment\0" as *const u8 as *const i8) }) == 0 {
        let fresh56 = unsafe { &mut ((*(*ctxt).sax).comment) };
        *fresh56 = unsafe { *(value as *mut commentSAXFunc) };
    } else if (unsafe { strcmp(name, b"SAX function warning\0" as *const u8 as *const i8) }) == 0 {
        let fresh57 = unsafe { &mut ((*(*ctxt).sax).warning) };
        *fresh57 = unsafe { *(value as *mut warningSAXFunc) };
    } else if (unsafe { strcmp(name, b"SAX function error\0" as *const u8 as *const i8) }) == 0 {
        let fresh58 = unsafe { &mut ((*(*ctxt).sax).error) };
        *fresh58 = unsafe { *(value as *mut errorSAXFunc) };
    } else if (unsafe { strcmp(name, b"SAX function fatalError\0" as *const u8 as *const i8) }) == 0 {
        let fresh59 = unsafe { &mut ((*(*ctxt).sax).fatalError) };
        *fresh59 = unsafe { *(value as *mut fatalErrorSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function getParameterEntity\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh60 = unsafe { &mut ((*(*ctxt).sax).getParameterEntity) };
        *fresh60 = unsafe { *(value as *mut getParameterEntitySAXFunc) };
    } else if (unsafe { strcmp(name, b"SAX function cdataBlock\0" as *const u8 as *const i8) }) == 0 {
        let fresh61 = unsafe { &mut ((*(*ctxt).sax).cdataBlock) };
        *fresh61 = unsafe { *(value as *mut cdataBlockSAXFunc) };
    } else if (unsafe { strcmp(
        name,
        b"SAX function externalSubset\0" as *const u8 as *const i8,
    ) }) == 0
    {
        let fresh62 = unsafe { &mut ((*(*ctxt).sax).externalSubset) };
        *fresh62 = unsafe { *(value as *mut externalSubsetSAXFunc) };
    } else {
        return -(1 as i32);
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlDecodeEntities(
    mut _ctxt: xmlParserCtxtPtr,
    mut _len: i32,
    mut _what: i32,
    mut _end: xmlChar,
    mut _end2: xmlChar,
    mut _end3: xmlChar,
) -> *mut xmlChar {
    static mut deprecated: i32 = 0 as i32;
    if (unsafe { deprecated }) == 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlDecodeEntities() deprecated function reached\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { deprecated = 1 as i32 });
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlNamespaceParseNCName(mut _ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    static mut deprecated: i32 = 0 as i32;
    if (unsafe { deprecated }) == 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlNamespaceParseNCName() deprecated function reached\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { deprecated = 1 as i32 });
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlNamespaceParseQName(
    mut _ctxt: xmlParserCtxtPtr,
    mut _prefix: *mut *mut xmlChar,
) -> *mut xmlChar {
    static mut deprecated: i32 = 0 as i32;
    if (unsafe { deprecated }) == 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlNamespaceParseQName() deprecated function reached\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { deprecated = 1 as i32 });
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlNamespaceParseNSDef(mut _ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    static mut deprecated: i32 = 0 as i32;
    if (unsafe { deprecated }) == 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlNamespaceParseNSDef() deprecated function reached\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { deprecated = 1 as i32 });
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlParseQuotedString(mut _ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    static mut deprecated: i32 = 0 as i32;
    if (unsafe { deprecated }) == 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlParseQuotedString() deprecated function reached\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { deprecated = 1 as i32 });
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlParseNamespace(mut _ctxt: xmlParserCtxtPtr) {
    static mut deprecated: i32 = 0 as i32;
    if (unsafe { deprecated }) == 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlParseNamespace() deprecated function reached\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { deprecated = 1 as i32 });
    }
}
#[no_mangle]
pub extern "C" fn xmlScanName(mut _ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    static mut deprecated: i32 = 0 as i32;
    if (unsafe { deprecated }) == 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlScanName() deprecated function reached\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { deprecated = 1 as i32 });
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlParserHandleReference(mut _ctxt: xmlParserCtxtPtr) {
    static mut deprecated: i32 = 0 as i32;
    if (unsafe { deprecated }) == 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlParserHandleReference() deprecated function reached\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { deprecated = 1 as i32 });
    }
}
#[no_mangle]
pub extern "C" fn xmlHandleEntity(mut _ctxt: xmlParserCtxtPtr, mut _entity: xmlEntityPtr) {
    static mut deprecated: i32 = 0 as i32;
    if (unsafe { deprecated }) == 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlHandleEntity() deprecated function reached\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { deprecated = 1 as i32 });
    }
}
#[no_mangle]
pub extern "C" fn xmlNewGlobalNs(
    mut _doc: xmlDocPtr,
    mut _href: *const xmlChar,
    mut _prefix: *const xmlChar,
) -> xmlNsPtr {
    static mut deprecated: i32 = 0 as i32;
    if (unsafe { deprecated }) == 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlNewGlobalNs() deprecated function reached\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { deprecated = 1 as i32 });
    }
    return 0 as xmlNsPtr;
}
#[no_mangle]
pub extern "C" fn xmlUpgradeOldNs(mut _doc: xmlDocPtr) {
    static mut deprecated: i32 = 0 as i32;
    if (unsafe { deprecated }) == 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlUpgradeOldNs() deprecated function reached\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { deprecated = 1 as i32 });
    }
}
#[no_mangle]
pub extern "C" fn xmlEncodeEntities(
    mut _doc: xmlDocPtr,
    mut _input: *const xmlChar,
) -> *const xmlChar {
    static mut warning: i32 = 1 as i32;
    if (unsafe { warning }) != 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Deprecated API xmlEncodeEntities() used\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"   change code to use xmlEncodeEntitiesReentrant()\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { warning = 0 as i32 });
    }
    return 0 as *const xmlChar;
}
static mut deprecated_v1_msg: i32 = 0 as i32;
#[no_mangle]
pub extern "C" fn getPublicId(mut ctx: *mut libc::c_void) -> *const xmlChar {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"getPublicId\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    return unsafe { xmlSAX2GetPublicId(ctx) };
}
#[no_mangle]
pub extern "C" fn getSystemId(mut ctx: *mut libc::c_void) -> *const xmlChar {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"getSystemId\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    return unsafe { xmlSAX2GetSystemId(ctx) };
}
#[no_mangle]
pub extern "C" fn getLineNumber(mut ctx: *mut libc::c_void) -> i32 {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"getLineNumber\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    return unsafe { xmlSAX2GetLineNumber(ctx) };
}
#[no_mangle]
pub extern "C" fn getColumnNumber(mut ctx: *mut libc::c_void) -> i32 {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"getColumnNumber\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    return unsafe { xmlSAX2GetColumnNumber(ctx) };
}
#[no_mangle]
pub extern "C" fn isStandalone(mut ctx: *mut libc::c_void) -> i32 {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"isStandalone\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    return unsafe { xmlSAX2IsStandalone(ctx) };
}
#[no_mangle]
pub extern "C" fn hasInternalSubset(mut ctx: *mut libc::c_void) -> i32 {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"hasInternalSubset\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    return unsafe { xmlSAX2HasInternalSubset(ctx) };
}
#[no_mangle]
pub extern "C" fn hasExternalSubset(mut ctx: *mut libc::c_void) -> i32 {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"hasExternalSubset\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    return unsafe { xmlSAX2HasExternalSubset(ctx) };
}
#[no_mangle]
pub extern "C" fn internalSubset(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"internalSubset\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2InternalSubset(ctx, name, ExternalID, SystemID) });
}
#[no_mangle]
pub extern "C" fn externalSubset(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"externalSubset\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2ExternalSubset(ctx, name, ExternalID, SystemID) });
}
#[no_mangle]
pub extern "C" fn resolveEntity(
    mut ctx: *mut libc::c_void,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
) -> xmlParserInputPtr {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"resolveEntity\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    return unsafe { xmlSAX2ResolveEntity(ctx, publicId, systemId) };
}
#[no_mangle]
pub extern "C" fn getEntity(mut ctx: *mut libc::c_void, mut name: *const xmlChar) -> xmlEntityPtr {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"getEntity\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    return unsafe { xmlSAX2GetEntity(ctx, name) };
}
#[no_mangle]
pub extern "C" fn getParameterEntity(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) -> xmlEntityPtr {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"getParameterEntity\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    return unsafe { xmlSAX2GetParameterEntity(ctx, name) };
}
#[no_mangle]
pub extern "C" fn entityDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut type_0: i32,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
    mut content: *mut xmlChar,
) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"entityDecl\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2EntityDecl(ctx, name, type_0, publicId, systemId, content) });
}
#[no_mangle]
pub extern "C" fn attributeDecl(
    mut ctx: *mut libc::c_void,
    mut elem: *const xmlChar,
    mut fullname: *const xmlChar,
    mut type_0: i32,
    mut def: i32,
    mut defaultValue: *const xmlChar,
    mut tree: xmlEnumerationPtr,
) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"attributeDecl\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2AttributeDecl(ctx, elem, fullname, type_0, def, defaultValue, tree) });
}
#[no_mangle]
pub extern "C" fn elementDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut type_0: i32,
    mut content: xmlElementContentPtr,
) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"elementDecl\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2ElementDecl(ctx, name, type_0, content) });
}
#[no_mangle]
pub extern "C" fn notationDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"notationDecl\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2NotationDecl(ctx, name, publicId, systemId) });
}
#[no_mangle]
pub extern "C" fn unparsedEntityDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
    mut notationName: *const xmlChar,
) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"unparsedEntityDecl\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2UnparsedEntityDecl(ctx, name, publicId, systemId, notationName) });
}
#[no_mangle]
pub extern "C" fn setDocumentLocator(mut _ctx: *mut libc::c_void, mut _loc: xmlSAXLocatorPtr) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"setDocumentLocator\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
}
#[no_mangle]
pub extern "C" fn startDocument(mut ctx: *mut libc::c_void) {
    (unsafe { xmlSAX2StartDocument(ctx) });
}
#[no_mangle]
pub extern "C" fn endDocument(mut ctx: *mut libc::c_void) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"endDocument\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2EndDocument(ctx) });
}
#[no_mangle]
pub extern "C" fn attribute(
    mut _ctx: *mut libc::c_void,
    mut _fullname: *const xmlChar,
    mut _value: *const xmlChar,
) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"attribute\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
}
#[no_mangle]
pub extern "C" fn startElement(
    mut ctx: *mut libc::c_void,
    mut fullname: *const xmlChar,
    mut atts: *mut *const xmlChar,
) {
    (unsafe { xmlSAX2StartElement(ctx, fullname, atts) });
}
#[no_mangle]
pub extern "C" fn endElement(mut ctx: *mut libc::c_void, mut name: *const xmlChar) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"endElement\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2EndElement(ctx, name) });
}
#[no_mangle]
pub extern "C" fn reference(mut ctx: *mut libc::c_void, mut name: *const xmlChar) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"reference\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2Reference(ctx, name) });
}
#[no_mangle]
pub extern "C" fn characters(mut ctx: *mut libc::c_void, mut ch: *const xmlChar, mut len: i32) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"characters\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2Characters(ctx, ch, len) });
}
#[no_mangle]
pub extern "C" fn ignorableWhitespace(
    mut _ctx: *mut libc::c_void,
    mut _ch: *const xmlChar,
    mut _len: i32,
) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"ignorableWhitespace\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
}
#[no_mangle]
pub extern "C" fn processingInstruction(
    mut ctx: *mut libc::c_void,
    mut target: *const xmlChar,
    mut data: *const xmlChar,
) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"processingInstruction\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2ProcessingInstruction(ctx, target, data) });
}
#[no_mangle]
pub extern "C" fn globalNamespace(
    mut _ctx: *mut libc::c_void,
    mut _href: *const xmlChar,
    mut _prefix: *const xmlChar,
) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"globalNamespace\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
}
#[no_mangle]
pub extern "C" fn setNamespace(mut _ctx: *mut libc::c_void, mut _name: *const xmlChar) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"setNamespace\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
}
#[no_mangle]
pub extern "C" fn getNamespace(mut _ctx: *mut libc::c_void) -> xmlNsPtr {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"getNamespace\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    return 0 as xmlNsPtr;
}
#[no_mangle]
pub extern "C" fn checkNamespace(mut _ctx: *mut libc::c_void, mut _namespace: *mut xmlChar) -> i32 {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"checkNamespace\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn namespaceDecl(
    mut _ctx: *mut libc::c_void,
    mut _href: *const xmlChar,
    mut _prefix: *const xmlChar,
) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"namespaceDecl\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
}
#[no_mangle]
pub extern "C" fn comment(mut ctx: *mut libc::c_void, mut value: *const xmlChar) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"comment\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2Comment(ctx, value) });
}
#[no_mangle]
pub extern "C" fn cdataBlock(mut ctx: *mut libc::c_void, mut value: *const xmlChar, mut len: i32) {
    if (unsafe { deprecated_v1_msg }) == 0 as i32 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8 as *const i8,
            b"cdataBlock\0" as *const u8 as *const i8,
        ) });
    }
    (unsafe { deprecated_v1_msg += 1 });
    (unsafe { xmlSAX2CDataBlock(ctx, value, len) });
}
