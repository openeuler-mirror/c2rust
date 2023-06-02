use :: libc;
extern "C" {
    pub type _xmlBuf;
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlStartTag;
    pub type _xmlAutomataState;
    pub type _xmlAutomata;
    pub type _xmlValidState;
    pub type _xmlXPathCompExpr;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrcmp(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrchr(str: *const xmlChar, val: xmlChar) -> *const xmlChar;
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn xmlBufContent(buf: *const xmlBuf) -> *mut xmlChar;
    fn xmlBufShrink(buf: xmlBufPtr, len: size_t) -> size_t;
    fn xmlDictReference(dict: xmlDictPtr) -> i32;
    fn xmlDictFree(dict: xmlDictPtr);
    fn xmlCreateIntSubset(
        doc: xmlDocPtr,
        name: *const xmlChar,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    ) -> xmlDtdPtr;
    fn xmlFreeDoc(cur: xmlDocPtr);
    fn xmlNewDocNode(
        doc: xmlDocPtr,
        ns: xmlNsPtr,
        name: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlNodePtr;
    fn xmlNewDocText(doc: *const xmlDoc, content: *const xmlChar) -> xmlNodePtr;
    fn xmlDocCopyNode(node: xmlNodePtr, doc: xmlDocPtr, recursive: i32) -> xmlNodePtr;
    fn xmlDocCopyNodeList(doc: xmlDocPtr, node: xmlNodePtr) -> xmlNodePtr;
    fn xmlDocGetRootElement(doc: *const xmlDoc) -> xmlNodePtr;
    fn xmlAddPrevSibling(cur: xmlNodePtr, elem: xmlNodePtr) -> xmlNodePtr;
    fn xmlAddNextSibling(cur: xmlNodePtr, elem: xmlNodePtr) -> xmlNodePtr;
    fn xmlUnlinkNode(cur: xmlNodePtr);
    fn xmlFreeNodeList(cur: xmlNodePtr);
    fn xmlFreeNode(cur: xmlNodePtr);
    fn xmlGetProp(node: *const xmlNode, name: *const xmlChar) -> *mut xmlChar;
    fn xmlGetNsProp(
        node: *const xmlNode,
        name: *const xmlChar,
        nameSpace: *const xmlChar,
    ) -> *mut xmlChar;
    fn xmlNodeAddContentLen(cur: xmlNodePtr, content: *const xmlChar, len: i32);
    fn xmlNodeGetBase(doc: *const xmlDoc, cur: *const xmlNode) -> *mut xmlChar;
    fn xmlNodeSetBase(cur: xmlNodePtr, uri: *const xmlChar);
    fn xmlUnsetProp(node: xmlNodePtr, name: *const xmlChar) -> i32;
    fn xmlHashScan(table: xmlHashTablePtr, f: xmlHashScanner, data: *mut libc::c_void);
    fn __xmlRaiseError(
        schannel: xmlStructuredErrorFunc,
        channel: xmlGenericErrorFunc,
        data: *mut libc::c_void,
        ctx: *mut libc::c_void,
        node: *mut libc::c_void,
        domain: i32,
        code: i32,
        level: xmlErrorLevel,
        file: *const i8,
        line: i32,
        str1: *const i8,
        str2: *const i8,
        str3: *const i8,
        int1: i32,
        col: i32,
        msg: *const i8,
        _: ...
    );
    fn xmlAddDocEntity(
        doc: xmlDocPtr,
        name: *const xmlChar,
        type_0: i32,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlEntityPtr;
    fn xmlGetDocEntity(doc: *const xmlDoc, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlGetCharEncodingHandler(enc: xmlCharEncoding) -> xmlCharEncodingHandlerPtr;
    fn xmlParseCharEncoding(name: *const i8) -> xmlCharEncoding;
    fn xmlCharEncCloseFunc(handler: *mut xmlCharEncodingHandler) -> i32;
    fn xmlParserInputBufferRead(in_0: xmlParserInputBufferPtr, len: i32) -> i32;
    fn xmlFreeParserInputBuffer(in_0: xmlParserInputBufferPtr);
    fn xmlParserGetDirectory(filename: *const i8) -> *mut i8;
    fn xmlInitParser();
    fn xmlParseDocument(ctxt: xmlParserCtxtPtr) -> i32;
    fn xmlNewParserCtxt() -> xmlParserCtxtPtr;
    fn xmlFreeParserCtxt(ctxt: xmlParserCtxtPtr);
    fn xmlLoadExternalEntity(
        URL: *const i8,
        ID: *const i8,
        ctxt: xmlParserCtxtPtr,
    ) -> xmlParserInputPtr;
    fn xmlCtxtUseOptions(ctxt: xmlParserCtxtPtr, options: i32) -> i32;
    static mut xmlFree: xmlFreeFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlMalloc: xmlMallocFunc;
    fn xmlBuildURI(URI: *const xmlChar, base: *const xmlChar) -> *mut xmlChar;
    fn xmlBuildRelativeURI(URI: *const xmlChar, base: *const xmlChar) -> *mut xmlChar;
    fn xmlParseURI(str: *const i8) -> xmlURIPtr;
    fn xmlSaveUri(uri: xmlURIPtr) -> *mut xmlChar;
    fn xmlURIEscape(str: *const xmlChar) -> *mut xmlChar;
    fn xmlFreeURI(uri: xmlURIPtr);
    fn xmlXPathFreeObject(obj: xmlXPathObjectPtr);
    fn xmlXPathFreeContext(ctxt: xmlXPathContextPtr);
    fn xmlXPtrNewContext(
        doc: xmlDocPtr,
        here: xmlNodePtr,
        origin: xmlNodePtr,
    ) -> xmlXPathContextPtr;
    fn xmlXPtrEval(str: *const xmlChar, ctx: xmlXPathContextPtr) -> xmlXPathObjectPtr;
    fn xmlFreeInputStream(input: xmlParserInputPtr);
    fn inputPush(ctxt: xmlParserCtxtPtr, value: xmlParserInputPtr) -> i32;
    fn xmlStringCurrentChar(ctxt: xmlParserCtxtPtr, cur: *const xmlChar, len: *mut i32) -> i32;
    fn xmlBufLength(buf: xmlBufPtr) -> size_t;
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
pub type xmlNsPtr = *mut xmlNs;
pub type xmlDtd = _xmlDtd;
pub type xmlDtdPtr = *mut xmlDtd;
pub type xmlHashScanner =
    Option<unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void, *const xmlChar) -> ()>;
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
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
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
pub type C2RustUnnamed_1 = u32;
pub const XML_PARSE_BIG_LINES: C2RustUnnamed_1 = 4194304;
pub const XML_PARSE_IGNORE_ENC: C2RustUnnamed_1 = 2097152;
pub const XML_PARSE_OLDSAX: C2RustUnnamed_1 = 1048576;
pub const XML_PARSE_HUGE: C2RustUnnamed_1 = 524288;
pub const XML_PARSE_NOBASEFIX: C2RustUnnamed_1 = 262144;
pub const XML_PARSE_OLD10: C2RustUnnamed_1 = 131072;
pub const XML_PARSE_COMPACT: C2RustUnnamed_1 = 65536;
pub const XML_PARSE_NOXINCNODE: C2RustUnnamed_1 = 32768;
pub const XML_PARSE_NOCDATA: C2RustUnnamed_1 = 16384;
pub const XML_PARSE_NSCLEAN: C2RustUnnamed_1 = 8192;
pub const XML_PARSE_NODICT: C2RustUnnamed_1 = 4096;
pub const XML_PARSE_NONET: C2RustUnnamed_1 = 2048;
pub const XML_PARSE_XINCLUDE: C2RustUnnamed_1 = 1024;
pub const XML_PARSE_SAX1: C2RustUnnamed_1 = 512;
pub const XML_PARSE_NOBLANKS: C2RustUnnamed_1 = 256;
pub const XML_PARSE_PEDANTIC: C2RustUnnamed_1 = 128;
pub const XML_PARSE_NOWARNING: C2RustUnnamed_1 = 64;
pub const XML_PARSE_NOERROR: C2RustUnnamed_1 = 32;
pub const XML_PARSE_DTDVALID: C2RustUnnamed_1 = 16;
pub const XML_PARSE_DTDATTR: C2RustUnnamed_1 = 8;
pub const XML_PARSE_DTDLOAD: C2RustUnnamed_1 = 4;
pub const XML_PARSE_NOENT: C2RustUnnamed_1 = 2;
pub const XML_PARSE_RECOVER: C2RustUnnamed_1 = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlURI {
    pub scheme: *mut i8,
    pub opaque: *mut i8,
    pub authority: *mut i8,
    pub server: *mut i8,
    pub user: *mut i8,
    pub port: i32,
    pub path: *mut i8,
    pub query: *mut i8,
    pub fragment: *mut i8,
    pub cleanup: i32,
    pub query_raw: *mut i8,
}
pub type xmlURI = _xmlURI;
pub type xmlURIPtr = *mut xmlURI;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathContext {
    pub doc: xmlDocPtr,
    pub node: xmlNodePtr,
    pub nb_variables_unused: i32,
    pub max_variables_unused: i32,
    pub varHash: xmlHashTablePtr,
    pub nb_types: i32,
    pub max_types: i32,
    pub types: xmlXPathTypePtr,
    pub nb_funcs_unused: i32,
    pub max_funcs_unused: i32,
    pub funcHash: xmlHashTablePtr,
    pub nb_axis: i32,
    pub max_axis: i32,
    pub axis: xmlXPathAxisPtr,
    pub namespaces: *mut xmlNsPtr,
    pub nsNr: i32,
    pub user: *mut libc::c_void,
    pub contextSize: i32,
    pub proximityPosition: i32,
    pub xptr: i32,
    pub here: xmlNodePtr,
    pub origin: xmlNodePtr,
    pub nsHash: xmlHashTablePtr,
    pub varLookupFunc: xmlXPathVariableLookupFunc,
    pub varLookupData: *mut libc::c_void,
    pub extra: *mut libc::c_void,
    pub function: *const xmlChar,
    pub functionURI: *const xmlChar,
    pub funcLookupFunc: xmlXPathFuncLookupFunc,
    pub funcLookupData: *mut libc::c_void,
    pub tmpNsList: *mut xmlNsPtr,
    pub tmpNsNr: i32,
    pub userData: *mut libc::c_void,
    pub error: xmlStructuredErrorFunc,
    pub lastError: xmlError,
    pub debugNode: xmlNodePtr,
    pub dict: xmlDictPtr,
    pub flags: i32,
    pub cache: *mut libc::c_void,
    pub opLimit: u64,
    pub opCount: u64,
    pub depth: i32,
}
pub type xmlXPathFuncLookupFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> xmlXPathFunction,
>;
pub type xmlXPathFunction = Option<unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()>;
pub type xmlXPathParserContextPtr = *mut xmlXPathParserContext;
pub type xmlXPathParserContext = _xmlXPathParserContext;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathParserContext {
    pub cur: *const xmlChar,
    pub base: *const xmlChar,
    pub error: i32,
    pub context: xmlXPathContextPtr,
    pub value: xmlXPathObjectPtr,
    pub valueNr: i32,
    pub valueMax: i32,
    pub valueTab: *mut xmlXPathObjectPtr,
    pub comp: xmlXPathCompExprPtr,
    pub xptr: i32,
    pub ancestor: xmlNodePtr,
    pub valueFrame: i32,
}
pub type xmlXPathCompExprPtr = *mut xmlXPathCompExpr;
pub type xmlXPathCompExpr = _xmlXPathCompExpr;
pub type xmlXPathObjectPtr = *mut xmlXPathObject;
pub type xmlXPathObject = _xmlXPathObject;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathObject {
    pub type_0: xmlXPathObjectType,
    pub nodesetval: xmlNodeSetPtr,
    pub boolval: i32,
    pub floatval: f64,
    pub stringval: *mut xmlChar,
    pub user: *mut libc::c_void,
    pub index: i32,
    pub user2: *mut libc::c_void,
    pub index2: i32,
}
pub type xmlNodeSetPtr = *mut xmlNodeSet;
pub type xmlNodeSet = _xmlNodeSet;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNodeSet {
    pub nodeNr: i32,
    pub nodeMax: i32,
    pub nodeTab: *mut xmlNodePtr,
}
pub type xmlXPathObjectType = u32;
pub const XPATH_XSLT_TREE: xmlXPathObjectType = 9;
pub const XPATH_USERS: xmlXPathObjectType = 8;
pub const XPATH_STRING: xmlXPathObjectType = 4;
pub const XPATH_NUMBER: xmlXPathObjectType = 3;
pub const XPATH_BOOLEAN: xmlXPathObjectType = 2;
pub const XPATH_NODESET: xmlXPathObjectType = 1;
pub const XPATH_UNDEFINED: xmlXPathObjectType = 0;
pub type xmlXPathContextPtr = *mut xmlXPathContext;
pub type xmlXPathContext = _xmlXPathContext;
pub type xmlXPathVariableLookupFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> xmlXPathObjectPtr,
>;
pub type xmlXPathAxisPtr = *mut xmlXPathAxis;
pub type xmlXPathAxis = _xmlXPathAxis;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathAxis {
    pub name: *const xmlChar,
    pub func: xmlXPathAxisFunc,
}
pub type xmlXPathAxisFunc =
    Option<unsafe extern "C" fn(xmlXPathParserContextPtr, xmlXPathObjectPtr) -> xmlXPathObjectPtr>;
pub type xmlXPathTypePtr = *mut xmlXPathType;
pub type xmlXPathType = _xmlXPathType;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathType {
    pub name: *const xmlChar,
    pub func: xmlXPathConvertFunc,
}
pub type xmlXPathConvertFunc = Option<unsafe extern "C" fn(xmlXPathObjectPtr, i32) -> i32>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXIncludeCtxt {
    pub doc: xmlDocPtr,
    pub incBase: i32,
    pub incNr: i32,
    pub incMax: i32,
    pub incTab: *mut xmlXIncludeRefPtr,
    pub txtNr: i32,
    pub txtMax: i32,
    pub txtTab: *mut *mut xmlChar,
    pub txturlTab: *mut xmlURL,
    pub url: *mut xmlChar,
    pub urlNr: i32,
    pub urlMax: i32,
    pub urlTab: *mut *mut xmlChar,
    pub nbErrors: i32,
    pub legacy: i32,
    pub parseFlags: i32,
    pub base: *mut xmlChar,
    pub _private: *mut libc::c_void,
    pub incTotal: u64,
}
pub type xmlURL = *mut xmlChar;
pub type xmlXIncludeRefPtr = *mut xmlXIncludeRef;
pub type xmlXIncludeRef = _xmlXIncludeRef;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXIncludeRef {
    pub URI: *mut xmlChar,
    pub fragment: *mut xmlChar,
    pub doc: xmlDocPtr,
    pub ref_0: xmlNodePtr,
    pub inc: xmlNodePtr,
    pub xml: i32,
    pub count: i32,
    pub fallback: i32,
    pub emptyFb: i32,
}
pub type xmlXIncludeCtxt = _xmlXIncludeCtxt;
pub type xmlXIncludeCtxtPtr = *mut xmlXIncludeCtxt;
pub type xmlXIncludeMergeData = _xmlXIncludeMergeData;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXIncludeMergeData {
    pub doc: xmlDocPtr,
    pub ctxt: xmlXIncludeCtxtPtr,
}
pub type xmlXIncludeMergeDataPtr = *mut xmlXIncludeMergeData;
extern "C" fn xmlXIncludeErrMemory(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut node: xmlNodePtr,
    mut extra: *const i8,
) {
    if !ctxt.is_null() {
        let fresh0 = unsafe { &mut ((*ctxt).nbErrors) };
        *fresh0 += 1;
    }
    (unsafe { __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        node as *mut libc::c_void,
        XML_FROM_XINCLUDE as i32,
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
    ) });
}
extern "C" fn xmlXIncludeErr(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut node: xmlNodePtr,
    mut error: i32,
    mut msg: *const i8,
    mut extra: *const xmlChar,
) {
    if !ctxt.is_null() {
        let fresh1 = unsafe { &mut ((*ctxt).nbErrors) };
        *fresh1 += 1;
    }
    (unsafe { __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        node as *mut libc::c_void,
        XML_FROM_XINCLUDE as i32,
        error,
        XML_ERR_ERROR,
        0 as *const i8,
        0 as i32,
        extra as *const i8,
        0 as *const i8,
        0 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        extra as *const i8,
    ) });
}
extern "C" fn xmlXIncludeGetProp(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut cur: xmlNodePtr,
    mut name: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    ret = unsafe { xmlGetNsProp(
        cur as *const xmlNode,
        b"http://www.w3.org/2003/XInclude\0" as *const u8 as *const i8 as *const xmlChar,
        name,
    ) };
    if !ret.is_null() {
        return ret;
    }
    if (unsafe { (*ctxt).legacy }) != 0 as i32 {
        ret = unsafe { xmlGetNsProp(
            cur as *const xmlNode,
            b"http://www.w3.org/2001/XInclude\0" as *const u8 as *const i8 as *const xmlChar,
            name,
        ) };
        if !ret.is_null() {
            return ret;
        }
    }
    ret = unsafe { xmlGetProp(cur as *const xmlNode, name) };
    return ret;
}
extern "C" fn xmlXIncludeFreeRef(mut ref_0: xmlXIncludeRefPtr) {
    if ref_0.is_null() {
        return;
    }
    if !(unsafe { (*ref_0).doc }).is_null() {
        (unsafe { xmlFreeDoc((*ref_0).doc) });
    }
    if !(unsafe { (*ref_0).URI }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*ref_0).URI as *mut libc::c_void) });
    }
    if !(unsafe { (*ref_0).fragment }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*ref_0).fragment as *mut libc::c_void) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(ref_0 as *mut libc::c_void) });
}
extern "C" fn xmlXIncludeNewRef(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut URI: *const xmlChar,
    mut ref_0: xmlNodePtr,
) -> xmlXIncludeRefPtr {
    let mut ret: xmlXIncludeRefPtr = 0 as *mut xmlXIncludeRef;
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXIncludeRef>() as u64
    ) }) as xmlXIncludeRefPtr;
    if ret.is_null() {
        xmlXIncludeErrMemory(
            ctxt,
            ref_0,
            b"growing XInclude context\0" as *const u8 as *const i8,
        );
        return 0 as xmlXIncludeRefPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXIncludeRef>() as u64,
    ) });
    if URI.is_null() {
        let fresh2 = unsafe { &mut ((*ret).URI) };
        *fresh2 = 0 as *mut xmlChar;
    } else {
        let fresh3 = unsafe { &mut ((*ret).URI) };
        *fresh3 = unsafe { xmlStrdup(URI) };
    }
    let fresh4 = unsafe { &mut ((*ret).fragment) };
    *fresh4 = 0 as *mut xmlChar;
    let fresh5 = unsafe { &mut ((*ret).ref_0) };
    *fresh5 = ref_0;
    let fresh6 = unsafe { &mut ((*ret).doc) };
    *fresh6 = 0 as xmlDocPtr;
    (unsafe { (*ret).count = 0 as i32 });
    (unsafe { (*ret).xml = 0 as i32 });
    let fresh7 = unsafe { &mut ((*ret).inc) };
    *fresh7 = 0 as xmlNodePtr;
    if (unsafe { (*ctxt).incMax }) == 0 as i32 {
        (unsafe { (*ctxt).incMax = 4 as i32 });
        let fresh8 = unsafe { &mut ((*ctxt).incTab) };
        *fresh8 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ((*ctxt).incMax as u64).wrapping_mul(::std::mem::size_of::<xmlXIncludeRefPtr>() as u64),
        ) }) as *mut xmlXIncludeRefPtr;
        if (unsafe { (*ctxt).incTab }).is_null() {
            xmlXIncludeErrMemory(
                ctxt,
                ref_0,
                b"growing XInclude context\0" as *const u8 as *const i8,
            );
            xmlXIncludeFreeRef(ret);
            return 0 as xmlXIncludeRefPtr;
        }
    }
    if (unsafe { (*ctxt).incNr }) >= (unsafe { (*ctxt).incMax }) {
        (unsafe { (*ctxt).incMax *= 2 as i32 });
        let fresh9 = unsafe { &mut ((*ctxt).incTab) };
        *fresh9 = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*ctxt).incTab as *mut libc::c_void,
            ((*ctxt).incMax as u64).wrapping_mul(::std::mem::size_of::<xmlXIncludeRefPtr>() as u64),
        ) }) as *mut xmlXIncludeRefPtr;
        if (unsafe { (*ctxt).incTab }).is_null() {
            xmlXIncludeErrMemory(
                ctxt,
                ref_0,
                b"growing XInclude context\0" as *const u8 as *const i8,
            );
            xmlXIncludeFreeRef(ret);
            return 0 as xmlXIncludeRefPtr;
        }
    }
    let fresh10 = unsafe { &mut ((*ctxt).incNr) };
    let fresh11 = *fresh10;
    *fresh10 = *fresh10 + 1;
    let fresh12 = unsafe { &mut (*((*ctxt).incTab).offset(fresh11 as isize)) };
    *fresh12 = ret;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXIncludeNewContext(mut doc: xmlDocPtr) -> xmlXIncludeCtxtPtr {
    let mut ret: xmlXIncludeCtxtPtr = 0 as *mut xmlXIncludeCtxt;
    if doc.is_null() {
        return 0 as xmlXIncludeCtxtPtr;
    }
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlXIncludeCtxt>() as u64
    ) }) as xmlXIncludeCtxtPtr;
    if ret.is_null() {
        xmlXIncludeErrMemory(
            0 as xmlXIncludeCtxtPtr,
            doc as xmlNodePtr,
            b"creating XInclude context\0" as *const u8 as *const i8,
        );
        return 0 as xmlXIncludeCtxtPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlXIncludeCtxt>() as u64,
    ) });
    let fresh13 = unsafe { &mut ((*ret).doc) };
    *fresh13 = doc;
    (unsafe { (*ret).incNr = 0 as i32 });
    (unsafe { (*ret).incBase = 0 as i32 });
    (unsafe { (*ret).incMax = 0 as i32 });
    let fresh14 = unsafe { &mut ((*ret).incTab) };
    *fresh14 = 0 as *mut xmlXIncludeRefPtr;
    (unsafe { (*ret).nbErrors = 0 as i32 });
    return ret;
}
extern "C" fn xmlXIncludeURLPush(mut ctxt: xmlXIncludeCtxtPtr, mut value: *const xmlChar) -> i32 {
    if (unsafe { (*ctxt).urlNr }) > 40 as i32 {
        xmlXIncludeErr(
            ctxt,
            0 as xmlNodePtr,
            XML_XINCLUDE_RECURSION as i32,
            b"detected a recursion in %s\n\0" as *const u8 as *const i8,
            value,
        );
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).urlTab }).is_null() {
        (unsafe { (*ctxt).urlMax = 4 as i32 });
        (unsafe { (*ctxt).urlNr = 0 as i32 });
        let fresh15 = unsafe { &mut ((*ctxt).urlTab) };
        *fresh15 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ((*ctxt).urlMax as u64).wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
        ) }) as *mut *mut xmlChar;
        if (unsafe { (*ctxt).urlTab }).is_null() {
            xmlXIncludeErrMemory(
                ctxt,
                0 as xmlNodePtr,
                b"adding URL\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
    }
    if (unsafe { (*ctxt).urlNr }) >= (unsafe { (*ctxt).urlMax }) {
        (unsafe { (*ctxt).urlMax *= 2 as i32 });
        let fresh16 = unsafe { &mut ((*ctxt).urlTab) };
        *fresh16 = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*ctxt).urlTab as *mut libc::c_void,
            ((*ctxt).urlMax as u64).wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
        ) }) as *mut *mut xmlChar;
        if (unsafe { (*ctxt).urlTab }).is_null() {
            xmlXIncludeErrMemory(
                ctxt,
                0 as xmlNodePtr,
                b"adding URL\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
    }
    let fresh17 = unsafe { &mut (*((*ctxt).urlTab).offset((*ctxt).urlNr as isize)) };
    *fresh17 = unsafe { xmlStrdup(value) };
    let fresh18 = unsafe { &mut ((*ctxt).url) };
    *fresh18 = *fresh17;
    let fresh19 = unsafe { &mut ((*ctxt).urlNr) };
    let fresh20 = *fresh19;
    *fresh19 = *fresh19 + 1;
    return fresh20;
}
extern "C" fn xmlXIncludeURLPop(mut ctxt: xmlXIncludeCtxtPtr) {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe { (*ctxt).urlNr }) <= 0 as i32 {
        return;
    }
    let fresh21 = unsafe { &mut ((*ctxt).urlNr) };
    *fresh21 -= 1;
    if (unsafe { (*ctxt).urlNr }) > 0 as i32 {
        let fresh22 = unsafe { &mut ((*ctxt).url) };
        *fresh22 = unsafe { *((*ctxt).urlTab).offset(((*ctxt).urlNr - 1 as i32) as isize) };
    } else {
        let fresh23 = unsafe { &mut ((*ctxt).url) };
        *fresh23 = 0 as *mut xmlChar;
    }
    ret = unsafe { *((*ctxt).urlTab).offset((*ctxt).urlNr as isize) };
    let fresh24 = unsafe { &mut (*((*ctxt).urlTab).offset((*ctxt).urlNr as isize)) };
    *fresh24 = 0 as *mut xmlChar;
    if !ret.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
    }
}
#[no_mangle]
pub extern "C" fn xmlXIncludeFreeContext(mut ctxt: xmlXIncludeCtxtPtr) {
    let mut i: i32 = 0;
    if ctxt.is_null() {
        return;
    }
    while (unsafe { (*ctxt).urlNr }) > 0 as i32 {
        xmlXIncludeURLPop(ctxt);
    }
    if !(unsafe { (*ctxt).urlTab }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).urlTab as *mut libc::c_void) });
    }
    i = 0 as i32;
    while i < (unsafe { (*ctxt).incNr }) {
        if !(unsafe { *((*ctxt).incTab).offset(i as isize) }).is_null() {
            xmlXIncludeFreeRef(unsafe { *((*ctxt).incTab).offset(i as isize) });
        }
        i += 1;
    }
    if !(unsafe { (*ctxt).incTab }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).incTab as *mut libc::c_void) });
    }
    if !(unsafe { (*ctxt).txtTab }).is_null() {
        i = 0 as i32;
        while i < (unsafe { (*ctxt).txtNr }) {
            if !(unsafe { *((*ctxt).txtTab).offset(i as isize) }).is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(
                    *((*ctxt).txtTab).offset(i as isize) as *mut libc::c_void
                ) });
            }
            i += 1;
        }
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).txtTab as *mut libc::c_void) });
    }
    if !(unsafe { (*ctxt).txturlTab }).is_null() {
        i = 0 as i32;
        while i < (unsafe { (*ctxt).txtNr }) {
            if !(unsafe { *((*ctxt).txturlTab).offset(i as isize) }).is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(
                    *((*ctxt).txturlTab).offset(i as isize) as *mut libc::c_void,
                ) });
            }
            i += 1;
        }
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).txturlTab as *mut libc::c_void) });
    }
    if !(unsafe { (*ctxt).base }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).base as *mut libc::c_void) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void) });
}
extern "C" fn xmlXIncludeParseFile(mut ctxt: xmlXIncludeCtxtPtr, mut URL: *const i8) -> xmlDocPtr {
    let mut ret: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    (unsafe { xmlInitParser() });
    pctxt = unsafe { xmlNewParserCtxt() };
    if pctxt.is_null() {
        xmlXIncludeErrMemory(
            ctxt,
            0 as xmlNodePtr,
            b"cannot allocate parser context\0" as *const u8 as *const i8,
        );
        return 0 as xmlDocPtr;
    }
    let fresh25 = unsafe { &mut ((*pctxt)._private) };
    *fresh25 = unsafe { (*ctxt)._private };
    if !(unsafe { (*ctxt).doc }).is_null() && !(unsafe { (*(*ctxt).doc).dict }).is_null() {
        if !(unsafe { (*pctxt).dict }).is_null() {
            (unsafe { xmlDictFree((*pctxt).dict) });
        }
        let fresh26 = unsafe { &mut ((*pctxt).dict) };
        *fresh26 = unsafe { (*(*ctxt).doc).dict };
        (unsafe { xmlDictReference((*pctxt).dict) });
    }
    (unsafe { xmlCtxtUseOptions(pctxt, (*ctxt).parseFlags | XML_PARSE_DTDLOAD as i32) });
    if !URL.is_null() && (unsafe { strcmp(URL, b"-\0" as *const u8 as *const i8) }) == 0 as i32 {
        URL = b"./-\0" as *const u8 as *const i8;
    }
    inputStream = unsafe { xmlLoadExternalEntity(URL, 0 as *const i8, pctxt) };
    if inputStream.is_null() {
        (unsafe { xmlFreeParserCtxt(pctxt) });
        return 0 as xmlDocPtr;
    }
    (unsafe { inputPush(pctxt, inputStream) });
    if (unsafe { (*pctxt).directory }).is_null() {
        let fresh27 = unsafe { &mut ((*pctxt).directory) };
        *fresh27 = unsafe { xmlParserGetDirectory(URL) };
    }
    (unsafe { (*pctxt).loadsubset |= 2 as i32 });
    (unsafe { xmlParseDocument(pctxt) });
    if (unsafe { (*pctxt).wellFormed }) != 0 {
        ret = unsafe { (*pctxt).myDoc };
    } else {
        ret = 0 as xmlDocPtr;
        if !(unsafe { (*pctxt).myDoc }).is_null() {
            (unsafe { xmlFreeDoc((*pctxt).myDoc) });
        }
        let fresh28 = unsafe { &mut ((*pctxt).myDoc) };
        *fresh28 = 0 as xmlDocPtr;
    }
    (unsafe { xmlFreeParserCtxt(pctxt) });
    return ret;
}
extern "C" fn xmlXIncludeAddNode(mut ctxt: xmlXIncludeCtxtPtr, mut cur: xmlNodePtr) -> i32 {
    let mut ref_0: xmlXIncludeRefPtr = 0 as *mut xmlXIncludeRef;
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut URL: *mut xmlChar = 0 as *mut xmlChar;
    let mut fragment: *mut xmlChar = 0 as *mut xmlChar;
    let mut href: *mut xmlChar = 0 as *mut xmlChar;
    let mut parse: *mut xmlChar = 0 as *mut xmlChar;
    let mut base: *mut xmlChar = 0 as *mut xmlChar;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let mut xml: i32 = 1 as i32;
    let mut i: i32 = 0;
    let mut local: i32 = 0 as i32;
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if cur.is_null() {
        return -(1 as i32);
    }
    href = xmlXIncludeGetProp(
        ctxt,
        cur,
        b"href\0" as *const u8 as *const i8 as *const xmlChar,
    );
    if href.is_null() {
        href = unsafe { xmlStrdup(b"\0" as *const u8 as *const i8 as *mut xmlChar) };
        if href.is_null() {
            return -(1 as i32);
        }
    }
    parse = xmlXIncludeGetProp(
        ctxt,
        cur,
        b"parse\0" as *const u8 as *const i8 as *const xmlChar,
    );
    if !parse.is_null() {
        if (unsafe { xmlStrEqual(parse, b"xml\0" as *const u8 as *const i8 as *const xmlChar) }) != 0 {
            xml = 1 as i32;
        } else if (unsafe { xmlStrEqual(parse, b"text\0" as *const u8 as *const i8 as *const xmlChar) }) != 0 {
            xml = 0 as i32;
        } else {
            xmlXIncludeErr(
                ctxt,
                cur,
                XML_XINCLUDE_PARSE_VALUE as i32,
                b"invalid value %s for 'parse'\n\0" as *const u8 as *const i8,
                parse,
            );
            if !href.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(href as *mut libc::c_void) });
            }
            if !parse.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(parse as *mut libc::c_void) });
            }
            return -(1 as i32);
        }
    }
    base = unsafe { xmlNodeGetBase((*ctxt).doc as *const xmlDoc, cur as *const xmlNode) };
    if base.is_null() {
        URI = unsafe { xmlBuildURI(href, (*(*ctxt).doc).URL) };
    } else {
        URI = unsafe { xmlBuildURI(href, base) };
    }
    if URI.is_null() {
        let mut escbase: *mut xmlChar = 0 as *mut xmlChar;
        let mut eschref: *mut xmlChar = 0 as *mut xmlChar;
        escbase = unsafe { xmlURIEscape(base) };
        eschref = unsafe { xmlURIEscape(href) };
        URI = unsafe { xmlBuildURI(eschref, escbase) };
        if !escbase.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(escbase as *mut libc::c_void) });
        }
        if !eschref.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(eschref as *mut libc::c_void) });
        }
    }
    if !parse.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(parse as *mut libc::c_void) });
    }
    if !href.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(href as *mut libc::c_void) });
    }
    if !base.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(base as *mut libc::c_void) });
    }
    if URI.is_null() {
        xmlXIncludeErr(
            ctxt,
            cur,
            XML_XINCLUDE_HREF_URI as i32,
            b"failed build URL\n\0" as *const u8 as *const i8,
            0 as *const xmlChar,
        );
        return -(1 as i32);
    }
    fragment = xmlXIncludeGetProp(
        ctxt,
        cur,
        b"xpointer\0" as *const u8 as *const i8 as *const xmlChar,
    );
    uri = unsafe { xmlParseURI(URI as *const i8) };
    if uri.is_null() {
        xmlXIncludeErr(
            ctxt,
            cur,
            XML_XINCLUDE_HREF_URI as i32,
            b"invalid value URI %s\n\0" as *const u8 as *const i8,
            URI,
        );
        if !fragment.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(fragment as *mut libc::c_void) });
        }
        (unsafe { xmlFree.expect("non-null function pointer")(URI as *mut libc::c_void) });
        return -(1 as i32);
    }
    if !(unsafe { (*uri).fragment }).is_null() {
        if (unsafe { (*ctxt).legacy }) != 0 as i32 {
            if fragment.is_null() {
                fragment = (unsafe { (*uri).fragment }) as *mut xmlChar;
            } else {
                (unsafe { xmlFree.expect("non-null function pointer")((*uri).fragment as *mut libc::c_void) });
            }
        } else {
            xmlXIncludeErr(
                ctxt,
                cur,
                XML_XINCLUDE_FRAGMENT_ID as i32,
                b"Invalid fragment identifier in URI %s use the xpointer attribute\n\0" as *const u8
                    as *const i8,
                URI,
            );
            if !fragment.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(fragment as *mut libc::c_void) });
            }
            (unsafe { xmlFreeURI(uri) });
            (unsafe { xmlFree.expect("non-null function pointer")(URI as *mut libc::c_void) });
            return -(1 as i32);
        }
        let fresh29 = unsafe { &mut ((*uri).fragment) };
        *fresh29 = 0 as *mut i8;
    }
    URL = unsafe { xmlSaveUri(uri) };
    (unsafe { xmlFreeURI(uri) });
    (unsafe { xmlFree.expect("non-null function pointer")(URI as *mut libc::c_void) });
    if URL.is_null() {
        xmlXIncludeErr(
            ctxt,
            cur,
            XML_XINCLUDE_HREF_URI as i32,
            b"invalid value URI %s\n\0" as *const u8 as *const i8,
            URI,
        );
        if !fragment.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(fragment as *mut libc::c_void) });
        }
        return -(1 as i32);
    }
    if (unsafe { xmlStrEqual(URL, (*(*ctxt).doc).URL) }) != 0 {
        local = 1 as i32;
    }
    if local == 1 as i32
        && xml == 1 as i32
        && (fragment.is_null() || (unsafe { *fragment.offset(0 as i32 as isize) }) as i32 == 0 as i32)
    {
        xmlXIncludeErr(
            ctxt,
            cur,
            XML_XINCLUDE_RECURSION as i32,
            b"detected a local recursion with no xpointer in %s\n\0" as *const u8 as *const i8,
            URL,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
        (unsafe { xmlFree.expect("non-null function pointer")(fragment as *mut libc::c_void) });
        return -(1 as i32);
    }
    if local == 0 && xml == 1 as i32 {
        i = 0 as i32;
        while i < (unsafe { (*ctxt).urlNr }) {
            if (unsafe { xmlStrEqual(URL, *((*ctxt).urlTab).offset(i as isize)) }) != 0 {
                xmlXIncludeErr(
                    ctxt,
                    cur,
                    XML_XINCLUDE_RECURSION as i32,
                    b"detected a recursion in %s\n\0" as *const u8 as *const i8,
                    URL,
                );
                (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
                (unsafe { xmlFree.expect("non-null function pointer")(fragment as *mut libc::c_void) });
                return -(1 as i32);
            }
            i += 1;
        }
    }
    ref_0 = xmlXIncludeNewRef(ctxt, URL, cur);
    (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
    if ref_0.is_null() {
        return -(1 as i32);
    }
    let fresh30 = unsafe { &mut ((*ref_0).fragment) };
    *fresh30 = fragment;
    let fresh31 = unsafe { &mut ((*ref_0).doc) };
    *fresh31 = 0 as xmlDocPtr;
    (unsafe { (*ref_0).xml = xml });
    (unsafe { (*ref_0).count = 1 as i32 });
    return 0 as i32;
}
extern "C" fn xmlXIncludeRecurseDoc(mut ctxt: xmlXIncludeCtxtPtr, mut doc: xmlDocPtr, _url: xmlURL) {
    let mut newctxt: xmlXIncludeCtxtPtr = 0 as *mut xmlXIncludeCtxt;
    let mut i: i32 = 0;
    newctxt = xmlXIncludeNewContext(doc);
    if !newctxt.is_null() {
        let fresh32 = unsafe { &mut ((*newctxt)._private) };
        *fresh32 = unsafe { (*ctxt)._private };
        (unsafe { (*newctxt).incMax = (*ctxt).incMax });
        (unsafe { (*newctxt).incNr = (*ctxt).incNr });
        let fresh33 = unsafe { &mut ((*newctxt).incTab) };
        *fresh33 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ((*newctxt).incMax as u64)
                .wrapping_mul(::std::mem::size_of::<xmlXIncludeRefPtr>() as u64),
        ) }) as *mut xmlXIncludeRefPtr;
        if (unsafe { (*newctxt).incTab }).is_null() {
            xmlXIncludeErrMemory(
                ctxt,
                doc as xmlNodePtr,
                b"processing doc\0" as *const u8 as *const i8,
            );
            (unsafe { xmlFree.expect("non-null function pointer")(newctxt as *mut libc::c_void) });
            return;
        }
        (unsafe { (*newctxt).urlMax = (*ctxt).urlMax });
        (unsafe { (*newctxt).urlNr = (*ctxt).urlNr });
        let fresh34 = unsafe { &mut ((*newctxt).urlTab) };
        *fresh34 = unsafe { (*ctxt).urlTab };
        let fresh35 = unsafe { &mut ((*newctxt).base) };
        *fresh35 = unsafe { xmlStrdup((*ctxt).base) };
        (unsafe { (*newctxt).incBase = (*ctxt).incNr });
        i = 0 as i32;
        while i < (unsafe { (*ctxt).incNr }) {
            let fresh36 = unsafe { &mut (*((*newctxt).incTab).offset(i as isize)) };
            *fresh36 = unsafe { *((*ctxt).incTab).offset(i as isize) };
            let fresh37 = unsafe { &mut ((**((*newctxt).incTab).offset(i as isize)).count) };
            *fresh37 += 1;
            i += 1;
        }
        (unsafe { (*newctxt).parseFlags = (*ctxt).parseFlags });
        (unsafe { (*newctxt).incTotal = (*ctxt).incTotal });
        xmlXIncludeDoProcess(
            newctxt,
            doc,
            unsafe { xmlDocGetRootElement(doc as *const xmlDoc) },
            0 as i32,
        );
        (unsafe { (*ctxt).incTotal = (*newctxt).incTotal });
        i = 0 as i32;
        while i < (unsafe { (*ctxt).incNr }) {
            let fresh38 = unsafe { &mut ((**((*newctxt).incTab).offset(i as isize)).count) };
            *fresh38 -= 1;
            let fresh39 = unsafe { &mut (*((*newctxt).incTab).offset(i as isize)) };
            *fresh39 = 0 as xmlXIncludeRefPtr;
            i += 1;
        }
        let fresh40 = unsafe { &mut ((*ctxt).urlTab) };
        *fresh40 = unsafe { (*newctxt).urlTab };
        (unsafe { (*ctxt).urlMax = (*newctxt).urlMax });
        (unsafe { (*newctxt).urlMax = 0 as i32 });
        (unsafe { (*newctxt).urlNr = 0 as i32 });
        let fresh41 = unsafe { &mut ((*newctxt).urlTab) };
        *fresh41 = 0 as *mut *mut xmlChar;
        xmlXIncludeFreeContext(newctxt);
    }
}
extern "C" fn xmlXIncludeAddTxt(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut txt: *const xmlChar,
    url: xmlURL,
) {
    if (unsafe { (*ctxt).txtMax }) == 0 as i32 {
        (unsafe { (*ctxt).txtMax = 4 as i32 });
        let fresh42 = unsafe { &mut ((*ctxt).txtTab) };
        *fresh42 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ((*ctxt).txtMax as u64).wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
        ) }) as *mut *mut xmlChar;
        if (unsafe { (*ctxt).txtTab }).is_null() {
            xmlXIncludeErrMemory(
                ctxt,
                0 as xmlNodePtr,
                b"processing text\0" as *const u8 as *const i8,
            );
            return;
        }
        let fresh43 = unsafe { &mut ((*ctxt).txturlTab) };
        *fresh43 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ((*ctxt).txtMax as u64).wrapping_mul(::std::mem::size_of::<xmlURL>() as u64),
        ) }) as *mut xmlURL;
        if (unsafe { (*ctxt).txturlTab }).is_null() {
            xmlXIncludeErrMemory(
                ctxt,
                0 as xmlNodePtr,
                b"processing text\0" as *const u8 as *const i8,
            );
            return;
        }
    }
    if (unsafe { (*ctxt).txtNr }) >= (unsafe { (*ctxt).txtMax }) {
        (unsafe { (*ctxt).txtMax *= 2 as i32 });
        let fresh44 = unsafe { &mut ((*ctxt).txtTab) };
        *fresh44 = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*ctxt).txtTab as *mut libc::c_void,
            ((*ctxt).txtMax as u64).wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
        ) }) as *mut *mut xmlChar;
        if (unsafe { (*ctxt).txtTab }).is_null() {
            xmlXIncludeErrMemory(
                ctxt,
                0 as xmlNodePtr,
                b"processing text\0" as *const u8 as *const i8,
            );
            return;
        }
        let fresh45 = unsafe { &mut ((*ctxt).txturlTab) };
        *fresh45 = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*ctxt).txturlTab as *mut libc::c_void,
            ((*ctxt).txtMax as u64).wrapping_mul(::std::mem::size_of::<xmlURL>() as u64),
        ) }) as *mut xmlURL;
        if (unsafe { (*ctxt).txturlTab }).is_null() {
            xmlXIncludeErrMemory(
                ctxt,
                0 as xmlNodePtr,
                b"processing text\0" as *const u8 as *const i8,
            );
            return;
        }
    }
    let fresh46 = unsafe { &mut (*((*ctxt).txtTab).offset((*ctxt).txtNr as isize)) };
    *fresh46 = unsafe { xmlStrdup(txt) };
    let fresh47 = unsafe { &mut (*((*ctxt).txturlTab).offset((*ctxt).txtNr as isize)) };
    *fresh47 = unsafe { xmlStrdup(url as *const xmlChar) };
    let fresh48 = unsafe { &mut ((*ctxt).txtNr) };
    *fresh48 += 1;
}
extern "C" fn xmlXIncludeCopyNode(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut target: xmlDocPtr,
    mut source: xmlDocPtr,
    mut elem: xmlNodePtr,
) -> xmlNodePtr {
    let mut result: xmlNodePtr = 0 as xmlNodePtr;
    if ctxt.is_null() || target.is_null() || source.is_null() || elem.is_null() {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*elem).type_0 }) as u32 == XML_DTD_NODE as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*elem).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32 {
        result = xmlXIncludeCopyNodeList(ctxt, target, source, unsafe { (*elem).children });
    } else {
        result = unsafe { xmlDocCopyNode(elem, target, 1 as i32) };
    }
    return result;
}
extern "C" fn xmlXIncludeCopyNodeList(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut target: xmlDocPtr,
    mut source: xmlDocPtr,
    mut elem: xmlNodePtr,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut res: xmlNodePtr = 0 as *mut xmlNode;
    let mut result: xmlNodePtr = 0 as xmlNodePtr;
    let mut last: xmlNodePtr = 0 as xmlNodePtr;
    if ctxt.is_null() || target.is_null() || source.is_null() || elem.is_null() {
        return 0 as xmlNodePtr;
    }
    cur = elem;
    while !cur.is_null() {
        res = xmlXIncludeCopyNode(ctxt, target, source, cur);
        if !res.is_null() {
            if result.is_null() {
                last = res;
                result = last;
            } else {
                let fresh49 = unsafe { &mut ((*last).next) };
                *fresh49 = res;
                let fresh50 = unsafe { &mut ((*res).prev) };
                *fresh50 = last;
                last = res;
            }
        }
        cur = unsafe { (*cur).next };
    }
    return result;
}
extern "C" fn xmlXIncludeCopyXPointer(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut target: xmlDocPtr,
    mut source: xmlDocPtr,
    mut obj: xmlXPathObjectPtr,
) -> xmlNodePtr {
    let mut list: xmlNodePtr = 0 as xmlNodePtr;
    let mut last: xmlNodePtr = 0 as xmlNodePtr;
    let mut i: i32 = 0;
    if source.is_null() {
        source = unsafe { (*ctxt).doc };
    }
    if ctxt.is_null() || target.is_null() || source.is_null() || obj.is_null() {
        return 0 as xmlNodePtr;
    }
    match (unsafe { (*obj).type_0 }) as u32 {
        1 => {
            let mut set: xmlNodeSetPtr = unsafe { (*obj).nodesetval };
            if set.is_null() {
                return 0 as xmlNodePtr;
            }
            let mut current_block_21: u64;
            i = 0 as i32;
            while i < (unsafe { (*set).nodeNr }) {
                if !(unsafe { *((*set).nodeTab).offset(i as isize) }).is_null() {
                    match (unsafe { (**((*set).nodeTab).offset(i as isize)).type_0 }) as u32 {
                        19 => {
                            current_block_21 = 10048703153582371463;
                            match current_block_21 {
                                17500079516916021833 => {
                                    if last.is_null() {
                                        last = xmlXIncludeCopyNode(
                                            ctxt,
                                            target,
                                            source,
                                            unsafe { *((*set).nodeTab).offset(i as isize) },
                                        );
                                        list = last;
                                    } else {
                                        (unsafe { xmlAddNextSibling(
                                            last,
                                            xmlXIncludeCopyNode(
                                                ctxt,
                                                target,
                                                source,
                                                *((*set).nodeTab).offset(i as isize),
                                            ),
                                        ) });
                                        if !(unsafe { (*last).next }).is_null() {
                                            last = unsafe { (*last).next };
                                        }
                                    }
                                }
                                _ => {
                                    let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
                                    let mut cur: xmlNodePtr = unsafe { *((*set).nodeTab).offset(i as isize) };
                                    cur = unsafe { (*cur).next };
                                    while !cur.is_null() {
                                        match (unsafe { (*cur).type_0 }) as u32 {
                                            3 | 4 | 1 | 5 | 6 | 7 | 8 => {}
                                            _ => {
                                                break;
                                            }
                                        }
                                        tmp = xmlXIncludeCopyNode(ctxt, target, source, cur);
                                        if last.is_null() {
                                            last = tmp;
                                            list = last;
                                        } else {
                                            last = unsafe { xmlAddNextSibling(last, tmp) };
                                        }
                                        cur = unsafe { (*cur).next };
                                    }
                                }
                            }
                        }
                        2 | 18 | 10 | 11 | 12 | 14 | 15 | 16 | 17 => {}
                        3 | 4 | 1 | 5 | 6 | 7 | 8 | 9 | 13 | 20 | _ => {
                            current_block_21 = 17500079516916021833;
                            match current_block_21 {
                                17500079516916021833 => {
                                    if last.is_null() {
                                        last = xmlXIncludeCopyNode(
                                            ctxt,
                                            target,
                                            source,
                                            unsafe { *((*set).nodeTab).offset(i as isize) },
                                        );
                                        list = last;
                                    } else {
                                        (unsafe { xmlAddNextSibling(
                                            last,
                                            xmlXIncludeCopyNode(
                                                ctxt,
                                                target,
                                                source,
                                                *((*set).nodeTab).offset(i as isize),
                                            ),
                                        ) });
                                        if !(unsafe { (*last).next }).is_null() {
                                            last = unsafe { (*last).next };
                                        }
                                    }
                                }
                                _ => {
                                    let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
                                    let mut cur: xmlNodePtr = unsafe { *((*set).nodeTab).offset(i as isize) };
                                    cur = unsafe { (*cur).next };
                                    while !cur.is_null() {
                                        match (unsafe { (*cur).type_0 }) as u32 {
                                            3 | 4 | 1 | 5 | 6 | 7 | 8 => {}
                                            _ => {
                                                break;
                                            }
                                        }
                                        tmp = xmlXIncludeCopyNode(ctxt, target, source, cur);
                                        if last.is_null() {
                                            last = tmp;
                                            list = last;
                                        } else {
                                            last = unsafe { xmlAddNextSibling(last, tmp) };
                                        }
                                        cur = unsafe { (*cur).next };
                                    }
                                }
                            }
                        }
                    }
                }
                i += 1;
            }
        }
        _ => {}
    }
    return list;
}
extern "C" fn xmlXIncludeMergeEntity(
    mut payload: *mut libc::c_void,
    mut vdata: *mut libc::c_void,
    mut _name: *const xmlChar,
) {
    let mut current_block: u64;
    let mut ent: xmlEntityPtr = payload as xmlEntityPtr;
    let mut data: xmlXIncludeMergeDataPtr = vdata as xmlXIncludeMergeDataPtr;
    let mut ret: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut prev: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlXIncludeCtxtPtr = 0 as *mut xmlXIncludeCtxt;
    if ent.is_null() || data.is_null() {
        return;
    }
    ctxt = unsafe { (*data).ctxt };
    doc = unsafe { (*data).doc };
    if ctxt.is_null() || doc.is_null() {
        return;
    }
    match (unsafe { (*ent).etype }) as u32 {
        4 | 5 | 6 => return,
        1 | 2 | 3 | _ => {}
    }
    ret = unsafe { xmlAddDocEntity(
        doc,
        (*ent).name,
        (*ent).etype as i32,
        (*ent).ExternalID,
        (*ent).SystemID,
        (*ent).content,
    ) };
    if !ret.is_null() {
        if !(unsafe { (*ent).URI }).is_null() {
            let fresh51 = unsafe { &mut ((*ret).URI) };
            *fresh51 = unsafe { xmlStrdup((*ent).URI) };
        }
    } else {
        prev = unsafe { xmlGetDocEntity(doc as *const xmlDoc, (*ent).name) };
        if !prev.is_null() {
            if (unsafe { (*ent).etype }) as u32 != (unsafe { (*prev).etype }) as u32 {
                current_block = 12812742145916658025;
            } else if !(unsafe { (*ent).SystemID }).is_null() && !(unsafe { (*prev).SystemID }).is_null() {
                if (unsafe { xmlStrEqual((*ent).SystemID, (*prev).SystemID) }) == 0 {
                    current_block = 12812742145916658025;
                } else {
                    current_block = 4488286894823169796;
                }
            } else if !(unsafe { (*ent).ExternalID }).is_null() && !(unsafe { (*prev).ExternalID }).is_null() {
                if (unsafe { xmlStrEqual((*ent).ExternalID, (*prev).ExternalID) }) == 0 {
                    current_block = 12812742145916658025;
                } else {
                    current_block = 4488286894823169796;
                }
            } else if !(unsafe { (*ent).content }).is_null() && !(unsafe { (*prev).content }).is_null() {
                if (unsafe { xmlStrEqual((*ent).content, (*prev).content) }) == 0 {
                    current_block = 12812742145916658025;
                } else {
                    current_block = 4488286894823169796;
                }
            } else {
                current_block = 12812742145916658025;
            }
            match current_block {
                4488286894823169796 => {}
                _ => {
                    match (unsafe { (*ent).etype }) as u32 {
                        4 | 5 | 6 | 1 | 2 => return,
                        3 | _ => {}
                    }
                    xmlXIncludeErr(
                        ctxt,
                        ent as xmlNodePtr,
                        XML_XINCLUDE_ENTITY_DEF_MISMATCH as i32,
                        b"mismatch in redefinition of entity %s\n\0" as *const u8 as *const i8,
                        unsafe { (*ent).name },
                    );
                    return;
                }
            }
        }
    };
}
extern "C" fn xmlXIncludeMergeEntities(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut doc: xmlDocPtr,
    mut from: xmlDocPtr,
) -> i32 {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut target: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut source: xmlDtdPtr = 0 as *mut xmlDtd;
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if from.is_null() || (unsafe { (*from).intSubset }).is_null() {
        return 0 as i32;
    }
    target = unsafe { (*doc).intSubset };
    if target.is_null() {
        cur = unsafe { xmlDocGetRootElement(doc as *const xmlDoc) };
        if cur.is_null() {
            return -(1 as i32);
        }
        target = unsafe { xmlCreateIntSubset(doc, (*cur).name, 0 as *const xmlChar, 0 as *const xmlChar) };
        if target.is_null() {
            return -(1 as i32);
        }
    }
    source = unsafe { (*from).intSubset };
    if !source.is_null() && !(unsafe { (*source).entities }).is_null() {
        let mut data: xmlXIncludeMergeData = xmlXIncludeMergeData {
            doc: 0 as *mut xmlDoc,
            ctxt: 0 as *mut xmlXIncludeCtxt,
        };
        data.ctxt = ctxt;
        data.doc = doc;
        (unsafe { xmlHashScan(
            (*source).entities as xmlHashTablePtr,
            Some(
                xmlXIncludeMergeEntity
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> (),
            ),
            &mut data as *mut xmlXIncludeMergeData as *mut libc::c_void,
        ) });
    }
    source = unsafe { (*from).extSubset };
    if !source.is_null() && !(unsafe { (*source).entities }).is_null() {
        let mut data_0: xmlXIncludeMergeData = xmlXIncludeMergeData {
            doc: 0 as *mut xmlDoc,
            ctxt: 0 as *mut xmlXIncludeCtxt,
        };
        data_0.ctxt = ctxt;
        data_0.doc = doc;
        if (unsafe { xmlStrEqual((*target).ExternalID, (*source).ExternalID) }) == 0
            && (unsafe { xmlStrEqual((*target).SystemID, (*source).SystemID) }) == 0
        {
            (unsafe { xmlHashScan(
                (*source).entities as xmlHashTablePtr,
                Some(
                    xmlXIncludeMergeEntity
                        as unsafe extern "C" fn(
                            *mut libc::c_void,
                            *mut libc::c_void,
                            *const xmlChar,
                        ) -> (),
                ),
                &mut data_0 as *mut xmlXIncludeMergeData as *mut libc::c_void,
            ) });
        }
    }
    return 0 as i32;
}
extern "C" fn xmlXIncludeLoadDoc(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut url: *const xmlChar,
    mut nr: i32,
) -> i32 {
    let mut current_block: u64;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut URL: *mut xmlChar = 0 as *mut xmlChar;
    let mut fragment: *mut xmlChar = 0 as *mut xmlChar;
    let mut i: i32 = 0 as i32;
    let mut saveFlags: i32 = 0;
    uri = unsafe { xmlParseURI(url as *const i8) };
    if uri.is_null() {
        xmlXIncludeErr(
            ctxt,
            unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
            XML_XINCLUDE_HREF_URI as i32,
            b"invalid value URI %s\n\0" as *const u8 as *const i8,
            url,
        );
        return -(1 as i32);
    }
    if !(unsafe { (*uri).fragment }).is_null() {
        fragment = (unsafe { (*uri).fragment }) as *mut xmlChar;
        let fresh52 = unsafe { &mut ((*uri).fragment) };
        *fresh52 = 0 as *mut i8;
    }
    if !(unsafe { (*ctxt).incTab }).is_null()
        && !(unsafe { *((*ctxt).incTab).offset(nr as isize) }).is_null()
        && !(unsafe { (**((*ctxt).incTab).offset(nr as isize)).fragment }).is_null()
    {
        if !fragment.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(fragment as *mut libc::c_void) });
        }
        fragment = unsafe { xmlStrdup((**((*ctxt).incTab).offset(nr as isize)).fragment) };
    }
    URL = unsafe { xmlSaveUri(uri) };
    (unsafe { xmlFreeURI(uri) });
    if URL.is_null() {
        if !(unsafe { (*ctxt).incTab }).is_null() {
            xmlXIncludeErr(
                ctxt,
                unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                XML_XINCLUDE_HREF_URI as i32,
                b"invalid value URI %s\n\0" as *const u8 as *const i8,
                url,
            );
        } else {
            xmlXIncludeErr(
                ctxt,
                0 as xmlNodePtr,
                XML_XINCLUDE_HREF_URI as i32,
                b"invalid value URI %s\n\0" as *const u8 as *const i8,
                url,
            );
        }
        if !fragment.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(fragment as *mut libc::c_void) });
        }
        return -(1 as i32);
    }
    if (unsafe { *URL.offset(0 as i32 as isize) }) as i32 == 0 as i32
        || (unsafe { *URL.offset(0 as i32 as isize) }) as i32 == '#' as i32
        || !(unsafe { (*ctxt).doc }).is_null() && (unsafe { xmlStrEqual(URL, (*(*ctxt).doc).URL) }) != 0
    {
        doc = unsafe { (*ctxt).doc };
    } else {
        i = 0 as i32;
        loop {
            if !(i < (unsafe { (*ctxt).incNr })) {
                current_block = 2891135413264362348;
                break;
            }
            if (unsafe { xmlStrEqual(URL, (**((*ctxt).incTab).offset(i as isize)).URI) }) != 0
                && !(unsafe { (**((*ctxt).incTab).offset(i as isize)).doc }).is_null()
            {
                doc = unsafe { (**((*ctxt).incTab).offset(i as isize)).doc };
                current_block = 589394341134521308;
                break;
            } else {
                i += 1;
            }
        }
        match current_block {
            589394341134521308 => {}
            _ => {
                saveFlags = unsafe { (*ctxt).parseFlags };
                if !fragment.is_null() {
                    (unsafe { (*ctxt).parseFlags |= XML_PARSE_NOENT as i32 });
                }
                doc = xmlXIncludeParseFile(ctxt, URL as *const i8);
                (unsafe { (*ctxt).parseFlags = saveFlags });
                if doc.is_null() {
                    (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
                    if !fragment.is_null() {
                        (unsafe { xmlFree.expect("non-null function pointer")(fragment as *mut libc::c_void) });
                    }
                    return -(1 as i32);
                }
                let fresh53 = unsafe { &mut ((**((*ctxt).incTab).offset(nr as isize)).doc) };
                *fresh53 = doc;
                if (unsafe { xmlStrEqual(URL, (*doc).URL) }) == 0 {
                    (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
                    URL = unsafe { xmlStrdup((*doc).URL) };
                }
                i = nr + 1 as i32;
                while i < (unsafe { (*ctxt).incNr }) {
                    if (unsafe { xmlStrEqual(URL, (**((*ctxt).incTab).offset(i as isize)).URI) }) != 0 {
                        let fresh54 = unsafe { &mut ((**((*ctxt).incTab).offset(nr as isize)).count) };
                        *fresh54 += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
                xmlXIncludeMergeEntities(ctxt, unsafe { (*ctxt).doc }, doc);
                xmlXIncludeRecurseDoc(ctxt, doc, URL);
            }
        }
    }
    if fragment.is_null() {
        let fresh55 = unsafe { &mut ((**((*ctxt).incTab).offset(nr as isize)).inc) };
        *fresh55 = xmlXIncludeCopyNodeList(ctxt, unsafe { (*ctxt).doc }, doc, unsafe { (*doc).children });
    } else {
        let mut xptr: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
        let mut xptrctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
        let mut set: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
        xptrctxt = unsafe { xmlXPtrNewContext(doc, 0 as xmlNodePtr, 0 as xmlNodePtr) };
        if xptrctxt.is_null() {
            xmlXIncludeErr(
                ctxt,
                unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                XML_XINCLUDE_XPTR_FAILED as i32,
                b"could not create XPointer context\n\0" as *const u8 as *const i8,
                0 as *const xmlChar,
            );
            (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
            (unsafe { xmlFree.expect("non-null function pointer")(fragment as *mut libc::c_void) });
            return -(1 as i32);
        }
        xptr = unsafe { xmlXPtrEval(fragment, xptrctxt) };
        if xptr.is_null() {
            xmlXIncludeErr(
                ctxt,
                unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                XML_XINCLUDE_XPTR_FAILED as i32,
                b"XPointer evaluation failed: #%s\n\0" as *const u8 as *const i8,
                fragment,
            );
            (unsafe { xmlXPathFreeContext(xptrctxt) });
            (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
            (unsafe { xmlFree.expect("non-null function pointer")(fragment as *mut libc::c_void) });
            return -(1 as i32);
        }
        match (unsafe { (*xptr).type_0 }) as u32 {
            0 | 2 | 3 | 4 | 8 | 9 => {
                xmlXIncludeErr(
                    ctxt,
                    unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                    XML_XINCLUDE_XPTR_RESULT as i32,
                    b"XPointer is not a range: #%s\n\0" as *const u8 as *const i8,
                    fragment,
                );
                (unsafe { xmlXPathFreeObject(xptr) });
                (unsafe { xmlXPathFreeContext(xptrctxt) });
                (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
                (unsafe { xmlFree.expect("non-null function pointer")(fragment as *mut libc::c_void) });
                return -(1 as i32);
            }
            1 => {
                if (unsafe { (*xptr).nodesetval }).is_null() || (unsafe { (*(*xptr).nodesetval).nodeNr }) <= 0 as i32 {
                    (unsafe { xmlXPathFreeObject(xptr) });
                    (unsafe { xmlXPathFreeContext(xptrctxt) });
                    (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
                    (unsafe { xmlFree.expect("non-null function pointer")(fragment as *mut libc::c_void) });
                    return -(1 as i32);
                }
            }
            _ => {}
        }
        set = unsafe { (*xptr).nodesetval };
        if !set.is_null() {
            let mut current_block_88: u64;
            i = 0 as i32;
            while i < (unsafe { (*set).nodeNr }) {
                if !(unsafe { *((*set).nodeTab).offset(i as isize) }).is_null() {
                    match (unsafe { (**((*set).nodeTab).offset(i as isize)).type_0 }) as u32 {
                        2 => {
                            current_block_88 = 8131075156226769733;
                            match current_block_88 {
                                8131075156226769733 => {
                                    xmlXIncludeErr(
                                        ctxt,
                                        unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                                        XML_XINCLUDE_XPTR_RESULT as i32,
                                        b"XPointer selects an attribute: #%s\n\0" as *const u8
                                            as *const i8,
                                        fragment,
                                    );
                                    let fresh56 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                                    *fresh56 = 0 as xmlNodePtr;
                                }
                                13051158764793554351 => {
                                    xmlXIncludeErr(
                                        ctxt,
                                        unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                                        XML_XINCLUDE_XPTR_RESULT as i32,
                                        b"XPointer selects a namespace: #%s\n\0" as *const u8
                                            as *const i8,
                                        fragment,
                                    );
                                    let fresh57 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                                    *fresh57 = 0 as xmlNodePtr;
                                }
                                _ => {
                                    xmlXIncludeErr(
                                        ctxt,
                                        unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                                        XML_XINCLUDE_XPTR_RESULT as i32,
                                        b"XPointer selects unexpected nodes: #%s\n\0" as *const u8
                                            as *const i8,
                                        fragment,
                                    );
                                    let fresh58 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                                    *fresh58 = 0 as xmlNodePtr;
                                    let fresh59 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                                    *fresh59 = 0 as xmlNodePtr;
                                }
                            }
                        }
                        18 => {
                            current_block_88 = 13051158764793554351;
                            match current_block_88 {
                                8131075156226769733 => {
                                    xmlXIncludeErr(
                                        ctxt,
                                        unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                                        XML_XINCLUDE_XPTR_RESULT as i32,
                                        b"XPointer selects an attribute: #%s\n\0" as *const u8
                                            as *const i8,
                                        fragment,
                                    );
                                    let fresh56 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                                    *fresh56 = 0 as xmlNodePtr;
                                }
                                13051158764793554351 => {
                                    xmlXIncludeErr(
                                        ctxt,
                                        unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                                        XML_XINCLUDE_XPTR_RESULT as i32,
                                        b"XPointer selects a namespace: #%s\n\0" as *const u8
                                            as *const i8,
                                        fragment,
                                    );
                                    let fresh57 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                                    *fresh57 = 0 as xmlNodePtr;
                                }
                                _ => {
                                    xmlXIncludeErr(
                                        ctxt,
                                        unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                                        XML_XINCLUDE_XPTR_RESULT as i32,
                                        b"XPointer selects unexpected nodes: #%s\n\0" as *const u8
                                            as *const i8,
                                        fragment,
                                    );
                                    let fresh58 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                                    *fresh58 = 0 as xmlNodePtr;
                                    let fresh59 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                                    *fresh59 = 0 as xmlNodePtr;
                                }
                            }
                        }
                        10 | 11 | 12 | 14 | 15 | 16 | 17 | 19 | 20 => {
                            current_block_88 = 10929830860880138834;
                            match current_block_88 {
                                8131075156226769733 => {
                                    xmlXIncludeErr(
                                        ctxt,
                                        unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                                        XML_XINCLUDE_XPTR_RESULT as i32,
                                        b"XPointer selects an attribute: #%s\n\0" as *const u8
                                            as *const i8,
                                        fragment,
                                    );
                                    let fresh56 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                                    *fresh56 = 0 as xmlNodePtr;
                                }
                                13051158764793554351 => {
                                    xmlXIncludeErr(
                                        ctxt,
                                        unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                                        XML_XINCLUDE_XPTR_RESULT as i32,
                                        b"XPointer selects a namespace: #%s\n\0" as *const u8
                                            as *const i8,
                                        fragment,
                                    );
                                    let fresh57 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                                    *fresh57 = 0 as xmlNodePtr;
                                }
                                _ => {
                                    xmlXIncludeErr(
                                        ctxt,
                                        unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                                        XML_XINCLUDE_XPTR_RESULT as i32,
                                        b"XPointer selects unexpected nodes: #%s\n\0" as *const u8
                                            as *const i8,
                                        fragment,
                                    );
                                    let fresh58 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                                    *fresh58 = 0 as xmlNodePtr;
                                    let fresh59 = unsafe { &mut (*((*set).nodeTab).offset(i as isize)) };
                                    *fresh59 = 0 as xmlNodePtr;
                                }
                            }
                        }
                        1 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 13 | _ => {}
                    }
                }
                i += 1;
            }
        }
        let fresh60 = unsafe { &mut ((**((*ctxt).incTab).offset(nr as isize)).inc) };
        *fresh60 = xmlXIncludeCopyXPointer(ctxt, unsafe { (*ctxt).doc }, doc, xptr);
        (unsafe { xmlXPathFreeObject(xptr) });
        (unsafe { xmlXPathFreeContext(xptrctxt) });
        (unsafe { xmlFree.expect("non-null function pointer")(fragment as *mut libc::c_void) });
    }
    if !doc.is_null()
        && !URL.is_null()
        && (unsafe { (*ctxt).parseFlags }) & XML_PARSE_NOBASEFIX as i32 == 0
        && (unsafe { (*doc).parseFlags }) & XML_PARSE_NOBASEFIX as i32 == 0
    {
        let mut node: xmlNodePtr = 0 as *mut xmlNode;
        let mut base: *mut xmlChar = 0 as *mut xmlChar;
        let mut curBase: *mut xmlChar = 0 as *mut xmlChar;
        base = unsafe { xmlGetNsProp(
            (**((*ctxt).incTab).offset(nr as isize)).ref_0 as *const xmlNode,
            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
        ) };
        if base.is_null() {
            curBase = unsafe { xmlBuildRelativeURI(URL, (*ctxt).base) };
            if curBase.is_null() {
                xmlXIncludeErr(
                    ctxt,
                    unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                    XML_XINCLUDE_HREF_URI as i32,
                    b"trying to build relative URI from %s\n\0" as *const u8 as *const i8,
                    URL,
                );
            } else if (unsafe { xmlStrchr(curBase, '/' as i32 as xmlChar) }).is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(curBase as *mut libc::c_void) });
            } else {
                base = curBase;
            }
        }
        if !base.is_null() {
            node = unsafe { (**((*ctxt).incTab).offset(nr as isize)).inc };
            while !node.is_null() {
                if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                    curBase = unsafe { xmlNodeGetBase((*node).doc, node as *const xmlNode) };
                    if curBase.is_null() {
                        (unsafe { xmlNodeSetBase(node, base) });
                    } else {
                        if (unsafe { xmlStrEqual(curBase, (*(*node).doc).URL) }) != 0 {
                            (unsafe { xmlNodeSetBase(node, base) });
                        } else {
                            let mut xmlBase: *mut xmlChar = 0 as *mut xmlChar;
                            xmlBase = unsafe { xmlGetNsProp(
                                node as *const xmlNode,
                                b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                                b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                                    as *const xmlChar,
                            ) };
                            if !xmlBase.is_null() {
                                let mut relBase: *mut xmlChar = 0 as *mut xmlChar;
                                relBase = unsafe { xmlBuildURI(xmlBase, base) };
                                if relBase.is_null() {
                                    xmlXIncludeErr(
                                        ctxt,
                                        unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                                        XML_XINCLUDE_HREF_URI as i32,
                                        b"trying to rebuild base from %s\n\0" as *const u8
                                            as *const i8,
                                        xmlBase,
                                    );
                                } else {
                                    (unsafe { xmlNodeSetBase(node, relBase) });
                                    (unsafe { xmlFree.expect("non-null function pointer")(
                                        relBase as *mut libc::c_void,
                                    ) });
                                }
                                (unsafe { xmlFree.expect("non-null function pointer")(
                                    xmlBase as *mut libc::c_void,
                                ) });
                            }
                        }
                        (unsafe { xmlFree.expect("non-null function pointer")(curBase as *mut libc::c_void) });
                    }
                }
                node = unsafe { (*node).next };
            }
            (unsafe { xmlFree.expect("non-null function pointer")(base as *mut libc::c_void) });
        }
    }
    if nr < (unsafe { (*ctxt).incNr })
        && !(unsafe { (**((*ctxt).incTab).offset(nr as isize)).doc }).is_null()
        && (unsafe { (**((*ctxt).incTab).offset(nr as isize)).count }) <= 1 as i32
    {
        (unsafe { xmlFreeDoc((**((*ctxt).incTab).offset(nr as isize)).doc) });
        let fresh61 = unsafe { &mut ((**((*ctxt).incTab).offset(nr as isize)).doc) };
        *fresh61 = 0 as xmlDocPtr;
    }
    (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
    return 0 as i32;
}
extern "C" fn xmlXIncludeLoadTxt(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut url: *const xmlChar,
    mut nr: i32,
) -> i32 {
    let mut current_block: u64;
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut URL: *mut xmlChar = 0 as *mut xmlChar;
    let mut i: i32 = 0;
    let mut encoding: *mut xmlChar = 0 as *mut xmlChar;
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    let mut pctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut xinclude_multibyte_fallback_used: i32 = 0 as i32;
    if (unsafe { xmlStrcmp(url, b"-\0" as *const u8 as *const i8 as *mut xmlChar) }) == 0 as i32 {
        url = b"./-\0" as *const u8 as *const i8 as *mut xmlChar;
    }
    uri = unsafe { xmlParseURI(url as *const i8) };
    if uri.is_null() {
        xmlXIncludeErr(
            ctxt,
            unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
            XML_XINCLUDE_HREF_URI as i32,
            b"invalid value URI %s\n\0" as *const u8 as *const i8,
            url,
        );
        return -(1 as i32);
    }
    if !(unsafe { (*uri).fragment }).is_null() {
        xmlXIncludeErr(
            ctxt,
            unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
            XML_XINCLUDE_TEXT_FRAGMENT as i32,
            b"fragment identifier forbidden for text: %s\n\0" as *const u8 as *const i8,
            (unsafe { (*uri).fragment }) as *const xmlChar,
        );
        (unsafe { xmlFreeURI(uri) });
        return -(1 as i32);
    }
    URL = unsafe { xmlSaveUri(uri) };
    (unsafe { xmlFreeURI(uri) });
    if URL.is_null() {
        xmlXIncludeErr(
            ctxt,
            unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
            XML_XINCLUDE_HREF_URI as i32,
            b"invalid value URI %s\n\0" as *const u8 as *const i8,
            url,
        );
        return -(1 as i32);
    }
    if (unsafe { *URL.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
        xmlXIncludeErr(
            ctxt,
            unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
            XML_XINCLUDE_TEXT_DOCUMENT as i32,
            b"text serialization of document not available\n\0" as *const u8 as *const i8,
            0 as *const xmlChar,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
        return -(1 as i32);
    }
    i = 0 as i32;
    loop {
        if !(i < (unsafe { (*ctxt).txtNr })) {
            current_block = 5689316957504528238;
            break;
        }
        if (unsafe { xmlStrEqual(
            URL,
            *((*ctxt).txturlTab).offset(i as isize) as *const xmlChar,
        ) }) != 0
        {
            node = unsafe { xmlNewDocText(
                (*ctxt).doc as *const xmlDoc,
                *((*ctxt).txtTab).offset(i as isize),
            ) };
            current_block = 13870927760773930552;
            break;
        } else {
            i += 1;
        }
    }
    match current_block {
        5689316957504528238 => {
            if !(unsafe { *((*ctxt).incTab).offset(nr as isize) }).is_null()
                && !(unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 }).is_null()
            {
                encoding = unsafe { xmlGetProp(
                    (**((*ctxt).incTab).offset(nr as isize)).ref_0 as *const xmlNode,
                    b"encoding\0" as *const u8 as *const i8 as *const xmlChar,
                ) };
            }
            if !encoding.is_null() {
                enc = unsafe { xmlParseCharEncoding(encoding as *const i8) };
                if enc as i32 == XML_CHAR_ENCODING_ERROR as i32 {
                    xmlXIncludeErr(
                        ctxt,
                        unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                        XML_XINCLUDE_UNKNOWN_ENCODING as i32,
                        b"encoding %s not supported\n\0" as *const u8 as *const i8,
                        encoding,
                    );
                    (unsafe { xmlFree.expect("non-null function pointer")(encoding as *mut libc::c_void) });
                    (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
                    return -(1 as i32);
                }
                (unsafe { xmlFree.expect("non-null function pointer")(encoding as *mut libc::c_void) });
            }
            pctxt = unsafe { xmlNewParserCtxt() };
            inputStream = unsafe { xmlLoadExternalEntity(URL as *const i8, 0 as *const i8, pctxt) };
            if inputStream.is_null() {
                (unsafe { xmlFreeParserCtxt(pctxt) });
                (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
                return -(1 as i32);
            }
            buf = unsafe { (*inputStream).buf };
            if buf.is_null() {
                (unsafe { xmlFreeInputStream(inputStream) });
                (unsafe { xmlFreeParserCtxt(pctxt) });
                (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
                return -(1 as i32);
            }
            if !(unsafe { (*buf).encoder }).is_null() {
                (unsafe { xmlCharEncCloseFunc((*buf).encoder) });
            }
            let fresh62 = unsafe { &mut ((*buf).encoder) };
            *fresh62 = unsafe { xmlGetCharEncodingHandler(enc) };
            node = unsafe { xmlNewDocText((*ctxt).doc as *const xmlDoc, 0 as *const xmlChar) };
            's_281: while (unsafe { xmlParserInputBufferRead(buf, 128 as i32) }) > 0 as i32 {
                let mut len: i32 = 0;
                let mut content: *const xmlChar = 0 as *const xmlChar;
                content = unsafe { xmlBufContent((*buf).buffer as *const xmlBuf) };
                len = (unsafe { xmlBufLength((*buf).buffer) }) as i32;
                i = 0 as i32;
                while i < len {
                    let mut cur: i32 = 0;
                    let mut l: i32 = 0;
                    cur = unsafe { xmlStringCurrentChar(
                        0 as xmlParserCtxtPtr,
                        &*content.offset(i as isize),
                        &mut l,
                    ) };
                    if if cur < 0x100 as i32 {
                        (0x9 as i32 <= cur && cur <= 0xa as i32
                            || cur == 0xd as i32
                            || 0x20 as i32 <= cur) as i32
                    } else {
                        (0x100 as i32 <= cur && cur <= 0xd7ff as i32
                            || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
                            || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32)
                            as i32
                    } == 0
                    {
                        if len - i < 4 as i32 && xinclude_multibyte_fallback_used == 0 {
                            xinclude_multibyte_fallback_used = 1 as i32;
                            (unsafe { xmlBufShrink((*buf).buffer, i as size_t) });
                            continue 's_281;
                        } else {
                            xmlXIncludeErr(
                                ctxt,
                                unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                                XML_XINCLUDE_INVALID_CHAR as i32,
                                b"%s contains invalid char\n\0" as *const u8 as *const i8,
                                URL,
                            );
                            (unsafe { xmlFreeParserCtxt(pctxt) });
                            (unsafe { xmlFreeParserInputBuffer(buf) });
                            (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
                            return -(1 as i32);
                        }
                    } else {
                        xinclude_multibyte_fallback_used = 0 as i32;
                        (unsafe { xmlNodeAddContentLen(node, &*content.offset(i as isize), l) });
                        i += l;
                    }
                }
                (unsafe { xmlBufShrink((*buf).buffer, len as size_t) });
            }
            (unsafe { xmlFreeParserCtxt(pctxt) });
            xmlXIncludeAddTxt(ctxt, unsafe { (*node).content }, URL);
            (unsafe { xmlFreeInputStream(inputStream) });
        }
        _ => {}
    }
    let fresh63 = unsafe { &mut ((**((*ctxt).incTab).offset(nr as isize)).inc) };
    *fresh63 = node;
    (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
    return 0 as i32;
}
extern "C" fn xmlXIncludeLoadFallback(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut fallback: xmlNodePtr,
    mut nr: i32,
) -> i32 {
    let mut newctxt: xmlXIncludeCtxtPtr = 0 as *mut xmlXIncludeCtxt;
    let mut ret: i32 = 0 as i32;
    let mut oldNbErrors: i32 = unsafe { (*ctxt).nbErrors };
    if fallback.is_null()
        || (unsafe { (*fallback).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
        || ctxt.is_null()
    {
        return -(1 as i32);
    }
    if !(unsafe { (*fallback).children }).is_null() {
        newctxt = xmlXIncludeNewContext(unsafe { (*ctxt).doc });
        if newctxt.is_null() {
            return -(1 as i32);
        }
        let fresh64 = unsafe { &mut ((*newctxt)._private) };
        *fresh64 = unsafe { (*ctxt)._private };
        let fresh65 = unsafe { &mut ((*newctxt).base) };
        *fresh65 = unsafe { xmlStrdup((*ctxt).base) };
        xmlXIncludeSetFlags(newctxt, unsafe { (*ctxt).parseFlags });
        (unsafe { (*newctxt).incTotal = (*ctxt).incTotal });
        if xmlXIncludeDoProcess(newctxt, unsafe { (*ctxt).doc }, fallback, 1 as i32) < 0 as i32 {
            ret = -(1 as i32);
        }
        (unsafe { (*ctxt).incTotal = (*newctxt).incTotal });
        if (unsafe { (*ctxt).nbErrors }) > oldNbErrors {
            ret = -(1 as i32);
        }
        xmlXIncludeFreeContext(newctxt);
        let fresh66 = unsafe { &mut ((**((*ctxt).incTab).offset(nr as isize)).inc) };
        *fresh66 = unsafe { xmlDocCopyNodeList((*ctxt).doc, (*fallback).children) };
        if (unsafe { (**((*ctxt).incTab).offset(nr as isize)).inc }).is_null() {
            (unsafe { (**((*ctxt).incTab).offset(nr as isize)).emptyFb = 1 as i32 });
        }
    } else {
        let fresh67 = unsafe { &mut ((**((*ctxt).incTab).offset(nr as isize)).inc) };
        *fresh67 = 0 as xmlNodePtr;
        (unsafe { (**((*ctxt).incTab).offset(nr as isize)).emptyFb = 1 as i32 });
    }
    (unsafe { (**((*ctxt).incTab).offset(nr as isize)).fallback = 1 as i32 });
    return ret;
}
extern "C" fn xmlXIncludePreProcessNode(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut node: xmlNodePtr,
) -> xmlNodePtr {
    xmlXIncludeAddNode(ctxt, node);
    return 0 as xmlNodePtr;
}
extern "C" fn xmlXIncludeLoadNode(mut ctxt: xmlXIncludeCtxtPtr, mut nr: i32) -> i32 {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut href: *mut xmlChar = 0 as *mut xmlChar;
    let mut parse: *mut xmlChar = 0 as *mut xmlChar;
    let mut base: *mut xmlChar = 0 as *mut xmlChar;
    let mut oldBase: *mut xmlChar = 0 as *mut xmlChar;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let mut xml: i32 = 1 as i32;
    let mut ret: i32 = 0;
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if nr < 0 as i32 || nr >= (unsafe { (*ctxt).incNr }) {
        return -(1 as i32);
    }
    cur = unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 };
    if cur.is_null() {
        return -(1 as i32);
    }
    href = xmlXIncludeGetProp(
        ctxt,
        cur,
        b"href\0" as *const u8 as *const i8 as *const xmlChar,
    );
    if href.is_null() {
        href = unsafe { xmlStrdup(b"\0" as *const u8 as *const i8 as *mut xmlChar) };
        if href.is_null() {
            return -(1 as i32);
        }
    }
    parse = xmlXIncludeGetProp(
        ctxt,
        cur,
        b"parse\0" as *const u8 as *const i8 as *const xmlChar,
    );
    if !parse.is_null() {
        if (unsafe { xmlStrEqual(parse, b"xml\0" as *const u8 as *const i8 as *const xmlChar) }) != 0 {
            xml = 1 as i32;
        } else if (unsafe { xmlStrEqual(parse, b"text\0" as *const u8 as *const i8 as *const xmlChar) }) != 0 {
            xml = 0 as i32;
        } else {
            xmlXIncludeErr(
                ctxt,
                unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                XML_XINCLUDE_PARSE_VALUE as i32,
                b"invalid value %s for 'parse'\n\0" as *const u8 as *const i8,
                parse,
            );
            if !href.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(href as *mut libc::c_void) });
            }
            if !parse.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(parse as *mut libc::c_void) });
            }
            return -(1 as i32);
        }
    }
    base = unsafe { xmlNodeGetBase((*ctxt).doc as *const xmlDoc, cur as *const xmlNode) };
    if base.is_null() {
        URI = unsafe { xmlBuildURI(href, (*(*ctxt).doc).URL) };
    } else {
        URI = unsafe { xmlBuildURI(href, base) };
    }
    if URI.is_null() {
        let mut escbase: *mut xmlChar = 0 as *mut xmlChar;
        let mut eschref: *mut xmlChar = 0 as *mut xmlChar;
        escbase = unsafe { xmlURIEscape(base) };
        eschref = unsafe { xmlURIEscape(href) };
        URI = unsafe { xmlBuildURI(eschref, escbase) };
        if !escbase.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(escbase as *mut libc::c_void) });
        }
        if !eschref.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(eschref as *mut libc::c_void) });
        }
    }
    if URI.is_null() {
        xmlXIncludeErr(
            ctxt,
            unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
            XML_XINCLUDE_HREF_URI as i32,
            b"failed build URL\n\0" as *const u8 as *const i8,
            0 as *const xmlChar,
        );
        if !parse.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(parse as *mut libc::c_void) });
        }
        if !href.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(href as *mut libc::c_void) });
        }
        if !base.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(base as *mut libc::c_void) });
        }
        return -(1 as i32);
    }
    oldBase = unsafe { (*ctxt).base };
    let fresh68 = unsafe { &mut ((*ctxt).base) };
    *fresh68 = base;
    if xml != 0 {
        ret = xmlXIncludeLoadDoc(ctxt, URI, nr);
    } else {
        ret = xmlXIncludeLoadTxt(ctxt, URI, nr);
    }
    let fresh69 = unsafe { &mut ((*ctxt).base) };
    *fresh69 = oldBase;
    if ret < 0 as i32 {
        let mut children: xmlNodePtr = 0 as *mut xmlNode;
        children = unsafe { (*cur).children };
        while !children.is_null() {
            if (unsafe { (*children).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                && !(unsafe { (*children).ns }).is_null()
                && (unsafe { xmlStrEqual(
                    (*children).name,
                    b"fallback\0" as *const u8 as *const i8 as *const xmlChar,
                ) }) != 0
                && ((unsafe { xmlStrEqual(
                    (*(*children).ns).href,
                    b"http://www.w3.org/2003/XInclude\0" as *const u8 as *const i8
                        as *const xmlChar,
                ) }) != 0
                    || (unsafe { xmlStrEqual(
                        (*(*children).ns).href,
                        b"http://www.w3.org/2001/XInclude\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) }) != 0)
            {
                ret = xmlXIncludeLoadFallback(ctxt, children, nr);
                break;
            } else {
                children = unsafe { (*children).next };
            }
        }
    }
    if ret < 0 as i32 {
        xmlXIncludeErr(
            ctxt,
            unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
            XML_XINCLUDE_NO_FALLBACK as i32,
            b"could not load %s, and no fallback was found\n\0" as *const u8 as *const i8,
            URI,
        );
    }
    if !URI.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(URI as *mut libc::c_void) });
    }
    if !parse.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(parse as *mut libc::c_void) });
    }
    if !href.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(href as *mut libc::c_void) });
    }
    if !base.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(base as *mut libc::c_void) });
    }
    return 0 as i32;
}
extern "C" fn xmlXIncludeIncludeNode(mut ctxt: xmlXIncludeCtxtPtr, mut nr: i32) -> i32 {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut end: xmlNodePtr = 0 as *mut xmlNode;
    let mut list: xmlNodePtr = 0 as *mut xmlNode;
    let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if nr < 0 as i32 || nr >= (unsafe { (*ctxt).incNr }) {
        return -(1 as i32);
    }
    cur = unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 };
    if cur.is_null() || (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return -(1 as i32);
    }
    list = unsafe { (**((*ctxt).incTab).offset(nr as isize)).inc };
    let fresh70 = unsafe { &mut ((**((*ctxt).incTab).offset(nr as isize)).inc) };
    *fresh70 = 0 as xmlNodePtr;
    (unsafe { (**((*ctxt).incTab).offset(nr as isize)).emptyFb = 0 as i32 });
    if !(unsafe { (*cur).parent }).is_null()
        && (unsafe { (*(*cur).parent).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
    {
        let mut nb_elem: i32 = 0 as i32;
        tmp = list;
        while !tmp.is_null() {
            if (unsafe { (*tmp).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                nb_elem += 1;
            }
            tmp = unsafe { (*tmp).next };
        }
        if nb_elem > 1 as i32 {
            xmlXIncludeErr(
                ctxt,
                unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                XML_XINCLUDE_MULTIPLE_ROOT as i32,
                b"XInclude error: would result in multiple root nodes\n\0" as *const u8
                    as *const i8,
                0 as *const xmlChar,
            );
            (unsafe { xmlFreeNodeList(list) });
            return -(1 as i32);
        }
    }
    if (unsafe { (*ctxt).parseFlags }) & XML_PARSE_NOXINCNODE as i32 != 0 {
        while !list.is_null() {
            end = list;
            list = unsafe { (*list).next };
            (unsafe { xmlAddPrevSibling(cur, end) });
        }
        (unsafe { xmlUnlinkNode(cur) });
        (unsafe { xmlFreeNode(cur) });
    } else {
        let mut child: xmlNodePtr = 0 as *mut xmlNode;
        let mut next: xmlNodePtr = 0 as *mut xmlNode;
        if (unsafe { (**((*ctxt).incTab).offset(nr as isize)).fallback }) != 0 {
            (unsafe { xmlUnsetProp(cur, b"href\0" as *const u8 as *const i8 as *mut xmlChar) });
        }
        (unsafe { (*cur).type_0 = XML_XINCLUDE_START });
        child = unsafe { (*cur).children };
        while !child.is_null() {
            next = unsafe { (*child).next };
            (unsafe { xmlUnlinkNode(child) });
            (unsafe { xmlFreeNode(child) });
            child = next;
        }
        end = unsafe { xmlNewDocNode((*cur).doc, (*cur).ns, (*cur).name, 0 as *const xmlChar) };
        if end.is_null() {
            xmlXIncludeErr(
                ctxt,
                unsafe { (**((*ctxt).incTab).offset(nr as isize)).ref_0 },
                XML_XINCLUDE_BUILD_FAILED as i32,
                b"failed to build node\n\0" as *const u8 as *const i8,
                0 as *const xmlChar,
            );
            (unsafe { xmlFreeNodeList(list) });
            return -(1 as i32);
        }
        (unsafe { (*end).type_0 = XML_XINCLUDE_END });
        (unsafe { xmlAddNextSibling(cur, end) });
        while !list.is_null() {
            cur = list;
            list = unsafe { (*list).next };
            (unsafe { xmlAddPrevSibling(end, cur) });
        }
    }
    return 0 as i32;
}
extern "C" fn xmlXIncludeTestNode(mut ctxt: xmlXIncludeCtxtPtr, mut node: xmlNodePtr) -> i32 {
    if node.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as i32;
    }
    if (unsafe { (*node).ns }).is_null() {
        return 0 as i32;
    }
    if (unsafe { xmlStrEqual(
        (*(*node).ns).href,
        b"http://www.w3.org/2003/XInclude\0" as *const u8 as *const i8 as *const xmlChar,
    ) }) != 0
        || (unsafe { xmlStrEqual(
            (*(*node).ns).href,
            b"http://www.w3.org/2001/XInclude\0" as *const u8 as *const i8 as *const xmlChar,
        ) }) != 0
    {
        if (unsafe { xmlStrEqual(
            (*(*node).ns).href,
            b"http://www.w3.org/2001/XInclude\0" as *const u8 as *const i8 as *const xmlChar,
        ) }) != 0
        {
            if (unsafe { (*ctxt).legacy }) == 0 as i32 {
                (unsafe { (*ctxt).legacy = 1 as i32 });
            }
        }
        if (unsafe { xmlStrEqual(
            (*node).name,
            b"include\0" as *const u8 as *const i8 as *const xmlChar,
        ) }) != 0
        {
            let mut child: xmlNodePtr = unsafe { (*node).children };
            let mut nb_fallback: i32 = 0 as i32;
            while !child.is_null() {
                if (unsafe { (*child).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                    && !(unsafe { (*child).ns }).is_null()
                    && ((unsafe { xmlStrEqual(
                        (*(*child).ns).href,
                        b"http://www.w3.org/2003/XInclude\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) }) != 0
                        || (unsafe { xmlStrEqual(
                            (*(*child).ns).href,
                            b"http://www.w3.org/2001/XInclude\0" as *const u8 as *const i8
                                as *const xmlChar,
                        ) }) != 0)
                {
                    if (unsafe { xmlStrEqual(
                        (*child).name,
                        b"include\0" as *const u8 as *const i8 as *const xmlChar,
                    ) }) != 0
                    {
                        xmlXIncludeErr(
                            ctxt,
                            node,
                            XML_XINCLUDE_INCLUDE_IN_INCLUDE as i32,
                            b"%s has an 'include' child\n\0" as *const u8 as *const i8,
                            b"include\0" as *const u8 as *const i8 as *const xmlChar,
                        );
                        return 0 as i32;
                    }
                    if (unsafe { xmlStrEqual(
                        (*child).name,
                        b"fallback\0" as *const u8 as *const i8 as *const xmlChar,
                    ) }) != 0
                    {
                        nb_fallback += 1;
                    }
                }
                child = unsafe { (*child).next };
            }
            if nb_fallback > 1 as i32 {
                xmlXIncludeErr(
                    ctxt,
                    node,
                    XML_XINCLUDE_FALLBACKS_IN_INCLUDE as i32,
                    b"%s has multiple fallback children\n\0" as *const u8 as *const i8,
                    b"include\0" as *const u8 as *const i8 as *const xmlChar,
                );
                return 0 as i32;
            }
            return 1 as i32;
        }
        if (unsafe { xmlStrEqual(
            (*node).name,
            b"fallback\0" as *const u8 as *const i8 as *const xmlChar,
        ) }) != 0
        {
            if (unsafe { (*node).parent }).is_null()
                || (unsafe { (*(*node).parent).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
                || (unsafe { (*(*node).parent).ns }).is_null()
                || (unsafe { xmlStrEqual(
                    (*(*(*node).parent).ns).href,
                    b"http://www.w3.org/2003/XInclude\0" as *const u8 as *const i8
                        as *const xmlChar,
                ) }) == 0
                    && (unsafe { xmlStrEqual(
                        (*(*(*node).parent).ns).href,
                        b"http://www.w3.org/2001/XInclude\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) }) == 0
                || (unsafe { xmlStrEqual(
                    (*(*node).parent).name,
                    b"include\0" as *const u8 as *const i8 as *const xmlChar,
                ) }) == 0
            {
                xmlXIncludeErr(
                    ctxt,
                    node,
                    XML_XINCLUDE_FALLBACK_NOT_IN_INCLUDE as i32,
                    b"%s is not the child of an 'include'\n\0" as *const u8 as *const i8,
                    b"fallback\0" as *const u8 as *const i8 as *const xmlChar,
                );
            }
        }
    }
    return 0 as i32;
}
extern "C" fn xmlXIncludeDoProcess(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut doc: xmlDocPtr,
    mut tree: xmlNodePtr,
    mut skipRoot: i32,
) -> i32 {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut ret: i32 = 0 as i32;
    let mut i: i32 = 0;
    let mut start: i32 = 0;
    if doc.is_null() || tree.is_null() || (unsafe { (*tree).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
    {
        return -(1 as i32);
    }
    if skipRoot != 0 && (unsafe { (*tree).children }).is_null() {
        return -(1 as i32);
    }
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if !(unsafe { (*doc).URL }).is_null() {
        ret = xmlXIncludeURLPush(ctxt, unsafe { (*doc).URL });
        if ret < 0 as i32 {
            return -(1 as i32);
        }
    }
    start = unsafe { (*ctxt).incNr };
    if skipRoot != 0 {
        cur = unsafe { (*tree).children };
    } else {
        cur = tree;
    }
    let mut current_block_21: u64;
    loop {
        if xmlXIncludeTestNode(ctxt, cur) == 1 as i32 {
            let fresh71 = unsafe { &mut ((*ctxt).incTotal) };
            *fresh71 = (*fresh71).wrapping_add(1);
            xmlXIncludePreProcessNode(ctxt, cur);
            current_block_21 = 5601891728916014340;
        } else if !(unsafe { (*cur).children }).is_null()
            && ((unsafe { (*cur).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
                || (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32)
        {
            cur = unsafe { (*cur).children };
            current_block_21 = 8236137900636309791;
        } else {
            current_block_21 = 5601891728916014340;
        }
        match current_block_21 {
            5601891728916014340 => {
                while !(cur == tree) {
                    if !(unsafe { (*cur).next }).is_null() {
                        cur = unsafe { (*cur).next };
                        break;
                    } else {
                        cur = unsafe { (*cur).parent };
                        if cur.is_null() {
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
        if !(!cur.is_null() && cur != tree) {
            break;
        }
    }
    i = start;
    while i < (unsafe { (*ctxt).incNr }) {
        xmlXIncludeLoadNode(ctxt, i);
        ret += 1;
        i += 1;
    }
    i = unsafe { (*ctxt).incBase };
    while i < (unsafe { (*ctxt).incNr }) {
        if !(unsafe { (**((*ctxt).incTab).offset(i as isize)).inc }).is_null()
            || (unsafe { (**((*ctxt).incTab).offset(i as isize)).emptyFb }) != 0 as i32
        {
            xmlXIncludeIncludeNode(ctxt, i);
        }
        i += 1;
    }
    if !(unsafe { (*doc).URL }).is_null() {
        xmlXIncludeURLPop(ctxt);
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXIncludeSetFlags(mut ctxt: xmlXIncludeCtxtPtr, mut flags: i32) -> i32 {
    if ctxt.is_null() {
        return -(1 as i32);
    }
    (unsafe { (*ctxt).parseFlags = flags });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlXIncludeProcessTreeFlagsData(
    mut tree: xmlNodePtr,
    mut flags: i32,
    mut data: *mut libc::c_void,
) -> i32 {
    let mut ctxt: xmlXIncludeCtxtPtr = 0 as *mut xmlXIncludeCtxt;
    let mut ret: i32 = 0 as i32;
    if tree.is_null()
        || (unsafe { (*tree).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
        || (unsafe { (*tree).doc }).is_null()
    {
        return -(1 as i32);
    }
    ctxt = xmlXIncludeNewContext(unsafe { (*tree).doc });
    if ctxt.is_null() {
        return -(1 as i32);
    }
    let fresh72 = unsafe { &mut ((*ctxt)._private) };
    *fresh72 = data;
    let fresh73 = unsafe { &mut ((*ctxt).base) };
    *fresh73 = unsafe { xmlStrdup((*(*tree).doc).URL as *mut xmlChar) };
    xmlXIncludeSetFlags(ctxt, flags);
    ret = xmlXIncludeDoProcess(ctxt, unsafe { (*tree).doc }, tree, 0 as i32);
    if ret >= 0 as i32 && (unsafe { (*ctxt).nbErrors }) > 0 as i32 {
        ret = -(1 as i32);
    }
    xmlXIncludeFreeContext(ctxt);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXIncludeProcessFlagsData(
    mut doc: xmlDocPtr,
    mut flags: i32,
    mut data: *mut libc::c_void,
) -> i32 {
    let mut tree: xmlNodePtr = 0 as *mut xmlNode;
    if doc.is_null() {
        return -(1 as i32);
    }
    tree = unsafe { xmlDocGetRootElement(doc as *const xmlDoc) };
    if tree.is_null() {
        return -(1 as i32);
    }
    return xmlXIncludeProcessTreeFlagsData(tree, flags, data);
}
#[no_mangle]
pub extern "C" fn xmlXIncludeProcessFlags(mut doc: xmlDocPtr, mut flags: i32) -> i32 {
    return xmlXIncludeProcessFlagsData(doc, flags, 0 as *mut libc::c_void);
}
#[no_mangle]
pub extern "C" fn xmlXIncludeProcess(mut doc: xmlDocPtr) -> i32 {
    return xmlXIncludeProcessFlags(doc, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlXIncludeProcessTreeFlags(mut tree: xmlNodePtr, mut flags: i32) -> i32 {
    let mut ctxt: xmlXIncludeCtxtPtr = 0 as *mut xmlXIncludeCtxt;
    let mut ret: i32 = 0 as i32;
    if tree.is_null()
        || (unsafe { (*tree).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
        || (unsafe { (*tree).doc }).is_null()
    {
        return -(1 as i32);
    }
    ctxt = xmlXIncludeNewContext(unsafe { (*tree).doc });
    if ctxt.is_null() {
        return -(1 as i32);
    }
    let fresh74 = unsafe { &mut ((*ctxt).base) };
    *fresh74 = unsafe { xmlNodeGetBase((*tree).doc, tree as *const xmlNode) };
    xmlXIncludeSetFlags(ctxt, flags);
    ret = xmlXIncludeDoProcess(ctxt, unsafe { (*tree).doc }, tree, 0 as i32);
    if ret >= 0 as i32 && (unsafe { (*ctxt).nbErrors }) > 0 as i32 {
        ret = -(1 as i32);
    }
    xmlXIncludeFreeContext(ctxt);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlXIncludeProcessTree(mut tree: xmlNodePtr) -> i32 {
    return xmlXIncludeProcessTreeFlags(tree, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlXIncludeProcessNode(
    mut ctxt: xmlXIncludeCtxtPtr,
    mut node: xmlNodePtr,
) -> i32 {
    let mut ret: i32 = 0 as i32;
    if node.is_null()
        || (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
        || (unsafe { (*node).doc }).is_null()
        || ctxt.is_null()
    {
        return -(1 as i32);
    }
    ret = xmlXIncludeDoProcess(ctxt, unsafe { (*node).doc }, node, 0 as i32);
    if ret >= 0 as i32 && (unsafe { (*ctxt).nbErrors }) > 0 as i32 {
        ret = -(1 as i32);
    }
    return ret;
}
