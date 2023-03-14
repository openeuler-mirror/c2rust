use ::libc;
extern "C" {
    pub type _xmlBuf;
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlStartTag;
    pub type _xmlAutomataState;
    pub type _xmlAutomata;
    pub type _xmlValidState;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn __xmlGenericErrorContext() -> *mut *mut libc::c_void;
    fn __xmlGenericError() -> *mut xmlGenericErrorFunc;
    fn xmlParserValidityError(ctx: *mut libc::c_void, msg: *const libc::c_char, _: ...);
    fn xmlParserValidityWarning(
        ctx: *mut libc::c_void,
        msg: *const libc::c_char,
        _: ...
    );
    fn xmlSAX2GetPublicId(ctx: *mut libc::c_void) -> *const xmlChar;
    fn xmlSAX2GetSystemId(ctx: *mut libc::c_void) -> *const xmlChar;
    fn xmlSAX2GetLineNumber(ctx: *mut libc::c_void) -> libc::c_int;
    fn xmlSAX2GetColumnNumber(ctx: *mut libc::c_void) -> libc::c_int;
    fn xmlSAX2IsStandalone(ctx: *mut libc::c_void) -> libc::c_int;
    fn xmlSAX2HasInternalSubset(ctx: *mut libc::c_void) -> libc::c_int;
    fn xmlSAX2HasExternalSubset(ctx: *mut libc::c_void) -> libc::c_int;
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
    fn xmlSAX2GetParameterEntity(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
    ) -> xmlEntityPtr;
    fn xmlSAX2ResolveEntity(
        ctx: *mut libc::c_void,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
    ) -> xmlParserInputPtr;
    fn xmlSAX2EntityDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: libc::c_int,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
        content: *mut xmlChar,
    );
    fn xmlSAX2AttributeDecl(
        ctx: *mut libc::c_void,
        elem: *const xmlChar,
        fullname: *const xmlChar,
        type_0: libc::c_int,
        def: libc::c_int,
        defaultValue: *const xmlChar,
        tree: xmlEnumerationPtr,
    );
    fn xmlSAX2ElementDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: libc::c_int,
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
    fn xmlSAX2Characters(ctx: *mut libc::c_void, ch: *const xmlChar, len: libc::c_int);
    fn xmlSAX2ProcessingInstruction(
        ctx: *mut libc::c_void,
        target: *const xmlChar,
        data: *const xmlChar,
    );
    fn xmlSAX2Comment(ctx: *mut libc::c_void, value: *const xmlChar);
    fn xmlSAX2CDataBlock(
        ctx: *mut libc::c_void,
        value: *const xmlChar,
        len: libc::c_int,
    );
}
pub type xmlChar = libc::c_uchar;
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
pub type xmlParserInputBuffer = _xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = *mut xmlParserInputBuffer;
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
pub type xmlParserInput = _xmlParserInput;
pub type xmlParserInputPtr = *mut xmlParserInput;
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
pub type xmlParserCtxt = _xmlParserCtxt;
pub type xmlParserCtxtPtr = *mut xmlParserCtxt;
pub type xmlSAXHandler = _xmlSAXHandler;
pub type xmlSAXHandlerPtr = *mut xmlSAXHandler;
pub type xmlNsPtr = *mut xmlNs;
pub type xmlGenericErrorFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type htmlParserCtxtPtr = xmlParserCtxtPtr;
#[no_mangle]
pub unsafe extern "C" fn htmlDecodeEntities(
    mut ctxt: htmlParserCtxtPtr,
    mut len: libc::c_int,
    mut end: xmlChar,
    mut end2: xmlChar,
    mut end3: xmlChar,
) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"htmlDecodeEntities() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlInitializePredefinedEntities() {}
#[no_mangle]
pub unsafe extern "C" fn xmlCleanupPredefinedEntities() {}
static mut xmlFeaturesList: [*const libc::c_char; 42] = [
    b"validate\0" as *const u8 as *const libc::c_char,
    b"load subset\0" as *const u8 as *const libc::c_char,
    b"keep blanks\0" as *const u8 as *const libc::c_char,
    b"disable SAX\0" as *const u8 as *const libc::c_char,
    b"fetch external entities\0" as *const u8 as *const libc::c_char,
    b"substitute entities\0" as *const u8 as *const libc::c_char,
    b"gather line info\0" as *const u8 as *const libc::c_char,
    b"user data\0" as *const u8 as *const libc::c_char,
    b"is html\0" as *const u8 as *const libc::c_char,
    b"is standalone\0" as *const u8 as *const libc::c_char,
    b"stop parser\0" as *const u8 as *const libc::c_char,
    b"document\0" as *const u8 as *const libc::c_char,
    b"is well formed\0" as *const u8 as *const libc::c_char,
    b"is valid\0" as *const u8 as *const libc::c_char,
    b"SAX block\0" as *const u8 as *const libc::c_char,
    b"SAX function internalSubset\0" as *const u8 as *const libc::c_char,
    b"SAX function isStandalone\0" as *const u8 as *const libc::c_char,
    b"SAX function hasInternalSubset\0" as *const u8 as *const libc::c_char,
    b"SAX function hasExternalSubset\0" as *const u8 as *const libc::c_char,
    b"SAX function resolveEntity\0" as *const u8 as *const libc::c_char,
    b"SAX function getEntity\0" as *const u8 as *const libc::c_char,
    b"SAX function entityDecl\0" as *const u8 as *const libc::c_char,
    b"SAX function notationDecl\0" as *const u8 as *const libc::c_char,
    b"SAX function attributeDecl\0" as *const u8 as *const libc::c_char,
    b"SAX function elementDecl\0" as *const u8 as *const libc::c_char,
    b"SAX function unparsedEntityDecl\0" as *const u8 as *const libc::c_char,
    b"SAX function setDocumentLocator\0" as *const u8 as *const libc::c_char,
    b"SAX function startDocument\0" as *const u8 as *const libc::c_char,
    b"SAX function endDocument\0" as *const u8 as *const libc::c_char,
    b"SAX function startElement\0" as *const u8 as *const libc::c_char,
    b"SAX function endElement\0" as *const u8 as *const libc::c_char,
    b"SAX function reference\0" as *const u8 as *const libc::c_char,
    b"SAX function characters\0" as *const u8 as *const libc::c_char,
    b"SAX function ignorableWhitespace\0" as *const u8 as *const libc::c_char,
    b"SAX function processingInstruction\0" as *const u8 as *const libc::c_char,
    b"SAX function comment\0" as *const u8 as *const libc::c_char,
    b"SAX function warning\0" as *const u8 as *const libc::c_char,
    b"SAX function error\0" as *const u8 as *const libc::c_char,
    b"SAX function fatalError\0" as *const u8 as *const libc::c_char,
    b"SAX function getParameterEntity\0" as *const u8 as *const libc::c_char,
    b"SAX function cdataBlock\0" as *const u8 as *const libc::c_char,
    b"SAX function externalSubset\0" as *const u8 as *const libc::c_char,
];
#[no_mangle]
pub unsafe extern "C" fn xmlGetFeaturesList(
    mut len: *mut libc::c_int,
    mut result: *mut *const libc::c_char,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    ret = (::std::mem::size_of::<[*const libc::c_char; 42]>() as libc::c_ulong)
        .wrapping_div(::std::mem::size_of::<*const libc::c_char>() as libc::c_ulong)
        as libc::c_int;
    if len.is_null() || result.is_null() {
        return ret;
    }
    if *len < 0 as libc::c_int || *len >= 1000 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if *len > ret {
        *len = ret;
    }
    i = 0 as libc::c_int;
    while i < *len {
        let ref mut fresh0 = *result.offset(i as isize);
        *fresh0 = xmlFeaturesList[i as usize];
        i += 1;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetFeature(
    mut ctxt: xmlParserCtxtPtr,
    mut name: *const libc::c_char,
    mut result: *mut libc::c_void,
) -> libc::c_int {
    if ctxt.is_null() || name.is_null() || result.is_null() {
        return -(1 as libc::c_int);
    }
    if strcmp(name, b"validate\0" as *const u8 as *const libc::c_char) == 0 {
        *(result as *mut libc::c_int) = (*ctxt).validate;
    } else if strcmp(name, b"keep blanks\0" as *const u8 as *const libc::c_char) == 0 {
        *(result as *mut libc::c_int) = (*ctxt).keepBlanks;
    } else if strcmp(name, b"disable SAX\0" as *const u8 as *const libc::c_char) == 0 {
        *(result as *mut libc::c_int) = (*ctxt).disableSAX;
    } else if strcmp(
            name,
            b"fetch external entities\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        *(result as *mut libc::c_int) = (*ctxt).loadsubset;
    } else if strcmp(name, b"substitute entities\0" as *const u8 as *const libc::c_char)
            == 0
        {
        *(result as *mut libc::c_int) = (*ctxt).replaceEntities;
    } else if strcmp(name, b"gather line info\0" as *const u8 as *const libc::c_char)
            == 0
        {
        *(result as *mut libc::c_int) = (*ctxt).record_info;
    } else if strcmp(name, b"user data\0" as *const u8 as *const libc::c_char) == 0 {
        let ref mut fresh1 = *(result as *mut *mut libc::c_void);
        *fresh1 = (*ctxt).userData;
    } else if strcmp(name, b"is html\0" as *const u8 as *const libc::c_char) == 0 {
        *(result as *mut libc::c_int) = (*ctxt).html;
    } else if strcmp(name, b"is standalone\0" as *const u8 as *const libc::c_char) == 0 {
        *(result as *mut libc::c_int) = (*ctxt).standalone;
    } else if strcmp(name, b"document\0" as *const u8 as *const libc::c_char) == 0 {
        let ref mut fresh2 = *(result as *mut xmlDocPtr);
        *fresh2 = (*ctxt).myDoc;
    } else if strcmp(name, b"is well formed\0" as *const u8 as *const libc::c_char) == 0
        {
        *(result as *mut libc::c_int) = (*ctxt).wellFormed;
    } else if strcmp(name, b"is valid\0" as *const u8 as *const libc::c_char) == 0 {
        *(result as *mut libc::c_int) = (*ctxt).valid;
    } else if strcmp(name, b"SAX block\0" as *const u8 as *const libc::c_char) == 0 {
        let ref mut fresh3 = *(result as *mut xmlSAXHandlerPtr);
        *fresh3 = (*ctxt).sax;
    } else if strcmp(
            name,
            b"SAX function internalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh4 = *(result as *mut internalSubsetSAXFunc);
        *fresh4 = (*(*ctxt).sax).internalSubset;
    } else if strcmp(
            name,
            b"SAX function isStandalone\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh5 = *(result as *mut isStandaloneSAXFunc);
        *fresh5 = (*(*ctxt).sax).isStandalone;
    } else if strcmp(
            name,
            b"SAX function hasInternalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh6 = *(result as *mut hasInternalSubsetSAXFunc);
        *fresh6 = (*(*ctxt).sax).hasInternalSubset;
    } else if strcmp(
            name,
            b"SAX function hasExternalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh7 = *(result as *mut hasExternalSubsetSAXFunc);
        *fresh7 = (*(*ctxt).sax).hasExternalSubset;
    } else if strcmp(
            name,
            b"SAX function resolveEntity\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh8 = *(result as *mut resolveEntitySAXFunc);
        *fresh8 = (*(*ctxt).sax).resolveEntity;
    } else if strcmp(
            name,
            b"SAX function getEntity\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh9 = *(result as *mut getEntitySAXFunc);
        *fresh9 = (*(*ctxt).sax).getEntity;
    } else if strcmp(
            name,
            b"SAX function entityDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh10 = *(result as *mut entityDeclSAXFunc);
        *fresh10 = (*(*ctxt).sax).entityDecl;
    } else if strcmp(
            name,
            b"SAX function notationDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh11 = *(result as *mut notationDeclSAXFunc);
        *fresh11 = (*(*ctxt).sax).notationDecl;
    } else if strcmp(
            name,
            b"SAX function attributeDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh12 = *(result as *mut attributeDeclSAXFunc);
        *fresh12 = (*(*ctxt).sax).attributeDecl;
    } else if strcmp(
            name,
            b"SAX function elementDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh13 = *(result as *mut elementDeclSAXFunc);
        *fresh13 = (*(*ctxt).sax).elementDecl;
    } else if strcmp(
            name,
            b"SAX function unparsedEntityDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh14 = *(result as *mut unparsedEntityDeclSAXFunc);
        *fresh14 = (*(*ctxt).sax).unparsedEntityDecl;
    } else if strcmp(
            name,
            b"SAX function setDocumentLocator\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh15 = *(result as *mut setDocumentLocatorSAXFunc);
        *fresh15 = (*(*ctxt).sax).setDocumentLocator;
    } else if strcmp(
            name,
            b"SAX function startDocument\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh16 = *(result as *mut startDocumentSAXFunc);
        *fresh16 = (*(*ctxt).sax).startDocument;
    } else if strcmp(
            name,
            b"SAX function endDocument\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh17 = *(result as *mut endDocumentSAXFunc);
        *fresh17 = (*(*ctxt).sax).endDocument;
    } else if strcmp(
            name,
            b"SAX function startElement\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh18 = *(result as *mut startElementSAXFunc);
        *fresh18 = (*(*ctxt).sax).startElement;
    } else if strcmp(
            name,
            b"SAX function endElement\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh19 = *(result as *mut endElementSAXFunc);
        *fresh19 = (*(*ctxt).sax).endElement;
    } else if strcmp(
            name,
            b"SAX function reference\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh20 = *(result as *mut referenceSAXFunc);
        *fresh20 = (*(*ctxt).sax).reference;
    } else if strcmp(
            name,
            b"SAX function characters\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh21 = *(result as *mut charactersSAXFunc);
        *fresh21 = (*(*ctxt).sax).characters;
    } else if strcmp(
            name,
            b"SAX function ignorableWhitespace\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh22 = *(result as *mut ignorableWhitespaceSAXFunc);
        *fresh22 = (*(*ctxt).sax).ignorableWhitespace;
    } else if strcmp(
            name,
            b"SAX function processingInstruction\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh23 = *(result as *mut processingInstructionSAXFunc);
        *fresh23 = (*(*ctxt).sax).processingInstruction;
    } else if strcmp(name, b"SAX function comment\0" as *const u8 as *const libc::c_char)
            == 0
        {
        let ref mut fresh24 = *(result as *mut commentSAXFunc);
        *fresh24 = (*(*ctxt).sax).comment;
    } else if strcmp(name, b"SAX function warning\0" as *const u8 as *const libc::c_char)
            == 0
        {
        let ref mut fresh25 = *(result as *mut warningSAXFunc);
        *fresh25 = (*(*ctxt).sax).warning;
    } else if strcmp(name, b"SAX function error\0" as *const u8 as *const libc::c_char)
            == 0
        {
        let ref mut fresh26 = *(result as *mut errorSAXFunc);
        *fresh26 = (*(*ctxt).sax).error;
    } else if strcmp(
            name,
            b"SAX function fatalError\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh27 = *(result as *mut fatalErrorSAXFunc);
        *fresh27 = (*(*ctxt).sax).fatalError;
    } else if strcmp(
            name,
            b"SAX function getParameterEntity\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh28 = *(result as *mut getParameterEntitySAXFunc);
        *fresh28 = (*(*ctxt).sax).getParameterEntity;
    } else if strcmp(
            name,
            b"SAX function cdataBlock\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh29 = *(result as *mut cdataBlockSAXFunc);
        *fresh29 = (*(*ctxt).sax).cdataBlock;
    } else if strcmp(
            name,
            b"SAX function externalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh30 = *(result as *mut externalSubsetSAXFunc);
        *fresh30 = (*(*ctxt).sax).externalSubset;
    } else {
        return -(1 as libc::c_int)
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetFeature(
    mut ctxt: xmlParserCtxtPtr,
    mut name: *const libc::c_char,
    mut value: *mut libc::c_void,
) -> libc::c_int {
    if ctxt.is_null() || name.is_null() || value.is_null() {
        return -(1 as libc::c_int);
    }
    if strcmp(name, b"validate\0" as *const u8 as *const libc::c_char) == 0 {
        let mut newvalidate: libc::c_int = *(value as *mut libc::c_int);
        if (*ctxt).validate == 0 && newvalidate != 0 as libc::c_int {
            if ((*ctxt).vctxt.warning).is_none() {
                let ref mut fresh31 = (*ctxt).vctxt.warning;
                *fresh31 = Some(
                    xmlParserValidityWarning
                        as unsafe extern "C" fn(
                            *mut libc::c_void,
                            *const libc::c_char,
                            ...
                        ) -> (),
                );
            }
            if ((*ctxt).vctxt.error).is_none() {
                let ref mut fresh32 = (*ctxt).vctxt.error;
                *fresh32 = Some(
                    xmlParserValidityError
                        as unsafe extern "C" fn(
                            *mut libc::c_void,
                            *const libc::c_char,
                            ...
                        ) -> (),
                );
            }
            (*ctxt).vctxt.nodeMax = 0 as libc::c_int;
        }
        (*ctxt).validate = newvalidate;
    } else if strcmp(name, b"keep blanks\0" as *const u8 as *const libc::c_char) == 0 {
        (*ctxt).keepBlanks = *(value as *mut libc::c_int);
    } else if strcmp(name, b"disable SAX\0" as *const u8 as *const libc::c_char) == 0 {
        (*ctxt).disableSAX = *(value as *mut libc::c_int);
    } else if strcmp(
            name,
            b"fetch external entities\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        (*ctxt).loadsubset = *(value as *mut libc::c_int);
    } else if strcmp(name, b"substitute entities\0" as *const u8 as *const libc::c_char)
            == 0
        {
        (*ctxt).replaceEntities = *(value as *mut libc::c_int);
    } else if strcmp(name, b"gather line info\0" as *const u8 as *const libc::c_char)
            == 0
        {
        (*ctxt).record_info = *(value as *mut libc::c_int);
    } else if strcmp(name, b"user data\0" as *const u8 as *const libc::c_char) == 0 {
        let ref mut fresh33 = (*ctxt).userData;
        *fresh33 = *(value as *mut *mut libc::c_void);
    } else if strcmp(name, b"is html\0" as *const u8 as *const libc::c_char) == 0 {
        (*ctxt).html = *(value as *mut libc::c_int);
    } else if strcmp(name, b"is standalone\0" as *const u8 as *const libc::c_char) == 0 {
        (*ctxt).standalone = *(value as *mut libc::c_int);
    } else if strcmp(name, b"document\0" as *const u8 as *const libc::c_char) == 0 {
        let ref mut fresh34 = (*ctxt).myDoc;
        *fresh34 = *(value as *mut xmlDocPtr);
    } else if strcmp(name, b"is well formed\0" as *const u8 as *const libc::c_char) == 0
        {
        (*ctxt).wellFormed = *(value as *mut libc::c_int);
    } else if strcmp(name, b"is valid\0" as *const u8 as *const libc::c_char) == 0 {
        (*ctxt).valid = *(value as *mut libc::c_int);
    } else if strcmp(name, b"SAX block\0" as *const u8 as *const libc::c_char) == 0 {
        let ref mut fresh35 = (*ctxt).sax;
        *fresh35 = *(value as *mut xmlSAXHandlerPtr);
    } else if strcmp(
            name,
            b"SAX function internalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh36 = (*(*ctxt).sax).internalSubset;
        *fresh36 = *(value as *mut internalSubsetSAXFunc);
    } else if strcmp(
            name,
            b"SAX function isStandalone\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh37 = (*(*ctxt).sax).isStandalone;
        *fresh37 = *(value as *mut isStandaloneSAXFunc);
    } else if strcmp(
            name,
            b"SAX function hasInternalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh38 = (*(*ctxt).sax).hasInternalSubset;
        *fresh38 = *(value as *mut hasInternalSubsetSAXFunc);
    } else if strcmp(
            name,
            b"SAX function hasExternalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh39 = (*(*ctxt).sax).hasExternalSubset;
        *fresh39 = *(value as *mut hasExternalSubsetSAXFunc);
    } else if strcmp(
            name,
            b"SAX function resolveEntity\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh40 = (*(*ctxt).sax).resolveEntity;
        *fresh40 = *(value as *mut resolveEntitySAXFunc);
    } else if strcmp(
            name,
            b"SAX function getEntity\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh41 = (*(*ctxt).sax).getEntity;
        *fresh41 = *(value as *mut getEntitySAXFunc);
    } else if strcmp(
            name,
            b"SAX function entityDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh42 = (*(*ctxt).sax).entityDecl;
        *fresh42 = *(value as *mut entityDeclSAXFunc);
    } else if strcmp(
            name,
            b"SAX function notationDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh43 = (*(*ctxt).sax).notationDecl;
        *fresh43 = *(value as *mut notationDeclSAXFunc);
    } else if strcmp(
            name,
            b"SAX function attributeDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh44 = (*(*ctxt).sax).attributeDecl;
        *fresh44 = *(value as *mut attributeDeclSAXFunc);
    } else if strcmp(
            name,
            b"SAX function elementDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh45 = (*(*ctxt).sax).elementDecl;
        *fresh45 = *(value as *mut elementDeclSAXFunc);
    } else if strcmp(
            name,
            b"SAX function unparsedEntityDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh46 = (*(*ctxt).sax).unparsedEntityDecl;
        *fresh46 = *(value as *mut unparsedEntityDeclSAXFunc);
    } else if strcmp(
            name,
            b"SAX function setDocumentLocator\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh47 = (*(*ctxt).sax).setDocumentLocator;
        *fresh47 = *(value as *mut setDocumentLocatorSAXFunc);
    } else if strcmp(
            name,
            b"SAX function startDocument\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh48 = (*(*ctxt).sax).startDocument;
        *fresh48 = *(value as *mut startDocumentSAXFunc);
    } else if strcmp(
            name,
            b"SAX function endDocument\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh49 = (*(*ctxt).sax).endDocument;
        *fresh49 = *(value as *mut endDocumentSAXFunc);
    } else if strcmp(
            name,
            b"SAX function startElement\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh50 = (*(*ctxt).sax).startElement;
        *fresh50 = *(value as *mut startElementSAXFunc);
    } else if strcmp(
            name,
            b"SAX function endElement\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh51 = (*(*ctxt).sax).endElement;
        *fresh51 = *(value as *mut endElementSAXFunc);
    } else if strcmp(
            name,
            b"SAX function reference\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh52 = (*(*ctxt).sax).reference;
        *fresh52 = *(value as *mut referenceSAXFunc);
    } else if strcmp(
            name,
            b"SAX function characters\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh53 = (*(*ctxt).sax).characters;
        *fresh53 = *(value as *mut charactersSAXFunc);
    } else if strcmp(
            name,
            b"SAX function ignorableWhitespace\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh54 = (*(*ctxt).sax).ignorableWhitespace;
        *fresh54 = *(value as *mut ignorableWhitespaceSAXFunc);
    } else if strcmp(
            name,
            b"SAX function processingInstruction\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh55 = (*(*ctxt).sax).processingInstruction;
        *fresh55 = *(value as *mut processingInstructionSAXFunc);
    } else if strcmp(name, b"SAX function comment\0" as *const u8 as *const libc::c_char)
            == 0
        {
        let ref mut fresh56 = (*(*ctxt).sax).comment;
        *fresh56 = *(value as *mut commentSAXFunc);
    } else if strcmp(name, b"SAX function warning\0" as *const u8 as *const libc::c_char)
            == 0
        {
        let ref mut fresh57 = (*(*ctxt).sax).warning;
        *fresh57 = *(value as *mut warningSAXFunc);
    } else if strcmp(name, b"SAX function error\0" as *const u8 as *const libc::c_char)
            == 0
        {
        let ref mut fresh58 = (*(*ctxt).sax).error;
        *fresh58 = *(value as *mut errorSAXFunc);
    } else if strcmp(
            name,
            b"SAX function fatalError\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh59 = (*(*ctxt).sax).fatalError;
        *fresh59 = *(value as *mut fatalErrorSAXFunc);
    } else if strcmp(
            name,
            b"SAX function getParameterEntity\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh60 = (*(*ctxt).sax).getParameterEntity;
        *fresh60 = *(value as *mut getParameterEntitySAXFunc);
    } else if strcmp(
            name,
            b"SAX function cdataBlock\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh61 = (*(*ctxt).sax).cdataBlock;
        *fresh61 = *(value as *mut cdataBlockSAXFunc);
    } else if strcmp(
            name,
            b"SAX function externalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh62 = (*(*ctxt).sax).externalSubset;
        *fresh62 = *(value as *mut externalSubsetSAXFunc);
    } else {
        return -(1 as libc::c_int)
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDecodeEntities(
    mut ctxt: xmlParserCtxtPtr,
    mut len: libc::c_int,
    mut what: libc::c_int,
    mut end: xmlChar,
    mut end2: xmlChar,
    mut end3: xmlChar,
) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlDecodeEntities() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNamespaceParseNCName(
    mut ctxt: xmlParserCtxtPtr,
) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlNamespaceParseNCName() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNamespaceParseQName(
    mut ctxt: xmlParserCtxtPtr,
    mut prefix: *mut *mut xmlChar,
) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlNamespaceParseQName() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNamespaceParseNSDef(
    mut ctxt: xmlParserCtxtPtr,
) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlNamespaceParseNSDef() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseQuotedString(
    mut ctxt: xmlParserCtxtPtr,
) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlParseQuotedString() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseNamespace(mut ctxt: xmlParserCtxtPtr) {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlParseNamespace() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlScanName(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlScanName() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserHandleReference(mut ctxt: xmlParserCtxtPtr) {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlParserHandleReference() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlHandleEntity(
    mut ctxt: xmlParserCtxtPtr,
    mut entity: xmlEntityPtr,
) {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlHandleEntity() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewGlobalNs(
    mut doc: xmlDocPtr,
    mut href: *const xmlChar,
    mut prefix: *const xmlChar,
) -> xmlNsPtr {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlNewGlobalNs() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as xmlNsPtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUpgradeOldNs(mut doc: xmlDocPtr) {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlUpgradeOldNs() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlEncodeEntities(
    mut doc: xmlDocPtr,
    mut input: *const xmlChar,
) -> *const xmlChar {
    static mut warning: libc::c_int = 1 as libc::c_int;
    if warning != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Deprecated API xmlEncodeEntities() used\n\0" as *const u8
                as *const libc::c_char,
        );
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"   change code to use xmlEncodeEntitiesReentrant()\n\0" as *const u8
                as *const libc::c_char,
        );
        warning = 0 as libc::c_int;
    }
    return 0 as *const xmlChar;
}
static mut deprecated_v1_msg: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn getPublicId(mut ctx: *mut libc::c_void) -> *const xmlChar {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getPublicId\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2GetPublicId(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn getSystemId(mut ctx: *mut libc::c_void) -> *const xmlChar {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getSystemId\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2GetSystemId(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn getLineNumber(mut ctx: *mut libc::c_void) -> libc::c_int {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getLineNumber\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2GetLineNumber(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn getColumnNumber(mut ctx: *mut libc::c_void) -> libc::c_int {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getColumnNumber\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2GetColumnNumber(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn isStandalone(mut ctx: *mut libc::c_void) -> libc::c_int {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"isStandalone\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2IsStandalone(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn hasInternalSubset(mut ctx: *mut libc::c_void) -> libc::c_int {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"hasInternalSubset\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2HasInternalSubset(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn hasExternalSubset(mut ctx: *mut libc::c_void) -> libc::c_int {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"hasExternalSubset\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2HasExternalSubset(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn internalSubset(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"internalSubset\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2InternalSubset(ctx, name, ExternalID, SystemID);
}
#[no_mangle]
pub unsafe extern "C" fn externalSubset(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"externalSubset\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2ExternalSubset(ctx, name, ExternalID, SystemID);
}
#[no_mangle]
pub unsafe extern "C" fn resolveEntity(
    mut ctx: *mut libc::c_void,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
) -> xmlParserInputPtr {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"resolveEntity\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2ResolveEntity(ctx, publicId, systemId);
}
#[no_mangle]
pub unsafe extern "C" fn getEntity(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) -> xmlEntityPtr {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getEntity\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2GetEntity(ctx, name);
}
#[no_mangle]
pub unsafe extern "C" fn getParameterEntity(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) -> xmlEntityPtr {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getParameterEntity\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2GetParameterEntity(ctx, name);
}
#[no_mangle]
pub unsafe extern "C" fn entityDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut type_0: libc::c_int,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
    mut content: *mut xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"entityDecl\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2EntityDecl(ctx, name, type_0, publicId, systemId, content);
}
#[no_mangle]
pub unsafe extern "C" fn attributeDecl(
    mut ctx: *mut libc::c_void,
    mut elem: *const xmlChar,
    mut fullname: *const xmlChar,
    mut type_0: libc::c_int,
    mut def: libc::c_int,
    mut defaultValue: *const xmlChar,
    mut tree: xmlEnumerationPtr,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"attributeDecl\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2AttributeDecl(ctx, elem, fullname, type_0, def, defaultValue, tree);
}
#[no_mangle]
pub unsafe extern "C" fn elementDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut type_0: libc::c_int,
    mut content: xmlElementContentPtr,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"elementDecl\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2ElementDecl(ctx, name, type_0, content);
}
#[no_mangle]
pub unsafe extern "C" fn notationDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"notationDecl\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2NotationDecl(ctx, name, publicId, systemId);
}
#[no_mangle]
pub unsafe extern "C" fn unparsedEntityDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
    mut notationName: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"unparsedEntityDecl\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2UnparsedEntityDecl(ctx, name, publicId, systemId, notationName);
}
#[no_mangle]
pub unsafe extern "C" fn setDocumentLocator(
    mut ctx: *mut libc::c_void,
    mut loc: xmlSAXLocatorPtr,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"setDocumentLocator\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
}
#[no_mangle]
pub unsafe extern "C" fn startDocument(mut ctx: *mut libc::c_void) {
    xmlSAX2StartDocument(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn endDocument(mut ctx: *mut libc::c_void) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"endDocument\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2EndDocument(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn attribute(
    mut ctx: *mut libc::c_void,
    mut fullname: *const xmlChar,
    mut value: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"attribute\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
}
#[no_mangle]
pub unsafe extern "C" fn startElement(
    mut ctx: *mut libc::c_void,
    mut fullname: *const xmlChar,
    mut atts: *mut *const xmlChar,
) {
    xmlSAX2StartElement(ctx, fullname, atts);
}
#[no_mangle]
pub unsafe extern "C" fn endElement(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"endElement\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2EndElement(ctx, name);
}
#[no_mangle]
pub unsafe extern "C" fn reference(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"reference\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2Reference(ctx, name);
}
#[no_mangle]
pub unsafe extern "C" fn characters(
    mut ctx: *mut libc::c_void,
    mut ch: *const xmlChar,
    mut len: libc::c_int,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"characters\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2Characters(ctx, ch, len);
}
#[no_mangle]
pub unsafe extern "C" fn ignorableWhitespace(
    mut ctx: *mut libc::c_void,
    mut ch: *const xmlChar,
    mut len: libc::c_int,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"ignorableWhitespace\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
}
#[no_mangle]
pub unsafe extern "C" fn processingInstruction(
    mut ctx: *mut libc::c_void,
    mut target: *const xmlChar,
    mut data: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"processingInstruction\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2ProcessingInstruction(ctx, target, data);
}
#[no_mangle]
pub unsafe extern "C" fn globalNamespace(
    mut ctx: *mut libc::c_void,
    mut href: *const xmlChar,
    mut prefix: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"globalNamespace\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
}
#[no_mangle]
pub unsafe extern "C" fn setNamespace(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"setNamespace\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
}
#[no_mangle]
pub unsafe extern "C" fn getNamespace(mut ctx: *mut libc::c_void) -> xmlNsPtr {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getNamespace\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return 0 as xmlNsPtr;
}
#[no_mangle]
pub unsafe extern "C" fn checkNamespace(
    mut ctx: *mut libc::c_void,
    mut namespace: *mut xmlChar,
) -> libc::c_int {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"checkNamespace\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn namespaceDecl(
    mut ctx: *mut libc::c_void,
    mut href: *const xmlChar,
    mut prefix: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"namespaceDecl\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
}
#[no_mangle]
pub unsafe extern "C" fn comment(mut ctx: *mut libc::c_void, mut value: *const xmlChar) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"comment\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2Comment(ctx, value);
}
#[no_mangle]
pub unsafe extern "C" fn cdataBlock(
    mut ctx: *mut libc::c_void,
    mut value: *const xmlChar,
    mut len: libc::c_int,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"cdataBlock\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2CDataBlock(ctx, value, len);
}
