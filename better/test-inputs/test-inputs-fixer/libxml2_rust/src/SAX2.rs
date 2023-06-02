use :: libc;
extern "C" {
    pub type _xmlBuf;
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlStartTag;
    pub type _xmlAutomataState;
    pub type _xmlAutomata;
    pub type _xmlValidState;
    pub type _xmlRegexp;
    fn xmlStrcat(cur: *mut xmlChar, add: *const xmlChar) -> *mut xmlChar;
    fn xmlStrlen(str: *const xmlChar) -> i32;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrndup(cur: *const xmlChar, len: i32) -> *mut xmlChar;
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    static mut __xmlRegisterCallbacks: i32;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn xmlValidateNCName(value: *const xmlChar, space: i32) -> i32;
    fn xmlBuildQName(
        ncname: *const xmlChar,
        prefix: *const xmlChar,
        memory: *mut xmlChar,
        len: i32,
    ) -> *mut xmlChar;
    fn xmlCreateIntSubset(
        doc: xmlDocPtr,
        name: *const xmlChar,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    ) -> xmlDtdPtr;
    fn xmlNewDtd(
        doc: xmlDocPtr,
        name: *const xmlChar,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    ) -> xmlDtdPtr;
    fn xmlGetIntSubset(doc: *const xmlDoc) -> xmlDtdPtr;
    fn xmlFreeDtd(cur: xmlDtdPtr);
    fn xmlNewNs(node: xmlNodePtr, href: *const xmlChar, prefix: *const xmlChar) -> xmlNsPtr;
    fn xmlNewDoc(version: *const xmlChar) -> xmlDocPtr;
    fn xmlNewNsProp(
        node: xmlNodePtr,
        ns: xmlNsPtr,
        name: *const xmlChar,
        value: *const xmlChar,
    ) -> xmlAttrPtr;
    fn xmlNewNsPropEatName(
        node: xmlNodePtr,
        ns: xmlNsPtr,
        name: *mut xmlChar,
        value: *const xmlChar,
    ) -> xmlAttrPtr;
    fn xmlNewDocNode(
        doc: xmlDocPtr,
        ns: xmlNsPtr,
        name: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlNodePtr;
    fn xmlNewDocNodeEatName(
        doc: xmlDocPtr,
        ns: xmlNsPtr,
        name: *mut xmlChar,
        content: *const xmlChar,
    ) -> xmlNodePtr;
    fn xmlNewDocText(doc: *const xmlDoc, content: *const xmlChar) -> xmlNodePtr;
    fn xmlNewDocPI(doc: xmlDocPtr, name: *const xmlChar, content: *const xmlChar) -> xmlNodePtr;
    fn xmlNewDocComment(doc: xmlDocPtr, content: *const xmlChar) -> xmlNodePtr;
    fn xmlNewCDataBlock(doc: xmlDocPtr, content: *const xmlChar, len: i32) -> xmlNodePtr;
    fn xmlNewCharRef(doc: xmlDocPtr, name: *const xmlChar) -> xmlNodePtr;
    fn xmlNewReference(doc: *const xmlDoc, name: *const xmlChar) -> xmlNodePtr;
    fn xmlAddChild(parent: xmlNodePtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlAddSibling(cur: xmlNodePtr, elem: xmlNodePtr) -> xmlNodePtr;
    fn xmlUnlinkNode(cur: xmlNodePtr);
    fn xmlTextConcat(node: xmlNodePtr, content: *const xmlChar, len: i32) -> i32;
    fn xmlFreeNode(cur: xmlNodePtr);
    fn xmlSearchNs(doc: xmlDocPtr, node: xmlNodePtr, nameSpace: *const xmlChar) -> xmlNsPtr;
    fn xmlSetNs(node: xmlNodePtr, ns: xmlNsPtr);
    fn xmlStringGetNodeList(doc: *const xmlDoc, value: *const xmlChar) -> xmlNodePtr;
    fn xmlStringLenGetNodeList(doc: *const xmlDoc, value: *const xmlChar, len: i32) -> xmlNodePtr;
    fn xmlDictOwns(dict: xmlDictPtr, str: *const xmlChar) -> i32;
    fn xmlDictQLookup(
        dict: xmlDictPtr,
        prefix: *const xmlChar,
        name: *const xmlChar,
    ) -> *const xmlChar;
    fn xmlDictLookup(dict: xmlDictPtr, name: *const xmlChar, len: i32) -> *const xmlChar;
    fn xmlDictReference(dict: xmlDictPtr) -> i32;
    fn xmlParserError(ctx: *mut libc::c_void, msg: *const i8, _: ...);
    fn xmlParserWarning(ctx: *mut libc::c_void, msg: *const i8, _: ...);
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
    fn xmlAddNotationDecl(
        ctxt: xmlValidCtxtPtr,
        dtd: xmlDtdPtr,
        name: *const xmlChar,
        PublicID: *const xmlChar,
        SystemID: *const xmlChar,
    ) -> xmlNotationPtr;
    fn xmlAddElementDecl(
        ctxt: xmlValidCtxtPtr,
        dtd: xmlDtdPtr,
        name: *const xmlChar,
        type_0: xmlElementTypeVal,
        content: xmlElementContentPtr,
    ) -> xmlElementPtr;
    fn xmlFreeEnumeration(cur: xmlEnumerationPtr);
    fn xmlAddAttributeDecl(
        ctxt: xmlValidCtxtPtr,
        dtd: xmlDtdPtr,
        elem: *const xmlChar,
        name: *const xmlChar,
        ns: *const xmlChar,
        type_0: xmlAttributeType,
        def: xmlAttributeDefault,
        defaultValue: *const xmlChar,
        tree: xmlEnumerationPtr,
    ) -> xmlAttributePtr;
    fn xmlAddID(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        value: *const xmlChar,
        attr: xmlAttrPtr,
    ) -> xmlIDPtr;
    fn xmlIsID(doc: xmlDocPtr, elem: xmlNodePtr, attr: xmlAttrPtr) -> i32;
    fn xmlAddRef(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        value: *const xmlChar,
        attr: xmlAttrPtr,
    ) -> xmlRefPtr;
    fn xmlIsRef(doc: xmlDocPtr, elem: xmlNodePtr, attr: xmlAttrPtr) -> i32;
    fn xmlValidateRoot(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr) -> i32;
    fn xmlValidateElementDecl(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr, elem: xmlElementPtr) -> i32;
    fn xmlValidNormalizeAttributeValue(
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        name: *const xmlChar,
        value: *const xmlChar,
    ) -> *mut xmlChar;
    fn xmlValidCtxtNormalizeAttributeValue(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        name: *const xmlChar,
        value: *const xmlChar,
    ) -> *mut xmlChar;
    fn xmlValidateAttributeDecl(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        attr: xmlAttributePtr,
    ) -> i32;
    fn xmlValidateNotationDecl(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr, nota: xmlNotationPtr) -> i32;
    fn xmlValidateDtdFinal(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr) -> i32;
    fn xmlValidateOneElement(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr, elem: xmlNodePtr) -> i32;
    fn xmlValidateOneAttribute(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        attr: xmlAttrPtr,
        value: *const xmlChar,
    ) -> i32;
    fn xmlValidateOneNamespace(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        prefix: *const xmlChar,
        ns: xmlNsPtr,
        value: *const xmlChar,
    ) -> i32;
    fn xmlValidateDocumentFinal(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr) -> i32;
    fn xmlGetDtdQAttrDesc(
        dtd: xmlDtdPtr,
        elem: *const xmlChar,
        name: *const xmlChar,
        prefix: *const xmlChar,
    ) -> xmlAttributePtr;
    fn xmlGetDtdQElementDesc(
        dtd: xmlDtdPtr,
        name: *const xmlChar,
        prefix: *const xmlChar,
    ) -> xmlElementPtr;
    fn xmlDetectCharEncoding(in_0: *const u8, len: i32) -> xmlCharEncoding;
    fn xmlParserAddNodeInfo(ctxt: xmlParserCtxtPtr, info: xmlParserNodeInfoPtr);
    fn xmlLoadExternalEntity(
        URL: *const i8,
        ID: *const i8,
        ctxt: xmlParserCtxtPtr,
    ) -> xmlParserInputPtr;
    static mut xmlFree: xmlFreeFunc;
    static mut xmlMalloc: xmlMallocFunc;
    fn __xmlRegisterNodeDefaultValue() -> *mut xmlRegisterNodeFunc;
    static mut xmlRealloc: xmlReallocFunc;
    fn __htmlDefaultSAXHandler() -> *mut xmlSAXHandlerV1;
    fn __xmlDefaultSAXHandler() -> *mut xmlSAXHandlerV1;
    fn xmlAddDocEntity(
        doc: xmlDocPtr,
        name: *const xmlChar,
        type_0: i32,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlEntityPtr;
    fn xmlAddDtdEntity(
        doc: xmlDocPtr,
        name: *const xmlChar,
        type_0: i32,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlEntityPtr;
    fn xmlGetPredefinedEntity(name: *const xmlChar) -> xmlEntityPtr;
    fn xmlGetDocEntity(doc: *const xmlDoc, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlGetParameterEntity(doc: xmlDocPtr, name: *const xmlChar) -> xmlEntityPtr;
    static xmlStringText: [xmlChar; 0];
    fn xmlSwitchEncoding(ctxt: xmlParserCtxtPtr, enc: xmlCharEncoding) -> i32;
    fn xmlPushInput(ctxt: xmlParserCtxtPtr, input: xmlParserInputPtr) -> i32;
    fn xmlPopInput(ctxt: xmlParserCtxtPtr) -> xmlChar;
    fn xmlFreeInputStream(input: xmlParserInputPtr);
    fn xmlSplitQName(
        ctxt: xmlParserCtxtPtr,
        name: *const xmlChar,
        prefix: *mut *mut xmlChar,
    ) -> *mut xmlChar;
    fn xmlStringDecodeEntities(
        ctxt: xmlParserCtxtPtr,
        str: *const xmlChar,
        what: i32,
        end: xmlChar,
        end2: xmlChar,
        end3: xmlChar,
    ) -> *mut xmlChar;
    fn xmlErrMemory(ctxt: xmlParserCtxtPtr, extra: *const i8);
    fn xmlStringLenDecodeEntities(
        ctxt: xmlParserCtxtPtr,
        str: *const xmlChar,
        len: i32,
        what: i32,
        end: xmlChar,
        end2: xmlChar,
        end3: xmlChar,
    ) -> *mut xmlChar;
    fn nodePop(ctxt: xmlParserCtxtPtr) -> xmlNodePtr;
    fn nodePush(ctxt: xmlParserCtxtPtr, value: xmlNodePtr) -> i32;
    fn xmlParseExternalSubset(
        ctxt: xmlParserCtxtPtr,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    );
    fn xmlBuildURI(URI: *const xmlChar, base: *const xmlChar) -> *mut xmlChar;
    fn xmlParseURI(str: *const i8) -> xmlURIPtr;
    fn xmlFreeURI(uri: xmlURIPtr);
    fn xmlCanonicPath(path: *const xmlChar) -> *mut xmlChar;
    fn xmlPathToURI(path: *const xmlChar) -> *mut xmlChar;
    fn htmlNewDocNoDtD(URI: *const xmlChar, ExternalID: *const xmlChar) -> htmlDocPtr;
    fn htmlIsBooleanAttr(name: *const xmlChar) -> i32;
}
pub type xmlChar = u8;
pub type size_t = u64;
pub type ptrdiff_t = i64;
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
pub type xmlSAXHandler = _xmlSAXHandler;
pub type xmlSAXHandlerPtr = *mut xmlSAXHandler;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNotation {
    pub name: *const xmlChar,
    pub PublicID: *const xmlChar,
    pub SystemID: *const xmlChar,
}
pub type xmlNotation = _xmlNotation;
pub type xmlNotationPtr = *mut xmlNotation;
pub type xmlAttributeDefault = u32;
pub const XML_ATTRIBUTE_FIXED: xmlAttributeDefault = 4;
pub const XML_ATTRIBUTE_IMPLIED: xmlAttributeDefault = 3;
pub const XML_ATTRIBUTE_REQUIRED: xmlAttributeDefault = 2;
pub const XML_ATTRIBUTE_NONE: xmlAttributeDefault = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlAttribute {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlDtd,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub nexth: *mut _xmlAttribute,
    pub atype: xmlAttributeType,
    pub def: xmlAttributeDefault,
    pub defaultValue: *const xmlChar,
    pub tree: xmlEnumerationPtr,
    pub prefix: *const xmlChar,
    pub elem: *const xmlChar,
}
pub type xmlAttribute = _xmlAttribute;
pub type xmlAttributePtr = *mut xmlAttribute;
pub type xmlElementTypeVal = u32;
pub const XML_ELEMENT_TYPE_ELEMENT: xmlElementTypeVal = 4;
pub const XML_ELEMENT_TYPE_MIXED: xmlElementTypeVal = 3;
pub const XML_ELEMENT_TYPE_ANY: xmlElementTypeVal = 2;
pub const XML_ELEMENT_TYPE_EMPTY: xmlElementTypeVal = 1;
pub const XML_ELEMENT_TYPE_UNDEFINED: xmlElementTypeVal = 0;
pub type xmlRegexp = _xmlRegexp;
pub type xmlRegexpPtr = *mut xmlRegexp;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlElement {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlDtd,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub etype: xmlElementTypeVal,
    pub content: xmlElementContentPtr,
    pub attributes: xmlAttributePtr,
    pub prefix: *const xmlChar,
    pub contModel: xmlRegexpPtr,
}
pub type xmlElement = _xmlElement;
pub type xmlElementPtr = *mut xmlElement;
pub type xmlNsPtr = *mut xmlNs;
pub type xmlDtd = _xmlDtd;
pub type xmlDtdPtr = *mut xmlDtd;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlID {
    pub next: *mut _xmlID,
    pub value: *const xmlChar,
    pub attr: xmlAttrPtr,
    pub name: *const xmlChar,
    pub lineno: i32,
    pub doc: *mut _xmlDoc,
}
pub type xmlID = _xmlID;
pub type xmlIDPtr = *mut xmlID;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlRef {
    pub next: *mut _xmlRef,
    pub value: *const xmlChar,
    pub attr: xmlAttrPtr,
    pub name: *const xmlChar,
    pub lineno: i32,
}
pub type xmlRef = _xmlRef;
pub type xmlRefPtr = *mut xmlRef;
pub type C2RustUnnamed = u32;
pub const XML_DOC_HTML: C2RustUnnamed = 128;
pub const XML_DOC_INTERNAL: C2RustUnnamed = 64;
pub const XML_DOC_USERBUILT: C2RustUnnamed = 32;
pub const XML_DOC_XINCLUDE: C2RustUnnamed = 16;
pub const XML_DOC_DTDVALID: C2RustUnnamed = 8;
pub const XML_DOC_OLD10: C2RustUnnamed = 4;
pub const XML_DOC_NSVALID: C2RustUnnamed = 2;
pub const XML_DOC_WELLFORMED: C2RustUnnamed = 1;
pub type C2RustUnnamed_0 = u32;
pub const XML_FROM_URI: C2RustUnnamed_0 = 30;
pub const XML_FROM_BUFFER: C2RustUnnamed_0 = 29;
pub const XML_FROM_SCHEMATRONV: C2RustUnnamed_0 = 28;
pub const XML_FROM_I18N: C2RustUnnamed_0 = 27;
pub const XML_FROM_MODULE: C2RustUnnamed_0 = 26;
pub const XML_FROM_WRITER: C2RustUnnamed_0 = 25;
pub const XML_FROM_CHECK: C2RustUnnamed_0 = 24;
pub const XML_FROM_VALID: C2RustUnnamed_0 = 23;
pub const XML_FROM_XSLT: C2RustUnnamed_0 = 22;
pub const XML_FROM_C14N: C2RustUnnamed_0 = 21;
pub const XML_FROM_CATALOG: C2RustUnnamed_0 = 20;
pub const XML_FROM_RELAXNGV: C2RustUnnamed_0 = 19;
pub const XML_FROM_RELAXNGP: C2RustUnnamed_0 = 18;
pub const XML_FROM_SCHEMASV: C2RustUnnamed_0 = 17;
pub const XML_FROM_SCHEMASP: C2RustUnnamed_0 = 16;
pub const XML_FROM_DATATYPE: C2RustUnnamed_0 = 15;
pub const XML_FROM_REGEXP: C2RustUnnamed_0 = 14;
pub const XML_FROM_XPOINTER: C2RustUnnamed_0 = 13;
pub const XML_FROM_XPATH: C2RustUnnamed_0 = 12;
pub const XML_FROM_XINCLUDE: C2RustUnnamed_0 = 11;
pub const XML_FROM_HTTP: C2RustUnnamed_0 = 10;
pub const XML_FROM_FTP: C2RustUnnamed_0 = 9;
pub const XML_FROM_IO: C2RustUnnamed_0 = 8;
pub const XML_FROM_OUTPUT: C2RustUnnamed_0 = 7;
pub const XML_FROM_MEMORY: C2RustUnnamed_0 = 6;
pub const XML_FROM_HTML: C2RustUnnamed_0 = 5;
pub const XML_FROM_DTD: C2RustUnnamed_0 = 4;
pub const XML_FROM_NAMESPACE: C2RustUnnamed_0 = 3;
pub const XML_FROM_TREE: C2RustUnnamed_0 = 2;
pub const XML_FROM_PARSER: C2RustUnnamed_0 = 1;
pub const XML_FROM_NONE: C2RustUnnamed_0 = 0;
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
pub type xmlGenericErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type xmlValidCtxtPtr = *mut xmlValidCtxt;
pub type xmlParserNodeInfoPtr = *mut xmlParserNodeInfo;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXHandlerV1 {
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
}
pub type xmlSAXHandlerV1 = _xmlSAXHandlerV1;
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
pub type htmlDocPtr = xmlDocPtr;
pub type xmlURIPtr = *mut xmlURI;
pub type xmlURI = _xmlURI;
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
pub type xmlRegisterNodeFunc = Option<unsafe extern "C" fn(xmlNodePtr) -> ()>;
extern "C" fn xmlSAX2ErrMemory(mut ctxt: xmlParserCtxtPtr, mut msg: *const i8) {
    let mut schannel: xmlStructuredErrorFunc = None;
    let mut str1: *const i8 = b"out of memory\n\0" as *const u8 as *const i8;
    if !ctxt.is_null() {
        (unsafe { (*ctxt).errNo = XML_ERR_NO_MEMORY as i32 });
        if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { (*(*ctxt).sax).initialized }) == 0xdeedbeaf as u32 {
            schannel = unsafe { (*(*ctxt).sax).serror };
        }
        (unsafe { __xmlRaiseError(
            schannel,
            (*ctxt).vctxt.error,
            (*ctxt).vctxt.userData,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as i32,
            XML_ERR_NO_MEMORY as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            str1,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            msg,
            str1,
            0 as *mut libc::c_void,
        ) });
        (unsafe { (*ctxt).errNo = XML_ERR_NO_MEMORY as i32 });
        (unsafe { (*ctxt).instate = XML_PARSER_EOF });
        (unsafe { (*ctxt).disableSAX = 1 as i32 });
    } else {
        (unsafe { __xmlRaiseError(
            schannel,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as i32,
            XML_ERR_NO_MEMORY as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            str1,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            msg,
            str1,
            0 as *mut libc::c_void,
        ) });
    };
}
extern "C" fn xmlErrValid(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut str1: *const i8,
    mut str2: *const i8,
) {
    let mut schannel: xmlStructuredErrorFunc = None;
    if !ctxt.is_null()
        && (unsafe { (*ctxt).disableSAX }) != 0 as i32
        && (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (unsafe { (*ctxt).errNo = error as i32 });
        if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { (*(*ctxt).sax).initialized }) == 0xdeedbeaf as u32 {
            schannel = unsafe { (*(*ctxt).sax).serror };
        }
        (unsafe { __xmlRaiseError(
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
            str1,
            str2,
            0 as *const i8,
            0 as i32,
            0 as i32,
            msg,
            str1,
            str2,
        ) });
        (unsafe { (*ctxt).valid = 0 as i32 });
    } else {
        (unsafe { __xmlRaiseError(
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
            str1,
            str2,
            0 as *const i8,
            0 as i32,
            0 as i32,
            msg,
            str1,
            str2,
        ) });
    };
}
extern "C" fn xmlFatalErrMsg(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) {
    if !ctxt.is_null()
        && (unsafe { (*ctxt).disableSAX }) != 0 as i32
        && (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (unsafe { (*ctxt).errNo = error as i32 });
    }
    (unsafe { __xmlRaiseError(
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
        0 as i32,
        0 as i32,
        msg,
        str1,
        str2,
    ) });
    if !ctxt.is_null() {
        (unsafe { (*ctxt).wellFormed = 0 as i32 });
        (unsafe { (*ctxt).valid = 0 as i32 });
        if (unsafe { (*ctxt).recovery }) == 0 as i32 {
            (unsafe { (*ctxt).disableSAX = 1 as i32 });
        }
    }
}
extern "C" fn xmlWarnMsg(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut str1: *const xmlChar,
) {
    if !ctxt.is_null()
        && (unsafe { (*ctxt).disableSAX }) != 0 as i32
        && (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (unsafe { (*ctxt).errNo = error as i32 });
    }
    (unsafe { __xmlRaiseError(
        None,
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
        0 as *const i8,
        0 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        str1,
    ) });
}
extern "C" fn xmlNsWarnMsg(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) {
    if !ctxt.is_null()
        && (unsafe { (*ctxt).disableSAX }) != 0 as i32
        && (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (unsafe { (*ctxt).errNo = error as i32 });
    }
    (unsafe { __xmlRaiseError(
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
        str1 as *const i8,
        str2 as *const i8,
        0 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        str1,
        str2,
    ) });
}
#[no_mangle]
pub extern "C" fn xmlSAX2GetPublicId(mut _ctx: *mut libc::c_void) -> *const xmlChar {
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlSAX2GetSystemId(mut ctx: *mut libc::c_void) -> *const xmlChar {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    if ctx.is_null() || (unsafe { (*ctxt).input }).is_null() {
        return 0 as *const xmlChar;
    }
    return (unsafe { (*(*ctxt).input).filename }) as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlSAX2GetLineNumber(mut ctx: *mut libc::c_void) -> i32 {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    if ctx.is_null() || (unsafe { (*ctxt).input }).is_null() {
        return 0 as i32;
    }
    return unsafe { (*(*ctxt).input).line };
}
#[no_mangle]
pub extern "C" fn xmlSAX2GetColumnNumber(mut ctx: *mut libc::c_void) -> i32 {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    if ctx.is_null() || (unsafe { (*ctxt).input }).is_null() {
        return 0 as i32;
    }
    return unsafe { (*(*ctxt).input).col };
}
#[no_mangle]
pub extern "C" fn xmlSAX2IsStandalone(mut ctx: *mut libc::c_void) -> i32 {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    if ctx.is_null() || (unsafe { (*ctxt).myDoc }).is_null() {
        return 0 as i32;
    }
    return ((unsafe { (*(*ctxt).myDoc).standalone }) == 1 as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlSAX2HasInternalSubset(mut ctx: *mut libc::c_void) -> i32 {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    if ctxt.is_null() || (unsafe { (*ctxt).myDoc }).is_null() {
        return 0 as i32;
    }
    return ((unsafe { (*(*ctxt).myDoc).intSubset }) != 0 as *mut libc::c_void as *mut _xmlDtd) as i32;
}
#[no_mangle]
pub extern "C" fn xmlSAX2HasExternalSubset(mut ctx: *mut libc::c_void) -> i32 {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    if ctxt.is_null() || (unsafe { (*ctxt).myDoc }).is_null() {
        return 0 as i32;
    }
    return ((unsafe { (*(*ctxt).myDoc).extSubset }) != 0 as *mut libc::c_void as *mut _xmlDtd) as i32;
}
#[no_mangle]
pub extern "C" fn xmlSAX2InternalSubset(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    if ctx.is_null() {
        return;
    }
    if (unsafe { (*ctxt).myDoc }).is_null() {
        return;
    }
    dtd = unsafe { xmlGetIntSubset((*ctxt).myDoc as *const xmlDoc) };
    if !dtd.is_null() {
        if (unsafe { (*ctxt).html }) != 0 {
            return;
        }
        (unsafe { xmlUnlinkNode(dtd as xmlNodePtr) });
        (unsafe { xmlFreeDtd(dtd) });
        let fresh0 = unsafe { &mut ((*(*ctxt).myDoc).intSubset) };
        *fresh0 = 0 as *mut _xmlDtd;
    }
    let fresh1 = unsafe { &mut ((*(*ctxt).myDoc).intSubset) };
    *fresh1 = unsafe { xmlCreateIntSubset((*ctxt).myDoc, name, ExternalID, SystemID) };
    if (unsafe { (*(*ctxt).myDoc).intSubset }).is_null() {
        xmlSAX2ErrMemory(ctxt, b"xmlSAX2InternalSubset\0" as *const u8 as *const i8);
    }
}
#[no_mangle]
pub extern "C" fn xmlSAX2ExternalSubset(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    if ctx.is_null() {
        return;
    }
    if (!ExternalID.is_null() || !SystemID.is_null())
        && (((unsafe { (*ctxt).validate }) != 0 || (unsafe { (*ctxt).loadsubset }) != 0 as i32)
            && ((unsafe { (*ctxt).wellFormed }) != 0 && !(unsafe { (*ctxt).myDoc }).is_null()))
    {
        let mut oldinput: xmlParserInputPtr = 0 as *mut xmlParserInput;
        let mut oldinputNr: i32 = 0;
        let mut oldinputMax: i32 = 0;
        let mut oldinputTab: *mut xmlParserInputPtr = 0 as *mut xmlParserInputPtr;
        let mut input: xmlParserInputPtr = 0 as xmlParserInputPtr;
        let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
        let mut oldcharset: i32 = 0;
        let mut oldencoding: *const xmlChar = 0 as *const xmlChar;
        if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).resolveEntity).is_some() }) {
            input = unsafe { ((*(*ctxt).sax).resolveEntity).expect("non-null function pointer")(
                (*ctxt).userData,
                ExternalID,
                SystemID,
            ) };
        }
        if input.is_null() {
            return;
        }
        (unsafe { xmlNewDtd((*ctxt).myDoc, name, ExternalID, SystemID) });
        oldinput = unsafe { (*ctxt).input };
        oldinputNr = unsafe { (*ctxt).inputNr };
        oldinputMax = unsafe { (*ctxt).inputMax };
        oldinputTab = unsafe { (*ctxt).inputTab };
        oldcharset = unsafe { (*ctxt).charset };
        oldencoding = unsafe { (*ctxt).encoding };
        let fresh2 = unsafe { &mut ((*ctxt).encoding) };
        *fresh2 = 0 as *const xmlChar;
        let fresh3 = unsafe { &mut ((*ctxt).inputTab) };
        *fresh3 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            (5 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlParserInputPtr>() as u64),
        ) }) as *mut xmlParserInputPtr;
        if (unsafe { (*ctxt).inputTab }).is_null() {
            xmlSAX2ErrMemory(ctxt, b"xmlSAX2ExternalSubset\0" as *const u8 as *const i8);
            let fresh4 = unsafe { &mut ((*ctxt).input) };
            *fresh4 = oldinput;
            (unsafe { (*ctxt).inputNr = oldinputNr });
            (unsafe { (*ctxt).inputMax = oldinputMax });
            let fresh5 = unsafe { &mut ((*ctxt).inputTab) };
            *fresh5 = oldinputTab;
            (unsafe { (*ctxt).charset = oldcharset });
            let fresh6 = unsafe { &mut ((*ctxt).encoding) };
            *fresh6 = oldencoding;
            return;
        }
        (unsafe { (*ctxt).inputNr = 0 as i32 });
        (unsafe { (*ctxt).inputMax = 5 as i32 });
        let fresh7 = unsafe { &mut ((*ctxt).input) };
        *fresh7 = 0 as xmlParserInputPtr;
        (unsafe { xmlPushInput(ctxt, input) });
        if (unsafe { (*(*ctxt).input).length }) >= 4 as i32 {
            enc = unsafe { xmlDetectCharEncoding((*(*ctxt).input).cur, 4 as i32) };
            (unsafe { xmlSwitchEncoding(ctxt, enc) });
        }
        if (unsafe { (*input).filename }).is_null() {
            let fresh8 = unsafe { &mut ((*input).filename) };
            *fresh8 = (unsafe { xmlCanonicPath(SystemID) }) as *mut i8;
        }
        (unsafe { (*input).line = 1 as i32 });
        (unsafe { (*input).col = 1 as i32 });
        let fresh9 = unsafe { &mut ((*input).base) };
        *fresh9 = unsafe { (*(*ctxt).input).cur };
        let fresh10 = unsafe { &mut ((*input).cur) };
        *fresh10 = unsafe { (*(*ctxt).input).cur };
        let fresh11 = unsafe { &mut ((*input).free) };
        *fresh11 = None;
        (unsafe { xmlParseExternalSubset(ctxt, ExternalID, SystemID) });
        while (unsafe { (*ctxt).inputNr }) > 1 as i32 {
            (unsafe { xmlPopInput(ctxt) });
        }
        (unsafe { xmlFreeInputStream((*ctxt).input) });
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).inputTab as *mut libc::c_void) });
        let fresh12 = unsafe { &mut ((*ctxt).input) };
        *fresh12 = oldinput;
        (unsafe { (*ctxt).inputNr = oldinputNr });
        (unsafe { (*ctxt).inputMax = oldinputMax });
        let fresh13 = unsafe { &mut ((*ctxt).inputTab) };
        *fresh13 = oldinputTab;
        (unsafe { (*ctxt).charset = oldcharset });
        if !(unsafe { (*ctxt).encoding }).is_null()
            && ((unsafe { (*ctxt).dict }).is_null() || (unsafe { xmlDictOwns((*ctxt).dict, (*ctxt).encoding) }) == 0)
        {
            (unsafe { xmlFree.expect("non-null function pointer")(
                (*ctxt).encoding as *mut xmlChar as *mut libc::c_void,
            ) });
        }
        let fresh14 = unsafe { &mut ((*ctxt).encoding) };
        *fresh14 = oldencoding;
    }
}
#[no_mangle]
pub extern "C" fn xmlSAX2ResolveEntity(
    mut ctx: *mut libc::c_void,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
) -> xmlParserInputPtr {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut ret: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let mut base: *const i8 = 0 as *const i8;
    if ctx.is_null() {
        return 0 as xmlParserInputPtr;
    }
    if !(unsafe { (*ctxt).input }).is_null() {
        base = unsafe { (*(*ctxt).input).filename };
    }
    if base.is_null() {
        base = unsafe { (*ctxt).directory };
    }
    URI = unsafe { xmlBuildURI(systemId, base as *const xmlChar) };
    ret = unsafe { xmlLoadExternalEntity(URI as *const i8, publicId as *const i8, ctxt) };
    if !URI.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(URI as *mut libc::c_void) });
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSAX2GetEntity(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) -> xmlEntityPtr {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut ret: xmlEntityPtr = 0 as xmlEntityPtr;
    if ctx.is_null() {
        return 0 as xmlEntityPtr;
    }
    if (unsafe { (*ctxt).inSubset }) == 0 as i32 {
        ret = unsafe { xmlGetPredefinedEntity(name) };
        if !ret.is_null() {
            return ret;
        }
    }
    if !(unsafe { (*ctxt).myDoc }).is_null() && (unsafe { (*(*ctxt).myDoc).standalone }) == 1 as i32 {
        if (unsafe { (*ctxt).inSubset }) == 2 as i32 {
            (unsafe { (*(*ctxt).myDoc).standalone = 0 as i32 });
            ret = unsafe { xmlGetDocEntity((*ctxt).myDoc as *const xmlDoc, name) };
            (unsafe { (*(*ctxt).myDoc).standalone = 1 as i32 });
        } else {
            ret = unsafe { xmlGetDocEntity((*ctxt).myDoc as *const xmlDoc, name) };
            if ret.is_null() {
                (unsafe { (*(*ctxt).myDoc).standalone = 0 as i32 });
                ret = unsafe { xmlGetDocEntity((*ctxt).myDoc as *const xmlDoc, name) };
                if !ret.is_null() {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_NOT_STANDALONE,
                        b"Entity(%s) document marked standalone but requires external subset\n\0"
                            as *const u8 as *const i8,
                        name,
                        0 as *const xmlChar,
                    );
                }
                (unsafe { (*(*ctxt).myDoc).standalone = 1 as i32 });
            }
        }
    } else {
        ret = unsafe { xmlGetDocEntity((*ctxt).myDoc as *const xmlDoc, name) };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSAX2GetParameterEntity(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) -> xmlEntityPtr {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut ret: xmlEntityPtr = 0 as *mut xmlEntity;
    if ctx.is_null() {
        return 0 as xmlEntityPtr;
    }
    ret = unsafe { xmlGetParameterEntity((*ctxt).myDoc, name) };
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSAX2EntityDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut type_0: i32,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
    mut content: *mut xmlChar,
) {
    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    if ctx.is_null() {
        return;
    }
    if (unsafe { (*ctxt).inSubset }) == 1 as i32 {
        ent = unsafe { xmlAddDocEntity((*ctxt).myDoc, name, type_0, publicId, systemId, content) };
        if ent.is_null() && (unsafe { (*ctxt).pedantic }) != 0 {
            xmlWarnMsg(
                ctxt,
                XML_WAR_ENTITY_REDEFINED,
                b"Entity(%s) already defined in the internal subset\n\0" as *const u8 as *const i8,
                name,
            );
        }
        if !ent.is_null() && (unsafe { (*ent).URI }).is_null() && !systemId.is_null() {
            let mut URI: *mut xmlChar = 0 as *mut xmlChar;
            let mut base: *const i8 = 0 as *const i8;
            if !(unsafe { (*ctxt).input }).is_null() {
                base = unsafe { (*(*ctxt).input).filename };
            }
            if base.is_null() {
                base = unsafe { (*ctxt).directory };
            }
            URI = unsafe { xmlBuildURI(systemId, base as *const xmlChar) };
            let fresh15 = unsafe { &mut ((*ent).URI) };
            *fresh15 = URI;
        }
    } else if (unsafe { (*ctxt).inSubset }) == 2 as i32 {
        ent = unsafe { xmlAddDtdEntity((*ctxt).myDoc, name, type_0, publicId, systemId, content) };
        if ent.is_null()
            && (unsafe { (*ctxt).pedantic }) != 0
            && !(unsafe { (*ctxt).sax }).is_null()
            && (unsafe { ((*(*ctxt).sax).warning).is_some() })
        {
            (unsafe { ((*(*ctxt).sax).warning).expect("non-null function pointer")(
                (*ctxt).userData,
                b"Entity(%s) already defined in the external subset\n\0" as *const u8 as *const i8,
                name,
            ) });
        }
        if !ent.is_null() && (unsafe { (*ent).URI }).is_null() && !systemId.is_null() {
            let mut URI_0: *mut xmlChar = 0 as *mut xmlChar;
            let mut base_0: *const i8 = 0 as *const i8;
            if !(unsafe { (*ctxt).input }).is_null() {
                base_0 = unsafe { (*(*ctxt).input).filename };
            }
            if base_0.is_null() {
                base_0 = unsafe { (*ctxt).directory };
            }
            URI_0 = unsafe { xmlBuildURI(systemId, base_0 as *const xmlChar) };
            let fresh16 = unsafe { &mut ((*ent).URI) };
            *fresh16 = URI_0;
        }
    } else {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_ENTITY_PROCESSING,
            b"SAX.xmlSAX2EntityDecl(%s) called while not in subset\n\0" as *const u8 as *const i8,
            name,
            0 as *const xmlChar,
        );
    };
}
#[no_mangle]
pub extern "C" fn xmlSAX2AttributeDecl(
    mut ctx: *mut libc::c_void,
    mut elem: *const xmlChar,
    mut fullname: *const xmlChar,
    mut type_0: i32,
    mut def: i32,
    mut defaultValue: *const xmlChar,
    mut tree: xmlEnumerationPtr,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut attr: xmlAttributePtr = 0 as *mut xmlAttribute;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if ctxt.is_null() || (unsafe { (*ctxt).myDoc }).is_null() {
        return;
    }
    if (unsafe { xmlStrEqual(
        fullname,
        b"xml:id\0" as *const u8 as *const i8 as *mut xmlChar,
    ) }) != 0
        && type_0 != XML_ATTRIBUTE_ID as i32
    {
        let mut tmp: i32 = unsafe { (*ctxt).valid };
        xmlErrValid(
            ctxt,
            XML_DTD_XMLID_TYPE,
            b"xml:id : attribute type should be ID\n\0" as *const u8 as *const i8,
            0 as *const i8,
            0 as *const i8,
        );
        (unsafe { (*ctxt).valid = tmp });
    }
    name = unsafe { xmlSplitQName(ctxt, fullname, &mut prefix) };
    (unsafe { (*ctxt).vctxt.valid = 1 as i32 });
    if (unsafe { (*ctxt).inSubset }) == 1 as i32 {
        attr = unsafe { xmlAddAttributeDecl(
            &mut (*ctxt).vctxt,
            (*(*ctxt).myDoc).intSubset,
            elem,
            name,
            prefix,
            type_0 as xmlAttributeType,
            def as xmlAttributeDefault,
            defaultValue,
            tree,
        ) };
    } else if (unsafe { (*ctxt).inSubset }) == 2 as i32 {
        attr = unsafe { xmlAddAttributeDecl(
            &mut (*ctxt).vctxt,
            (*(*ctxt).myDoc).extSubset,
            elem,
            name,
            prefix,
            type_0 as xmlAttributeType,
            def as xmlAttributeDefault,
            defaultValue,
            tree,
        ) };
    } else {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"SAX.xmlSAX2AttributeDecl(%s) called while not in subset\n\0" as *const u8
                as *const i8,
            name,
            0 as *const xmlChar,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
        (unsafe { xmlFreeEnumeration(tree) });
        return;
    }
    if (unsafe { (*ctxt).vctxt.valid }) == 0 as i32 {
        (unsafe { (*ctxt).valid = 0 as i32 });
    }
    if !attr.is_null()
        && (unsafe { (*ctxt).validate }) != 0
        && (unsafe { (*ctxt).wellFormed }) != 0
        && !(unsafe { (*(*ctxt).myDoc).intSubset }).is_null()
    {
        (unsafe { (*ctxt).valid &= xmlValidateAttributeDecl(&mut (*ctxt).vctxt, (*ctxt).myDoc, attr) });
    }
    if !prefix.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
    }
    if !name.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
    }
}
#[no_mangle]
pub extern "C" fn xmlSAX2ElementDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut type_0: i32,
    mut content: xmlElementContentPtr,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut elem: xmlElementPtr = 0 as xmlElementPtr;
    if ctxt.is_null() || (unsafe { (*ctxt).myDoc }).is_null() {
        return;
    }
    if (unsafe { (*ctxt).inSubset }) == 1 as i32 {
        elem = unsafe { xmlAddElementDecl(
            &mut (*ctxt).vctxt,
            (*(*ctxt).myDoc).intSubset,
            name,
            type_0 as xmlElementTypeVal,
            content,
        ) };
    } else if (unsafe { (*ctxt).inSubset }) == 2 as i32 {
        elem = unsafe { xmlAddElementDecl(
            &mut (*ctxt).vctxt,
            (*(*ctxt).myDoc).extSubset,
            name,
            type_0 as xmlElementTypeVal,
            content,
        ) };
    } else {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"SAX.xmlSAX2ElementDecl(%s) called while not in subset\n\0" as *const u8 as *const i8,
            name,
            0 as *const xmlChar,
        );
        return;
    }
    if elem.is_null() {
        (unsafe { (*ctxt).valid = 0 as i32 });
    }
    if (unsafe { (*ctxt).validate }) != 0
        && (unsafe { (*ctxt).wellFormed }) != 0
        && !(unsafe { (*ctxt).myDoc }).is_null()
        && !(unsafe { (*(*ctxt).myDoc).intSubset }).is_null()
    {
        (unsafe { (*ctxt).valid &= xmlValidateElementDecl(&mut (*ctxt).vctxt, (*ctxt).myDoc, elem) });
    }
}
#[no_mangle]
pub extern "C" fn xmlSAX2NotationDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut nota: xmlNotationPtr = 0 as xmlNotationPtr;
    if ctxt.is_null() || (unsafe { (*ctxt).myDoc }).is_null() {
        return;
    }
    if publicId.is_null() && systemId.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NOTATION_PROCESSING,
            b"SAX.xmlSAX2NotationDecl(%s) externalID or PublicID missing\n\0" as *const u8
                as *const i8,
            name,
            0 as *const xmlChar,
        );
        return;
    } else {
        if (unsafe { (*ctxt).inSubset }) == 1 as i32 {
            nota = unsafe { xmlAddNotationDecl(
                &mut (*ctxt).vctxt,
                (*(*ctxt).myDoc).intSubset,
                name,
                publicId,
                systemId,
            ) };
        } else if (unsafe { (*ctxt).inSubset }) == 2 as i32 {
            nota = unsafe { xmlAddNotationDecl(
                &mut (*ctxt).vctxt,
                (*(*ctxt).myDoc).extSubset,
                name,
                publicId,
                systemId,
            ) };
        } else {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_NOTATION_PROCESSING,
                b"SAX.xmlSAX2NotationDecl(%s) called while not in subset\n\0" as *const u8
                    as *const i8,
                name,
                0 as *const xmlChar,
            );
            return;
        }
    }
    if nota.is_null() {
        (unsafe { (*ctxt).valid = 0 as i32 });
    }
    if (unsafe { (*ctxt).validate }) != 0 && (unsafe { (*ctxt).wellFormed }) != 0 && !(unsafe { (*(*ctxt).myDoc).intSubset }).is_null() {
        (unsafe { (*ctxt).valid &= xmlValidateNotationDecl(&mut (*ctxt).vctxt, (*ctxt).myDoc, nota) });
    }
}
#[no_mangle]
pub extern "C" fn xmlSAX2UnparsedEntityDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
    mut notationName: *const xmlChar,
) {
    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    if ctx.is_null() {
        return;
    }
    if (unsafe { (*ctxt).inSubset }) == 1 as i32 {
        ent = unsafe { xmlAddDocEntity(
            (*ctxt).myDoc,
            name,
            XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as i32,
            publicId,
            systemId,
            notationName,
        ) };
        if ent.is_null()
            && (unsafe { (*ctxt).pedantic }) != 0
            && !(unsafe { (*ctxt).sax }).is_null()
            && (unsafe { ((*(*ctxt).sax).warning).is_some() })
        {
            (unsafe { ((*(*ctxt).sax).warning).expect("non-null function pointer")(
                (*ctxt).userData,
                b"Entity(%s) already defined in the internal subset\n\0" as *const u8 as *const i8,
                name,
            ) });
        }
        if !ent.is_null() && (unsafe { (*ent).URI }).is_null() && !systemId.is_null() {
            let mut URI: *mut xmlChar = 0 as *mut xmlChar;
            let mut base: *const i8 = 0 as *const i8;
            if !(unsafe { (*ctxt).input }).is_null() {
                base = unsafe { (*(*ctxt).input).filename };
            }
            if base.is_null() {
                base = unsafe { (*ctxt).directory };
            }
            URI = unsafe { xmlBuildURI(systemId, base as *const xmlChar) };
            let fresh17 = unsafe { &mut ((*ent).URI) };
            *fresh17 = URI;
        }
    } else if (unsafe { (*ctxt).inSubset }) == 2 as i32 {
        ent = unsafe { xmlAddDtdEntity(
            (*ctxt).myDoc,
            name,
            XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as i32,
            publicId,
            systemId,
            notationName,
        ) };
        if ent.is_null()
            && (unsafe { (*ctxt).pedantic }) != 0
            && !(unsafe { (*ctxt).sax }).is_null()
            && (unsafe { ((*(*ctxt).sax).warning).is_some() })
        {
            (unsafe { ((*(*ctxt).sax).warning).expect("non-null function pointer")(
                (*ctxt).userData,
                b"Entity(%s) already defined in the external subset\n\0" as *const u8 as *const i8,
                name,
            ) });
        }
        if !ent.is_null() && (unsafe { (*ent).URI }).is_null() && !systemId.is_null() {
            let mut URI_0: *mut xmlChar = 0 as *mut xmlChar;
            let mut base_0: *const i8 = 0 as *const i8;
            if !(unsafe { (*ctxt).input }).is_null() {
                base_0 = unsafe { (*(*ctxt).input).filename };
            }
            if base_0.is_null() {
                base_0 = unsafe { (*ctxt).directory };
            }
            URI_0 = unsafe { xmlBuildURI(systemId, base_0 as *const xmlChar) };
            let fresh18 = unsafe { &mut ((*ent).URI) };
            *fresh18 = URI_0;
        }
    } else {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"SAX.xmlSAX2UnparsedEntityDecl(%s) called while not in subset\n\0" as *const u8
                as *const i8,
            name,
            0 as *const xmlChar,
        );
    };
}
#[no_mangle]
pub extern "C" fn xmlSAX2SetDocumentLocator(mut _ctx: *mut libc::c_void, mut _loc: xmlSAXLocatorPtr) {
}
#[no_mangle]
pub extern "C" fn xmlSAX2StartDocument(mut ctx: *mut libc::c_void) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    if ctx.is_null() {
        return;
    }
    if (unsafe { (*ctxt).html }) != 0 {
        if (unsafe { (*ctxt).myDoc }).is_null() {
            let fresh19 = unsafe { &mut ((*ctxt).myDoc) };
            *fresh19 = unsafe { htmlNewDocNoDtD(0 as *const xmlChar, 0 as *const xmlChar) };
        }
        if (unsafe { (*ctxt).myDoc }).is_null() {
            xmlSAX2ErrMemory(ctxt, b"xmlSAX2StartDocument\0" as *const u8 as *const i8);
            return;
        }
        (unsafe { (*(*ctxt).myDoc).properties = XML_DOC_HTML as i32 });
        (unsafe { (*(*ctxt).myDoc).parseFlags = (*ctxt).options });
    } else {
        let fresh20 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh20 = unsafe { xmlNewDoc((*ctxt).version) };
        doc = *fresh20;
        if !doc.is_null() {
            (unsafe { (*doc).properties = 0 as i32 });
            if (unsafe { (*ctxt).options }) & XML_PARSE_OLD10 as i32 != 0 {
                (unsafe { (*doc).properties |= XML_DOC_OLD10 as i32 });
            }
            (unsafe { (*doc).parseFlags = (*ctxt).options });
            if !(unsafe { (*ctxt).encoding }).is_null() {
                let fresh21 = unsafe { &mut ((*doc).encoding) };
                *fresh21 = unsafe { xmlStrdup((*ctxt).encoding) };
            } else {
                let fresh22 = unsafe { &mut ((*doc).encoding) };
                *fresh22 = 0 as *const xmlChar;
            }
            (unsafe { (*doc).standalone = (*ctxt).standalone });
        } else {
            xmlSAX2ErrMemory(ctxt, b"xmlSAX2StartDocument\0" as *const u8 as *const i8);
            return;
        }
        if (unsafe { (*ctxt).dictNames }) != 0 && !doc.is_null() {
            let fresh23 = unsafe { &mut ((*doc).dict) };
            *fresh23 = unsafe { (*ctxt).dict };
            (unsafe { xmlDictReference((*doc).dict) });
        }
    }
    if !(unsafe { (*ctxt).myDoc }).is_null()
        && (unsafe { (*(*ctxt).myDoc).URL }).is_null()
        && !(unsafe { (*ctxt).input }).is_null()
        && !(unsafe { (*(*ctxt).input).filename }).is_null()
    {
        let fresh24 = unsafe { &mut ((*(*ctxt).myDoc).URL) };
        *fresh24 = unsafe { xmlPathToURI((*(*ctxt).input).filename as *const xmlChar) };
        if (unsafe { (*(*ctxt).myDoc).URL }).is_null() {
            xmlSAX2ErrMemory(ctxt, b"xmlSAX2StartDocument\0" as *const u8 as *const i8);
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlSAX2EndDocument(mut ctx: *mut libc::c_void) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    if ctx.is_null() {
        return;
    }
    if (unsafe { (*ctxt).validate }) != 0
        && (unsafe { (*ctxt).wellFormed }) != 0
        && !(unsafe { (*ctxt).myDoc }).is_null()
        && !(unsafe { (*(*ctxt).myDoc).intSubset }).is_null()
    {
        (unsafe { (*ctxt).valid &= xmlValidateDocumentFinal(&mut (*ctxt).vctxt, (*ctxt).myDoc) });
    }
    if !(unsafe { (*ctxt).encoding }).is_null()
        && !(unsafe { (*ctxt).myDoc }).is_null()
        && (unsafe { (*(*ctxt).myDoc).encoding }).is_null()
    {
        let fresh25 = unsafe { &mut ((*(*ctxt).myDoc).encoding) };
        *fresh25 = unsafe { (*ctxt).encoding };
        let fresh26 = unsafe { &mut ((*ctxt).encoding) };
        *fresh26 = 0 as *const xmlChar;
    }
    if !(unsafe { (*ctxt).inputTab }).is_null()
        && (unsafe { (*ctxt).inputNr }) > 0 as i32
        && !(unsafe { *((*ctxt).inputTab).offset(0 as i32 as isize) }).is_null()
        && !(unsafe { (**((*ctxt).inputTab).offset(0 as i32 as isize)).encoding }).is_null()
        && !(unsafe { (*ctxt).myDoc }).is_null()
        && (unsafe { (*(*ctxt).myDoc).encoding }).is_null()
    {
        let fresh27 = unsafe { &mut ((*(*ctxt).myDoc).encoding) };
        *fresh27 = unsafe { xmlStrdup((**((*ctxt).inputTab).offset(0 as i32 as isize)).encoding) };
    }
    if (unsafe { (*ctxt).charset }) != XML_CHAR_ENCODING_NONE as i32
        && !(unsafe { (*ctxt).myDoc }).is_null()
        && (unsafe { (*(*ctxt).myDoc).charset }) == XML_CHAR_ENCODING_NONE as i32
    {
        (unsafe { (*(*ctxt).myDoc).charset = (*ctxt).charset });
    }
}
extern "C" fn xmlNsErrMsg(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) {
    if !ctxt.is_null()
        && (unsafe { (*ctxt).disableSAX }) != 0 as i32
        && (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (unsafe { (*ctxt).errNo = error as i32 });
    }
    (unsafe { __xmlRaiseError(
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
        str1 as *const i8,
        str2 as *const i8,
        0 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        str1,
        str2,
    ) });
}
extern "C" fn xmlSAX2AttributeInternal(
    mut ctx: *mut libc::c_void,
    mut fullname: *const xmlChar,
    mut value: *const xmlChar,
    mut prefix: *const xmlChar,
) {
    let mut current_block: u64;
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut ret: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut ns: *mut xmlChar = 0 as *mut xmlChar;
    let mut nval: *mut xmlChar = 0 as *mut xmlChar;
    let mut namespace: xmlNsPtr = 0 as *mut xmlNs;
    if (unsafe { (*ctxt).html }) != 0 {
        name = unsafe { xmlStrdup(fullname) };
        ns = 0 as *mut xmlChar;
        namespace = 0 as xmlNsPtr;
    } else {
        name = unsafe { xmlSplitQName(ctxt, fullname, &mut ns) };
        if !name.is_null() && (unsafe { *name.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
            if (unsafe { xmlStrEqual(ns, b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
                xmlNsErrMsg(
                    ctxt,
                    XML_ERR_NS_DECL_ERROR,
                    b"invalid namespace declaration '%s'\n\0" as *const u8 as *const i8,
                    fullname,
                    0 as *const xmlChar,
                );
            } else {
                xmlNsWarnMsg(
                    ctxt,
                    XML_WAR_NS_COLUMN,
                    b"Avoid attribute ending with ':' like '%s'\n\0" as *const u8 as *const i8,
                    fullname,
                    0 as *const xmlChar,
                );
            }
            if !ns.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void) });
            }
            ns = 0 as *mut xmlChar;
            (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
            name = unsafe { xmlStrdup(fullname) };
        }
    }
    if name.is_null() {
        xmlSAX2ErrMemory(ctxt, b"xmlSAX2StartElement\0" as *const u8 as *const i8);
        if !ns.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void) });
        }
        return;
    }
    if (unsafe { (*ctxt).html }) != 0 && value.is_null() && (unsafe { htmlIsBooleanAttr(fullname) }) != 0 {
        nval = unsafe { xmlStrdup(fullname) };
        value = nval as *const xmlChar;
    } else {
        (unsafe { (*ctxt).vctxt.valid = 1 as i32 });
        nval = unsafe { xmlValidCtxtNormalizeAttributeValue(
            &mut (*ctxt).vctxt,
            (*ctxt).myDoc,
            (*ctxt).node,
            fullname,
            value,
        ) };
        if (unsafe { (*ctxt).vctxt.valid }) != 1 as i32 {
            (unsafe { (*ctxt).valid = 0 as i32 });
        }
        if !nval.is_null() {
            value = nval;
        }
    }
    if (unsafe { (*ctxt).html }) == 0
        && ns.is_null()
        && (unsafe { *name.offset(0 as i32 as isize) }) as i32 == 'x' as i32
        && (unsafe { *name.offset(1 as i32 as isize) }) as i32 == 'm' as i32
        && (unsafe { *name.offset(2 as i32 as isize) }) as i32 == 'l' as i32
        && (unsafe { *name.offset(3 as i32 as isize) }) as i32 == 'n' as i32
        && (unsafe { *name.offset(4 as i32 as isize) }) as i32 == 's' as i32
        && (unsafe { *name.offset(5 as i32 as isize) }) as i32 == 0 as i32
    {
        let mut nsret: xmlNsPtr = 0 as *mut xmlNs;
        let mut val: *mut xmlChar = 0 as *mut xmlChar;
        if (unsafe { (*ctxt).replaceEntities }) == 0 {
            let fresh28 = unsafe { &mut ((*ctxt).depth) };
            *fresh28 += 1;
            val = unsafe { xmlStringDecodeEntities(
                ctxt,
                value,
                1 as i32,
                0 as i32 as xmlChar,
                0 as i32 as xmlChar,
                0 as i32 as xmlChar,
            ) };
            let fresh29 = unsafe { &mut ((*ctxt).depth) };
            *fresh29 -= 1;
            if val.is_null() {
                xmlSAX2ErrMemory(ctxt, b"xmlSAX2StartElement\0" as *const u8 as *const i8);
                if !name.is_null() {
                    (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
                }
                if !nval.is_null() {
                    (unsafe { xmlFree.expect("non-null function pointer")(nval as *mut libc::c_void) });
                }
                return;
            }
        } else {
            val = value as *mut xmlChar;
        }
        if (unsafe { *val.offset(0 as i32 as isize) }) as i32 != 0 as i32 {
            let mut uri: xmlURIPtr = 0 as *mut xmlURI;
            uri = unsafe { xmlParseURI(val as *const i8) };
            if uri.is_null() {
                if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).warning).is_some() }) {
                    (unsafe { ((*(*ctxt).sax).warning).expect("non-null function pointer")(
                        (*ctxt).userData,
                        b"xmlns: %s not a valid URI\n\0" as *const u8 as *const i8,
                        val,
                    ) });
                }
            } else {
                if (unsafe { (*uri).scheme }).is_null() {
                    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).warning).is_some() }) {
                        (unsafe { ((*(*ctxt).sax).warning).expect("non-null function pointer")(
                            (*ctxt).userData,
                            b"xmlns: URI %s is not absolute\n\0" as *const u8 as *const i8,
                            val,
                        ) });
                    }
                }
                (unsafe { xmlFreeURI(uri) });
            }
        }
        nsret = unsafe { xmlNewNs((*ctxt).node, val, 0 as *const xmlChar) };
        if !nsret.is_null()
            && (unsafe { (*ctxt).validate }) != 0
            && (unsafe { (*ctxt).wellFormed }) != 0
            && !(unsafe { (*ctxt).myDoc }).is_null()
            && !(unsafe { (*(*ctxt).myDoc).intSubset }).is_null()
        {
            (unsafe { (*ctxt).valid &= xmlValidateOneNamespace(
                &mut (*ctxt).vctxt,
                (*ctxt).myDoc,
                (*ctxt).node,
                prefix,
                nsret,
                val,
            ) });
        }
        if !name.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
        }
        if !nval.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(nval as *mut libc::c_void) });
        }
        if val != value as *mut xmlChar {
            (unsafe { xmlFree.expect("non-null function pointer")(val as *mut libc::c_void) });
        }
        return;
    }
    if (unsafe { (*ctxt).html }) == 0
        && !ns.is_null()
        && (unsafe { *ns.offset(0 as i32 as isize) }) as i32 == 'x' as i32
        && (unsafe { *ns.offset(1 as i32 as isize) }) as i32 == 'm' as i32
        && (unsafe { *ns.offset(2 as i32 as isize) }) as i32 == 'l' as i32
        && (unsafe { *ns.offset(3 as i32 as isize) }) as i32 == 'n' as i32
        && (unsafe { *ns.offset(4 as i32 as isize) }) as i32 == 's' as i32
        && (unsafe { *ns.offset(5 as i32 as isize) }) as i32 == 0 as i32
    {
        let mut nsret_0: xmlNsPtr = 0 as *mut xmlNs;
        let mut val_0: *mut xmlChar = 0 as *mut xmlChar;
        if (unsafe { (*ctxt).replaceEntities }) == 0 {
            let fresh30 = unsafe { &mut ((*ctxt).depth) };
            *fresh30 += 1;
            val_0 = unsafe { xmlStringDecodeEntities(
                ctxt,
                value,
                1 as i32,
                0 as i32 as xmlChar,
                0 as i32 as xmlChar,
                0 as i32 as xmlChar,
            ) };
            let fresh31 = unsafe { &mut ((*ctxt).depth) };
            *fresh31 -= 1;
            if val_0.is_null() {
                xmlSAX2ErrMemory(ctxt, b"xmlSAX2StartElement\0" as *const u8 as *const i8);
                (unsafe { xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void) });
                if !name.is_null() {
                    (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
                }
                if !nval.is_null() {
                    (unsafe { xmlFree.expect("non-null function pointer")(nval as *mut libc::c_void) });
                }
                return;
            }
        } else {
            val_0 = value as *mut xmlChar;
        }
        if (unsafe { *val_0.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
            xmlNsErrMsg(
                ctxt,
                XML_NS_ERR_EMPTY,
                b"Empty namespace name for prefix %s\n\0" as *const u8 as *const i8,
                name,
                0 as *const xmlChar,
            );
        }
        if (unsafe { (*ctxt).pedantic }) != 0 as i32 && (unsafe { *val_0.offset(0 as i32 as isize) }) as i32 != 0 as i32 {
            let mut uri_0: xmlURIPtr = 0 as *mut xmlURI;
            uri_0 = unsafe { xmlParseURI(val_0 as *const i8) };
            if uri_0.is_null() {
                xmlNsWarnMsg(
                    ctxt,
                    XML_WAR_NS_URI,
                    b"xmlns:%s: %s not a valid URI\n\0" as *const u8 as *const i8,
                    name,
                    value,
                );
            } else {
                if (unsafe { (*uri_0).scheme }).is_null() {
                    xmlNsWarnMsg(
                        ctxt,
                        XML_WAR_NS_URI_RELATIVE,
                        b"xmlns:%s: URI %s is not absolute\n\0" as *const u8 as *const i8,
                        name,
                        value,
                    );
                }
                (unsafe { xmlFreeURI(uri_0) });
            }
        }
        nsret_0 = unsafe { xmlNewNs((*ctxt).node, val_0, name) };
        (unsafe { xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void) });
        if !nsret_0.is_null()
            && (unsafe { (*ctxt).validate }) != 0
            && (unsafe { (*ctxt).wellFormed }) != 0
            && !(unsafe { (*ctxt).myDoc }).is_null()
            && !(unsafe { (*(*ctxt).myDoc).intSubset }).is_null()
        {
            (unsafe { (*ctxt).valid &= xmlValidateOneNamespace(
                &mut (*ctxt).vctxt,
                (*ctxt).myDoc,
                (*ctxt).node,
                prefix,
                nsret_0,
                value,
            ) });
        }
        if !name.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
        }
        if !nval.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(nval as *mut libc::c_void) });
        }
        if val_0 != value as *mut xmlChar {
            (unsafe { xmlFree.expect("non-null function pointer")(val_0 as *mut libc::c_void) });
        }
        return;
    }
    if !ns.is_null() {
        namespace = unsafe { xmlSearchNs((*ctxt).myDoc, (*ctxt).node, ns) };
        if namespace.is_null() {
            xmlNsErrMsg(
                ctxt,
                XML_NS_ERR_UNDEFINED_NAMESPACE,
                b"Namespace prefix %s of attribute %s is not defined\n\0" as *const u8 as *const i8,
                ns,
                name,
            );
            current_block = 13425230902034816933;
        } else {
            let mut prop: xmlAttrPtr = 0 as *mut xmlAttr;
            prop = unsafe { (*(*ctxt).node).properties };
            loop {
                if prop.is_null() {
                    current_block = 13425230902034816933;
                    break;
                }
                if !(unsafe { (*prop).ns }).is_null() {
                    if (unsafe { xmlStrEqual(name, (*prop).name) }) != 0
                        && (namespace == (unsafe { (*prop).ns })
                            || (unsafe { xmlStrEqual((*namespace).href, (*(*prop).ns).href) }) != 0)
                    {
                        xmlNsErrMsg(
                            ctxt,
                            XML_ERR_ATTRIBUTE_REDEFINED,
                            b"Attribute %s in %s redefined\n\0" as *const u8 as *const i8,
                            name,
                            unsafe { (*namespace).href },
                        );
                        (unsafe { (*ctxt).wellFormed = 0 as i32 });
                        if (unsafe { (*ctxt).recovery }) == 0 as i32 {
                            (unsafe { (*ctxt).disableSAX = 1 as i32 });
                        }
                        if !name.is_null() {
                            (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
                        }
                        current_block = 6621008398210872980;
                        break;
                    }
                }
                prop = unsafe { (*prop).next };
            }
        }
    } else {
        namespace = 0 as xmlNsPtr;
        current_block = 13425230902034816933;
    }
    match current_block {
        13425230902034816933 => {
            ret = unsafe { xmlNewNsPropEatName((*ctxt).node, namespace, name, 0 as *const xmlChar) };
            if !ret.is_null() {
                if (unsafe { (*ctxt).replaceEntities }) == 0 as i32 && (unsafe { (*ctxt).html }) == 0 {
                    let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
                    let fresh32 = unsafe { &mut ((*ret).children) };
                    *fresh32 = unsafe { xmlStringGetNodeList((*ctxt).myDoc as *const xmlDoc, value) };
                    tmp = unsafe { (*ret).children };
                    while !tmp.is_null() {
                        let fresh33 = unsafe { &mut ((*tmp).parent) };
                        *fresh33 = ret as xmlNodePtr;
                        if (unsafe { (*tmp).next }).is_null() {
                            let fresh34 = unsafe { &mut ((*ret).last) };
                            *fresh34 = tmp;
                        }
                        tmp = unsafe { (*tmp).next };
                    }
                } else if !value.is_null() {
                    let fresh35 = unsafe { &mut ((*ret).children) };
                    *fresh35 = unsafe { xmlNewDocText((*ctxt).myDoc as *const xmlDoc, value) };
                    let fresh36 = unsafe { &mut ((*ret).last) };
                    *fresh36 = unsafe { (*ret).children };
                    if !(unsafe { (*ret).children }).is_null() {
                        let fresh37 = unsafe { &mut ((*(*ret).children).parent) };
                        *fresh37 = ret as xmlNodePtr;
                    }
                }
            }
            if (unsafe { (*ctxt).html }) == 0
                && (unsafe { (*ctxt).validate }) != 0
                && (unsafe { (*ctxt).wellFormed }) != 0
                && !(unsafe { (*ctxt).myDoc }).is_null()
                && !(unsafe { (*(*ctxt).myDoc).intSubset }).is_null()
            {
                if (unsafe { (*ctxt).replaceEntities }) == 0 {
                    let mut val_1: *mut xmlChar = 0 as *mut xmlChar;
                    let fresh38 = unsafe { &mut ((*ctxt).depth) };
                    *fresh38 += 1;
                    val_1 = unsafe { xmlStringDecodeEntities(
                        ctxt,
                        value,
                        1 as i32,
                        0 as i32 as xmlChar,
                        0 as i32 as xmlChar,
                        0 as i32 as xmlChar,
                    ) };
                    let fresh39 = unsafe { &mut ((*ctxt).depth) };
                    *fresh39 -= 1;
                    if val_1.is_null() {
                        (unsafe { (*ctxt).valid &= xmlValidateOneAttribute(
                            &mut (*ctxt).vctxt,
                            (*ctxt).myDoc,
                            (*ctxt).node,
                            ret,
                            value,
                        ) });
                    } else {
                        let mut nvalnorm: *mut xmlChar = 0 as *mut xmlChar;
                        nvalnorm = unsafe { xmlValidNormalizeAttributeValue(
                            (*ctxt).myDoc,
                            (*ctxt).node,
                            fullname,
                            val_1,
                        ) };
                        if !nvalnorm.is_null() {
                            (unsafe { xmlFree.expect("non-null function pointer")(val_1 as *mut libc::c_void) });
                            val_1 = nvalnorm;
                        }
                        (unsafe { (*ctxt).valid &= xmlValidateOneAttribute(
                            &mut (*ctxt).vctxt,
                            (*ctxt).myDoc,
                            (*ctxt).node,
                            ret,
                            val_1,
                        ) });
                        (unsafe { xmlFree.expect("non-null function pointer")(val_1 as *mut libc::c_void) });
                    }
                } else {
                    (unsafe { (*ctxt).valid &= xmlValidateOneAttribute(
                        &mut (*ctxt).vctxt,
                        (*ctxt).myDoc,
                        (*ctxt).node,
                        ret,
                        value,
                    ) });
                }
            } else if (unsafe { (*ctxt).loadsubset }) & 8 as i32 == 0 as i32
                && ((unsafe { (*ctxt).replaceEntities }) == 0 as i32 && (unsafe { (*ctxt).external }) != 2 as i32
                    || (unsafe { (*ctxt).replaceEntities }) != 0 as i32 && (unsafe { (*ctxt).inSubset }) == 0 as i32)
                && !(unsafe { (*ret).children }).is_null()
                && (unsafe { (*(*ret).children).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
                && (unsafe { (*(*ret).children).next }).is_null()
            {
                let mut content: *mut xmlChar = unsafe { (*(*ret).children).content };
                if (unsafe { xmlStrEqual(
                    fullname,
                    b"xml:id\0" as *const u8 as *const i8 as *mut xmlChar,
                ) }) != 0
                {
                    if (unsafe { xmlValidateNCName(content, 1 as i32) }) != 0 as i32 {
                        xmlErrValid(
                            ctxt,
                            XML_DTD_XMLID_VALUE,
                            b"xml:id : attribute value %s is not an NCName\n\0" as *const u8
                                as *const i8,
                            content as *const i8,
                            0 as *const i8,
                        );
                    }
                    (unsafe { xmlAddID(&mut (*ctxt).vctxt, (*ctxt).myDoc, content, ret) });
                } else if (unsafe { xmlIsID((*ctxt).myDoc, (*ctxt).node, ret) }) != 0 {
                    (unsafe { xmlAddID(&mut (*ctxt).vctxt, (*ctxt).myDoc, content, ret) });
                } else if (unsafe { xmlIsRef((*ctxt).myDoc, (*ctxt).node, ret) }) != 0 {
                    (unsafe { xmlAddRef(&mut (*ctxt).vctxt, (*ctxt).myDoc, content, ret) });
                }
            }
        }
        _ => {}
    }
    if !nval.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(nval as *mut libc::c_void) });
    }
    if !ns.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void) });
    }
}
extern "C" fn xmlCheckDefaultedAttributes(
    mut ctxt: xmlParserCtxtPtr,
    mut name: *const xmlChar,
    mut prefix: *const xmlChar,
    mut atts: *mut *const xmlChar,
) {
    let mut elemDecl: xmlElementPtr = 0 as *mut xmlElement;
    let mut att: *const xmlChar = 0 as *const xmlChar;
    let mut internal: i32 = 1 as i32;
    let mut i: i32 = 0;
    elemDecl = unsafe { xmlGetDtdQElementDesc((*(*ctxt).myDoc).intSubset, name, prefix) };
    if elemDecl.is_null() {
        elemDecl = unsafe { xmlGetDtdQElementDesc((*(*ctxt).myDoc).extSubset, name, prefix) };
        internal = 0 as i32;
    }
    while !elemDecl.is_null() {
        let mut attr: xmlAttributePtr = unsafe { (*elemDecl).attributes };
        if (unsafe { (*(*ctxt).myDoc).standalone }) == 1 as i32
            && !(unsafe { (*(*ctxt).myDoc).extSubset }).is_null()
            && (unsafe { (*ctxt).validate }) != 0
        {
            while !attr.is_null() {
                if !(unsafe { (*attr).defaultValue }).is_null()
                    && (unsafe { xmlGetDtdQAttrDesc(
                        (*(*ctxt).myDoc).extSubset,
                        (*attr).elem,
                        (*attr).name,
                        (*attr).prefix,
                    ) }) == attr
                    && (unsafe { xmlGetDtdQAttrDesc(
                        (*(*ctxt).myDoc).intSubset,
                        (*attr).elem,
                        (*attr).name,
                        (*attr).prefix,
                    ) })
                    .is_null()
                {
                    let mut fulln: *mut xmlChar = 0 as *mut xmlChar;
                    if !(unsafe { (*attr).prefix }).is_null() {
                        fulln = unsafe { xmlStrdup((*attr).prefix) };
                        fulln = unsafe { xmlStrcat(fulln, b":\0" as *const u8 as *const i8 as *mut xmlChar) };
                        fulln = unsafe { xmlStrcat(fulln, (*attr).name) };
                    } else {
                        fulln = unsafe { xmlStrdup((*attr).name) };
                    }
                    if fulln.is_null() {
                        xmlSAX2ErrMemory(ctxt, b"xmlSAX2StartElement\0" as *const u8 as *const i8);
                        break;
                    } else {
                        att = 0 as *const xmlChar;
                        if !atts.is_null() {
                            i = 0 as i32;
                            att = unsafe { *atts.offset(i as isize) };
                            while !att.is_null() {
                                if (unsafe { xmlStrEqual(att, fulln) }) != 0 {
                                    break;
                                }
                                i += 2 as i32;
                                att = unsafe { *atts.offset(i as isize) };
                            }
                        }
                        if att.is_null() {
                            xmlErrValid(
                                ctxt,
                                XML_DTD_STANDALONE_DEFAULTED,
                                b"standalone: attribute %s on %s defaulted from external subset\n\0"
                                    as *const u8 as *const i8,
                                fulln as *const i8,
                                (unsafe { (*attr).elem }) as *const i8,
                            );
                        }
                        (unsafe { xmlFree.expect("non-null function pointer")(fulln as *mut libc::c_void) });
                    }
                }
                attr = unsafe { (*attr).nexth };
            }
        }
        attr = unsafe { (*elemDecl).attributes };
        while !attr.is_null() {
            if !(unsafe { (*attr).defaultValue }).is_null() {
                if !(unsafe { (*attr).prefix }).is_null()
                    && (unsafe { xmlStrEqual(
                        (*attr).prefix,
                        b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                    ) }) != 0
                    || (unsafe { (*attr).prefix }).is_null()
                        && (unsafe { xmlStrEqual(
                            (*attr).name,
                            b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                        ) }) != 0
                    || (unsafe { (*ctxt).loadsubset }) & 4 as i32 != 0
                {
                    let mut tst: xmlAttributePtr = 0 as *mut xmlAttribute;
                    tst = unsafe { xmlGetDtdQAttrDesc(
                        (*(*ctxt).myDoc).intSubset,
                        (*attr).elem,
                        (*attr).name,
                        (*attr).prefix,
                    ) };
                    if tst == attr || tst.is_null() {
                        let mut fn_0: [xmlChar; 50] = [0; 50];
                        let mut fulln_0: *mut xmlChar = 0 as *mut xmlChar;
                        fulln_0 = unsafe { xmlBuildQName(
                            (*attr).name,
                            (*attr).prefix,
                            fn_0.as_mut_ptr(),
                            50 as i32,
                        ) };
                        if fulln_0.is_null() {
                            xmlSAX2ErrMemory(
                                ctxt,
                                b"xmlSAX2StartElement\0" as *const u8 as *const i8,
                            );
                            return;
                        }
                        att = 0 as *const xmlChar;
                        if !atts.is_null() {
                            i = 0 as i32;
                            att = unsafe { *atts.offset(i as isize) };
                            while !att.is_null() {
                                if (unsafe { xmlStrEqual(att, fulln_0) }) != 0 {
                                    break;
                                }
                                i += 2 as i32;
                                att = unsafe { *atts.offset(i as isize) };
                            }
                        }
                        if att.is_null() {
                            xmlSAX2AttributeInternal(
                                ctxt as *mut libc::c_void,
                                fulln_0,
                                unsafe { (*attr).defaultValue },
                                prefix,
                            );
                        }
                        if fulln_0 != fn_0.as_mut_ptr() && fulln_0 != (unsafe { (*attr).name }) as *mut xmlChar {
                            (unsafe { xmlFree.expect("non-null function pointer")(
                                fulln_0 as *mut libc::c_void,
                            ) });
                        }
                    }
                }
            }
            attr = unsafe { (*attr).nexth };
        }
        if !(internal == 1 as i32) {
            break;
        }
        elemDecl = unsafe { xmlGetDtdQElementDesc((*(*ctxt).myDoc).extSubset, name, prefix) };
        internal = 0 as i32;
    }
}
#[no_mangle]
pub extern "C" fn xmlSAX2StartElement(
    mut ctx: *mut libc::c_void,
    mut fullname: *const xmlChar,
    mut atts: *mut *const xmlChar,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    let mut att: *const xmlChar = 0 as *const xmlChar;
    let mut value: *const xmlChar = 0 as *const xmlChar;
    let mut i: i32 = 0;
    if ctx.is_null() || fullname.is_null() || (unsafe { (*ctxt).myDoc }).is_null() {
        return;
    }
    parent = unsafe { (*ctxt).node };
    if (unsafe { (*ctxt).validate }) != 0
        && (unsafe { (*(*ctxt).myDoc).extSubset }).is_null()
        && ((unsafe { (*(*ctxt).myDoc).intSubset }).is_null()
            || (unsafe { (*(*(*ctxt).myDoc).intSubset).notations }).is_null()
                && (unsafe { (*(*(*ctxt).myDoc).intSubset).elements }).is_null()
                && (unsafe { (*(*(*ctxt).myDoc).intSubset).attributes }).is_null()
                && (unsafe { (*(*(*ctxt).myDoc).intSubset).entities }).is_null())
    {
        xmlErrValid(
            ctxt,
            XML_ERR_NO_DTD,
            b"Validation failed: no DTD found !\0" as *const u8 as *const i8,
            0 as *const i8,
            0 as *const i8,
        );
        (unsafe { (*ctxt).validate = 0 as i32 });
    }
    name = unsafe { xmlSplitQName(ctxt, fullname, &mut prefix) };
    ret = unsafe { xmlNewDocNodeEatName((*ctxt).myDoc, 0 as xmlNsPtr, name, 0 as *const xmlChar) };
    if ret.is_null() {
        if !prefix.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
        }
        xmlSAX2ErrMemory(ctxt, b"xmlSAX2StartElement\0" as *const u8 as *const i8);
        return;
    }
    if (unsafe { (*(*ctxt).myDoc).children }).is_null() {
        (unsafe { xmlAddChild((*ctxt).myDoc as xmlNodePtr, ret) });
    } else if parent.is_null() {
        parent = unsafe { (*(*ctxt).myDoc).children };
    }
    (unsafe { (*ctxt).nodemem = -(1 as i32) });
    if (unsafe { (*ctxt).linenumbers }) != 0 {
        if !(unsafe { (*ctxt).input }).is_null() {
            if (unsafe { (*(*ctxt).input).line }) < 32767 as i32 * 2 as i32 + 1 as i32 {
                (unsafe { (*ret).line = (*(*ctxt).input).line as u16 });
            } else {
                (unsafe { (*ret).line = (32767 as i32 * 2 as i32 + 1 as i32) as u16 });
            }
        }
    }
    if (unsafe { nodePush(ctxt, ret) }) < 0 as i32 {
        (unsafe { xmlUnlinkNode(ret) });
        (unsafe { xmlFreeNode(ret) });
        if !prefix.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
        }
        return;
    }
    if !parent.is_null() {
        if (unsafe { (*parent).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            (unsafe { xmlAddChild(parent, ret) });
        } else {
            (unsafe { xmlAddSibling(parent, ret) });
        }
    }
    if (unsafe { (*ctxt).html }) == 0 {
        if !(unsafe { (*(*ctxt).myDoc).intSubset }).is_null() || !(unsafe { (*(*ctxt).myDoc).extSubset }).is_null() {
            xmlCheckDefaultedAttributes(ctxt, name, prefix, atts);
        }
        if !atts.is_null() {
            i = 0 as i32;
            let fresh40 = i;
            i = i + 1;
            att = unsafe { *atts.offset(fresh40 as isize) };
            let fresh41 = i;
            i = i + 1;
            value = unsafe { *atts.offset(fresh41 as isize) };
            while !att.is_null() && !value.is_null() {
                if (unsafe { *att.offset(0 as i32 as isize) }) as i32 == 'x' as i32
                    && (unsafe { *att.offset(1 as i32 as isize) }) as i32 == 'm' as i32
                    && (unsafe { *att.offset(2 as i32 as isize) }) as i32 == 'l' as i32
                    && (unsafe { *att.offset(3 as i32 as isize) }) as i32 == 'n' as i32
                    && (unsafe { *att.offset(4 as i32 as isize) }) as i32 == 's' as i32
                {
                    xmlSAX2AttributeInternal(ctxt as *mut libc::c_void, att, value, prefix);
                }
                let fresh42 = i;
                i = i + 1;
                att = unsafe { *atts.offset(fresh42 as isize) };
                let fresh43 = i;
                i = i + 1;
                value = unsafe { *atts.offset(fresh43 as isize) };
            }
        }
        ns = unsafe { xmlSearchNs((*ctxt).myDoc, ret, prefix) };
        if ns.is_null() && !parent.is_null() {
            ns = unsafe { xmlSearchNs((*ctxt).myDoc, parent, prefix) };
        }
        if !prefix.is_null() && ns.is_null() {
            ns = unsafe { xmlNewNs(ret, 0 as *const xmlChar, prefix) };
            xmlNsWarnMsg(
                ctxt,
                XML_NS_ERR_UNDEFINED_NAMESPACE,
                b"Namespace prefix %s is not defined\n\0" as *const u8 as *const i8,
                prefix,
                0 as *const xmlChar,
            );
        }
        if !ns.is_null()
            && !(unsafe { (*ns).href }).is_null()
            && ((unsafe { *((*ns).href).offset(0 as i32 as isize) }) as i32 != 0 as i32
                || !(unsafe { (*ns).prefix }).is_null())
        {
            (unsafe { xmlSetNs(ret, ns) });
        }
    }
    if !atts.is_null() {
        i = 0 as i32;
        let fresh44 = i;
        i = i + 1;
        att = unsafe { *atts.offset(fresh44 as isize) };
        let fresh45 = i;
        i = i + 1;
        value = unsafe { *atts.offset(fresh45 as isize) };
        if (unsafe { (*ctxt).html }) != 0 {
            while !att.is_null() {
                xmlSAX2AttributeInternal(
                    ctxt as *mut libc::c_void,
                    att,
                    value,
                    0 as *const xmlChar,
                );
                let fresh46 = i;
                i = i + 1;
                att = unsafe { *atts.offset(fresh46 as isize) };
                let fresh47 = i;
                i = i + 1;
                value = unsafe { *atts.offset(fresh47 as isize) };
            }
        } else {
            while !att.is_null() && !value.is_null() {
                if (unsafe { *att.offset(0 as i32 as isize) }) as i32 != 'x' as i32
                    || (unsafe { *att.offset(1 as i32 as isize) }) as i32 != 'm' as i32
                    || (unsafe { *att.offset(2 as i32 as isize) }) as i32 != 'l' as i32
                    || (unsafe { *att.offset(3 as i32 as isize) }) as i32 != 'n' as i32
                    || (unsafe { *att.offset(4 as i32 as isize) }) as i32 != 's' as i32
                {
                    xmlSAX2AttributeInternal(
                        ctxt as *mut libc::c_void,
                        att,
                        value,
                        0 as *const xmlChar,
                    );
                }
                let fresh48 = i;
                i = i + 1;
                att = unsafe { *atts.offset(fresh48 as isize) };
                let fresh49 = i;
                i = i + 1;
                value = unsafe { *atts.offset(fresh49 as isize) };
            }
        }
    }
    if (unsafe { (*ctxt).validate }) != 0 && (unsafe { (*ctxt).vctxt.flags }) & (1 as u32) << 0 as i32 == 0 as i32 as u32 {
        let mut chk: i32 = 0;
        chk = unsafe { xmlValidateDtdFinal(&mut (*ctxt).vctxt, (*ctxt).myDoc) };
        if chk <= 0 as i32 {
            (unsafe { (*ctxt).valid = 0 as i32 });
        }
        if chk < 0 as i32 {
            (unsafe { (*ctxt).wellFormed = 0 as i32 });
        }
        (unsafe { (*ctxt).valid &= xmlValidateRoot(&mut (*ctxt).vctxt, (*ctxt).myDoc) });
        (unsafe { (*ctxt).vctxt.flags |= (1 as u32) << 0 as i32 });
    }
    if !prefix.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
    }
}
#[no_mangle]
pub extern "C" fn xmlSAX2EndElement(mut ctx: *mut libc::c_void, mut _name: *const xmlChar) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if ctx.is_null() {
        return;
    }
    cur = unsafe { (*ctxt).node };
    if !cur.is_null() && (unsafe { (*ctxt).record_info }) != 0 {
        (unsafe { (*(*ctxt).nodeInfo).end_pos =
            ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64 as u64 });
        (unsafe { (*(*ctxt).nodeInfo).end_line = (*(*ctxt).input).line as u64 });
        let fresh50 = unsafe { &mut ((*(*ctxt).nodeInfo).node) };
        *fresh50 = cur as *const _xmlNode;
        (unsafe { xmlParserAddNodeInfo(ctxt, (*ctxt).nodeInfo) });
    }
    (unsafe { (*ctxt).nodemem = -(1 as i32) });
    if (unsafe { (*ctxt).validate }) != 0
        && (unsafe { (*ctxt).wellFormed }) != 0
        && !(unsafe { (*ctxt).myDoc }).is_null()
        && !(unsafe { (*(*ctxt).myDoc).intSubset }).is_null()
    {
        (unsafe { (*ctxt).valid &= xmlValidateOneElement(&mut (*ctxt).vctxt, (*ctxt).myDoc, cur) });
    }
    (unsafe { nodePop(ctxt) });
}
extern "C" fn xmlSAX2TextNode(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *const xmlChar,
    mut len: i32,
) -> xmlNodePtr {
    let mut current_block: u64;
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    let mut intern: *const xmlChar = 0 as *const xmlChar;
    if !(unsafe { (*ctxt).freeElems }).is_null() {
        ret = unsafe { (*ctxt).freeElems };
        let fresh51 = unsafe { &mut ((*ctxt).freeElems) };
        *fresh51 = unsafe { (*ret).next };
        let fresh52 = unsafe { &mut ((*ctxt).freeElemsNr) };
        *fresh52 -= 1;
    } else {
        ret = (unsafe { xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNode>() as u64) })
            as xmlNodePtr;
    }
    if ret.is_null() {
        (unsafe { xmlErrMemory(ctxt, b"xmlSAX2Characters\0" as *const u8 as *const i8) });
        return 0 as xmlNodePtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlNode>() as u64,
    ) });
    if (unsafe { (*ctxt).dictNames }) != 0 {
        let mut cur: xmlChar = unsafe { *str.offset(len as isize) };
        if len
            < (2 as i32 as u64).wrapping_mul(::std::mem::size_of::<*mut libc::c_void>() as u64)
                as i32
            && (unsafe { (*ctxt).options }) & XML_PARSE_COMPACT as i32 != 0
        {
            let mut tmp: *mut xmlChar =
                (unsafe { &mut (*ret).properties }) as *mut *mut _xmlAttr as *mut xmlChar;
            (unsafe { memcpy(
                tmp as *mut libc::c_void,
                str as *const libc::c_void,
                len as u64,
            ) });
            (unsafe { *tmp.offset(len as isize) = 0 as i32 as xmlChar });
            intern = tmp;
        } else if len <= 3 as i32
            && (cur as i32 == '"' as i32
                || cur as i32 == '\'' as i32
                || cur as i32 == '<' as i32
                    && (unsafe { *str.offset((len + 1 as i32) as isize) }) as i32 != '!' as i32)
        {
            intern = unsafe { xmlDictLookup((*ctxt).dict, str, len) };
        } else if ((unsafe { *str }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *str }) as i32 && (unsafe { *str }) as i32 <= 0xa as i32
            || (unsafe { *str }) as i32 == 0xd as i32)
            && len < 60 as i32
            && cur as i32 == '<' as i32
            && (unsafe { *str.offset((len + 1 as i32) as isize) }) as i32 != '!' as i32
        {
            let mut i: i32 = 0;
            i = 1 as i32;
            loop {
                if !(i < len) {
                    current_block = 17478428563724192186;
                    break;
                }
                if !((unsafe { *str.offset(i as isize) }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *str.offset(i as isize) }) as i32
                        && (unsafe { *str.offset(i as isize) }) as i32 <= 0xa as i32
                    || (unsafe { *str.offset(i as isize) }) as i32 == 0xd as i32)
                {
                    current_block = 8377240654589692732;
                    break;
                }
                i += 1;
            }
            match current_block {
                8377240654589692732 => {}
                _ => {
                    intern = unsafe { xmlDictLookup((*ctxt).dict, str, len) };
                }
            }
        }
    }
    (unsafe { (*ret).type_0 = XML_TEXT_NODE });
    let fresh53 = unsafe { &mut ((*ret).name) };
    *fresh53 = unsafe { xmlStringText.as_ptr() };
    if intern.is_null() {
        let fresh54 = unsafe { &mut ((*ret).content) };
        *fresh54 = unsafe { xmlStrndup(str, len) };
        if (unsafe { (*ret).content }).is_null() {
            xmlSAX2ErrMemory(ctxt, b"xmlSAX2TextNode\0" as *const u8 as *const i8);
            (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
            return 0 as xmlNodePtr;
        }
    } else {
        let fresh55 = unsafe { &mut ((*ret).content) };
        *fresh55 = intern as *mut xmlChar;
    }
    if (unsafe { (*ctxt).linenumbers }) != 0 {
        if !(unsafe { (*ctxt).input }).is_null() {
            if (unsafe { (*(*ctxt).input).line }) < 32767 as i32 * 2 as i32 + 1 as i32 {
                (unsafe { (*ret).line = (*(*ctxt).input).line as u16 });
            } else {
                (unsafe { (*ret).line = (32767 as i32 * 2 as i32 + 1 as i32) as u16 });
                if (unsafe { (*ctxt).options }) & XML_PARSE_BIG_LINES as i32 != 0 {
                    let fresh56 = unsafe { &mut ((*ret).psvi) };
                    *fresh56 = (unsafe { (*(*ctxt).input).line }) as ptrdiff_t as *mut libc::c_void;
                }
            }
        }
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0 && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() }) {
        (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(ret) });
    }
    return ret;
}
extern "C" fn xmlSAX2DecodeAttrEntities(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *const xmlChar,
    mut end: *const xmlChar,
) -> *mut xmlChar {
    let mut current_block: u64;
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    in_0 = str;
    loop {
        if !(in_0 < end) {
            current_block = 17778012151635330486;
            break;
        }
        let fresh57 = in_0;
        in_0 = unsafe { in_0.offset(1) };
        if (unsafe { *fresh57 }) as i32 == '&' as i32 {
            current_block = 14709023407236833147;
            break;
        }
    }
    match current_block {
        17778012151635330486 => return 0 as *mut xmlChar,
        _ => {
            let fresh58 = unsafe { &mut ((*ctxt).depth) };
            *fresh58 += 1;
            ret = unsafe { xmlStringLenDecodeEntities(
                ctxt,
                str,
                end.offset_from(str) as i64 as i32,
                1 as i32,
                0 as i32 as xmlChar,
                0 as i32 as xmlChar,
                0 as i32 as xmlChar,
            ) };
            let fresh59 = unsafe { &mut ((*ctxt).depth) };
            *fresh59 -= 1;
            return ret;
        }
    };
}
extern "C" fn xmlSAX2AttributeNs(
    mut ctxt: xmlParserCtxtPtr,
    mut localname: *const xmlChar,
    mut prefix: *const xmlChar,
    mut value: *const xmlChar,
    mut valueend: *const xmlChar,
) {
    let mut ret: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut namespace: xmlNsPtr = 0 as xmlNsPtr;
    let mut dup: *mut xmlChar = 0 as *mut xmlChar;
    if !prefix.is_null() {
        namespace = unsafe { xmlSearchNs((*ctxt).myDoc, (*ctxt).node, prefix) };
    }
    if !(unsafe { (*ctxt).freeAttrs }).is_null() {
        ret = unsafe { (*ctxt).freeAttrs };
        let fresh60 = unsafe { &mut ((*ctxt).freeAttrs) };
        *fresh60 = unsafe { (*ret).next };
        let fresh61 = unsafe { &mut ((*ctxt).freeAttrsNr) };
        *fresh61 -= 1;
        (unsafe { memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlAttr>() as u64,
        ) });
        (unsafe { (*ret).type_0 = XML_ATTRIBUTE_NODE });
        let fresh62 = unsafe { &mut ((*ret).parent) };
        *fresh62 = unsafe { (*ctxt).node };
        let fresh63 = unsafe { &mut ((*ret).doc) };
        *fresh63 = unsafe { (*ctxt).myDoc };
        let fresh64 = unsafe { &mut ((*ret).ns) };
        *fresh64 = namespace;
        if (unsafe { (*ctxt).dictNames }) != 0 {
            let fresh65 = unsafe { &mut ((*ret).name) };
            *fresh65 = localname;
        } else {
            let fresh66 = unsafe { &mut ((*ret).name) };
            *fresh66 = unsafe { xmlStrdup(localname) };
        }
        if (unsafe { (*(*ctxt).node).properties }).is_null() {
            let fresh67 = unsafe { &mut ((*(*ctxt).node).properties) };
            *fresh67 = ret;
        } else {
            let mut prev: xmlAttrPtr = unsafe { (*(*ctxt).node).properties };
            while !(unsafe { (*prev).next }).is_null() {
                prev = unsafe { (*prev).next };
            }
            let fresh68 = unsafe { &mut ((*prev).next) };
            *fresh68 = ret;
            let fresh69 = unsafe { &mut ((*ret).prev) };
            *fresh69 = prev;
        }
        if (unsafe { __xmlRegisterCallbacks }) != 0 && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() }) {
            (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(
                ret as xmlNodePtr,
            ) });
        }
    } else {
        if (unsafe { (*ctxt).dictNames }) != 0 {
            ret = unsafe { xmlNewNsPropEatName(
                (*ctxt).node,
                namespace,
                localname as *mut xmlChar,
                0 as *const xmlChar,
            ) };
        } else {
            ret = unsafe { xmlNewNsProp((*ctxt).node, namespace, localname, 0 as *const xmlChar) };
        }
        if ret.is_null() {
            (unsafe { xmlErrMemory(ctxt, b"xmlSAX2AttributeNs\0" as *const u8 as *const i8) });
            return;
        }
    }
    if (unsafe { (*ctxt).replaceEntities }) == 0 as i32 && (unsafe { (*ctxt).html }) == 0 {
        let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
        if (unsafe { *valueend }) as i32 != 0 as i32 {
            tmp = xmlSAX2TextNode(ctxt, value, (unsafe { valueend.offset_from(value) }) as i64 as i32);
            let fresh70 = unsafe { &mut ((*ret).children) };
            *fresh70 = tmp;
            let fresh71 = unsafe { &mut ((*ret).last) };
            *fresh71 = tmp;
            if !tmp.is_null() {
                let fresh72 = unsafe { &mut ((*tmp).doc) };
                *fresh72 = unsafe { (*ret).doc };
                let fresh73 = unsafe { &mut ((*tmp).parent) };
                *fresh73 = ret as xmlNodePtr;
            }
        } else {
            let fresh74 = unsafe { &mut ((*ret).children) };
            *fresh74 = unsafe { xmlStringLenGetNodeList(
                (*ctxt).myDoc as *const xmlDoc,
                value,
                valueend.offset_from(value) as i64 as i32,
            ) };
            tmp = unsafe { (*ret).children };
            while !tmp.is_null() {
                let fresh75 = unsafe { &mut ((*tmp).doc) };
                *fresh75 = unsafe { (*ret).doc };
                let fresh76 = unsafe { &mut ((*tmp).parent) };
                *fresh76 = ret as xmlNodePtr;
                if (unsafe { (*tmp).next }).is_null() {
                    let fresh77 = unsafe { &mut ((*ret).last) };
                    *fresh77 = tmp;
                }
                tmp = unsafe { (*tmp).next };
            }
        }
    } else if !value.is_null() {
        let mut tmp_0: xmlNodePtr = 0 as *mut xmlNode;
        tmp_0 = xmlSAX2TextNode(ctxt, value, (unsafe { valueend.offset_from(value) }) as i64 as i32);
        let fresh78 = unsafe { &mut ((*ret).children) };
        *fresh78 = tmp_0;
        let fresh79 = unsafe { &mut ((*ret).last) };
        *fresh79 = tmp_0;
        if !tmp_0.is_null() {
            let fresh80 = unsafe { &mut ((*tmp_0).doc) };
            *fresh80 = unsafe { (*ret).doc };
            let fresh81 = unsafe { &mut ((*tmp_0).parent) };
            *fresh81 = ret as xmlNodePtr;
        }
    }
    if (unsafe { (*ctxt).html }) == 0
        && (unsafe { (*ctxt).validate }) != 0
        && (unsafe { (*ctxt).wellFormed }) != 0
        && !(unsafe { (*ctxt).myDoc }).is_null()
        && !(unsafe { (*(*ctxt).myDoc).intSubset }).is_null()
    {
        if (unsafe { (*ctxt).replaceEntities }) == 0 {
            dup = xmlSAX2DecodeAttrEntities(ctxt, value, valueend);
            if dup.is_null() {
                if (unsafe { *valueend }) as i32 == 0 as i32 {
                    (unsafe { (*ctxt).valid &= xmlValidateOneAttribute(
                        &mut (*ctxt).vctxt,
                        (*ctxt).myDoc,
                        (*ctxt).node,
                        ret,
                        value,
                    ) });
                } else {
                    dup = unsafe { xmlStrndup(value, valueend.offset_from(value) as i64 as i32) };
                    (unsafe { (*ctxt).valid &= xmlValidateOneAttribute(
                        &mut (*ctxt).vctxt,
                        (*ctxt).myDoc,
                        (*ctxt).node,
                        ret,
                        dup,
                    ) });
                }
            } else {
                if !(unsafe { (*ctxt).attsSpecial }).is_null() {
                    let mut nvalnorm: *mut xmlChar = 0 as *mut xmlChar;
                    let mut fn_0: [xmlChar; 50] = [0; 50];
                    let mut fullname: *mut xmlChar = 0 as *mut xmlChar;
                    fullname = unsafe { xmlBuildQName(localname, prefix, fn_0.as_mut_ptr(), 50 as i32) };
                    if !fullname.is_null() {
                        (unsafe { (*ctxt).vctxt.valid = 1 as i32 });
                        nvalnorm = unsafe { xmlValidCtxtNormalizeAttributeValue(
                            &mut (*ctxt).vctxt,
                            (*ctxt).myDoc,
                            (*ctxt).node,
                            fullname,
                            dup,
                        ) };
                        if (unsafe { (*ctxt).vctxt.valid }) != 1 as i32 {
                            (unsafe { (*ctxt).valid = 0 as i32 });
                        }
                        if fullname != fn_0.as_mut_ptr() && fullname != localname as *mut xmlChar {
                            (unsafe { xmlFree.expect("non-null function pointer")(
                                fullname as *mut libc::c_void,
                            ) });
                        }
                        if !nvalnorm.is_null() {
                            (unsafe { xmlFree.expect("non-null function pointer")(dup as *mut libc::c_void) });
                            dup = nvalnorm;
                        }
                    }
                }
                (unsafe { (*ctxt).valid &= xmlValidateOneAttribute(
                    &mut (*ctxt).vctxt,
                    (*ctxt).myDoc,
                    (*ctxt).node,
                    ret,
                    dup,
                ) });
            }
        } else {
            dup = unsafe { xmlStrndup(value, valueend.offset_from(value) as i64 as i32) };
            (unsafe { (*ctxt).valid &=
                xmlValidateOneAttribute(&mut (*ctxt).vctxt, (*ctxt).myDoc, (*ctxt).node, ret, dup) });
        }
    } else if (unsafe { (*ctxt).loadsubset }) & 8 as i32 == 0 as i32
        && ((unsafe { (*ctxt).replaceEntities }) == 0 as i32 && (unsafe { (*ctxt).external }) != 2 as i32
            || (unsafe { (*ctxt).replaceEntities }) != 0 as i32 && (unsafe { (*ctxt).inSubset }) == 0 as i32)
        && !(unsafe { (*ret).children }).is_null()
        && (unsafe { (*(*ret).children).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
        && (unsafe { (*(*ret).children).next }).is_null()
    {
        let mut content: *mut xmlChar = unsafe { (*(*ret).children).content };
        if prefix == (unsafe { (*ctxt).str_xml })
            && (unsafe { *localname.offset(0 as i32 as isize) }) as i32 == 'i' as i32
            && (unsafe { *localname.offset(1 as i32 as isize) }) as i32 == 'd' as i32
            && (unsafe { *localname.offset(2 as i32 as isize) }) as i32 == 0 as i32
        {
            if (unsafe { xmlValidateNCName(content, 1 as i32) }) != 0 as i32 {
                xmlErrValid(
                    ctxt,
                    XML_DTD_XMLID_VALUE,
                    b"xml:id : attribute value %s is not an NCName\n\0" as *const u8 as *const i8,
                    content as *const i8,
                    0 as *const i8,
                );
            }
            (unsafe { xmlAddID(&mut (*ctxt).vctxt, (*ctxt).myDoc, content, ret) });
        } else if (unsafe { xmlIsID((*ctxt).myDoc, (*ctxt).node, ret) }) != 0 {
            (unsafe { xmlAddID(&mut (*ctxt).vctxt, (*ctxt).myDoc, content, ret) });
        } else if (unsafe { xmlIsRef((*ctxt).myDoc, (*ctxt).node, ret) }) != 0 {
            (unsafe { xmlAddRef(&mut (*ctxt).vctxt, (*ctxt).myDoc, content, ret) });
        }
    }
    if !dup.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(dup as *mut libc::c_void) });
    }
}
#[no_mangle]
pub extern "C" fn xmlSAX2StartElementNs(
    mut ctx: *mut libc::c_void,
    mut localname: *const xmlChar,
    mut prefix: *const xmlChar,
    mut URI: *const xmlChar,
    mut nb_namespaces: i32,
    mut namespaces: *mut *const xmlChar,
    mut nb_attributes: i32,
    mut nb_defaulted: i32,
    mut attributes: *mut *const xmlChar,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut last: xmlNsPtr = 0 as xmlNsPtr;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut uri: *const xmlChar = 0 as *const xmlChar;
    let mut pref: *const xmlChar = 0 as *const xmlChar;
    let mut lname: *mut xmlChar = 0 as *mut xmlChar;
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    if ctx.is_null() {
        return;
    }
    parent = unsafe { (*ctxt).node };
    if (unsafe { (*ctxt).validate }) != 0
        && (unsafe { (*(*ctxt).myDoc).extSubset }).is_null()
        && ((unsafe { (*(*ctxt).myDoc).intSubset }).is_null()
            || (unsafe { (*(*(*ctxt).myDoc).intSubset).notations }).is_null()
                && (unsafe { (*(*(*ctxt).myDoc).intSubset).elements }).is_null()
                && (unsafe { (*(*(*ctxt).myDoc).intSubset).attributes }).is_null()
                && (unsafe { (*(*(*ctxt).myDoc).intSubset).entities }).is_null())
    {
        xmlErrValid(
            ctxt,
            XML_DTD_NO_DTD,
            b"Validation failed: no DTD found !\0" as *const u8 as *const i8,
            0 as *const i8,
            0 as *const i8,
        );
        (unsafe { (*ctxt).validate = 0 as i32 });
    }
    if !prefix.is_null() && URI.is_null() {
        if (unsafe { (*ctxt).dictNames }) != 0 {
            let mut fullname: *const xmlChar = 0 as *const xmlChar;
            fullname = unsafe { xmlDictQLookup((*ctxt).dict, prefix, localname) };
            if !fullname.is_null() {
                localname = fullname;
            }
        } else {
            lname = unsafe { xmlBuildQName(localname, prefix, 0 as *mut xmlChar, 0 as i32) };
        }
    }
    if !(unsafe { (*ctxt).freeElems }).is_null() {
        ret = unsafe { (*ctxt).freeElems };
        let fresh82 = unsafe { &mut ((*ctxt).freeElems) };
        *fresh82 = unsafe { (*ret).next };
        let fresh83 = unsafe { &mut ((*ctxt).freeElemsNr) };
        *fresh83 -= 1;
        (unsafe { memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNode>() as u64,
        ) });
        let fresh84 = unsafe { &mut ((*ret).doc) };
        *fresh84 = unsafe { (*ctxt).myDoc };
        (unsafe { (*ret).type_0 = XML_ELEMENT_NODE });
        if (unsafe { (*ctxt).dictNames }) != 0 {
            let fresh85 = unsafe { &mut ((*ret).name) };
            *fresh85 = localname;
        } else {
            if lname.is_null() {
                let fresh86 = unsafe { &mut ((*ret).name) };
                *fresh86 = unsafe { xmlStrdup(localname) };
            } else {
                let fresh87 = unsafe { &mut ((*ret).name) };
                *fresh87 = lname;
            }
            if (unsafe { (*ret).name }).is_null() {
                xmlSAX2ErrMemory(ctxt, b"xmlSAX2StartElementNs\0" as *const u8 as *const i8);
                return;
            }
        }
        if (unsafe { __xmlRegisterCallbacks }) != 0 && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() }) {
            (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(ret) });
        }
    } else {
        if (unsafe { (*ctxt).dictNames }) != 0 {
            ret = unsafe { xmlNewDocNodeEatName(
                (*ctxt).myDoc,
                0 as xmlNsPtr,
                localname as *mut xmlChar,
                0 as *const xmlChar,
            ) };
        } else if lname.is_null() {
            ret = unsafe { xmlNewDocNode((*ctxt).myDoc, 0 as xmlNsPtr, localname, 0 as *const xmlChar) };
        } else {
            ret = unsafe { xmlNewDocNodeEatName((*ctxt).myDoc, 0 as xmlNsPtr, lname, 0 as *const xmlChar) };
        }
        if ret.is_null() {
            xmlSAX2ErrMemory(ctxt, b"xmlSAX2StartElementNs\0" as *const u8 as *const i8);
            return;
        }
    }
    if (unsafe { (*ctxt).linenumbers }) != 0 {
        if !(unsafe { (*ctxt).input }).is_null() {
            if (unsafe { (*(*ctxt).input).line }) < 32767 as i32 * 2 as i32 + 1 as i32 {
                (unsafe { (*ret).line = (*(*ctxt).input).line as u16 });
            } else {
                (unsafe { (*ret).line = (32767 as i32 * 2 as i32 + 1 as i32) as u16 });
            }
        }
    }
    if parent.is_null() {
        (unsafe { xmlAddChild((*ctxt).myDoc as xmlNodePtr, ret) });
    }
    i = 0 as i32;
    j = 0 as i32;
    while j < nb_namespaces {
        let fresh88 = i;
        i = i + 1;
        pref = unsafe { *namespaces.offset(fresh88 as isize) };
        let fresh89 = i;
        i = i + 1;
        uri = unsafe { *namespaces.offset(fresh89 as isize) };
        ns = unsafe { xmlNewNs(0 as xmlNodePtr, uri, pref) };
        if !ns.is_null() {
            if last.is_null() {
                last = ns;
                let fresh90 = unsafe { &mut ((*ret).nsDef) };
                *fresh90 = last;
            } else {
                let fresh91 = unsafe { &mut ((*last).next) };
                *fresh91 = ns;
                last = ns;
            }
            if !URI.is_null() && prefix == pref {
                let fresh92 = unsafe { &mut ((*ret).ns) };
                *fresh92 = ns;
            }
            if (unsafe { (*ctxt).html }) == 0
                && (unsafe { (*ctxt).validate }) != 0
                && (unsafe { (*ctxt).wellFormed }) != 0
                && !(unsafe { (*ctxt).myDoc }).is_null()
                && !(unsafe { (*(*ctxt).myDoc).intSubset }).is_null()
            {
                (unsafe { (*ctxt).valid &= xmlValidateOneNamespace(
                    &mut (*ctxt).vctxt,
                    (*ctxt).myDoc,
                    ret,
                    prefix,
                    ns,
                    uri,
                ) });
            }
        }
        j += 1;
    }
    (unsafe { (*ctxt).nodemem = -(1 as i32) });
    if (unsafe { nodePush(ctxt, ret) }) < 0 as i32 {
        (unsafe { xmlUnlinkNode(ret) });
        (unsafe { xmlFreeNode(ret) });
        return;
    }
    if !parent.is_null() {
        if (unsafe { (*parent).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            (unsafe { xmlAddChild(parent, ret) });
        } else {
            (unsafe { xmlAddSibling(parent, ret) });
        }
    }
    if nb_defaulted != 0 as i32 && (unsafe { (*ctxt).loadsubset }) & 4 as i32 == 0 as i32 {
        nb_attributes -= nb_defaulted;
    }
    if !URI.is_null() && (unsafe { (*ret).ns }).is_null() {
        let fresh93 = unsafe { &mut ((*ret).ns) };
        *fresh93 = unsafe { xmlSearchNs((*ctxt).myDoc, parent, prefix) };
        if (unsafe { (*ret).ns }).is_null()
            && (unsafe { xmlStrEqual(prefix, b"xml\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0
        {
            let fresh94 = unsafe { &mut ((*ret).ns) };
            *fresh94 = unsafe { xmlSearchNs((*ctxt).myDoc, ret, prefix) };
        }
        if (unsafe { (*ret).ns }).is_null() {
            ns = unsafe { xmlNewNs(ret, 0 as *const xmlChar, prefix) };
            if ns.is_null() {
                xmlSAX2ErrMemory(ctxt, b"xmlSAX2StartElementNs\0" as *const u8 as *const i8);
                return;
            }
            if !prefix.is_null() {
                xmlNsWarnMsg(
                    ctxt,
                    XML_NS_ERR_UNDEFINED_NAMESPACE,
                    b"Namespace prefix %s was not found\n\0" as *const u8 as *const i8,
                    prefix,
                    0 as *const xmlChar,
                );
            } else {
                xmlNsWarnMsg(
                    ctxt,
                    XML_NS_ERR_UNDEFINED_NAMESPACE,
                    b"Namespace default prefix was not found\n\0" as *const u8 as *const i8,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
            }
        }
    }
    if nb_attributes > 0 as i32 {
        let mut current_block_110: u64;
        j = 0 as i32;
        i = 0 as i32;
        while i < nb_attributes {
            if !(unsafe { *attributes.offset((j + 1 as i32) as isize) }).is_null()
                && (unsafe { *attributes.offset((j + 2 as i32) as isize) }).is_null()
            {
                if (unsafe { (*ctxt).dictNames }) != 0 {
                    let mut fullname_0: *const xmlChar = 0 as *const xmlChar;
                    fullname_0 = unsafe { xmlDictQLookup(
                        (*ctxt).dict,
                        *attributes.offset((j + 1 as i32) as isize),
                        *attributes.offset(j as isize),
                    ) };
                    if !fullname_0.is_null() {
                        xmlSAX2AttributeNs(
                            ctxt,
                            fullname_0,
                            0 as *const xmlChar,
                            unsafe { *attributes.offset((j + 3 as i32) as isize) },
                            unsafe { *attributes.offset((j + 4 as i32) as isize) },
                        );
                        current_block_110 = 13003737910779602957;
                    } else {
                        current_block_110 = 8304106758420804164;
                    }
                } else {
                    lname = unsafe { xmlBuildQName(
                        *attributes.offset(j as isize),
                        *attributes.offset((j + 1 as i32) as isize),
                        0 as *mut xmlChar,
                        0 as i32,
                    ) };
                    if !lname.is_null() {
                        xmlSAX2AttributeNs(
                            ctxt,
                            lname,
                            0 as *const xmlChar,
                            unsafe { *attributes.offset((j + 3 as i32) as isize) },
                            unsafe { *attributes.offset((j + 4 as i32) as isize) },
                        );
                        (unsafe { xmlFree.expect("non-null function pointer")(lname as *mut libc::c_void) });
                        current_block_110 = 13003737910779602957;
                    } else {
                        current_block_110 = 8304106758420804164;
                    }
                }
            } else {
                current_block_110 = 8304106758420804164;
            }
            match current_block_110 {
                8304106758420804164 => {
                    xmlSAX2AttributeNs(
                        ctxt,
                        unsafe { *attributes.offset(j as isize) },
                        unsafe { *attributes.offset((j + 1 as i32) as isize) },
                        unsafe { *attributes.offset((j + 3 as i32) as isize) },
                        unsafe { *attributes.offset((j + 4 as i32) as isize) },
                    );
                }
                _ => {}
            }
            i += 1;
            j += 5 as i32;
        }
    }
    if (unsafe { (*ctxt).validate }) != 0 && (unsafe { (*ctxt).vctxt.flags }) & (1 as u32) << 0 as i32 == 0 as i32 as u32 {
        let mut chk: i32 = 0;
        chk = unsafe { xmlValidateDtdFinal(&mut (*ctxt).vctxt, (*ctxt).myDoc) };
        if chk <= 0 as i32 {
            (unsafe { (*ctxt).valid = 0 as i32 });
        }
        if chk < 0 as i32 {
            (unsafe { (*ctxt).wellFormed = 0 as i32 });
        }
        (unsafe { (*ctxt).valid &= xmlValidateRoot(&mut (*ctxt).vctxt, (*ctxt).myDoc) });
        (unsafe { (*ctxt).vctxt.flags |= (1 as u32) << 0 as i32 });
    }
}
#[no_mangle]
pub extern "C" fn xmlSAX2EndElementNs(
    mut ctx: *mut libc::c_void,
    mut _localname: *const xmlChar,
    mut _prefix: *const xmlChar,
    mut _URI: *const xmlChar,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut node_info: xmlParserNodeInfo = xmlParserNodeInfo {
        node: 0 as *const _xmlNode,
        begin_pos: 0,
        begin_line: 0,
        end_pos: 0,
        end_line: 0,
    };
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if ctx.is_null() {
        return;
    }
    cur = unsafe { (*ctxt).node };
    if (unsafe { (*ctxt).record_info }) != 0 && !cur.is_null() {
        node_info.end_pos = (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64;
        node_info.end_line = (unsafe { (*(*ctxt).input).line }) as u64;
        node_info.node = cur as *const _xmlNode;
        (unsafe { xmlParserAddNodeInfo(ctxt, &mut node_info) });
    }
    (unsafe { (*ctxt).nodemem = -(1 as i32) });
    if (unsafe { (*ctxt).validate }) != 0
        && (unsafe { (*ctxt).wellFormed }) != 0
        && !(unsafe { (*ctxt).myDoc }).is_null()
        && !(unsafe { (*(*ctxt).myDoc).intSubset }).is_null()
    {
        (unsafe { (*ctxt).valid &= xmlValidateOneElement(&mut (*ctxt).vctxt, (*ctxt).myDoc, cur) });
    }
    (unsafe { nodePop(ctxt) });
}
#[no_mangle]
pub extern "C" fn xmlSAX2Reference(mut ctx: *mut libc::c_void, mut name: *const xmlChar) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    if ctx.is_null() {
        return;
    }
    if (unsafe { *name.offset(0 as i32 as isize) }) as i32 == '#' as i32 {
        ret = unsafe { xmlNewCharRef((*ctxt).myDoc, name) };
    } else {
        ret = unsafe { xmlNewReference((*ctxt).myDoc as *const xmlDoc, name) };
    }
    if (unsafe { xmlAddChild((*ctxt).node, ret) }).is_null() {
        (unsafe { xmlFreeNode(ret) });
    }
}
extern "C" fn xmlSAX2Text(
    mut ctxt: xmlParserCtxtPtr,
    mut ch: *const xmlChar,
    mut len: i32,
    mut type_0: xmlElementType,
) {
    let mut lastChild: xmlNodePtr = 0 as *mut xmlNode;
    if ctxt.is_null() {
        return;
    }
    if (unsafe { (*ctxt).node }).is_null() {
        return;
    }
    lastChild = unsafe { (*(*ctxt).node).last };
    if lastChild.is_null() {
        if type_0 as u32 == XML_TEXT_NODE as i32 as u32 {
            lastChild = xmlSAX2TextNode(ctxt, ch, len);
        } else {
            lastChild = unsafe { xmlNewCDataBlock((*ctxt).myDoc, ch, len) };
        }
        if !lastChild.is_null() {
            let fresh95 = unsafe { &mut ((*(*ctxt).node).children) };
            *fresh95 = lastChild;
            let fresh96 = unsafe { &mut ((*(*ctxt).node).last) };
            *fresh96 = lastChild;
            let fresh97 = unsafe { &mut ((*lastChild).parent) };
            *fresh97 = unsafe { (*ctxt).node };
            let fresh98 = unsafe { &mut ((*lastChild).doc) };
            *fresh98 = unsafe { (*(*ctxt).node).doc };
            (unsafe { (*ctxt).nodelen = len });
            (unsafe { (*ctxt).nodemem = len + 1 as i32 });
        } else {
            xmlSAX2ErrMemory(ctxt, b"xmlSAX2Characters\0" as *const u8 as *const i8);
            return;
        }
    } else {
        let mut coalesceText: i32 = (!lastChild.is_null()
            && (unsafe { (*lastChild).type_0 }) as u32 == type_0 as u32
            && (type_0 as u32 != XML_TEXT_NODE as i32 as u32
                || (unsafe { (*lastChild).name }) == (unsafe { xmlStringText.as_ptr() })))
            as i32;
        if coalesceText != 0 && (unsafe { (*ctxt).nodemem }) != 0 as i32 {
            if (unsafe { (*lastChild).content })
                == (unsafe { &mut (*lastChild).properties }) as *mut *mut _xmlAttr as *mut xmlChar
            {
                let fresh99 = unsafe { &mut ((*lastChild).content) };
                *fresh99 = unsafe { xmlStrdup((*lastChild).content) };
                let fresh100 = unsafe { &mut ((*lastChild).properties) };
                *fresh100 = 0 as *mut _xmlAttr;
            } else if (unsafe { (*ctxt).nodemem }) == (unsafe { (*ctxt).nodelen }) + 1 as i32
                && (unsafe { xmlDictOwns((*ctxt).dict, (*lastChild).content) }) != 0
            {
                let fresh101 = unsafe { &mut ((*lastChild).content) };
                *fresh101 = unsafe { xmlStrdup((*lastChild).content) };
            }
            if (unsafe { (*lastChild).content }).is_null() {
                xmlSAX2ErrMemory(
                    ctxt,
                    b"xmlSAX2Characters: xmlStrdup returned NULL\0" as *const u8 as *const i8,
                );
                return;
            }
            if ((unsafe { (*ctxt).nodelen }) as size_t).wrapping_add(len as size_t) > 10000000 as i32 as u64
                && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
            {
                xmlSAX2ErrMemory(
                    ctxt,
                    b"xmlSAX2Characters: huge text node\0" as *const u8 as *const i8,
                );
                return;
            }
            if (unsafe { (*ctxt).nodelen }) as size_t > (-(1 as i32) as size_t).wrapping_sub(len as size_t)
                || ((unsafe { (*ctxt).nodemem }) as size_t).wrapping_add(len as size_t)
                    > (-(1 as i32) as size_t).wrapping_div(2 as i32 as u64)
            {
                xmlSAX2ErrMemory(
                    ctxt,
                    b"xmlSAX2Characters overflow prevented\0" as *const u8 as *const i8,
                );
                return;
            }
            if (unsafe { (*ctxt).nodelen }) + len >= (unsafe { (*ctxt).nodemem }) {
                let mut newbuf: *mut xmlChar = 0 as *mut xmlChar;
                let mut size: size_t = 0;
                size = ((unsafe { (*ctxt).nodemem }) + len) as size_t;
                size = (size as u64).wrapping_mul(2 as i32 as u64) as size_t as size_t;
                newbuf = (unsafe { xmlRealloc.expect("non-null function pointer")(
                    (*lastChild).content as *mut libc::c_void,
                    size,
                ) }) as *mut xmlChar;
                if newbuf.is_null() {
                    xmlSAX2ErrMemory(ctxt, b"xmlSAX2Characters\0" as *const u8 as *const i8);
                    return;
                }
                (unsafe { (*ctxt).nodemem = size as i32 });
                let fresh102 = unsafe { &mut ((*lastChild).content) };
                *fresh102 = newbuf;
            }
            (unsafe { memcpy(
                &mut *((*lastChild).content).offset((*ctxt).nodelen as isize) as *mut xmlChar
                    as *mut libc::c_void,
                ch as *const libc::c_void,
                len as u64,
            ) });
            (unsafe { (*ctxt).nodelen += len });
            (unsafe { *((*lastChild).content).offset((*ctxt).nodelen as isize) = 0 as i32 as xmlChar });
        } else if coalesceText != 0 {
            if (unsafe { xmlTextConcat(lastChild, ch, len) }) != 0 {
                xmlSAX2ErrMemory(ctxt, b"xmlSAX2Characters\0" as *const u8 as *const i8);
            }
            if !(unsafe { (*(*ctxt).node).children }).is_null() {
                (unsafe { (*ctxt).nodelen = xmlStrlen((*lastChild).content) });
                (unsafe { (*ctxt).nodemem = (*ctxt).nodelen + 1 as i32 });
            }
        } else {
            if type_0 as u32 == XML_TEXT_NODE as i32 as u32 {
                lastChild = xmlSAX2TextNode(ctxt, ch, len);
                let fresh103 = unsafe { &mut ((*lastChild).doc) };
                *fresh103 = unsafe { (*ctxt).myDoc };
            } else {
                lastChild = unsafe { xmlNewCDataBlock((*ctxt).myDoc, ch, len) };
            }
            if !lastChild.is_null() {
                (unsafe { xmlAddChild((*ctxt).node, lastChild) });
                if !(unsafe { (*(*ctxt).node).children }).is_null() {
                    (unsafe { (*ctxt).nodelen = len });
                    (unsafe { (*ctxt).nodemem = len + 1 as i32 });
                }
            }
        }
    };
}
#[no_mangle]
pub extern "C" fn xmlSAX2Characters(
    mut ctx: *mut libc::c_void,
    mut ch: *const xmlChar,
    mut len: i32,
) {
    xmlSAX2Text(ctx as xmlParserCtxtPtr, ch, len, XML_TEXT_NODE);
}
#[no_mangle]
pub extern "C" fn xmlSAX2IgnorableWhitespace(
    mut _ctx: *mut libc::c_void,
    mut _ch: *const xmlChar,
    mut _len: i32,
) {
}
#[no_mangle]
pub extern "C" fn xmlSAX2ProcessingInstruction(
    mut ctx: *mut libc::c_void,
    mut target: *const xmlChar,
    mut data: *const xmlChar,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    if ctx.is_null() {
        return;
    }
    parent = unsafe { (*ctxt).node };
    ret = unsafe { xmlNewDocPI((*ctxt).myDoc, target, data) };
    if ret.is_null() {
        return;
    }
    if (unsafe { (*ctxt).linenumbers }) != 0 {
        if !(unsafe { (*ctxt).input }).is_null() {
            if (unsafe { (*(*ctxt).input).line }) < 32767 as i32 * 2 as i32 + 1 as i32 {
                (unsafe { (*ret).line = (*(*ctxt).input).line as u16 });
            } else {
                (unsafe { (*ret).line = (32767 as i32 * 2 as i32 + 1 as i32) as u16 });
            }
        }
    }
    if (unsafe { (*ctxt).inSubset }) == 1 as i32 {
        (unsafe { xmlAddChild((*(*ctxt).myDoc).intSubset as xmlNodePtr, ret) });
        return;
    } else {
        if (unsafe { (*ctxt).inSubset }) == 2 as i32 {
            (unsafe { xmlAddChild((*(*ctxt).myDoc).extSubset as xmlNodePtr, ret) });
            return;
        }
    }
    if parent.is_null() {
        (unsafe { xmlAddChild((*ctxt).myDoc as xmlNodePtr, ret) });
        return;
    }
    if (unsafe { (*parent).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
        (unsafe { xmlAddChild(parent, ret) });
    } else {
        (unsafe { xmlAddSibling(parent, ret) });
    };
}
#[no_mangle]
pub extern "C" fn xmlSAX2Comment(mut ctx: *mut libc::c_void, mut value: *const xmlChar) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    if ctx.is_null() {
        return;
    }
    parent = unsafe { (*ctxt).node };
    ret = unsafe { xmlNewDocComment((*ctxt).myDoc, value) };
    if ret.is_null() {
        return;
    }
    if (unsafe { (*ctxt).linenumbers }) != 0 {
        if !(unsafe { (*ctxt).input }).is_null() {
            if (unsafe { (*(*ctxt).input).line }) < 32767 as i32 * 2 as i32 + 1 as i32 {
                (unsafe { (*ret).line = (*(*ctxt).input).line as u16 });
            } else {
                (unsafe { (*ret).line = (32767 as i32 * 2 as i32 + 1 as i32) as u16 });
            }
        }
    }
    if (unsafe { (*ctxt).inSubset }) == 1 as i32 {
        (unsafe { xmlAddChild((*(*ctxt).myDoc).intSubset as xmlNodePtr, ret) });
        return;
    } else {
        if (unsafe { (*ctxt).inSubset }) == 2 as i32 {
            (unsafe { xmlAddChild((*(*ctxt).myDoc).extSubset as xmlNodePtr, ret) });
            return;
        }
    }
    if parent.is_null() {
        (unsafe { xmlAddChild((*ctxt).myDoc as xmlNodePtr, ret) });
        return;
    }
    if (unsafe { (*parent).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
        (unsafe { xmlAddChild(parent, ret) });
    } else {
        (unsafe { xmlAddSibling(parent, ret) });
    };
}
#[no_mangle]
pub extern "C" fn xmlSAX2CDataBlock(
    mut ctx: *mut libc::c_void,
    mut value: *const xmlChar,
    mut len: i32,
) {
    xmlSAX2Text(ctx as xmlParserCtxtPtr, value, len, XML_CDATA_SECTION_NODE);
}
static mut xmlSAX2DefaultVersionValue: i32 = 2 as i32;
#[no_mangle]
pub extern "C" fn xmlSAXDefaultVersion(mut version: i32) -> i32 {
    let mut ret: i32 = unsafe { xmlSAX2DefaultVersionValue };
    if version != 1 as i32 && version != 2 as i32 {
        return -(1 as i32);
    }
    (unsafe { xmlSAX2DefaultVersionValue = version });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSAXVersion(mut hdlr: *mut xmlSAXHandler, mut version: i32) -> i32 {
    if hdlr.is_null() {
        return -(1 as i32);
    }
    if version == 2 as i32 {
        let fresh104 = unsafe { &mut ((*hdlr).startElement) };
        *fresh104 = None;
        let fresh105 = unsafe { &mut ((*hdlr).endElement) };
        *fresh105 = None;
        let fresh106 = unsafe { &mut ((*hdlr).startElementNs) };
        *fresh106 = Some(
            xmlSAX2StartElementNs
                as unsafe extern "C" fn(
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
        );
        let fresh107 = unsafe { &mut ((*hdlr).endElementNs) };
        *fresh107 = Some(
            xmlSAX2EndElementNs
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const xmlChar,
                    *const xmlChar,
                    *const xmlChar,
                ) -> (),
        );
        let fresh108 = unsafe { &mut ((*hdlr).serror) };
        *fresh108 = None;
        (unsafe { (*hdlr).initialized = 0xdeedbeaf as u32 });
    } else if version == 1 as i32 {
        let fresh109 = unsafe { &mut ((*hdlr).startElement) };
        *fresh109 = Some(
            xmlSAX2StartElement
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const xmlChar,
                    *mut *const xmlChar,
                ) -> (),
        );
        let fresh110 = unsafe { &mut ((*hdlr).endElement) };
        *fresh110 = Some(
            xmlSAX2EndElement as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        );
        (unsafe { (*hdlr).initialized = 1 as i32 as u32 });
    } else {
        return -(1 as i32);
    }
    let fresh111 = unsafe { &mut ((*hdlr).internalSubset) };
    *fresh111 = Some(
        xmlSAX2InternalSubset
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh112 = unsafe { &mut ((*hdlr).externalSubset) };
    *fresh112 = Some(
        xmlSAX2ExternalSubset
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh113 = unsafe { &mut ((*hdlr).isStandalone) };
    *fresh113 = Some(xmlSAX2IsStandalone as unsafe extern "C" fn(*mut libc::c_void) -> i32);
    let fresh114 = unsafe { &mut ((*hdlr).hasInternalSubset) };
    *fresh114 = Some(xmlSAX2HasInternalSubset as unsafe extern "C" fn(*mut libc::c_void) -> i32);
    let fresh115 = unsafe { &mut ((*hdlr).hasExternalSubset) };
    *fresh115 = Some(xmlSAX2HasExternalSubset as unsafe extern "C" fn(*mut libc::c_void) -> i32);
    let fresh116 = unsafe { &mut ((*hdlr).resolveEntity) };
    *fresh116 = Some(
        xmlSAX2ResolveEntity
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
            ) -> xmlParserInputPtr,
    );
    let fresh117 = unsafe { &mut ((*hdlr).getEntity) };
    *fresh117 = Some(
        xmlSAX2GetEntity as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
    );
    let fresh118 = unsafe { &mut ((*hdlr).getParameterEntity) };
    *fresh118 = Some(
        xmlSAX2GetParameterEntity
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
    );
    let fresh119 = unsafe { &mut ((*hdlr).entityDecl) };
    *fresh119 = Some(
        xmlSAX2EntityDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                i32,
                *const xmlChar,
                *const xmlChar,
                *mut xmlChar,
            ) -> (),
    );
    let fresh120 = unsafe { &mut ((*hdlr).attributeDecl) };
    *fresh120 = Some(
        xmlSAX2AttributeDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                i32,
                i32,
                *const xmlChar,
                xmlEnumerationPtr,
            ) -> (),
    );
    let fresh121 = unsafe { &mut ((*hdlr).elementDecl) };
    *fresh121 = Some(
        xmlSAX2ElementDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                i32,
                xmlElementContentPtr,
            ) -> (),
    );
    let fresh122 = unsafe { &mut ((*hdlr).notationDecl) };
    *fresh122 = Some(
        xmlSAX2NotationDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh123 = unsafe { &mut ((*hdlr).unparsedEntityDecl) };
    *fresh123 = Some(
        xmlSAX2UnparsedEntityDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh124 = unsafe { &mut ((*hdlr).setDocumentLocator) };
    *fresh124 = Some(
        xmlSAX2SetDocumentLocator
            as unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
    );
    let fresh125 = unsafe { &mut ((*hdlr).startDocument) };
    *fresh125 = Some(xmlSAX2StartDocument as unsafe extern "C" fn(*mut libc::c_void) -> ());
    let fresh126 = unsafe { &mut ((*hdlr).endDocument) };
    *fresh126 = Some(xmlSAX2EndDocument as unsafe extern "C" fn(*mut libc::c_void) -> ());
    let fresh127 = unsafe { &mut ((*hdlr).reference) };
    *fresh127 =
        Some(xmlSAX2Reference as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ());
    let fresh128 = unsafe { &mut ((*hdlr).characters) };
    *fresh128 = Some(
        xmlSAX2Characters as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh129 = unsafe { &mut ((*hdlr).cdataBlock) };
    *fresh129 = Some(
        xmlSAX2CDataBlock as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh130 = unsafe { &mut ((*hdlr).ignorableWhitespace) };
    *fresh130 = Some(
        xmlSAX2Characters as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh131 = unsafe { &mut ((*hdlr).processingInstruction) };
    *fresh131 = Some(
        xmlSAX2ProcessingInstruction
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> (),
    );
    let fresh132 = unsafe { &mut ((*hdlr).comment) };
    *fresh132 =
        Some(xmlSAX2Comment as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ());
    let fresh133 = unsafe { &mut ((*hdlr).warning) };
    *fresh133 =
        Some(xmlParserWarning as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
    let fresh134 = unsafe { &mut ((*hdlr).error) };
    *fresh134 =
        Some(xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
    let fresh135 = unsafe { &mut ((*hdlr).fatalError) };
    *fresh135 =
        Some(xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlSAX2InitDefaultSAXHandler(mut hdlr: *mut xmlSAXHandler, mut warning: i32) {
    if hdlr.is_null() || (unsafe { (*hdlr).initialized }) != 0 as i32 as u32 {
        return;
    }
    xmlSAXVersion(hdlr, unsafe { xmlSAX2DefaultVersionValue });
    if warning == 0 as i32 {
        let fresh136 = unsafe { &mut ((*hdlr).warning) };
        *fresh136 = None;
    } else {
        let fresh137 = unsafe { &mut ((*hdlr).warning) };
        *fresh137 =
            Some(xmlParserWarning as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
    };
}
#[no_mangle]
pub extern "C" fn xmlDefaultSAXHandlerInit() {
    xmlSAXVersion((unsafe { __xmlDefaultSAXHandler() }) as xmlSAXHandlerPtr, 1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlSAX2InitHtmlDefaultSAXHandler(mut hdlr: *mut xmlSAXHandler) {
    if hdlr.is_null() || (unsafe { (*hdlr).initialized }) != 0 as i32 as u32 {
        return;
    }
    let fresh138 = unsafe { &mut ((*hdlr).internalSubset) };
    *fresh138 = Some(
        xmlSAX2InternalSubset
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh139 = unsafe { &mut ((*hdlr).externalSubset) };
    *fresh139 = None;
    let fresh140 = unsafe { &mut ((*hdlr).isStandalone) };
    *fresh140 = None;
    let fresh141 = unsafe { &mut ((*hdlr).hasInternalSubset) };
    *fresh141 = None;
    let fresh142 = unsafe { &mut ((*hdlr).hasExternalSubset) };
    *fresh142 = None;
    let fresh143 = unsafe { &mut ((*hdlr).resolveEntity) };
    *fresh143 = None;
    let fresh144 = unsafe { &mut ((*hdlr).getEntity) };
    *fresh144 = Some(
        xmlSAX2GetEntity as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
    );
    let fresh145 = unsafe { &mut ((*hdlr).getParameterEntity) };
    *fresh145 = None;
    let fresh146 = unsafe { &mut ((*hdlr).entityDecl) };
    *fresh146 = None;
    let fresh147 = unsafe { &mut ((*hdlr).attributeDecl) };
    *fresh147 = None;
    let fresh148 = unsafe { &mut ((*hdlr).elementDecl) };
    *fresh148 = None;
    let fresh149 = unsafe { &mut ((*hdlr).notationDecl) };
    *fresh149 = None;
    let fresh150 = unsafe { &mut ((*hdlr).unparsedEntityDecl) };
    *fresh150 = None;
    let fresh151 = unsafe { &mut ((*hdlr).setDocumentLocator) };
    *fresh151 = Some(
        xmlSAX2SetDocumentLocator
            as unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
    );
    let fresh152 = unsafe { &mut ((*hdlr).startDocument) };
    *fresh152 = Some(xmlSAX2StartDocument as unsafe extern "C" fn(*mut libc::c_void) -> ());
    let fresh153 = unsafe { &mut ((*hdlr).endDocument) };
    *fresh153 = Some(xmlSAX2EndDocument as unsafe extern "C" fn(*mut libc::c_void) -> ());
    let fresh154 = unsafe { &mut ((*hdlr).startElement) };
    *fresh154 = Some(
        xmlSAX2StartElement
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *mut *const xmlChar) -> (),
    );
    let fresh155 = unsafe { &mut ((*hdlr).endElement) };
    *fresh155 =
        Some(xmlSAX2EndElement as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ());
    let fresh156 = unsafe { &mut ((*hdlr).reference) };
    *fresh156 = None;
    let fresh157 = unsafe { &mut ((*hdlr).characters) };
    *fresh157 = Some(
        xmlSAX2Characters as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh158 = unsafe { &mut ((*hdlr).cdataBlock) };
    *fresh158 = Some(
        xmlSAX2CDataBlock as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh159 = unsafe { &mut ((*hdlr).ignorableWhitespace) };
    *fresh159 = Some(
        xmlSAX2IgnorableWhitespace
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh160 = unsafe { &mut ((*hdlr).processingInstruction) };
    *fresh160 = Some(
        xmlSAX2ProcessingInstruction
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> (),
    );
    let fresh161 = unsafe { &mut ((*hdlr).comment) };
    *fresh161 =
        Some(xmlSAX2Comment as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ());
    let fresh162 = unsafe { &mut ((*hdlr).warning) };
    *fresh162 =
        Some(xmlParserWarning as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
    let fresh163 = unsafe { &mut ((*hdlr).error) };
    *fresh163 =
        Some(xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
    let fresh164 = unsafe { &mut ((*hdlr).fatalError) };
    *fresh164 =
        Some(xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
    (unsafe { (*hdlr).initialized = 1 as i32 as u32 });
}
#[no_mangle]
pub extern "C" fn htmlDefaultSAXHandlerInit() {
    xmlSAX2InitHtmlDefaultSAXHandler((unsafe { __htmlDefaultSAXHandler() }) as xmlSAXHandlerPtr);
}
