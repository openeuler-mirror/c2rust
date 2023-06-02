use :: libc;
extern "C" {
    pub type _xmlBuf;
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlStartTag;
    pub type _xmlAutomataState;
    pub type _xmlAutomata;
    pub type _xmlValidState;
    pub type _xmlRelaxNG;
    pub type _xmlRelaxNGParserCtxt;
    pub type _xmlRelaxNGValidCtxt;
    pub type _xmlSchema;
    pub type _xmlSchemaParserCtxt;
    pub type _xmlSchemaValidCtxt;
    pub type _xmlSchemaSAXPlug;
    pub type _xmlPattern;
    pub type _xmlXIncludeCtxt;
    fn vsnprintf(_: *mut i8, _: u64, _: *const i8, _: ::std::ffi::VaList) -> i32;
    fn xmlStrcat(cur: *mut xmlChar, add: *const xmlChar) -> *mut xmlChar;
    fn xmlStrlen(str: *const xmlChar) -> i32;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    static mut __xmlRegisterCallbacks: i32;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn xmlBufContent(buf: *const xmlBuf) -> *mut xmlChar;
    fn xmlBufUse(buf: xmlBufPtr) -> size_t;
    fn xmlBufShrink(buf: xmlBufPtr, len: size_t) -> size_t;
    fn xmlDictCreate() -> xmlDictPtr;
    fn xmlDictFree(dict: xmlDictPtr);
    fn xmlDictLookup(dict: xmlDictPtr, name: *const xmlChar, len: i32) -> *const xmlChar;
    fn xmlDictQLookup(
        dict: xmlDictPtr,
        prefix: *const xmlChar,
        name: *const xmlChar,
    ) -> *const xmlChar;
    fn xmlDictOwns(dict: xmlDictPtr, str: *const xmlChar) -> i32;
    fn xmlSplitQName2(name: *const xmlChar, prefix: *mut *mut xmlChar) -> *mut xmlChar;
    fn xmlBufferCreate() -> xmlBufferPtr;
    fn xmlBufferFree(buf: xmlBufferPtr);
    fn xmlBufferCat(buf: xmlBufferPtr, str: *const xmlChar) -> i32;
    fn xmlBufferSetAllocationScheme(buf: xmlBufferPtr, scheme: xmlBufferAllocationScheme);
    fn xmlFreeDtd(cur: xmlDtdPtr);
    fn xmlFreeNs(cur: xmlNsPtr);
    fn xmlFreeNsList(cur: xmlNsPtr);
    fn xmlFreeDoc(cur: xmlDocPtr);
    fn xmlCopyDtd(dtd: xmlDtdPtr) -> xmlDtdPtr;
    fn xmlNewDocText(doc: *const xmlDoc, content: *const xmlChar) -> xmlNodePtr;
    fn xmlDocCopyNode(node: xmlNodePtr, doc: xmlDocPtr, recursive: i32) -> xmlNodePtr;
    fn xmlGetLineNo(node: *const xmlNode) -> i64;
    fn xmlIsBlankNode(node: *const xmlNode) -> i32;
    fn xmlUnlinkNode(cur: xmlNodePtr);
    fn xmlFreeNode(cur: xmlNodePtr);
    fn xmlSearchNs(doc: xmlDocPtr, node: xmlNodePtr, nameSpace: *const xmlChar) -> xmlNsPtr;
    fn xmlGetNoNsProp(node: *const xmlNode, name: *const xmlChar) -> *mut xmlChar;
    fn xmlGetNsProp(
        node: *const xmlNode,
        name: *const xmlChar,
        nameSpace: *const xmlChar,
    ) -> *mut xmlChar;
    fn xmlNodeListGetString(doc: xmlDocPtr, list: *const xmlNode, inLine: i32) -> *mut xmlChar;
    fn xmlBufGetNodeContent(buf: xmlBufPtr, cur: *const xmlNode) -> i32;
    fn xmlNodeGetLang(cur: *const xmlNode) -> *mut xmlChar;
    fn xmlNodeGetSpacePreserve(cur: *const xmlNode) -> i32;
    fn xmlNodeGetBase(doc: *const xmlDoc, cur: *const xmlNode) -> *mut xmlChar;
    fn xmlNodeDump(
        buf: xmlBufferPtr,
        doc: xmlDocPtr,
        cur: xmlNodePtr,
        level: i32,
        format: i32,
    ) -> i32;
    fn xmlParserError(ctx: *mut libc::c_void, msg: *const i8, _: ...);
    fn xmlParserWarning(ctx: *mut libc::c_void, msg: *const i8, _: ...);
    fn xmlParserValidityError(ctx: *mut libc::c_void, msg: *const i8, _: ...);
    fn xmlParserValidityWarning(ctx: *mut libc::c_void, msg: *const i8, _: ...);
    fn xmlFreeIDTable(table: xmlIDTablePtr);
    fn xmlFreeRefTable(table: xmlRefTablePtr);
    fn xmlValidatePushElement(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        qname: *const xmlChar,
    ) -> i32;
    fn xmlValidatePushCData(ctxt: xmlValidCtxtPtr, data: *const xmlChar, len: i32) -> i32;
    fn xmlValidatePopElement(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        qname: *const xmlChar,
    ) -> i32;
    fn xmlFindCharEncodingHandler(name: *const i8) -> xmlCharEncodingHandlerPtr;
    fn xmlAllocParserInputBuffer(enc: xmlCharEncoding) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferCreateFilename(
        URI: *const i8,
        enc: xmlCharEncoding,
    ) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferCreateFd(fd: i32, enc: xmlCharEncoding) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferCreateStatic(
        mem: *const i8,
        size: i32,
        enc: xmlCharEncoding,
    ) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferCreateIO(
        ioread: xmlInputReadCallback,
        ioclose: xmlInputCloseCallback,
        ioctx: *mut libc::c_void,
        enc: xmlCharEncoding,
    ) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferRead(in_0: xmlParserInputBufferPtr, len: i32) -> i32;
    fn xmlFreeParserInputBuffer(in_0: xmlParserInputBufferPtr);
    fn xmlParserGetDirectory(filename: *const i8) -> *mut i8;
    fn xmlStopParser(ctxt: xmlParserCtxtPtr);
    fn xmlFreeParserCtxt(ctxt: xmlParserCtxtPtr);
    fn xmlCreatePushParserCtxt(
        sax: xmlSAXHandlerPtr,
        user_data: *mut libc::c_void,
        chunk: *const i8,
        size: i32,
        filename: *const i8,
    ) -> xmlParserCtxtPtr;
    fn xmlParseChunk(ctxt: xmlParserCtxtPtr, chunk: *const i8, size: i32, terminate: i32) -> i32;
    fn xmlSAXVersion(hdlr: *mut xmlSAXHandler, version: i32) -> i32;
    static mut xmlMalloc: xmlMallocFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlFree: xmlFreeFunc;
    fn __xmlGenericError() -> *mut xmlGenericErrorFunc;
    fn __xmlGenericErrorContext() -> *mut *mut libc::c_void;
    fn __xmlDeregisterNodeDefaultValue() -> *mut xmlDeregisterNodeFunc;
    fn xmlCtxtUseOptions(ctxt: xmlParserCtxtPtr, options: i32) -> i32;
    fn xmlCtxtReset(ctxt: xmlParserCtxtPtr);
    fn xmlByteConsumed(ctxt: xmlParserCtxtPtr) -> i64;
    fn xmlRelaxNGFree(schema: xmlRelaxNGPtr);
    fn xmlRelaxNGSetValidErrors(
        ctxt: xmlRelaxNGValidCtxtPtr,
        err: xmlRelaxNGValidityErrorFunc,
        warn: xmlRelaxNGValidityWarningFunc,
        ctx: *mut libc::c_void,
    );
    fn xmlRelaxNGParse(ctxt: xmlRelaxNGParserCtxtPtr) -> xmlRelaxNGPtr;
    fn xmlRelaxNGSetValidStructuredErrors(
        ctxt: xmlRelaxNGValidCtxtPtr,
        serror: xmlStructuredErrorFunc,
        ctx: *mut libc::c_void,
    );
    fn xmlRelaxNGNewValidCtxt(schema: xmlRelaxNGPtr) -> xmlRelaxNGValidCtxtPtr;
    fn xmlRelaxNGFreeValidCtxt(ctxt: xmlRelaxNGValidCtxtPtr);
    fn xmlRelaxNGValidatePushElement(
        ctxt: xmlRelaxNGValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
    ) -> i32;
    fn xmlRelaxNGValidatePushCData(
        ctxt: xmlRelaxNGValidCtxtPtr,
        data: *const xmlChar,
        len: i32,
    ) -> i32;
    fn xmlRelaxNGValidatePopElement(
        ctxt: xmlRelaxNGValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
    ) -> i32;
    fn xmlRelaxNGValidateFullElement(
        ctxt: xmlRelaxNGValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
    ) -> i32;
    fn xmlRelaxNGNewParserCtxt(URL: *const i8) -> xmlRelaxNGParserCtxtPtr;
    fn xmlRelaxNGFreeParserCtxt(ctxt: xmlRelaxNGParserCtxtPtr);
    fn xmlRelaxNGSetParserErrors(
        ctxt: xmlRelaxNGParserCtxtPtr,
        err: xmlRelaxNGValidityErrorFunc,
        warn: xmlRelaxNGValidityWarningFunc,
        ctx: *mut libc::c_void,
    );
    fn xmlSchemaIsValid(ctxt: xmlSchemaValidCtxtPtr) -> i32;
    fn xmlSchemaFreeParserCtxt(ctxt: xmlSchemaParserCtxtPtr);
    fn xmlSchemaSetParserErrors(
        ctxt: xmlSchemaParserCtxtPtr,
        err: xmlSchemaValidityErrorFunc,
        warn: xmlSchemaValidityWarningFunc,
        ctx: *mut libc::c_void,
    );
    fn xmlSchemaNewParserCtxt(URL: *const i8) -> xmlSchemaParserCtxtPtr;
    fn xmlSchemaFreeValidCtxt(ctxt: xmlSchemaValidCtxtPtr);
    fn xmlSchemaParse(ctxt: xmlSchemaParserCtxtPtr) -> xmlSchemaPtr;
    fn xmlSchemaFree(schema: xmlSchemaPtr);
    fn xmlSchemaSetValidErrors(
        ctxt: xmlSchemaValidCtxtPtr,
        err: xmlSchemaValidityErrorFunc,
        warn: xmlSchemaValidityWarningFunc,
        ctx: *mut libc::c_void,
    );
    fn xmlSchemaNewValidCtxt(schema: xmlSchemaPtr) -> xmlSchemaValidCtxtPtr;
    fn xmlSchemaSetValidStructuredErrors(
        ctxt: xmlSchemaValidCtxtPtr,
        serror: xmlStructuredErrorFunc,
        ctx: *mut libc::c_void,
    );
    fn xmlSchemaSAXPlug(
        ctxt: xmlSchemaValidCtxtPtr,
        sax: *mut xmlSAXHandlerPtr,
        user_data: *mut *mut libc::c_void,
    ) -> xmlSchemaSAXPlugPtr;
    fn xmlSchemaSAXUnplug(plug: xmlSchemaSAXPlugPtr) -> i32;
    fn xmlSchemaValidateSetLocator(
        vctxt: xmlSchemaValidCtxtPtr,
        f: xmlSchemaValidityLocatorFunc,
        ctxt: *mut libc::c_void,
    );
    fn xmlSwitchToEncoding(ctxt: xmlParserCtxtPtr, handler: xmlCharEncodingHandlerPtr) -> i32;
    fn xmlNewInputStream(ctxt: xmlParserCtxtPtr) -> xmlParserInputPtr;
    fn inputPush(ctxt: xmlParserCtxtPtr, value: xmlParserInputPtr) -> i32;
    fn xmlCanonicPath(path: *const xmlChar) -> *mut xmlChar;
    fn xmlXIncludeNewContext(doc: xmlDocPtr) -> xmlXIncludeCtxtPtr;
    fn xmlXIncludeSetFlags(ctxt: xmlXIncludeCtxtPtr, flags: i32) -> i32;
    fn xmlXIncludeFreeContext(ctxt: xmlXIncludeCtxtPtr);
    fn xmlXIncludeProcessNode(ctxt: xmlXIncludeCtxtPtr, tree: xmlNodePtr) -> i32;
    fn xmlFreePattern(comp: xmlPatternPtr);
    fn xmlPatterncompile(
        pattern: *const xmlChar,
        dict: *mut xmlDict,
        flags: i32,
        namespaces: *mut *const xmlChar,
    ) -> xmlPatternPtr;
    fn xmlPatternMatch(comp: xmlPatternPtr, node: xmlNodePtr) -> i32;
    fn xmlBufCreateSize(size: size_t) -> xmlBufPtr;
    fn xmlBufSetAllocationScheme(buf: xmlBufPtr, scheme: xmlBufferAllocationScheme) -> i32;
    fn xmlBufGetAllocationScheme(buf: xmlBufPtr) -> i32;
    fn xmlBufFree(buf: xmlBufPtr);
    fn xmlBufEmpty(buf: xmlBufPtr);
    fn xmlBufResetInput(buf: xmlBufPtr, input: xmlParserInputPtr) -> i32;
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
pub type xmlSAXHandler = _xmlSAXHandler;
pub type xmlSAXHandlerPtr = *mut xmlSAXHandler;
pub type xmlBufferAllocationScheme = u32;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlBuffer {
    pub content: *mut xmlChar,
    pub use_0: u32,
    pub size: u32,
    pub alloc: xmlBufferAllocationScheme,
    pub contentIO: *mut xmlChar,
}
pub type xmlBuffer = _xmlBuffer;
pub type xmlBufferPtr = *mut xmlBuffer;
pub type xmlNsPtr = *mut xmlNs;
pub type xmlDtd = _xmlDtd;
pub type xmlDtdPtr = *mut xmlDtd;
pub type xmlGenericErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type xmlValidCtxtPtr = *mut xmlValidCtxt;
pub type xmlIDTable = _xmlHashTable;
pub type xmlIDTablePtr = *mut xmlIDTable;
pub type xmlRefTable = _xmlHashTable;
pub type xmlRefTablePtr = *mut xmlRefTable;
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
pub type C2RustUnnamed = u32;
pub const XML_PARSE_BIG_LINES: C2RustUnnamed = 4194304;
pub const XML_PARSE_IGNORE_ENC: C2RustUnnamed = 2097152;
pub const XML_PARSE_OLDSAX: C2RustUnnamed = 1048576;
pub const XML_PARSE_HUGE: C2RustUnnamed = 524288;
pub const XML_PARSE_NOBASEFIX: C2RustUnnamed = 262144;
pub const XML_PARSE_OLD10: C2RustUnnamed = 131072;
pub const XML_PARSE_COMPACT: C2RustUnnamed = 65536;
pub const XML_PARSE_NOXINCNODE: C2RustUnnamed = 32768;
pub const XML_PARSE_NOCDATA: C2RustUnnamed = 16384;
pub const XML_PARSE_NSCLEAN: C2RustUnnamed = 8192;
pub const XML_PARSE_NODICT: C2RustUnnamed = 4096;
pub const XML_PARSE_NONET: C2RustUnnamed = 2048;
pub const XML_PARSE_XINCLUDE: C2RustUnnamed = 1024;
pub const XML_PARSE_SAX1: C2RustUnnamed = 512;
pub const XML_PARSE_NOBLANKS: C2RustUnnamed = 256;
pub const XML_PARSE_PEDANTIC: C2RustUnnamed = 128;
pub const XML_PARSE_NOWARNING: C2RustUnnamed = 64;
pub const XML_PARSE_NOERROR: C2RustUnnamed = 32;
pub const XML_PARSE_DTDVALID: C2RustUnnamed = 16;
pub const XML_PARSE_DTDATTR: C2RustUnnamed = 8;
pub const XML_PARSE_DTDLOAD: C2RustUnnamed = 4;
pub const XML_PARSE_NOENT: C2RustUnnamed = 2;
pub const XML_PARSE_RECOVER: C2RustUnnamed = 1;
pub type xmlDeregisterNodeFunc = Option<unsafe extern "C" fn(xmlNodePtr) -> ()>;
pub type xmlRelaxNG = _xmlRelaxNG;
pub type xmlRelaxNGPtr = *mut xmlRelaxNG;
pub type xmlRelaxNGValidityErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type xmlRelaxNGValidityWarningFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type xmlRelaxNGParserCtxt = _xmlRelaxNGParserCtxt;
pub type xmlRelaxNGParserCtxtPtr = *mut xmlRelaxNGParserCtxt;
pub type xmlRelaxNGValidCtxt = _xmlRelaxNGValidCtxt;
pub type xmlRelaxNGValidCtxtPtr = *mut xmlRelaxNGValidCtxt;
pub type xmlSchema = _xmlSchema;
pub type xmlSchemaPtr = *mut xmlSchema;
pub type xmlSchemaValidityErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type xmlSchemaValidityWarningFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type xmlSchemaParserCtxt = _xmlSchemaParserCtxt;
pub type xmlSchemaParserCtxtPtr = *mut xmlSchemaParserCtxt;
pub type xmlSchemaValidCtxt = _xmlSchemaValidCtxt;
pub type xmlSchemaValidCtxtPtr = *mut xmlSchemaValidCtxt;
pub type xmlSchemaValidityLocatorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *mut *const i8, *mut u64) -> i32>;
pub type xmlSchemaSAXPlugStruct = _xmlSchemaSAXPlug;
pub type xmlSchemaSAXPlugPtr = *mut xmlSchemaSAXPlugStruct;
pub type xmlParserSeverities = u32;
pub const XML_PARSER_SEVERITY_ERROR: xmlParserSeverities = 4;
pub const XML_PARSER_SEVERITY_WARNING: xmlParserSeverities = 3;
pub const XML_PARSER_SEVERITY_VALIDITY_ERROR: xmlParserSeverities = 2;
pub const XML_PARSER_SEVERITY_VALIDITY_WARNING: xmlParserSeverities = 1;
pub type C2RustUnnamed_0 = u32;
pub const XML_TEXTREADER_MODE_READING: C2RustUnnamed_0 = 5;
pub const XML_TEXTREADER_MODE_CLOSED: C2RustUnnamed_0 = 4;
pub const XML_TEXTREADER_MODE_EOF: C2RustUnnamed_0 = 3;
pub const XML_TEXTREADER_MODE_ERROR: C2RustUnnamed_0 = 2;
pub const XML_TEXTREADER_MODE_INTERACTIVE: C2RustUnnamed_0 = 1;
pub const XML_TEXTREADER_MODE_INITIAL: C2RustUnnamed_0 = 0;
pub type xmlParserProperties = u32;
pub const XML_PARSER_SUBST_ENTITIES: xmlParserProperties = 4;
pub const XML_PARSER_VALIDATE: xmlParserProperties = 3;
pub const XML_PARSER_DEFAULTATTRS: xmlParserProperties = 2;
pub const XML_PARSER_LOADDTD: xmlParserProperties = 1;
pub type C2RustUnnamed_1 = u32;
pub const XML_READER_TYPE_XML_DECLARATION: C2RustUnnamed_1 = 17;
pub const XML_READER_TYPE_END_ENTITY: C2RustUnnamed_1 = 16;
pub const XML_READER_TYPE_END_ELEMENT: C2RustUnnamed_1 = 15;
pub const XML_READER_TYPE_SIGNIFICANT_WHITESPACE: C2RustUnnamed_1 = 14;
pub const XML_READER_TYPE_WHITESPACE: C2RustUnnamed_1 = 13;
pub const XML_READER_TYPE_NOTATION: C2RustUnnamed_1 = 12;
pub const XML_READER_TYPE_DOCUMENT_FRAGMENT: C2RustUnnamed_1 = 11;
pub const XML_READER_TYPE_DOCUMENT_TYPE: C2RustUnnamed_1 = 10;
pub const XML_READER_TYPE_DOCUMENT: C2RustUnnamed_1 = 9;
pub const XML_READER_TYPE_COMMENT: C2RustUnnamed_1 = 8;
pub const XML_READER_TYPE_PROCESSING_INSTRUCTION: C2RustUnnamed_1 = 7;
pub const XML_READER_TYPE_ENTITY: C2RustUnnamed_1 = 6;
pub const XML_READER_TYPE_ENTITY_REFERENCE: C2RustUnnamed_1 = 5;
pub const XML_READER_TYPE_CDATA: C2RustUnnamed_1 = 4;
pub const XML_READER_TYPE_TEXT: C2RustUnnamed_1 = 3;
pub const XML_READER_TYPE_ATTRIBUTE: C2RustUnnamed_1 = 2;
pub const XML_READER_TYPE_ELEMENT: C2RustUnnamed_1 = 1;
pub const XML_READER_TYPE_NONE: C2RustUnnamed_1 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlTextReader {
    pub mode: i32,
    pub doc: xmlDocPtr,
    pub validate: xmlTextReaderValidate,
    pub allocs: i32,
    pub state: xmlTextReaderState,
    pub ctxt: xmlParserCtxtPtr,
    pub sax: xmlSAXHandlerPtr,
    pub input: xmlParserInputBufferPtr,
    pub startElement: startElementSAXFunc,
    pub endElement: endElementSAXFunc,
    pub startElementNs: startElementNsSAX2Func,
    pub endElementNs: endElementNsSAX2Func,
    pub characters: charactersSAXFunc,
    pub cdataBlock: cdataBlockSAXFunc,
    pub base: u32,
    pub cur: u32,
    pub node: xmlNodePtr,
    pub curnode: xmlNodePtr,
    pub depth: i32,
    pub faketext: xmlNodePtr,
    pub preserve: i32,
    pub buffer: xmlBufPtr,
    pub dict: xmlDictPtr,
    pub ent: xmlNodePtr,
    pub entNr: i32,
    pub entMax: i32,
    pub entTab: *mut xmlNodePtr,
    pub errorFunc: xmlTextReaderErrorFunc,
    pub errorFuncArg: *mut libc::c_void,
    pub rngSchemas: xmlRelaxNGPtr,
    pub rngValidCtxt: xmlRelaxNGValidCtxtPtr,
    pub rngPreserveCtxt: i32,
    pub rngValidErrors: i32,
    pub rngFullNode: xmlNodePtr,
    pub xsdSchemas: xmlSchemaPtr,
    pub xsdValidCtxt: xmlSchemaValidCtxtPtr,
    pub xsdPreserveCtxt: i32,
    pub xsdValidErrors: i32,
    pub xsdPlug: xmlSchemaSAXPlugPtr,
    pub xinclude: i32,
    pub xinclude_name: *const xmlChar,
    pub xincctxt: xmlXIncludeCtxtPtr,
    pub in_xinclude: i32,
    pub patternNr: i32,
    pub patternMax: i32,
    pub patternTab: *mut xmlPatternPtr,
    pub preserves: i32,
    pub parserFlags: i32,
    pub sErrorFunc: xmlStructuredErrorFunc,
}
pub type xmlPatternPtr = *mut xmlPattern;
pub type xmlPattern = _xmlPattern;
pub type xmlXIncludeCtxtPtr = *mut xmlXIncludeCtxt;
pub type xmlXIncludeCtxt = _xmlXIncludeCtxt;
pub type xmlTextReaderErrorFunc = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const i8,
        xmlParserSeverities,
        xmlTextReaderLocatorPtr,
    ) -> (),
>;
pub type xmlTextReaderLocatorPtr = *mut libc::c_void;
pub type xmlTextReaderState = i32;
pub const XML_TEXTREADER_ERROR: xmlTextReaderState = 6;
pub const XML_TEXTREADER_DONE: xmlTextReaderState = 5;
pub const XML_TEXTREADER_BACKTRACK: xmlTextReaderState = 4;
pub const XML_TEXTREADER_EMPTY: xmlTextReaderState = 3;
pub const XML_TEXTREADER_END: xmlTextReaderState = 2;
pub const XML_TEXTREADER_ELEMENT: xmlTextReaderState = 1;
pub const XML_TEXTREADER_START: xmlTextReaderState = 0;
pub const XML_TEXTREADER_NONE: xmlTextReaderState = -1;
pub type xmlTextReaderValidate = u32;
pub const XML_TEXTREADER_VALIDATE_XSD: xmlTextReaderValidate = 4;
pub const XML_TEXTREADER_VALIDATE_RNG: xmlTextReaderValidate = 2;
pub const XML_TEXTREADER_VALIDATE_DTD: xmlTextReaderValidate = 1;
pub const XML_TEXTREADER_NOT_VALIDATE: xmlTextReaderValidate = 0;
pub type xmlTextReader = _xmlTextReader;
pub type xmlTextReaderPtr = *mut xmlTextReader;
extern "C" fn xmlTextReaderFreeProp(mut reader: xmlTextReaderPtr, mut cur: xmlAttrPtr) {
    let mut dict: xmlDictPtr = 0 as *mut xmlDict;
    if !reader.is_null() && !(unsafe { (*reader).ctxt }).is_null() {
        dict = unsafe { (*(*reader).ctxt).dict };
    } else {
        dict = 0 as xmlDictPtr;
    }
    if cur.is_null() {
        return;
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0 && (unsafe { (*__xmlDeregisterNodeDefaultValue()).is_some() }) {
        (unsafe { (*__xmlDeregisterNodeDefaultValue()).expect("non-null function pointer")(cur as xmlNodePtr) });
    }
    if !(unsafe { (*cur).children }).is_null() {
        xmlTextReaderFreeNodeList(reader, unsafe { (*cur).children });
    }
    if !(unsafe { (*cur).name }).is_null() && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*cur).name) }) == 0 as i32) {
        (unsafe { xmlFree.expect("non-null function pointer")((*cur).name as *mut i8 as *mut libc::c_void) });
    }
    if !reader.is_null()
        && !(unsafe { (*reader).ctxt }).is_null()
        && (unsafe { (*(*reader).ctxt).freeAttrsNr }) < 100 as i32
    {
        let fresh0 = unsafe { &mut ((*cur).next) };
        *fresh0 = unsafe { (*(*reader).ctxt).freeAttrs };
        let fresh1 = unsafe { &mut ((*(*reader).ctxt).freeAttrs) };
        *fresh1 = cur;
        let fresh2 = unsafe { &mut ((*(*reader).ctxt).freeAttrsNr) };
        *fresh2 += 1;
    } else {
        (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
    };
}
extern "C" fn xmlTextReaderFreePropList(mut reader: xmlTextReaderPtr, mut cur: xmlAttrPtr) {
    let mut next: xmlAttrPtr = 0 as *mut xmlAttr;
    while !cur.is_null() {
        next = unsafe { (*cur).next };
        xmlTextReaderFreeProp(reader, cur);
        cur = next;
    }
}
extern "C" fn xmlTextReaderFreeNodeList(mut reader: xmlTextReaderPtr, mut cur: xmlNodePtr) {
    let mut next: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut dict: xmlDictPtr = 0 as *mut xmlDict;
    let mut depth: size_t = 0 as i32 as size_t;
    if !reader.is_null() && !(unsafe { (*reader).ctxt }).is_null() {
        dict = unsafe { (*(*reader).ctxt).dict };
    } else {
        dict = 0 as xmlDictPtr;
    }
    if cur.is_null() {
        return;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        (unsafe { xmlFreeNsList(cur as xmlNsPtr) });
        return;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
        || (unsafe { (*cur).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        (unsafe { xmlFreeDoc(cur as xmlDocPtr) });
        return;
    }
    loop {
        while (unsafe { (*cur).type_0 }) as u32 != XML_DTD_NODE as i32 as u32
            && (unsafe { (*cur).type_0 }) as u32 != XML_ENTITY_REF_NODE as i32 as u32
            && !(unsafe { (*cur).children }).is_null()
            && (unsafe { (*(*cur).children).parent }) == cur
        {
            cur = unsafe { (*cur).children };
            depth = (depth as u64).wrapping_add(1 as i32 as u64) as size_t as size_t;
        }
        next = unsafe { (*cur).next };
        parent = unsafe { (*cur).parent };
        if (unsafe { (*cur).type_0 }) as u32 != XML_DTD_NODE as i32 as u32 {
            if (unsafe { __xmlRegisterCallbacks }) != 0 && (unsafe { (*__xmlDeregisterNodeDefaultValue()).is_some() }) {
                (unsafe { (*__xmlDeregisterNodeDefaultValue()).expect("non-null function pointer")(cur) });
            }
            if ((unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32
                || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_END as i32 as u32)
                && !(unsafe { (*cur).properties }).is_null()
            {
                xmlTextReaderFreePropList(reader, unsafe { (*cur).properties });
            }
            if (unsafe { (*cur).content }) != (unsafe { &mut (*cur).properties }) as *mut *mut _xmlAttr as *mut xmlChar
                && (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
                && (unsafe { (*cur).type_0 }) as u32 != XML_XINCLUDE_START as i32 as u32
                && (unsafe { (*cur).type_0 }) as u32 != XML_XINCLUDE_END as i32 as u32
                && (unsafe { (*cur).type_0 }) as u32 != XML_ENTITY_REF_NODE as i32 as u32
            {
                if !(unsafe { (*cur).content }).is_null()
                    && (dict.is_null()
                        || (unsafe { xmlDictOwns(dict, (*cur).content as *const xmlChar) }) == 0 as i32)
                {
                    (unsafe { xmlFree.expect("non-null function pointer")(
                        (*cur).content as *mut i8 as *mut libc::c_void,
                    ) });
                }
            }
            if ((unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32
                || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_END as i32 as u32)
                && !(unsafe { (*cur).nsDef }).is_null()
            {
                (unsafe { xmlFreeNsList((*cur).nsDef) });
            }
            if (unsafe { (*cur).type_0 }) as u32 != XML_TEXT_NODE as i32 as u32
                && (unsafe { (*cur).type_0 }) as u32 != XML_COMMENT_NODE as i32 as u32
            {
                if !(unsafe { (*cur).name }).is_null()
                    && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*cur).name) }) == 0 as i32)
                {
                    (unsafe { xmlFree.expect("non-null function pointer")(
                        (*cur).name as *mut i8 as *mut libc::c_void,
                    ) });
                }
            }
            if ((unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                || (unsafe { (*cur).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32)
                && !reader.is_null()
                && !(unsafe { (*reader).ctxt }).is_null()
                && (unsafe { (*(*reader).ctxt).freeElemsNr }) < 100 as i32
            {
                let fresh3 = unsafe { &mut ((*cur).next) };
                *fresh3 = unsafe { (*(*reader).ctxt).freeElems };
                let fresh4 = unsafe { &mut ((*(*reader).ctxt).freeElems) };
                *fresh4 = cur;
                let fresh5 = unsafe { &mut ((*(*reader).ctxt).freeElemsNr) };
                *fresh5 += 1;
            } else {
                (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
            }
        }
        if !next.is_null() {
            cur = next;
        } else {
            if depth == 0 as i32 as u64 || parent.is_null() {
                break;
            }
            depth = (depth as u64).wrapping_sub(1 as i32 as u64) as size_t as size_t;
            cur = parent;
            let fresh6 = unsafe { &mut ((*cur).children) };
            *fresh6 = 0 as *mut _xmlNode;
        }
    }
}
extern "C" fn xmlTextReaderFreeNode(mut reader: xmlTextReaderPtr, mut cur: xmlNodePtr) {
    let mut dict: xmlDictPtr = 0 as *mut xmlDict;
    if !reader.is_null() && !(unsafe { (*reader).ctxt }).is_null() {
        dict = unsafe { (*(*reader).ctxt).dict };
    } else {
        dict = 0 as xmlDictPtr;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_DTD_NODE as i32 as u32 {
        (unsafe { xmlFreeDtd(cur as xmlDtdPtr) });
        return;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        (unsafe { xmlFreeNs(cur as xmlNsPtr) });
        return;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
        xmlTextReaderFreeProp(reader, cur as xmlAttrPtr);
        return;
    }
    if !(unsafe { (*cur).children }).is_null() && (unsafe { (*cur).type_0 }) as u32 != XML_ENTITY_REF_NODE as i32 as u32 {
        if (unsafe { (*(*cur).children).parent }) == cur {
            xmlTextReaderFreeNodeList(reader, unsafe { (*cur).children });
        }
        let fresh7 = unsafe { &mut ((*cur).children) };
        *fresh7 = 0 as *mut _xmlNode;
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0 && (unsafe { (*__xmlDeregisterNodeDefaultValue()).is_some() }) {
        (unsafe { (*__xmlDeregisterNodeDefaultValue()).expect("non-null function pointer")(cur) });
    }
    if ((unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
        || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32
        || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_END as i32 as u32)
        && !(unsafe { (*cur).properties }).is_null()
    {
        xmlTextReaderFreePropList(reader, unsafe { (*cur).properties });
    }
    if (unsafe { (*cur).content }) != (unsafe { &mut (*cur).properties }) as *mut *mut _xmlAttr as *mut xmlChar
        && (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
        && (unsafe { (*cur).type_0 }) as u32 != XML_XINCLUDE_START as i32 as u32
        && (unsafe { (*cur).type_0 }) as u32 != XML_XINCLUDE_END as i32 as u32
        && (unsafe { (*cur).type_0 }) as u32 != XML_ENTITY_REF_NODE as i32 as u32
    {
        if !(unsafe { (*cur).content }).is_null()
            && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*cur).content as *const xmlChar) }) == 0 as i32)
        {
            (unsafe { xmlFree.expect("non-null function pointer")(
                (*cur).content as *mut i8 as *mut libc::c_void,
            ) });
        }
    }
    if ((unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
        || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32
        || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_END as i32 as u32)
        && !(unsafe { (*cur).nsDef }).is_null()
    {
        (unsafe { xmlFreeNsList((*cur).nsDef) });
    }
    if (unsafe { (*cur).type_0 }) as u32 != XML_TEXT_NODE as i32 as u32
        && (unsafe { (*cur).type_0 }) as u32 != XML_COMMENT_NODE as i32 as u32
    {
        if !(unsafe { (*cur).name }).is_null()
            && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*cur).name) }) == 0 as i32)
        {
            (unsafe { xmlFree.expect("non-null function pointer")(
                (*cur).name as *mut i8 as *mut libc::c_void,
            ) });
        }
    }
    if ((unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
        || (unsafe { (*cur).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32)
        && !reader.is_null()
        && !(unsafe { (*reader).ctxt }).is_null()
        && (unsafe { (*(*reader).ctxt).freeElemsNr }) < 100 as i32
    {
        let fresh8 = unsafe { &mut ((*cur).next) };
        *fresh8 = unsafe { (*(*reader).ctxt).freeElems };
        let fresh9 = unsafe { &mut ((*(*reader).ctxt).freeElems) };
        *fresh9 = cur;
        let fresh10 = unsafe { &mut ((*(*reader).ctxt).freeElemsNr) };
        *fresh10 += 1;
    } else {
        (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
    };
}
extern "C" fn xmlTextReaderFreeDoc(mut reader: xmlTextReaderPtr, mut cur: xmlDocPtr) {
    let mut extSubset: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut intSubset: xmlDtdPtr = 0 as *mut xmlDtd;
    if cur.is_null() {
        return;
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0 && (unsafe { (*__xmlDeregisterNodeDefaultValue()).is_some() }) {
        (unsafe { (*__xmlDeregisterNodeDefaultValue()).expect("non-null function pointer")(cur as xmlNodePtr) });
    }
    if !(unsafe { (*cur).ids }).is_null() {
        (unsafe { xmlFreeIDTable((*cur).ids as xmlIDTablePtr) });
    }
    let fresh11 = unsafe { &mut ((*cur).ids) };
    *fresh11 = 0 as *mut libc::c_void;
    if !(unsafe { (*cur).refs }).is_null() {
        (unsafe { xmlFreeRefTable((*cur).refs as xmlRefTablePtr) });
    }
    let fresh12 = unsafe { &mut ((*cur).refs) };
    *fresh12 = 0 as *mut libc::c_void;
    extSubset = unsafe { (*cur).extSubset };
    intSubset = unsafe { (*cur).intSubset };
    if intSubset == extSubset {
        extSubset = 0 as xmlDtdPtr;
    }
    if !extSubset.is_null() {
        (unsafe { xmlUnlinkNode((*cur).extSubset as xmlNodePtr) });
        let fresh13 = unsafe { &mut ((*cur).extSubset) };
        *fresh13 = 0 as *mut _xmlDtd;
        (unsafe { xmlFreeDtd(extSubset) });
    }
    if !intSubset.is_null() {
        (unsafe { xmlUnlinkNode((*cur).intSubset as xmlNodePtr) });
        let fresh14 = unsafe { &mut ((*cur).intSubset) };
        *fresh14 = 0 as *mut _xmlDtd;
        (unsafe { xmlFreeDtd(intSubset) });
    }
    if !(unsafe { (*cur).children }).is_null() {
        xmlTextReaderFreeNodeList(reader, unsafe { (*cur).children });
    }
    if !(unsafe { (*cur).version }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*cur).version as *mut i8 as *mut libc::c_void) });
    }
    if !(unsafe { (*cur).name }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*cur).name as *mut libc::c_void) });
    }
    if !(unsafe { (*cur).encoding }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(
            (*cur).encoding as *mut i8 as *mut libc::c_void,
        ) });
    }
    if !(unsafe { (*cur).oldNs }).is_null() {
        (unsafe { xmlFreeNsList((*cur).oldNs) });
    }
    if !(unsafe { (*cur).URL }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*cur).URL as *mut i8 as *mut libc::c_void) });
    }
    if !(unsafe { (*cur).dict }).is_null() {
        (unsafe { xmlDictFree((*cur).dict) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
}
extern "C" fn xmlTextReaderEntPush(mut reader: xmlTextReaderPtr, mut value: xmlNodePtr) -> i32 {
    if (unsafe { (*reader).entMax }) <= 0 as i32 {
        (unsafe { (*reader).entMax = 10 as i32 });
        let fresh15 = unsafe { &mut ((*reader).entTab) };
        *fresh15 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ((*reader).entMax as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) }) as *mut xmlNodePtr;
        if (unsafe { (*reader).entTab }).is_null() {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlMalloc failed !\n\0" as *const u8 as *const i8,
            ) });
            return 0 as i32;
        }
    }
    if (unsafe { (*reader).entNr }) >= (unsafe { (*reader).entMax }) {
        (unsafe { (*reader).entMax *= 2 as i32 });
        let fresh16 = unsafe { &mut ((*reader).entTab) };
        *fresh16 = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*reader).entTab as *mut libc::c_void,
            ((*reader).entMax as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) }) as *mut xmlNodePtr;
        if (unsafe { (*reader).entTab }).is_null() {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlRealloc failed !\n\0" as *const u8 as *const i8,
            ) });
            return 0 as i32;
        }
    }
    let fresh17 = unsafe { &mut (*((*reader).entTab).offset((*reader).entNr as isize)) };
    *fresh17 = value;
    let fresh18 = unsafe { &mut ((*reader).ent) };
    *fresh18 = value;
    let fresh19 = unsafe { &mut ((*reader).entNr) };
    let fresh20 = *fresh19;
    *fresh19 = *fresh19 + 1;
    return fresh20;
}
extern "C" fn xmlTextReaderEntPop(mut reader: xmlTextReaderPtr) -> xmlNodePtr {
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    if (unsafe { (*reader).entNr }) <= 0 as i32 {
        return 0 as xmlNodePtr;
    }
    let fresh21 = unsafe { &mut ((*reader).entNr) };
    *fresh21 -= 1;
    if (unsafe { (*reader).entNr }) > 0 as i32 {
        let fresh22 = unsafe { &mut ((*reader).ent) };
        *fresh22 = unsafe { *((*reader).entTab).offset(((*reader).entNr - 1 as i32) as isize) };
    } else {
        let fresh23 = unsafe { &mut ((*reader).ent) };
        *fresh23 = 0 as xmlNodePtr;
    }
    ret = unsafe { *((*reader).entTab).offset((*reader).entNr as isize) };
    let fresh24 = unsafe { &mut (*((*reader).entTab).offset((*reader).entNr as isize)) };
    *fresh24 = 0 as xmlNodePtr;
    return ret;
}
extern "C" fn xmlTextReaderStartElement(
    mut ctx: *mut libc::c_void,
    mut fullname: *const xmlChar,
    mut atts: *mut *const xmlChar,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut reader: xmlTextReaderPtr = (unsafe { (*ctxt)._private }) as xmlTextReaderPtr;
    if !reader.is_null() && (unsafe { ((*reader).startElement).is_some() }) {
        (unsafe { ((*reader).startElement).expect("non-null function pointer")(ctx, fullname, atts) });
        if !(unsafe { (*ctxt).node }).is_null()
            && !(unsafe { (*ctxt).input }).is_null()
            && !(unsafe { (*(*ctxt).input).cur }).is_null()
            && (unsafe { *((*(*ctxt).input).cur).offset(0 as i32 as isize) }) as i32 == '/' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '>' as i32
        {
            (unsafe { (*(*ctxt).node).extra = 0x1 as i32 as u16 });
        }
    }
    if !reader.is_null() {
        (unsafe { (*reader).state = XML_TEXTREADER_ELEMENT });
    }
}
extern "C" fn xmlTextReaderEndElement(mut ctx: *mut libc::c_void, mut fullname: *const xmlChar) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut reader: xmlTextReaderPtr = (unsafe { (*ctxt)._private }) as xmlTextReaderPtr;
    if !reader.is_null() && (unsafe { ((*reader).endElement).is_some() }) {
        (unsafe { ((*reader).endElement).expect("non-null function pointer")(ctx, fullname) });
    }
}
extern "C" fn xmlTextReaderStartElementNs(
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
    let mut reader: xmlTextReaderPtr = (unsafe { (*ctxt)._private }) as xmlTextReaderPtr;
    if !reader.is_null() && (unsafe { ((*reader).startElementNs).is_some() }) {
        (unsafe { ((*reader).startElementNs).expect("non-null function pointer")(
            ctx,
            localname,
            prefix,
            URI,
            nb_namespaces,
            namespaces,
            nb_attributes,
            nb_defaulted,
            attributes,
        ) });
        if !(unsafe { (*ctxt).node }).is_null()
            && !(unsafe { (*ctxt).input }).is_null()
            && !(unsafe { (*(*ctxt).input).cur }).is_null()
            && (unsafe { *((*(*ctxt).input).cur).offset(0 as i32 as isize) }) as i32 == '/' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '>' as i32
        {
            (unsafe { (*(*ctxt).node).extra = 0x1 as i32 as u16 });
        }
    }
    if !reader.is_null() {
        (unsafe { (*reader).state = XML_TEXTREADER_ELEMENT });
    }
}
extern "C" fn xmlTextReaderEndElementNs(
    mut ctx: *mut libc::c_void,
    mut localname: *const xmlChar,
    mut prefix: *const xmlChar,
    mut URI: *const xmlChar,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut reader: xmlTextReaderPtr = (unsafe { (*ctxt)._private }) as xmlTextReaderPtr;
    if !reader.is_null() && (unsafe { ((*reader).endElementNs).is_some() }) {
        (unsafe { ((*reader).endElementNs).expect("non-null function pointer")(ctx, localname, prefix, URI) });
    }
}
extern "C" fn xmlTextReaderCharacters(
    mut ctx: *mut libc::c_void,
    mut ch: *const xmlChar,
    mut len: i32,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut reader: xmlTextReaderPtr = (unsafe { (*ctxt)._private }) as xmlTextReaderPtr;
    if !reader.is_null() && (unsafe { ((*reader).characters).is_some() }) {
        (unsafe { ((*reader).characters).expect("non-null function pointer")(ctx, ch, len) });
    }
}
extern "C" fn xmlTextReaderCDataBlock(
    mut ctx: *mut libc::c_void,
    mut ch: *const xmlChar,
    mut len: i32,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut reader: xmlTextReaderPtr = (unsafe { (*ctxt)._private }) as xmlTextReaderPtr;
    if !reader.is_null() && (unsafe { ((*reader).cdataBlock).is_some() }) {
        (unsafe { ((*reader).cdataBlock).expect("non-null function pointer")(ctx, ch, len) });
    }
}
extern "C" fn xmlTextReaderPushData(mut reader: xmlTextReaderPtr) -> i32 {
    let mut inbuf: xmlBufPtr = 0 as *mut xmlBuf;
    let mut val: i32 = 0;
    let mut s: i32 = 0;
    let mut oldstate: xmlTextReaderState = XML_TEXTREADER_START;
    let mut alloc: i32 = 0;
    if (unsafe { (*reader).input }).is_null() || (unsafe { (*(*reader).input).buffer }).is_null() {
        return -(1 as i32);
    }
    oldstate = unsafe { (*reader).state };
    (unsafe { (*reader).state = XML_TEXTREADER_NONE });
    inbuf = unsafe { (*(*reader).input).buffer };
    alloc = unsafe { xmlBufGetAllocationScheme(inbuf) };
    while (unsafe { (*reader).state }) as i32 == XML_TEXTREADER_NONE as i32 {
        if (unsafe { xmlBufUse(inbuf) }) < (unsafe { (*reader).cur }).wrapping_add(512 as i32 as u32) as u64 {
            if !((unsafe { (*reader).mode }) != XML_TEXTREADER_MODE_EOF as i32) {
                break;
            }
            val = unsafe { xmlParserInputBufferRead((*reader).input, 4096 as i32) };
            if val == 0 as i32 && alloc == XML_BUFFER_ALLOC_IMMUTABLE as i32 {
                if (unsafe { xmlBufUse(inbuf) }) == (unsafe { (*reader).cur }) as u64 {
                    (unsafe { (*reader).mode = XML_TEXTREADER_MODE_EOF as i32 });
                    (unsafe { (*reader).state = oldstate });
                }
            } else if val < 0 as i32 {
                (unsafe { (*reader).mode = XML_TEXTREADER_MODE_EOF as i32 });
                (unsafe { (*reader).state = oldstate });
                if oldstate as i32 != XML_TEXTREADER_START as i32
                    || !(unsafe { (*(*reader).ctxt).myDoc }).is_null()
                {
                    return val;
                }
            } else if val == 0 as i32 {
                (unsafe { (*reader).mode = XML_TEXTREADER_MODE_EOF as i32 });
                break;
            }
        }
        if (unsafe { xmlBufUse(inbuf) }) >= (unsafe { (*reader).cur }).wrapping_add(512 as i32 as u32) as u64 {
            val = unsafe { xmlParseChunk(
                (*reader).ctxt,
                (xmlBufContent(inbuf as *const xmlBuf) as *const i8).offset((*reader).cur as isize),
                512 as i32,
                0 as i32,
            ) };
            let fresh25 = unsafe { &mut ((*reader).cur) };
            *fresh25 = (*fresh25).wrapping_add(512 as i32 as u32);
            if val != 0 as i32 {
                (unsafe { (*(*reader).ctxt).wellFormed = 0 as i32 });
            }
            if (unsafe { (*(*reader).ctxt).wellFormed }) == 0 as i32 {
                break;
            }
        } else {
            s = (unsafe { xmlBufUse(inbuf) }).wrapping_sub((unsafe { (*reader).cur }) as u64) as i32;
            val = unsafe { xmlParseChunk(
                (*reader).ctxt,
                (xmlBufContent(inbuf as *const xmlBuf) as *const i8).offset((*reader).cur as isize),
                s,
                0 as i32,
            ) };
            let fresh26 = unsafe { &mut ((*reader).cur) };
            *fresh26 = (*fresh26).wrapping_add(s as u32);
            if val != 0 as i32 {
                (unsafe { (*(*reader).ctxt).wellFormed = 0 as i32 });
            }
            break;
        }
    }
    if (unsafe { (*reader).mode }) == XML_TEXTREADER_MODE_INTERACTIVE as i32 {
        if alloc != XML_BUFFER_ALLOC_IMMUTABLE as i32 {
            if (unsafe { (*reader).cur }) >= 4096 as i32 as u32
                && (unsafe { xmlBufUse(inbuf) }).wrapping_sub((unsafe { (*reader).cur }) as u64) <= 512 as i32 as u64
            {
                val = (unsafe { xmlBufShrink(inbuf, (*reader).cur as size_t) }) as i32;
                if val >= 0 as i32 {
                    let fresh27 = unsafe { &mut ((*reader).cur) };
                    *fresh27 = (*fresh27).wrapping_sub(val as u32);
                }
            }
        }
    } else if (unsafe { (*reader).mode }) == XML_TEXTREADER_MODE_EOF as i32 {
        if (unsafe { (*reader).state }) as i32 != XML_TEXTREADER_DONE as i32 {
            s = (unsafe { xmlBufUse(inbuf) }).wrapping_sub((unsafe { (*reader).cur }) as u64) as i32;
            val = unsafe { xmlParseChunk(
                (*reader).ctxt,
                (xmlBufContent(inbuf as *const xmlBuf) as *const i8).offset((*reader).cur as isize),
                s,
                1 as i32,
            ) };
            (unsafe { (*reader).cur = xmlBufUse(inbuf) as u32 });
            (unsafe { (*reader).state = XML_TEXTREADER_DONE });
            if val != 0 as i32 {
                if (unsafe { (*(*reader).ctxt).wellFormed }) != 0 {
                    (unsafe { (*(*reader).ctxt).wellFormed = 0 as i32 });
                } else {
                    return -(1 as i32);
                }
            }
        }
    }
    (unsafe { (*reader).state = oldstate });
    if (unsafe { (*(*reader).ctxt).wellFormed }) == 0 as i32 {
        (unsafe { (*reader).mode = XML_TEXTREADER_MODE_EOF as i32 });
        return -(1 as i32);
    }
    return 0 as i32;
}
extern "C" fn xmlTextReaderValidatePush(mut reader: xmlTextReaderPtr) {
    let mut node: xmlNodePtr = unsafe { (*reader).node };
    if (unsafe { (*reader).validate }) as u32 == XML_TEXTREADER_VALIDATE_DTD as i32 as u32
        && !(unsafe { (*reader).ctxt }).is_null()
        && (unsafe { (*(*reader).ctxt).validate }) == 1 as i32
    {
        if (unsafe { (*node).ns }).is_null() || (unsafe { (*(*node).ns).prefix }).is_null() {
            (unsafe { (*(*reader).ctxt).valid &= xmlValidatePushElement(
                &mut (*(*reader).ctxt).vctxt,
                (*(*reader).ctxt).myDoc,
                node,
                (*node).name,
            ) });
        } else {
            let mut qname: *mut xmlChar = 0 as *mut xmlChar;
            qname = unsafe { xmlStrdup((*(*node).ns).prefix) };
            qname = unsafe { xmlStrcat(qname, b":\0" as *const u8 as *const i8 as *mut xmlChar) };
            qname = unsafe { xmlStrcat(qname, (*node).name) };
            (unsafe { (*(*reader).ctxt).valid &= xmlValidatePushElement(
                &mut (*(*reader).ctxt).vctxt,
                (*(*reader).ctxt).myDoc,
                node,
                qname,
            ) });
            if !qname.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(qname as *mut libc::c_void) });
            }
        }
    }
    if (unsafe { (*reader).validate }) as u32 == XML_TEXTREADER_VALIDATE_RNG as i32 as u32
        && !(unsafe { (*reader).rngValidCtxt }).is_null()
    {
        let mut ret: i32 = 0;
        if !(unsafe { (*reader).rngFullNode }).is_null() {
            return;
        }
        ret = unsafe { xmlRelaxNGValidatePushElement((*reader).rngValidCtxt, (*(*reader).ctxt).myDoc, node) };
        if ret == 0 as i32 {
            node = xmlTextReaderExpand(reader);
            if node.is_null() {
                ret = -(1 as i32);
            } else {
                ret = unsafe { xmlRelaxNGValidateFullElement(
                    (*reader).rngValidCtxt,
                    (*(*reader).ctxt).myDoc,
                    node,
                ) };
                let fresh28 = unsafe { &mut ((*reader).rngFullNode) };
                *fresh28 = node;
            }
        }
        if ret != 1 as i32 {
            let fresh29 = unsafe { &mut ((*reader).rngValidErrors) };
            *fresh29 += 1;
        }
    }
}
extern "C" fn xmlTextReaderValidateCData(
    mut reader: xmlTextReaderPtr,
    mut data: *const xmlChar,
    mut len: i32,
) {
    if (unsafe { (*reader).validate }) as u32 == XML_TEXTREADER_VALIDATE_DTD as i32 as u32
        && !(unsafe { (*reader).ctxt }).is_null()
        && (unsafe { (*(*reader).ctxt).validate }) == 1 as i32
    {
        (unsafe { (*(*reader).ctxt).valid &= xmlValidatePushCData(&mut (*(*reader).ctxt).vctxt, data, len) });
    }
    if (unsafe { (*reader).validate }) as u32 == XML_TEXTREADER_VALIDATE_RNG as i32 as u32
        && !(unsafe { (*reader).rngValidCtxt }).is_null()
    {
        let mut ret: i32 = 0;
        if !(unsafe { (*reader).rngFullNode }).is_null() {
            return;
        }
        ret = unsafe { xmlRelaxNGValidatePushCData((*reader).rngValidCtxt, data, len) };
        if ret != 1 as i32 {
            let fresh30 = unsafe { &mut ((*reader).rngValidErrors) };
            *fresh30 += 1;
        }
    }
}
extern "C" fn xmlTextReaderValidatePop(mut reader: xmlTextReaderPtr) {
    let mut node: xmlNodePtr = unsafe { (*reader).node };
    if (unsafe { (*reader).validate }) as u32 == XML_TEXTREADER_VALIDATE_DTD as i32 as u32
        && !(unsafe { (*reader).ctxt }).is_null()
        && (unsafe { (*(*reader).ctxt).validate }) == 1 as i32
    {
        if (unsafe { (*node).ns }).is_null() || (unsafe { (*(*node).ns).prefix }).is_null() {
            (unsafe { (*(*reader).ctxt).valid &= xmlValidatePopElement(
                &mut (*(*reader).ctxt).vctxt,
                (*(*reader).ctxt).myDoc,
                node,
                (*node).name,
            ) });
        } else {
            let mut qname: *mut xmlChar = 0 as *mut xmlChar;
            qname = unsafe { xmlStrdup((*(*node).ns).prefix) };
            qname = unsafe { xmlStrcat(qname, b":\0" as *const u8 as *const i8 as *mut xmlChar) };
            qname = unsafe { xmlStrcat(qname, (*node).name) };
            (unsafe { (*(*reader).ctxt).valid &= xmlValidatePopElement(
                &mut (*(*reader).ctxt).vctxt,
                (*(*reader).ctxt).myDoc,
                node,
                qname,
            ) });
            if !qname.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(qname as *mut libc::c_void) });
            }
        }
    }
    if (unsafe { (*reader).validate }) as u32 == XML_TEXTREADER_VALIDATE_RNG as i32 as u32
        && !(unsafe { (*reader).rngValidCtxt }).is_null()
    {
        let mut ret: i32 = 0;
        if !(unsafe { (*reader).rngFullNode }).is_null() {
            if node == (unsafe { (*reader).rngFullNode }) {
                let fresh31 = unsafe { &mut ((*reader).rngFullNode) };
                *fresh31 = 0 as xmlNodePtr;
            }
            return;
        }
        ret = unsafe { xmlRelaxNGValidatePopElement((*reader).rngValidCtxt, (*(*reader).ctxt).myDoc, node) };
        if ret != 1 as i32 {
            let fresh32 = unsafe { &mut ((*reader).rngValidErrors) };
            *fresh32 += 1;
        }
    }
}
extern "C" fn xmlTextReaderValidateEntity(mut reader: xmlTextReaderPtr) {
    let mut oldnode: xmlNodePtr = unsafe { (*reader).node };
    let mut node: xmlNodePtr = unsafe { (*reader).node };
    let mut current_block_29: u64;
    loop {
        if (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_REF_NODE as i32 as u32 {
            if !(unsafe { (*node).children }).is_null()
                && (unsafe { (*(*node).children).type_0 }) as u32 == XML_ENTITY_DECL as i32 as u32
                && !(unsafe { (*(*node).children).children }).is_null()
            {
                xmlTextReaderEntPush(reader, node);
                node = unsafe { (*(*node).children).children };
                current_block_29 = 12237857397564741460;
            } else {
                if node == oldnode {
                    break;
                }
                current_block_29 = 13226217046118304493;
            }
        } else {
            if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                let fresh33 = unsafe { &mut ((*reader).node) };
                *fresh33 = node;
                xmlTextReaderValidatePush(reader);
            } else if (unsafe { (*node).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
                || (unsafe { (*node).type_0 }) as u32 == XML_CDATA_SECTION_NODE as i32 as u32
            {
                xmlTextReaderValidateCData(reader, unsafe { (*node).content }, unsafe { xmlStrlen((*node).content) });
            }
            if !(unsafe { (*node).children }).is_null() {
                node = unsafe { (*node).children };
                current_block_29 = 12237857397564741460;
            } else {
                if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                    xmlTextReaderValidatePop(reader);
                }
                current_block_29 = 13226217046118304493;
            }
        }
        match current_block_29 {
            13226217046118304493 => {
                if !(unsafe { (*node).next }).is_null() {
                    node = unsafe { (*node).next };
                } else {
                    loop {
                        node = unsafe { (*node).parent };
                        if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                            let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
                            if (unsafe { (*reader).entNr }) == 0 as i32 {
                                loop {
                                    tmp = unsafe { (*node).last };
                                    if tmp.is_null() {
                                        break;
                                    }
                                    if !((unsafe { (*tmp).extra }) as i32 & 0x2 as i32 == 0 as i32) {
                                        break;
                                    }
                                    (unsafe { xmlUnlinkNode(tmp) });
                                    xmlTextReaderFreeNode(reader, tmp);
                                }
                            }
                            let fresh34 = unsafe { &mut ((*reader).node) };
                            *fresh34 = node;
                            xmlTextReaderValidatePop(reader);
                        }
                        if (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_DECL as i32 as u32
                            && !(unsafe { (*reader).ent }).is_null()
                            && (unsafe { (*(*reader).ent).children }) == node
                        {
                            node = xmlTextReaderEntPop(reader);
                        }
                        if node == oldnode {
                            break;
                        }
                        if !(unsafe { (*node).next }).is_null() {
                            node = unsafe { (*node).next };
                            break;
                        } else if !(!node.is_null() && node != oldnode) {
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
        if !(!node.is_null() && node != oldnode) {
            break;
        }
    }
    let fresh35 = unsafe { &mut ((*reader).node) };
    *fresh35 = oldnode;
}
extern "C" fn xmlTextReaderGetSuccessor(mut cur: xmlNodePtr) -> xmlNodePtr {
    if cur.is_null() {
        return 0 as xmlNodePtr;
    }
    if !(unsafe { (*cur).next }).is_null() {
        return unsafe { (*cur).next };
    }
    loop {
        cur = unsafe { (*cur).parent };
        if cur.is_null() {
            break;
        }
        if !(unsafe { (*cur).next }).is_null() {
            return unsafe { (*cur).next };
        }
        if cur.is_null() {
            break;
        }
    }
    return cur;
}
extern "C" fn xmlTextReaderDoExpand(mut reader: xmlTextReaderPtr) -> i32 {
    let mut val: i32 = 0;
    if reader.is_null() || (unsafe { (*reader).node }).is_null() || (unsafe { (*reader).ctxt }).is_null() {
        return -(1 as i32);
    }
    loop {
        if (unsafe { (*(*reader).ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
            return 1 as i32;
        }
        if !(xmlTextReaderGetSuccessor(unsafe { (*reader).node })).is_null() {
            return 1 as i32;
        }
        if (unsafe { (*(*reader).ctxt).nodeNr }) < (unsafe { (*reader).depth }) {
            return 1 as i32;
        }
        if (unsafe { (*reader).mode }) == XML_TEXTREADER_MODE_EOF as i32 {
            return 1 as i32;
        }
        val = xmlTextReaderPushData(reader);
        if val < 0 as i32 {
            (unsafe { (*reader).mode = XML_TEXTREADER_MODE_ERROR as i32 });
            return -(1 as i32);
        }
        if !((unsafe { (*reader).mode }) != XML_TEXTREADER_MODE_EOF as i32) {
            break;
        }
    }
    return 1 as i32;
}
extern "C" fn xmlTextReaderCollectSiblings(mut node: xmlNodePtr) -> *mut xmlChar {
    let mut buffer: xmlBufferPtr = 0 as *mut xmlBuffer;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if node.is_null() || (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as *mut xmlChar;
    }
    buffer = unsafe { xmlBufferCreate() };
    if buffer.is_null() {
        return 0 as *mut xmlChar;
    }
    (unsafe { xmlBufferSetAllocationScheme(buffer, XML_BUFFER_ALLOC_DOUBLEIT) });
    while !node.is_null() {
        match (unsafe { (*node).type_0 }) as u32 {
            3 | 4 => {
                (unsafe { xmlBufferCat(buffer, (*node).content) });
            }
            1 => {
                let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                tmp = xmlTextReaderCollectSiblings(unsafe { (*node).children });
                (unsafe { xmlBufferCat(buffer, tmp) });
                (unsafe { xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
            }
            _ => {}
        }
        node = unsafe { (*node).next };
    }
    ret = unsafe { (*buffer).content };
    let fresh36 = unsafe { &mut ((*buffer).content) };
    *fresh36 = 0 as *mut xmlChar;
    (unsafe { xmlBufferFree(buffer) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderRead(mut reader: xmlTextReaderPtr) -> i32 {
    let mut current_block: u64;
    let mut val: i32 = 0;
    let mut olddepth: i32 = 0 as i32;
    let mut oldstate: xmlTextReaderState = XML_TEXTREADER_START;
    let mut oldnode: xmlNodePtr = 0 as xmlNodePtr;
    if reader.is_null() {
        return -(1 as i32);
    }
    let fresh37 = unsafe { &mut ((*reader).curnode) };
    *fresh37 = 0 as xmlNodePtr;
    if !(unsafe { (*reader).doc }).is_null() {
        return xmlTextReaderReadTree(reader);
    }
    if (unsafe { (*reader).ctxt }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).mode }) == XML_TEXTREADER_MODE_INITIAL as i32 {
        (unsafe { (*reader).mode = XML_TEXTREADER_MODE_INTERACTIVE as i32 });
        loop {
            val = xmlTextReaderPushData(reader);
            if val < 0 as i32 {
                (unsafe { (*reader).mode = XML_TEXTREADER_MODE_ERROR as i32 });
                (unsafe { (*reader).state = XML_TEXTREADER_ERROR });
                return -(1 as i32);
            }
            if !((unsafe { (*(*reader).ctxt).node }).is_null()
                && ((unsafe { (*reader).mode }) != XML_TEXTREADER_MODE_EOF as i32
                    && (unsafe { (*reader).state }) as i32 != XML_TEXTREADER_DONE as i32))
            {
                break;
            }
        }
        if (unsafe { (*(*reader).ctxt).node }).is_null() {
            if !(unsafe { (*(*reader).ctxt).myDoc }).is_null() {
                let fresh38 = unsafe { &mut ((*reader).node) };
                *fresh38 = unsafe { (*(*(*reader).ctxt).myDoc).children };
            }
            if (unsafe { (*reader).node }).is_null() {
                (unsafe { (*reader).mode = XML_TEXTREADER_MODE_ERROR as i32 });
                (unsafe { (*reader).state = XML_TEXTREADER_ERROR });
                return -(1 as i32);
            }
            (unsafe { (*reader).state = XML_TEXTREADER_ELEMENT });
        } else {
            if !(unsafe { (*(*reader).ctxt).myDoc }).is_null() {
                let fresh39 = unsafe { &mut ((*reader).node) };
                *fresh39 = unsafe { (*(*(*reader).ctxt).myDoc).children };
            }
            if (unsafe { (*reader).node }).is_null() {
                let fresh40 = unsafe { &mut ((*reader).node) };
                *fresh40 = unsafe { *((*(*reader).ctxt).nodeTab).offset(0 as i32 as isize) };
            }
            (unsafe { (*reader).state = XML_TEXTREADER_ELEMENT });
        }
        (unsafe { (*reader).depth = 0 as i32 });
        (unsafe { (*(*reader).ctxt).parseMode = XML_PARSE_READER });
        current_block = 6684489022775130119;
    } else {
        oldstate = unsafe { (*reader).state };
        olddepth = unsafe { (*(*reader).ctxt).nodeNr };
        oldnode = unsafe { (*reader).node };
        current_block = 11951279088167397802;
    }
    'c_11937: loop {
        match current_block {
            11951279088167397802 => {
                if (unsafe { (*reader).node }).is_null() {
                    if (unsafe { (*reader).mode }) == XML_TEXTREADER_MODE_EOF as i32 {
                        return 0 as i32;
                    } else {
                        return -(1 as i32);
                    }
                }
                while !(unsafe { (*reader).node }).is_null()
                    && (unsafe { (*(*reader).node).next }).is_null()
                    && (unsafe { (*(*reader).ctxt).nodeNr }) == olddepth
                    && (oldstate as i32 == XML_TEXTREADER_BACKTRACK as i32
                        || (unsafe { (*(*reader).node).children }).is_null()
                        || (unsafe { (*(*reader).node).type_0 }) as u32 == XML_ENTITY_REF_NODE as i32 as u32
                        || !(unsafe { (*(*reader).node).children }).is_null()
                            && (unsafe { (*(*(*reader).node).children).type_0 }) as u32
                                == XML_TEXT_NODE as i32 as u32
                            && (unsafe { (*(*(*reader).node).children).next }).is_null()
                        || (unsafe { (*(*reader).node).type_0 }) as u32 == XML_DTD_NODE as i32 as u32
                        || (unsafe { (*(*reader).node).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
                        || (unsafe { (*(*reader).node).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32)
                    && ((unsafe { (*(*reader).ctxt).node }).is_null()
                        || (unsafe { (*(*reader).ctxt).node }) == (unsafe { (*reader).node })
                        || (unsafe { (*(*reader).ctxt).node }) == (unsafe { (*(*reader).node).parent }))
                    && (unsafe { (*(*reader).ctxt).instate }) as i32 != XML_PARSER_EOF as i32
                {
                    val = xmlTextReaderPushData(reader);
                    if val < 0 as i32 {
                        (unsafe { (*reader).mode = XML_TEXTREADER_MODE_ERROR as i32 });
                        (unsafe { (*reader).state = XML_TEXTREADER_ERROR });
                        return -(1 as i32);
                    }
                    if (unsafe { (*reader).node }).is_null() {
                        break 'c_11937;
                    }
                }
                if oldstate as i32 != XML_TEXTREADER_BACKTRACK as i32 {
                    if !(unsafe { (*(*reader).node).children }).is_null()
                        && (unsafe { (*(*reader).node).type_0 }) as u32 != XML_ENTITY_REF_NODE as i32 as u32
                        && (unsafe { (*(*reader).node).type_0 }) as u32 != XML_XINCLUDE_START as i32 as u32
                        && (unsafe { (*(*reader).node).type_0 }) as u32 != XML_DTD_NODE as i32 as u32
                    {
                        let fresh41 = unsafe { &mut ((*reader).node) };
                        *fresh41 = unsafe { (*(*reader).node).children };
                        let fresh42 = unsafe { &mut ((*reader).depth) };
                        *fresh42 += 1;
                        (unsafe { (*reader).state = XML_TEXTREADER_ELEMENT });
                        current_block = 6684489022775130119;
                        continue;
                    }
                }
                if !(unsafe { (*(*reader).node).next }).is_null() {
                    if oldstate as i32 == XML_TEXTREADER_ELEMENT as i32
                        && (unsafe { (*(*reader).node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                        && (unsafe { (*(*reader).node).children }).is_null()
                        && (unsafe { (*(*reader).node).extra }) as i32 & 0x1 as i32 == 0 as i32
                        && (unsafe { (*reader).in_xinclude }) <= 0 as i32
                    {
                        (unsafe { (*reader).state = XML_TEXTREADER_END });
                        current_block = 6684489022775130119;
                    } else {
                        if (unsafe { (*reader).validate }) as u32 != 0
                            && (unsafe { (*(*reader).node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                        {
                            xmlTextReaderValidatePop(reader);
                        }
                        if (unsafe { (*reader).preserves }) > 0 as i32
                            && (unsafe { (*(*reader).node).extra }) as i32 & 0x4 as i32 != 0
                        {
                            let fresh43 = unsafe { &mut ((*reader).preserves) };
                            *fresh43 -= 1;
                        }
                        let fresh44 = unsafe { &mut ((*reader).node) };
                        *fresh44 = unsafe { (*(*reader).node).next };
                        (unsafe { (*reader).state = XML_TEXTREADER_ELEMENT });
                        if (unsafe { (*reader).preserves }) == 0 as i32
                            && (unsafe { (*reader).in_xinclude }) == 0 as i32
                            && (unsafe { (*reader).entNr }) == 0 as i32
                            && !(unsafe { (*(*reader).node).prev }).is_null()
                            && (unsafe { (*(*(*reader).node).prev).type_0 }) as u32 != XML_DTD_NODE as i32 as u32
                        {
                            let mut tmp: xmlNodePtr = unsafe { (*(*reader).node).prev };
                            if (unsafe { (*tmp).extra }) as i32 & 0x2 as i32 == 0 as i32 {
                                if oldnode == tmp {
                                    oldnode = 0 as xmlNodePtr;
                                }
                                (unsafe { xmlUnlinkNode(tmp) });
                                xmlTextReaderFreeNode(reader, tmp);
                            }
                        }
                        current_block = 6684489022775130119;
                    }
                } else if oldstate as i32 == XML_TEXTREADER_ELEMENT as i32
                    && (unsafe { (*(*reader).node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                    && (unsafe { (*(*reader).node).children }).is_null()
                    && (unsafe { (*(*reader).node).extra }) as i32 & 0x1 as i32 == 0 as i32
                {
                    (unsafe { (*reader).state = XML_TEXTREADER_END });
                    current_block = 6684489022775130119;
                } else {
                    if (unsafe { (*reader).validate }) as u32 != XML_TEXTREADER_NOT_VALIDATE as i32 as u32
                        && (unsafe { (*(*reader).node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                    {
                        xmlTextReaderValidatePop(reader);
                    }
                    if (unsafe { (*reader).preserves }) > 0 as i32
                        && (unsafe { (*(*reader).node).extra }) as i32 & 0x4 as i32 != 0
                    {
                        let fresh45 = unsafe { &mut ((*reader).preserves) };
                        *fresh45 -= 1;
                    }
                    let fresh46 = unsafe { &mut ((*reader).node) };
                    *fresh46 = unsafe { (*(*reader).node).parent };
                    if (unsafe { (*reader).node }).is_null()
                        || (unsafe { (*(*reader).node).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
                        || (unsafe { (*(*reader).node).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32
                    {
                        if (unsafe { (*reader).mode }) != XML_TEXTREADER_MODE_EOF as i32 {
                            val = unsafe { xmlParseChunk(
                                (*reader).ctxt,
                                b"\0" as *const u8 as *const i8,
                                0 as i32,
                                1 as i32,
                            ) };
                            (unsafe { (*reader).state = XML_TEXTREADER_DONE });
                            if val != 0 as i32 {
                                return -(1 as i32);
                            }
                        }
                        let fresh47 = unsafe { &mut ((*reader).node) };
                        *fresh47 = 0 as xmlNodePtr;
                        (unsafe { (*reader).depth = -(1 as i32) });
                        if !oldnode.is_null()
                            && (unsafe { (*reader).preserves }) == 0 as i32
                            && (unsafe { (*reader).in_xinclude }) == 0 as i32
                            && (unsafe { (*reader).entNr }) == 0 as i32
                            && (unsafe { (*oldnode).type_0 }) as u32 != XML_DTD_NODE as i32 as u32
                            && (unsafe { (*oldnode).extra }) as i32 & 0x2 as i32 == 0 as i32
                        {
                            (unsafe { xmlUnlinkNode(oldnode) });
                            xmlTextReaderFreeNode(reader, oldnode);
                        }
                        break;
                    } else {
                        if (unsafe { (*reader).preserves }) == 0 as i32
                            && (unsafe { (*reader).in_xinclude }) == 0 as i32
                            && (unsafe { (*reader).entNr }) == 0 as i32
                            && !(unsafe { (*(*reader).node).last }).is_null()
                            && (unsafe { (*(*(*reader).node).last).extra }) as i32 & 0x2 as i32 == 0 as i32
                        {
                            let mut tmp_0: xmlNodePtr = unsafe { (*(*reader).node).last };
                            (unsafe { xmlUnlinkNode(tmp_0) });
                            xmlTextReaderFreeNode(reader, tmp_0);
                        }
                        let fresh48 = unsafe { &mut ((*reader).depth) };
                        *fresh48 -= 1;
                        (unsafe { (*reader).state = XML_TEXTREADER_BACKTRACK });
                        current_block = 6684489022775130119;
                    }
                }
            }
            _ => {
                if !(unsafe { (*reader).node }).is_null()
                    && (unsafe { (*(*reader).node).next }).is_null()
                    && ((unsafe { (*(*reader).node).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
                        || (unsafe { (*(*reader).node).type_0 }) as u32 == XML_CDATA_SECTION_NODE as i32 as u32)
                {
                    if (xmlTextReaderExpand(reader)).is_null() {
                        return -(1 as i32);
                    }
                }
                if (unsafe { (*reader).xinclude }) != 0
                    && (unsafe { (*reader).in_xinclude }) == 0 as i32
                    && !(unsafe { (*reader).node }).is_null()
                    && (unsafe { (*(*reader).node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                    && !(unsafe { (*(*reader).node).ns }).is_null()
                    && ((unsafe { xmlStrEqual(
                        (*(*(*reader).node).ns).href,
                        b"http://www.w3.org/2003/XInclude\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) }) != 0
                        || (unsafe { xmlStrEqual(
                            (*(*(*reader).node).ns).href,
                            b"http://www.w3.org/2001/XInclude\0" as *const u8 as *const i8
                                as *const xmlChar,
                        ) }) != 0)
                {
                    if (unsafe { (*reader).xincctxt }).is_null() {
                        let fresh49 = unsafe { &mut ((*reader).xincctxt) };
                        *fresh49 = unsafe { xmlXIncludeNewContext((*(*reader).ctxt).myDoc) };
                        (unsafe { xmlXIncludeSetFlags(
                            (*reader).xincctxt,
                            (*reader).parserFlags & !(XML_PARSE_NOXINCNODE as i32),
                        ) });
                    }
                    if (xmlTextReaderExpand(reader)).is_null() {
                        return -(1 as i32);
                    }
                    (unsafe { xmlXIncludeProcessNode((*reader).xincctxt, (*reader).node) });
                }
                if !(unsafe { (*reader).node }).is_null()
                    && (unsafe { (*(*reader).node).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32
                {
                    let fresh50 = unsafe { &mut ((*reader).in_xinclude) };
                    *fresh50 += 1;
                    current_block = 11951279088167397802;
                } else if !(unsafe { (*reader).node }).is_null()
                    && (unsafe { (*(*reader).node).type_0 }) as u32 == XML_XINCLUDE_END as i32 as u32
                {
                    let fresh51 = unsafe { &mut ((*reader).in_xinclude) };
                    *fresh51 -= 1;
                    current_block = 11951279088167397802;
                } else {
                    if !(unsafe { (*reader).node }).is_null()
                        && (unsafe { (*(*reader).node).type_0 }) as u32 == XML_ENTITY_REF_NODE as i32 as u32
                        && !(unsafe { (*reader).ctxt }).is_null()
                        && (unsafe { (*(*reader).ctxt).replaceEntities }) == 1 as i32
                    {
                        if !(unsafe { (*(*reader).node).children }).is_null()
                            && (unsafe { (*(*(*reader).node).children).type_0 }) as u32
                                == XML_ENTITY_DECL as i32 as u32
                            && !(unsafe { (*(*(*reader).node).children).children }).is_null()
                        {
                            xmlTextReaderEntPush(reader, unsafe { (*reader).node });
                            let fresh52 = unsafe { &mut ((*reader).node) };
                            *fresh52 = unsafe { (*(*(*reader).node).children).children };
                        }
                    } else if !(unsafe { (*reader).node }).is_null()
                        && (unsafe { (*(*reader).node).type_0 }) as u32 == XML_ENTITY_REF_NODE as i32 as u32
                        && !(unsafe { (*reader).ctxt }).is_null()
                        && (unsafe { (*reader).validate }) as u32 != 0
                    {
                        xmlTextReaderValidateEntity(reader);
                    }
                    if !(unsafe { (*reader).node }).is_null()
                        && (unsafe { (*(*reader).node).type_0 }) as u32 == XML_ENTITY_DECL as i32 as u32
                        && !(unsafe { (*reader).ent }).is_null()
                        && (unsafe { (*(*reader).ent).children }) == (unsafe { (*reader).node })
                    {
                        let fresh53 = unsafe { &mut ((*reader).node) };
                        *fresh53 = xmlTextReaderEntPop(reader);
                        let fresh54 = unsafe { &mut ((*reader).depth) };
                        *fresh54 += 1;
                        current_block = 11951279088167397802;
                    } else {
                        if (unsafe { (*reader).validate }) as u32 != XML_TEXTREADER_NOT_VALIDATE as i32 as u32
                            && !(unsafe { (*reader).node }).is_null()
                        {
                            let mut node: xmlNodePtr = unsafe { (*reader).node };
                            if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                                && ((unsafe { (*reader).state }) as i32 != XML_TEXTREADER_END as i32
                                    && (unsafe { (*reader).state }) as i32 != XML_TEXTREADER_BACKTRACK as i32)
                            {
                                xmlTextReaderValidatePush(reader);
                            } else if (unsafe { (*node).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
                                || (unsafe { (*node).type_0 }) as u32 == XML_CDATA_SECTION_NODE as i32 as u32
                            {
                                xmlTextReaderValidateCData(
                                    reader,
                                    unsafe { (*node).content },
                                    unsafe { xmlStrlen((*node).content) },
                                );
                            }
                        }
                        if (unsafe { (*reader).patternNr }) > 0 as i32
                            && (unsafe { (*reader).state }) as i32 != XML_TEXTREADER_END as i32
                            && (unsafe { (*reader).state }) as i32 != XML_TEXTREADER_BACKTRACK as i32
                        {
                            let mut i: i32 = 0;
                            i = 0 as i32;
                            while i < (unsafe { (*reader).patternNr }) {
                                if (unsafe { xmlPatternMatch(
                                    *((*reader).patternTab).offset(i as isize),
                                    (*reader).node,
                                ) }) == 1 as i32
                                {
                                    xmlTextReaderPreserve(reader);
                                    break;
                                } else {
                                    i += 1;
                                }
                            }
                        }
                        if (unsafe { (*reader).validate }) as u32 == XML_TEXTREADER_VALIDATE_XSD as i32 as u32
                            && (unsafe { (*reader).xsdValidErrors }) == 0 as i32
                            && !(unsafe { (*reader).xsdValidCtxt }).is_null()
                        {
                            (unsafe { (*reader).xsdValidErrors =
                                (xmlSchemaIsValid((*reader).xsdValidCtxt) == 0) as i32 });
                        }
                        return 1 as i32;
                    }
                }
            }
        }
    }
    (unsafe { (*reader).state = XML_TEXTREADER_DONE });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderReadState(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    return unsafe { (*reader).mode };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderExpand(mut reader: xmlTextReaderPtr) -> xmlNodePtr {
    if reader.is_null() || (unsafe { (*reader).node }).is_null() {
        return 0 as xmlNodePtr;
    }
    if !(unsafe { (*reader).doc }).is_null() {
        return unsafe { (*reader).node };
    }
    if (unsafe { (*reader).ctxt }).is_null() {
        return 0 as xmlNodePtr;
    }
    if xmlTextReaderDoExpand(reader) < 0 as i32 {
        return 0 as xmlNodePtr;
    }
    return unsafe { (*reader).node };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderNext(mut reader: xmlTextReaderPtr) -> i32 {
    let mut ret: i32 = 0;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() {
        return -(1 as i32);
    }
    if !(unsafe { (*reader).doc }).is_null() {
        return xmlTextReaderNextTree(reader);
    }
    cur = unsafe { (*reader).node };
    if cur.is_null() || (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return xmlTextReaderRead(reader);
    }
    if (unsafe { (*reader).state }) as i32 == XML_TEXTREADER_END as i32
        || (unsafe { (*reader).state }) as i32 == XML_TEXTREADER_BACKTRACK as i32
    {
        return xmlTextReaderRead(reader);
    }
    if (unsafe { (*cur).extra }) as i32 & 0x1 as i32 != 0 {
        return xmlTextReaderRead(reader);
    }
    loop {
        ret = xmlTextReaderRead(reader);
        if ret != 1 as i32 {
            return ret;
        }
        if !((unsafe { (*reader).node }) != cur) {
            break;
        }
    }
    return xmlTextReaderRead(reader);
}
#[no_mangle]
pub extern "C" fn xmlTextReaderReadInnerXml(mut reader: xmlTextReaderPtr) -> *mut xmlChar {
    let mut resbuf: *mut xmlChar = 0 as *mut xmlChar;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut cur_node: xmlNodePtr = 0 as *mut xmlNode;
    let mut buff: xmlBufferPtr = 0 as *mut xmlBuffer;
    let mut buff2: xmlBufferPtr = 0 as *mut xmlBuffer;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    if (xmlTextReaderExpand(reader)).is_null() {
        return 0 as *mut xmlChar;
    }
    doc = unsafe { (*(*reader).node).doc };
    buff = unsafe { xmlBufferCreate() };
    if buff.is_null() {
        return 0 as *mut xmlChar;
    }
    (unsafe { xmlBufferSetAllocationScheme(buff, XML_BUFFER_ALLOC_DOUBLEIT) });
    cur_node = unsafe { (*(*reader).node).children };
    while !cur_node.is_null() {
        node = unsafe { xmlDocCopyNode(cur_node, doc, 1 as i32) };
        buff2 = unsafe { xmlBufferCreate() };
        (unsafe { xmlBufferSetAllocationScheme(buff2, XML_BUFFER_ALLOC_DOUBLEIT) });
        if (unsafe { xmlNodeDump(buff2, doc, node, 0 as i32, 0 as i32) }) == -(1 as i32) {
            (unsafe { xmlFreeNode(node) });
            (unsafe { xmlBufferFree(buff2) });
            (unsafe { xmlBufferFree(buff) });
            return 0 as *mut xmlChar;
        }
        (unsafe { xmlBufferCat(buff, (*buff2).content) });
        (unsafe { xmlFreeNode(node) });
        (unsafe { xmlBufferFree(buff2) });
        cur_node = unsafe { (*cur_node).next };
    }
    resbuf = unsafe { (*buff).content };
    let fresh55 = unsafe { &mut ((*buff).content) };
    *fresh55 = 0 as *mut xmlChar;
    (unsafe { xmlBufferFree(buff) });
    return resbuf;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderReadOuterXml(mut reader: xmlTextReaderPtr) -> *mut xmlChar {
    let mut resbuf: *mut xmlChar = 0 as *mut xmlChar;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut buff: xmlBufferPtr = 0 as *mut xmlBuffer;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    if (xmlTextReaderExpand(reader)).is_null() {
        return 0 as *mut xmlChar;
    }
    node = unsafe { (*reader).node };
    doc = unsafe { (*node).doc };
    if (unsafe { (*node).type_0 }) as u32 == XML_DTD_NODE as i32 as u32 {
        node = (unsafe { xmlCopyDtd(node as xmlDtdPtr) }) as xmlNodePtr;
    } else {
        node = unsafe { xmlDocCopyNode(node, doc, 1 as i32) };
    }
    buff = unsafe { xmlBufferCreate() };
    (unsafe { xmlBufferSetAllocationScheme(buff, XML_BUFFER_ALLOC_DOUBLEIT) });
    if (unsafe { xmlNodeDump(buff, doc, node, 0 as i32, 0 as i32) }) == -(1 as i32) {
        (unsafe { xmlFreeNode(node) });
        (unsafe { xmlBufferFree(buff) });
        return 0 as *mut xmlChar;
    }
    resbuf = unsafe { (*buff).content };
    let fresh56 = unsafe { &mut ((*buff).content) };
    *fresh56 = 0 as *mut xmlChar;
    (unsafe { xmlFreeNode(node) });
    (unsafe { xmlBufferFree(buff) });
    return resbuf;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderReadString(mut reader: xmlTextReaderPtr) -> *mut xmlChar {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() || (unsafe { (*reader).node }).is_null() {
        return 0 as *mut xmlChar;
    }
    node = if !(unsafe { (*reader).curnode }).is_null() {
        unsafe { (*reader).curnode }
    } else {
        unsafe { (*reader).node }
    };
    match (unsafe { (*node).type_0 }) as u32 {
        3 => {
            if !(unsafe { (*node).content }).is_null() {
                return unsafe { xmlStrdup((*node).content) };
            }
        }
        1 => {
            if xmlTextReaderDoExpand(reader) != -(1 as i32) {
                return xmlTextReaderCollectSiblings(unsafe { (*node).children });
            }
        }
        2 => {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
                b"xmlreader.c\0" as *const u8 as *const i8,
                1740 as i32,
            ) });
        }
        _ => {}
    }
    return 0 as *mut xmlChar;
}
extern "C" fn xmlTextReaderNextTree(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).state }) as i32 == XML_TEXTREADER_END as i32 {
        return 0 as i32;
    }
    if (unsafe { (*reader).node }).is_null() {
        if (unsafe { (*(*reader).doc).children }).is_null() {
            (unsafe { (*reader).state = XML_TEXTREADER_END });
            return 0 as i32;
        }
        let fresh57 = unsafe { &mut ((*reader).node) };
        *fresh57 = unsafe { (*(*reader).doc).children };
        (unsafe { (*reader).state = XML_TEXTREADER_START });
        return 1 as i32;
    }
    if (unsafe { (*reader).state }) as i32 != XML_TEXTREADER_BACKTRACK as i32 {
        if !(unsafe { (*(*reader).node).next }).is_null() {
            let fresh58 = unsafe { &mut ((*reader).node) };
            *fresh58 = unsafe { (*(*reader).node).next };
            (unsafe { (*reader).state = XML_TEXTREADER_START });
            return 1 as i32;
        }
        (unsafe { (*reader).state = XML_TEXTREADER_BACKTRACK });
        xmlTextReaderRead(reader);
    }
    if !(unsafe { (*(*reader).node).next }).is_null() {
        let fresh59 = unsafe { &mut ((*reader).node) };
        *fresh59 = unsafe { (*(*reader).node).next };
        (unsafe { (*reader).state = XML_TEXTREADER_START });
        return 1 as i32;
    }
    if !(unsafe { (*(*reader).node).parent }).is_null() {
        if (unsafe { (*(*(*reader).node).parent).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32 {
            (unsafe { (*reader).state = XML_TEXTREADER_END });
            return 0 as i32;
        }
        let fresh60 = unsafe { &mut ((*reader).node) };
        *fresh60 = unsafe { (*(*reader).node).parent };
        let fresh61 = unsafe { &mut ((*reader).depth) };
        *fresh61 -= 1;
        (unsafe { (*reader).state = XML_TEXTREADER_BACKTRACK });
        xmlTextReaderNextTree(reader);
    }
    (unsafe { (*reader).state = XML_TEXTREADER_END });
    return 1 as i32;
}
extern "C" fn xmlTextReaderReadTree(mut reader: xmlTextReaderPtr) -> i32 {
    let mut current_block: u64;
    if (unsafe { (*reader).state }) as i32 == XML_TEXTREADER_END as i32 {
        return 0 as i32;
    }
    loop {
        if (unsafe { (*reader).node }).is_null() {
            if (unsafe { (*(*reader).doc).children }).is_null() {
                (unsafe { (*reader).state = XML_TEXTREADER_END });
                return 0 as i32;
            }
            let fresh62 = unsafe { &mut ((*reader).node) };
            *fresh62 = unsafe { (*(*reader).doc).children };
            (unsafe { (*reader).state = XML_TEXTREADER_START });
        } else {
            if (unsafe { (*reader).state }) as i32 != XML_TEXTREADER_BACKTRACK as i32
                && (unsafe { (*(*reader).node).type_0 }) as u32 != XML_DTD_NODE as i32 as u32
                && (unsafe { (*(*reader).node).type_0 }) as u32 != XML_XINCLUDE_START as i32 as u32
                && (unsafe { (*(*reader).node).type_0 }) as u32 != XML_ENTITY_REF_NODE as i32 as u32
            {
                if !(unsafe { (*(*reader).node).children }).is_null() {
                    let fresh63 = unsafe { &mut ((*reader).node) };
                    *fresh63 = unsafe { (*(*reader).node).children };
                    let fresh64 = unsafe { &mut ((*reader).depth) };
                    *fresh64 += 1;
                    (unsafe { (*reader).state = XML_TEXTREADER_START });
                    current_block = 4103914342875670315;
                } else if (unsafe { (*(*reader).node).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
                    (unsafe { (*reader).state = XML_TEXTREADER_BACKTRACK });
                    current_block = 4103914342875670315;
                } else {
                    current_block = 5143058163439228106;
                }
            } else {
                current_block = 5143058163439228106;
            }
            match current_block {
                4103914342875670315 => {}
                _ => {
                    if !(unsafe { (*(*reader).node).next }).is_null() {
                        let fresh65 = unsafe { &mut ((*reader).node) };
                        *fresh65 = unsafe { (*(*reader).node).next };
                        (unsafe { (*reader).state = XML_TEXTREADER_START });
                    } else if !(unsafe { (*(*reader).node).parent }).is_null() {
                        if (unsafe { (*(*(*reader).node).parent).type_0 }) as u32
                            == XML_DOCUMENT_NODE as i32 as u32
                            || (unsafe { (*(*(*reader).node).parent).type_0 }) as u32
                                == XML_HTML_DOCUMENT_NODE as i32 as u32
                        {
                            (unsafe { (*reader).state = XML_TEXTREADER_END });
                            return 0 as i32;
                        }
                        let fresh66 = unsafe { &mut ((*reader).node) };
                        *fresh66 = unsafe { (*(*reader).node).parent };
                        let fresh67 = unsafe { &mut ((*reader).depth) };
                        *fresh67 -= 1;
                        (unsafe { (*reader).state = XML_TEXTREADER_BACKTRACK });
                    } else {
                        (unsafe { (*reader).state = XML_TEXTREADER_END });
                    }
                }
            }
        }
        if !((unsafe { (*(*reader).node).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32
            || (unsafe { (*(*reader).node).type_0 }) as u32 == XML_XINCLUDE_END as i32 as u32)
        {
            break;
        }
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderNextSibling(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).doc }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).state }) as i32 == XML_TEXTREADER_END as i32 {
        return 0 as i32;
    }
    if (unsafe { (*reader).node }).is_null() {
        return xmlTextReaderNextTree(reader);
    }
    if !(unsafe { (*(*reader).node).next }).is_null() {
        let fresh68 = unsafe { &mut ((*reader).node) };
        *fresh68 = unsafe { (*(*reader).node).next };
        (unsafe { (*reader).state = XML_TEXTREADER_START });
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlNewTextReader(
    mut input: xmlParserInputBufferPtr,
    mut URI: *const i8,
) -> xmlTextReaderPtr {
    let mut ret: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    if input.is_null() {
        return 0 as xmlTextReaderPtr;
    }
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlTextReader>() as u64
    ) }) as xmlTextReaderPtr;
    if ret.is_null() {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlNewTextReader : malloc failed\n\0" as *const u8 as *const i8,
        ) });
        return 0 as xmlTextReaderPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlTextReader>() as u64,
    ) });
    let fresh69 = unsafe { &mut ((*ret).doc) };
    *fresh69 = 0 as xmlDocPtr;
    let fresh70 = unsafe { &mut ((*ret).entTab) };
    *fresh70 = 0 as *mut xmlNodePtr;
    (unsafe { (*ret).entMax = 0 as i32 });
    (unsafe { (*ret).entNr = 0 as i32 });
    let fresh71 = unsafe { &mut ((*ret).input) };
    *fresh71 = input;
    let fresh72 = unsafe { &mut ((*ret).buffer) };
    *fresh72 = unsafe { xmlBufCreateSize(100 as i32 as size_t) };
    if (unsafe { (*ret).buffer }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlNewTextReader : malloc failed\n\0" as *const u8 as *const i8,
        ) });
        return 0 as xmlTextReaderPtr;
    }
    (unsafe { xmlBufSetAllocationScheme((*ret).buffer, XML_BUFFER_ALLOC_DOUBLEIT) });
    let fresh73 = unsafe { &mut ((*ret).sax) };
    *fresh73 = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlSAXHandler>() as u64
    ) }) as *mut xmlSAXHandler;
    if (unsafe { (*ret).sax }).is_null() {
        (unsafe { xmlBufFree((*ret).buffer) });
        (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlNewTextReader : malloc failed\n\0" as *const u8 as *const i8,
        ) });
        return 0 as xmlTextReaderPtr;
    }
    (unsafe { xmlSAXVersion((*ret).sax, 2 as i32) });
    let fresh74 = unsafe { &mut ((*ret).startElement) };
    *fresh74 = unsafe { (*(*ret).sax).startElement };
    let fresh75 = unsafe { &mut ((*(*ret).sax).startElement) };
    *fresh75 = Some(
        xmlTextReaderStartElement
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *mut *const xmlChar) -> (),
    );
    let fresh76 = unsafe { &mut ((*ret).endElement) };
    *fresh76 = unsafe { (*(*ret).sax).endElement };
    let fresh77 = unsafe { &mut ((*(*ret).sax).endElement) };
    *fresh77 = Some(
        xmlTextReaderEndElement as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
    );
    if (unsafe { (*(*ret).sax).initialized }) == 0xdeedbeaf as u32 {
        let fresh78 = unsafe { &mut ((*ret).startElementNs) };
        *fresh78 = unsafe { (*(*ret).sax).startElementNs };
        let fresh79 = unsafe { &mut ((*(*ret).sax).startElementNs) };
        *fresh79 = Some(
            xmlTextReaderStartElementNs
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
        let fresh80 = unsafe { &mut ((*ret).endElementNs) };
        *fresh80 = unsafe { (*(*ret).sax).endElementNs };
        let fresh81 = unsafe { &mut ((*(*ret).sax).endElementNs) };
        *fresh81 = Some(
            xmlTextReaderEndElementNs
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const xmlChar,
                    *const xmlChar,
                    *const xmlChar,
                ) -> (),
        );
    } else {
        let fresh82 = unsafe { &mut ((*ret).startElementNs) };
        *fresh82 = None;
        let fresh83 = unsafe { &mut ((*ret).endElementNs) };
        *fresh83 = None;
    }
    let fresh84 = unsafe { &mut ((*ret).characters) };
    *fresh84 = unsafe { (*(*ret).sax).characters };
    let fresh85 = unsafe { &mut ((*(*ret).sax).characters) };
    *fresh85 = Some(
        xmlTextReaderCharacters
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh86 = unsafe { &mut ((*(*ret).sax).ignorableWhitespace) };
    *fresh86 = Some(
        xmlTextReaderCharacters
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh87 = unsafe { &mut ((*ret).cdataBlock) };
    *fresh87 = unsafe { (*(*ret).sax).cdataBlock };
    let fresh88 = unsafe { &mut ((*(*ret).sax).cdataBlock) };
    *fresh88 = Some(
        xmlTextReaderCDataBlock
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    (unsafe { (*ret).mode = XML_TEXTREADER_MODE_INITIAL as i32 });
    let fresh89 = unsafe { &mut ((*ret).node) };
    *fresh89 = 0 as xmlNodePtr;
    let fresh90 = unsafe { &mut ((*ret).curnode) };
    *fresh90 = 0 as xmlNodePtr;
    if (unsafe { xmlBufUse((*(*ret).input).buffer) }) < 4 as i32 as u64 {
        (unsafe { xmlParserInputBufferRead(input, 4 as i32) });
    }
    if (unsafe { xmlBufUse((*(*ret).input).buffer) }) >= 4 as i32 as u64 {
        let fresh91 = unsafe { &mut ((*ret).ctxt) };
        *fresh91 = unsafe { xmlCreatePushParserCtxt(
            (*ret).sax,
            0 as *mut libc::c_void,
            xmlBufContent((*(*ret).input).buffer as *const xmlBuf) as *const i8,
            4 as i32,
            URI,
        ) };
        (unsafe { (*ret).base = 0 as i32 as u32 });
        (unsafe { (*ret).cur = 4 as i32 as u32 });
    } else {
        let fresh92 = unsafe { &mut ((*ret).ctxt) };
        *fresh92 = unsafe { xmlCreatePushParserCtxt(
            (*ret).sax,
            0 as *mut libc::c_void,
            0 as *const i8,
            0 as i32,
            URI,
        ) };
        (unsafe { (*ret).base = 0 as i32 as u32 });
        (unsafe { (*ret).cur = 0 as i32 as u32 });
    }
    if (unsafe { (*ret).ctxt }).is_null() {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlNewTextReader : malloc failed\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { xmlBufFree((*ret).buffer) });
        (unsafe { xmlFree.expect("non-null function pointer")((*ret).sax as *mut libc::c_void) });
        (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
        return 0 as xmlTextReaderPtr;
    }
    (unsafe { (*(*ret).ctxt).parseMode = XML_PARSE_READER });
    let fresh93 = unsafe { &mut ((*(*ret).ctxt)._private) };
    *fresh93 = ret as *mut libc::c_void;
    (unsafe { (*(*ret).ctxt).linenumbers = 1 as i32 });
    (unsafe { (*(*ret).ctxt).dictNames = 1 as i32 });
    (unsafe { (*ret).allocs = 2 as i32 });
    (unsafe { (*(*ret).ctxt).docdict = 1 as i32 });
    let fresh94 = unsafe { &mut ((*ret).dict) };
    *fresh94 = unsafe { (*(*ret).ctxt).dict };
    (unsafe { (*ret).xinclude = 0 as i32 });
    (unsafe { (*ret).patternMax = 0 as i32 });
    let fresh95 = unsafe { &mut ((*ret).patternTab) };
    *fresh95 = 0 as *mut xmlPatternPtr;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlNewTextReaderFilename(mut URI: *const i8) -> xmlTextReaderPtr {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut ret: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut directory: *mut i8 = 0 as *mut i8;
    input = unsafe { xmlParserInputBufferCreateFilename(URI, XML_CHAR_ENCODING_NONE) };
    if input.is_null() {
        return 0 as xmlTextReaderPtr;
    }
    ret = xmlNewTextReader(input, URI);
    if ret.is_null() {
        (unsafe { xmlFreeParserInputBuffer(input) });
        return 0 as xmlTextReaderPtr;
    }
    (unsafe { (*ret).allocs |= 1 as i32 });
    if (unsafe { (*(*ret).ctxt).directory }).is_null() {
        directory = unsafe { xmlParserGetDirectory(URI) };
    }
    if (unsafe { (*(*ret).ctxt).directory }).is_null() && !directory.is_null() {
        let fresh96 = unsafe { &mut ((*(*ret).ctxt).directory) };
        *fresh96 = (unsafe { xmlStrdup(directory as *mut xmlChar) }) as *mut i8;
    }
    if !directory.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(directory as *mut libc::c_void) });
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlFreeTextReader(mut reader: xmlTextReaderPtr) {
    if reader.is_null() {
        return;
    }
    if !(unsafe { (*reader).rngSchemas }).is_null() {
        (unsafe { xmlRelaxNGFree((*reader).rngSchemas) });
        let fresh97 = unsafe { &mut ((*reader).rngSchemas) };
        *fresh97 = 0 as xmlRelaxNGPtr;
    }
    if !(unsafe { (*reader).rngValidCtxt }).is_null() {
        if (unsafe { (*reader).rngPreserveCtxt }) == 0 {
            (unsafe { xmlRelaxNGFreeValidCtxt((*reader).rngValidCtxt) });
        }
        let fresh98 = unsafe { &mut ((*reader).rngValidCtxt) };
        *fresh98 = 0 as xmlRelaxNGValidCtxtPtr;
    }
    if !(unsafe { (*reader).xsdPlug }).is_null() {
        (unsafe { xmlSchemaSAXUnplug((*reader).xsdPlug) });
        let fresh99 = unsafe { &mut ((*reader).xsdPlug) };
        *fresh99 = 0 as xmlSchemaSAXPlugPtr;
    }
    if !(unsafe { (*reader).xsdValidCtxt }).is_null() {
        if (unsafe { (*reader).xsdPreserveCtxt }) == 0 {
            (unsafe { xmlSchemaFreeValidCtxt((*reader).xsdValidCtxt) });
        }
        let fresh100 = unsafe { &mut ((*reader).xsdValidCtxt) };
        *fresh100 = 0 as xmlSchemaValidCtxtPtr;
    }
    if !(unsafe { (*reader).xsdSchemas }).is_null() {
        (unsafe { xmlSchemaFree((*reader).xsdSchemas) });
        let fresh101 = unsafe { &mut ((*reader).xsdSchemas) };
        *fresh101 = 0 as xmlSchemaPtr;
    }
    if !(unsafe { (*reader).xincctxt }).is_null() {
        (unsafe { xmlXIncludeFreeContext((*reader).xincctxt) });
    }
    if !(unsafe { (*reader).patternTab }).is_null() {
        let mut i: i32 = 0;
        i = 0 as i32;
        while i < (unsafe { (*reader).patternNr }) {
            if !(unsafe { *((*reader).patternTab).offset(i as isize) }).is_null() {
                (unsafe { xmlFreePattern(*((*reader).patternTab).offset(i as isize)) });
            }
            i += 1;
        }
        (unsafe { xmlFree.expect("non-null function pointer")((*reader).patternTab as *mut libc::c_void) });
    }
    if (unsafe { (*reader).mode }) != XML_TEXTREADER_MODE_CLOSED as i32 {
        xmlTextReaderClose(reader);
    }
    if !(unsafe { (*reader).ctxt }).is_null() {
        if (unsafe { (*reader).dict }) == (unsafe { (*(*reader).ctxt).dict }) {
            let fresh102 = unsafe { &mut ((*reader).dict) };
            *fresh102 = 0 as xmlDictPtr;
        }
        if (unsafe { (*reader).allocs }) & 2 as i32 != 0 {
            (unsafe { xmlFreeParserCtxt((*reader).ctxt) });
        }
    }
    if !(unsafe { (*reader).sax }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*reader).sax as *mut libc::c_void) });
    }
    if !(unsafe { (*reader).buffer }).is_null() {
        (unsafe { xmlBufFree((*reader).buffer) });
    }
    if !(unsafe { (*reader).entTab }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*reader).entTab as *mut libc::c_void) });
    }
    if !(unsafe { (*reader).dict }).is_null() {
        (unsafe { xmlDictFree((*reader).dict) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(reader as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlTextReaderClose(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    let fresh103 = unsafe { &mut ((*reader).node) };
    *fresh103 = 0 as xmlNodePtr;
    let fresh104 = unsafe { &mut ((*reader).curnode) };
    *fresh104 = 0 as xmlNodePtr;
    (unsafe { (*reader).mode = XML_TEXTREADER_MODE_CLOSED as i32 });
    if !(unsafe { (*reader).faketext }).is_null() {
        (unsafe { xmlFreeNode((*reader).faketext) });
        let fresh105 = unsafe { &mut ((*reader).faketext) };
        *fresh105 = 0 as xmlNodePtr;
    }
    if !(unsafe { (*reader).ctxt }).is_null() {
        if !(unsafe { (*(*reader).ctxt).vctxt.vstateTab }).is_null()
            && (unsafe { (*(*reader).ctxt).vctxt.vstateMax }) > 0 as i32
        {
            while (unsafe { (*(*reader).ctxt).vctxt.vstateNr }) > 0 as i32 {
                (unsafe { xmlValidatePopElement(
                    &mut (*(*reader).ctxt).vctxt,
                    0 as xmlDocPtr,
                    0 as xmlNodePtr,
                    0 as *const xmlChar,
                ) });
            }
            (unsafe { xmlFree.expect("non-null function pointer")(
                (*(*reader).ctxt).vctxt.vstateTab as *mut libc::c_void,
            ) });
            let fresh106 = unsafe { &mut ((*(*reader).ctxt).vctxt.vstateTab) };
            *fresh106 = 0 as *mut xmlValidState;
            (unsafe { (*(*reader).ctxt).vctxt.vstateMax = 0 as i32 });
        }
        (unsafe { xmlStopParser((*reader).ctxt) });
        if !(unsafe { (*(*reader).ctxt).myDoc }).is_null() {
            if (unsafe { (*reader).preserve }) == 0 as i32 {
                xmlTextReaderFreeDoc(reader, unsafe { (*(*reader).ctxt).myDoc });
            }
            let fresh107 = unsafe { &mut ((*(*reader).ctxt).myDoc) };
            *fresh107 = 0 as xmlDocPtr;
        }
    }
    if !(unsafe { (*reader).input }).is_null() && (unsafe { (*reader).allocs }) & 1 as i32 != 0 {
        (unsafe { xmlFreeParserInputBuffer((*reader).input) });
        (unsafe { (*reader).allocs -= 1 as i32 });
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderGetAttributeNo(
    mut reader: xmlTextReaderPtr,
    mut no: i32,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut i: i32 = 0;
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    if reader.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { (*reader).node }).is_null() {
        return 0 as *mut xmlChar;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { (*(*reader).node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as *mut xmlChar;
    }
    ns = unsafe { (*(*reader).node).nsDef };
    i = 0 as i32;
    while i < no && !ns.is_null() {
        ns = unsafe { (*ns).next };
        i += 1;
    }
    if !ns.is_null() {
        return unsafe { xmlStrdup((*ns).href) };
    }
    cur = unsafe { (*(*reader).node).properties };
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    while i < no {
        cur = unsafe { (*cur).next };
        if cur.is_null() {
            return 0 as *mut xmlChar;
        }
        i += 1;
    }
    ret = unsafe { xmlNodeListGetString((*(*reader).node).doc, (*cur).children, 1 as i32) };
    if ret.is_null() {
        return unsafe { xmlStrdup(b"\0" as *const u8 as *const i8 as *mut xmlChar) };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderGetAttribute(
    mut reader: xmlTextReaderPtr,
    mut name: *const xmlChar,
) -> *mut xmlChar {
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    let mut localname: *mut xmlChar = 0 as *mut xmlChar;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if reader.is_null() || name.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { (*reader).node }).is_null() {
        return 0 as *mut xmlChar;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { (*(*reader).node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as *mut xmlChar;
    }
    localname = unsafe { xmlSplitQName2(name, &mut prefix) };
    if localname.is_null() {
        if (unsafe { xmlStrEqual(name, b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
            ns = unsafe { (*(*reader).node).nsDef };
            while !ns.is_null() {
                if (unsafe { (*ns).prefix }).is_null() {
                    return unsafe { xmlStrdup((*ns).href) };
                }
                ns = unsafe { (*ns).next };
            }
            return 0 as *mut xmlChar;
        }
        return unsafe { xmlGetNoNsProp((*reader).node as *const xmlNode, name) };
    }
    if (unsafe { xmlStrEqual(prefix, b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
        ns = unsafe { (*(*reader).node).nsDef };
        while !ns.is_null() {
            if !(unsafe { (*ns).prefix }).is_null() && (unsafe { xmlStrEqual((*ns).prefix, localname) }) != 0 {
                ret = unsafe { xmlStrdup((*ns).href) };
                break;
            } else {
                ns = unsafe { (*ns).next };
            }
        }
    } else {
        ns = unsafe { xmlSearchNs((*(*reader).node).doc, (*reader).node, prefix) };
        if !ns.is_null() {
            ret = unsafe { xmlGetNsProp((*reader).node as *const xmlNode, localname, (*ns).href) };
        }
    }
    (unsafe { xmlFree.expect("non-null function pointer")(localname as *mut libc::c_void) });
    if !prefix.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderGetAttributeNs(
    mut reader: xmlTextReaderPtr,
    mut localName: *const xmlChar,
    mut namespaceURI: *const xmlChar,
) -> *mut xmlChar {
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    if reader.is_null() || localName.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { (*reader).node }).is_null() {
        return 0 as *mut xmlChar;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { (*(*reader).node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as *mut xmlChar;
    }
    if (unsafe { xmlStrEqual(
        namespaceURI,
        b"http://www.w3.org/2000/xmlns/\0" as *const u8 as *const i8 as *mut xmlChar,
    ) }) != 0
    {
        if (unsafe { xmlStrEqual(
            localName,
            b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
        ) }) == 0
        {
            prefix = localName as *mut xmlChar;
        }
        ns = unsafe { (*(*reader).node).nsDef };
        while !ns.is_null() {
            if prefix.is_null() && (unsafe { (*ns).prefix }).is_null()
                || !(unsafe { (*ns).prefix }).is_null() && (unsafe { xmlStrEqual((*ns).prefix, localName) }) != 0
            {
                return unsafe { xmlStrdup((*ns).href) };
            }
            ns = unsafe { (*ns).next };
        }
        return 0 as *mut xmlChar;
    }
    return unsafe { xmlGetNsProp((*reader).node as *const xmlNode, localName, namespaceURI) };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderGetRemainder(
    mut reader: xmlTextReaderPtr,
) -> xmlParserInputBufferPtr {
    let mut ret: xmlParserInputBufferPtr = 0 as xmlParserInputBufferPtr;
    if reader.is_null() {
        return 0 as xmlParserInputBufferPtr;
    }
    if (unsafe { (*reader).node }).is_null() {
        return 0 as xmlParserInputBufferPtr;
    }
    let fresh108 = unsafe { &mut ((*reader).node) };
    *fresh108 = 0 as xmlNodePtr;
    let fresh109 = unsafe { &mut ((*reader).curnode) };
    *fresh109 = 0 as xmlNodePtr;
    (unsafe { (*reader).mode = XML_TEXTREADER_MODE_EOF as i32 });
    if !(unsafe { (*reader).ctxt }).is_null() {
        (unsafe { xmlStopParser((*reader).ctxt) });
        if !(unsafe { (*(*reader).ctxt).myDoc }).is_null() {
            if (unsafe { (*reader).preserve }) == 0 as i32 {
                xmlTextReaderFreeDoc(reader, unsafe { (*(*reader).ctxt).myDoc });
            }
            let fresh110 = unsafe { &mut ((*(*reader).ctxt).myDoc) };
            *fresh110 = 0 as xmlDocPtr;
        }
    }
    if (unsafe { (*reader).allocs }) & 1 as i32 != 0 {
        ret = unsafe { (*reader).input };
        let fresh111 = unsafe { &mut ((*reader).input) };
        *fresh111 = 0 as xmlParserInputBufferPtr;
        (unsafe { (*reader).allocs -= 1 as i32 });
    } else {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
            b"xmlreader.c\0" as *const u8 as *const i8,
            2468 as i32,
        ) });
        return 0 as xmlParserInputBufferPtr;
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderLookupNamespace(
    mut reader: xmlTextReaderPtr,
    mut prefix: *const xmlChar,
) -> *mut xmlChar {
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    if reader.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { (*reader).node }).is_null() {
        return 0 as *mut xmlChar;
    }
    ns = unsafe { xmlSearchNs((*(*reader).node).doc, (*reader).node, prefix) };
    if ns.is_null() {
        return 0 as *mut xmlChar;
    }
    return unsafe { xmlStrdup((*ns).href) };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderMoveToAttributeNo(mut reader: xmlTextReaderPtr, mut no: i32) -> i32 {
    let mut i: i32 = 0;
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).node }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*(*reader).node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return -(1 as i32);
    }
    let fresh112 = unsafe { &mut ((*reader).curnode) };
    *fresh112 = 0 as xmlNodePtr;
    ns = unsafe { (*(*reader).node).nsDef };
    i = 0 as i32;
    while i < no && !ns.is_null() {
        ns = unsafe { (*ns).next };
        i += 1;
    }
    if !ns.is_null() {
        let fresh113 = unsafe { &mut ((*reader).curnode) };
        *fresh113 = ns as xmlNodePtr;
        return 1 as i32;
    }
    cur = unsafe { (*(*reader).node).properties };
    if cur.is_null() {
        return 0 as i32;
    }
    while i < no {
        cur = unsafe { (*cur).next };
        if cur.is_null() {
            return 0 as i32;
        }
        i += 1;
    }
    let fresh114 = unsafe { &mut ((*reader).curnode) };
    *fresh114 = cur as xmlNodePtr;
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderMoveToAttribute(
    mut reader: xmlTextReaderPtr,
    mut name: *const xmlChar,
) -> i32 {
    let mut current_block: u64;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    let mut localname: *mut xmlChar = 0 as *mut xmlChar;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut prop: xmlAttrPtr = 0 as *mut xmlAttr;
    if reader.is_null() || name.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).node }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*(*reader).node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as i32;
    }
    localname = unsafe { xmlSplitQName2(name, &mut prefix) };
    if localname.is_null() {
        if (unsafe { xmlStrEqual(name, b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
            ns = unsafe { (*(*reader).node).nsDef };
            while !ns.is_null() {
                if (unsafe { (*ns).prefix }).is_null() {
                    let fresh115 = unsafe { &mut ((*reader).curnode) };
                    *fresh115 = ns as xmlNodePtr;
                    return 1 as i32;
                }
                ns = unsafe { (*ns).next };
            }
            return 0 as i32;
        }
        prop = unsafe { (*(*reader).node).properties };
        while !prop.is_null() {
            if (unsafe { xmlStrEqual((*prop).name, name) }) != 0
                && ((unsafe { (*prop).ns }).is_null() || (unsafe { (*(*prop).ns).prefix }).is_null())
            {
                let fresh116 = unsafe { &mut ((*reader).curnode) };
                *fresh116 = prop as xmlNodePtr;
                return 1 as i32;
            }
            prop = unsafe { (*prop).next };
        }
        return 0 as i32;
    }
    if (unsafe { xmlStrEqual(prefix, b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
        ns = unsafe { (*(*reader).node).nsDef };
        loop {
            if ns.is_null() {
                current_block = 7357153348284164863;
                break;
            }
            if !(unsafe { (*ns).prefix }).is_null() && (unsafe { xmlStrEqual((*ns).prefix, localname) }) != 0 {
                let fresh117 = unsafe { &mut ((*reader).curnode) };
                *fresh117 = ns as xmlNodePtr;
                current_block = 17751903034314626763;
                break;
            } else {
                ns = unsafe { (*ns).next };
            }
        }
    } else {
        prop = unsafe { (*(*reader).node).properties };
        loop {
            if prop.is_null() {
                current_block = 7357153348284164863;
                break;
            }
            if (unsafe { xmlStrEqual((*prop).name, localname) }) != 0
                && !(unsafe { (*prop).ns }).is_null()
                && (unsafe { xmlStrEqual((*(*prop).ns).prefix, prefix) }) != 0
            {
                let fresh118 = unsafe { &mut ((*reader).curnode) };
                *fresh118 = prop as xmlNodePtr;
                current_block = 17751903034314626763;
                break;
            } else {
                prop = unsafe { (*prop).next };
            }
        }
    }
    match current_block {
        17751903034314626763 => {
            if !localname.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(localname as *mut libc::c_void) });
            }
            if !prefix.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
            }
            return 1 as i32;
        }
        _ => {
            if !localname.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(localname as *mut libc::c_void) });
            }
            if !prefix.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
            }
            return 0 as i32;
        }
    };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderMoveToAttributeNs(
    mut reader: xmlTextReaderPtr,
    mut localName: *const xmlChar,
    mut namespaceURI: *const xmlChar,
) -> i32 {
    let mut prop: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if reader.is_null() || localName.is_null() || namespaceURI.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).node }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*(*reader).node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as i32;
    }
    node = unsafe { (*reader).node };
    if (unsafe { xmlStrEqual(
        namespaceURI,
        b"http://www.w3.org/2000/xmlns/\0" as *const u8 as *const i8 as *mut xmlChar,
    ) }) != 0
    {
        if (unsafe { xmlStrEqual(
            localName,
            b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
        ) }) == 0
        {
            prefix = localName as *mut xmlChar;
        }
        ns = unsafe { (*(*reader).node).nsDef };
        while !ns.is_null() {
            if prefix.is_null() && (unsafe { (*ns).prefix }).is_null()
                || !(unsafe { (*ns).prefix }).is_null() && (unsafe { xmlStrEqual((*ns).prefix, localName) }) != 0
            {
                let fresh119 = unsafe { &mut ((*reader).curnode) };
                *fresh119 = ns as xmlNodePtr;
                return 1 as i32;
            }
            ns = unsafe { (*ns).next };
        }
        return 0 as i32;
    }
    prop = unsafe { (*node).properties };
    while !prop.is_null() {
        if (unsafe { xmlStrEqual((*prop).name, localName) }) != 0
            && (!(unsafe { (*prop).ns }).is_null() && (unsafe { xmlStrEqual((*(*prop).ns).href, namespaceURI) }) != 0)
        {
            let fresh120 = unsafe { &mut ((*reader).curnode) };
            *fresh120 = prop as xmlNodePtr;
            return 1 as i32;
        }
        prop = unsafe { (*prop).next };
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderMoveToFirstAttribute(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).node }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*(*reader).node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as i32;
    }
    if !(unsafe { (*(*reader).node).nsDef }).is_null() {
        let fresh121 = unsafe { &mut ((*reader).curnode) };
        *fresh121 = (unsafe { (*(*reader).node).nsDef }) as xmlNodePtr;
        return 1 as i32;
    }
    if !(unsafe { (*(*reader).node).properties }).is_null() {
        let fresh122 = unsafe { &mut ((*reader).curnode) };
        *fresh122 = (unsafe { (*(*reader).node).properties }) as xmlNodePtr;
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderMoveToNextAttribute(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).node }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*(*reader).node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as i32;
    }
    if (unsafe { (*reader).curnode }).is_null() {
        return xmlTextReaderMoveToFirstAttribute(reader);
    }
    if (unsafe { (*(*reader).curnode).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        let mut ns: xmlNsPtr = (unsafe { (*reader).curnode }) as xmlNsPtr;
        if !(unsafe { (*ns).next }).is_null() {
            let fresh123 = unsafe { &mut ((*reader).curnode) };
            *fresh123 = (unsafe { (*ns).next }) as xmlNodePtr;
            return 1 as i32;
        }
        if !(unsafe { (*(*reader).node).properties }).is_null() {
            let fresh124 = unsafe { &mut ((*reader).curnode) };
            *fresh124 = (unsafe { (*(*reader).node).properties }) as xmlNodePtr;
            return 1 as i32;
        }
        return 0 as i32;
    } else {
        if (unsafe { (*(*reader).curnode).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
            && !(unsafe { (*(*reader).curnode).next }).is_null()
        {
            let fresh125 = unsafe { &mut ((*reader).curnode) };
            *fresh125 = unsafe { (*(*reader).curnode).next };
            return 1 as i32;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderMoveToElement(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).node }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*(*reader).node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as i32;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        let fresh126 = unsafe { &mut ((*reader).curnode) };
        *fresh126 = 0 as xmlNodePtr;
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderReadAttributeValue(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).node }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).curnode }).is_null() {
        return 0 as i32;
    }
    if (unsafe { (*(*reader).curnode).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
        if (unsafe { (*(*reader).curnode).children }).is_null() {
            return 0 as i32;
        }
        let fresh127 = unsafe { &mut ((*reader).curnode) };
        *fresh127 = unsafe { (*(*reader).curnode).children };
    } else if (unsafe { (*(*reader).curnode).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        let mut ns: xmlNsPtr = (unsafe { (*reader).curnode }) as xmlNsPtr;
        if (unsafe { (*reader).faketext }).is_null() {
            let fresh128 = unsafe { &mut ((*reader).faketext) };
            *fresh128 = unsafe { xmlNewDocText((*(*reader).node).doc, (*ns).href) };
        } else {
            if !(unsafe { (*(*reader).faketext).content }).is_null()
                && (unsafe { (*(*reader).faketext).content })
                    != (unsafe { &mut (*(*reader).faketext).properties }) as *mut *mut _xmlAttr as *mut xmlChar
            {
                (unsafe { xmlFree.expect("non-null function pointer")(
                    (*(*reader).faketext).content as *mut libc::c_void,
                ) });
            }
            let fresh129 = unsafe { &mut ((*(*reader).faketext).content) };
            *fresh129 = unsafe { xmlStrdup((*ns).href) };
        }
        let fresh130 = unsafe { &mut ((*reader).curnode) };
        *fresh130 = unsafe { (*reader).faketext };
    } else {
        if (unsafe { (*(*reader).curnode).next }).is_null() {
            return 0 as i32;
        }
        let fresh131 = unsafe { &mut ((*reader).curnode) };
        *fresh131 = unsafe { (*(*reader).curnode).next };
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderConstEncoding(mut reader: xmlTextReaderPtr) -> *const xmlChar {
    let mut doc: xmlDocPtr = 0 as xmlDocPtr;
    if reader.is_null() {
        return 0 as *const xmlChar;
    }
    if !(unsafe { (*reader).doc }).is_null() {
        doc = unsafe { (*reader).doc };
    } else if !(unsafe { (*reader).ctxt }).is_null() {
        doc = unsafe { (*(*reader).ctxt).myDoc };
    }
    if doc.is_null() {
        return 0 as *const xmlChar;
    }
    if (unsafe { (*doc).encoding }).is_null() {
        return 0 as *const xmlChar;
    } else {
        return unsafe { xmlDictLookup((*reader).dict, (*doc).encoding, -(1 as i32)) };
    };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderAttributeCount(mut reader: xmlTextReaderPtr) -> i32 {
    let mut ret: i32 = 0;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).node }).is_null() {
        return 0 as i32;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as i32;
    }
    if (unsafe { (*reader).state }) as i32 == XML_TEXTREADER_END as i32
        || (unsafe { (*reader).state }) as i32 == XML_TEXTREADER_BACKTRACK as i32
    {
        return 0 as i32;
    }
    ret = 0 as i32;
    attr = unsafe { (*node).properties };
    while !attr.is_null() {
        ret += 1;
        attr = unsafe { (*attr).next };
    }
    ns = unsafe { (*node).nsDef };
    while !ns.is_null() {
        ret += 1;
        ns = unsafe { (*ns).next };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderNodeType(mut reader: xmlTextReaderPtr) -> i32 {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).node }).is_null() {
        return XML_READER_TYPE_NONE as i32;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    match (unsafe { (*node).type_0 }) as u32 {
        1 => {
            if (unsafe { (*reader).state }) as i32 == XML_TEXTREADER_END as i32
                || (unsafe { (*reader).state }) as i32 == XML_TEXTREADER_BACKTRACK as i32
            {
                return XML_READER_TYPE_END_ELEMENT as i32;
            }
            return XML_READER_TYPE_ELEMENT as i32;
        }
        18 | 2 => return XML_READER_TYPE_ATTRIBUTE as i32,
        3 => {
            if (unsafe { xmlIsBlankNode((*reader).node as *const xmlNode) }) != 0 {
                if (unsafe { xmlNodeGetSpacePreserve((*reader).node as *const xmlNode) }) != 0 {
                    return XML_READER_TYPE_SIGNIFICANT_WHITESPACE as i32;
                } else {
                    return XML_READER_TYPE_WHITESPACE as i32;
                }
            } else {
                return XML_READER_TYPE_TEXT as i32;
            }
        }
        4 => return XML_READER_TYPE_CDATA as i32,
        5 => return XML_READER_TYPE_ENTITY_REFERENCE as i32,
        6 => return XML_READER_TYPE_ENTITY as i32,
        7 => return XML_READER_TYPE_PROCESSING_INSTRUCTION as i32,
        8 => return XML_READER_TYPE_COMMENT as i32,
        9 | 13 => return XML_READER_TYPE_DOCUMENT as i32,
        11 => return XML_READER_TYPE_DOCUMENT_FRAGMENT as i32,
        12 => return XML_READER_TYPE_NOTATION as i32,
        10 | 14 => return XML_READER_TYPE_DOCUMENT_TYPE as i32,
        15 | 16 | 17 | 19 | 20 => return XML_READER_TYPE_NONE as i32,
        _ => {}
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlTextReaderIsEmptyElement(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() || (unsafe { (*reader).node }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*(*reader).node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as i32;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        return 0 as i32;
    }
    if !(unsafe { (*(*reader).node).children }).is_null() {
        return 0 as i32;
    }
    if (unsafe { (*reader).state }) as i32 == XML_TEXTREADER_END as i32 {
        return 0 as i32;
    }
    if !(unsafe { (*reader).doc }).is_null() {
        return 1 as i32;
    }
    if (unsafe { (*reader).in_xinclude }) > 0 as i32 {
        return 1 as i32;
    }
    return ((unsafe { (*(*reader).node).extra }) as i32 & 0x1 as i32 != 0 as i32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderLocalName(mut reader: xmlTextReaderPtr) -> *mut xmlChar {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() || (unsafe { (*reader).node }).is_null() {
        return 0 as *mut xmlChar;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    if (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        let mut ns: xmlNsPtr = node as xmlNsPtr;
        if (unsafe { (*ns).prefix }).is_null() {
            return unsafe { xmlStrdup(b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar) };
        } else {
            return unsafe { xmlStrdup((*ns).prefix) };
        }
    }
    if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32
    {
        return xmlTextReaderName(reader);
    }
    return unsafe { xmlStrdup((*node).name) };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderConstLocalName(mut reader: xmlTextReaderPtr) -> *const xmlChar {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() || (unsafe { (*reader).node }).is_null() {
        return 0 as *const xmlChar;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    if (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        let mut ns: xmlNsPtr = node as xmlNsPtr;
        if (unsafe { (*ns).prefix }).is_null() {
            return unsafe { xmlDictLookup(
                (*reader).dict,
                b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                -(1 as i32),
            ) };
        } else {
            return unsafe { (*ns).prefix };
        }
    }
    if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32
    {
        return xmlTextReaderConstName(reader);
    }
    return unsafe { (*node).name };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderName(mut reader: xmlTextReaderPtr) -> *mut xmlChar {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if reader.is_null() || (unsafe { (*reader).node }).is_null() {
        return 0 as *mut xmlChar;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    match (unsafe { (*node).type_0 }) as u32 {
        1 | 2 => {
            if (unsafe { (*node).ns }).is_null() || (unsafe { (*(*node).ns).prefix }).is_null() {
                return unsafe { xmlStrdup((*node).name) };
            }
            ret = unsafe { xmlStrdup((*(*node).ns).prefix) };
            ret = unsafe { xmlStrcat(ret, b":\0" as *const u8 as *const i8 as *mut xmlChar) };
            ret = unsafe { xmlStrcat(ret, (*node).name) };
            return ret;
        }
        3 => {
            return unsafe { xmlStrdup(b"#text\0" as *const u8 as *const i8 as *mut xmlChar) };
        }
        4 => {
            return unsafe { xmlStrdup(b"#cdata-section\0" as *const u8 as *const i8 as *mut xmlChar) };
        }
        6 | 5 => return unsafe { xmlStrdup((*node).name) },
        7 => return unsafe { xmlStrdup((*node).name) },
        8 => {
            return unsafe { xmlStrdup(b"#comment\0" as *const u8 as *const i8 as *mut xmlChar) };
        }
        9 | 13 => {
            return unsafe { xmlStrdup(b"#document\0" as *const u8 as *const i8 as *mut xmlChar) };
        }
        11 => {
            return unsafe { xmlStrdup(b"#document-fragment\0" as *const u8 as *const i8 as *mut xmlChar) };
        }
        12 => return unsafe { xmlStrdup((*node).name) },
        10 | 14 => return unsafe { xmlStrdup((*node).name) },
        18 => {
            let mut ns: xmlNsPtr = node as xmlNsPtr;
            ret = unsafe { xmlStrdup(b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar) };
            if (unsafe { (*ns).prefix }).is_null() {
                return ret;
            }
            ret = unsafe { xmlStrcat(ret, b":\0" as *const u8 as *const i8 as *mut xmlChar) };
            ret = unsafe { xmlStrcat(ret, (*ns).prefix) };
            return ret;
        }
        15 | 16 | 17 | 19 | 20 => return 0 as *mut xmlChar,
        _ => {}
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderConstName(mut reader: xmlTextReaderPtr) -> *const xmlChar {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() || (unsafe { (*reader).node }).is_null() {
        return 0 as *const xmlChar;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    match (unsafe { (*node).type_0 }) as u32 {
        1 | 2 => {
            if (unsafe { (*node).ns }).is_null() || (unsafe { (*(*node).ns).prefix }).is_null() {
                return unsafe { (*node).name };
            }
            return unsafe { xmlDictQLookup((*reader).dict, (*(*node).ns).prefix, (*node).name) };
        }
        3 => {
            return unsafe { xmlDictLookup(
                (*reader).dict,
                b"#text\0" as *const u8 as *const i8 as *mut xmlChar,
                -(1 as i32),
            ) };
        }
        4 => {
            return unsafe { xmlDictLookup(
                (*reader).dict,
                b"#cdata-section\0" as *const u8 as *const i8 as *mut xmlChar,
                -(1 as i32),
            ) };
        }
        6 | 5 => return unsafe { xmlDictLookup((*reader).dict, (*node).name, -(1 as i32)) },
        7 => return unsafe { xmlDictLookup((*reader).dict, (*node).name, -(1 as i32)) },
        8 => {
            return unsafe { xmlDictLookup(
                (*reader).dict,
                b"#comment\0" as *const u8 as *const i8 as *mut xmlChar,
                -(1 as i32),
            ) };
        }
        9 | 13 => {
            return unsafe { xmlDictLookup(
                (*reader).dict,
                b"#document\0" as *const u8 as *const i8 as *mut xmlChar,
                -(1 as i32),
            ) };
        }
        11 => {
            return unsafe { xmlDictLookup(
                (*reader).dict,
                b"#document-fragment\0" as *const u8 as *const i8 as *mut xmlChar,
                -(1 as i32),
            ) };
        }
        12 => return unsafe { xmlDictLookup((*reader).dict, (*node).name, -(1 as i32)) },
        10 | 14 => {
            return unsafe { xmlDictLookup((*reader).dict, (*node).name, -(1 as i32)) };
        }
        18 => {
            let mut ns: xmlNsPtr = node as xmlNsPtr;
            if (unsafe { (*ns).prefix }).is_null() {
                return unsafe { xmlDictLookup(
                    (*reader).dict,
                    b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                    -(1 as i32),
                ) };
            }
            return unsafe { xmlDictQLookup(
                (*reader).dict,
                b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                (*ns).prefix,
            ) };
        }
        15 | 16 | 17 | 19 | 20 => return 0 as *const xmlChar,
        _ => {}
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderPrefix(mut reader: xmlTextReaderPtr) -> *mut xmlChar {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() || (unsafe { (*reader).node }).is_null() {
        return 0 as *mut xmlChar;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    if (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        let mut ns: xmlNsPtr = node as xmlNsPtr;
        if (unsafe { (*ns).prefix }).is_null() {
            return 0 as *mut xmlChar;
        }
        return unsafe { xmlStrdup(b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar) };
    }
    if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32
    {
        return 0 as *mut xmlChar;
    }
    if !(unsafe { (*node).ns }).is_null() && !(unsafe { (*(*node).ns).prefix }).is_null() {
        return unsafe { xmlStrdup((*(*node).ns).prefix) };
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderConstPrefix(mut reader: xmlTextReaderPtr) -> *const xmlChar {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() || (unsafe { (*reader).node }).is_null() {
        return 0 as *const xmlChar;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    if (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        let mut ns: xmlNsPtr = node as xmlNsPtr;
        if (unsafe { (*ns).prefix }).is_null() {
            return 0 as *const xmlChar;
        }
        return unsafe { xmlDictLookup(
            (*reader).dict,
            b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
            -(1 as i32),
        ) };
    }
    if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32
    {
        return 0 as *const xmlChar;
    }
    if !(unsafe { (*node).ns }).is_null() && !(unsafe { (*(*node).ns).prefix }).is_null() {
        return unsafe { xmlDictLookup((*reader).dict, (*(*node).ns).prefix, -(1 as i32)) };
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderNamespaceUri(mut reader: xmlTextReaderPtr) -> *mut xmlChar {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() || (unsafe { (*reader).node }).is_null() {
        return 0 as *mut xmlChar;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    if (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return unsafe { xmlStrdup(
            b"http://www.w3.org/2000/xmlns/\0" as *const u8 as *const i8 as *mut xmlChar,
        ) };
    }
    if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32
    {
        return 0 as *mut xmlChar;
    }
    if !(unsafe { (*node).ns }).is_null() {
        return unsafe { xmlStrdup((*(*node).ns).href) };
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderConstNamespaceUri(mut reader: xmlTextReaderPtr) -> *const xmlChar {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() || (unsafe { (*reader).node }).is_null() {
        return 0 as *const xmlChar;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    if (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return unsafe { xmlDictLookup(
            (*reader).dict,
            b"http://www.w3.org/2000/xmlns/\0" as *const u8 as *const i8 as *mut xmlChar,
            -(1 as i32),
        ) };
    }
    if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32
    {
        return 0 as *const xmlChar;
    }
    if !(unsafe { (*node).ns }).is_null() {
        return unsafe { xmlDictLookup((*reader).dict, (*(*node).ns).href, -(1 as i32)) };
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderBaseUri(mut reader: xmlTextReaderPtr) -> *mut xmlChar {
    if reader.is_null() || (unsafe { (*reader).node }).is_null() {
        return 0 as *mut xmlChar;
    }
    return unsafe { xmlNodeGetBase(0 as *const xmlDoc, (*reader).node as *const xmlNode) };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderConstBaseUri(mut reader: xmlTextReaderPtr) -> *const xmlChar {
    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    if reader.is_null() || (unsafe { (*reader).node }).is_null() {
        return 0 as *const xmlChar;
    }
    tmp = unsafe { xmlNodeGetBase(0 as *const xmlDoc, (*reader).node as *const xmlNode) };
    if tmp.is_null() {
        return 0 as *const xmlChar;
    }
    ret = unsafe { xmlDictLookup((*reader).dict, tmp, -(1 as i32)) };
    (unsafe { xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderDepth(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).node }).is_null() {
        return 0 as i32;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        if (unsafe { (*(*reader).curnode).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
            || (unsafe { (*(*reader).curnode).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
        {
            return (unsafe { (*reader).depth }) + 1 as i32;
        }
        return (unsafe { (*reader).depth }) + 2 as i32;
    }
    return unsafe { (*reader).depth };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderHasAttributes(mut reader: xmlTextReaderPtr) -> i32 {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).node }).is_null() {
        return 0 as i32;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
        && (!(unsafe { (*node).properties }).is_null() || !(unsafe { (*node).nsDef }).is_null())
    {
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderHasValue(mut reader: xmlTextReaderPtr) -> i32 {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).node }).is_null() {
        return 0 as i32;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    match (unsafe { (*node).type_0 }) as u32 {
        2 | 3 | 4 | 7 | 8 | 18 => return 1 as i32,
        _ => {}
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderValue(mut reader: xmlTextReaderPtr) -> *mut xmlChar {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { (*reader).node }).is_null() {
        return 0 as *mut xmlChar;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    match (unsafe { (*node).type_0 }) as u32 {
        18 => return unsafe { xmlStrdup((*(node as xmlNsPtr)).href) },
        2 => {
            let mut attr: xmlAttrPtr = node as xmlAttrPtr;
            if !(unsafe { (*attr).parent }).is_null() {
                return unsafe { xmlNodeListGetString((*(*attr).parent).doc, (*attr).children, 1 as i32) };
            } else {
                return unsafe { xmlNodeListGetString(0 as xmlDocPtr, (*attr).children, 1 as i32) };
            }
        }
        3 | 4 | 7 | 8 => {
            if !(unsafe { (*node).content }).is_null() {
                return unsafe { xmlStrdup((*node).content) };
            }
        }
        _ => {}
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderConstValue(mut reader: xmlTextReaderPtr) -> *const xmlChar {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() {
        return 0 as *const xmlChar;
    }
    if (unsafe { (*reader).node }).is_null() {
        return 0 as *const xmlChar;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    match (unsafe { (*node).type_0 }) as u32 {
        18 => return unsafe { (*(node as xmlNsPtr)).href },
        2 => {
            let mut attr: xmlAttrPtr = node as xmlAttrPtr;
            let mut ret: *const xmlChar = 0 as *const xmlChar;
            if !(unsafe { (*attr).children }).is_null()
                && (unsafe { (*(*attr).children).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
                && (unsafe { (*(*attr).children).next }).is_null()
            {
                return unsafe { (*(*attr).children).content };
            } else {
                if (unsafe { (*reader).buffer }).is_null() {
                    let fresh132 = unsafe { &mut ((*reader).buffer) };
                    *fresh132 = unsafe { xmlBufCreateSize(100 as i32 as size_t) };
                    if (unsafe { (*reader).buffer }).is_null() {
                        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                            *__xmlGenericErrorContext(),
                            b"xmlTextReaderSetup : malloc failed\n\0" as *const u8 as *const i8,
                        ) });
                        return 0 as *const xmlChar;
                    }
                    (unsafe { xmlBufSetAllocationScheme((*reader).buffer, XML_BUFFER_ALLOC_DOUBLEIT) });
                } else {
                    (unsafe { xmlBufEmpty((*reader).buffer) });
                }
                (unsafe { xmlBufGetNodeContent((*reader).buffer, node as *const xmlNode) });
                ret = unsafe { xmlBufContent((*reader).buffer as *const xmlBuf) };
                if ret.is_null() {
                    (unsafe { xmlBufFree((*reader).buffer) });
                    let fresh133 = unsafe { &mut ((*reader).buffer) };
                    *fresh133 = unsafe { xmlBufCreateSize(100 as i32 as size_t) };
                    (unsafe { xmlBufSetAllocationScheme((*reader).buffer, XML_BUFFER_ALLOC_DOUBLEIT) });
                    ret = b"\0" as *const u8 as *const i8 as *mut xmlChar;
                }
                return ret;
            }
        }
        3 | 4 | 7 | 8 => return unsafe { (*node).content },
        _ => {}
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderIsDefault(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderQuoteChar(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    return '"' as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderXmlLang(mut reader: xmlTextReaderPtr) -> *mut xmlChar {
    if reader.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { (*reader).node }).is_null() {
        return 0 as *mut xmlChar;
    }
    return unsafe { xmlNodeGetLang((*reader).node as *const xmlNode) };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderConstXmlLang(mut reader: xmlTextReaderPtr) -> *const xmlChar {
    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    if reader.is_null() {
        return 0 as *const xmlChar;
    }
    if (unsafe { (*reader).node }).is_null() {
        return 0 as *const xmlChar;
    }
    tmp = unsafe { xmlNodeGetLang((*reader).node as *const xmlNode) };
    if tmp.is_null() {
        return 0 as *const xmlChar;
    }
    ret = unsafe { xmlDictLookup((*reader).dict, tmp, -(1 as i32)) };
    (unsafe { xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderConstString(
    mut reader: xmlTextReaderPtr,
    mut str: *const xmlChar,
) -> *const xmlChar {
    if reader.is_null() {
        return 0 as *const xmlChar;
    }
    return unsafe { xmlDictLookup((*reader).dict, str, -(1 as i32)) };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderNormalization(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderSetParserProp(
    mut reader: xmlTextReaderPtr,
    mut prop: i32,
    mut value: i32,
) -> i32 {
    let mut p: xmlParserProperties = prop as xmlParserProperties;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    if reader.is_null() || (unsafe { (*reader).ctxt }).is_null() {
        return -(1 as i32);
    }
    ctxt = unsafe { (*reader).ctxt };
    match p as u32 {
        1 => {
            if value != 0 as i32 {
                if (unsafe { (*ctxt).loadsubset }) == 0 as i32 {
                    if (unsafe { (*reader).mode }) != XML_TEXTREADER_MODE_INITIAL as i32 {
                        return -(1 as i32);
                    }
                    (unsafe { (*ctxt).loadsubset = 2 as i32 });
                }
            } else {
                (unsafe { (*ctxt).loadsubset = 0 as i32 });
            }
            return 0 as i32;
        }
        2 => {
            if value != 0 as i32 {
                (unsafe { (*ctxt).loadsubset |= 4 as i32 });
            } else if (unsafe { (*ctxt).loadsubset }) & 4 as i32 != 0 {
                (unsafe { (*ctxt).loadsubset -= 4 as i32 });
            }
            return 0 as i32;
        }
        3 => {
            if value != 0 as i32 {
                (unsafe { (*ctxt).options |= XML_PARSE_DTDVALID as i32 });
                (unsafe { (*ctxt).validate = 1 as i32 });
                (unsafe { (*reader).validate = XML_TEXTREADER_VALIDATE_DTD });
            } else {
                (unsafe { (*ctxt).options &= !(XML_PARSE_DTDVALID as i32) });
                (unsafe { (*ctxt).validate = 0 as i32 });
            }
            return 0 as i32;
        }
        4 => {
            if value != 0 as i32 {
                (unsafe { (*ctxt).options |= XML_PARSE_NOENT as i32 });
                (unsafe { (*ctxt).replaceEntities = 1 as i32 });
            } else {
                (unsafe { (*ctxt).options &= !(XML_PARSE_NOENT as i32) });
                (unsafe { (*ctxt).replaceEntities = 0 as i32 });
            }
            return 0 as i32;
        }
        _ => {}
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlTextReaderGetParserProp(mut reader: xmlTextReaderPtr, mut prop: i32) -> i32 {
    let mut p: xmlParserProperties = prop as xmlParserProperties;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    if reader.is_null() || (unsafe { (*reader).ctxt }).is_null() {
        return -(1 as i32);
    }
    ctxt = unsafe { (*reader).ctxt };
    match p as u32 {
        1 => {
            if (unsafe { (*ctxt).loadsubset }) != 0 as i32 || (unsafe { (*ctxt).validate }) != 0 as i32 {
                return 1 as i32;
            }
            return 0 as i32;
        }
        2 => {
            if (unsafe { (*ctxt).loadsubset }) & 4 as i32 != 0 {
                return 1 as i32;
            }
            return 0 as i32;
        }
        3 => return (unsafe { (*reader).validate }) as i32,
        4 => return unsafe { (*ctxt).replaceEntities },
        _ => {}
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlTextReaderGetParserLineNumber(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() || (unsafe { (*reader).ctxt }).is_null() || (unsafe { (*(*reader).ctxt).input }).is_null() {
        return 0 as i32;
    }
    return unsafe { (*(*(*reader).ctxt).input).line };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderGetParserColumnNumber(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() || (unsafe { (*reader).ctxt }).is_null() || (unsafe { (*(*reader).ctxt).input }).is_null() {
        return 0 as i32;
    }
    return unsafe { (*(*(*reader).ctxt).input).col };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderCurrentNode(mut reader: xmlTextReaderPtr) -> xmlNodePtr {
    if reader.is_null() {
        return 0 as xmlNodePtr;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        return unsafe { (*reader).curnode };
    }
    return unsafe { (*reader).node };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderPreserve(mut reader: xmlTextReaderPtr) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() {
        return 0 as xmlNodePtr;
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        cur = unsafe { (*reader).curnode };
    } else {
        cur = unsafe { (*reader).node };
    }
    if cur.is_null() {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*cur).type_0 }) as u32 != XML_DOCUMENT_NODE as i32 as u32
        && (unsafe { (*cur).type_0 }) as u32 != XML_DTD_NODE as i32 as u32
    {
        let fresh134 = unsafe { &mut ((*cur).extra) };
        *fresh134 = (*fresh134 as i32 | 0x2 as i32) as u16;
        let fresh135 = unsafe { &mut ((*cur).extra) };
        *fresh135 = (*fresh135 as i32 | 0x4 as i32) as u16;
    }
    let fresh136 = unsafe { &mut ((*reader).preserves) };
    *fresh136 += 1;
    parent = unsafe { (*cur).parent };
    while !parent.is_null() {
        if (unsafe { (*parent).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            let fresh137 = unsafe { &mut ((*parent).extra) };
            *fresh137 = (*fresh137 as i32 | 0x2 as i32) as u16;
        }
        parent = unsafe { (*parent).parent };
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderPreservePattern(
    mut reader: xmlTextReaderPtr,
    mut pattern: *const xmlChar,
    mut namespaces: *mut *const xmlChar,
) -> i32 {
    let mut comp: xmlPatternPtr = 0 as *mut xmlPattern;
    if reader.is_null() || pattern.is_null() {
        return -(1 as i32);
    }
    comp = unsafe { xmlPatterncompile(pattern, (*reader).dict, 0 as i32, namespaces) };
    if comp.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).patternMax }) <= 0 as i32 {
        (unsafe { (*reader).patternMax = 4 as i32 });
        let fresh138 = unsafe { &mut ((*reader).patternTab) };
        *fresh138 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ((*reader).patternMax as u64)
                .wrapping_mul(::std::mem::size_of::<xmlPatternPtr>() as u64),
        ) }) as *mut xmlPatternPtr;
        if (unsafe { (*reader).patternTab }).is_null() {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlMalloc failed !\n\0" as *const u8 as *const i8,
            ) });
            return -(1 as i32);
        }
    }
    if (unsafe { (*reader).patternNr }) >= (unsafe { (*reader).patternMax }) {
        let mut tmp: *mut xmlPatternPtr = 0 as *mut xmlPatternPtr;
        (unsafe { (*reader).patternMax *= 2 as i32 });
        tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*reader).patternTab as *mut libc::c_void,
            ((*reader).patternMax as u64)
                .wrapping_mul(::std::mem::size_of::<xmlPatternPtr>() as u64),
        ) }) as *mut xmlPatternPtr;
        if tmp.is_null() {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlRealloc failed !\n\0" as *const u8 as *const i8,
            ) });
            (unsafe { (*reader).patternMax /= 2 as i32 });
            return -(1 as i32);
        }
        let fresh139 = unsafe { &mut ((*reader).patternTab) };
        *fresh139 = tmp;
    }
    let fresh140 = unsafe { &mut (*((*reader).patternTab).offset((*reader).patternNr as isize)) };
    *fresh140 = comp;
    let fresh141 = unsafe { &mut ((*reader).patternNr) };
    let fresh142 = *fresh141;
    *fresh141 = *fresh141 + 1;
    return fresh142;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderCurrentDoc(mut reader: xmlTextReaderPtr) -> xmlDocPtr {
    if reader.is_null() {
        return 0 as xmlDocPtr;
    }
    if !(unsafe { (*reader).doc }).is_null() {
        return unsafe { (*reader).doc };
    }
    if (unsafe { (*reader).ctxt }).is_null() || (unsafe { (*(*reader).ctxt).myDoc }).is_null() {
        return 0 as xmlDocPtr;
    }
    (unsafe { (*reader).preserve = 1 as i32 });
    return unsafe { (*(*reader).ctxt).myDoc };
}
unsafe extern "C" fn xmlTextReaderValidityErrorRelay(
    mut ctx: *mut libc::c_void,
    mut msg: *const i8,
    mut args: ...
) {
    let mut reader: xmlTextReaderPtr = ctx as xmlTextReaderPtr;
    let mut str: *mut i8 = 0 as *mut i8;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    str = xmlTextReaderBuildMessage(msg, ap.as_va_list());
    if ((*reader).errorFunc).is_none() {
        xmlTextReaderValidityError(ctx, b"%s\0" as *const u8 as *const i8, str);
    } else {
        ((*reader).errorFunc).expect("non-null function pointer")(
            (*reader).errorFuncArg,
            str,
            XML_PARSER_SEVERITY_VALIDITY_ERROR,
            0 as *mut libc::c_void,
        );
    }
    if !str.is_null() {
        xmlFree.expect("non-null function pointer")(str as *mut libc::c_void);
    }
}
unsafe extern "C" fn xmlTextReaderValidityWarningRelay(
    mut ctx: *mut libc::c_void,
    mut msg: *const i8,
    mut args: ...
) {
    let mut reader: xmlTextReaderPtr = ctx as xmlTextReaderPtr;
    let mut str: *mut i8 = 0 as *mut i8;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    str = xmlTextReaderBuildMessage(msg, ap.as_va_list());
    if ((*reader).errorFunc).is_none() {
        xmlTextReaderValidityWarning(ctx, b"%s\0" as *const u8 as *const i8, str);
    } else {
        ((*reader).errorFunc).expect("non-null function pointer")(
            (*reader).errorFuncArg,
            str,
            XML_PARSER_SEVERITY_VALIDITY_WARNING,
            0 as *mut libc::c_void,
        );
    }
    if !str.is_null() {
        xmlFree.expect("non-null function pointer")(str as *mut libc::c_void);
    }
}
extern "C" fn xmlTextReaderValidityStructuredRelay(
    mut userData: *mut libc::c_void,
    mut error: xmlErrorPtr,
) {
    let mut reader: xmlTextReaderPtr = userData as xmlTextReaderPtr;
    if unsafe { ((*reader).sErrorFunc).is_some() } {
        (unsafe { ((*reader).sErrorFunc).expect("non-null function pointer")((*reader).errorFuncArg, error) });
    } else {
        xmlTextReaderStructuredError(reader as *mut libc::c_void, error);
    };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderRelaxNGSetSchema(
    mut reader: xmlTextReaderPtr,
    mut schema: xmlRelaxNGPtr,
) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    if schema.is_null() {
        if !(unsafe { (*reader).rngSchemas }).is_null() {
            (unsafe { xmlRelaxNGFree((*reader).rngSchemas) });
            let fresh143 = unsafe { &mut ((*reader).rngSchemas) };
            *fresh143 = 0 as xmlRelaxNGPtr;
        }
        if !(unsafe { (*reader).rngValidCtxt }).is_null() {
            if (unsafe { (*reader).rngPreserveCtxt }) == 0 {
                (unsafe { xmlRelaxNGFreeValidCtxt((*reader).rngValidCtxt) });
            }
            let fresh144 = unsafe { &mut ((*reader).rngValidCtxt) };
            *fresh144 = 0 as xmlRelaxNGValidCtxtPtr;
        }
        (unsafe { (*reader).rngPreserveCtxt = 0 as i32 });
        return 0 as i32;
    }
    if (unsafe { (*reader).mode }) != XML_TEXTREADER_MODE_INITIAL as i32 {
        return -(1 as i32);
    }
    if !(unsafe { (*reader).rngSchemas }).is_null() {
        (unsafe { xmlRelaxNGFree((*reader).rngSchemas) });
        let fresh145 = unsafe { &mut ((*reader).rngSchemas) };
        *fresh145 = 0 as xmlRelaxNGPtr;
    }
    if !(unsafe { (*reader).rngValidCtxt }).is_null() {
        if (unsafe { (*reader).rngPreserveCtxt }) == 0 {
            (unsafe { xmlRelaxNGFreeValidCtxt((*reader).rngValidCtxt) });
        }
        let fresh146 = unsafe { &mut ((*reader).rngValidCtxt) };
        *fresh146 = 0 as xmlRelaxNGValidCtxtPtr;
    }
    (unsafe { (*reader).rngPreserveCtxt = 0 as i32 });
    let fresh147 = unsafe { &mut ((*reader).rngValidCtxt) };
    *fresh147 = unsafe { xmlRelaxNGNewValidCtxt(schema) };
    if (unsafe { (*reader).rngValidCtxt }).is_null() {
        return -(1 as i32);
    }
    if unsafe { ((*reader).errorFunc).is_some() } {
        (unsafe { xmlRelaxNGSetValidErrors(
            (*reader).rngValidCtxt,
            Some(
                xmlTextReaderValidityErrorRelay
                    as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            Some(
                xmlTextReaderValidityWarningRelay
                    as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            reader as *mut libc::c_void,
        ) });
    }
    if unsafe { ((*reader).sErrorFunc).is_some() } {
        (unsafe { xmlRelaxNGSetValidStructuredErrors(
            (*reader).rngValidCtxt,
            Some(
                xmlTextReaderValidityStructuredRelay
                    as unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> (),
            ),
            reader as *mut libc::c_void,
        ) });
    }
    (unsafe { (*reader).rngValidErrors = 0 as i32 });
    let fresh148 = unsafe { &mut ((*reader).rngFullNode) };
    *fresh148 = 0 as xmlNodePtr;
    (unsafe { (*reader).validate = XML_TEXTREADER_VALIDATE_RNG });
    return 0 as i32;
}
extern "C" fn xmlTextReaderLocator(
    mut ctx: *mut libc::c_void,
    mut file: *mut *const i8,
    mut line: *mut u64,
) -> i32 {
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    if ctx.is_null() || file.is_null() && line.is_null() {
        return -(1 as i32);
    }
    if !file.is_null() {
        (unsafe { *file = 0 as *const i8 });
    }
    if !line.is_null() {
        (unsafe { *line = 0 as i32 as u64 });
    }
    reader = ctx as xmlTextReaderPtr;
    if !(unsafe { (*reader).ctxt }).is_null() && !(unsafe { (*(*reader).ctxt).input }).is_null() {
        if !file.is_null() {
            (unsafe { *file = (*(*(*reader).ctxt).input).filename });
        }
        if !line.is_null() {
            (unsafe { *line = (*(*(*reader).ctxt).input).line as u64 });
        }
        return 0 as i32;
    }
    if !(unsafe { (*reader).node }).is_null() {
        let mut res: i64 = 0;
        let mut ret: i32 = 0 as i32;
        if !line.is_null() {
            res = unsafe { xmlGetLineNo((*reader).node as *const xmlNode) };
            if res > 0 as i32 as i64 {
                (unsafe { *line = res as u64 });
            } else {
                ret = -(1 as i32);
            }
        }
        if !file.is_null() {
            let mut doc: xmlDocPtr = unsafe { (*(*reader).node).doc };
            if !doc.is_null() && !(unsafe { (*doc).URL }).is_null() {
                (unsafe { *file = (*doc).URL as *const i8 });
            } else {
                ret = -(1 as i32);
            }
        }
        return ret;
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlTextReaderSetSchema(
    mut reader: xmlTextReaderPtr,
    mut schema: xmlSchemaPtr,
) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    if schema.is_null() {
        if !(unsafe { (*reader).xsdPlug }).is_null() {
            (unsafe { xmlSchemaSAXUnplug((*reader).xsdPlug) });
            let fresh149 = unsafe { &mut ((*reader).xsdPlug) };
            *fresh149 = 0 as xmlSchemaSAXPlugPtr;
        }
        if !(unsafe { (*reader).xsdValidCtxt }).is_null() {
            if (unsafe { (*reader).xsdPreserveCtxt }) == 0 {
                (unsafe { xmlSchemaFreeValidCtxt((*reader).xsdValidCtxt) });
            }
            let fresh150 = unsafe { &mut ((*reader).xsdValidCtxt) };
            *fresh150 = 0 as xmlSchemaValidCtxtPtr;
        }
        (unsafe { (*reader).xsdPreserveCtxt = 0 as i32 });
        if !(unsafe { (*reader).xsdSchemas }).is_null() {
            (unsafe { xmlSchemaFree((*reader).xsdSchemas) });
            let fresh151 = unsafe { &mut ((*reader).xsdSchemas) };
            *fresh151 = 0 as xmlSchemaPtr;
        }
        return 0 as i32;
    }
    if (unsafe { (*reader).mode }) != XML_TEXTREADER_MODE_INITIAL as i32 {
        return -(1 as i32);
    }
    if !(unsafe { (*reader).xsdPlug }).is_null() {
        (unsafe { xmlSchemaSAXUnplug((*reader).xsdPlug) });
        let fresh152 = unsafe { &mut ((*reader).xsdPlug) };
        *fresh152 = 0 as xmlSchemaSAXPlugPtr;
    }
    if !(unsafe { (*reader).xsdValidCtxt }).is_null() {
        if (unsafe { (*reader).xsdPreserveCtxt }) == 0 {
            (unsafe { xmlSchemaFreeValidCtxt((*reader).xsdValidCtxt) });
        }
        let fresh153 = unsafe { &mut ((*reader).xsdValidCtxt) };
        *fresh153 = 0 as xmlSchemaValidCtxtPtr;
    }
    (unsafe { (*reader).xsdPreserveCtxt = 0 as i32 });
    if !(unsafe { (*reader).xsdSchemas }).is_null() {
        (unsafe { xmlSchemaFree((*reader).xsdSchemas) });
        let fresh154 = unsafe { &mut ((*reader).xsdSchemas) };
        *fresh154 = 0 as xmlSchemaPtr;
    }
    let fresh155 = unsafe { &mut ((*reader).xsdValidCtxt) };
    *fresh155 = unsafe { xmlSchemaNewValidCtxt(schema) };
    if (unsafe { (*reader).xsdValidCtxt }).is_null() {
        (unsafe { xmlSchemaFree((*reader).xsdSchemas) });
        let fresh156 = unsafe { &mut ((*reader).xsdSchemas) };
        *fresh156 = 0 as xmlSchemaPtr;
        return -(1 as i32);
    }
    let fresh157 = unsafe { &mut ((*reader).xsdPlug) };
    *fresh157 = unsafe { xmlSchemaSAXPlug(
        (*reader).xsdValidCtxt,
        &mut (*(*reader).ctxt).sax,
        &mut (*(*reader).ctxt).userData,
    ) };
    if (unsafe { (*reader).xsdPlug }).is_null() {
        (unsafe { xmlSchemaFree((*reader).xsdSchemas) });
        let fresh158 = unsafe { &mut ((*reader).xsdSchemas) };
        *fresh158 = 0 as xmlSchemaPtr;
        (unsafe { xmlSchemaFreeValidCtxt((*reader).xsdValidCtxt) });
        let fresh159 = unsafe { &mut ((*reader).xsdValidCtxt) };
        *fresh159 = 0 as xmlSchemaValidCtxtPtr;
        return -(1 as i32);
    }
    (unsafe { xmlSchemaValidateSetLocator(
        (*reader).xsdValidCtxt,
        Some(
            xmlTextReaderLocator
                as unsafe extern "C" fn(*mut libc::c_void, *mut *const i8, *mut u64) -> i32,
        ),
        reader as *mut libc::c_void,
    ) });
    if unsafe { ((*reader).errorFunc).is_some() } {
        (unsafe { xmlSchemaSetValidErrors(
            (*reader).xsdValidCtxt,
            Some(
                xmlTextReaderValidityErrorRelay
                    as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            Some(
                xmlTextReaderValidityWarningRelay
                    as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            reader as *mut libc::c_void,
        ) });
    }
    if unsafe { ((*reader).sErrorFunc).is_some() } {
        (unsafe { xmlSchemaSetValidStructuredErrors(
            (*reader).xsdValidCtxt,
            Some(
                xmlTextReaderValidityStructuredRelay
                    as unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> (),
            ),
            reader as *mut libc::c_void,
        ) });
    }
    (unsafe { (*reader).xsdValidErrors = 0 as i32 });
    (unsafe { (*reader).validate = XML_TEXTREADER_VALIDATE_XSD });
    return 0 as i32;
}
extern "C" fn xmlTextReaderRelaxNGValidateInternal(
    mut reader: xmlTextReaderPtr,
    mut rng: *const i8,
    mut ctxt: xmlRelaxNGValidCtxtPtr,
    mut _options: i32,
) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    if !rng.is_null() && !ctxt.is_null() {
        return -(1 as i32);
    }
    if (!rng.is_null() || !ctxt.is_null())
        && ((unsafe { (*reader).mode }) != XML_TEXTREADER_MODE_INITIAL as i32 || (unsafe { (*reader).ctxt }).is_null())
    {
        return -(1 as i32);
    }
    if !(unsafe { (*reader).rngValidCtxt }).is_null() {
        if (unsafe { (*reader).rngPreserveCtxt }) == 0 {
            (unsafe { xmlRelaxNGFreeValidCtxt((*reader).rngValidCtxt) });
        }
        let fresh160 = unsafe { &mut ((*reader).rngValidCtxt) };
        *fresh160 = 0 as xmlRelaxNGValidCtxtPtr;
    }
    (unsafe { (*reader).rngPreserveCtxt = 0 as i32 });
    if !(unsafe { (*reader).rngSchemas }).is_null() {
        (unsafe { xmlRelaxNGFree((*reader).rngSchemas) });
        let fresh161 = unsafe { &mut ((*reader).rngSchemas) };
        *fresh161 = 0 as xmlRelaxNGPtr;
    }
    if rng.is_null() && ctxt.is_null() {
        return 0 as i32;
    }
    if !rng.is_null() {
        let mut pctxt: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
        pctxt = unsafe { xmlRelaxNGNewParserCtxt(rng) };
        if unsafe { ((*reader).errorFunc).is_some() } {
            (unsafe { xmlRelaxNGSetParserErrors(
                pctxt,
                Some(
                    xmlTextReaderValidityErrorRelay
                        as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
                ),
                Some(
                    xmlTextReaderValidityWarningRelay
                        as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
                ),
                reader as *mut libc::c_void,
            ) });
        }
        if unsafe { ((*reader).sErrorFunc).is_some() } {
            (unsafe { xmlRelaxNGSetValidStructuredErrors(
                (*reader).rngValidCtxt,
                Some(
                    xmlTextReaderValidityStructuredRelay
                        as unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> (),
                ),
                reader as *mut libc::c_void,
            ) });
        }
        let fresh162 = unsafe { &mut ((*reader).rngSchemas) };
        *fresh162 = unsafe { xmlRelaxNGParse(pctxt) };
        (unsafe { xmlRelaxNGFreeParserCtxt(pctxt) });
        if (unsafe { (*reader).rngSchemas }).is_null() {
            return -(1 as i32);
        }
        let fresh163 = unsafe { &mut ((*reader).rngValidCtxt) };
        *fresh163 = unsafe { xmlRelaxNGNewValidCtxt((*reader).rngSchemas) };
        if (unsafe { (*reader).rngValidCtxt }).is_null() {
            (unsafe { xmlRelaxNGFree((*reader).rngSchemas) });
            let fresh164 = unsafe { &mut ((*reader).rngSchemas) };
            *fresh164 = 0 as xmlRelaxNGPtr;
            return -(1 as i32);
        }
    } else {
        let fresh165 = unsafe { &mut ((*reader).rngValidCtxt) };
        *fresh165 = ctxt;
        (unsafe { (*reader).rngPreserveCtxt = 1 as i32 });
    }
    if unsafe { ((*reader).errorFunc).is_some() } {
        (unsafe { xmlRelaxNGSetValidErrors(
            (*reader).rngValidCtxt,
            Some(
                xmlTextReaderValidityErrorRelay
                    as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            Some(
                xmlTextReaderValidityWarningRelay
                    as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            reader as *mut libc::c_void,
        ) });
    }
    if unsafe { ((*reader).sErrorFunc).is_some() } {
        (unsafe { xmlRelaxNGSetValidStructuredErrors(
            (*reader).rngValidCtxt,
            Some(
                xmlTextReaderValidityStructuredRelay
                    as unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> (),
            ),
            reader as *mut libc::c_void,
        ) });
    }
    (unsafe { (*reader).rngValidErrors = 0 as i32 });
    let fresh166 = unsafe { &mut ((*reader).rngFullNode) };
    *fresh166 = 0 as xmlNodePtr;
    (unsafe { (*reader).validate = XML_TEXTREADER_VALIDATE_RNG });
    return 0 as i32;
}
extern "C" fn xmlTextReaderSchemaValidateInternal(
    mut reader: xmlTextReaderPtr,
    mut xsd: *const i8,
    mut ctxt: xmlSchemaValidCtxtPtr,
    mut _options: i32,
) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    if !xsd.is_null() && !ctxt.is_null() {
        return -(1 as i32);
    }
    if (!xsd.is_null() || !ctxt.is_null())
        && ((unsafe { (*reader).mode }) != XML_TEXTREADER_MODE_INITIAL as i32 || (unsafe { (*reader).ctxt }).is_null())
    {
        return -(1 as i32);
    }
    if !(unsafe { (*reader).xsdPlug }).is_null() {
        (unsafe { xmlSchemaSAXUnplug((*reader).xsdPlug) });
        let fresh167 = unsafe { &mut ((*reader).xsdPlug) };
        *fresh167 = 0 as xmlSchemaSAXPlugPtr;
    }
    if !(unsafe { (*reader).xsdValidCtxt }).is_null() {
        if (unsafe { (*reader).xsdPreserveCtxt }) == 0 {
            (unsafe { xmlSchemaFreeValidCtxt((*reader).xsdValidCtxt) });
        }
        let fresh168 = unsafe { &mut ((*reader).xsdValidCtxt) };
        *fresh168 = 0 as xmlSchemaValidCtxtPtr;
    }
    (unsafe { (*reader).xsdPreserveCtxt = 0 as i32 });
    if !(unsafe { (*reader).xsdSchemas }).is_null() {
        (unsafe { xmlSchemaFree((*reader).xsdSchemas) });
        let fresh169 = unsafe { &mut ((*reader).xsdSchemas) };
        *fresh169 = 0 as xmlSchemaPtr;
    }
    if xsd.is_null() && ctxt.is_null() {
        return 0 as i32;
    }
    if !xsd.is_null() {
        let mut pctxt: xmlSchemaParserCtxtPtr = 0 as *mut xmlSchemaParserCtxt;
        pctxt = unsafe { xmlSchemaNewParserCtxt(xsd) };
        if unsafe { ((*reader).errorFunc).is_some() } {
            (unsafe { xmlSchemaSetParserErrors(
                pctxt,
                Some(
                    xmlTextReaderValidityErrorRelay
                        as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
                ),
                Some(
                    xmlTextReaderValidityWarningRelay
                        as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
                ),
                reader as *mut libc::c_void,
            ) });
        }
        let fresh170 = unsafe { &mut ((*reader).xsdSchemas) };
        *fresh170 = unsafe { xmlSchemaParse(pctxt) };
        (unsafe { xmlSchemaFreeParserCtxt(pctxt) });
        if (unsafe { (*reader).xsdSchemas }).is_null() {
            return -(1 as i32);
        }
        let fresh171 = unsafe { &mut ((*reader).xsdValidCtxt) };
        *fresh171 = unsafe { xmlSchemaNewValidCtxt((*reader).xsdSchemas) };
        if (unsafe { (*reader).xsdValidCtxt }).is_null() {
            (unsafe { xmlSchemaFree((*reader).xsdSchemas) });
            let fresh172 = unsafe { &mut ((*reader).xsdSchemas) };
            *fresh172 = 0 as xmlSchemaPtr;
            return -(1 as i32);
        }
        let fresh173 = unsafe { &mut ((*reader).xsdPlug) };
        *fresh173 = unsafe { xmlSchemaSAXPlug(
            (*reader).xsdValidCtxt,
            &mut (*(*reader).ctxt).sax,
            &mut (*(*reader).ctxt).userData,
        ) };
        if (unsafe { (*reader).xsdPlug }).is_null() {
            (unsafe { xmlSchemaFree((*reader).xsdSchemas) });
            let fresh174 = unsafe { &mut ((*reader).xsdSchemas) };
            *fresh174 = 0 as xmlSchemaPtr;
            (unsafe { xmlSchemaFreeValidCtxt((*reader).xsdValidCtxt) });
            let fresh175 = unsafe { &mut ((*reader).xsdValidCtxt) };
            *fresh175 = 0 as xmlSchemaValidCtxtPtr;
            return -(1 as i32);
        }
    } else {
        let fresh176 = unsafe { &mut ((*reader).xsdValidCtxt) };
        *fresh176 = ctxt;
        (unsafe { (*reader).xsdPreserveCtxt = 1 as i32 });
        let fresh177 = unsafe { &mut ((*reader).xsdPlug) };
        *fresh177 = unsafe { xmlSchemaSAXPlug(
            (*reader).xsdValidCtxt,
            &mut (*(*reader).ctxt).sax,
            &mut (*(*reader).ctxt).userData,
        ) };
        if (unsafe { (*reader).xsdPlug }).is_null() {
            let fresh178 = unsafe { &mut ((*reader).xsdValidCtxt) };
            *fresh178 = 0 as xmlSchemaValidCtxtPtr;
            (unsafe { (*reader).xsdPreserveCtxt = 0 as i32 });
            return -(1 as i32);
        }
    }
    (unsafe { xmlSchemaValidateSetLocator(
        (*reader).xsdValidCtxt,
        Some(
            xmlTextReaderLocator
                as unsafe extern "C" fn(*mut libc::c_void, *mut *const i8, *mut u64) -> i32,
        ),
        reader as *mut libc::c_void,
    ) });
    if unsafe { ((*reader).errorFunc).is_some() } {
        (unsafe { xmlSchemaSetValidErrors(
            (*reader).xsdValidCtxt,
            Some(
                xmlTextReaderValidityErrorRelay
                    as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            Some(
                xmlTextReaderValidityWarningRelay
                    as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            ),
            reader as *mut libc::c_void,
        ) });
    }
    if unsafe { ((*reader).sErrorFunc).is_some() } {
        (unsafe { xmlSchemaSetValidStructuredErrors(
            (*reader).xsdValidCtxt,
            Some(
                xmlTextReaderValidityStructuredRelay
                    as unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> (),
            ),
            reader as *mut libc::c_void,
        ) });
    }
    (unsafe { (*reader).xsdValidErrors = 0 as i32 });
    (unsafe { (*reader).validate = XML_TEXTREADER_VALIDATE_XSD });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderSchemaValidateCtxt(
    mut reader: xmlTextReaderPtr,
    mut ctxt: xmlSchemaValidCtxtPtr,
    mut options: i32,
) -> i32 {
    return xmlTextReaderSchemaValidateInternal(reader, 0 as *const i8, ctxt, options);
}
#[no_mangle]
pub extern "C" fn xmlTextReaderSchemaValidate(
    mut reader: xmlTextReaderPtr,
    mut xsd: *const i8,
) -> i32 {
    return xmlTextReaderSchemaValidateInternal(reader, xsd, 0 as xmlSchemaValidCtxtPtr, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlTextReaderRelaxNGValidateCtxt(
    mut reader: xmlTextReaderPtr,
    mut ctxt: xmlRelaxNGValidCtxtPtr,
    mut options: i32,
) -> i32 {
    return xmlTextReaderRelaxNGValidateInternal(reader, 0 as *const i8, ctxt, options);
}
#[no_mangle]
pub extern "C" fn xmlTextReaderRelaxNGValidate(
    mut reader: xmlTextReaderPtr,
    mut rng: *const i8,
) -> i32 {
    return xmlTextReaderRelaxNGValidateInternal(
        reader,
        rng,
        0 as xmlRelaxNGValidCtxtPtr,
        0 as i32,
    );
}
#[no_mangle]
pub extern "C" fn xmlTextReaderIsNamespaceDecl(mut reader: xmlTextReaderPtr) -> i32 {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).node }).is_null() {
        return -(1 as i32);
    }
    if !(unsafe { (*reader).curnode }).is_null() {
        node = unsafe { (*reader).curnode };
    } else {
        node = unsafe { (*reader).node };
    }
    if XML_NAMESPACE_DECL as i32 as u32 == (unsafe { (*node).type_0 }) as u32 {
        return 1 as i32;
    } else {
        return 0 as i32;
    };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderConstXmlVersion(mut reader: xmlTextReaderPtr) -> *const xmlChar {
    let mut doc: xmlDocPtr = 0 as xmlDocPtr;
    if reader.is_null() {
        return 0 as *const xmlChar;
    }
    if !(unsafe { (*reader).doc }).is_null() {
        doc = unsafe { (*reader).doc };
    } else if !(unsafe { (*reader).ctxt }).is_null() {
        doc = unsafe { (*(*reader).ctxt).myDoc };
    }
    if doc.is_null() {
        return 0 as *const xmlChar;
    }
    if (unsafe { (*doc).version }).is_null() {
        return 0 as *const xmlChar;
    } else {
        return unsafe { xmlDictLookup((*reader).dict, (*doc).version, -(1 as i32)) };
    };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderStandalone(mut reader: xmlTextReaderPtr) -> i32 {
    let mut doc: xmlDocPtr = 0 as xmlDocPtr;
    if reader.is_null() {
        return -(1 as i32);
    }
    if !(unsafe { (*reader).doc }).is_null() {
        doc = unsafe { (*reader).doc };
    } else if !(unsafe { (*reader).ctxt }).is_null() {
        doc = unsafe { (*(*reader).ctxt).myDoc };
    }
    if doc.is_null() {
        return -(1 as i32);
    }
    return unsafe { (*doc).standalone };
}
extern "C" fn xmlTextReaderBuildMessage(mut msg: *const i8, mut ap: ::std::ffi::VaList) -> *mut i8 {
    let mut size: i32 = 0 as i32;
    let mut chars: i32 = 0;
    let mut larger: *mut i8 = 0 as *mut i8;
    let mut str: *mut i8 = 0 as *mut i8;
    let mut aq: ::std::ffi::VaListImpl;
    loop {
        aq = ap.clone();
        chars = unsafe { vsnprintf(str, size as u64, msg, aq.as_va_list()) };
        if chars < 0 as i32 {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"vsnprintf failed !\n\0" as *const u8 as *const i8,
            ) });
            if !str.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(str as *mut libc::c_void) });
            }
            return 0 as *mut i8;
        }
        if chars < size || size == 64000 as i32 {
            break;
        }
        if chars < 64000 as i32 {
            size = chars + 1 as i32;
        } else {
            size = 64000 as i32;
        }
        larger = (unsafe { xmlRealloc.expect("non-null function pointer")(
            str as *mut libc::c_void,
            size as size_t,
        ) }) as *mut i8;
        if larger.is_null() {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlRealloc failed !\n\0" as *const u8 as *const i8,
            ) });
            if !str.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(str as *mut libc::c_void) });
            }
            return 0 as *mut i8;
        }
        str = larger;
    }
    return str;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderLocatorLineNumber(mut locator: xmlTextReaderLocatorPtr) -> i32 {
    let mut ctx: xmlParserCtxtPtr = locator as xmlParserCtxtPtr;
    let mut ret: i32 = -(1 as i32);
    if locator.is_null() {
        return -(1 as i32);
    }
    if !(unsafe { (*ctx).node }).is_null() {
        ret = (unsafe { xmlGetLineNo((*ctx).node as *const xmlNode) }) as i32;
    } else {
        let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
        input = unsafe { (*ctx).input };
        if (unsafe { (*input).filename }).is_null() && (unsafe { (*ctx).inputNr }) > 1 as i32 {
            input = unsafe { *((*ctx).inputTab).offset(((*ctx).inputNr - 2 as i32) as isize) };
        }
        if !input.is_null() {
            ret = unsafe { (*input).line };
        } else {
            ret = -(1 as i32);
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderLocatorBaseURI(
    mut locator: xmlTextReaderLocatorPtr,
) -> *mut xmlChar {
    let mut ctx: xmlParserCtxtPtr = locator as xmlParserCtxtPtr;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if locator.is_null() {
        return 0 as *mut xmlChar;
    }
    if !(unsafe { (*ctx).node }).is_null() {
        ret = unsafe { xmlNodeGetBase(0 as *const xmlDoc, (*ctx).node as *const xmlNode) };
    } else {
        let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
        input = unsafe { (*ctx).input };
        if (unsafe { (*input).filename }).is_null() && (unsafe { (*ctx).inputNr }) > 1 as i32 {
            input = unsafe { *((*ctx).inputTab).offset(((*ctx).inputNr - 2 as i32) as isize) };
        }
        if !input.is_null() {
            ret = unsafe { xmlStrdup((*input).filename as *mut xmlChar) };
        } else {
            ret = 0 as *mut xmlChar;
        }
    }
    return ret;
}
extern "C" fn xmlTextReaderGenericError(
    mut ctxt: *mut libc::c_void,
    mut severity: xmlParserSeverities,
    mut str: *mut i8,
) {
    let mut ctx: xmlParserCtxtPtr = ctxt as xmlParserCtxtPtr;
    let mut reader: xmlTextReaderPtr = (unsafe { (*ctx)._private }) as xmlTextReaderPtr;
    if !str.is_null() {
        if unsafe { ((*reader).errorFunc).is_some() } {
            (unsafe { ((*reader).errorFunc).expect("non-null function pointer")(
                (*reader).errorFuncArg,
                str,
                severity,
                ctx as xmlTextReaderLocatorPtr,
            ) });
        }
        (unsafe { xmlFree.expect("non-null function pointer")(str as *mut libc::c_void) });
    }
}
extern "C" fn xmlTextReaderStructuredError(mut ctxt: *mut libc::c_void, mut error: xmlErrorPtr) {
    let mut ctx: xmlParserCtxtPtr = ctxt as xmlParserCtxtPtr;
    let mut reader: xmlTextReaderPtr = (unsafe { (*ctx)._private }) as xmlTextReaderPtr;
    if !error.is_null() && (unsafe { ((*reader).sErrorFunc).is_some() }) {
        (unsafe { ((*reader).sErrorFunc).expect("non-null function pointer")((*reader).errorFuncArg, error) });
    }
}
unsafe extern "C" fn xmlTextReaderError(
    mut ctxt: *mut libc::c_void,
    mut msg: *const i8,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    xmlTextReaderGenericError(
        ctxt,
        XML_PARSER_SEVERITY_ERROR,
        xmlTextReaderBuildMessage(msg, ap.as_va_list()),
    );
}
unsafe extern "C" fn xmlTextReaderWarning(
    mut ctxt: *mut libc::c_void,
    mut msg: *const i8,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    xmlTextReaderGenericError(
        ctxt,
        XML_PARSER_SEVERITY_WARNING,
        xmlTextReaderBuildMessage(msg, ap.as_va_list()),
    );
}
unsafe extern "C" fn xmlTextReaderValidityError(
    mut ctxt: *mut libc::c_void,
    mut msg: *const i8,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    let mut len: i32 = xmlStrlen(msg as *const xmlChar);
    if len > 1 as i32 && *msg.offset((len - 2 as i32) as isize) as i32 != ':' as i32 {
        ap = args.clone();
        xmlTextReaderGenericError(
            ctxt,
            XML_PARSER_SEVERITY_VALIDITY_ERROR,
            xmlTextReaderBuildMessage(msg, ap.as_va_list()),
        );
    }
}
unsafe extern "C" fn xmlTextReaderValidityWarning(
    mut ctxt: *mut libc::c_void,
    mut msg: *const i8,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    let mut len: i32 = xmlStrlen(msg as *const xmlChar);
    if len != 0 as i32 && *msg.offset((len - 1 as i32) as isize) as i32 != ':' as i32 {
        ap = args.clone();
        xmlTextReaderGenericError(
            ctxt,
            XML_PARSER_SEVERITY_VALIDITY_WARNING,
            xmlTextReaderBuildMessage(msg, ap.as_va_list()),
        );
    }
}
#[no_mangle]
pub extern "C" fn xmlTextReaderSetErrorHandler(
    mut reader: xmlTextReaderPtr,
    mut f: xmlTextReaderErrorFunc,
    mut arg: *mut libc::c_void,
) {
    if f.is_some() {
        let fresh179 = unsafe { &mut ((*(*(*reader).ctxt).sax).error) };
        *fresh179 = Some(
            xmlTextReaderError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
        );
        let fresh180 = unsafe { &mut ((*(*(*reader).ctxt).sax).serror) };
        *fresh180 = None;
        let fresh181 = unsafe { &mut ((*(*reader).ctxt).vctxt.error) };
        *fresh181 = Some(
            xmlTextReaderValidityError
                as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
        );
        let fresh182 = unsafe { &mut ((*(*(*reader).ctxt).sax).warning) };
        *fresh182 = Some(
            xmlTextReaderWarning as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
        );
        let fresh183 = unsafe { &mut ((*(*reader).ctxt).vctxt.warning) };
        *fresh183 = Some(
            xmlTextReaderValidityWarning
                as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
        );
        let fresh184 = unsafe { &mut ((*reader).errorFunc) };
        *fresh184 = f;
        let fresh185 = unsafe { &mut ((*reader).sErrorFunc) };
        *fresh185 = None;
        let fresh186 = unsafe { &mut ((*reader).errorFuncArg) };
        *fresh186 = arg;
        if !(unsafe { (*reader).rngValidCtxt }).is_null() {
            (unsafe { xmlRelaxNGSetValidErrors(
                (*reader).rngValidCtxt,
                Some(
                    xmlTextReaderValidityErrorRelay
                        as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
                ),
                Some(
                    xmlTextReaderValidityWarningRelay
                        as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
                ),
                reader as *mut libc::c_void,
            ) });
            (unsafe { xmlRelaxNGSetValidStructuredErrors(
                (*reader).rngValidCtxt,
                None,
                reader as *mut libc::c_void,
            ) });
        }
        if !(unsafe { (*reader).xsdValidCtxt }).is_null() {
            (unsafe { xmlSchemaSetValidErrors(
                (*reader).xsdValidCtxt,
                Some(
                    xmlTextReaderValidityErrorRelay
                        as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
                ),
                Some(
                    xmlTextReaderValidityWarningRelay
                        as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
                ),
                reader as *mut libc::c_void,
            ) });
            (unsafe { xmlSchemaSetValidStructuredErrors(
                (*reader).xsdValidCtxt,
                None,
                reader as *mut libc::c_void,
            ) });
        }
    } else {
        let fresh187 = unsafe { &mut ((*(*(*reader).ctxt).sax).error) };
        *fresh187 =
            Some(xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
        let fresh188 = unsafe { &mut ((*(*reader).ctxt).vctxt.error) };
        *fresh188 = Some(
            xmlParserValidityError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
        );
        let fresh189 = unsafe { &mut ((*(*(*reader).ctxt).sax).warning) };
        *fresh189 =
            Some(xmlParserWarning as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
        let fresh190 = unsafe { &mut ((*(*reader).ctxt).vctxt.warning) };
        *fresh190 = Some(
            xmlParserValidityWarning
                as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
        );
        let fresh191 = unsafe { &mut ((*reader).errorFunc) };
        *fresh191 = None;
        let fresh192 = unsafe { &mut ((*reader).sErrorFunc) };
        *fresh192 = None;
        let fresh193 = unsafe { &mut ((*reader).errorFuncArg) };
        *fresh193 = 0 as *mut libc::c_void;
        if !(unsafe { (*reader).rngValidCtxt }).is_null() {
            (unsafe { xmlRelaxNGSetValidErrors(
                (*reader).rngValidCtxt,
                None,
                None,
                reader as *mut libc::c_void,
            ) });
            (unsafe { xmlRelaxNGSetValidStructuredErrors(
                (*reader).rngValidCtxt,
                None,
                reader as *mut libc::c_void,
            ) });
        }
        if !(unsafe { (*reader).xsdValidCtxt }).is_null() {
            (unsafe { xmlSchemaSetValidErrors(
                (*reader).xsdValidCtxt,
                None,
                None,
                reader as *mut libc::c_void,
            ) });
            (unsafe { xmlSchemaSetValidStructuredErrors(
                (*reader).xsdValidCtxt,
                None,
                reader as *mut libc::c_void,
            ) });
        }
    };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderSetStructuredErrorHandler(
    mut reader: xmlTextReaderPtr,
    mut f: xmlStructuredErrorFunc,
    mut arg: *mut libc::c_void,
) {
    if f.is_some() {
        let fresh194 = unsafe { &mut ((*(*(*reader).ctxt).sax).error) };
        *fresh194 = None;
        let fresh195 = unsafe { &mut ((*(*(*reader).ctxt).sax).serror) };
        *fresh195 = Some(
            xmlTextReaderStructuredError
                as unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> (),
        );
        let fresh196 = unsafe { &mut ((*(*reader).ctxt).vctxt.error) };
        *fresh196 = Some(
            xmlTextReaderValidityError
                as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
        );
        let fresh197 = unsafe { &mut ((*(*(*reader).ctxt).sax).warning) };
        *fresh197 = Some(
            xmlTextReaderWarning as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
        );
        let fresh198 = unsafe { &mut ((*(*reader).ctxt).vctxt.warning) };
        *fresh198 = Some(
            xmlTextReaderValidityWarning
                as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
        );
        let fresh199 = unsafe { &mut ((*reader).sErrorFunc) };
        *fresh199 = f;
        let fresh200 = unsafe { &mut ((*reader).errorFunc) };
        *fresh200 = None;
        let fresh201 = unsafe { &mut ((*reader).errorFuncArg) };
        *fresh201 = arg;
        if !(unsafe { (*reader).rngValidCtxt }).is_null() {
            (unsafe { xmlRelaxNGSetValidErrors(
                (*reader).rngValidCtxt,
                None,
                None,
                reader as *mut libc::c_void,
            ) });
            (unsafe { xmlRelaxNGSetValidStructuredErrors(
                (*reader).rngValidCtxt,
                Some(
                    xmlTextReaderValidityStructuredRelay
                        as unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> (),
                ),
                reader as *mut libc::c_void,
            ) });
        }
        if !(unsafe { (*reader).xsdValidCtxt }).is_null() {
            (unsafe { xmlSchemaSetValidErrors(
                (*reader).xsdValidCtxt,
                None,
                None,
                reader as *mut libc::c_void,
            ) });
            (unsafe { xmlSchemaSetValidStructuredErrors(
                (*reader).xsdValidCtxt,
                Some(
                    xmlTextReaderValidityStructuredRelay
                        as unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> (),
                ),
                reader as *mut libc::c_void,
            ) });
        }
    } else {
        let fresh202 = unsafe { &mut ((*(*(*reader).ctxt).sax).error) };
        *fresh202 =
            Some(xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
        let fresh203 = unsafe { &mut ((*(*(*reader).ctxt).sax).serror) };
        *fresh203 = None;
        let fresh204 = unsafe { &mut ((*(*reader).ctxt).vctxt.error) };
        *fresh204 = Some(
            xmlParserValidityError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
        );
        let fresh205 = unsafe { &mut ((*(*(*reader).ctxt).sax).warning) };
        *fresh205 =
            Some(xmlParserWarning as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
        let fresh206 = unsafe { &mut ((*(*reader).ctxt).vctxt.warning) };
        *fresh206 = Some(
            xmlParserValidityWarning
                as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
        );
        let fresh207 = unsafe { &mut ((*reader).errorFunc) };
        *fresh207 = None;
        let fresh208 = unsafe { &mut ((*reader).sErrorFunc) };
        *fresh208 = None;
        let fresh209 = unsafe { &mut ((*reader).errorFuncArg) };
        *fresh209 = 0 as *mut libc::c_void;
        if !(unsafe { (*reader).rngValidCtxt }).is_null() {
            (unsafe { xmlRelaxNGSetValidErrors(
                (*reader).rngValidCtxt,
                None,
                None,
                reader as *mut libc::c_void,
            ) });
            (unsafe { xmlRelaxNGSetValidStructuredErrors(
                (*reader).rngValidCtxt,
                None,
                reader as *mut libc::c_void,
            ) });
        }
        if !(unsafe { (*reader).xsdValidCtxt }).is_null() {
            (unsafe { xmlSchemaSetValidErrors(
                (*reader).xsdValidCtxt,
                None,
                None,
                reader as *mut libc::c_void,
            ) });
            (unsafe { xmlSchemaSetValidStructuredErrors(
                (*reader).xsdValidCtxt,
                None,
                reader as *mut libc::c_void,
            ) });
        }
    };
}
#[no_mangle]
pub extern "C" fn xmlTextReaderIsValid(mut reader: xmlTextReaderPtr) -> i32 {
    if reader.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*reader).validate }) as u32 == XML_TEXTREADER_VALIDATE_RNG as i32 as u32 {
        return ((unsafe { (*reader).rngValidErrors }) == 0 as i32) as i32;
    }
    if (unsafe { (*reader).validate }) as u32 == XML_TEXTREADER_VALIDATE_XSD as i32 as u32 {
        return ((unsafe { (*reader).xsdValidErrors }) == 0 as i32) as i32;
    }
    if !(unsafe { (*reader).ctxt }).is_null() && (unsafe { (*(*reader).ctxt).validate }) == 1 as i32 {
        return unsafe { (*(*reader).ctxt).valid };
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderGetErrorHandler(
    mut reader: xmlTextReaderPtr,
    mut f: *mut xmlTextReaderErrorFunc,
    mut arg: *mut *mut libc::c_void,
) {
    if !f.is_null() {
        (unsafe { *f = (*reader).errorFunc });
    }
    if !arg.is_null() {
        (unsafe { *arg = (*reader).errorFuncArg });
    }
}
#[no_mangle]
pub extern "C" fn xmlTextReaderSetup(
    mut reader: xmlTextReaderPtr,
    mut input: xmlParserInputBufferPtr,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> i32 {
    if reader.is_null() {
        if !input.is_null() {
            (unsafe { xmlFreeParserInputBuffer(input) });
        }
        return -(1 as i32);
    }
    options |= XML_PARSE_COMPACT as i32;
    let fresh210 = unsafe { &mut ((*reader).doc) };
    *fresh210 = 0 as xmlDocPtr;
    (unsafe { (*reader).entNr = 0 as i32 });
    (unsafe { (*reader).parserFlags = options });
    (unsafe { (*reader).validate = XML_TEXTREADER_NOT_VALIDATE });
    if !input.is_null() && !(unsafe { (*reader).input }).is_null() && (unsafe { (*reader).allocs }) & 1 as i32 != 0 {
        (unsafe { xmlFreeParserInputBuffer((*reader).input) });
        let fresh211 = unsafe { &mut ((*reader).input) };
        *fresh211 = 0 as xmlParserInputBufferPtr;
        (unsafe { (*reader).allocs -= 1 as i32 });
    }
    if !input.is_null() {
        let fresh212 = unsafe { &mut ((*reader).input) };
        *fresh212 = input;
        (unsafe { (*reader).allocs |= 1 as i32 });
    }
    if (unsafe { (*reader).buffer }).is_null() {
        let fresh213 = unsafe { &mut ((*reader).buffer) };
        *fresh213 = unsafe { xmlBufCreateSize(100 as i32 as size_t) };
    }
    if (unsafe { (*reader).buffer }).is_null() {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlTextReaderSetup : malloc failed\n\0" as *const u8 as *const i8,
        ) });
        return -(1 as i32);
    }
    (unsafe { xmlBufSetAllocationScheme((*reader).buffer, XML_BUFFER_ALLOC_DOUBLEIT) });
    if (unsafe { (*reader).sax }).is_null() {
        let fresh214 = unsafe { &mut ((*reader).sax) };
        *fresh214 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlSAXHandler>() as u64,
        ) }) as *mut xmlSAXHandler;
    }
    if (unsafe { (*reader).sax }).is_null() {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlTextReaderSetup : malloc failed\n\0" as *const u8 as *const i8,
        ) });
        return -(1 as i32);
    }
    (unsafe { xmlSAXVersion((*reader).sax, 2 as i32) });
    let fresh215 = unsafe { &mut ((*reader).startElement) };
    *fresh215 = unsafe { (*(*reader).sax).startElement };
    let fresh216 = unsafe { &mut ((*(*reader).sax).startElement) };
    *fresh216 = Some(
        xmlTextReaderStartElement
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *mut *const xmlChar) -> (),
    );
    let fresh217 = unsafe { &mut ((*reader).endElement) };
    *fresh217 = unsafe { (*(*reader).sax).endElement };
    let fresh218 = unsafe { &mut ((*(*reader).sax).endElement) };
    *fresh218 = Some(
        xmlTextReaderEndElement as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
    );
    if (unsafe { (*(*reader).sax).initialized }) == 0xdeedbeaf as u32 {
        let fresh219 = unsafe { &mut ((*reader).startElementNs) };
        *fresh219 = unsafe { (*(*reader).sax).startElementNs };
        let fresh220 = unsafe { &mut ((*(*reader).sax).startElementNs) };
        *fresh220 = Some(
            xmlTextReaderStartElementNs
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
        let fresh221 = unsafe { &mut ((*reader).endElementNs) };
        *fresh221 = unsafe { (*(*reader).sax).endElementNs };
        let fresh222 = unsafe { &mut ((*(*reader).sax).endElementNs) };
        *fresh222 = Some(
            xmlTextReaderEndElementNs
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const xmlChar,
                    *const xmlChar,
                    *const xmlChar,
                ) -> (),
        );
    } else {
        let fresh223 = unsafe { &mut ((*reader).startElementNs) };
        *fresh223 = None;
        let fresh224 = unsafe { &mut ((*reader).endElementNs) };
        *fresh224 = None;
    }
    let fresh225 = unsafe { &mut ((*reader).characters) };
    *fresh225 = unsafe { (*(*reader).sax).characters };
    let fresh226 = unsafe { &mut ((*(*reader).sax).characters) };
    *fresh226 = Some(
        xmlTextReaderCharacters
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh227 = unsafe { &mut ((*(*reader).sax).ignorableWhitespace) };
    *fresh227 = Some(
        xmlTextReaderCharacters
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh228 = unsafe { &mut ((*reader).cdataBlock) };
    *fresh228 = unsafe { (*(*reader).sax).cdataBlock };
    let fresh229 = unsafe { &mut ((*(*reader).sax).cdataBlock) };
    *fresh229 = Some(
        xmlTextReaderCDataBlock
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    (unsafe { (*reader).mode = XML_TEXTREADER_MODE_INITIAL as i32 });
    let fresh230 = unsafe { &mut ((*reader).node) };
    *fresh230 = 0 as xmlNodePtr;
    let fresh231 = unsafe { &mut ((*reader).curnode) };
    *fresh231 = 0 as xmlNodePtr;
    if !input.is_null() {
        if (unsafe { xmlBufUse((*(*reader).input).buffer) }) < 4 as i32 as u64 {
            (unsafe { xmlParserInputBufferRead(input, 4 as i32) });
        }
        if (unsafe { (*reader).ctxt }).is_null() {
            if (unsafe { xmlBufUse((*(*reader).input).buffer) }) >= 4 as i32 as u64 {
                let fresh232 = unsafe { &mut ((*reader).ctxt) };
                *fresh232 = unsafe { xmlCreatePushParserCtxt(
                    (*reader).sax,
                    0 as *mut libc::c_void,
                    xmlBufContent((*(*reader).input).buffer as *const xmlBuf) as *const i8,
                    4 as i32,
                    URL,
                ) };
                (unsafe { (*reader).base = 0 as i32 as u32 });
                (unsafe { (*reader).cur = 4 as i32 as u32 });
            } else {
                let fresh233 = unsafe { &mut ((*reader).ctxt) };
                *fresh233 = unsafe { xmlCreatePushParserCtxt(
                    (*reader).sax,
                    0 as *mut libc::c_void,
                    0 as *const i8,
                    0 as i32,
                    URL,
                ) };
                (unsafe { (*reader).base = 0 as i32 as u32 });
                (unsafe { (*reader).cur = 0 as i32 as u32 });
            }
        } else {
            let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
            let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
            let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
            (unsafe { xmlCtxtReset((*reader).ctxt) });
            buf = unsafe { xmlAllocParserInputBuffer(enc) };
            if buf.is_null() {
                return -(1 as i32);
            }
            inputStream = unsafe { xmlNewInputStream((*reader).ctxt) };
            if inputStream.is_null() {
                (unsafe { xmlFreeParserInputBuffer(buf) });
                return -(1 as i32);
            }
            if URL.is_null() {
                let fresh234 = unsafe { &mut ((*inputStream).filename) };
                *fresh234 = 0 as *const i8;
            } else {
                let fresh235 = unsafe { &mut ((*inputStream).filename) };
                *fresh235 = (unsafe { xmlCanonicPath(URL as *const xmlChar) }) as *mut i8;
            }
            let fresh236 = unsafe { &mut ((*inputStream).buf) };
            *fresh236 = buf;
            (unsafe { xmlBufResetInput((*buf).buffer, inputStream) });
            (unsafe { inputPush((*reader).ctxt, inputStream) });
            (unsafe { (*reader).cur = 0 as i32 as u32 });
        }
        if (unsafe { (*reader).ctxt }).is_null() {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"xmlTextReaderSetup : malloc failed\n\0" as *const u8 as *const i8,
            ) });
            return -(1 as i32);
        }
    }
    if !(unsafe { (*reader).dict }).is_null() {
        if !(unsafe { (*(*reader).ctxt).dict }).is_null() {
            if (unsafe { (*reader).dict }) != (unsafe { (*(*reader).ctxt).dict }) {
                (unsafe { xmlDictFree((*reader).dict) });
                let fresh237 = unsafe { &mut ((*reader).dict) };
                *fresh237 = unsafe { (*(*reader).ctxt).dict };
            }
        } else {
            let fresh238 = unsafe { &mut ((*(*reader).ctxt).dict) };
            *fresh238 = unsafe { (*reader).dict };
        }
    } else {
        if (unsafe { (*(*reader).ctxt).dict }).is_null() {
            let fresh239 = unsafe { &mut ((*(*reader).ctxt).dict) };
            *fresh239 = unsafe { xmlDictCreate() };
        }
        let fresh240 = unsafe { &mut ((*reader).dict) };
        *fresh240 = unsafe { (*(*reader).ctxt).dict };
    }
    let fresh241 = unsafe { &mut ((*(*reader).ctxt)._private) };
    *fresh241 = reader as *mut libc::c_void;
    (unsafe { (*(*reader).ctxt).linenumbers = 1 as i32 });
    (unsafe { (*(*reader).ctxt).dictNames = 1 as i32 });
    (unsafe { (*(*reader).ctxt).docdict = 1 as i32 });
    (unsafe { (*(*reader).ctxt).parseMode = XML_PARSE_READER });
    if !(unsafe { (*reader).xincctxt }).is_null() {
        (unsafe { xmlXIncludeFreeContext((*reader).xincctxt) });
        let fresh242 = unsafe { &mut ((*reader).xincctxt) };
        *fresh242 = 0 as xmlXIncludeCtxtPtr;
    }
    if options & XML_PARSE_XINCLUDE as i32 != 0 {
        (unsafe { (*reader).xinclude = 1 as i32 });
        let fresh243 = unsafe { &mut ((*reader).xinclude_name) };
        *fresh243 = unsafe { xmlDictLookup(
            (*reader).dict,
            b"include\0" as *const u8 as *const i8 as *const xmlChar,
            -(1 as i32),
        ) };
        options -= XML_PARSE_XINCLUDE as i32;
    } else {
        (unsafe { (*reader).xinclude = 0 as i32 });
    }
    (unsafe { (*reader).in_xinclude = 0 as i32 });
    if (unsafe { (*reader).patternTab }).is_null() {
        (unsafe { (*reader).patternNr = 0 as i32 });
        (unsafe { (*reader).patternMax = 0 as i32 });
    }
    while (unsafe { (*reader).patternNr }) > 0 as i32 {
        let fresh244 = unsafe { &mut ((*reader).patternNr) };
        *fresh244 -= 1;
        if !(unsafe { *((*reader).patternTab).offset((*reader).patternNr as isize) }).is_null() {
            (unsafe { xmlFreePattern(*((*reader).patternTab).offset((*reader).patternNr as isize)) });
            let fresh245 = unsafe { &mut (*((*reader).patternTab).offset((*reader).patternNr as isize)) };
            *fresh245 = 0 as xmlPatternPtr;
        }
    }
    if options & XML_PARSE_DTDVALID as i32 != 0 {
        (unsafe { (*reader).validate = XML_TEXTREADER_VALIDATE_DTD });
    }
    (unsafe { xmlCtxtUseOptions((*reader).ctxt, options) });
    if !encoding.is_null() {
        let mut hdlr: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
        hdlr = unsafe { xmlFindCharEncodingHandler(encoding) };
        if !hdlr.is_null() {
            (unsafe { xmlSwitchToEncoding((*reader).ctxt, hdlr) });
        }
    }
    if !URL.is_null()
        && !(unsafe { (*(*reader).ctxt).input }).is_null()
        && (unsafe { (*(*(*reader).ctxt).input).filename }).is_null()
    {
        let fresh246 = unsafe { &mut ((*(*(*reader).ctxt).input).filename) };
        *fresh246 = (unsafe { xmlStrdup(URL as *const xmlChar) }) as *mut i8;
    }
    let fresh247 = unsafe { &mut ((*reader).doc) };
    *fresh247 = 0 as xmlDocPtr;
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextReaderByteConsumed(mut reader: xmlTextReaderPtr) -> i64 {
    if reader.is_null() || (unsafe { (*reader).ctxt }).is_null() {
        return -(1 as i32) as i64;
    }
    return unsafe { xmlByteConsumed((*reader).ctxt) };
}
#[no_mangle]
pub extern "C" fn xmlReaderWalker(mut doc: xmlDocPtr) -> xmlTextReaderPtr {
    let mut ret: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    if doc.is_null() {
        return 0 as xmlTextReaderPtr;
    }
    ret = (unsafe { xmlMalloc.expect("non-null function pointer")(
        ::std::mem::size_of::<xmlTextReader>() as u64
    ) }) as xmlTextReaderPtr;
    if ret.is_null() {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"xmlNewTextReader : malloc failed\n\0" as *const u8 as *const i8,
        ) });
        return 0 as xmlTextReaderPtr;
    }
    (unsafe { memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlTextReader>() as u64,
    ) });
    (unsafe { (*ret).entNr = 0 as i32 });
    let fresh248 = unsafe { &mut ((*ret).input) };
    *fresh248 = 0 as xmlParserInputBufferPtr;
    (unsafe { (*ret).mode = XML_TEXTREADER_MODE_INITIAL as i32 });
    let fresh249 = unsafe { &mut ((*ret).node) };
    *fresh249 = 0 as xmlNodePtr;
    let fresh250 = unsafe { &mut ((*ret).curnode) };
    *fresh250 = 0 as xmlNodePtr;
    (unsafe { (*ret).base = 0 as i32 as u32 });
    (unsafe { (*ret).cur = 0 as i32 as u32 });
    (unsafe { (*ret).allocs = 2 as i32 });
    let fresh251 = unsafe { &mut ((*ret).doc) };
    *fresh251 = doc;
    (unsafe { (*ret).state = XML_TEXTREADER_START });
    let fresh252 = unsafe { &mut ((*ret).dict) };
    *fresh252 = unsafe { xmlDictCreate() };
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlReaderForDoc(
    mut cur: *const xmlChar,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlTextReaderPtr {
    let mut len: i32 = 0;
    if cur.is_null() {
        return 0 as xmlTextReaderPtr;
    }
    len = unsafe { xmlStrlen(cur) };
    return xmlReaderForMemory(cur as *const i8, len, URL, encoding, options);
}
#[no_mangle]
pub extern "C" fn xmlReaderForFile(
    mut filename: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlTextReaderPtr {
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    reader = xmlNewTextReaderFilename(filename);
    if reader.is_null() {
        return 0 as xmlTextReaderPtr;
    }
    xmlTextReaderSetup(
        reader,
        0 as xmlParserInputBufferPtr,
        0 as *const i8,
        encoding,
        options,
    );
    return reader;
}
#[no_mangle]
pub extern "C" fn xmlReaderForMemory(
    mut buffer: *const i8,
    mut size: i32,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlTextReaderPtr {
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    buf = unsafe { xmlParserInputBufferCreateStatic(buffer, size, XML_CHAR_ENCODING_NONE) };
    if buf.is_null() {
        return 0 as xmlTextReaderPtr;
    }
    reader = xmlNewTextReader(buf, URL);
    if reader.is_null() {
        (unsafe { xmlFreeParserInputBuffer(buf) });
        return 0 as xmlTextReaderPtr;
    }
    (unsafe { (*reader).allocs |= 1 as i32 });
    xmlTextReaderSetup(reader, 0 as xmlParserInputBufferPtr, URL, encoding, options);
    return reader;
}
#[no_mangle]
pub extern "C" fn xmlReaderForFd(
    mut fd: i32,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlTextReaderPtr {
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if fd < 0 as i32 {
        return 0 as xmlTextReaderPtr;
    }
    input = unsafe { xmlParserInputBufferCreateFd(fd, XML_CHAR_ENCODING_NONE) };
    if input.is_null() {
        return 0 as xmlTextReaderPtr;
    }
    let fresh253 = unsafe { &mut ((*input).closecallback) };
    *fresh253 = None;
    reader = xmlNewTextReader(input, URL);
    if reader.is_null() {
        (unsafe { xmlFreeParserInputBuffer(input) });
        return 0 as xmlTextReaderPtr;
    }
    (unsafe { (*reader).allocs |= 1 as i32 });
    xmlTextReaderSetup(reader, 0 as xmlParserInputBufferPtr, URL, encoding, options);
    return reader;
}
#[no_mangle]
pub extern "C" fn xmlReaderForIO(
    mut ioread: xmlInputReadCallback,
    mut ioclose: xmlInputCloseCallback,
    mut ioctx: *mut libc::c_void,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlTextReaderPtr {
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if ioread.is_none() {
        return 0 as xmlTextReaderPtr;
    }
    input = unsafe { xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, XML_CHAR_ENCODING_NONE) };
    if input.is_null() {
        if ioclose.is_some() {
            (unsafe { ioclose.expect("non-null function pointer")(ioctx) });
        }
        return 0 as xmlTextReaderPtr;
    }
    reader = xmlNewTextReader(input, URL);
    if reader.is_null() {
        (unsafe { xmlFreeParserInputBuffer(input) });
        return 0 as xmlTextReaderPtr;
    }
    (unsafe { (*reader).allocs |= 1 as i32 });
    xmlTextReaderSetup(reader, 0 as xmlParserInputBufferPtr, URL, encoding, options);
    return reader;
}
#[no_mangle]
pub extern "C" fn xmlReaderNewWalker(mut reader: xmlTextReaderPtr, mut doc: xmlDocPtr) -> i32 {
    if doc.is_null() {
        return -(1 as i32);
    }
    if reader.is_null() {
        return -(1 as i32);
    }
    if !(unsafe { (*reader).input }).is_null() {
        (unsafe { xmlFreeParserInputBuffer((*reader).input) });
    }
    if !(unsafe { (*reader).ctxt }).is_null() {
        (unsafe { xmlCtxtReset((*reader).ctxt) });
    }
    (unsafe { (*reader).entNr = 0 as i32 });
    let fresh254 = unsafe { &mut ((*reader).input) };
    *fresh254 = 0 as xmlParserInputBufferPtr;
    (unsafe { (*reader).mode = XML_TEXTREADER_MODE_INITIAL as i32 });
    let fresh255 = unsafe { &mut ((*reader).node) };
    *fresh255 = 0 as xmlNodePtr;
    let fresh256 = unsafe { &mut ((*reader).curnode) };
    *fresh256 = 0 as xmlNodePtr;
    (unsafe { (*reader).base = 0 as i32 as u32 });
    (unsafe { (*reader).cur = 0 as i32 as u32 });
    (unsafe { (*reader).allocs = 2 as i32 });
    let fresh257 = unsafe { &mut ((*reader).doc) };
    *fresh257 = doc;
    (unsafe { (*reader).state = XML_TEXTREADER_START });
    if (unsafe { (*reader).dict }).is_null() {
        if !(unsafe { (*reader).ctxt }).is_null() && !(unsafe { (*(*reader).ctxt).dict }).is_null() {
            let fresh258 = unsafe { &mut ((*reader).dict) };
            *fresh258 = unsafe { (*(*reader).ctxt).dict };
        } else {
            let fresh259 = unsafe { &mut ((*reader).dict) };
            *fresh259 = unsafe { xmlDictCreate() };
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlReaderNewDoc(
    mut reader: xmlTextReaderPtr,
    mut cur: *const xmlChar,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> i32 {
    let mut len: i32 = 0;
    if cur.is_null() {
        return -(1 as i32);
    }
    if reader.is_null() {
        return -(1 as i32);
    }
    len = unsafe { xmlStrlen(cur) };
    return xmlReaderNewMemory(reader, cur as *const i8, len, URL, encoding, options);
}
#[no_mangle]
pub extern "C" fn xmlReaderNewFile(
    mut reader: xmlTextReaderPtr,
    mut filename: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> i32 {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if filename.is_null() {
        return -(1 as i32);
    }
    if reader.is_null() {
        return -(1 as i32);
    }
    input = unsafe { xmlParserInputBufferCreateFilename(filename, XML_CHAR_ENCODING_NONE) };
    if input.is_null() {
        return -(1 as i32);
    }
    return xmlTextReaderSetup(reader, input, filename, encoding, options);
}
#[no_mangle]
pub extern "C" fn xmlReaderNewMemory(
    mut reader: xmlTextReaderPtr,
    mut buffer: *const i8,
    mut size: i32,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> i32 {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if reader.is_null() {
        return -(1 as i32);
    }
    if buffer.is_null() {
        return -(1 as i32);
    }
    input = unsafe { xmlParserInputBufferCreateStatic(buffer, size, XML_CHAR_ENCODING_NONE) };
    if input.is_null() {
        return -(1 as i32);
    }
    return xmlTextReaderSetup(reader, input, URL, encoding, options);
}
#[no_mangle]
pub extern "C" fn xmlReaderNewFd(
    mut reader: xmlTextReaderPtr,
    mut fd: i32,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> i32 {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if fd < 0 as i32 {
        return -(1 as i32);
    }
    if reader.is_null() {
        return -(1 as i32);
    }
    input = unsafe { xmlParserInputBufferCreateFd(fd, XML_CHAR_ENCODING_NONE) };
    if input.is_null() {
        return -(1 as i32);
    }
    let fresh260 = unsafe { &mut ((*input).closecallback) };
    *fresh260 = None;
    return xmlTextReaderSetup(reader, input, URL, encoding, options);
}
#[no_mangle]
pub extern "C" fn xmlReaderNewIO(
    mut reader: xmlTextReaderPtr,
    mut ioread: xmlInputReadCallback,
    mut ioclose: xmlInputCloseCallback,
    mut ioctx: *mut libc::c_void,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> i32 {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if ioread.is_none() {
        return -(1 as i32);
    }
    if reader.is_null() {
        return -(1 as i32);
    }
    input = unsafe { xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, XML_CHAR_ENCODING_NONE) };
    if input.is_null() {
        if ioclose.is_some() {
            (unsafe { ioclose.expect("non-null function pointer")(ioctx) });
        }
        return -(1 as i32);
    }
    return xmlTextReaderSetup(reader, input, URL, encoding, options);
}
