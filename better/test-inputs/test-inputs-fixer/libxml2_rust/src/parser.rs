use :: libc;
extern "C" {
    pub type _xmlBuf;
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlAutomataState;
    pub type _xmlAutomata;
    pub type _xmlValidState;
    fn xmlStrlen(str: *const xmlChar) -> i32;
    fn xmlCharStrdup(cur: *const i8) -> *mut xmlChar;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrcasecmp(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrncmp(str1: *const xmlChar, str2: *const xmlChar, len: i32) -> i32;
    fn xmlStrcmp(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrcasestr(str: *const xmlChar, val: *const xmlChar) -> *const xmlChar;
    fn xmlStrchr(str: *const xmlChar, val: xmlChar) -> *const xmlChar;
    fn xmlStrndup(cur: *const xmlChar, len: i32) -> *mut xmlChar;
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    fn snprintf(_: *mut i8, _: u64, _: *const i8, _: ...) -> i32;
    fn __htmlParseContent(ctx: *mut libc::c_void);
    fn __xmlGlobalInitMutexLock();
    fn __xmlGlobalInitMutexUnlock();
    fn xmlInputReadCallbackNop(context: *mut libc::c_void, buffer: *mut i8, len: i32) -> i32;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn memchr(_: *const libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn strncmp(_: *const i8, _: *const i8, _: u64) -> i32;
    fn strlen(_: *const i8) -> u64;
    fn xmlNewDocElementContent(
        doc: xmlDocPtr,
        name: *const xmlChar,
        type_0: xmlElementContentType,
    ) -> xmlElementContentPtr;
    fn xmlFreeDocElementContent(doc: xmlDocPtr, cur: xmlElementContentPtr);
    fn xmlCreateEnumeration(name: *const xmlChar) -> xmlEnumerationPtr;
    fn xmlFreeEnumeration(cur: xmlEnumerationPtr);
    fn xmlBufContent(buf: *const xmlBuf) -> *mut xmlChar;
    fn xmlBufUse(buf: xmlBufPtr) -> size_t;
    fn xmlInitializeDict() -> i32;
    fn xmlDictSetLimit(dict: xmlDictPtr, limit: size_t) -> size_t;
    fn xmlDictReference(dict: xmlDictPtr) -> i32;
    fn xmlDictFree(dict: xmlDictPtr);
    fn xmlDictLookup(dict: xmlDictPtr, name: *const xmlChar, len: i32) -> *const xmlChar;
    fn xmlDictOwns(dict: xmlDictPtr, str: *const xmlChar) -> i32;
    fn xmlDictCleanup();
    fn xmlBuildQName(
        ncname: *const xmlChar,
        prefix: *const xmlChar,
        memory: *mut xmlChar,
        len: i32,
    ) -> *mut xmlChar;
    fn xmlSplitQName3(name: *const xmlChar, len: *mut i32) -> *const xmlChar;
    fn xmlBufferCreate() -> xmlBufferPtr;
    fn xmlBufferFree(buf: xmlBufferPtr);
    fn xmlBufferAdd(buf: xmlBufferPtr, str: *const xmlChar, len: i32) -> i32;
    fn xmlBufferSetAllocationScheme(buf: xmlBufferPtr, scheme: xmlBufferAllocationScheme);
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
    fn xmlNewDoc(version: *const xmlChar) -> xmlDocPtr;
    fn xmlFreeDoc(cur: xmlDocPtr);
    fn xmlNewDocNode(
        doc: xmlDocPtr,
        ns: xmlNsPtr,
        name: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlNodePtr;
    fn xmlNewDocComment(doc: xmlDocPtr, content: *const xmlChar) -> xmlNodePtr;
    fn xmlDocCopyNode(node: xmlNodePtr, doc: xmlDocPtr, recursive: i32) -> xmlNodePtr;
    fn xmlGetLastChild(parent: *const xmlNode) -> xmlNodePtr;
    fn xmlNodeIsText(node: *const xmlNode) -> i32;
    fn xmlAddChild(parent: xmlNodePtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlAddChildList(parent: xmlNodePtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlUnlinkNode(cur: xmlNodePtr);
    fn xmlFreeNodeList(cur: xmlNodePtr);
    fn xmlFreeNode(cur: xmlNodePtr);
    fn xmlSetTreeDoc(tree: xmlNodePtr, doc: xmlDocPtr);
    fn xmlSearchNsByHref(doc: xmlDocPtr, node: xmlNodePtr, href: *const xmlChar) -> xmlNsPtr;
    fn xmlHashCreateDict(size: i32, dict: xmlDictPtr) -> xmlHashTablePtr;
    fn xmlHashFree(table: xmlHashTablePtr, f: xmlHashDeallocator);
    fn xmlHashDefaultDeallocator(entry: *mut libc::c_void, name: *const xmlChar);
    fn xmlHashAddEntry2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        name2: *const xmlChar,
        userdata: *mut libc::c_void,
    ) -> i32;
    fn xmlHashUpdateEntry2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        name2: *const xmlChar,
        userdata: *mut libc::c_void,
        f: xmlHashDeallocator,
    ) -> i32;
    fn xmlHashRemoveEntry2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        name2: *const xmlChar,
        f: xmlHashDeallocator,
    ) -> i32;
    fn xmlHashLookup2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        name2: *const xmlChar,
    ) -> *mut libc::c_void;
    fn xmlHashQLookup2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        prefix: *const xmlChar,
        name2: *const xmlChar,
        prefix2: *const xmlChar,
    ) -> *mut libc::c_void;
    fn xmlHashSize(table: xmlHashTablePtr) -> i32;
    fn xmlHashScanFull(table: xmlHashTablePtr, f: xmlHashScannerFull, data: *mut libc::c_void);
    fn initGenericErrorDefaultFunc(handler: *mut xmlGenericErrorFunc);
    fn xmlResetError(err: xmlErrorPtr);
    fn xmlCopyError(from: xmlErrorPtr, to: xmlErrorPtr) -> i32;
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
    fn xmlCleanupMemory();
    fn xmlInitMemory() -> i32;
    fn xmlValidateRoot(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr) -> i32;
    fn xmlValidateElement(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr, elem: xmlNodePtr) -> i32;
    fn xmlIsMixedElement(doc: xmlDocPtr, name: *const xmlChar) -> i32;
    fn xmlGetPredefinedEntity(name: *const xmlChar) -> xmlEntityPtr;
    fn xmlInitCharEncodingHandlers();
    fn xmlCleanupCharEncodingHandlers();
    fn xmlFindCharEncodingHandler(name: *const i8) -> xmlCharEncodingHandlerPtr;
    fn xmlDetectCharEncoding(in_0: *const u8, len: i32) -> xmlCharEncoding;
    fn xmlCleanupInputCallbacks();
    fn xmlRegisterDefaultInputCallbacks();
    fn xmlAllocParserInputBuffer(enc: xmlCharEncoding) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferCreateFd(fd: i32, enc: xmlCharEncoding) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferCreateMem(
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
    fn xmlParserInputBufferPush(in_0: xmlParserInputBufferPtr, len: i32, buf: *const i8) -> i32;
    fn xmlFreeParserInputBuffer(in_0: xmlParserInputBufferPtr);
    fn xmlParserGetDirectory(filename: *const i8) -> *mut i8;
    fn xmlCleanupOutputCallbacks();
    fn xmlRegisterDefaultOutputCallbacks();
    fn htmlDefaultSAXHandlerInit();
    fn xmlDefaultSAXHandlerInit();
    fn __xmlGenericError() -> *mut xmlGenericErrorFunc;
    fn xmlInitGlobals();
    fn xmlInitThreads();
    fn xmlCleanupThreads();
    fn xmlCleanupGlobals();
    static mut xmlFree: xmlFreeFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlMallocAtomic: xmlMallocFunc;
    fn __xmlGenericErrorContext() -> *mut *mut libc::c_void;
    fn __xmlParserDebugEntities() -> *mut i32;
    fn __xmlDefaultSAXHandler() -> *mut xmlSAXHandlerV1;
    fn xmlSAX2IgnorableWhitespace(ctx: *mut libc::c_void, ch: *const xmlChar, len: i32);
    fn xmlSAX2StartElement(
        ctx: *mut libc::c_void,
        fullname: *const xmlChar,
        atts: *mut *const xmlChar,
    );
    fn xmlSAX2EndElement(ctx: *mut libc::c_void, name: *const xmlChar);
    fn __xmlDefaultSAXLocator() -> *mut xmlSAXLocator;
    fn xmlSAX2EntityDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: i32,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
        content: *mut xmlChar,
    );
    static mut xmlMalloc: xmlMallocFunc;
    fn xmlSAX2GetEntity(ctx: *mut libc::c_void, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlParserInputGrow(in_0: xmlParserInputPtr, len: i32) -> i32;
    fn xmlClearParserCtxt(ctxt: xmlParserCtxtPtr);
    fn xmlFreeParserCtxt(ctxt: xmlParserCtxtPtr);
    fn xmlNewParserCtxt() -> xmlParserCtxtPtr;
    fn xmlNewIOInputStream(
        ctxt: xmlParserCtxtPtr,
        input: xmlParserInputBufferPtr,
        enc: xmlCharEncoding,
    ) -> xmlParserInputPtr;
    fn xmlParserAddNodeInfo(ctxt: xmlParserCtxtPtr, info: xmlParserNodeInfoPtr);
    fn xmlLoadExternalEntity(
        URL: *const i8,
        ID: *const i8,
        ctxt: xmlParserCtxtPtr,
    ) -> xmlParserInputPtr;
    fn xmlInitNodeInfoSeq(seq: xmlParserNodeInfoSeqPtr);
    fn xmlSwitchEncoding(ctxt: xmlParserCtxtPtr, enc: xmlCharEncoding) -> i32;
    fn xmlSwitchToEncoding(ctxt: xmlParserCtxtPtr, handler: xmlCharEncodingHandlerPtr) -> i32;
    fn __xmlErrEncoding(
        ctxt: xmlParserCtxtPtr,
        xmlerr: xmlParserErrors,
        msg: *const i8,
        str1: *const xmlChar,
        str2: *const xmlChar,
    );
    fn xmlNewStringInputStream(ctxt: xmlParserCtxtPtr, buffer: *const xmlChar)
        -> xmlParserInputPtr;
    fn xmlNewEntityInputStream(ctxt: xmlParserCtxtPtr, entity: xmlEntityPtr) -> xmlParserInputPtr;
    fn xmlFreeInputStream(input: xmlParserInputPtr);
    fn xmlNewInputStream(ctxt: xmlParserCtxtPtr) -> xmlParserInputPtr;
    fn xmlCopyChar(len: i32, out: *mut xmlChar, val: i32) -> i32;
    fn xmlStringCurrentChar(ctxt: xmlParserCtxtPtr, cur: *const xmlChar, len: *mut i32) -> i32;
    fn htmlCreateMemoryParserCtxt(buffer: *const i8, size: i32) -> htmlParserCtxtPtr;
    fn htmlInitAutoClose();
    fn xmlErrMemory(ctxt: xmlParserCtxtPtr, extra: *const i8);
    fn xmlCopyCharMultiByte(out: *mut xmlChar, val: i32) -> i32;
    fn xmlParserInputShrink(in_0: xmlParserInputPtr);
    fn xmlCurrentChar(ctxt: xmlParserCtxtPtr, len: *mut i32) -> i32;
    fn xmlNextChar(ctxt: xmlParserCtxtPtr);
    static xmlIsDigitGroup: xmlChRangeGroup;
    static xmlIsCombiningGroup: xmlChRangeGroup;
    static xmlIsBaseCharGroup: xmlChRangeGroup;
    fn xmlCharInRange(val: u32, group: *const xmlChRangeGroup) -> i32;
    static xmlIsExtenderGroup: xmlChRangeGroup;
    static xmlIsPubidChar_tab: [u8; 256];
    fn xmlBuildURI(URI: *const xmlChar, base: *const xmlChar) -> *mut xmlChar;
    fn xmlParseURI(str: *const i8) -> xmlURIPtr;
    fn xmlFreeURI(uri: xmlURIPtr);
    fn xmlCanonicPath(path: *const xmlChar) -> *mut xmlChar;
    fn xmlCatalogCleanup();
    fn xmlCatalogFreeLocal(catalogs: *mut libc::c_void);
    fn xmlCatalogAddLocal(catalogs: *mut libc::c_void, URL: *const xmlChar) -> *mut libc::c_void;
    fn xmlCatalogGetDefaults() -> xmlCatalogAllow;
    fn xmlSchemaCleanupTypes();
    fn xmlRelaxNGCleanupTypes();
    fn xmlBufIsEmpty(buf: xmlBufPtr) -> i32;
    fn xmlBufResetInput(buf: xmlBufPtr, input: xmlParserInputPtr) -> i32;
    fn xmlBufGetInputBase(buf: xmlBufPtr, input: xmlParserInputPtr) -> size_t;
    fn xmlBufSetInputBaseCur(
        buf: xmlBufPtr,
        input: xmlParserInputPtr,
        base: size_t,
        cur: size_t,
    ) -> i32;
    fn xmlCharEncInput(input: xmlParserInputBufferPtr, flush: i32) -> i32;
    fn xmlXPathInit();
    fn xmlGenericErrorDefaultFunc(ctx: *mut libc::c_void, msg: *const i8, _: ...);
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStartTag {
    pub prefix: *const xmlChar,
    pub URI: *const xmlChar,
    pub line: i32,
    pub nsNr: i32,
}
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
pub type xmlNsPtr = *mut xmlNs;
pub type xmlDtd = _xmlDtd;
pub type xmlDtdPtr = *mut xmlDtd;
pub type C2RustUnnamed_1 = u32;
pub const XML_DOC_HTML: C2RustUnnamed_1 = 128;
pub const XML_DOC_INTERNAL: C2RustUnnamed_1 = 64;
pub const XML_DOC_USERBUILT: C2RustUnnamed_1 = 32;
pub const XML_DOC_XINCLUDE: C2RustUnnamed_1 = 16;
pub const XML_DOC_DTDVALID: C2RustUnnamed_1 = 8;
pub const XML_DOC_OLD10: C2RustUnnamed_1 = 4;
pub const XML_DOC_NSVALID: C2RustUnnamed_1 = 2;
pub const XML_DOC_WELLFORMED: C2RustUnnamed_1 = 1;
pub type xmlHashDeallocator = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type xmlHashScannerFull = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
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
pub type xmlGenericErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type xmlValidCtxtPtr = *mut xmlValidCtxt;
pub type xmlParserNodeInfoPtr = *mut xmlParserNodeInfo;
pub type xmlParserNodeInfoSeqPtr = *mut xmlParserNodeInfoSeq;
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
pub type xmlChRangeGroup = _xmlChRangeGroup;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChRangeGroup {
    pub nbShortRange: i32,
    pub nbLongRange: i32,
    pub shortRange: *const xmlChSRange,
    pub longRange: *const xmlChLRange,
}
pub type xmlChLRange = _xmlChLRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChLRange {
    pub low: u32,
    pub high: u32,
}
pub type xmlChSRange = _xmlChSRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChSRange {
    pub low: u16,
    pub high: u16,
}
pub const XML_PARSE_OLDSAX: C2RustUnnamed_3 = 1048576;
pub type xmlEntityReferenceFunc =
    Option<unsafe extern "C" fn(xmlEntityPtr, xmlNodePtr, xmlNodePtr) -> ()>;
pub const XML_PARSE_NSCLEAN: C2RustUnnamed_3 = 8192;
pub type xmlDefAttrsPtr = *mut xmlDefAttrs;
pub type xmlDefAttrs = _xmlDefAttrs;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDefAttrs {
    pub nbAttrs: i32,
    pub maxAttrs: i32,
    pub values: [*const xmlChar; 0],
}
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
pub type htmlParserCtxtPtr = xmlParserCtxtPtr;
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
extern "C" fn xmlParserEntityCheck(
    mut ctxt: xmlParserCtxtPtr,
    mut size: size_t,
    mut ent: xmlEntityPtr,
    mut replacement: size_t,
) -> i32 {
    let mut consumed: size_t = 0 as i32 as size_t;
    let mut i: i32 = 0;
    if ctxt.is_null() || (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 != 0 {
        return 0 as i32;
    }
    if (unsafe { (*ctxt).lastError.code }) == XML_ERR_ENTITY_LOOP as i32 {
        return 1 as i32;
    }
    if !ent.is_null()
        && (unsafe { (*ent).etype }) as u32 != XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
        && !(unsafe { (*ent).content }).is_null()
        && (unsafe { (*ent).checked }) == 0 as i32
        && (unsafe { (*ctxt).errNo }) != XML_ERR_ENTITY_LOOP as i32
    {
        let mut oldnbent: u64 = unsafe { (*ctxt).nbentities };
        let mut diff: u64 = 0;
        let mut rep: *mut xmlChar = 0 as *mut xmlChar;
        (unsafe { (*ent).checked = 1 as i32 });
        let fresh0 = unsafe { &mut ((*ctxt).depth) };
        *fresh0 += 1;
        rep = xmlStringDecodeEntities(
            ctxt,
            unsafe { (*ent).content },
            1 as i32,
            0 as i32 as xmlChar,
            0 as i32 as xmlChar,
            0 as i32 as xmlChar,
        );
        let fresh1 = unsafe { &mut ((*ctxt).depth) };
        *fresh1 -= 1;
        if rep.is_null() || (unsafe { (*ctxt).errNo }) == XML_ERR_ENTITY_LOOP as i32 {
            (unsafe { *((*ent).content).offset(0 as i32 as isize) = 0 as i32 as xmlChar });
        }
        diff = (unsafe { (*ctxt).nbentities })
            .wrapping_sub(oldnbent)
            .wrapping_add(1 as i32 as u64);
        if diff > (2147483647 as i32 / 2 as i32) as u64 {
            diff = (2147483647 as i32 / 2 as i32) as u64;
        }
        (unsafe { (*ent).checked = diff.wrapping_mul(2 as i32 as u64) as i32 });
        if !rep.is_null() {
            if !(unsafe { xmlStrchr(rep, '<' as i32 as xmlChar) }).is_null() {
                (unsafe { (*ent).checked |= 1 as i32 });
            }
            (unsafe { xmlFree.expect("non-null function pointer")(rep as *mut libc::c_void) });
            rep = 0 as *mut xmlChar;
        }
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_DTD as i32
        && (unsafe { (*ctxt).nbentities }) > 10000 as i32 as u64
        && (unsafe { (*ctxt).nbentities }).wrapping_rem(1024 as i32 as u64) == 0 as i32 as u64
    {
        i = 0 as i32;
        while i < (unsafe { (*ctxt).inputNr }) {
            consumed = (consumed as u64).wrapping_add(
                (unsafe { (**((*ctxt).inputTab).offset(i as isize)).consumed }).wrapping_add(
                    (unsafe { ((**((*ctxt).inputTab).offset(i as isize)).cur)
                        .offset_from((**((*ctxt).inputTab).offset(i as isize)).base) })
                        as i64 as u64,
                ),
            ) as size_t as size_t;
            i += 1;
        }
        if (unsafe { (*ctxt).nbentities }) > consumed.wrapping_mul(10 as i32 as u64) {
            xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const i8);
            (unsafe { (*ctxt).instate = XML_PARSER_EOF });
            return 1 as i32;
        }
        consumed = 0 as i32 as size_t;
    }
    if replacement != 0 as i32 as u64 {
        if replacement < 10000000 as i32 as u64 {
            return 0 as i32;
        }
        if !(unsafe { (*ctxt).input }).is_null() {
            consumed = (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
            );
        }
        consumed = (consumed as u64).wrapping_add(unsafe { (*ctxt).sizeentities }) as size_t as size_t;
        if replacement < (10 as i32 as u64).wrapping_mul(consumed) {
            return 0 as i32;
        }
    } else if size != 0 as i32 as u64 {
        if size < 1000 as i32 as u64 {
            return 0 as i32;
        }
        if !(unsafe { (*ctxt).input }).is_null() {
            consumed = (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
            );
        }
        consumed = (consumed as u64).wrapping_add(unsafe { (*ctxt).sizeentities }) as size_t as size_t;
        if size < (10 as i32 as u64).wrapping_mul(consumed)
            && (unsafe { (*ctxt).nbentities }).wrapping_mul(3 as i32 as u64)
                < (10 as i32 as u64).wrapping_mul(consumed)
        {
            return 0 as i32;
        }
    } else if !ent.is_null() {
        size = ((unsafe { (*ent).checked }) / 2 as i32) as size_t;
        if !(unsafe { (*ctxt).input }).is_null() {
            consumed = (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
            );
        }
        consumed = (consumed as u64).wrapping_add(unsafe { (*ctxt).sizeentities }) as size_t as size_t;
        if size.wrapping_mul(3 as i32 as u64) < consumed.wrapping_mul(10 as i32 as u64) {
            return 0 as i32;
        }
    } else if (unsafe { (*ctxt).lastError.code }) != XML_ERR_UNDECLARED_ENTITY as i32
        && (unsafe { (*ctxt).lastError.code }) != XML_WAR_UNDECLARED_ENTITY as i32
        || (unsafe { (*ctxt).nbentities }) <= 10000 as i32 as u64
    {
        return 0 as i32;
    }
    xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const i8);
    return 1 as i32;
}
#[no_mangle]
pub static mut xmlParserMaxDepth: u32 = 256 as i32 as u32;
static mut xmlW3CPIs: [*const i8; 3] = [
    b"xml-stylesheet\0" as *const u8 as *const i8,
    b"xml-model\0" as *const u8 as *const i8,
    0 as *const i8,
];
extern "C" fn xmlErrAttributeDup(
    mut ctxt: xmlParserCtxtPtr,
    mut prefix: *const xmlChar,
    mut localname: *const xmlChar,
) {
    if !ctxt.is_null()
        && (unsafe { (*ctxt).disableSAX }) != 0 as i32
        && (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (unsafe { (*ctxt).errNo = XML_ERR_ATTRIBUTE_REDEFINED as i32 });
    }
    if prefix.is_null() {
        (unsafe { __xmlRaiseError(
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
        ) });
    } else {
        (unsafe { __xmlRaiseError(
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
        ) });
    }
    if !ctxt.is_null() {
        (unsafe { (*ctxt).wellFormed = 0 as i32 });
        if (unsafe { (*ctxt).recovery }) == 0 as i32 {
            (unsafe { (*ctxt).disableSAX = 1 as i32 });
        }
    }
}
extern "C" fn xmlFatalErr(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut info: *const i8,
) {
    let mut errmsg: *const i8 = 0 as *const i8;
    if !ctxt.is_null()
        && (unsafe { (*ctxt).disableSAX }) != 0 as i32
        && (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    match error as u32 {
        6 => {
            errmsg = b"CharRef: invalid hexadecimal value\0" as *const u8 as *const i8;
        }
        7 => {
            errmsg = b"CharRef: invalid decimal value\0" as *const u8 as *const i8;
        }
        8 => {
            errmsg = b"CharRef: invalid value\0" as *const u8 as *const i8;
        }
        1 => {
            errmsg = b"internal error\0" as *const u8 as *const i8;
        }
        18 => {
            errmsg = b"PEReference at end of document\0" as *const u8 as *const i8;
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
            errmsg = b"Detected an entity reference loop\0" as *const u8 as *const i8;
        }
        36 => {
            errmsg = b"EntityValue: \" or ' expected\0" as *const u8 as *const i8;
        }
        88 => {
            errmsg = b"PEReferences forbidden in internal subset\0" as *const u8 as *const i8;
        }
        37 => {
            errmsg = b"EntityValue: \" or ' expected\0" as *const u8 as *const i8;
        }
        39 => {
            errmsg = b"AttValue: \" or ' expected\0" as *const u8 as *const i8;
        }
        38 => {
            errmsg = b"Unescaped '<' not allowed in attributes values\0" as *const u8 as *const i8;
        }
        43 => {
            errmsg = b"SystemLiteral \" or ' expected\0" as *const u8 as *const i8;
        }
        44 => {
            errmsg = b"Unfinished System or Public ID \" or ' expected\0" as *const u8 as *const i8;
        }
        62 => {
            errmsg = b"Sequence ']]>' not allowed in content\0" as *const u8 as *const i8;
        }
        70 => {
            errmsg = b"SYSTEM or PUBLIC, the URI is missing\0" as *const u8 as *const i8;
        }
        71 => {
            errmsg = b"PUBLIC, the Public Identifier is missing\0" as *const u8 as *const i8;
        }
        80 => {
            errmsg = b"Comment must not contain '--' (double-hyphen)\0" as *const u8 as *const i8;
        }
        46 => {
            errmsg = b"xmlParsePI : no target name\0" as *const u8 as *const i8;
        }
        64 => {
            errmsg = b"Invalid PI name\0" as *const u8 as *const i8;
        }
        48 => {
            errmsg = b"NOTATION: Name expected here\0" as *const u8 as *const i8;
        }
        49 => {
            errmsg = b"'>' required to close NOTATION declaration\0" as *const u8 as *const i8;
        }
        84 => {
            errmsg = b"Entity value required\0" as *const u8 as *const i8;
        }
        92 => {
            errmsg = b"Fragment not allowed\0" as *const u8 as *const i8;
        }
        50 => {
            errmsg = b"'(' required to start ATTLIST enumeration\0" as *const u8 as *const i8;
        }
        67 => {
            errmsg = b"NmToken expected in ATTLIST enumeration\0" as *const u8 as *const i8;
        }
        51 => {
            errmsg = b"')' required to finish ATTLIST enumeration\0" as *const u8 as *const i8;
        }
        52 => {
            errmsg = b"MixedContentDecl : '|' or ')*' expected\0" as *const u8 as *const i8;
        }
        69 => {
            errmsg = b"MixedContentDecl : '#PCDATA' expected\0" as *const u8 as *const i8;
        }
        54 => {
            errmsg = b"ContentDecl : Name or '(' expected\0" as *const u8 as *const i8;
        }
        55 => {
            errmsg = b"ContentDecl : ',' '|' or ')' expected\0" as *const u8 as *const i8;
        }
        21 => {
            errmsg = b"PEReference: forbidden within markup decl in internal subset\0" as *const u8
                as *const i8;
        }
        73 => {
            errmsg = b"expected '>'\0" as *const u8 as *const i8;
        }
        83 => {
            errmsg = b"XML conditional section '[' expected\0" as *const u8 as *const i8;
        }
        60 => {
            errmsg = b"Content error in the external subset\0" as *const u8 as *const i8;
        }
        95 => {
            errmsg = b"conditional section INCLUDE or IGNORE keyword expected\0" as *const u8
                as *const i8;
        }
        59 => {
            errmsg = b"XML conditional section not closed\0" as *const u8 as *const i8;
        }
        56 => {
            errmsg = b"Text declaration '<?xml' required\0" as *const u8 as *const i8;
        }
        57 => {
            errmsg = b"parsing XML declaration: '?>' expected\0" as *const u8 as *const i8;
        }
        82 => {
            errmsg = b"external parsed entities cannot be standalone\0" as *const u8 as *const i8;
        }
        23 => {
            errmsg = b"EntityRef: expecting ';'\0" as *const u8 as *const i8;
        }
        61 => {
            errmsg = b"DOCTYPE improperly terminated\0" as *const u8 as *const i8;
        }
        74 => {
            errmsg = b"EndTag: '</' not found\0" as *const u8 as *const i8;
        }
        75 => {
            errmsg = b"expected '='\0" as *const u8 as *const i8;
        }
        34 => {
            errmsg = b"String not closed expecting \" or '\0" as *const u8 as *const i8;
        }
        33 => {
            errmsg = b"String not started expecting ' or \"\0" as *const u8 as *const i8;
        }
        79 => {
            errmsg = b"Invalid XML encoding name\0" as *const u8 as *const i8;
        }
        78 => {
            errmsg = b"standalone accepts only 'yes' or 'no'\0" as *const u8 as *const i8;
        }
        4 => {
            errmsg = b"Document is empty\0" as *const u8 as *const i8;
        }
        5 => {
            errmsg = b"Extra content at the end of the document\0" as *const u8 as *const i8;
        }
        85 => {
            errmsg = b"chunk is not well balanced\0" as *const u8 as *const i8;
        }
        86 => {
            errmsg = b"extra content at the end of well balanced chunk\0" as *const u8 as *const i8;
        }
        96 => {
            errmsg = b"Malformed declaration expecting version\0" as *const u8 as *const i8;
        }
        110 => {
            errmsg = b"Name too long use XML_PARSE_HUGE option\0" as *const u8 as *const i8;
        }
        _ => {
            errmsg = b"Unregistered error message\0" as *const u8 as *const i8;
        }
    }
    if !ctxt.is_null() {
        (unsafe { (*ctxt).errNo = error as i32 });
    }
    if info.is_null() {
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
            info,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"%s\n\0" as *const u8 as *const i8,
            errmsg,
        ) });
    } else {
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
            info,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"%s: %s\n\0" as *const u8 as *const i8,
            errmsg,
            info,
        ) });
    }
    if !ctxt.is_null() {
        (unsafe { (*ctxt).wellFormed = 0 as i32 });
        if (unsafe { (*ctxt).recovery }) == 0 as i32 {
            (unsafe { (*ctxt).disableSAX = 1 as i32 });
        }
    }
}
extern "C" fn xmlFatalErrMsg(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
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
        0 as *const i8,
        0 as *const i8,
        0 as *const i8,
        0 as i32,
        0 as i32,
        b"%s\0" as *const u8 as *const i8,
        msg,
    ) });
    if !ctxt.is_null() {
        (unsafe { (*ctxt).wellFormed = 0 as i32 });
        if (unsafe { (*ctxt).recovery }) == 0 as i32 {
            (unsafe { (*ctxt).disableSAX = 1 as i32 });
        }
    }
}
extern "C" fn xmlWarningMsg(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) {
    let mut schannel: xmlStructuredErrorFunc = None;
    if !ctxt.is_null()
        && (unsafe { (*ctxt).disableSAX }) != 0 as i32
        && (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null()
        && !(unsafe { (*ctxt).sax }).is_null()
        && (unsafe { (*(*ctxt).sax).initialized }) == 0xdeedbeaf as u32
    {
        schannel = unsafe { (*(*ctxt).sax).serror };
    }
    if !ctxt.is_null() {
        (unsafe { __xmlRaiseError(
            schannel,
            if !((*ctxt).sax).is_null() {
                (*(*ctxt).sax).warning
            } else {
                None
            },
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
        ) });
    } else {
        (unsafe { __xmlRaiseError(
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
        ) });
    };
}
extern "C" fn xmlValidityError(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
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
    }
    if !ctxt.is_null() {
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
            str1 as *const i8,
            str2 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            msg,
            str1 as *const i8,
            str2 as *const i8,
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
            str1 as *const i8,
            str2 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            msg,
            str1 as *const i8,
            str2 as *const i8,
        ) });
    };
}
extern "C" fn xmlFatalErrMsgInt(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut val: i32,
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
        0 as *const i8,
        0 as *const i8,
        0 as *const i8,
        val,
        0 as i32,
        msg,
        val,
    ) });
    if !ctxt.is_null() {
        (unsafe { (*ctxt).wellFormed = 0 as i32 });
        if (unsafe { (*ctxt).recovery }) == 0 as i32 {
            (unsafe { (*ctxt).disableSAX = 1 as i32 });
        }
    }
}
extern "C" fn xmlFatalErrMsgStrIntStr(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut str1: *const xmlChar,
    mut val: i32,
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
        val,
        0 as i32,
        msg,
        str1,
        val,
        str2,
    ) });
    if !ctxt.is_null() {
        (unsafe { (*ctxt).wellFormed = 0 as i32 });
        if (unsafe { (*ctxt).recovery }) == 0 as i32 {
            (unsafe { (*ctxt).disableSAX = 1 as i32 });
        }
    }
}
extern "C" fn xmlFatalErrMsgStr(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut val: *const xmlChar,
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
        val as *const i8,
        0 as *const i8,
        0 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        val,
    ) });
    if !ctxt.is_null() {
        (unsafe { (*ctxt).wellFormed = 0 as i32 });
        if (unsafe { (*ctxt).recovery }) == 0 as i32 {
            (unsafe { (*ctxt).disableSAX = 1 as i32 });
        }
    }
}
extern "C" fn xmlErrMsgStr(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut val: *const xmlChar,
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
    ) });
}
extern "C" fn xmlNsErr(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut info1: *const xmlChar,
    mut info2: *const xmlChar,
    mut info3: *const xmlChar,
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
        info1 as *const i8,
        info2 as *const i8,
        info3 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        info1,
        info2,
        info3,
    ) });
    if !ctxt.is_null() {
        (unsafe { (*ctxt).nsWellFormed = 0 as i32 });
    }
}
extern "C" fn xmlNsWarn(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut info1: *const xmlChar,
    mut info2: *const xmlChar,
    mut info3: *const xmlChar,
) {
    if !ctxt.is_null()
        && (unsafe { (*ctxt).disableSAX }) != 0 as i32
        && (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32
    {
        return;
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
        info1 as *const i8,
        info2 as *const i8,
        info3 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        info1,
        info2,
        info3,
    ) });
}
#[no_mangle]
pub extern "C" fn xmlHasFeature(mut feature: xmlFeature) -> i32 {
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
extern "C" fn xmlDetectSAX2(mut ctxt: xmlParserCtxtPtr) {
    let mut sax: xmlSAXHandlerPtr = 0 as *mut xmlSAXHandler;
    if ctxt.is_null() {
        return;
    }
    sax = unsafe { (*ctxt).sax };
    if !sax.is_null()
        && (unsafe { (*sax).initialized }) == 0xdeedbeaf as u32
        && ((unsafe { ((*sax).startElementNs).is_some() })
            || (unsafe { ((*sax).endElementNs).is_some() })
            || (unsafe { ((*sax).startElement).is_none() }) && (unsafe { ((*sax).endElement).is_none() }))
    {
        (unsafe { (*ctxt).sax2 = 1 as i32 });
    }
    let fresh2 = unsafe { &mut ((*ctxt).str_xml) };
    *fresh2 = unsafe { xmlDictLookup(
        (*ctxt).dict,
        b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
        3 as i32,
    ) };
    let fresh3 = unsafe { &mut ((*ctxt).str_xmlns) };
    *fresh3 = unsafe { xmlDictLookup(
        (*ctxt).dict,
        b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
        5 as i32,
    ) };
    let fresh4 = unsafe { &mut ((*ctxt).str_xml_ns) };
    *fresh4 = unsafe { xmlDictLookup(
        (*ctxt).dict,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
        36 as i32,
    ) };
    if (unsafe { (*ctxt).str_xml }).is_null()
        || (unsafe { (*ctxt).str_xmlns }).is_null()
        || (unsafe { (*ctxt).str_xml_ns }).is_null()
    {
        (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
    }
}
extern "C" fn xmlAttrNormalizeSpace(
    mut src: *const xmlChar,
    mut dst: *mut xmlChar,
) -> *mut xmlChar {
    if src.is_null() || dst.is_null() {
        return 0 as *mut xmlChar;
    }
    while (unsafe { *src }) as i32 == 0x20 as i32 {
        src = unsafe { src.offset(1) };
    }
    while (unsafe { *src }) as i32 != 0 as i32 {
        if (unsafe { *src }) as i32 == 0x20 as i32 {
            while (unsafe { *src }) as i32 == 0x20 as i32 {
                src = unsafe { src.offset(1) };
            }
            if (unsafe { *src }) as i32 != 0 as i32 {
                let fresh5 = dst;
                dst = unsafe { dst.offset(1) };
                (unsafe { *fresh5 = 0x20 as i32 as xmlChar });
            }
        } else {
            let fresh6 = src;
            src = unsafe { src.offset(1) };
            let fresh7 = dst;
            dst = unsafe { dst.offset(1) };
            (unsafe { *fresh7 = *fresh6 });
        }
    }
    (unsafe { *dst = 0 as i32 as xmlChar });
    if dst == src as *mut xmlChar {
        return 0 as *mut xmlChar;
    }
    return dst;
}
extern "C" fn xmlAttrNormalizeSpace2(
    mut ctxt: xmlParserCtxtPtr,
    mut src: *mut xmlChar,
    mut len: *mut i32,
) -> *const xmlChar {
    let mut i: i32 = 0;
    let mut remove_head: i32 = 0 as i32;
    let mut need_realloc: i32 = 0 as i32;
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    if ctxt.is_null() || src.is_null() || len.is_null() {
        return 0 as *const xmlChar;
    }
    i = unsafe { *len };
    if i <= 0 as i32 {
        return 0 as *const xmlChar;
    }
    cur = src;
    while (unsafe { *cur }) as i32 == 0x20 as i32 {
        cur = unsafe { cur.offset(1) };
        remove_head += 1;
    }
    while (unsafe { *cur }) as i32 != 0 as i32 {
        if (unsafe { *cur }) as i32 == 0x20 as i32 {
            cur = unsafe { cur.offset(1) };
            if !((unsafe { *cur }) as i32 == 0x20 as i32 || (unsafe { *cur }) as i32 == 0 as i32) {
                continue;
            }
            need_realloc = 1 as i32;
            break;
        } else {
            cur = unsafe { cur.offset(1) };
        }
    }
    if need_realloc != 0 {
        let mut ret: *mut xmlChar = 0 as *mut xmlChar;
        ret = unsafe { xmlStrndup(src.offset(remove_head as isize), i - remove_head + 1 as i32) };
        if ret.is_null() {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            return 0 as *const xmlChar;
        }
        xmlAttrNormalizeSpace(ret, ret);
        (unsafe { *len = strlen(ret as *const i8) as i32 });
        return ret;
    } else {
        if remove_head != 0 {
            (unsafe { *len -= remove_head });
            (unsafe { memmove(
                src as *mut libc::c_void,
                src.offset(remove_head as isize) as *const libc::c_void,
                (1 as i32 + *len) as u64,
            ) });
            return src;
        }
    }
    return 0 as *const xmlChar;
}
extern "C" fn xmlAddDefAttrs(
    mut ctxt: xmlParserCtxtPtr,
    mut fullname: *const xmlChar,
    mut fullattr: *const xmlChar,
    mut value: *const xmlChar,
) {
    let mut current_block: u64;
    let mut defaults: xmlDefAttrsPtr = 0 as *mut xmlDefAttrs;
    let mut len: i32 = 0;
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut prefix: *const xmlChar = 0 as *const xmlChar;
    if !(unsafe { (*ctxt).attsSpecial }).is_null() {
        if !(unsafe { xmlHashLookup2((*ctxt).attsSpecial, fullname, fullattr) }).is_null() {
            return;
        }
    }
    if (unsafe { (*ctxt).attsDefault }).is_null() {
        let fresh8 = unsafe { &mut ((*ctxt).attsDefault) };
        *fresh8 = unsafe { xmlHashCreateDict(10 as i32, (*ctxt).dict) };
        if (unsafe { (*ctxt).attsDefault }).is_null() {
            current_block = 15121983726504061653;
        } else {
            current_block = 13183875560443969876;
        }
    } else {
        current_block = 13183875560443969876;
    }
    match current_block {
        13183875560443969876 => {
            name = unsafe { xmlSplitQName3(fullname, &mut len) };
            if name.is_null() {
                name = unsafe { xmlDictLookup((*ctxt).dict, fullname, -(1 as i32)) };
                prefix = 0 as *const xmlChar;
            } else {
                name = unsafe { xmlDictLookup((*ctxt).dict, name, -(1 as i32)) };
                prefix = unsafe { xmlDictLookup((*ctxt).dict, fullname, len) };
            }
            defaults = (unsafe { xmlHashLookup2((*ctxt).attsDefault, name, prefix) }) as xmlDefAttrsPtr;
            if defaults.is_null() {
                defaults = (unsafe { xmlMalloc.expect("non-null function pointer")(
                    (::std::mem::size_of::<xmlDefAttrs>() as u64).wrapping_add(
                        ((4 as i32 * 5 as i32) as u64)
                            .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as u64),
                    ),
                ) }) as xmlDefAttrsPtr;
                if defaults.is_null() {
                    current_block = 15121983726504061653;
                } else {
                    (unsafe { (*defaults).nbAttrs = 0 as i32 });
                    (unsafe { (*defaults).maxAttrs = 4 as i32 });
                    if (unsafe { xmlHashUpdateEntry2(
                        (*ctxt).attsDefault,
                        name,
                        prefix,
                        defaults as *mut libc::c_void,
                        None,
                    ) }) < 0 as i32
                    {
                        (unsafe { xmlFree.expect("non-null function pointer")(defaults as *mut libc::c_void) });
                        current_block = 15121983726504061653;
                    } else {
                        current_block = 8704759739624374314;
                    }
                }
            } else if (unsafe { (*defaults).nbAttrs }) >= (unsafe { (*defaults).maxAttrs }) {
                let mut temp: xmlDefAttrsPtr = 0 as *mut xmlDefAttrs;
                temp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                    defaults as *mut libc::c_void,
                    (::std::mem::size_of::<xmlDefAttrs>() as u64).wrapping_add(
                        ((2 as i32 * (*defaults).maxAttrs * 5 as i32) as u64)
                            .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as u64),
                    ),
                ) }) as xmlDefAttrsPtr;
                if temp.is_null() {
                    current_block = 15121983726504061653;
                } else {
                    defaults = temp;
                    (unsafe { (*defaults).maxAttrs *= 2 as i32 });
                    if (unsafe { xmlHashUpdateEntry2(
                        (*ctxt).attsDefault,
                        name,
                        prefix,
                        defaults as *mut libc::c_void,
                        None,
                    ) }) < 0 as i32
                    {
                        (unsafe { xmlFree.expect("non-null function pointer")(defaults as *mut libc::c_void) });
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
                    name = unsafe { xmlSplitQName3(fullattr, &mut len) };
                    if name.is_null() {
                        name = unsafe { xmlDictLookup((*ctxt).dict, fullattr, -(1 as i32)) };
                        prefix = 0 as *const xmlChar;
                    } else {
                        name = unsafe { xmlDictLookup((*ctxt).dict, name, -(1 as i32)) };
                        prefix = unsafe { xmlDictLookup((*ctxt).dict, fullattr, len) };
                    }
                    let fresh9 = unsafe { &mut (*((*defaults).values)
                        .as_mut_ptr()
                        .offset((5 as i32 * (*defaults).nbAttrs) as isize)) };
                    *fresh9 = name;
                    let fresh10 = unsafe { &mut (*((*defaults).values)
                        .as_mut_ptr()
                        .offset((5 as i32 * (*defaults).nbAttrs + 1 as i32) as isize)) };
                    *fresh10 = prefix;
                    len = unsafe { xmlStrlen(value) };
                    value = unsafe { xmlDictLookup((*ctxt).dict, value, len) };
                    let fresh11 = unsafe { &mut (*((*defaults).values)
                        .as_mut_ptr()
                        .offset((5 as i32 * (*defaults).nbAttrs + 2 as i32) as isize)) };
                    *fresh11 = value;
                    let fresh12 = unsafe { &mut (*((*defaults).values)
                        .as_mut_ptr()
                        .offset((5 as i32 * (*defaults).nbAttrs + 3 as i32) as isize)) };
                    *fresh12 = unsafe { value.offset(len as isize) };
                    if (unsafe { (*ctxt).external }) != 0 {
                        let fresh13 = unsafe { &mut (*((*defaults).values)
                            .as_mut_ptr()
                            .offset((5 as i32 * (*defaults).nbAttrs + 4 as i32) as isize)) };
                        *fresh13 = b"external\0" as *const u8 as *const i8 as *mut xmlChar;
                    } else {
                        let fresh14 = unsafe { &mut (*((*defaults).values)
                            .as_mut_ptr()
                            .offset((5 as i32 * (*defaults).nbAttrs + 4 as i32) as isize)) };
                        *fresh14 = 0 as *const xmlChar;
                    }
                    let fresh15 = unsafe { &mut ((*defaults).nbAttrs) };
                    *fresh15 += 1;
                    return;
                }
            }
        }
        _ => {}
    }
    (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
}
extern "C" fn xmlAddSpecialAttr(
    mut ctxt: xmlParserCtxtPtr,
    mut fullname: *const xmlChar,
    mut fullattr: *const xmlChar,
    mut type_0: i32,
) {
    if (unsafe { (*ctxt).attsSpecial }).is_null() {
        let fresh16 = unsafe { &mut ((*ctxt).attsSpecial) };
        *fresh16 = unsafe { xmlHashCreateDict(10 as i32, (*ctxt).dict) };
        if (unsafe { (*ctxt).attsSpecial }).is_null() {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            return;
        }
    }
    if !(unsafe { xmlHashLookup2((*ctxt).attsSpecial, fullname, fullattr) }).is_null() {
        return;
    }
    (unsafe { xmlHashAddEntry2(
        (*ctxt).attsSpecial,
        fullname,
        fullattr,
        type_0 as ptrdiff_t as *mut libc::c_void,
    ) });
}
extern "C" fn xmlCleanSpecialAttrCallback(
    mut payload: *mut libc::c_void,
    mut data: *mut libc::c_void,
    mut fullname: *const xmlChar,
    mut fullattr: *const xmlChar,
    mut _unused: *const xmlChar,
) {
    let mut ctxt: xmlParserCtxtPtr = data as xmlParserCtxtPtr;
    if payload as ptrdiff_t == XML_ATTRIBUTE_CDATA as i32 as i64 {
        (unsafe { xmlHashRemoveEntry2((*ctxt).attsSpecial, fullname, fullattr, None) });
    }
}
extern "C" fn xmlCleanSpecialAttr(mut ctxt: xmlParserCtxtPtr) {
    if (unsafe { (*ctxt).attsSpecial }).is_null() {
        return;
    }
    (unsafe { xmlHashScanFull(
        (*ctxt).attsSpecial,
        Some(
            xmlCleanSpecialAttrCallback
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_void,
                    *const xmlChar,
                    *const xmlChar,
                    *const xmlChar,
                ) -> (),
        ),
        ctxt as *mut libc::c_void,
    ) });
    if (unsafe { xmlHashSize((*ctxt).attsSpecial) }) == 0 as i32 {
        (unsafe { xmlHashFree((*ctxt).attsSpecial, None) });
        let fresh17 = unsafe { &mut ((*ctxt).attsSpecial) };
        *fresh17 = 0 as xmlHashTablePtr;
    }
}
#[no_mangle]
pub extern "C" fn xmlCheckLanguageID(mut lang: *const xmlChar) -> i32 {
    let mut current_block: u64;
    let mut cur: *const xmlChar = lang;
    let mut nxt: *const xmlChar = 0 as *const xmlChar;
    if cur.is_null() {
        return 0 as i32;
    }
    if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == 'i' as i32
        && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '-' as i32
        || (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == 'I' as i32
            && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '-' as i32
        || (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == 'x' as i32
            && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '-' as i32
        || (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == 'X' as i32
            && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '-' as i32
    {
        cur = unsafe { cur.offset(2 as i32 as isize) };
        while (unsafe { *cur.offset(0 as i32 as isize) }) as i32 >= 'A' as i32
            && (unsafe { *cur.offset(0 as i32 as isize) }) as i32 <= 'Z' as i32
            || (unsafe { *cur.offset(0 as i32 as isize) }) as i32 >= 'a' as i32
                && (unsafe { *cur.offset(0 as i32 as isize) }) as i32 <= 'z' as i32
        {
            cur = unsafe { cur.offset(1) };
        }
        return ((unsafe { *cur.offset(0 as i32 as isize) }) as i32 == 0 as i32) as i32;
    }
    nxt = cur;
    while (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 >= 'A' as i32
        && (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 <= 'Z' as i32
        || (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 >= 'a' as i32
            && (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 <= 'z' as i32
    {
        nxt = unsafe { nxt.offset(1) };
    }
    if (unsafe { nxt.offset_from(cur) }) as i64 >= 4 as i32 as i64 {
        if (unsafe { nxt.offset_from(cur) }) as i64 > 8 as i32 as i64
            || (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 != 0 as i32
        {
            return 0 as i32;
        }
        return 1 as i32;
    }
    if ((unsafe { nxt.offset_from(cur) }) as i64) < 2 as i32 as i64 {
        return 0 as i32;
    }
    if (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
        return 1 as i32;
    }
    if (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 != '-' as i32 {
        return 0 as i32;
    }
    nxt = unsafe { nxt.offset(1) };
    cur = nxt;
    if (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 >= '0' as i32
        && (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 <= '9' as i32
    {
        current_block = 16811467638080314455;
    } else {
        while (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 >= 'A' as i32
            && (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 <= 'Z' as i32
            || (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 >= 'a' as i32
                && (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 <= 'z' as i32
        {
            nxt = unsafe { nxt.offset(1) };
        }
        if (unsafe { nxt.offset_from(cur) }) as i64 == 4 as i32 as i64 {
            current_block = 9144990194416275176;
        } else if (unsafe { nxt.offset_from(cur) }) as i64 == 2 as i32 as i64 {
            current_block = 8704481894642172821;
        } else if (unsafe { nxt.offset_from(cur) }) as i64 >= 5 as i32 as i64
            && (unsafe { nxt.offset_from(cur) }) as i64 <= 8 as i32 as i64
        {
            current_block = 9213009941721548937;
        } else {
            if (unsafe { nxt.offset_from(cur) }) as i64 != 3 as i32 as i64 {
                return 0 as i32;
            }
            if (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
                return 1 as i32;
            }
            if (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 != '-' as i32 {
                return 0 as i32;
            }
            nxt = unsafe { nxt.offset(1) };
            cur = nxt;
            if (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 <= '9' as i32
            {
                current_block = 16811467638080314455;
            } else {
                while (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 >= 'A' as i32
                    && (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 <= 'Z' as i32
                    || (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 >= 'a' as i32
                        && (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 <= 'z' as i32
                {
                    nxt = unsafe { nxt.offset(1) };
                }
                if (unsafe { nxt.offset_from(cur) }) as i64 == 2 as i32 as i64 {
                    current_block = 8704481894642172821;
                } else if (unsafe { nxt.offset_from(cur) }) as i64 >= 5 as i32 as i64
                    && (unsafe { nxt.offset_from(cur) }) as i64 <= 8 as i32 as i64
                {
                    current_block = 9213009941721548937;
                } else {
                    if (unsafe { nxt.offset_from(cur) }) as i64 != 4 as i32 as i64 {
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
                if (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
                    return 1 as i32;
                }
                if (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 != '-' as i32 {
                    return 0 as i32;
                }
                nxt = unsafe { nxt.offset(1) };
                cur = nxt;
                if (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 >= '0' as i32
                    && (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 <= '9' as i32
                {
                    current_block = 16811467638080314455;
                } else {
                    while (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 >= 'A' as i32
                        && (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 <= 'Z' as i32
                        || (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 >= 'a' as i32
                            && (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 <= 'z' as i32
                    {
                        nxt = unsafe { nxt.offset(1) };
                    }
                    if (unsafe { nxt.offset_from(cur) }) as i64 >= 5 as i32 as i64
                        && (unsafe { nxt.offset_from(cur) }) as i64 <= 8 as i32 as i64
                    {
                        current_block = 9213009941721548937;
                    } else {
                        if (unsafe { nxt.offset_from(cur) }) as i64 != 2 as i32 as i64 {
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
            if (unsafe { *nxt.offset(1 as i32 as isize) }) as i32 >= '0' as i32
                && (unsafe { *nxt.offset(1 as i32 as isize) }) as i32 <= '9' as i32
                && ((unsafe { *nxt.offset(2 as i32 as isize) }) as i32 >= '0' as i32
                    && (unsafe { *nxt.offset(2 as i32 as isize) }) as i32 <= '9' as i32)
            {
                nxt = unsafe { nxt.offset(3 as i32 as isize) };
            } else {
                return 0 as i32;
            }
            current_block = 8704481894642172821;
        }
        _ => {}
    }
    match current_block {
        8704481894642172821 => {
            if (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
                return 1 as i32;
            }
            if (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 != '-' as i32 {
                return 0 as i32;
            }
            nxt = unsafe { nxt.offset(1) };
            cur = nxt;
            while (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 >= 'A' as i32
                && (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 <= 'Z' as i32
                || (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 >= 'a' as i32
                    && (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 <= 'z' as i32
            {
                nxt = unsafe { nxt.offset(1) };
            }
            if ((unsafe { nxt.offset_from(cur) }) as i64) < 5 as i32 as i64
                || (unsafe { nxt.offset_from(cur) }) as i64 > 8 as i32 as i64
            {
                return 0 as i32;
            }
        }
        _ => {}
    }
    if (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
        return 1 as i32;
    }
    if (unsafe { *nxt.offset(0 as i32 as isize) }) as i32 != '-' as i32 {
        return 0 as i32;
    }
    return 1 as i32;
}
extern "C" fn nsPush(
    mut ctxt: xmlParserCtxtPtr,
    mut prefix: *const xmlChar,
    mut URL: *const xmlChar,
) -> i32 {
    if (unsafe { (*ctxt).options }) & XML_PARSE_NSCLEAN as i32 != 0 {
        let mut i: i32 = 0;
        i = (unsafe { (*ctxt).nsNr }) - 2 as i32;
        while i >= 0 as i32 {
            if (unsafe { *((*ctxt).nsTab).offset(i as isize) }) == prefix {
                if (unsafe { *((*ctxt).nsTab).offset((i + 1 as i32) as isize) }) == URL {
                    return -(2 as i32);
                }
                break;
            } else {
                i -= 2 as i32;
            }
        }
    }
    if (unsafe { (*ctxt).nsMax }) == 0 as i32 || (unsafe { (*ctxt).nsTab }).is_null() {
        (unsafe { (*ctxt).nsMax = 10 as i32 });
        (unsafe { (*ctxt).nsNr = 0 as i32 });
        let fresh18 = unsafe { &mut ((*ctxt).nsTab) };
        *fresh18 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ((*ctxt).nsMax as u64).wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
        ) }) as *mut *const xmlChar;
        if (unsafe { (*ctxt).nsTab }).is_null() {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            (unsafe { (*ctxt).nsMax = 0 as i32 });
            return -(1 as i32);
        }
    } else if (unsafe { (*ctxt).nsNr }) >= (unsafe { (*ctxt).nsMax }) {
        let mut tmp: *mut *const xmlChar = 0 as *mut *const xmlChar;
        (unsafe { (*ctxt).nsMax *= 2 as i32 });
        tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*ctxt).nsTab as *mut i8 as *mut libc::c_void,
            ((*ctxt).nsMax as u64).wrapping_mul(::std::mem::size_of::<*const xmlChar>() as u64),
        ) }) as *mut *const xmlChar;
        if tmp.is_null() {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            (unsafe { (*ctxt).nsMax /= 2 as i32 });
            return -(1 as i32);
        }
        let fresh19 = unsafe { &mut ((*ctxt).nsTab) };
        *fresh19 = tmp;
    }
    let fresh20 = unsafe { &mut ((*ctxt).nsNr) };
    let fresh21 = *fresh20;
    *fresh20 = *fresh20 + 1;
    let fresh22 = unsafe { &mut (*((*ctxt).nsTab).offset(fresh21 as isize)) };
    *fresh22 = prefix;
    let fresh23 = unsafe { &mut ((*ctxt).nsNr) };
    let fresh24 = *fresh23;
    *fresh23 = *fresh23 + 1;
    let fresh25 = unsafe { &mut (*((*ctxt).nsTab).offset(fresh24 as isize)) };
    *fresh25 = URL;
    return unsafe { (*ctxt).nsNr };
}
extern "C" fn nsPop(mut ctxt: xmlParserCtxtPtr, mut nr: i32) -> i32 {
    let mut i: i32 = 0;
    if (unsafe { (*ctxt).nsTab }).is_null() {
        return 0 as i32;
    }
    if (unsafe { (*ctxt).nsNr }) < nr {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Pbm popping %d NS\n\0" as *const u8 as *const i8,
            nr,
        ) });
        nr = unsafe { (*ctxt).nsNr };
    }
    if (unsafe { (*ctxt).nsNr }) <= 0 as i32 {
        return 0 as i32;
    }
    i = 0 as i32;
    while i < nr {
        let fresh26 = unsafe { &mut ((*ctxt).nsNr) };
        *fresh26 -= 1;
        let fresh27 = unsafe { &mut (*((*ctxt).nsTab).offset((*ctxt).nsNr as isize)) };
        *fresh27 = 0 as *const xmlChar;
        i += 1;
    }
    return nr;
}
extern "C" fn xmlCtxtGrowAttrs(mut ctxt: xmlParserCtxtPtr, mut nr: i32) -> i32 {
    let mut current_block: u64;
    let mut atts: *mut *const xmlChar = 0 as *mut *const xmlChar;
    let mut attallocs: *mut i32 = 0 as *mut i32;
    let mut maxatts: i32 = 0;
    if (unsafe { (*ctxt).atts }).is_null() {
        maxatts = 55 as i32;
        atts = (unsafe { xmlMalloc.expect("non-null function pointer")(
            (maxatts as u64).wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
        ) }) as *mut *const xmlChar;
        if atts.is_null() {
            current_block = 15593660875440590097;
        } else {
            let fresh28 = unsafe { &mut ((*ctxt).atts) };
            *fresh28 = atts;
            attallocs = (unsafe { xmlMalloc.expect("non-null function pointer")(
                ((maxatts / 5 as i32) as u64).wrapping_mul(::std::mem::size_of::<i32>() as u64),
            ) }) as *mut i32;
            if attallocs.is_null() {
                current_block = 15593660875440590097;
            } else {
                let fresh29 = unsafe { &mut ((*ctxt).attallocs) };
                *fresh29 = attallocs;
                (unsafe { (*ctxt).maxatts = maxatts });
                current_block = 13242334135786603907;
            }
        }
    } else if nr + 5 as i32 > (unsafe { (*ctxt).maxatts }) {
        maxatts = (nr + 5 as i32) * 2 as i32;
        atts = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*ctxt).atts as *mut libc::c_void,
            (maxatts as u64).wrapping_mul(::std::mem::size_of::<*const xmlChar>() as u64),
        ) }) as *mut *const xmlChar;
        if atts.is_null() {
            current_block = 15593660875440590097;
        } else {
            let fresh30 = unsafe { &mut ((*ctxt).atts) };
            *fresh30 = atts;
            attallocs = (unsafe { xmlRealloc.expect("non-null function pointer")(
                (*ctxt).attallocs as *mut libc::c_void,
                ((maxatts / 5 as i32) as u64).wrapping_mul(::std::mem::size_of::<i32>() as u64),
            ) }) as *mut i32;
            if attallocs.is_null() {
                current_block = 15593660875440590097;
            } else {
                let fresh31 = unsafe { &mut ((*ctxt).attallocs) };
                *fresh31 = attallocs;
                (unsafe { (*ctxt).maxatts = maxatts });
                current_block = 13242334135786603907;
            }
        }
    } else {
        current_block = 13242334135786603907;
    }
    match current_block {
        13242334135786603907 => return unsafe { (*ctxt).maxatts },
        _ => {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            return -(1 as i32);
        }
    };
}
#[no_mangle]
pub extern "C" fn inputPush(mut ctxt: xmlParserCtxtPtr, mut value: xmlParserInputPtr) -> i32 {
    if ctxt.is_null() || value.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).inputNr }) >= (unsafe { (*ctxt).inputMax }) {
        (unsafe { (*ctxt).inputMax *= 2 as i32 });
        let fresh32 = unsafe { &mut ((*ctxt).inputTab) };
        *fresh32 = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*ctxt).inputTab as *mut libc::c_void,
            ((*ctxt).inputMax as u64)
                .wrapping_mul(::std::mem::size_of::<xmlParserInputPtr>() as u64),
        ) }) as *mut xmlParserInputPtr;
        if (unsafe { (*ctxt).inputTab }).is_null() {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            (unsafe { (*ctxt).inputMax /= 2 as i32 });
            return -(1 as i32);
        }
    }
    let fresh33 = unsafe { &mut (*((*ctxt).inputTab).offset((*ctxt).inputNr as isize)) };
    *fresh33 = value;
    let fresh34 = unsafe { &mut ((*ctxt).input) };
    *fresh34 = value;
    let fresh35 = unsafe { &mut ((*ctxt).inputNr) };
    let fresh36 = *fresh35;
    *fresh35 = *fresh35 + 1;
    return fresh36;
}
#[no_mangle]
pub extern "C" fn inputPop(mut ctxt: xmlParserCtxtPtr) -> xmlParserInputPtr {
    let mut ret: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ctxt.is_null() {
        return 0 as xmlParserInputPtr;
    }
    if (unsafe { (*ctxt).inputNr }) <= 0 as i32 {
        return 0 as xmlParserInputPtr;
    }
    let fresh37 = unsafe { &mut ((*ctxt).inputNr) };
    *fresh37 -= 1;
    if (unsafe { (*ctxt).inputNr }) > 0 as i32 {
        let fresh38 = unsafe { &mut ((*ctxt).input) };
        *fresh38 = unsafe { *((*ctxt).inputTab).offset(((*ctxt).inputNr - 1 as i32) as isize) };
    } else {
        let fresh39 = unsafe { &mut ((*ctxt).input) };
        *fresh39 = 0 as xmlParserInputPtr;
    }
    ret = unsafe { *((*ctxt).inputTab).offset((*ctxt).inputNr as isize) };
    let fresh40 = unsafe { &mut (*((*ctxt).inputTab).offset((*ctxt).inputNr as isize)) };
    *fresh40 = 0 as xmlParserInputPtr;
    return ret;
}
#[no_mangle]
pub extern "C" fn nodePush(mut ctxt: xmlParserCtxtPtr, mut value: xmlNodePtr) -> i32 {
    if ctxt.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*ctxt).nodeNr }) >= (unsafe { (*ctxt).nodeMax }) {
        let mut tmp: *mut xmlNodePtr = 0 as *mut xmlNodePtr;
        tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*ctxt).nodeTab as *mut libc::c_void,
            (((*ctxt).nodeMax * 2 as i32) as u64)
                .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) }) as *mut xmlNodePtr;
        if tmp.is_null() {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            return -(1 as i32);
        }
        let fresh41 = unsafe { &mut ((*ctxt).nodeTab) };
        *fresh41 = tmp;
        (unsafe { (*ctxt).nodeMax *= 2 as i32 });
    }
    if (unsafe { (*ctxt).nodeNr }) as u32 > (unsafe { xmlParserMaxDepth })
        && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
    {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"Excessive depth in document: %d use XML_PARSE_HUGE option\n\0" as *const u8
                as *const i8,
            (unsafe { xmlParserMaxDepth }) as i32,
        );
        xmlHaltParser(ctxt);
        return -(1 as i32);
    }
    let fresh42 = unsafe { &mut (*((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize)) };
    *fresh42 = value;
    let fresh43 = unsafe { &mut ((*ctxt).node) };
    *fresh43 = value;
    let fresh44 = unsafe { &mut ((*ctxt).nodeNr) };
    let fresh45 = *fresh44;
    *fresh44 = *fresh44 + 1;
    return fresh45;
}
#[no_mangle]
pub extern "C" fn nodePop(mut ctxt: xmlParserCtxtPtr) -> xmlNodePtr {
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    if ctxt.is_null() {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*ctxt).nodeNr }) <= 0 as i32 {
        return 0 as xmlNodePtr;
    }
    let fresh46 = unsafe { &mut ((*ctxt).nodeNr) };
    *fresh46 -= 1;
    if (unsafe { (*ctxt).nodeNr }) > 0 as i32 {
        let fresh47 = unsafe { &mut ((*ctxt).node) };
        *fresh47 = unsafe { *((*ctxt).nodeTab).offset(((*ctxt).nodeNr - 1 as i32) as isize) };
    } else {
        let fresh48 = unsafe { &mut ((*ctxt).node) };
        *fresh48 = 0 as xmlNodePtr;
    }
    ret = unsafe { *((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize) };
    let fresh49 = unsafe { &mut (*((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize)) };
    *fresh49 = 0 as xmlNodePtr;
    return ret;
}
extern "C" fn nameNsPush(
    mut ctxt: xmlParserCtxtPtr,
    mut value: *const xmlChar,
    mut prefix: *const xmlChar,
    mut URI: *const xmlChar,
    mut line: i32,
    mut nsNr: i32,
) -> i32 {
    let mut current_block: u64;
    let mut tag: *mut xmlStartTag = 0 as *mut xmlStartTag;
    if (unsafe { (*ctxt).nameNr }) >= (unsafe { (*ctxt).nameMax }) {
        let mut tmp: *mut *const xmlChar = 0 as *mut *const xmlChar;
        let mut tmp2: *mut xmlStartTag = 0 as *mut xmlStartTag;
        (unsafe { (*ctxt).nameMax *= 2 as i32 });
        tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*ctxt).nameTab as *mut *mut xmlChar as *mut libc::c_void,
            ((*ctxt).nameMax as u64).wrapping_mul(::std::mem::size_of::<*const xmlChar>() as u64),
        ) }) as *mut *const xmlChar;
        if tmp.is_null() {
            (unsafe { (*ctxt).nameMax /= 2 as i32 });
            current_block = 17671332882901204954;
        } else {
            let fresh50 = unsafe { &mut ((*ctxt).nameTab) };
            *fresh50 = tmp;
            tmp2 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                (*ctxt).pushTab as *mut *mut libc::c_void as *mut libc::c_void,
                ((*ctxt).nameMax as u64).wrapping_mul(::std::mem::size_of::<xmlStartTag>() as u64),
            ) }) as *mut xmlStartTag;
            if tmp2.is_null() {
                (unsafe { (*ctxt).nameMax /= 2 as i32 });
                current_block = 17671332882901204954;
            } else {
                let fresh51 = unsafe { &mut ((*ctxt).pushTab) };
                *fresh51 = tmp2;
                current_block = 1054647088692577877;
            }
        }
    } else if (unsafe { (*ctxt).pushTab }).is_null() {
        let fresh52 = unsafe { &mut ((*ctxt).pushTab) };
        *fresh52 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ((*ctxt).nameMax as u64).wrapping_mul(::std::mem::size_of::<xmlStartTag>() as u64),
        ) }) as *mut xmlStartTag;
        if (unsafe { (*ctxt).pushTab }).is_null() {
            current_block = 17671332882901204954;
        } else {
            current_block = 1054647088692577877;
        }
    } else {
        current_block = 1054647088692577877;
    }
    match current_block {
        17671332882901204954 => {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            return -(1 as i32);
        }
        _ => {
            let fresh53 = unsafe { &mut (*((*ctxt).nameTab).offset((*ctxt).nameNr as isize)) };
            *fresh53 = value;
            let fresh54 = unsafe { &mut ((*ctxt).name) };
            *fresh54 = value;
            tag = (unsafe { &mut *((*ctxt).pushTab).offset((*ctxt).nameNr as isize) }) as *mut xmlStartTag;
            let fresh55 = unsafe { &mut ((*tag).prefix) };
            *fresh55 = prefix;
            let fresh56 = unsafe { &mut ((*tag).URI) };
            *fresh56 = URI;
            (unsafe { (*tag).line = line });
            (unsafe { (*tag).nsNr = nsNr });
            let fresh57 = unsafe { &mut ((*ctxt).nameNr) };
            let fresh58 = *fresh57;
            *fresh57 = *fresh57 + 1;
            return fresh58;
        }
    };
}
extern "C" fn nameNsPop(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    if (unsafe { (*ctxt).nameNr }) <= 0 as i32 {
        return 0 as *const xmlChar;
    }
    let fresh59 = unsafe { &mut ((*ctxt).nameNr) };
    *fresh59 -= 1;
    if (unsafe { (*ctxt).nameNr }) > 0 as i32 {
        let fresh60 = unsafe { &mut ((*ctxt).name) };
        *fresh60 = unsafe { *((*ctxt).nameTab).offset(((*ctxt).nameNr - 1 as i32) as isize) };
    } else {
        let fresh61 = unsafe { &mut ((*ctxt).name) };
        *fresh61 = 0 as *const xmlChar;
    }
    ret = unsafe { *((*ctxt).nameTab).offset((*ctxt).nameNr as isize) };
    let fresh62 = unsafe { &mut (*((*ctxt).nameTab).offset((*ctxt).nameNr as isize)) };
    *fresh62 = 0 as *const xmlChar;
    return ret;
}
#[no_mangle]
pub extern "C" fn namePush(mut ctxt: xmlParserCtxtPtr, mut value: *const xmlChar) -> i32 {
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).nameNr }) >= (unsafe { (*ctxt).nameMax }) {
        let mut tmp: *mut *const xmlChar = 0 as *mut *const xmlChar;
        tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*ctxt).nameTab as *mut *mut xmlChar as *mut libc::c_void,
            (((*ctxt).nameMax * 2 as i32) as u64)
                .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as u64),
        ) }) as *mut *const xmlChar;
        if tmp.is_null() {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            return -(1 as i32);
        } else {
            let fresh63 = unsafe { &mut ((*ctxt).nameTab) };
            *fresh63 = tmp;
            (unsafe { (*ctxt).nameMax *= 2 as i32 });
        }
    }
    let fresh64 = unsafe { &mut (*((*ctxt).nameTab).offset((*ctxt).nameNr as isize)) };
    *fresh64 = value;
    let fresh65 = unsafe { &mut ((*ctxt).name) };
    *fresh65 = value;
    let fresh66 = unsafe { &mut ((*ctxt).nameNr) };
    let fresh67 = *fresh66;
    *fresh66 = *fresh66 + 1;
    return fresh67;
}
#[no_mangle]
pub extern "C" fn namePop(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    if ctxt.is_null() || (unsafe { (*ctxt).nameNr }) <= 0 as i32 {
        return 0 as *const xmlChar;
    }
    let fresh68 = unsafe { &mut ((*ctxt).nameNr) };
    *fresh68 -= 1;
    if (unsafe { (*ctxt).nameNr }) > 0 as i32 {
        let fresh69 = unsafe { &mut ((*ctxt).name) };
        *fresh69 = unsafe { *((*ctxt).nameTab).offset(((*ctxt).nameNr - 1 as i32) as isize) };
    } else {
        let fresh70 = unsafe { &mut ((*ctxt).name) };
        *fresh70 = 0 as *const xmlChar;
    }
    ret = unsafe { *((*ctxt).nameTab).offset((*ctxt).nameNr as isize) };
    let fresh71 = unsafe { &mut (*((*ctxt).nameTab).offset((*ctxt).nameNr as isize)) };
    *fresh71 = 0 as *const xmlChar;
    return ret;
}
extern "C" fn spacePush(mut ctxt: xmlParserCtxtPtr, mut val: i32) -> i32 {
    if (unsafe { (*ctxt).spaceNr }) >= (unsafe { (*ctxt).spaceMax }) {
        let mut tmp: *mut i32 = 0 as *mut i32;
        (unsafe { (*ctxt).spaceMax *= 2 as i32 });
        tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
            (*ctxt).spaceTab as *mut libc::c_void,
            ((*ctxt).spaceMax as u64).wrapping_mul(::std::mem::size_of::<i32>() as u64),
        ) }) as *mut i32;
        if tmp.is_null() {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            (unsafe { (*ctxt).spaceMax /= 2 as i32 });
            return -(1 as i32);
        }
        let fresh72 = unsafe { &mut ((*ctxt).spaceTab) };
        *fresh72 = tmp;
    }
    (unsafe { *((*ctxt).spaceTab).offset((*ctxt).spaceNr as isize) = val });
    let fresh73 = unsafe { &mut ((*ctxt).space) };
    *fresh73 = (unsafe { &mut *((*ctxt).spaceTab).offset((*ctxt).spaceNr as isize) }) as *mut i32;
    let fresh74 = unsafe { &mut ((*ctxt).spaceNr) };
    let fresh75 = *fresh74;
    *fresh74 = *fresh74 + 1;
    return fresh75;
}
extern "C" fn spacePop(mut ctxt: xmlParserCtxtPtr) -> i32 {
    let mut ret: i32 = 0;
    if (unsafe { (*ctxt).spaceNr }) <= 0 as i32 {
        return 0 as i32;
    }
    let fresh76 = unsafe { &mut ((*ctxt).spaceNr) };
    *fresh76 -= 1;
    if (unsafe { (*ctxt).spaceNr }) > 0 as i32 {
        let fresh77 = unsafe { &mut ((*ctxt).space) };
        *fresh77 =
            (unsafe { &mut *((*ctxt).spaceTab).offset(((*ctxt).spaceNr - 1 as i32) as isize) }) as *mut i32;
    } else {
        let fresh78 = unsafe { &mut ((*ctxt).space) };
        *fresh78 = (unsafe { &mut *((*ctxt).spaceTab).offset(0 as i32 as isize) }) as *mut i32;
    }
    ret = unsafe { *((*ctxt).spaceTab).offset((*ctxt).spaceNr as isize) };
    (unsafe { *((*ctxt).spaceTab).offset((*ctxt).spaceNr as isize) = -(1 as i32) });
    return ret;
}
extern "C" fn xmlSHRINK(mut ctxt: xmlParserCtxtPtr) {
    (unsafe { xmlParserInputShrink((*ctxt).input) });
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
        (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
    }
}
extern "C" fn xmlGROW(mut ctxt: xmlParserCtxtPtr) {
    let mut curEnd: ptrdiff_t = (unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64;
    let mut curBase: ptrdiff_t = (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64;
    if (curEnd > 10000000 as i32 as i64 || curBase > 10000000 as i32 as i64)
        && (!(unsafe { (*(*ctxt).input).buf }).is_null()
            && (unsafe { (*(*(*ctxt).input).buf).readcallback })
                != Some(
                    xmlInputReadCallbackNop
                        as unsafe extern "C" fn(*mut libc::c_void, *mut i8, i32) -> i32,
                ))
        && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"Huge input lookup\0" as *const u8 as *const i8,
        );
        xmlHaltParser(ctxt);
        return;
    }
    (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
    if (unsafe { (*(*ctxt).input).cur }) > (unsafe { (*(*ctxt).input).end }) || (unsafe { (*(*ctxt).input).cur }) < (unsafe { (*(*ctxt).input).base }) {
        xmlHaltParser(ctxt);
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"cur index out of bound\0" as *const u8 as *const i8,
        );
        return;
    }
    if !(unsafe { (*(*ctxt).input).cur }).is_null() && (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
        (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
    }
}
#[no_mangle]
pub extern "C" fn xmlSkipBlankChars(mut ctxt: xmlParserCtxtPtr) -> i32 {
    let mut res: i32 = 0 as i32;
    if (unsafe { (*ctxt).inputNr }) == 1 as i32 && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_DTD as i32
        || (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_START as i32
    {
        let mut cur: *const xmlChar = 0 as *const xmlChar;
        cur = unsafe { (*(*ctxt).input).cur };
        while (unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32
        {
            if (unsafe { *cur }) as i32 == '\n' as i32 {
                let fresh79 = unsafe { &mut ((*(*ctxt).input).line) };
                *fresh79 += 1;
                (unsafe { (*(*ctxt).input).col = 1 as i32 });
            } else {
                let fresh80 = unsafe { &mut ((*(*ctxt).input).col) };
                *fresh80 += 1;
            }
            cur = unsafe { cur.offset(1) };
            if res < 2147483647 as i32 {
                res += 1;
            }
            if (unsafe { *cur }) as i32 == 0 as i32 {
                let fresh81 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh81 = cur;
                (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                cur = unsafe { (*(*ctxt).input).cur };
            }
        }
        let fresh82 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh82 = cur;
    } else {
        let mut expandPE: i32 =
            ((unsafe { (*ctxt).external }) != 0 as i32 || (unsafe { (*ctxt).inputNr }) != 1 as i32) as i32;
        loop {
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *(*(*ctxt).input).cur }) as i32
                    && (unsafe { *(*(*ctxt).input).cur }) as i32 <= 0xa as i32
                || (unsafe { *(*(*ctxt).input).cur }) as i32 == 0xd as i32
            {
                (unsafe { xmlNextChar(ctxt) });
            } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '%' as i32 {
                if expandPE == 0 as i32
                    || ((unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == 0x20 as i32
                        || 0x9 as i32 <= (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32
                            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32
                                <= 0xa as i32
                        || (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == 0xd as i32)
                    || (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == 0 as i32
                {
                    break;
                }
                xmlParsePEReference(ctxt);
            } else {
                if !((unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32) {
                    break;
                }
                if (unsafe { (*ctxt).inputNr }) <= 1 as i32 {
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
pub extern "C" fn xmlPopInput(mut ctxt: xmlParserCtxtPtr) -> xmlChar {
    if ctxt.is_null() || (unsafe { (*ctxt).inputNr }) <= 1 as i32 {
        return 0 as i32 as xmlChar;
    }
    if (unsafe { *__xmlParserDebugEntities() }) != 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Popping input %d\n\0" as *const u8 as *const i8,
            (*ctxt).inputNr,
        ) });
    }
    if (unsafe { (*ctxt).inputNr }) > 1 as i32
        && (unsafe { (*ctxt).inSubset }) == 0 as i32
        && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"Unfinished entity outside the DTD\0" as *const u8 as *const i8,
        );
    }
    (unsafe { xmlFreeInputStream(inputPop(ctxt)) });
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
        (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
    }
    return unsafe { *(*(*ctxt).input).cur };
}
#[no_mangle]
pub extern "C" fn xmlPushInput(mut ctxt: xmlParserCtxtPtr, mut input: xmlParserInputPtr) -> i32 {
    let mut ret: i32 = 0;
    if input.is_null() {
        return -(1 as i32);
    }
    if (unsafe { *__xmlParserDebugEntities() }) != 0 {
        if !(unsafe { (*ctxt).input }).is_null() && !(unsafe { (*(*ctxt).input).filename }).is_null() {
            (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"%s(%d): \0" as *const u8 as *const i8,
                (*(*ctxt).input).filename,
                (*(*ctxt).input).line,
            ) });
        }
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Pushing input %d : %.30s\n\0" as *const u8 as *const i8,
            (*ctxt).inputNr + 1 as i32,
            (*input).cur,
        ) });
    }
    if (unsafe { (*ctxt).inputNr }) > 40 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
        || (unsafe { (*ctxt).inputNr }) > 1024 as i32
    {
        xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const i8);
        while (unsafe { (*ctxt).inputNr }) > 1 as i32 {
            (unsafe { xmlFreeInputStream(inputPop(ctxt)) });
        }
        return -(1 as i32);
    }
    ret = inputPush(ctxt, input);
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlParseCharRef(mut ctxt: xmlParserCtxtPtr) -> i32 {
    let mut val: i32 = 0 as i32;
    let mut count: i32 = 0 as i32;
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '&' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '#' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == 'x' as i32
    {
        let fresh83 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh83 = unsafe { (*fresh83).offset(3 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 3 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        while (unsafe { *(*(*ctxt).input).cur }) as i32 != ';' as i32 {
            let fresh84 = count;
            count = count + 1;
            if fresh84 > 20 as i32 {
                count = 0 as i32;
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                    return 0 as i32;
                }
            }
            if (unsafe { *(*(*ctxt).input).cur }) as i32 >= '0' as i32
                && (unsafe { *(*(*ctxt).input).cur }) as i32 <= '9' as i32
            {
                val = val * 16 as i32 + ((unsafe { *(*(*ctxt).input).cur }) as i32 - '0' as i32);
            } else if (unsafe { *(*(*ctxt).input).cur }) as i32 >= 'a' as i32
                && (unsafe { *(*(*ctxt).input).cur }) as i32 <= 'f' as i32
                && count < 20 as i32
            {
                val = val * 16 as i32 + ((unsafe { *(*(*ctxt).input).cur }) as i32 - 'a' as i32) + 10 as i32;
            } else if (unsafe { *(*(*ctxt).input).cur }) as i32 >= 'A' as i32
                && (unsafe { *(*(*ctxt).input).cur }) as i32 <= 'F' as i32
                && count < 20 as i32
            {
                val = val * 16 as i32 + ((unsafe { *(*(*ctxt).input).cur }) as i32 - 'A' as i32) + 10 as i32;
            } else {
                xmlFatalErr(ctxt, XML_ERR_INVALID_HEX_CHARREF, 0 as *const i8);
                val = 0 as i32;
                break;
            }
            if val > 0x110000 as i32 {
                val = 0x110000 as i32;
            }
            (unsafe { xmlNextChar(ctxt) });
            count += 1;
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == ';' as i32 {
            let fresh85 = unsafe { &mut ((*(*ctxt).input).col) };
            *fresh85 += 1;
            let fresh86 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh86 = unsafe { (*fresh86).offset(1) };
        }
    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '&' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '#' as i32
    {
        let fresh87 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh87 = unsafe { (*fresh87).offset(2 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 2 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        while (unsafe { *(*(*ctxt).input).cur }) as i32 != ';' as i32 {
            let fresh88 = count;
            count = count + 1;
            if fresh88 > 20 as i32 {
                count = 0 as i32;
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                    return 0 as i32;
                }
            }
            if (unsafe { *(*(*ctxt).input).cur }) as i32 >= '0' as i32
                && (unsafe { *(*(*ctxt).input).cur }) as i32 <= '9' as i32
            {
                val = val * 10 as i32 + ((unsafe { *(*(*ctxt).input).cur }) as i32 - '0' as i32);
                if val > 0x110000 as i32 {
                    val = 0x110000 as i32;
                }
                (unsafe { xmlNextChar(ctxt) });
                count += 1;
            } else {
                xmlFatalErr(ctxt, XML_ERR_INVALID_DEC_CHARREF, 0 as *const i8);
                val = 0 as i32;
                break;
            }
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == ';' as i32 {
            let fresh89 = unsafe { &mut ((*(*ctxt).input).col) };
            *fresh89 += 1;
            let fresh90 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh90 = unsafe { (*fresh90).offset(1) };
        }
    } else {
        xmlFatalErr(ctxt, XML_ERR_INVALID_CHARREF, 0 as *const i8);
    }
    if val >= 0x110000 as i32 {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlParseCharRef: character reference out of bounds\n\0" as *const u8 as *const i8,
            val,
        );
    } else if if val < 0x100 as i32 {
        (0x9 as i32 <= val && val <= 0xa as i32 || val == 0xd as i32 || 0x20 as i32 <= val) as i32
    } else {
        (0x100 as i32 <= val && val <= 0xd7ff as i32
            || 0xe000 as i32 <= val && val <= 0xfffd as i32
            || 0x10000 as i32 <= val && val <= 0x10ffff as i32) as i32
    } != 0
    {
        return val;
    } else {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlParseCharRef: invalid xmlChar value %d\n\0" as *const u8 as *const i8,
            val,
        );
    }
    return 0 as i32;
}
extern "C" fn xmlParseStringCharRef(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *mut *const xmlChar,
) -> i32 {
    let mut ptr: *const xmlChar = 0 as *const xmlChar;
    let mut cur: xmlChar = 0;
    let mut val: i32 = 0 as i32;
    if str.is_null() || (unsafe { *str }).is_null() {
        return 0 as i32;
    }
    ptr = unsafe { *str };
    cur = unsafe { *ptr };
    if cur as i32 == '&' as i32
        && (unsafe { *ptr.offset(1 as i32 as isize) }) as i32 == '#' as i32
        && (unsafe { *ptr.offset(2 as i32 as isize) }) as i32 == 'x' as i32
    {
        ptr = unsafe { ptr.offset(3 as i32 as isize) };
        cur = unsafe { *ptr };
        while cur as i32 != ';' as i32 {
            if cur as i32 >= '0' as i32 && cur as i32 <= '9' as i32 {
                val = val * 16 as i32 + (cur as i32 - '0' as i32);
            } else if cur as i32 >= 'a' as i32 && cur as i32 <= 'f' as i32 {
                val = val * 16 as i32 + (cur as i32 - 'a' as i32) + 10 as i32;
            } else if cur as i32 >= 'A' as i32 && cur as i32 <= 'F' as i32 {
                val = val * 16 as i32 + (cur as i32 - 'A' as i32) + 10 as i32;
            } else {
                xmlFatalErr(ctxt, XML_ERR_INVALID_HEX_CHARREF, 0 as *const i8);
                val = 0 as i32;
                break;
            }
            if val > 0x110000 as i32 {
                val = 0x110000 as i32;
            }
            ptr = unsafe { ptr.offset(1) };
            cur = unsafe { *ptr };
        }
        if cur as i32 == ';' as i32 {
            ptr = unsafe { ptr.offset(1) };
        }
    } else if cur as i32 == '&' as i32 && (unsafe { *ptr.offset(1 as i32 as isize) }) as i32 == '#' as i32 {
        ptr = unsafe { ptr.offset(2 as i32 as isize) };
        cur = unsafe { *ptr };
        while cur as i32 != ';' as i32 {
            if cur as i32 >= '0' as i32 && cur as i32 <= '9' as i32 {
                val = val * 10 as i32 + (cur as i32 - '0' as i32);
                if val > 0x110000 as i32 {
                    val = 0x110000 as i32;
                }
                ptr = unsafe { ptr.offset(1) };
                cur = unsafe { *ptr };
            } else {
                xmlFatalErr(ctxt, XML_ERR_INVALID_DEC_CHARREF, 0 as *const i8);
                val = 0 as i32;
                break;
            }
        }
        if cur as i32 == ';' as i32 {
            ptr = unsafe { ptr.offset(1) };
        }
    } else {
        xmlFatalErr(ctxt, XML_ERR_INVALID_CHARREF, 0 as *const i8);
        return 0 as i32;
    }
    (unsafe { *str = ptr });
    if val >= 0x110000 as i32 {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlParseStringCharRef: character reference out of bounds\n\0" as *const u8
                as *const i8,
            val,
        );
    } else if if val < 0x100 as i32 {
        (0x9 as i32 <= val && val <= 0xa as i32 || val == 0xd as i32 || 0x20 as i32 <= val) as i32
    } else {
        (0x100 as i32 <= val && val <= 0xd7ff as i32
            || 0xe000 as i32 <= val && val <= 0xfffd as i32
            || 0x10000 as i32 <= val && val <= 0x10ffff as i32) as i32
    } != 0
    {
        return val;
    } else {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlParseStringCharRef: invalid xmlChar value %d\n\0" as *const u8 as *const i8,
            val,
        );
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlParserHandlePEReference(mut ctxt: xmlParserCtxtPtr) {
    match (unsafe { (*ctxt).instate }) as i32 {
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
            if (unsafe { (*ctxt).external }) == 0 as i32 && (unsafe { (*ctxt).inputNr }) == 1 as i32 {
                return;
            }
            if (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 <= 0xa as i32
                || (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == 0xd as i32
                || (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == 0 as i32
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
pub extern "C" fn xmlStringLenDecodeEntities(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *const xmlChar,
    mut len: i32,
    mut what: i32,
    mut end: xmlChar,
    mut end2: xmlChar,
    mut end3: xmlChar,
) -> *mut xmlChar {
    let mut current_block: u64;
    let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
    let mut buffer_size: size_t = 0 as i32 as size_t;
    let mut nbchars: size_t = 0 as i32 as size_t;
    let mut current: *mut xmlChar = 0 as *mut xmlChar;
    let mut rep: *mut xmlChar = 0 as *mut xmlChar;
    let mut last: *const xmlChar = 0 as *const xmlChar;
    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut c: i32 = 0;
    let mut l: i32 = 0;
    if ctxt.is_null() || str.is_null() || len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    last = unsafe { str.offset(len as isize) };
    if (unsafe { (*ctxt).depth }) > 40 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
        || (unsafe { (*ctxt).depth }) > 1024 as i32
    {
        xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    buffer_size = 300 as i32 as size_t;
    buffer = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(buffer_size) }) as *mut xmlChar;
    if buffer.is_null() {
        current_block = 12997678243655494442;
    } else {
        if str < last {
            c = unsafe { xmlStringCurrentChar(ctxt, str, &mut l) };
        } else {
            c = 0 as i32;
        }
        's_81: loop {
            if !(c != 0 as i32
                && c != end as i32
                && c != end2 as i32
                && c != end3 as i32
                && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32)
            {
                current_block = 13810333397648094191;
                break;
            }
            if c == 0 as i32 {
                current_block = 13810333397648094191;
                break;
            }
            if c == '&' as i32 && (unsafe { *str.offset(1 as i32 as isize) }) as i32 == '#' as i32 {
                let mut val: i32 = xmlParseStringCharRef(ctxt, &mut str);
                if val == 0 as i32 {
                    current_block = 15857547771987096737;
                    break;
                }
                if 0 as i32 == 1 as i32 {
                    let fresh91 = nbchars;
                    nbchars = nbchars.wrapping_add(1);
                    (unsafe { *buffer.offset(fresh91 as isize) = val as xmlChar });
                } else {
                    nbchars = (nbchars as u64).wrapping_add((unsafe { xmlCopyCharMultiByte(
                        &mut *buffer.offset(nbchars as isize),
                        val,
                    ) }) as u64) as size_t as size_t;
                }
                if nbchars.wrapping_add(100 as i32 as u64) > buffer_size {
                    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                    let mut new_size: size_t = buffer_size
                        .wrapping_mul(2 as i32 as u64)
                        .wrapping_add(100 as i32 as u64);
                    if new_size < buffer_size {
                        current_block = 12997678243655494442;
                        break;
                    }
                    tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                        buffer as *mut libc::c_void,
                        new_size,
                    ) }) as *mut xmlChar;
                    if tmp.is_null() {
                        current_block = 12997678243655494442;
                        break;
                    }
                    buffer = tmp;
                    buffer_size = new_size;
                }
            } else if c == '&' as i32 && what & 1 as i32 != 0 {
                if (unsafe { *__xmlParserDebugEntities() }) != 0 {
                    (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"String decoding Entity Reference: %.30s\n\0" as *const u8 as *const i8,
                        str,
                    ) });
                }
                ent = xmlParseStringEntityRef(ctxt, &mut str);
                xmlParserEntityCheck(ctxt, 0 as i32 as size_t, ent, 0 as i32 as size_t);
                if !ent.is_null() {
                    let fresh92 = unsafe { &mut ((*ctxt).nbentities) };
                    *fresh92 = (*fresh92).wrapping_add(((unsafe { (*ent).checked }) / 2 as i32) as u64);
                }
                if !ent.is_null()
                    && (unsafe { (*ent).etype }) as u32 == XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
                {
                    if !(unsafe { (*ent).content }).is_null() {
                        if 0 as i32 == 1 as i32 {
                            let fresh93 = nbchars;
                            nbchars = nbchars.wrapping_add(1);
                            (unsafe { *buffer.offset(fresh93 as isize) =
                                *((*ent).content).offset(0 as i32 as isize) });
                        } else {
                            nbchars = (nbchars as u64).wrapping_add((unsafe { xmlCopyCharMultiByte(
                                &mut *buffer.offset(nbchars as isize),
                                *((*ent).content).offset(0 as i32 as isize) as i32,
                            ) })
                                as u64) as size_t as size_t;
                        }
                        if nbchars.wrapping_add(100 as i32 as u64) > buffer_size {
                            let mut tmp_0: *mut xmlChar = 0 as *mut xmlChar;
                            let mut new_size_0: size_t = buffer_size
                                .wrapping_mul(2 as i32 as u64)
                                .wrapping_add(100 as i32 as u64);
                            if new_size_0 < buffer_size {
                                current_block = 12997678243655494442;
                                break;
                            }
                            tmp_0 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                                buffer as *mut libc::c_void,
                                new_size_0,
                            ) }) as *mut xmlChar;
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
                            b"predefined entity has no content\n\0" as *const u8 as *const i8,
                        );
                        current_block = 15857547771987096737;
                        break;
                    }
                } else if !ent.is_null() && !(unsafe { (*ent).content }).is_null() {
                    let fresh94 = unsafe { &mut ((*ctxt).depth) };
                    *fresh94 += 1;
                    rep = xmlStringDecodeEntities(
                        ctxt,
                        unsafe { (*ent).content },
                        what,
                        0 as i32 as xmlChar,
                        0 as i32 as xmlChar,
                        0 as i32 as xmlChar,
                    );
                    let fresh95 = unsafe { &mut ((*ctxt).depth) };
                    *fresh95 -= 1;
                    if rep.is_null() {
                        (unsafe { *((*ent).content).offset(0 as i32 as isize) = 0 as i32 as xmlChar });
                        current_block = 15857547771987096737;
                        break;
                    } else {
                        current = rep;
                        while (unsafe { *current }) as i32 != 0 as i32 {
                            let fresh96 = current;
                            current = unsafe { current.offset(1) };
                            let fresh97 = nbchars;
                            nbchars = nbchars.wrapping_add(1);
                            (unsafe { *buffer.offset(fresh97 as isize) = *fresh96 });
                            if !(nbchars.wrapping_add(100 as i32 as u64) > buffer_size) {
                                continue;
                            }
                            if xmlParserEntityCheck(ctxt, nbchars, ent, 0 as i32 as size_t) != 0 {
                                current_block = 15857547771987096737;
                                break 's_81;
                            }
                            let mut tmp_1: *mut xmlChar = 0 as *mut xmlChar;
                            let mut new_size_1: size_t = buffer_size
                                .wrapping_mul(2 as i32 as u64)
                                .wrapping_add(100 as i32 as u64);
                            if new_size_1 < buffer_size {
                                current_block = 12997678243655494442;
                                break 's_81;
                            }
                            tmp_1 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                                buffer as *mut libc::c_void,
                                new_size_1,
                            ) }) as *mut xmlChar;
                            if tmp_1.is_null() {
                                current_block = 12997678243655494442;
                                break 's_81;
                            }
                            buffer = tmp_1;
                            buffer_size = new_size_1;
                        }
                        (unsafe { xmlFree.expect("non-null function pointer")(rep as *mut libc::c_void) });
                        rep = 0 as *mut xmlChar;
                    }
                } else if !ent.is_null() {
                    let mut i: i32 = unsafe { xmlStrlen((*ent).name) };
                    let mut cur: *const xmlChar = unsafe { (*ent).name };
                    let fresh98 = nbchars;
                    nbchars = nbchars.wrapping_add(1);
                    (unsafe { *buffer.offset(fresh98 as isize) = '&' as i32 as xmlChar });
                    if nbchars
                        .wrapping_add(i as u64)
                        .wrapping_add(100 as i32 as u64)
                        > buffer_size
                    {
                        let mut tmp_2: *mut xmlChar = 0 as *mut xmlChar;
                        let mut new_size_2: size_t = buffer_size
                            .wrapping_mul(2 as i32 as u64)
                            .wrapping_add(i as u64)
                            .wrapping_add(100 as i32 as u64);
                        if new_size_2 < buffer_size {
                            current_block = 12997678243655494442;
                            break;
                        }
                        tmp_2 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                            buffer as *mut libc::c_void,
                            new_size_2,
                        ) }) as *mut xmlChar;
                        if tmp_2.is_null() {
                            current_block = 12997678243655494442;
                            break;
                        }
                        buffer = tmp_2;
                        buffer_size = new_size_2;
                    }
                    while i > 0 as i32 {
                        let fresh99 = cur;
                        cur = unsafe { cur.offset(1) };
                        let fresh100 = nbchars;
                        nbchars = nbchars.wrapping_add(1);
                        (unsafe { *buffer.offset(fresh100 as isize) = *fresh99 });
                        i -= 1;
                    }
                    let fresh101 = nbchars;
                    nbchars = nbchars.wrapping_add(1);
                    (unsafe { *buffer.offset(fresh101 as isize) = ';' as i32 as xmlChar });
                }
            } else if c == '%' as i32 && what & 2 as i32 != 0 {
                if (unsafe { *__xmlParserDebugEntities() }) != 0 {
                    (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"String decoding PE Reference: %.30s\n\0" as *const u8 as *const i8,
                        str,
                    ) });
                }
                ent = xmlParseStringPEReference(ctxt, &mut str);
                xmlParserEntityCheck(ctxt, 0 as i32 as size_t, ent, 0 as i32 as size_t);
                if !ent.is_null() {
                    let fresh102 = unsafe { &mut ((*ctxt).nbentities) };
                    *fresh102 = (*fresh102).wrapping_add(((unsafe { (*ent).checked }) / 2 as i32) as u64);
                }
                if !ent.is_null() {
                    if (unsafe { (*ent).content }).is_null() {
                        if (unsafe { (*ctxt).options }) & XML_PARSE_NOENT as i32 != 0 as i32
                            || (unsafe { (*ctxt).options }) & XML_PARSE_DTDVALID as i32 != 0 as i32
                            || (unsafe { (*ctxt).validate }) != 0 as i32
                        {
                            xmlLoadEntityContent(ctxt, ent);
                        } else {
                            xmlWarningMsg(
                                ctxt,
                                XML_ERR_ENTITY_PROCESSING,
                                b"not validating will not read content for PE entity %s\n\0"
                                    as *const u8 as *const i8,
                                unsafe { (*ent).name },
                                0 as *const xmlChar,
                            );
                        }
                    }
                    let fresh103 = unsafe { &mut ((*ctxt).depth) };
                    *fresh103 += 1;
                    rep = xmlStringDecodeEntities(
                        ctxt,
                        unsafe { (*ent).content },
                        what,
                        0 as i32 as xmlChar,
                        0 as i32 as xmlChar,
                        0 as i32 as xmlChar,
                    );
                    let fresh104 = unsafe { &mut ((*ctxt).depth) };
                    *fresh104 -= 1;
                    if rep.is_null() {
                        if !(unsafe { (*ent).content }).is_null() {
                            (unsafe { *((*ent).content).offset(0 as i32 as isize) = 0 as i32 as xmlChar });
                        }
                        current_block = 15857547771987096737;
                        break;
                    } else {
                        current = rep;
                        while (unsafe { *current }) as i32 != 0 as i32 {
                            let fresh105 = current;
                            current = unsafe { current.offset(1) };
                            let fresh106 = nbchars;
                            nbchars = nbchars.wrapping_add(1);
                            (unsafe { *buffer.offset(fresh106 as isize) = *fresh105 });
                            if !(nbchars.wrapping_add(100 as i32 as u64) > buffer_size) {
                                continue;
                            }
                            if xmlParserEntityCheck(ctxt, nbchars, ent, 0 as i32 as size_t) != 0 {
                                current_block = 15857547771987096737;
                                break 's_81;
                            }
                            let mut tmp_3: *mut xmlChar = 0 as *mut xmlChar;
                            let mut new_size_3: size_t = buffer_size
                                .wrapping_mul(2 as i32 as u64)
                                .wrapping_add(100 as i32 as u64);
                            if new_size_3 < buffer_size {
                                current_block = 12997678243655494442;
                                break 's_81;
                            }
                            tmp_3 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                                buffer as *mut libc::c_void,
                                new_size_3,
                            ) }) as *mut xmlChar;
                            if tmp_3.is_null() {
                                current_block = 12997678243655494442;
                                break 's_81;
                            }
                            buffer = tmp_3;
                            buffer_size = new_size_3;
                        }
                        (unsafe { xmlFree.expect("non-null function pointer")(rep as *mut libc::c_void) });
                        rep = 0 as *mut xmlChar;
                    }
                }
            } else {
                if l == 1 as i32 {
                    let fresh107 = nbchars;
                    nbchars = nbchars.wrapping_add(1);
                    (unsafe { *buffer.offset(fresh107 as isize) = c as xmlChar });
                } else {
                    nbchars = (nbchars as u64)
                        .wrapping_add(
                            (unsafe { xmlCopyCharMultiByte(&mut *buffer.offset(nbchars as isize), c) }) as u64,
                        ) as size_t as size_t;
                }
                str = unsafe { str.offset(l as isize) };
                if nbchars.wrapping_add(100 as i32 as u64) > buffer_size {
                    let mut tmp_4: *mut xmlChar = 0 as *mut xmlChar;
                    let mut new_size_4: size_t = buffer_size
                        .wrapping_mul(2 as i32 as u64)
                        .wrapping_add(100 as i32 as u64);
                    if new_size_4 < buffer_size {
                        current_block = 12997678243655494442;
                        break;
                    }
                    tmp_4 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                        buffer as *mut libc::c_void,
                        new_size_4,
                    ) }) as *mut xmlChar;
                    if tmp_4.is_null() {
                        current_block = 12997678243655494442;
                        break;
                    }
                    buffer = tmp_4;
                    buffer_size = new_size_4;
                }
            }
            if str < last {
                c = unsafe { xmlStringCurrentChar(ctxt, str, &mut l) };
            } else {
                c = 0 as i32;
            }
        }
        match current_block {
            12997678243655494442 => {}
            15857547771987096737 => {}
            _ => {
                (unsafe { *buffer.offset(nbchars as isize) = 0 as i32 as xmlChar });
                return buffer;
            }
        }
    }
    match current_block {
        12997678243655494442 => {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
        }
        _ => {}
    }
    if !rep.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(rep as *mut libc::c_void) });
    }
    if !buffer.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlStringDecodeEntities(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *const xmlChar,
    mut what: i32,
    mut end: xmlChar,
    mut end2: xmlChar,
    mut end3: xmlChar,
) -> *mut xmlChar {
    if ctxt.is_null() || str.is_null() {
        return 0 as *mut xmlChar;
    }
    return xmlStringLenDecodeEntities(ctxt, str, unsafe { xmlStrlen(str) }, what, end, end2, end3);
}
extern "C" fn areBlanks(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *const xmlChar,
    mut len: i32,
    mut blank_chars: i32,
) -> i32 {
    let mut i: i32 = 0;
    let mut ret: i32 = 0;
    let mut lastChild: xmlNodePtr = 0 as *mut xmlNode;
    if (unsafe { (*(*ctxt).sax).ignorableWhitespace }) == (unsafe { (*(*ctxt).sax).characters }) {
        return 0 as i32;
    }
    if (unsafe { (*ctxt).space }).is_null() || (unsafe { *(*ctxt).space }) == 1 as i32 || (unsafe { *(*ctxt).space }) == -(2 as i32) {
        return 0 as i32;
    }
    if blank_chars == 0 as i32 {
        i = 0 as i32;
        while i < len {
            if !((unsafe { *str.offset(i as isize) }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *str.offset(i as isize) }) as i32
                    && (unsafe { *str.offset(i as isize) }) as i32 <= 0xa as i32
                || (unsafe { *str.offset(i as isize) }) as i32 == 0xd as i32)
            {
                return 0 as i32;
            }
            i += 1;
        }
    }
    if (unsafe { (*ctxt).node }).is_null() {
        return 0 as i32;
    }
    if !(unsafe { (*ctxt).myDoc }).is_null() {
        ret = unsafe { xmlIsMixedElement((*ctxt).myDoc, (*(*ctxt).node).name) };
        if ret == 0 as i32 {
            return 1 as i32;
        }
        if ret == 1 as i32 {
            return 0 as i32;
        }
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '<' as i32 && (unsafe { *(*(*ctxt).input).cur }) as i32 != 0xd as i32 {
        return 0 as i32;
    }
    if (unsafe { (*(*ctxt).node).children }).is_null()
        && (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32
    {
        return 0 as i32;
    }
    lastChild = unsafe { xmlGetLastChild((*ctxt).node as *const xmlNode) };
    if lastChild.is_null() {
        if (unsafe { (*(*ctxt).node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
            && !(unsafe { (*(*ctxt).node).content }).is_null()
        {
            return 0 as i32;
        }
    } else if (unsafe { xmlNodeIsText(lastChild as *const xmlNode) }) != 0 {
        return 0 as i32;
    } else {
        if !(unsafe { (*(*ctxt).node).children }).is_null() && (unsafe { xmlNodeIsText((*(*ctxt).node).children) }) != 0 {
            return 0 as i32;
        }
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlSplitQName(
    mut ctxt: xmlParserCtxtPtr,
    mut name: *const xmlChar,
    mut prefix: *mut *mut xmlChar,
) -> *mut xmlChar {
    let mut buf: [xmlChar; 105] = [0; 105];
    let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut max: i32 = 100 as i32;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *const xmlChar = name;
    let mut c: i32 = 0;
    if prefix.is_null() {
        return 0 as *mut xmlChar;
    }
    (unsafe { *prefix = 0 as *mut xmlChar });
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == ':' as i32 {
        return unsafe { xmlStrdup(name) };
    }
    let fresh108 = cur;
    cur = unsafe { cur.offset(1) };
    c = (unsafe { *fresh108 }) as i32;
    while c != 0 as i32 && c != ':' as i32 && len < max {
        let fresh109 = len;
        len = len + 1;
        buf[fresh109 as usize] = c as xmlChar;
        let fresh110 = cur;
        cur = unsafe { cur.offset(1) };
        c = (unsafe { *fresh110 }) as i32;
    }
    if len >= max {
        max = len * 2 as i32;
        buffer = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
            (max as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        ) }) as *mut xmlChar;
        if buffer.is_null() {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            return 0 as *mut xmlChar;
        }
        (unsafe { memcpy(
            buffer as *mut libc::c_void,
            buf.as_mut_ptr() as *const libc::c_void,
            len as u64,
        ) });
        while c != 0 as i32 && c != ':' as i32 {
            if len + 10 as i32 > max {
                let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                max *= 2 as i32;
                tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                    buffer as *mut libc::c_void,
                    (max as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
                ) }) as *mut xmlChar;
                if tmp.is_null() {
                    (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
                    (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                    return 0 as *mut xmlChar;
                }
                buffer = tmp;
            }
            let fresh111 = len;
            len = len + 1;
            (unsafe { *buffer.offset(fresh111 as isize) = c as xmlChar });
            let fresh112 = cur;
            cur = unsafe { cur.offset(1) };
            c = (unsafe { *fresh112 }) as i32;
        }
        (unsafe { *buffer.offset(len as isize) = 0 as i32 as xmlChar });
    }
    if c == ':' as i32 && (unsafe { *cur }) as i32 == 0 as i32 {
        if !buffer.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
        }
        (unsafe { *prefix = 0 as *mut xmlChar });
        return unsafe { xmlStrdup(name) };
    }
    if buffer.is_null() {
        ret = unsafe { xmlStrndup(buf.as_mut_ptr(), len) };
    } else {
        ret = buffer;
        buffer = 0 as *mut xmlChar;
        max = 100 as i32;
    }
    if c == ':' as i32 {
        c = (unsafe { *cur }) as i32;
        (unsafe { *prefix = ret });
        if c == 0 as i32 {
            return unsafe { xmlStrndup(b"\0" as *const u8 as *const i8 as *mut xmlChar, 0 as i32) };
        }
        len = 0 as i32;
        if !(c >= 0x61 as i32 && c <= 0x7a as i32
            || c >= 0x41 as i32 && c <= 0x5a as i32
            || c == '_' as i32
            || c == ':' as i32)
        {
            let mut l: i32 = 0;
            let mut first: i32 = unsafe { xmlStringCurrentChar(ctxt, cur, &mut l) };
            if !((if first < 0x100 as i32 {
                (0x41 as i32 <= first && first <= 0x5a as i32
                    || 0x61 as i32 <= first && first <= 0x7a as i32
                    || 0xc0 as i32 <= first && first <= 0xd6 as i32
                    || 0xd8 as i32 <= first && first <= 0xf6 as i32
                    || 0xf8 as i32 <= first) as i32
            } else {
                unsafe { xmlCharInRange(first as u32, &xmlIsBaseCharGroup) }
            }) != 0
                || (if first < 0x100 as i32 {
                    0 as i32
                } else {
                    (0x4e00 as i32 <= first && first <= 0x9fa5 as i32
                        || first == 0x3007 as i32
                        || 0x3021 as i32 <= first && first <= 0x3029 as i32)
                        as i32
                }) != 0)
                && first != '_' as i32
            {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_NS_ERR_QNAME,
                    b"Name %s is not XML Namespace compliant\n\0" as *const u8 as *const i8,
                    name,
                );
            }
        }
        cur = unsafe { cur.offset(1) };
        while c != 0 as i32 && len < max {
            let fresh113 = len;
            len = len + 1;
            buf[fresh113 as usize] = c as xmlChar;
            let fresh114 = cur;
            cur = unsafe { cur.offset(1) };
            c = (unsafe { *fresh114 }) as i32;
        }
        if len >= max {
            max = len * 2 as i32;
            buffer = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
                (max as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) }) as *mut xmlChar;
            if buffer.is_null() {
                (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                return 0 as *mut xmlChar;
            }
            (unsafe { memcpy(
                buffer as *mut libc::c_void,
                buf.as_mut_ptr() as *const libc::c_void,
                len as u64,
            ) });
            while c != 0 as i32 {
                if len + 10 as i32 > max {
                    let mut tmp_0: *mut xmlChar = 0 as *mut xmlChar;
                    max *= 2 as i32;
                    tmp_0 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                        buffer as *mut libc::c_void,
                        (max as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
                    ) }) as *mut xmlChar;
                    if tmp_0.is_null() {
                        (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                        (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
                        return 0 as *mut xmlChar;
                    }
                    buffer = tmp_0;
                }
                let fresh115 = len;
                len = len + 1;
                (unsafe { *buffer.offset(fresh115 as isize) = c as xmlChar });
                let fresh116 = cur;
                cur = unsafe { cur.offset(1) };
                c = (unsafe { *fresh116 }) as i32;
            }
            (unsafe { *buffer.offset(len as isize) = 0 as i32 as xmlChar });
        }
        if buffer.is_null() {
            ret = unsafe { xmlStrndup(buf.as_mut_ptr(), len) };
        } else {
            ret = buffer;
        }
    }
    return ret;
}
extern "C" fn xmlIsNameStartChar(mut ctxt: xmlParserCtxtPtr, mut c: i32) -> i32 {
    if (unsafe { (*ctxt).options }) & XML_PARSE_OLD10 as i32 == 0 as i32 {
        if c != ' ' as i32
            && c != '>' as i32
            && c != '/' as i32
            && (c >= 'a' as i32 && c <= 'z' as i32
                || c >= 'A' as i32 && c <= 'Z' as i32
                || c == '_' as i32
                || c == ':' as i32
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
        unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
        }) != 0
        || c == '_' as i32
        || c == ':' as i32
    {
        return 1 as i32;
    }
    return 0 as i32;
}
extern "C" fn xmlIsNameChar(mut ctxt: xmlParserCtxtPtr, mut c: i32) -> i32 {
    if (unsafe { (*ctxt).options }) & XML_PARSE_OLD10 as i32 == 0 as i32 {
        if c != ' ' as i32
            && c != '>' as i32
            && c != '/' as i32
            && (c >= 'a' as i32 && c <= 'z' as i32
                || c >= 'A' as i32 && c <= 'Z' as i32
                || c >= '0' as i32 && c <= '9' as i32
                || c == '_' as i32
                || c == ':' as i32
                || c == '-' as i32
                || c == '.' as i32
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
        unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
        }) != 0
        || (if c < 0x100 as i32 {
            (0x30 as i32 <= c && c <= 0x39 as i32) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsDigitGroup) }
        }) != 0
        || c == '.' as i32
        || c == '-' as i32
        || c == '_' as i32
        || c == ':' as i32
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsCombiningGroup) }
        }) != 0
        || (if c < 0x100 as i32 {
            (c == 0xb7 as i32) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsExtenderGroup) }
        }) != 0
    {
        return 1 as i32;
    }
    return 0 as i32;
}
extern "C" fn xmlParseNameComplex(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut len: i32 = 0 as i32;
    let mut l: i32 = 0;
    let mut c: i32 = 0;
    let mut count: i32 = 0 as i32;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return 0 as *const xmlChar;
    }
    c = unsafe { xmlCurrentChar(ctxt, &mut l) };
    if (unsafe { (*ctxt).options }) & XML_PARSE_OLD10 as i32 == 0 as i32 {
        if c == ' ' as i32
            || c == '>' as i32
            || c == '/' as i32
            || !(c >= 'a' as i32 && c <= 'z' as i32
                || c >= 'A' as i32 && c <= 'Z' as i32
                || c == '_' as i32
                || c == ':' as i32
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
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
            let fresh117 = unsafe { &mut ((*(*ctxt).input).line) };
            *fresh117 += 1;
            (unsafe { (*(*ctxt).input).col = 1 as i32 });
        } else {
            let fresh118 = unsafe { &mut ((*(*ctxt).input).col) };
            *fresh118 += 1;
        }
        let fresh119 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh119 = unsafe { (*fresh119).offset(l as isize) };
        c = unsafe { xmlCurrentChar(ctxt, &mut l) };
        while c != ' ' as i32
            && c != '>' as i32
            && c != '/' as i32
            && (c >= 'a' as i32 && c <= 'z' as i32
                || c >= 'A' as i32 && c <= 'Z' as i32
                || c >= '0' as i32 && c <= '9' as i32
                || c == '_' as i32
                || c == ':' as i32
                || c == '-' as i32
                || c == '.' as i32
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
            let fresh120 = count;
            count = count + 1;
            if fresh120 > 100 as i32 {
                count = 0 as i32;
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *const xmlChar;
                }
            }
            len += l;
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
                let fresh121 = unsafe { &mut ((*(*ctxt).input).line) };
                *fresh121 += 1;
                (unsafe { (*(*ctxt).input).col = 1 as i32 });
            } else {
                let fresh122 = unsafe { &mut ((*(*ctxt).input).col) };
                *fresh122 += 1;
            }
            let fresh123 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh123 = unsafe { (*fresh123).offset(l as isize) };
            c = unsafe { xmlCurrentChar(ctxt, &mut l) };
        }
    } else {
        if c == ' ' as i32
            || c == '>' as i32
            || c == '/' as i32
            || !((if c < 0x100 as i32 {
                (0x41 as i32 <= c && c <= 0x5a as i32
                    || 0x61 as i32 <= c && c <= 0x7a as i32
                    || 0xc0 as i32 <= c && c <= 0xd6 as i32
                    || 0xd8 as i32 <= c && c <= 0xf6 as i32
                    || 0xf8 as i32 <= c) as i32
            } else {
                unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
            }) != 0
                || (if c < 0x100 as i32 {
                    0 as i32
                } else {
                    (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                        || c == 0x3007 as i32
                        || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
                }) != 0)
                && c != '_' as i32
                && c != ':' as i32
        {
            return 0 as *const xmlChar;
        }
        len += l;
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
            let fresh124 = unsafe { &mut ((*(*ctxt).input).line) };
            *fresh124 += 1;
            (unsafe { (*(*ctxt).input).col = 1 as i32 });
        } else {
            let fresh125 = unsafe { &mut ((*(*ctxt).input).col) };
            *fresh125 += 1;
        }
        let fresh126 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh126 = unsafe { (*fresh126).offset(l as isize) };
        c = unsafe { xmlCurrentChar(ctxt, &mut l) };
        while c != ' ' as i32
            && c != '>' as i32
            && c != '/' as i32
            && ((if c < 0x100 as i32 {
                (0x41 as i32 <= c && c <= 0x5a as i32
                    || 0x61 as i32 <= c && c <= 0x7a as i32
                    || 0xc0 as i32 <= c && c <= 0xd6 as i32
                    || 0xd8 as i32 <= c && c <= 0xf6 as i32
                    || 0xf8 as i32 <= c) as i32
            } else {
                unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
            }) != 0
                || (if c < 0x100 as i32 {
                    0 as i32
                } else {
                    (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                        || c == 0x3007 as i32
                        || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
                }) != 0
                || (if c < 0x100 as i32 {
                    (0x30 as i32 <= c && c <= 0x39 as i32) as i32
                } else {
                    unsafe { xmlCharInRange(c as u32, &xmlIsDigitGroup) }
                }) != 0
                || c == '.' as i32
                || c == '-' as i32
                || c == '_' as i32
                || c == ':' as i32
                || (if c < 0x100 as i32 {
                    0 as i32
                } else {
                    unsafe { xmlCharInRange(c as u32, &xmlIsCombiningGroup) }
                }) != 0
                || (if c < 0x100 as i32 {
                    (c == 0xb7 as i32) as i32
                } else {
                    unsafe { xmlCharInRange(c as u32, &xmlIsExtenderGroup) }
                }) != 0)
        {
            let fresh127 = count;
            count = count + 1;
            if fresh127 > 100 as i32 {
                count = 0 as i32;
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *const xmlChar;
                }
            }
            len += l;
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
                let fresh128 = unsafe { &mut ((*(*ctxt).input).line) };
                *fresh128 += 1;
                (unsafe { (*(*ctxt).input).col = 1 as i32 });
            } else {
                let fresh129 = unsafe { &mut ((*(*ctxt).input).col) };
                *fresh129 += 1;
            }
            let fresh130 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh130 = unsafe { (*fresh130).offset(l as isize) };
            c = unsafe { xmlCurrentChar(ctxt, &mut l) };
        }
    }
    if len > 50000 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
        xmlFatalErr(
            ctxt,
            XML_ERR_NAME_TOO_LONG,
            b"Name\0" as *const u8 as *const i8,
        );
        return 0 as *const xmlChar;
    }
    if ((unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64) < len as i64 {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"unexpected change of input buffer\0" as *const u8 as *const i8,
        );
        return 0 as *const xmlChar;
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(-(1 as i32) as isize) }) as i32 == '\r' as i32
    {
        return unsafe { xmlDictLookup(
            (*ctxt).dict,
            ((*(*ctxt).input).cur).offset(-((len + 1 as i32) as isize)),
            len,
        ) };
    }
    return unsafe { xmlDictLookup(
        (*ctxt).dict,
        ((*(*ctxt).input).cur).offset(-(len as isize)),
        len,
    ) };
}
#[no_mangle]
pub extern "C" fn xmlParseName(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    let mut count: i32 = 0 as i32;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    in_0 = unsafe { (*(*ctxt).input).cur };
    if (unsafe { *in_0 }) as i32 >= 0x61 as i32 && (unsafe { *in_0 }) as i32 <= 0x7a as i32
        || (unsafe { *in_0 }) as i32 >= 0x41 as i32 && (unsafe { *in_0 }) as i32 <= 0x5a as i32
        || (unsafe { *in_0 }) as i32 == '_' as i32
        || (unsafe { *in_0 }) as i32 == ':' as i32
    {
        in_0 = unsafe { in_0.offset(1) };
        while (unsafe { *in_0 }) as i32 >= 0x61 as i32 && (unsafe { *in_0 }) as i32 <= 0x7a as i32
            || (unsafe { *in_0 }) as i32 >= 0x41 as i32 && (unsafe { *in_0 }) as i32 <= 0x5a as i32
            || (unsafe { *in_0 }) as i32 >= 0x30 as i32 && (unsafe { *in_0 }) as i32 <= 0x39 as i32
            || (unsafe { *in_0 }) as i32 == '_' as i32
            || (unsafe { *in_0 }) as i32 == '-' as i32
            || (unsafe { *in_0 }) as i32 == ':' as i32
            || (unsafe { *in_0 }) as i32 == '.' as i32
        {
            in_0 = unsafe { in_0.offset(1) };
        }
        if (unsafe { *in_0 }) as i32 > 0 as i32 && ((unsafe { *in_0 }) as i32) < 0x80 as i32 {
            count = (unsafe { in_0.offset_from((*(*ctxt).input).cur) }) as i64 as i32;
            if count > 50000 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_NAME_TOO_LONG,
                    b"Name\0" as *const u8 as *const i8,
                );
                return 0 as *const xmlChar;
            }
            ret = unsafe { xmlDictLookup((*ctxt).dict, (*(*ctxt).input).cur, count) };
            let fresh131 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh131 = in_0;
            (unsafe { (*(*ctxt).input).col += count });
            if ret.is_null() {
                (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            }
            return ret;
        }
    }
    return xmlParseNameComplex(ctxt);
}
extern "C" fn xmlParseNCNameComplex(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut len: i32 = 0 as i32;
    let mut l: i32 = 0;
    let mut c: i32 = 0;
    let mut count: i32 = 0 as i32;
    let mut startPosition: size_t = 0 as i32 as size_t;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    startPosition = (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as size_t;
    c = unsafe { xmlCurrentChar(ctxt, &mut l) };
    if c == ' ' as i32
        || c == '>' as i32
        || c == '/' as i32
        || (xmlIsNameStartChar(ctxt, c) == 0 || c == ':' as i32)
    {
        return 0 as *const xmlChar;
    }
    while c != ' ' as i32
        && c != '>' as i32
        && c != '/' as i32
        && (xmlIsNameChar(ctxt, c) != 0 && c != ':' as i32)
    {
        let fresh132 = count;
        count = count + 1;
        if fresh132 > 100 as i32 {
            if len > 50000 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_NAME_TOO_LONG,
                    b"NCName\0" as *const u8 as *const i8,
                );
                return 0 as *const xmlChar;
            }
            count = 0 as i32;
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                return 0 as *const xmlChar;
            }
        }
        len += l;
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
            let fresh133 = unsafe { &mut ((*(*ctxt).input).line) };
            *fresh133 += 1;
            (unsafe { (*(*ctxt).input).col = 1 as i32 });
        } else {
            let fresh134 = unsafe { &mut ((*(*ctxt).input).col) };
            *fresh134 += 1;
        }
        let fresh135 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh135 = unsafe { (*fresh135).offset(l as isize) };
        c = unsafe { xmlCurrentChar(ctxt, &mut l) };
        if c == 0 as i32 {
            count = 0 as i32;
            let fresh136 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh136 = unsafe { (*fresh136).offset(-(l as isize)) };
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                return 0 as *const xmlChar;
            }
            let fresh137 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh137 = unsafe { (*fresh137).offset(l as isize) };
            c = unsafe { xmlCurrentChar(ctxt, &mut l) };
        }
    }
    if len > 50000 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
        xmlFatalErr(
            ctxt,
            XML_ERR_NAME_TOO_LONG,
            b"NCName\0" as *const u8 as *const i8,
        );
        return 0 as *const xmlChar;
    }
    return unsafe { xmlDictLookup(
        (*ctxt).dict,
        ((*(*ctxt).input).base).offset(startPosition as isize),
        len,
    ) };
}
extern "C" fn xmlParseNCName(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut e: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    let mut count: i32 = 0 as i32;
    in_0 = unsafe { (*(*ctxt).input).cur };
    e = unsafe { (*(*ctxt).input).end };
    if ((unsafe { *in_0 }) as i32 >= 0x61 as i32 && (unsafe { *in_0 }) as i32 <= 0x7a as i32
        || (unsafe { *in_0 }) as i32 >= 0x41 as i32 && (unsafe { *in_0 }) as i32 <= 0x5a as i32
        || (unsafe { *in_0 }) as i32 == '_' as i32)
        && in_0 < e
    {
        in_0 = unsafe { in_0.offset(1) };
        while ((unsafe { *in_0 }) as i32 >= 0x61 as i32 && (unsafe { *in_0 }) as i32 <= 0x7a as i32
            || (unsafe { *in_0 }) as i32 >= 0x41 as i32 && (unsafe { *in_0 }) as i32 <= 0x5a as i32
            || (unsafe { *in_0 }) as i32 >= 0x30 as i32 && (unsafe { *in_0 }) as i32 <= 0x39 as i32
            || (unsafe { *in_0 }) as i32 == '_' as i32
            || (unsafe { *in_0 }) as i32 == '-' as i32
            || (unsafe { *in_0 }) as i32 == '.' as i32)
            && in_0 < e
        {
            in_0 = unsafe { in_0.offset(1) };
        }
        if !(in_0 >= e) {
            if (unsafe { *in_0 }) as i32 > 0 as i32 && ((unsafe { *in_0 }) as i32) < 0x80 as i32 {
                count = (unsafe { in_0.offset_from((*(*ctxt).input).cur) }) as i64 as i32;
                if count > 50000 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
                    xmlFatalErr(
                        ctxt,
                        XML_ERR_NAME_TOO_LONG,
                        b"NCName\0" as *const u8 as *const i8,
                    );
                    return 0 as *const xmlChar;
                }
                ret = unsafe { xmlDictLookup((*ctxt).dict, (*(*ctxt).input).cur, count) };
                let fresh138 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh138 = in_0;
                (unsafe { (*(*ctxt).input).col += count });
                if ret.is_null() {
                    (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                }
                return ret;
            }
        }
    }
    return xmlParseNCNameComplex(ctxt);
}
extern "C" fn xmlParseNameAndCompare(
    mut ctxt: xmlParserCtxtPtr,
    mut other: *const xmlChar,
) -> *const xmlChar {
    let mut cmp: *const xmlChar = other;
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return 0 as *const xmlChar;
    }
    in_0 = unsafe { (*(*ctxt).input).cur };
    while (unsafe { *in_0 }) as i32 != 0 as i32 && (unsafe { *in_0 }) as i32 == (unsafe { *cmp }) as i32 {
        in_0 = unsafe { in_0.offset(1) };
        cmp = unsafe { cmp.offset(1) };
    }
    if (unsafe { *cmp }) as i32 == 0 as i32
        && ((unsafe { *in_0 }) as i32 == '>' as i32
            || ((unsafe { *in_0 }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *in_0 }) as i32 && (unsafe { *in_0 }) as i32 <= 0xa as i32
                || (unsafe { *in_0 }) as i32 == 0xd as i32))
    {
        let fresh139 = unsafe { &mut ((*(*ctxt).input).col) };
        *fresh139 = (*fresh139 as i64 + (unsafe { in_0.offset_from((*(*ctxt).input).cur) }) as i64) as i32;
        let fresh140 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh140 = in_0;
        return 1 as i32 as *const xmlChar;
    }
    ret = xmlParseName(ctxt);
    if ret == other {
        return 1 as i32 as *const xmlChar;
    }
    return ret;
}
extern "C" fn xmlParseStringName(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *mut *const xmlChar,
) -> *mut xmlChar {
    let mut buf: [xmlChar; 105] = [0; 105];
    let mut cur: *const xmlChar = unsafe { *str };
    let mut len: i32 = 0 as i32;
    let mut l: i32 = 0;
    let mut c: i32 = 0;
    c = unsafe { xmlStringCurrentChar(ctxt, cur, &mut l) };
    if xmlIsNameStartChar(ctxt, c) == 0 {
        return 0 as *mut xmlChar;
    }
    if l == 1 as i32 {
        let fresh141 = len;
        len = len + 1;
        buf[fresh141 as usize] = c as xmlChar;
    } else {
        len += unsafe { xmlCopyCharMultiByte(&mut *buf.as_mut_ptr().offset(len as isize), c) };
    }
    cur = unsafe { cur.offset(l as isize) };
    c = unsafe { xmlStringCurrentChar(ctxt, cur, &mut l) };
    while xmlIsNameChar(ctxt, c) != 0 {
        if l == 1 as i32 {
            let fresh142 = len;
            len = len + 1;
            buf[fresh142 as usize] = c as xmlChar;
        } else {
            len += unsafe { xmlCopyCharMultiByte(&mut *buf.as_mut_ptr().offset(len as isize), c) };
        }
        cur = unsafe { cur.offset(l as isize) };
        c = unsafe { xmlStringCurrentChar(ctxt, cur, &mut l) };
        if len >= 100 as i32 {
            let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
            let mut max: i32 = len * 2 as i32;
            buffer = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
                (max as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) }) as *mut xmlChar;
            if buffer.is_null() {
                (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                return 0 as *mut xmlChar;
            }
            (unsafe { memcpy(
                buffer as *mut libc::c_void,
                buf.as_mut_ptr() as *const libc::c_void,
                len as u64,
            ) });
            while xmlIsNameChar(ctxt, c) != 0 {
                if len + 10 as i32 > max {
                    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                    if len > 50000 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_NAME_TOO_LONG,
                            b"NCName\0" as *const u8 as *const i8,
                        );
                        (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
                        return 0 as *mut xmlChar;
                    }
                    max *= 2 as i32;
                    tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                        buffer as *mut libc::c_void,
                        (max as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
                    ) }) as *mut xmlChar;
                    if tmp.is_null() {
                        (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                        (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
                        return 0 as *mut xmlChar;
                    }
                    buffer = tmp;
                }
                if l == 1 as i32 {
                    let fresh143 = len;
                    len = len + 1;
                    (unsafe { *buffer.offset(fresh143 as isize) = c as xmlChar });
                } else {
                    len += unsafe { xmlCopyCharMultiByte(&mut *buffer.offset(len as isize), c) };
                }
                cur = unsafe { cur.offset(l as isize) };
                c = unsafe { xmlStringCurrentChar(ctxt, cur, &mut l) };
            }
            (unsafe { *buffer.offset(len as isize) = 0 as i32 as xmlChar });
            (unsafe { *str = cur });
            return buffer;
        }
    }
    if len > 50000 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
        xmlFatalErr(
            ctxt,
            XML_ERR_NAME_TOO_LONG,
            b"NCName\0" as *const u8 as *const i8,
        );
        return 0 as *mut xmlChar;
    }
    (unsafe { *str = cur });
    return unsafe { xmlStrndup(buf.as_mut_ptr(), len) };
}
#[no_mangle]
pub extern "C" fn xmlParseNmtoken(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    let mut buf: [xmlChar; 105] = [0; 105];
    let mut len: i32 = 0 as i32;
    let mut l: i32 = 0;
    let mut c: i32 = 0;
    let mut count: i32 = 0 as i32;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return 0 as *mut xmlChar;
    }
    c = unsafe { xmlCurrentChar(ctxt, &mut l) };
    while xmlIsNameChar(ctxt, c) != 0 {
        let fresh144 = count;
        count = count + 1;
        if fresh144 > 100 as i32 {
            count = 0 as i32;
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
        }
        if l == 1 as i32 {
            let fresh145 = len;
            len = len + 1;
            buf[fresh145 as usize] = c as xmlChar;
        } else {
            len += unsafe { xmlCopyCharMultiByte(&mut *buf.as_mut_ptr().offset(len as isize), c) };
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
            let fresh146 = unsafe { &mut ((*(*ctxt).input).line) };
            *fresh146 += 1;
            (unsafe { (*(*ctxt).input).col = 1 as i32 });
        } else {
            let fresh147 = unsafe { &mut ((*(*ctxt).input).col) };
            *fresh147 += 1;
        }
        let fresh148 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh148 = unsafe { (*fresh148).offset(l as isize) };
        c = unsafe { xmlCurrentChar(ctxt, &mut l) };
        if c == 0 as i32 {
            count = 0 as i32;
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                return 0 as *mut xmlChar;
            }
            c = unsafe { xmlCurrentChar(ctxt, &mut l) };
        }
        if len >= 100 as i32 {
            let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
            let mut max: i32 = len * 2 as i32;
            buffer = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
                (max as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) }) as *mut xmlChar;
            if buffer.is_null() {
                (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                return 0 as *mut xmlChar;
            }
            (unsafe { memcpy(
                buffer as *mut libc::c_void,
                buf.as_mut_ptr() as *const libc::c_void,
                len as u64,
            ) });
            while xmlIsNameChar(ctxt, c) != 0 {
                let fresh149 = count;
                count = count + 1;
                if fresh149 > 100 as i32 {
                    count = 0 as i32;
                    if (unsafe { (*ctxt).progressive }) == 0 as i32
                        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                            < 250 as i32 as i64
                    {
                        xmlGROW(ctxt);
                    }
                    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                        (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
                        return 0 as *mut xmlChar;
                    }
                }
                if len + 10 as i32 > max {
                    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                    if max > 50000 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_NAME_TOO_LONG,
                            b"NmToken\0" as *const u8 as *const i8,
                        );
                        (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
                        return 0 as *mut xmlChar;
                    }
                    max *= 2 as i32;
                    tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                        buffer as *mut libc::c_void,
                        (max as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
                    ) }) as *mut xmlChar;
                    if tmp.is_null() {
                        (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                        (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
                        return 0 as *mut xmlChar;
                    }
                    buffer = tmp;
                }
                if l == 1 as i32 {
                    let fresh150 = len;
                    len = len + 1;
                    (unsafe { *buffer.offset(fresh150 as isize) = c as xmlChar });
                } else {
                    len += unsafe { xmlCopyCharMultiByte(&mut *buffer.offset(len as isize), c) };
                }
                if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
                    let fresh151 = unsafe { &mut ((*(*ctxt).input).line) };
                    *fresh151 += 1;
                    (unsafe { (*(*ctxt).input).col = 1 as i32 });
                } else {
                    let fresh152 = unsafe { &mut ((*(*ctxt).input).col) };
                    *fresh152 += 1;
                }
                let fresh153 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh153 = unsafe { (*fresh153).offset(l as isize) };
                c = unsafe { xmlCurrentChar(ctxt, &mut l) };
            }
            (unsafe { *buffer.offset(len as isize) = 0 as i32 as xmlChar });
            return buffer;
        }
    }
    if len == 0 as i32 {
        return 0 as *mut xmlChar;
    }
    if len > 50000 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
        xmlFatalErr(
            ctxt,
            XML_ERR_NAME_TOO_LONG,
            b"NmToken\0" as *const u8 as *const i8,
        );
        return 0 as *mut xmlChar;
    }
    return unsafe { xmlStrndup(buf.as_mut_ptr(), len) };
}
#[no_mangle]
pub extern "C" fn xmlParseEntityValue(
    mut ctxt: xmlParserCtxtPtr,
    mut orig: *mut *mut xmlChar,
) -> *mut xmlChar {
    let mut current_block: u64;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 100 as i32;
    let mut c: i32 = 0;
    let mut l: i32 = 0;
    let mut stop: xmlChar = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '"' as i32 {
        stop = '"' as i32 as xmlChar;
    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\'' as i32 {
        stop = '\'' as i32 as xmlChar;
    } else {
        xmlFatalErr(ctxt, XML_ERR_ENTITY_NOT_STARTED, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    buf = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
        (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) }) as *mut xmlChar;
    if buf.is_null() {
        (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
        return 0 as *mut xmlChar;
    }
    (unsafe { (*ctxt).instate = XML_PARSER_ENTITY_VALUE });
    input = unsafe { (*ctxt).input };
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if !((unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32) {
        (unsafe { xmlNextChar(ctxt) });
        c = unsafe { xmlCurrentChar(ctxt, &mut l) };
        loop {
            if !((if c < 0x100 as i32 {
                (0x9 as i32 <= c && c <= 0xa as i32 || c == 0xd as i32 || 0x20 as i32 <= c) as i32
            } else {
                (0x100 as i32 <= c && c <= 0xd7ff as i32
                    || 0xe000 as i32 <= c && c <= 0xfffd as i32
                    || 0x10000 as i32 <= c && c <= 0x10ffff as i32) as i32
            }) != 0
                && (c != stop as i32 || (unsafe { (*ctxt).input }) != input)
                && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32)
            {
                current_block = 13460095289871124136;
                break;
            }
            if len + 5 as i32 >= size {
                let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                size *= 2 as i32;
                tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                    buf as *mut libc::c_void,
                    (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
                ) }) as *mut xmlChar;
                if tmp.is_null() {
                    (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                    current_block = 1959508989248982327;
                    break;
                } else {
                    buf = tmp;
                }
            }
            if l == 1 as i32 {
                let fresh154 = len;
                len = len + 1;
                (unsafe { *buf.offset(fresh154 as isize) = c as xmlChar });
            } else {
                len += unsafe { xmlCopyCharMultiByte(&mut *buf.offset(len as isize), c) };
            }
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
                let fresh155 = unsafe { &mut ((*(*ctxt).input).line) };
                *fresh155 += 1;
                (unsafe { (*(*ctxt).input).col = 1 as i32 });
            } else {
                let fresh156 = unsafe { &mut ((*(*ctxt).input).col) };
                *fresh156 += 1;
            }
            let fresh157 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh157 = unsafe { (*fresh157).offset(l as isize) };
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            c = unsafe { xmlCurrentChar(ctxt, &mut l) };
            if c == 0 as i32 {
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                c = unsafe { xmlCurrentChar(ctxt, &mut l) };
            }
        }
        match current_block {
            1959508989248982327 => {}
            _ => {
                (unsafe { *buf.offset(len as isize) = 0 as i32 as xmlChar });
                if !((unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32) {
                    if c != stop as i32 {
                        xmlFatalErr(ctxt, XML_ERR_ENTITY_NOT_FINISHED, 0 as *const i8);
                    } else {
                        (unsafe { xmlNextChar(ctxt) });
                        cur = buf;
                        loop {
                            if !((unsafe { *cur }) as i32 != 0 as i32) {
                                current_block = 7158658067966855297;
                                break;
                            }
                            if (unsafe { *cur }) as i32 == '%' as i32
                                || (unsafe { *cur }) as i32 == '&' as i32
                                    && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 != '#' as i32
                            {
                                let mut name: *mut xmlChar = 0 as *mut xmlChar;
                                let mut tmp_0: xmlChar = unsafe { *cur };
                                let mut nameOk: i32 = 0 as i32;
                                cur = unsafe { cur.offset(1) };
                                name = xmlParseStringName(ctxt, &mut cur);
                                if !name.is_null() {
                                    nameOk = 1 as i32;
                                    (unsafe { xmlFree.expect("non-null function pointer")(
                                        name as *mut libc::c_void,
                                    ) });
                                }
                                if nameOk == 0 as i32 || (unsafe { *cur }) as i32 != ';' as i32 {
                                    xmlFatalErrMsgInt (ctxt , XML_ERR_ENTITY_CHAR_ERROR , b"EntityValue: '%c' forbidden except for entities references\n\0" as * const u8 as * const i8 , tmp_0 as i32 ,) ;
                                    current_block = 1959508989248982327;
                                    break;
                                } else if tmp_0 as i32 == '%' as i32
                                    && (unsafe { (*ctxt).inSubset }) == 1 as i32
                                    && (unsafe { (*ctxt).inputNr }) == 1 as i32
                                {
                                    xmlFatalErr(ctxt, XML_ERR_ENTITY_PE_INTERNAL, 0 as *const i8);
                                    current_block = 1959508989248982327;
                                    break;
                                } else if (unsafe { *cur }) as i32 == 0 as i32 {
                                    current_block = 7158658067966855297;
                                    break;
                                }
                            }
                            cur = unsafe { cur.offset(1) };
                        }
                        match current_block {
                            1959508989248982327 => {}
                            _ => {
                                let fresh158 = unsafe { &mut ((*ctxt).depth) };
                                *fresh158 += 1;
                                ret = xmlStringDecodeEntities(
                                    ctxt,
                                    buf,
                                    2 as i32,
                                    0 as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                );
                                let fresh159 = unsafe { &mut ((*ctxt).depth) };
                                *fresh159 -= 1;
                                if !orig.is_null() {
                                    (unsafe { *orig = buf });
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
        (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    }
    return ret;
}
extern "C" fn xmlParseAttValueComplex(
    mut ctxt: xmlParserCtxtPtr,
    mut attlen: *mut i32,
    mut normalize: i32,
) -> *mut xmlChar {
    let mut current_block: u64;
    let mut limit: xmlChar = 0 as i32 as xmlChar;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut rep: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: size_t = 0 as i32 as size_t;
    let mut buf_size: size_t = 0 as i32 as size_t;
    let mut c: i32 = 0;
    let mut l: i32 = 0;
    let mut in_space: i32 = 0 as i32;
    let mut current: *mut xmlChar = 0 as *mut xmlChar;
    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
    if (unsafe { *((*(*ctxt).input).cur).offset(0 as i32 as isize) }) as i32 == '"' as i32 {
        (unsafe { (*ctxt).instate = XML_PARSER_ATTRIBUTE_VALUE });
        limit = '"' as i32 as xmlChar;
        (unsafe { xmlNextChar(ctxt) });
    } else if (unsafe { *((*(*ctxt).input).cur).offset(0 as i32 as isize) }) as i32 == '\'' as i32 {
        limit = '\'' as i32 as xmlChar;
        (unsafe { (*ctxt).instate = XML_PARSER_ATTRIBUTE_VALUE });
        (unsafe { xmlNextChar(ctxt) });
    } else {
        xmlFatalErr(ctxt, XML_ERR_ATTRIBUTE_NOT_STARTED, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    buf_size = 100 as i32 as size_t;
    buf = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(buf_size) }) as *mut xmlChar;
    if buf.is_null() {
        current_block = 4728557498262148097;
    } else {
        c = unsafe { xmlCurrentChar(ctxt, &mut l) };
        's_99: loop {
            if !((unsafe { *((*(*ctxt).input).cur).offset(0 as i32 as isize) }) as i32 != limit as i32
                && (if c < 0x100 as i32 {
                    (0x9 as i32 <= c && c <= 0xa as i32 || c == 0xd as i32 || 0x20 as i32 <= c)
                        as i32
                } else {
                    (0x100 as i32 <= c && c <= 0xd7ff as i32
                        || 0xe000 as i32 <= c && c <= 0xfffd as i32
                        || 0x10000 as i32 <= c && c <= 0x10ffff as i32) as i32
                }) != 0
                && c != '<' as i32
                && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32)
            {
                current_block = 3166194604430448652;
                break;
            }
            if len > 10000000 as i32 as u64 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
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
                    if (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '#' as i32 {
                        let mut val: i32 = xmlParseCharRef(ctxt);
                        if val == '&' as i32 {
                            if (unsafe { (*ctxt).replaceEntities }) != 0 {
                                if len.wrapping_add(10 as i32 as u64) > buf_size {
                                    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                                    let mut new_size: size_t = buf_size
                                        .wrapping_mul(2 as i32 as u64)
                                        .wrapping_add(10 as i32 as u64);
                                    if new_size < buf_size {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                                        buf as *mut libc::c_void,
                                        new_size,
                                    ) }) as *mut xmlChar;
                                    if tmp.is_null() {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    buf = tmp;
                                    buf_size = new_size;
                                }
                                let fresh160 = len;
                                len = len.wrapping_add(1);
                                (unsafe { *buf.offset(fresh160 as isize) = '&' as i32 as xmlChar });
                            } else {
                                if len.wrapping_add(10 as i32 as u64) > buf_size {
                                    let mut tmp_0: *mut xmlChar = 0 as *mut xmlChar;
                                    let mut new_size_0: size_t = buf_size
                                        .wrapping_mul(2 as i32 as u64)
                                        .wrapping_add(10 as i32 as u64);
                                    if new_size_0 < buf_size {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    tmp_0 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                                        buf as *mut libc::c_void,
                                        new_size_0,
                                    ) }) as *mut xmlChar;
                                    if tmp_0.is_null() {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    buf = tmp_0;
                                    buf_size = new_size_0;
                                }
                                let fresh161 = len;
                                len = len.wrapping_add(1);
                                (unsafe { *buf.offset(fresh161 as isize) = '&' as i32 as xmlChar });
                                let fresh162 = len;
                                len = len.wrapping_add(1);
                                (unsafe { *buf.offset(fresh162 as isize) = '#' as i32 as xmlChar });
                                let fresh163 = len;
                                len = len.wrapping_add(1);
                                (unsafe { *buf.offset(fresh163 as isize) = '3' as i32 as xmlChar });
                                let fresh164 = len;
                                len = len.wrapping_add(1);
                                (unsafe { *buf.offset(fresh164 as isize) = '8' as i32 as xmlChar });
                                let fresh165 = len;
                                len = len.wrapping_add(1);
                                (unsafe { *buf.offset(fresh165 as isize) = ';' as i32 as xmlChar });
                            }
                        } else if val != 0 as i32 {
                            if len.wrapping_add(10 as i32 as u64) > buf_size {
                                let mut tmp_1: *mut xmlChar = 0 as *mut xmlChar;
                                let mut new_size_1: size_t = buf_size
                                    .wrapping_mul(2 as i32 as u64)
                                    .wrapping_add(10 as i32 as u64);
                                if new_size_1 < buf_size {
                                    current_block = 4728557498262148097;
                                    break;
                                }
                                tmp_1 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                                    buf as *mut libc::c_void,
                                    new_size_1,
                                ) }) as *mut xmlChar;
                                if tmp_1.is_null() {
                                    current_block = 4728557498262148097;
                                    break;
                                }
                                buf = tmp_1;
                                buf_size = new_size_1;
                            }
                            len = (len as u64).wrapping_add((unsafe { xmlCopyChar(
                                0 as i32,
                                &mut *buf.offset(len as isize),
                                val,
                            ) }) as u64) as size_t as size_t;
                        }
                    } else {
                        ent = xmlParseEntityRef(ctxt);
                        let fresh166 = unsafe { &mut ((*ctxt).nbentities) };
                        *fresh166 = (*fresh166).wrapping_add(1);
                        if !ent.is_null() {
                            let fresh167 = unsafe { &mut ((*ctxt).nbentities) };
                            *fresh167 = (*fresh167).wrapping_add((unsafe { (*ent).owner }) as u64);
                        }
                        if !ent.is_null()
                            && (unsafe { (*ent).etype }) as u32 == XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
                        {
                            if len.wrapping_add(10 as i32 as u64) > buf_size {
                                let mut tmp_2: *mut xmlChar = 0 as *mut xmlChar;
                                let mut new_size_2: size_t = buf_size
                                    .wrapping_mul(2 as i32 as u64)
                                    .wrapping_add(10 as i32 as u64);
                                if new_size_2 < buf_size {
                                    current_block = 4728557498262148097;
                                    break;
                                }
                                tmp_2 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                                    buf as *mut libc::c_void,
                                    new_size_2,
                                ) }) as *mut xmlChar;
                                if tmp_2.is_null() {
                                    current_block = 4728557498262148097;
                                    break;
                                }
                                buf = tmp_2;
                                buf_size = new_size_2;
                            }
                            if (unsafe { (*ctxt).replaceEntities }) == 0 as i32
                                && (unsafe { *((*ent).content).offset(0 as i32 as isize) }) as i32 == '&' as i32
                            {
                                let fresh168 = len;
                                len = len.wrapping_add(1);
                                (unsafe { *buf.offset(fresh168 as isize) = '&' as i32 as xmlChar });
                                let fresh169 = len;
                                len = len.wrapping_add(1);
                                (unsafe { *buf.offset(fresh169 as isize) = '#' as i32 as xmlChar });
                                let fresh170 = len;
                                len = len.wrapping_add(1);
                                (unsafe { *buf.offset(fresh170 as isize) = '3' as i32 as xmlChar });
                                let fresh171 = len;
                                len = len.wrapping_add(1);
                                (unsafe { *buf.offset(fresh171 as isize) = '8' as i32 as xmlChar });
                                let fresh172 = len;
                                len = len.wrapping_add(1);
                                (unsafe { *buf.offset(fresh172 as isize) = ';' as i32 as xmlChar });
                            } else {
                                let fresh173 = len;
                                len = len.wrapping_add(1);
                                (unsafe { *buf.offset(fresh173 as isize) =
                                    *((*ent).content).offset(0 as i32 as isize) });
                            }
                        } else if !ent.is_null() && (unsafe { (*ctxt).replaceEntities }) != 0 as i32 {
                            if (unsafe { (*ent).etype }) as u32 != XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32 {
                                let fresh174 = unsafe { &mut ((*ctxt).depth) };
                                *fresh174 += 1;
                                rep = xmlStringDecodeEntities(
                                    ctxt,
                                    unsafe { (*ent).content },
                                    1 as i32,
                                    0 as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                );
                                let fresh175 = unsafe { &mut ((*ctxt).depth) };
                                *fresh175 -= 1;
                                if !rep.is_null() {
                                    current = rep;
                                    while (unsafe { *current }) as i32 != 0 as i32 {
                                        if (unsafe { *current }) as i32 == 0xd as i32
                                            || (unsafe { *current }) as i32 == 0xa as i32
                                            || (unsafe { *current }) as i32 == 0x9 as i32
                                        {
                                            let fresh176 = len;
                                            len = len.wrapping_add(1);
                                            (unsafe { *buf.offset(fresh176 as isize) = 0x20 as i32 as xmlChar });
                                            current = unsafe { current.offset(1) };
                                        } else {
                                            let fresh177 = current;
                                            current = unsafe { current.offset(1) };
                                            let fresh178 = len;
                                            len = len.wrapping_add(1);
                                            (unsafe { *buf.offset(fresh178 as isize) = *fresh177 });
                                        }
                                        if !(len.wrapping_add(10 as i32 as u64) > buf_size) {
                                            continue;
                                        }
                                        let mut tmp_3: *mut xmlChar = 0 as *mut xmlChar;
                                        let mut new_size_3: size_t = buf_size
                                            .wrapping_mul(2 as i32 as u64)
                                            .wrapping_add(10 as i32 as u64);
                                        if new_size_3 < buf_size {
                                            current_block = 4728557498262148097;
                                            break 's_99;
                                        }
                                        tmp_3 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                                            buf as *mut libc::c_void,
                                            new_size_3,
                                        ) })
                                            as *mut xmlChar;
                                        if tmp_3.is_null() {
                                            current_block = 4728557498262148097;
                                            break 's_99;
                                        }
                                        buf = tmp_3;
                                        buf_size = new_size_3;
                                    }
                                    (unsafe { xmlFree.expect("non-null function pointer")(
                                        rep as *mut libc::c_void,
                                    ) });
                                    rep = 0 as *mut xmlChar;
                                }
                            } else {
                                if len.wrapping_add(10 as i32 as u64) > buf_size {
                                    let mut tmp_4: *mut xmlChar = 0 as *mut xmlChar;
                                    let mut new_size_4: size_t = buf_size
                                        .wrapping_mul(2 as i32 as u64)
                                        .wrapping_add(10 as i32 as u64);
                                    if new_size_4 < buf_size {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    tmp_4 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                                        buf as *mut libc::c_void,
                                        new_size_4,
                                    ) }) as *mut xmlChar;
                                    if tmp_4.is_null() {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    buf = tmp_4;
                                    buf_size = new_size_4;
                                }
                                if !(unsafe { (*ent).content }).is_null() {
                                    let fresh179 = len;
                                    len = len.wrapping_add(1);
                                    (unsafe { *buf.offset(fresh179 as isize) =
                                        *((*ent).content).offset(0 as i32 as isize) });
                                }
                            }
                        } else if !ent.is_null() {
                            let mut i: i32 = unsafe { xmlStrlen((*ent).name) };
                            let mut cur: *const xmlChar = unsafe { (*ent).name };
                            if (unsafe { (*ent).etype }) as u32 != XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
                                && !(unsafe { (*ent).content }).is_null()
                                && (unsafe { (*ent).checked }) == 0 as i32
                            {
                                let mut oldnbent: u64 = unsafe { (*ctxt).nbentities };
                                let mut diff: u64 = 0;
                                let fresh180 = unsafe { &mut ((*ctxt).depth) };
                                *fresh180 += 1;
                                rep = xmlStringDecodeEntities(
                                    ctxt,
                                    unsafe { (*ent).content },
                                    1 as i32,
                                    0 as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                    0 as i32 as xmlChar,
                                );
                                let fresh181 = unsafe { &mut ((*ctxt).depth) };
                                *fresh181 -= 1;
                                diff = (unsafe { (*ctxt).nbentities })
                                    .wrapping_sub(oldnbent)
                                    .wrapping_add(1 as i32 as u64);
                                if diff > (2147483647 as i32 / 2 as i32) as u64 {
                                    diff = (2147483647 as i32 / 2 as i32) as u64;
                                }
                                (unsafe { (*ent).checked = diff.wrapping_mul(2 as i32 as u64) as i32 });
                                if !rep.is_null() {
                                    if !(unsafe { xmlStrchr(rep, '<' as i32 as xmlChar) }).is_null() {
                                        (unsafe { (*ent).checked |= 1 as i32 });
                                    }
                                    (unsafe { xmlFree.expect("non-null function pointer")(
                                        rep as *mut libc::c_void,
                                    ) });
                                    rep = 0 as *mut xmlChar;
                                } else {
                                    (unsafe { *((*ent).content).offset(0 as i32 as isize) =
                                        0 as i32 as xmlChar });
                                }
                            }
                            let fresh182 = len;
                            len = len.wrapping_add(1);
                            (unsafe { *buf.offset(fresh182 as isize) = '&' as i32 as xmlChar });
                            while len.wrapping_add(i as u64).wrapping_add(10 as i32 as u64)
                                > buf_size
                            {
                                let mut tmp_5: *mut xmlChar = 0 as *mut xmlChar;
                                let mut new_size_5: size_t = buf_size
                                    .wrapping_mul(2 as i32 as u64)
                                    .wrapping_add(i as u64)
                                    .wrapping_add(10 as i32 as u64);
                                if new_size_5 < buf_size {
                                    current_block = 4728557498262148097;
                                    break 's_99;
                                }
                                tmp_5 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                                    buf as *mut libc::c_void,
                                    new_size_5,
                                ) }) as *mut xmlChar;
                                if tmp_5.is_null() {
                                    current_block = 4728557498262148097;
                                    break 's_99;
                                }
                                buf = tmp_5;
                                buf_size = new_size_5;
                            }
                            while i > 0 as i32 {
                                let fresh183 = cur;
                                cur = unsafe { cur.offset(1) };
                                let fresh184 = len;
                                len = len.wrapping_add(1);
                                (unsafe { *buf.offset(fresh184 as isize) = *fresh183 });
                                i -= 1;
                            }
                            let fresh185 = len;
                            len = len.wrapping_add(1);
                            (unsafe { *buf.offset(fresh185 as isize) = ';' as i32 as xmlChar });
                        }
                    }
                } else {
                    if c == 0x20 as i32 || c == 0xd as i32 || c == 0xa as i32 || c == 0x9 as i32 {
                        if len != 0 as i32 as u64 || normalize == 0 {
                            if normalize == 0 || in_space == 0 {
                                if l == 1 as i32 {
                                    let fresh186 = len;
                                    len = len.wrapping_add(1);
                                    (unsafe { *buf.offset(fresh186 as isize) = 0x20 as i32 as xmlChar });
                                } else {
                                    len = (len as u64).wrapping_add((unsafe { xmlCopyCharMultiByte(
                                        &mut *buf.offset(len as isize),
                                        0x20 as i32,
                                    ) })
                                        as u64) as size_t
                                        as size_t;
                                }
                                while len.wrapping_add(10 as i32 as u64) > buf_size {
                                    let mut tmp_6: *mut xmlChar = 0 as *mut xmlChar;
                                    let mut new_size_6: size_t = buf_size
                                        .wrapping_mul(2 as i32 as u64)
                                        .wrapping_add(10 as i32 as u64);
                                    if new_size_6 < buf_size {
                                        current_block = 4728557498262148097;
                                        break 's_99;
                                    }
                                    tmp_6 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                                        buf as *mut libc::c_void,
                                        new_size_6,
                                    ) }) as *mut xmlChar;
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
                            let fresh187 = len;
                            len = len.wrapping_add(1);
                            (unsafe { *buf.offset(fresh187 as isize) = c as xmlChar });
                        } else {
                            len = (len as u64).wrapping_add((unsafe { xmlCopyCharMultiByte(
                                &mut *buf.offset(len as isize),
                                c,
                            ) }) as u64) as size_t as size_t;
                        }
                        if len.wrapping_add(10 as i32 as u64) > buf_size {
                            let mut tmp_7: *mut xmlChar = 0 as *mut xmlChar;
                            let mut new_size_7: size_t = buf_size
                                .wrapping_mul(2 as i32 as u64)
                                .wrapping_add(10 as i32 as u64);
                            if new_size_7 < buf_size {
                                current_block = 4728557498262148097;
                                break;
                            }
                            tmp_7 = (unsafe { xmlRealloc.expect("non-null function pointer")(
                                buf as *mut libc::c_void,
                                new_size_7,
                            ) }) as *mut xmlChar;
                            if tmp_7.is_null() {
                                current_block = 4728557498262148097;
                                break;
                            }
                            buf = tmp_7;
                            buf_size = new_size_7;
                        }
                    }
                    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
                        let fresh188 = unsafe { &mut ((*(*ctxt).input).line) };
                        *fresh188 += 1;
                        (unsafe { (*(*ctxt).input).col = 1 as i32 });
                    } else {
                        let fresh189 = unsafe { &mut ((*(*ctxt).input).col) };
                        *fresh189 += 1;
                    }
                    let fresh190 = unsafe { &mut ((*(*ctxt).input).cur) };
                    *fresh190 = unsafe { (*fresh190).offset(l as isize) };
                }
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                c = unsafe { xmlCurrentChar(ctxt, &mut l) };
            }
        }
        match current_block {
            4728557498262148097 => {}
            _ => {
                if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                    current_block = 7833996145497313433;
                } else {
                    if in_space != 0 && normalize != 0 {
                        while len > 0 as i32 as u64
                            && (unsafe { *buf.offset(len.wrapping_sub(1 as i32 as u64) as isize) }) as i32
                                == 0x20 as i32
                        {
                            len = len.wrapping_sub(1);
                        }
                    }
                    (unsafe { *buf.offset(len as isize) = 0 as i32 as xmlChar });
                    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32 {
                        xmlFatalErr(ctxt, XML_ERR_LT_IN_ATTRIBUTE, 0 as *const i8);
                    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 != limit as i32 {
                        if c != 0 as i32
                            && (if c < 0x100 as i32 {
                                (0x9 as i32 <= c && c <= 0xa as i32
                                    || c == 0xd as i32
                                    || 0x20 as i32 <= c) as i32
                            } else {
                                (0x100 as i32 <= c && c <= 0xd7ff as i32
                                    || 0xe000 as i32 <= c && c <= 0xfffd as i32
                                    || 0x10000 as i32 <= c && c <= 0x10ffff as i32)
                                    as i32
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
                                b"AttValue: ' expected\n\0" as *const u8 as *const i8,
                            );
                        }
                    } else {
                        (unsafe { xmlNextChar(ctxt) });
                    }
                    if len >= 2147483647 as i32 as u64 {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_ATTRIBUTE_NOT_FINISHED,
                            b"AttValue length too long\n\0" as *const u8 as *const i8,
                        );
                    } else {
                        if !attlen.is_null() {
                            (unsafe { *attlen = len as i32 });
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
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
        }
        _ => {}
    }
    if !buf.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    }
    if !rep.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(rep as *mut libc::c_void) });
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlParseAttValue(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    if ctxt.is_null() || (unsafe { (*ctxt).input }).is_null() {
        return 0 as *mut xmlChar;
    }
    return xmlParseAttValueInternal(ctxt, 0 as *mut i32, 0 as *mut i32, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlParseSystemLiteral(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 100 as i32;
    let mut cur: i32 = 0;
    let mut l: i32 = 0;
    let mut stop: xmlChar = 0;
    let mut state: i32 = (unsafe { (*ctxt).instate }) as i32;
    let mut count: i32 = 0 as i32;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
            > (2 as i32 * 250 as i32) as i64
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '"' as i32 {
        (unsafe { xmlNextChar(ctxt) });
        stop = '"' as i32 as xmlChar;
    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\'' as i32 {
        (unsafe { xmlNextChar(ctxt) });
        stop = '\'' as i32 as xmlChar;
    } else {
        xmlFatalErr(ctxt, XML_ERR_LITERAL_NOT_STARTED, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    buf = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
        (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) }) as *mut xmlChar;
    if buf.is_null() {
        (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
        return 0 as *mut xmlChar;
    }
    (unsafe { (*ctxt).instate = XML_PARSER_SYSTEM_LITERAL });
    cur = unsafe { xmlCurrentChar(ctxt, &mut l) };
    while (if cur < 0x100 as i32 {
        (0x9 as i32 <= cur && cur <= 0xa as i32 || cur == 0xd as i32 || 0x20 as i32 <= cur) as i32
    } else {
        (0x100 as i32 <= cur && cur <= 0xd7ff as i32
            || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
            || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32) as i32
    }) != 0
        && cur != stop as i32
    {
        if len + 5 as i32 >= size {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            if size > 50000 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_NAME_TOO_LONG,
                    b"SystemLiteral\0" as *const u8 as *const i8,
                );
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                (unsafe { (*ctxt).instate = state as xmlParserInputState });
                return 0 as *mut xmlChar;
            }
            size *= 2 as i32;
            tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                buf as *mut libc::c_void,
                (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) }) as *mut xmlChar;
            if tmp.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                (unsafe { (*ctxt).instate = state as xmlParserInputState });
                return 0 as *mut xmlChar;
            }
            buf = tmp;
        }
        count += 1;
        if count > 50 as i32 {
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                    > (2 as i32 * 250 as i32) as i64
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            count = 0 as i32;
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                return 0 as *mut xmlChar;
            }
        }
        if l == 1 as i32 {
            let fresh191 = len;
            len = len + 1;
            (unsafe { *buf.offset(fresh191 as isize) = cur as xmlChar });
        } else {
            len += unsafe { xmlCopyCharMultiByte(&mut *buf.offset(len as isize), cur) };
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
            let fresh192 = unsafe { &mut ((*(*ctxt).input).line) };
            *fresh192 += 1;
            (unsafe { (*(*ctxt).input).col = 1 as i32 });
        } else {
            let fresh193 = unsafe { &mut ((*(*ctxt).input).col) };
            *fresh193 += 1;
        }
        let fresh194 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh194 = unsafe { (*fresh194).offset(l as isize) };
        cur = unsafe { xmlCurrentChar(ctxt, &mut l) };
        if cur == 0 as i32 {
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                    > (2 as i32 * 250 as i32) as i64
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            cur = unsafe { xmlCurrentChar(ctxt, &mut l) };
        }
    }
    (unsafe { *buf.offset(len as isize) = 0 as i32 as xmlChar });
    (unsafe { (*ctxt).instate = state as xmlParserInputState });
    if if cur < 0x100 as i32 {
        (0x9 as i32 <= cur && cur <= 0xa as i32 || cur == 0xd as i32 || 0x20 as i32 <= cur) as i32
    } else {
        (0x100 as i32 <= cur && cur <= 0xd7ff as i32
            || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
            || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32) as i32
    } == 0
    {
        xmlFatalErr(ctxt, XML_ERR_LITERAL_NOT_FINISHED, 0 as *const i8);
    } else {
        (unsafe { xmlNextChar(ctxt) });
    }
    return buf;
}
#[no_mangle]
pub extern "C" fn xmlParsePubidLiteral(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 100 as i32;
    let mut cur: xmlChar = 0;
    let mut stop: xmlChar = 0;
    let mut count: i32 = 0 as i32;
    let mut oldstate: xmlParserInputState = unsafe { (*ctxt).instate };
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
            > (2 as i32 * 250 as i32) as i64
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '"' as i32 {
        (unsafe { xmlNextChar(ctxt) });
        stop = '"' as i32 as xmlChar;
    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\'' as i32 {
        (unsafe { xmlNextChar(ctxt) });
        stop = '\'' as i32 as xmlChar;
    } else {
        xmlFatalErr(ctxt, XML_ERR_LITERAL_NOT_STARTED, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    buf = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
        (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) }) as *mut xmlChar;
    if buf.is_null() {
        (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
        return 0 as *mut xmlChar;
    }
    (unsafe { (*ctxt).instate = XML_PARSER_PUBLIC_LITERAL });
    cur = unsafe { *(*(*ctxt).input).cur };
    while (unsafe { xmlIsPubidChar_tab[cur as usize] }) as i32 != 0 && cur as i32 != stop as i32 {
        if len + 1 as i32 >= size {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            if size > 50000 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_NAME_TOO_LONG,
                    b"Public ID\0" as *const u8 as *const i8,
                );
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                return 0 as *mut xmlChar;
            }
            size *= 2 as i32;
            tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                buf as *mut libc::c_void,
                (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) }) as *mut xmlChar;
            if tmp.is_null() {
                (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                return 0 as *mut xmlChar;
            }
            buf = tmp;
        }
        let fresh195 = len;
        len = len + 1;
        (unsafe { *buf.offset(fresh195 as isize) = cur });
        count += 1;
        if count > 50 as i32 {
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                    > (2 as i32 * 250 as i32) as i64
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            count = 0 as i32;
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                return 0 as *mut xmlChar;
            }
        }
        (unsafe { xmlNextChar(ctxt) });
        cur = unsafe { *(*(*ctxt).input).cur };
        if cur as i32 == 0 as i32 {
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                    > (2 as i32 * 250 as i32) as i64
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            cur = unsafe { *(*(*ctxt).input).cur };
        }
    }
    (unsafe { *buf.offset(len as isize) = 0 as i32 as xmlChar });
    if cur as i32 != stop as i32 {
        xmlFatalErr(ctxt, XML_ERR_LITERAL_NOT_FINISHED, 0 as *const i8);
    } else {
        (unsafe { xmlNextChar(ctxt) });
    }
    (unsafe { (*ctxt).instate = oldstate });
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
pub extern "C" fn xmlParseCharData(mut ctxt: xmlParserCtxtPtr, mut cdata: i32) {
    let mut current_block: u64;
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut nbchar: i32 = 0 as i32;
    let mut line: i32 = unsafe { (*(*ctxt).input).line };
    let mut col: i32 = unsafe { (*(*ctxt).input).col };
    let mut ccol: i32 = 0;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
            > (2 as i32 * 250 as i32) as i64
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if cdata == 0 {
        in_0 = unsafe { (*(*ctxt).input).cur };
        loop {
            while (unsafe { *in_0 }) as i32 == 0x20 as i32 {
                in_0 = unsafe { in_0.offset(1) };
                let fresh196 = unsafe { &mut ((*(*ctxt).input).col) };
                *fresh196 += 1;
            }
            if (unsafe { *in_0 }) as i32 == 0xa as i32 {
                loop {
                    let fresh197 = unsafe { &mut ((*(*ctxt).input).line) };
                    *fresh197 += 1;
                    (unsafe { (*(*ctxt).input).col = 1 as i32 });
                    in_0 = unsafe { in_0.offset(1) };
                    if !((unsafe { *in_0 }) as i32 == 0xa as i32) {
                        break;
                    }
                }
            } else {
                if (unsafe { *in_0 }) as i32 == '<' as i32 {
                    nbchar = (unsafe { in_0.offset_from((*(*ctxt).input).cur) }) as i64 as i32;
                    if nbchar > 0 as i32 {
                        let mut tmp: *const xmlChar = unsafe { (*(*ctxt).input).cur };
                        let fresh198 = unsafe { &mut ((*(*ctxt).input).cur) };
                        *fresh198 = in_0;
                        if !(unsafe { (*ctxt).sax }).is_null()
                            && (unsafe { (*(*ctxt).sax).ignorableWhitespace }) != (unsafe { (*(*ctxt).sax).characters })
                        {
                            if areBlanks(ctxt, tmp, nbchar, 1 as i32) != 0 {
                                if unsafe { ((*(*ctxt).sax).ignorableWhitespace).is_some() } {
                                    (unsafe { ((*(*ctxt).sax).ignorableWhitespace)
                                        .expect("non-null function pointer")(
                                        (*ctxt).userData,
                                        tmp,
                                        nbchar,
                                    ) });
                                }
                            } else {
                                if unsafe { ((*(*ctxt).sax).characters).is_some() } {
                                    (unsafe { ((*(*ctxt).sax).characters).expect("non-null function pointer")(
                                        (*ctxt).userData,
                                        tmp,
                                        nbchar,
                                    ) });
                                }
                                if (unsafe { *(*ctxt).space }) == -(1 as i32) {
                                    (unsafe { *(*ctxt).space = -(2 as i32) });
                                }
                            }
                        } else if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).characters).is_some() })
                        {
                            (unsafe { ((*(*ctxt).sax).characters).expect("non-null function pointer")(
                                (*ctxt).userData,
                                tmp,
                                nbchar,
                            ) });
                        }
                    }
                    return;
                }
                loop {
                    ccol = unsafe { (*(*ctxt).input).col };
                    while (unsafe { test_char_data[*in_0 as usize] }) != 0 {
                        in_0 = unsafe { in_0.offset(1) };
                        ccol += 1;
                    }
                    (unsafe { (*(*ctxt).input).col = ccol });
                    if (unsafe { *in_0 }) as i32 == 0xa as i32 {
                        loop {
                            let fresh199 = unsafe { &mut ((*(*ctxt).input).line) };
                            *fresh199 += 1;
                            (unsafe { (*(*ctxt).input).col = 1 as i32 });
                            in_0 = unsafe { in_0.offset(1) };
                            if !((unsafe { *in_0 }) as i32 == 0xa as i32) {
                                break;
                            }
                        }
                    } else {
                        if !((unsafe { *in_0 }) as i32 == ']' as i32) {
                            break;
                        }
                        if (unsafe { *in_0.offset(1 as i32 as isize) }) as i32 == ']' as i32
                            && (unsafe { *in_0.offset(2 as i32 as isize) }) as i32 == '>' as i32
                        {
                            xmlFatalErr(ctxt, XML_ERR_MISPLACED_CDATA_END, 0 as *const i8);
                            let fresh200 = unsafe { &mut ((*(*ctxt).input).cur) };
                            *fresh200 = unsafe { in_0.offset(1 as i32 as isize) };
                            return;
                        }
                        in_0 = unsafe { in_0.offset(1) };
                        let fresh201 = unsafe { &mut ((*(*ctxt).input).col) };
                        *fresh201 += 1;
                    }
                }
                nbchar = (unsafe { in_0.offset_from((*(*ctxt).input).cur) }) as i64 as i32;
                if nbchar > 0 as i32 {
                    if !(unsafe { (*ctxt).sax }).is_null()
                        && (unsafe { (*(*ctxt).sax).ignorableWhitespace }) != (unsafe { (*(*ctxt).sax).characters })
                        && ((unsafe { *(*(*ctxt).input).cur }) as i32 == 0x20 as i32
                            || 0x9 as i32 <= (unsafe { *(*(*ctxt).input).cur }) as i32
                                && (unsafe { *(*(*ctxt).input).cur }) as i32 <= 0xa as i32
                            || (unsafe { *(*(*ctxt).input).cur }) as i32 == 0xd as i32)
                    {
                        let mut tmp_0: *const xmlChar = unsafe { (*(*ctxt).input).cur };
                        let fresh202 = unsafe { &mut ((*(*ctxt).input).cur) };
                        *fresh202 = in_0;
                        if areBlanks(ctxt, tmp_0, nbchar, 0 as i32) != 0 {
                            if unsafe { ((*(*ctxt).sax).ignorableWhitespace).is_some() } {
                                (unsafe { ((*(*ctxt).sax).ignorableWhitespace)
                                    .expect("non-null function pointer")(
                                    (*ctxt).userData,
                                    tmp_0,
                                    nbchar,
                                ) });
                            }
                        } else {
                            if unsafe { ((*(*ctxt).sax).characters).is_some() } {
                                (unsafe { ((*(*ctxt).sax).characters).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                    tmp_0,
                                    nbchar,
                                ) });
                            }
                            if (unsafe { *(*ctxt).space }) == -(1 as i32) {
                                (unsafe { *(*ctxt).space = -(2 as i32) });
                            }
                        }
                        line = unsafe { (*(*ctxt).input).line };
                        col = unsafe { (*(*ctxt).input).col };
                    } else if !(unsafe { (*ctxt).sax }).is_null() {
                        if unsafe { ((*(*ctxt).sax).characters).is_some() } {
                            (unsafe { ((*(*ctxt).sax).characters).expect("non-null function pointer")(
                                (*ctxt).userData,
                                (*(*ctxt).input).cur,
                                nbchar,
                            ) });
                        }
                        line = unsafe { (*(*ctxt).input).line };
                        col = unsafe { (*(*ctxt).input).col };
                    }
                    if (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_CONTENT as i32 {
                        return;
                    }
                }
                let fresh203 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh203 = in_0;
                if (unsafe { *in_0 }) as i32 == 0xd as i32 {
                    in_0 = unsafe { in_0.offset(1) };
                    if (unsafe { *in_0 }) as i32 == 0xa as i32 {
                        let fresh204 = unsafe { &mut ((*(*ctxt).input).cur) };
                        *fresh204 = in_0;
                        in_0 = unsafe { in_0.offset(1) };
                        let fresh205 = unsafe { &mut ((*(*ctxt).input).line) };
                        *fresh205 += 1;
                        (unsafe { (*(*ctxt).input).col = 1 as i32 });
                        current_block = 1917311967535052937;
                    } else {
                        in_0 = unsafe { in_0.offset(-1) };
                        current_block = 17769492591016358583;
                    }
                } else {
                    current_block = 17769492591016358583;
                }
                match current_block {
                    17769492591016358583 => {
                        if (unsafe { *in_0 }) as i32 == '<' as i32 {
                            return;
                        }
                        if (unsafe { *in_0 }) as i32 == '&' as i32 {
                            return;
                        }
                        if (unsafe { (*ctxt).progressive }) == 0 as i32
                            && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                                > (2 as i32 * 250 as i32) as i64
                            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                                < (2 as i32 * 250 as i32) as i64
                        {
                            xmlSHRINK(ctxt);
                        }
                        if (unsafe { (*ctxt).progressive }) == 0 as i32
                            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                                < 250 as i32 as i64
                        {
                            xmlGROW(ctxt);
                        }
                        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                            return;
                        }
                        in_0 = unsafe { (*(*ctxt).input).cur };
                    }
                    _ => {}
                }
                if !((unsafe { *in_0 }) as i32 >= 0x20 as i32 && (unsafe { *in_0 }) as i32 <= 0x7f as i32
                    || (unsafe { *in_0 }) as i32 == 0x9 as i32
                    || (unsafe { *in_0 }) as i32 == 0xa as i32)
                {
                    break;
                }
            }
        }
        nbchar = 0 as i32;
    }
    (unsafe { (*(*ctxt).input).line = line });
    (unsafe { (*(*ctxt).input).col = col });
    xmlParseCharDataComplex(ctxt, cdata);
}
extern "C" fn xmlParseCharDataComplex(mut ctxt: xmlParserCtxtPtr, mut cdata: i32) {
    let mut buf: [xmlChar; 305] = [0; 305];
    let mut nbchar: i32 = 0 as i32;
    let mut cur: i32 = 0;
    let mut l: i32 = 0;
    let mut count: i32 = 0 as i32;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
            > (2 as i32 * 250 as i32) as i64
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    cur = unsafe { xmlCurrentChar(ctxt, &mut l) };
    while cur != '<' as i32
        && cur != '&' as i32
        && (if cur < 0x100 as i32 {
            (0x9 as i32 <= cur && cur <= 0xa as i32 || cur == 0xd as i32 || 0x20 as i32 <= cur)
                as i32
        } else {
            (0x100 as i32 <= cur && cur <= 0xd7ff as i32
                || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
                || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32) as i32
        }) != 0
    {
        if cur == ']' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == ']' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == '>' as i32
        {
            if cdata != 0 {
                break;
            }
            xmlFatalErr(ctxt, XML_ERR_MISPLACED_CDATA_END, 0 as *const i8);
        }
        if l == 1 as i32 {
            let fresh206 = nbchar;
            nbchar = nbchar + 1;
            buf[fresh206 as usize] = cur as xmlChar;
        } else {
            nbchar += unsafe { xmlCopyCharMultiByte(&mut *buf.as_mut_ptr().offset(nbchar as isize), cur) };
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
            let fresh207 = unsafe { &mut ((*(*ctxt).input).line) };
            *fresh207 += 1;
            (unsafe { (*(*ctxt).input).col = 1 as i32 });
        } else {
            let fresh208 = unsafe { &mut ((*(*ctxt).input).col) };
            *fresh208 += 1;
        }
        let fresh209 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh209 = unsafe { (*fresh209).offset(l as isize) };
        cur = unsafe { xmlCurrentChar(ctxt, &mut l) };
        if nbchar >= 300 as i32 {
            buf[nbchar as usize] = 0 as i32 as xmlChar;
            if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { (*ctxt).disableSAX }) == 0 {
                if areBlanks(ctxt, buf.as_mut_ptr(), nbchar, 0 as i32) != 0 {
                    if unsafe { ((*(*ctxt).sax).ignorableWhitespace).is_some() } {
                        (unsafe { ((*(*ctxt).sax).ignorableWhitespace).expect("non-null function pointer")(
                            (*ctxt).userData,
                            buf.as_mut_ptr(),
                            nbchar,
                        ) });
                    }
                } else {
                    if unsafe { ((*(*ctxt).sax).characters).is_some() } {
                        (unsafe { ((*(*ctxt).sax).characters).expect("non-null function pointer")(
                            (*ctxt).userData,
                            buf.as_mut_ptr(),
                            nbchar,
                        ) });
                    }
                    if (unsafe { (*(*ctxt).sax).characters }) != (unsafe { (*(*ctxt).sax).ignorableWhitespace })
                        && (unsafe { *(*ctxt).space }) == -(1 as i32)
                    {
                        (unsafe { *(*ctxt).space = -(2 as i32) });
                    }
                }
            }
            nbchar = 0 as i32;
            if (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_CONTENT as i32 {
                return;
            }
        }
        count += 1;
        if count > 50 as i32 {
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                    > (2 as i32 * 250 as i32) as i64
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            count = 0 as i32;
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                return;
            }
        }
    }
    if nbchar != 0 as i32 {
        buf[nbchar as usize] = 0 as i32 as xmlChar;
        if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { (*ctxt).disableSAX }) == 0 {
            if areBlanks(ctxt, buf.as_mut_ptr(), nbchar, 0 as i32) != 0 {
                if unsafe { ((*(*ctxt).sax).ignorableWhitespace).is_some() } {
                    (unsafe { ((*(*ctxt).sax).ignorableWhitespace).expect("non-null function pointer")(
                        (*ctxt).userData,
                        buf.as_mut_ptr(),
                        nbchar,
                    ) });
                }
            } else {
                if unsafe { ((*(*ctxt).sax).characters).is_some() } {
                    (unsafe { ((*(*ctxt).sax).characters).expect("non-null function pointer")(
                        (*ctxt).userData,
                        buf.as_mut_ptr(),
                        nbchar,
                    ) });
                }
                if (unsafe { (*(*ctxt).sax).characters }) != (unsafe { (*(*ctxt).sax).ignorableWhitespace })
                    && (unsafe { *(*ctxt).space }) == -(1 as i32)
                {
                    (unsafe { *(*ctxt).space = -(2 as i32) });
                }
            }
        }
    }
    if cur != 0 as i32
        && (if cur < 0x100 as i32 {
            (0x9 as i32 <= cur && cur <= 0xa as i32 || cur == 0xd as i32 || 0x20 as i32 <= cur)
                as i32
        } else {
            (0x100 as i32 <= cur && cur <= 0xd7ff as i32
                || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
                || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32) as i32
        }) == 0
    {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"PCDATA invalid Char value %d\n\0" as *const u8 as *const i8,
            cur,
        );
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
            let fresh210 = unsafe { &mut ((*(*ctxt).input).line) };
            *fresh210 += 1;
            (unsafe { (*(*ctxt).input).col = 1 as i32 });
        } else {
            let fresh211 = unsafe { &mut ((*(*ctxt).input).col) };
            *fresh211 += 1;
        }
        let fresh212 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh212 = unsafe { (*fresh212).offset(l as isize) };
    }
}
#[no_mangle]
pub extern "C" fn xmlParseExternalID(
    mut ctxt: xmlParserCtxtPtr,
    mut publicID: *mut *mut xmlChar,
    mut strict: i32,
) -> *mut xmlChar {
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
            > (2 as i32 * 250 as i32) as i64
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    (unsafe { *publicID = 0 as *mut xmlChar });
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == 'S' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'Y' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'S' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'E' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'M' as i32
    {
        let fresh213 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh213 = unsafe { (*fresh213).offset(6 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 6 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
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
    } else if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == 'P' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'U' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'B' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'L' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'I' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'C' as i32
    {
        let fresh214 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh214 = unsafe { (*fresh214).offset(6 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 6 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after 'PUBLIC'\n\0" as *const u8 as *const i8,
            );
        }
        (unsafe { *publicID = xmlParsePubidLiteral(ctxt) });
        if (unsafe { *publicID }).is_null() {
            xmlFatalErr(ctxt, XML_ERR_PUBID_REQUIRED, 0 as *const i8);
        }
        if strict != 0 {
            if xmlSkipBlankChars(ctxt) == 0 as i32 {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_SPACE_REQUIRED,
                    b"Space required after the Public Identifier\n\0" as *const u8 as *const i8,
                );
            }
        } else {
            if xmlSkipBlankChars(ctxt) == 0 as i32 {
                return 0 as *mut xmlChar;
            }
            if (unsafe { *(*(*ctxt).input).cur }) as i32 != '\'' as i32
                && (unsafe { *(*(*ctxt).input).cur }) as i32 != '"' as i32
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
extern "C" fn xmlParseCommentComplex(
    mut ctxt: xmlParserCtxtPtr,
    mut buf: *mut xmlChar,
    mut len: size_t,
    mut size: size_t,
) {
    let mut q: i32 = 0;
    let mut ql: i32 = 0;
    let mut r: i32 = 0;
    let mut rl: i32 = 0;
    let mut cur: i32 = 0;
    let mut l: i32 = 0;
    let mut count: size_t = 0 as i32 as size_t;
    let mut inputid: i32 = 0;
    inputid = unsafe { (*(*ctxt).input).id };
    if buf.is_null() {
        len = 0 as i32 as size_t;
        size = 100 as i32 as size_t;
        buf = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
            size.wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        ) }) as *mut xmlChar;
        if buf.is_null() {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            return;
        }
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    q = unsafe { xmlCurrentChar(ctxt, &mut ql) };
    if !(q == 0 as i32) {
        if if q < 0x100 as i32 {
            (0x9 as i32 <= q && q <= 0xa as i32 || q == 0xd as i32 || 0x20 as i32 <= q) as i32
        } else {
            (0x100 as i32 <= q && q <= 0xd7ff as i32
                || 0xe000 as i32 <= q && q <= 0xfffd as i32
                || 0x10000 as i32 <= q && q <= 0x10ffff as i32) as i32
        } == 0
        {
            xmlFatalErrMsgInt(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"xmlParseComment: invalid xmlChar value %d\n\0" as *const u8 as *const i8,
                q,
            );
            (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
            return;
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
            let fresh215 = unsafe { &mut ((*(*ctxt).input).line) };
            *fresh215 += 1;
            (unsafe { (*(*ctxt).input).col = 1 as i32 });
        } else {
            let fresh216 = unsafe { &mut ((*(*ctxt).input).col) };
            *fresh216 += 1;
        }
        let fresh217 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh217 = unsafe { (*fresh217).offset(ql as isize) };
        r = unsafe { xmlCurrentChar(ctxt, &mut rl) };
        if !(r == 0 as i32) {
            if if r < 0x100 as i32 {
                (0x9 as i32 <= r && r <= 0xa as i32 || r == 0xd as i32 || 0x20 as i32 <= r) as i32
            } else {
                (0x100 as i32 <= r && r <= 0xd7ff as i32
                    || 0xe000 as i32 <= r && r <= 0xfffd as i32
                    || 0x10000 as i32 <= r && r <= 0x10ffff as i32) as i32
            } == 0
            {
                xmlFatalErrMsgInt(
                    ctxt,
                    XML_ERR_INVALID_CHAR,
                    b"xmlParseComment: invalid xmlChar value %d\n\0" as *const u8 as *const i8,
                    q,
                );
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                return;
            }
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
                let fresh218 = unsafe { &mut ((*(*ctxt).input).line) };
                *fresh218 += 1;
                (unsafe { (*(*ctxt).input).col = 1 as i32 });
            } else {
                let fresh219 = unsafe { &mut ((*(*ctxt).input).col) };
                *fresh219 += 1;
            }
            let fresh220 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh220 = unsafe { (*fresh220).offset(rl as isize) };
            cur = unsafe { xmlCurrentChar(ctxt, &mut l) };
            if !(cur == 0 as i32) {
                while (if cur < 0x100 as i32 {
                    (0x9 as i32 <= cur && cur <= 0xa as i32
                        || cur == 0xd as i32
                        || 0x20 as i32 <= cur) as i32
                } else {
                    (0x100 as i32 <= cur && cur <= 0xd7ff as i32
                        || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
                        || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32)
                        as i32
                }) != 0
                    && (cur != '>' as i32 || r != '-' as i32 || q != '-' as i32)
                {
                    if r == '-' as i32 && q == '-' as i32 {
                        xmlFatalErr(ctxt, XML_ERR_HYPHEN_IN_COMMENT, 0 as *const i8);
                    }
                    if len > 10000000 as i32 as u64
                        && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
                    {
                        xmlFatalErrMsgStr(
                            ctxt,
                            XML_ERR_COMMENT_NOT_FINISHED,
                            b"Comment too big found\0" as *const u8 as *const i8,
                            0 as *const xmlChar,
                        );
                        (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                        return;
                    }
                    if len.wrapping_add(5 as i32 as u64) >= size {
                        let mut new_buf: *mut xmlChar = 0 as *mut xmlChar;
                        let mut new_size: size_t = 0;
                        new_size = size.wrapping_mul(2 as i32 as u64);
                        new_buf = (unsafe { xmlRealloc.expect("non-null function pointer")(
                            buf as *mut libc::c_void,
                            new_size,
                        ) }) as *mut xmlChar;
                        if new_buf.is_null() {
                            (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                            return;
                        }
                        buf = new_buf;
                        size = new_size;
                    }
                    if ql == 1 as i32 {
                        let fresh221 = len;
                        len = len.wrapping_add(1);
                        (unsafe { *buf.offset(fresh221 as isize) = q as xmlChar });
                    } else {
                        len = (len as u64)
                            .wrapping_add(
                                (unsafe { xmlCopyCharMultiByte(&mut *buf.offset(len as isize), q) }) as u64
                            ) as size_t as size_t;
                    }
                    q = r;
                    ql = rl;
                    r = cur;
                    rl = l;
                    count = count.wrapping_add(1);
                    if count > 50 as i32 as u64 {
                        if (unsafe { (*ctxt).progressive }) == 0 as i32
                            && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                                > (2 as i32 * 250 as i32) as i64
                            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                                < (2 as i32 * 250 as i32) as i64
                        {
                            xmlSHRINK(ctxt);
                        }
                        if (unsafe { (*ctxt).progressive }) == 0 as i32
                            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                                < 250 as i32 as i64
                        {
                            xmlGROW(ctxt);
                        }
                        count = 0 as i32 as size_t;
                        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                            (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                            return;
                        }
                    }
                    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
                        let fresh222 = unsafe { &mut ((*(*ctxt).input).line) };
                        *fresh222 += 1;
                        (unsafe { (*(*ctxt).input).col = 1 as i32 });
                    } else {
                        let fresh223 = unsafe { &mut ((*(*ctxt).input).col) };
                        *fresh223 += 1;
                    }
                    let fresh224 = unsafe { &mut ((*(*ctxt).input).cur) };
                    *fresh224 = unsafe { (*fresh224).offset(l as isize) };
                    cur = unsafe { xmlCurrentChar(ctxt, &mut l) };
                    if cur == 0 as i32 {
                        if (unsafe { (*ctxt).progressive }) == 0 as i32
                            && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                                > (2 as i32 * 250 as i32) as i64
                            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                                < (2 as i32 * 250 as i32) as i64
                        {
                            xmlSHRINK(ctxt);
                        }
                        if (unsafe { (*ctxt).progressive }) == 0 as i32
                            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                                < 250 as i32 as i64
                        {
                            xmlGROW(ctxt);
                        }
                        cur = unsafe { xmlCurrentChar(ctxt, &mut l) };
                    }
                }
                (unsafe { *buf.offset(len as isize) = 0 as i32 as xmlChar });
                if cur == 0 as i32 {
                    xmlFatalErrMsgStr(
                        ctxt,
                        XML_ERR_COMMENT_NOT_FINISHED,
                        b"Comment not terminated \n<!--%.50s\n\0" as *const u8 as *const i8,
                        buf,
                    );
                } else if if cur < 0x100 as i32 {
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
                    xmlFatalErrMsgInt(
                        ctxt,
                        XML_ERR_INVALID_CHAR,
                        b"xmlParseComment: invalid xmlChar value %d\n\0" as *const u8 as *const i8,
                        cur,
                    );
                } else {
                    if inputid != (unsafe { (*(*ctxt).input).id }) {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_ENTITY_BOUNDARY,
                            b"Comment doesn't start and stop in the same entity\n\0" as *const u8
                                as *const i8,
                        );
                    }
                    (unsafe { xmlNextChar(ctxt) });
                    if !(unsafe { (*ctxt).sax }).is_null()
                        && (unsafe { ((*(*ctxt).sax).comment).is_some() })
                        && (unsafe { (*ctxt).disableSAX }) == 0
                    {
                        (unsafe { ((*(*ctxt).sax).comment).expect("non-null function pointer")(
                            (*ctxt).userData,
                            buf,
                        ) });
                    }
                }
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
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
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlParseComment(mut ctxt: xmlParserCtxtPtr) {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut size: size_t = 100 as i32 as size_t;
    let mut len: size_t = 0 as i32 as size_t;
    let mut state: xmlParserInputState = XML_PARSER_START;
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut nbchar: size_t = 0 as i32 as size_t;
    let mut ccol: i32 = 0;
    let mut inputid: i32 = 0;
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '<' as i32
        || (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 != '!' as i32
        || (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 != '-' as i32
        || (unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) }) as i32 != '-' as i32
    {
        return;
    }
    state = unsafe { (*ctxt).instate };
    (unsafe { (*ctxt).instate = XML_PARSER_COMMENT });
    inputid = unsafe { (*(*ctxt).input).id };
    let fresh225 = unsafe { &mut ((*(*ctxt).input).cur) };
    *fresh225 = unsafe { (*fresh225).offset(4 as i32 as isize) };
    (unsafe { (*(*ctxt).input).col += 4 as i32 });
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
        (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
            > (2 as i32 * 250 as i32) as i64
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    in_0 = unsafe { (*(*ctxt).input).cur };
    loop {
        if (unsafe { *in_0 }) as i32 == 0xa as i32 {
            loop {
                let fresh226 = unsafe { &mut ((*(*ctxt).input).line) };
                *fresh226 += 1;
                (unsafe { (*(*ctxt).input).col = 1 as i32 });
                in_0 = unsafe { in_0.offset(1) };
                if !((unsafe { *in_0 }) as i32 == 0xa as i32) {
                    break;
                }
            }
        }
        loop {
            ccol = unsafe { (*(*ctxt).input).col };
            while (unsafe { *in_0 }) as i32 > '-' as i32 && (unsafe { *in_0 }) as i32 <= 0x7f as i32
                || (unsafe { *in_0 }) as i32 >= 0x20 as i32 && ((unsafe { *in_0 }) as i32) < '-' as i32
                || (unsafe { *in_0 }) as i32 == 0x9 as i32
            {
                in_0 = unsafe { in_0.offset(1) };
                ccol += 1;
            }
            (unsafe { (*(*ctxt).input).col = ccol });
            if (unsafe { *in_0 }) as i32 == 0xa as i32 {
                loop {
                    let fresh227 = unsafe { &mut ((*(*ctxt).input).line) };
                    *fresh227 += 1;
                    (unsafe { (*(*ctxt).input).col = 1 as i32 });
                    in_0 = unsafe { in_0.offset(1) };
                    if !((unsafe { *in_0 }) as i32 == 0xa as i32) {
                        break;
                    }
                }
            } else {
                nbchar = (unsafe { in_0.offset_from((*(*ctxt).input).cur) }) as i64 as size_t;
                if nbchar > 0 as i32 as u64 {
                    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).comment).is_some() }) {
                        if buf.is_null() {
                            if (unsafe { *in_0 }) as i32 == '-' as i32
                                && (unsafe { *in_0.offset(1 as i32 as isize) }) as i32 == '-' as i32
                            {
                                size = nbchar.wrapping_add(1 as i32 as u64);
                            } else {
                                size = (100 as i32 as u64).wrapping_add(nbchar);
                            }
                            buf = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
                                size.wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
                            ) }) as *mut xmlChar;
                            if buf.is_null() {
                                (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                                (unsafe { (*ctxt).instate = state });
                                return;
                            }
                            len = 0 as i32 as size_t;
                        } else if len.wrapping_add(nbchar).wrapping_add(1 as i32 as u64) >= size {
                            let mut new_buf: *mut xmlChar = 0 as *mut xmlChar;
                            size = (size as u64).wrapping_add(
                                len.wrapping_add(nbchar).wrapping_add(100 as i32 as u64),
                            ) as size_t as size_t;
                            new_buf = (unsafe { xmlRealloc.expect("non-null function pointer")(
                                buf as *mut libc::c_void,
                                size.wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
                            ) }) as *mut xmlChar;
                            if new_buf.is_null() {
                                (unsafe { xmlFree.expect("non-null function pointer")(
                                    buf as *mut libc::c_void,
                                ) });
                                (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                                (unsafe { (*ctxt).instate = state });
                                return;
                            }
                            buf = new_buf;
                        }
                        (unsafe { memcpy(
                            &mut *buf.offset(len as isize) as *mut xmlChar as *mut libc::c_void,
                            (*(*ctxt).input).cur as *const libc::c_void,
                            nbchar,
                        ) });
                        len = (len as u64).wrapping_add(nbchar) as size_t as size_t;
                        (unsafe { *buf.offset(len as isize) = 0 as i32 as xmlChar });
                    }
                }
                if len > 10000000 as i32 as u64
                    && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
                {
                    xmlFatalErrMsgStr(
                        ctxt,
                        XML_ERR_COMMENT_NOT_FINISHED,
                        b"Comment too big found\0" as *const u8 as *const i8,
                        0 as *const xmlChar,
                    );
                    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                    return;
                }
                let fresh228 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh228 = in_0;
                if (unsafe { *in_0 }) as i32 == 0xa as i32 {
                    in_0 = unsafe { in_0.offset(1) };
                    let fresh229 = unsafe { &mut ((*(*ctxt).input).line) };
                    *fresh229 += 1;
                    (unsafe { (*(*ctxt).input).col = 1 as i32 });
                }
                if (unsafe { *in_0 }) as i32 == 0xd as i32 {
                    in_0 = unsafe { in_0.offset(1) };
                    if (unsafe { *in_0 }) as i32 == 0xa as i32 {
                        let fresh230 = unsafe { &mut ((*(*ctxt).input).cur) };
                        *fresh230 = in_0;
                        in_0 = unsafe { in_0.offset(1) };
                        let fresh231 = unsafe { &mut ((*(*ctxt).input).line) };
                        *fresh231 += 1;
                        (unsafe { (*(*ctxt).input).col = 1 as i32 });
                        continue;
                    } else {
                        in_0 = unsafe { in_0.offset(-1) };
                    }
                }
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                        > (2 as i32 * 250 as i32) as i64
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < (2 as i32 * 250 as i32) as i64
                {
                    xmlSHRINK(ctxt);
                }
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                    return;
                }
                in_0 = unsafe { (*(*ctxt).input).cur };
                if !((unsafe { *in_0 }) as i32 == '-' as i32) {
                    break;
                }
                if (unsafe { *in_0.offset(1 as i32 as isize) }) as i32 == '-' as i32 {
                    if (unsafe { *in_0.offset(2 as i32 as isize) }) as i32 == '>' as i32 {
                        if (unsafe { (*(*ctxt).input).id }) != inputid {
                            xmlFatalErrMsg(
                                ctxt,
                                XML_ERR_ENTITY_BOUNDARY,
                                b"comment doesn't start and stop in the same entity\n\0"
                                    as *const u8 as *const i8,
                            );
                        }
                        let fresh232 = unsafe { &mut ((*(*ctxt).input).cur) };
                        *fresh232 = unsafe { (*fresh232).offset(3 as i32 as isize) };
                        (unsafe { (*(*ctxt).input).col += 3 as i32 });
                        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                        }
                        if !(unsafe { (*ctxt).sax }).is_null()
                            && (unsafe { ((*(*ctxt).sax).comment).is_some() })
                            && (unsafe { (*ctxt).disableSAX }) == 0
                        {
                            if !buf.is_null() {
                                (unsafe { ((*(*ctxt).sax).comment).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                    buf,
                                ) });
                            } else {
                                (unsafe { ((*(*ctxt).sax).comment).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                    b"\0" as *const u8 as *const i8 as *mut xmlChar,
                                ) });
                            }
                        }
                        if !buf.is_null() {
                            (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                        }
                        if (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32 {
                            (unsafe { (*ctxt).instate = state });
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
                            b"Double hyphen within comment\n\0" as *const u8 as *const i8,
                            0 as *const xmlChar,
                        );
                    }
                    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                        (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                        return;
                    }
                    in_0 = unsafe { in_0.offset(1) };
                    let fresh233 = unsafe { &mut ((*(*ctxt).input).col) };
                    *fresh233 += 1;
                }
                in_0 = unsafe { in_0.offset(1) };
                let fresh234 = unsafe { &mut ((*(*ctxt).input).col) };
                *fresh234 += 1;
            }
        }
        if !((unsafe { *in_0 }) as i32 >= 0x20 as i32 && (unsafe { *in_0 }) as i32 <= 0x7f as i32
            || (unsafe { *in_0 }) as i32 == 0x9 as i32
            || (unsafe { *in_0 }) as i32 == 0xa as i32)
        {
            break;
        }
    }
    xmlParseCommentComplex(ctxt, buf, len, size);
    (unsafe { (*ctxt).instate = state });
}
#[no_mangle]
pub extern "C" fn xmlParsePITarget(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    name = xmlParseName(ctxt);
    if !name.is_null()
        && ((unsafe { *name.offset(0 as i32 as isize) }) as i32 == 'x' as i32
            || (unsafe { *name.offset(0 as i32 as isize) }) as i32 == 'X' as i32)
        && ((unsafe { *name.offset(1 as i32 as isize) }) as i32 == 'm' as i32
            || (unsafe { *name.offset(1 as i32 as isize) }) as i32 == 'M' as i32)
        && ((unsafe { *name.offset(2 as i32 as isize) }) as i32 == 'l' as i32
            || (unsafe { *name.offset(2 as i32 as isize) }) as i32 == 'L' as i32)
    {
        let mut i: i32 = 0;
        if (unsafe { *name.offset(0 as i32 as isize) }) as i32 == 'x' as i32
            && (unsafe { *name.offset(1 as i32 as isize) }) as i32 == 'm' as i32
            && (unsafe { *name.offset(2 as i32 as isize) }) as i32 == 'l' as i32
            && (unsafe { *name.offset(3 as i32 as isize) }) as i32 == 0 as i32
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_RESERVED_XML_NAME,
                b"XML declaration allowed only at the start of the document\n\0" as *const u8
                    as *const i8,
            );
            return name;
        } else {
            if (unsafe { *name.offset(3 as i32 as isize) }) as i32 == 0 as i32 {
                xmlFatalErr(ctxt, XML_ERR_RESERVED_XML_NAME, 0 as *const i8);
                return name;
            }
        }
        i = 0 as i32;
        while !(unsafe { xmlW3CPIs[i as usize] }).is_null() {
            if (unsafe { xmlStrEqual(name, xmlW3CPIs[i as usize] as *const xmlChar) }) != 0 {
                return name;
            }
            i += 1;
        }
        xmlWarningMsg(
            ctxt,
            XML_ERR_RESERVED_XML_NAME,
            b"xmlParsePITarget: invalid name prefix 'xml'\n\0" as *const u8 as *const i8,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    }
    if !name.is_null() && !(unsafe { xmlStrchr(name, ':' as i32 as xmlChar) }).is_null() {
        xmlNsErr(
            ctxt,
            XML_NS_ERR_COLON,
            b"colons are forbidden from PI names '%s'\n\0" as *const u8 as *const i8,
            name,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    }
    return name;
}
extern "C" fn xmlParseCatalogPI(mut ctxt: xmlParserCtxtPtr, mut catalog: *const xmlChar) {
    let mut URL: *mut xmlChar = 0 as *mut xmlChar;
    let mut tmp: *const xmlChar = 0 as *const xmlChar;
    let mut base: *const xmlChar = 0 as *const xmlChar;
    let mut marker: xmlChar = 0;
    tmp = catalog;
    while (unsafe { *tmp }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *tmp }) as i32 && (unsafe { *tmp }) as i32 <= 0xa as i32
        || (unsafe { *tmp }) as i32 == 0xd as i32
    {
        tmp = unsafe { tmp.offset(1) };
    }
    if !((unsafe { xmlStrncmp(
        tmp,
        b"catalog\0" as *const u8 as *const i8 as *mut xmlChar,
        7 as i32,
    ) }) != 0)
    {
        tmp = unsafe { tmp.offset(7 as i32 as isize) };
        while (unsafe { *tmp }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *tmp }) as i32 && (unsafe { *tmp }) as i32 <= 0xa as i32
            || (unsafe { *tmp }) as i32 == 0xd as i32
        {
            tmp = unsafe { tmp.offset(1) };
        }
        if (unsafe { *tmp }) as i32 != '=' as i32 {
            return;
        }
        tmp = unsafe { tmp.offset(1) };
        while (unsafe { *tmp }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *tmp }) as i32 && (unsafe { *tmp }) as i32 <= 0xa as i32
            || (unsafe { *tmp }) as i32 == 0xd as i32
        {
            tmp = unsafe { tmp.offset(1) };
        }
        marker = unsafe { *tmp };
        if !(marker as i32 != '\'' as i32 && marker as i32 != '"' as i32) {
            tmp = unsafe { tmp.offset(1) };
            base = tmp;
            while (unsafe { *tmp }) as i32 != 0 as i32 && (unsafe { *tmp }) as i32 != marker as i32 {
                tmp = unsafe { tmp.offset(1) };
            }
            if !((unsafe { *tmp }) as i32 == 0 as i32) {
                URL = unsafe { xmlStrndup(base, tmp.offset_from(base) as i64 as i32) };
                tmp = unsafe { tmp.offset(1) };
                while (unsafe { *tmp }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *tmp }) as i32 && (unsafe { *tmp }) as i32 <= 0xa as i32
                    || (unsafe { *tmp }) as i32 == 0xd as i32
                {
                    tmp = unsafe { tmp.offset(1) };
                }
                if !((unsafe { *tmp }) as i32 != 0 as i32) {
                    if !URL.is_null() {
                        let fresh235 = unsafe { &mut ((*ctxt).catalogs) };
                        *fresh235 = unsafe { xmlCatalogAddLocal((*ctxt).catalogs, URL) };
                        (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
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
        (unsafe { xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void) });
    }
}
#[no_mangle]
pub extern "C" fn xmlParsePI(mut ctxt: xmlParserCtxtPtr) {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: size_t = 0 as i32 as size_t;
    let mut size: size_t = 100 as i32 as size_t;
    let mut cur: i32 = 0;
    let mut l: i32 = 0;
    let mut target: *const xmlChar = 0 as *const xmlChar;
    let mut state: xmlParserInputState = XML_PARSER_START;
    let mut count: i32 = 0 as i32;
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '?' as i32
    {
        let mut inputid: i32 = unsafe { (*(*ctxt).input).id };
        state = unsafe { (*ctxt).instate };
        (unsafe { (*ctxt).instate = XML_PARSER_PI });
        let fresh236 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh236 = unsafe { (*fresh236).offset(2 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 2 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                > (2 as i32 * 250 as i32) as i64
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                < (2 as i32 * 250 as i32) as i64
        {
            xmlSHRINK(ctxt);
        }
        target = xmlParsePITarget(ctxt);
        if !target.is_null() {
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == '?' as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '>' as i32
            {
                if inputid != (unsafe { (*(*ctxt).input).id }) {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ENTITY_BOUNDARY,
                        b"PI declaration doesn't start and stop in the same entity\n\0" as *const u8
                            as *const i8,
                    );
                }
                let fresh237 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh237 = unsafe { (*fresh237).offset(2 as i32 as isize) };
                (unsafe { (*(*ctxt).input).col += 2 as i32 });
                if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                    (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                }
                if !(unsafe { (*ctxt).sax }).is_null()
                    && (unsafe { (*ctxt).disableSAX }) == 0
                    && (unsafe { ((*(*ctxt).sax).processingInstruction).is_some() })
                {
                    (unsafe { ((*(*ctxt).sax).processingInstruction).expect("non-null function pointer")(
                        (*ctxt).userData,
                        target,
                        0 as *const xmlChar,
                    ) });
                }
                if (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32 {
                    (unsafe { (*ctxt).instate = state });
                }
                return;
            }
            buf = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
                size.wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) }) as *mut xmlChar;
            if buf.is_null() {
                (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                (unsafe { (*ctxt).instate = state });
                return;
            }
            if xmlSkipBlankChars(ctxt) == 0 as i32 {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_SPACE_REQUIRED,
                    b"ParsePI: PI %s space expected\n\0" as *const u8 as *const i8,
                    target,
                );
            }
            cur = unsafe { xmlCurrentChar(ctxt, &mut l) };
            while (if cur < 0x100 as i32 {
                (0x9 as i32 <= cur && cur <= 0xa as i32 || cur == 0xd as i32 || 0x20 as i32 <= cur)
                    as i32
            } else {
                (0x100 as i32 <= cur && cur <= 0xd7ff as i32
                    || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
                    || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32) as i32
            }) != 0
                && (cur != '?' as i32
                    || (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 != '>' as i32)
            {
                if len.wrapping_add(5 as i32 as u64) >= size {
                    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                    let mut new_size: size_t = size.wrapping_mul(2 as i32 as u64);
                    tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                        buf as *mut libc::c_void,
                        new_size,
                    ) }) as *mut xmlChar;
                    if tmp.is_null() {
                        (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                        (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                        (unsafe { (*ctxt).instate = state });
                        return;
                    }
                    buf = tmp;
                    size = new_size;
                }
                count += 1;
                if count > 50 as i32 {
                    if (unsafe { (*ctxt).progressive }) == 0 as i32
                        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                            > (2 as i32 * 250 as i32) as i64
                        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                            < (2 as i32 * 250 as i32) as i64
                    {
                        xmlSHRINK(ctxt);
                    }
                    if (unsafe { (*ctxt).progressive }) == 0 as i32
                        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                            < 250 as i32 as i64
                    {
                        xmlGROW(ctxt);
                    }
                    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                        (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                        return;
                    }
                    count = 0 as i32;
                    if len > 10000000 as i32 as u64
                        && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
                    {
                        xmlFatalErrMsgStr(
                            ctxt,
                            XML_ERR_PI_NOT_FINISHED,
                            b"PI %s too big found\0" as *const u8 as *const i8,
                            target,
                        );
                        (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                        (unsafe { (*ctxt).instate = state });
                        return;
                    }
                }
                if l == 1 as i32 {
                    let fresh238 = len;
                    len = len.wrapping_add(1);
                    (unsafe { *buf.offset(fresh238 as isize) = cur as xmlChar });
                } else {
                    len = (len as u64)
                        .wrapping_add(
                            (unsafe { xmlCopyCharMultiByte(&mut *buf.offset(len as isize), cur) }) as u64
                        ) as size_t as size_t;
                }
                if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
                    let fresh239 = unsafe { &mut ((*(*ctxt).input).line) };
                    *fresh239 += 1;
                    (unsafe { (*(*ctxt).input).col = 1 as i32 });
                } else {
                    let fresh240 = unsafe { &mut ((*(*ctxt).input).col) };
                    *fresh240 += 1;
                }
                let fresh241 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh241 = unsafe { (*fresh241).offset(l as isize) };
                cur = unsafe { xmlCurrentChar(ctxt, &mut l) };
                if cur == 0 as i32 {
                    if (unsafe { (*ctxt).progressive }) == 0 as i32
                        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                            > (2 as i32 * 250 as i32) as i64
                        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                            < (2 as i32 * 250 as i32) as i64
                    {
                        xmlSHRINK(ctxt);
                    }
                    if (unsafe { (*ctxt).progressive }) == 0 as i32
                        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                            < 250 as i32 as i64
                    {
                        xmlGROW(ctxt);
                    }
                    cur = unsafe { xmlCurrentChar(ctxt, &mut l) };
                }
            }
            if len > 10000000 as i32 as u64 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_PI_NOT_FINISHED,
                    b"PI %s too big found\0" as *const u8 as *const i8,
                    target,
                );
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                (unsafe { (*ctxt).instate = state });
                return;
            }
            (unsafe { *buf.offset(len as isize) = 0 as i32 as xmlChar });
            if cur != '?' as i32 {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_PI_NOT_FINISHED,
                    b"ParsePI: PI %s never end ...\n\0" as *const u8 as *const i8,
                    target,
                );
            } else {
                if inputid != (unsafe { (*(*ctxt).input).id }) {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ENTITY_BOUNDARY,
                        b"PI declaration doesn't start and stop in the same entity\n\0" as *const u8
                            as *const i8,
                    );
                }
                let fresh242 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh242 = unsafe { (*fresh242).offset(2 as i32 as isize) };
                (unsafe { (*(*ctxt).input).col += 2 as i32 });
                if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                    (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                }
                if (state as i32 == XML_PARSER_MISC as i32
                    || state as i32 == XML_PARSER_START as i32)
                    && (unsafe { xmlStrEqual(
                        target,
                        b"oasis-xml-catalog\0" as *const u8 as *const i8 as *const xmlChar,
                    ) }) != 0
                {
                    let mut allow: xmlCatalogAllow = unsafe { xmlCatalogGetDefaults() };
                    if allow as u32 == XML_CATA_ALLOW_DOCUMENT as i32 as u32
                        || allow as u32 == XML_CATA_ALLOW_ALL as i32 as u32
                    {
                        xmlParseCatalogPI(ctxt, buf);
                    }
                }
                if !(unsafe { (*ctxt).sax }).is_null()
                    && (unsafe { (*ctxt).disableSAX }) == 0
                    && (unsafe { ((*(*ctxt).sax).processingInstruction).is_some() })
                {
                    (unsafe { ((*(*ctxt).sax).processingInstruction).expect("non-null function pointer")(
                        (*ctxt).userData,
                        target,
                        buf,
                    ) });
                }
            }
            (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
        } else {
            xmlFatalErr(ctxt, XML_ERR_PI_NOT_STARTED, 0 as *const i8);
        }
        if (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32 {
            (unsafe { (*ctxt).instate = state });
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlParseNotationDecl(mut ctxt: xmlParserCtxtPtr) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut Pubid: *mut xmlChar = 0 as *mut xmlChar;
    let mut Systemid: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == '!' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'N' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'O' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'A' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) }) as i32 == 'I' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(8 as i32 as isize) }) as i32 == 'O' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(9 as i32 as isize) }) as i32 == 'N' as i32
    {
        let mut inputid: i32 = unsafe { (*(*ctxt).input).id };
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                > (2 as i32 * 250 as i32) as i64
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                < (2 as i32 * 250 as i32) as i64
        {
            xmlSHRINK(ctxt);
        }
        let fresh243 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh243 = unsafe { (*fresh243).offset(10 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 10 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after '<!NOTATION'\n\0" as *const u8 as *const i8,
            );
            return;
        }
        name = xmlParseName(ctxt);
        if name.is_null() {
            xmlFatalErr(ctxt, XML_ERR_NOTATION_NOT_STARTED, 0 as *const i8);
            return;
        }
        if !(unsafe { xmlStrchr(name, ':' as i32 as xmlChar) }).is_null() {
            xmlNsErr(
                ctxt,
                XML_NS_ERR_COLON,
                b"colons are forbidden from notation names '%s'\n\0" as *const u8 as *const i8,
                name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after the NOTATION name'\n\0" as *const u8 as *const i8,
            );
            return;
        }
        Systemid = xmlParseExternalID(ctxt, &mut Pubid, 0 as i32);
        xmlSkipBlankChars(ctxt);
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '>' as i32 {
            if inputid != (unsafe { (*(*ctxt).input).id }) {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Notation declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const i8,
                );
            }
            (unsafe { xmlNextChar(ctxt) });
            if !(unsafe { (*ctxt).sax }).is_null()
                && (unsafe { (*ctxt).disableSAX }) == 0
                && (unsafe { ((*(*ctxt).sax).notationDecl).is_some() })
            {
                (unsafe { ((*(*ctxt).sax).notationDecl).expect("non-null function pointer")(
                    (*ctxt).userData,
                    name,
                    Pubid,
                    Systemid,
                ) });
            }
        } else {
            xmlFatalErr(ctxt, XML_ERR_NOTATION_NOT_FINISHED, 0 as *const i8);
        }
        if !Systemid.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(Systemid as *mut libc::c_void) });
        }
        if !Pubid.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(Pubid as *mut libc::c_void) });
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlParseEntityDecl(mut ctxt: xmlParserCtxtPtr) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let mut literal: *mut xmlChar = 0 as *mut xmlChar;
    let mut ndata: *const xmlChar = 0 as *const xmlChar;
    let mut isParameter: i32 = 0 as i32;
    let mut orig: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == '!' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'E' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'N' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'I' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) }) as i32 == 'Y' as i32
    {
        let mut inputid: i32 = unsafe { (*(*ctxt).input).id };
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                > (2 as i32 * 250 as i32) as i64
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                < (2 as i32 * 250 as i32) as i64
        {
            xmlSHRINK(ctxt);
        }
        let fresh244 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh244 = unsafe { (*fresh244).offset(8 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 8 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after '<!ENTITY'\n\0" as *const u8 as *const i8,
            );
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '%' as i32 {
            (unsafe { xmlNextChar(ctxt) });
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
        if !(unsafe { xmlStrchr(name, ':' as i32 as xmlChar) }).is_null() {
            xmlNsErr(
                ctxt,
                XML_NS_ERR_COLON,
                b"colons are forbidden from entities names '%s'\n\0" as *const u8 as *const i8,
                name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after the entity name\n\0" as *const u8 as *const i8,
            );
        }
        (unsafe { (*ctxt).instate = XML_PARSER_ENTITY_DECL });
        if isParameter != 0 {
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == '"' as i32
                || (unsafe { *(*(*ctxt).input).cur }) as i32 == '\'' as i32
            {
                value = xmlParseEntityValue(ctxt, &mut orig);
                if !value.is_null() {
                    if !(unsafe { (*ctxt).sax }).is_null()
                        && (unsafe { (*ctxt).disableSAX }) == 0
                        && (unsafe { ((*(*ctxt).sax).entityDecl).is_some() })
                    {
                        (unsafe { ((*(*ctxt).sax).entityDecl).expect("non-null function pointer")(
                            (*ctxt).userData,
                            name,
                            XML_INTERNAL_PARAMETER_ENTITY as i32,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                            value,
                        ) });
                    }
                }
            } else {
                URI = xmlParseExternalID(ctxt, &mut literal, 1 as i32);
                if URI.is_null() && literal.is_null() {
                    xmlFatalErr(ctxt, XML_ERR_VALUE_REQUIRED, 0 as *const i8);
                }
                if !URI.is_null() {
                    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
                    uri = unsafe { xmlParseURI(URI as *const i8) };
                    if uri.is_null() {
                        xmlErrMsgStr(
                            ctxt,
                            XML_ERR_INVALID_URI,
                            b"Invalid URI: %s\n\0" as *const u8 as *const i8,
                            URI,
                        );
                    } else {
                        if !(unsafe { (*uri).fragment }).is_null() {
                            xmlFatalErr(ctxt, XML_ERR_URI_FRAGMENT, 0 as *const i8);
                        } else if !(unsafe { (*ctxt).sax }).is_null()
                            && (unsafe { (*ctxt).disableSAX }) == 0
                            && (unsafe { ((*(*ctxt).sax).entityDecl).is_some() })
                        {
                            (unsafe { ((*(*ctxt).sax).entityDecl).expect("non-null function pointer")(
                                (*ctxt).userData,
                                name,
                                XML_EXTERNAL_PARAMETER_ENTITY as i32,
                                literal,
                                URI,
                                0 as *mut xmlChar,
                            ) });
                        }
                        (unsafe { xmlFreeURI(uri) });
                    }
                }
            }
        } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '"' as i32
            || (unsafe { *(*(*ctxt).input).cur }) as i32 == '\'' as i32
        {
            value = xmlParseEntityValue(ctxt, &mut orig);
            if !(unsafe { (*ctxt).sax }).is_null()
                && (unsafe { (*ctxt).disableSAX }) == 0
                && (unsafe { ((*(*ctxt).sax).entityDecl).is_some() })
            {
                (unsafe { ((*(*ctxt).sax).entityDecl).expect("non-null function pointer")(
                    (*ctxt).userData,
                    name,
                    XML_INTERNAL_GENERAL_ENTITY as i32,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    value,
                ) });
            }
            if (unsafe { (*ctxt).myDoc }).is_null()
                || (unsafe { xmlStrEqual(
                    (*(*ctxt).myDoc).version,
                    b"SAX compatibility mode document\0" as *const u8 as *const i8 as *mut xmlChar,
                ) }) != 0
            {
                if (unsafe { (*ctxt).myDoc }).is_null() {
                    let fresh245 = unsafe { &mut ((*ctxt).myDoc) };
                    *fresh245 = unsafe { xmlNewDoc(
                        b"SAX compatibility mode document\0" as *const u8 as *const i8
                            as *mut xmlChar,
                    ) };
                    if (unsafe { (*ctxt).myDoc }).is_null() {
                        (unsafe { xmlErrMemory(ctxt, b"New Doc failed\0" as *const u8 as *const i8) });
                        return;
                    }
                    (unsafe { (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as i32 });
                }
                if (unsafe { (*(*ctxt).myDoc).intSubset }).is_null() {
                    let fresh246 = unsafe { &mut ((*(*ctxt).myDoc).intSubset) };
                    *fresh246 = unsafe { xmlNewDtd(
                        (*ctxt).myDoc,
                        b"fake\0" as *const u8 as *const i8 as *mut xmlChar,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    ) };
                }
                (unsafe { xmlSAX2EntityDecl(
                    ctxt as *mut libc::c_void,
                    name,
                    XML_INTERNAL_GENERAL_ENTITY as i32,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    value,
                ) });
            }
        } else {
            URI = xmlParseExternalID(ctxt, &mut literal, 1 as i32);
            if URI.is_null() && literal.is_null() {
                xmlFatalErr(ctxt, XML_ERR_VALUE_REQUIRED, 0 as *const i8);
            }
            if !URI.is_null() {
                let mut uri_0: xmlURIPtr = 0 as *mut xmlURI;
                uri_0 = unsafe { xmlParseURI(URI as *const i8) };
                if uri_0.is_null() {
                    xmlErrMsgStr(
                        ctxt,
                        XML_ERR_INVALID_URI,
                        b"Invalid URI: %s\n\0" as *const u8 as *const i8,
                        URI,
                    );
                } else {
                    if !(unsafe { (*uri_0).fragment }).is_null() {
                        xmlFatalErr(ctxt, XML_ERR_URI_FRAGMENT, 0 as *const i8);
                    }
                    (unsafe { xmlFreeURI(uri_0) });
                }
            }
            if (unsafe { *(*(*ctxt).input).cur }) as i32 != '>' as i32 && xmlSkipBlankChars(ctxt) == 0 as i32 {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_SPACE_REQUIRED,
                    b"Space required before 'NDATA'\n\0" as *const u8 as *const i8,
                );
            }
            if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == 'N' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'D' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'A' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'T' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'A' as i32
            {
                let fresh247 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh247 = unsafe { (*fresh247).offset(5 as i32 as isize) };
                (unsafe { (*(*ctxt).input).col += 5 as i32 });
                if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                    (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                }
                if xmlSkipBlankChars(ctxt) == 0 as i32 {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_SPACE_REQUIRED,
                        b"Space required after 'NDATA'\n\0" as *const u8 as *const i8,
                    );
                }
                ndata = xmlParseName(ctxt);
                if !(unsafe { (*ctxt).sax }).is_null()
                    && (unsafe { (*ctxt).disableSAX }) == 0
                    && (unsafe { ((*(*ctxt).sax).unparsedEntityDecl).is_some() })
                {
                    (unsafe { ((*(*ctxt).sax).unparsedEntityDecl).expect("non-null function pointer")(
                        (*ctxt).userData,
                        name,
                        literal,
                        URI,
                        ndata,
                    ) });
                }
            } else {
                if !(unsafe { (*ctxt).sax }).is_null()
                    && (unsafe { (*ctxt).disableSAX }) == 0
                    && (unsafe { ((*(*ctxt).sax).entityDecl).is_some() })
                {
                    (unsafe { ((*(*ctxt).sax).entityDecl).expect("non-null function pointer")(
                        (*ctxt).userData,
                        name,
                        XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32,
                        literal,
                        URI,
                        0 as *mut xmlChar,
                    ) });
                }
                if (unsafe { (*ctxt).replaceEntities }) != 0 as i32
                    && ((unsafe { (*ctxt).myDoc }).is_null()
                        || (unsafe { xmlStrEqual(
                            (*(*ctxt).myDoc).version,
                            b"SAX compatibility mode document\0" as *const u8 as *const i8
                                as *mut xmlChar,
                        ) }) != 0)
                {
                    if (unsafe { (*ctxt).myDoc }).is_null() {
                        let fresh248 = unsafe { &mut ((*ctxt).myDoc) };
                        *fresh248 = unsafe { xmlNewDoc(
                            b"SAX compatibility mode document\0" as *const u8 as *const i8
                                as *mut xmlChar,
                        ) };
                        if (unsafe { (*ctxt).myDoc }).is_null() {
                            (unsafe { xmlErrMemory(ctxt, b"New Doc failed\0" as *const u8 as *const i8) });
                            return;
                        }
                        (unsafe { (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as i32 });
                    }
                    if (unsafe { (*(*ctxt).myDoc).intSubset }).is_null() {
                        let fresh249 = unsafe { &mut ((*(*ctxt).myDoc).intSubset) };
                        *fresh249 = unsafe { xmlNewDtd(
                            (*ctxt).myDoc,
                            b"fake\0" as *const u8 as *const i8 as *mut xmlChar,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        ) };
                    }
                    (unsafe { xmlSAX2EntityDecl(
                        ctxt as *mut libc::c_void,
                        name,
                        XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32,
                        literal,
                        URI,
                        0 as *mut xmlChar,
                    ) });
                }
            }
        }
        if !((unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32) {
            xmlSkipBlankChars(ctxt);
            if (unsafe { *(*(*ctxt).input).cur }) as i32 != '>' as i32 {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_ENTITY_NOT_FINISHED,
                    b"xmlParseEntityDecl: entity %s not terminated\n\0" as *const u8 as *const i8,
                    name,
                );
                xmlHaltParser(ctxt);
            } else {
                if inputid != (unsafe { (*(*ctxt).input).id }) {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ENTITY_BOUNDARY,
                        b"Entity declaration doesn't start and stop in the same entity\n\0"
                            as *const u8 as *const i8,
                    );
                }
                (unsafe { xmlNextChar(ctxt) });
            }
            if !orig.is_null() {
                let mut cur: xmlEntityPtr = 0 as xmlEntityPtr;
                if isParameter != 0 {
                    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).getParameterEntity).is_some() }) {
                        cur = unsafe { ((*(*ctxt).sax).getParameterEntity)
                            .expect("non-null function pointer")(
                            (*ctxt).userData, name
                        ) };
                    }
                } else {
                    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).getEntity).is_some() }) {
                        cur = unsafe { ((*(*ctxt).sax).getEntity).expect("non-null function pointer")(
                            (*ctxt).userData,
                            name,
                        ) };
                    }
                    if cur.is_null() && (unsafe { (*ctxt).userData }) == ctxt as *mut libc::c_void {
                        cur = unsafe { xmlSAX2GetEntity(ctxt as *mut libc::c_void, name) };
                    }
                }
                if !cur.is_null() && (unsafe { (*cur).orig }).is_null() {
                    let fresh250 = unsafe { &mut ((*cur).orig) };
                    *fresh250 = orig;
                    orig = 0 as *mut xmlChar;
                }
            }
        }
        if !value.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(value as *mut libc::c_void) });
        }
        if !URI.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(URI as *mut libc::c_void) });
        }
        if !literal.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(literal as *mut libc::c_void) });
        }
        if !orig.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(orig as *mut libc::c_void) });
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlParseDefaultDecl(
    mut ctxt: xmlParserCtxtPtr,
    mut value: *mut *mut xmlChar,
) -> i32 {
    let mut val: i32 = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    (unsafe { *value = 0 as *mut xmlChar });
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '#' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'R' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'E' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'Q' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'U' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'I' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'R' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) }) as i32 == 'E' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(8 as i32 as isize) }) as i32 == 'D' as i32
    {
        let fresh251 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh251 = unsafe { (*fresh251).offset(9 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 9 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        return XML_ATTRIBUTE_REQUIRED as i32;
    }
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '#' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'I' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'M' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'P' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'L' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'I' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'E' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) }) as i32 == 'D' as i32
    {
        let fresh252 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh252 = unsafe { (*fresh252).offset(8 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 8 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        return XML_ATTRIBUTE_IMPLIED as i32;
    }
    val = XML_ATTRIBUTE_NONE as i32;
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '#' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'F' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'I' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'X' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'E' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'D' as i32
    {
        let fresh253 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh253 = unsafe { (*fresh253).offset(6 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 6 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
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
    (unsafe { (*ctxt).instate = XML_PARSER_DTD });
    if ret.is_null() {
        xmlFatalErrMsg(
            ctxt,
            (unsafe { (*ctxt).errNo }) as xmlParserErrors,
            b"Attribute default value declaration error\n\0" as *const u8 as *const i8,
        );
    } else {
        (unsafe { *value = ret });
    }
    return val;
}
#[no_mangle]
pub extern "C" fn xmlParseNotationType(mut ctxt: xmlParserCtxtPtr) -> xmlEnumerationPtr {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut ret: xmlEnumerationPtr = 0 as xmlEnumerationPtr;
    let mut last: xmlEnumerationPtr = 0 as xmlEnumerationPtr;
    let mut cur: xmlEnumerationPtr = 0 as *mut xmlEnumeration;
    let mut tmp: xmlEnumerationPtr = 0 as *mut xmlEnumeration;
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '(' as i32 {
        xmlFatalErr(ctxt, XML_ERR_NOTATION_NOT_STARTED, 0 as *const i8);
        return 0 as xmlEnumerationPtr;
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
            > (2 as i32 * 250 as i32) as i64
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    loop {
        (unsafe { xmlNextChar(ctxt) });
        xmlSkipBlankChars(ctxt);
        name = xmlParseName(ctxt);
        if name.is_null() {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_NAME_REQUIRED,
                b"Name expected in NOTATION declaration\n\0" as *const u8 as *const i8,
            );
            (unsafe { xmlFreeEnumeration(ret) });
            return 0 as xmlEnumerationPtr;
        }
        tmp = ret;
        while !tmp.is_null() {
            if (unsafe { xmlStrEqual(name, (*tmp).name) }) != 0 {
                xmlValidityError(
                    ctxt,
                    XML_DTD_DUP_TOKEN,
                    b"standalone: attribute notation value token %s duplicated\n\0" as *const u8
                        as *const i8,
                    name,
                    0 as *const xmlChar,
                );
                if (unsafe { xmlDictOwns((*ctxt).dict, name) }) == 0 {
                    (unsafe { xmlFree.expect("non-null function pointer")(
                        name as *mut xmlChar as *mut libc::c_void,
                    ) });
                }
                break;
            } else {
                tmp = unsafe { (*tmp).next };
            }
        }
        if tmp.is_null() {
            cur = unsafe { xmlCreateEnumeration(name) };
            if cur.is_null() {
                (unsafe { xmlFreeEnumeration(ret) });
                return 0 as xmlEnumerationPtr;
            }
            if last.is_null() {
                last = cur;
                ret = last;
            } else {
                let fresh254 = unsafe { &mut ((*last).next) };
                *fresh254 = cur;
                last = cur;
            }
        }
        xmlSkipBlankChars(ctxt);
        if !((unsafe { *(*(*ctxt).input).cur }) as i32 == '|' as i32) {
            break;
        }
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != ')' as i32 {
        xmlFatalErr(ctxt, XML_ERR_NOTATION_NOT_FINISHED, 0 as *const i8);
        (unsafe { xmlFreeEnumeration(ret) });
        return 0 as xmlEnumerationPtr;
    }
    (unsafe { xmlNextChar(ctxt) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlParseEnumerationType(mut ctxt: xmlParserCtxtPtr) -> xmlEnumerationPtr {
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut ret: xmlEnumerationPtr = 0 as xmlEnumerationPtr;
    let mut last: xmlEnumerationPtr = 0 as xmlEnumerationPtr;
    let mut cur: xmlEnumerationPtr = 0 as *mut xmlEnumeration;
    let mut tmp: xmlEnumerationPtr = 0 as *mut xmlEnumeration;
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '(' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ATTLIST_NOT_STARTED, 0 as *const i8);
        return 0 as xmlEnumerationPtr;
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
            > (2 as i32 * 250 as i32) as i64
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    loop {
        (unsafe { xmlNextChar(ctxt) });
        xmlSkipBlankChars(ctxt);
        name = xmlParseNmtoken(ctxt);
        if name.is_null() {
            xmlFatalErr(ctxt, XML_ERR_NMTOKEN_REQUIRED, 0 as *const i8);
            return ret;
        }
        tmp = ret;
        while !tmp.is_null() {
            if (unsafe { xmlStrEqual(name, (*tmp).name) }) != 0 {
                xmlValidityError(
                    ctxt,
                    XML_DTD_DUP_TOKEN,
                    b"standalone: attribute enumeration value token %s duplicated\n\0" as *const u8
                        as *const i8,
                    name,
                    0 as *const xmlChar,
                );
                if (unsafe { xmlDictOwns((*ctxt).dict, name) }) == 0 {
                    (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
                }
                break;
            } else {
                tmp = unsafe { (*tmp).next };
            }
        }
        if tmp.is_null() {
            cur = unsafe { xmlCreateEnumeration(name) };
            if (unsafe { xmlDictOwns((*ctxt).dict, name) }) == 0 {
                (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
            }
            if cur.is_null() {
                (unsafe { xmlFreeEnumeration(ret) });
                return 0 as xmlEnumerationPtr;
            }
            if last.is_null() {
                last = cur;
                ret = last;
            } else {
                let fresh255 = unsafe { &mut ((*last).next) };
                *fresh255 = cur;
                last = cur;
            }
        }
        xmlSkipBlankChars(ctxt);
        if !((unsafe { *(*(*ctxt).input).cur }) as i32 == '|' as i32) {
            break;
        }
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != ')' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ATTLIST_NOT_FINISHED, 0 as *const i8);
        return ret;
    }
    (unsafe { xmlNextChar(ctxt) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlParseEnumeratedType(
    mut ctxt: xmlParserCtxtPtr,
    mut tree: *mut xmlEnumerationPtr,
) -> i32 {
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == 'N' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'O' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'A' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'I' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'O' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) }) as i32 == 'N' as i32
    {
        let fresh256 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh256 = unsafe { (*fresh256).offset(8 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 8 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after 'NOTATION'\n\0" as *const u8 as *const i8,
            );
            return 0 as i32;
        }
        (unsafe { *tree = xmlParseNotationType(ctxt) });
        if (unsafe { *tree }).is_null() {
            return 0 as i32;
        }
        return XML_ATTRIBUTE_NOTATION as i32;
    }
    (unsafe { *tree = xmlParseEnumerationType(ctxt) });
    if (unsafe { *tree }).is_null() {
        return 0 as i32;
    }
    return XML_ATTRIBUTE_ENUMERATION as i32;
}
#[no_mangle]
pub extern "C" fn xmlParseAttributeType(
    mut ctxt: xmlParserCtxtPtr,
    mut tree: *mut xmlEnumerationPtr,
) -> i32 {
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
            > (2 as i32 * 250 as i32) as i64
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == 'C' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'D' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'A' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'A' as i32
    {
        let fresh257 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh257 = unsafe { (*fresh257).offset(5 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 5 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        return XML_ATTRIBUTE_CDATA as i32;
    } else {
        if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == 'I' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'D' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'R' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'E' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'F' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'S' as i32
        {
            let fresh258 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh258 = unsafe { (*fresh258).offset(6 as i32 as isize) };
            (unsafe { (*(*ctxt).input).col += 6 as i32 });
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
            }
            return XML_ATTRIBUTE_IDREFS as i32;
        } else {
            if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == 'I' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'D' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'R' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'E' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'F' as i32
            {
                let fresh259 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh259 = unsafe { (*fresh259).offset(5 as i32 as isize) };
                (unsafe { (*(*ctxt).input).col += 5 as i32 });
                if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                    (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                }
                return XML_ATTRIBUTE_IDREF as i32;
            } else {
                if (unsafe { *(*(*ctxt).input).cur }) as i32 == 'I' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == 'D' as i32
                {
                    let fresh260 = unsafe { &mut ((*(*ctxt).input).cur) };
                    *fresh260 = unsafe { (*fresh260).offset(2 as i32 as isize) };
                    (unsafe { (*(*ctxt).input).col += 2 as i32 });
                    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                        (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                    }
                    return XML_ATTRIBUTE_ID as i32;
                } else {
                    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32
                        == 'E' as i32
                        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32
                            == 'N' as i32
                        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32
                            == 'T' as i32
                        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32
                            == 'I' as i32
                        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32
                            == 'T' as i32
                        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32
                            == 'Y' as i32
                    {
                        let fresh261 = unsafe { &mut ((*(*ctxt).input).cur) };
                        *fresh261 = unsafe { (*fresh261).offset(6 as i32 as isize) };
                        (unsafe { (*(*ctxt).input).col += 6 as i32 });
                        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                        }
                        return XML_ATTRIBUTE_ENTITY as i32;
                    } else {
                        if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32
                            == 'E' as i32
                            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32
                                == 'N' as i32
                            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32
                                == 'T' as i32
                            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32
                                == 'I' as i32
                            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32
                                == 'T' as i32
                            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32
                                == 'I' as i32
                            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32
                                == 'E' as i32
                            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) }) as i32
                                == 'S' as i32
                        {
                            let fresh262 = unsafe { &mut ((*(*ctxt).input).cur) };
                            *fresh262 = unsafe { (*fresh262).offset(8 as i32 as isize) };
                            (unsafe { (*(*ctxt).input).col += 8 as i32 });
                            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                                (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                            }
                            return XML_ATTRIBUTE_ENTITIES as i32;
                        } else {
                            if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32
                                == 'N' as i32
                                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) })
                                    as i32
                                    == 'M' as i32
                                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) })
                                    as i32
                                    == 'T' as i32
                                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) })
                                    as i32
                                    == 'O' as i32
                                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) })
                                    as i32
                                    == 'K' as i32
                                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) })
                                    as i32
                                    == 'E' as i32
                                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) })
                                    as i32
                                    == 'N' as i32
                                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) })
                                    as i32
                                    == 'S' as i32
                            {
                                let fresh263 = unsafe { &mut ((*(*ctxt).input).cur) };
                                *fresh263 = unsafe { (*fresh263).offset(8 as i32 as isize) };
                                (unsafe { (*(*ctxt).input).col += 8 as i32 });
                                if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                                    (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                                }
                                return XML_ATTRIBUTE_NMTOKENS as i32;
                            } else {
                                if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) })
                                    as i32
                                    == 'N' as i32
                                    && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) })
                                        as i32
                                        == 'M' as i32
                                    && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) })
                                        as i32
                                        == 'T' as i32
                                    && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) })
                                        as i32
                                        == 'O' as i32
                                    && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) })
                                        as i32
                                        == 'K' as i32
                                    && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) })
                                        as i32
                                        == 'E' as i32
                                    && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) })
                                        as i32
                                        == 'N' as i32
                                {
                                    let fresh264 = unsafe { &mut ((*(*ctxt).input).cur) };
                                    *fresh264 = unsafe { (*fresh264).offset(7 as i32 as isize) };
                                    (unsafe { (*(*ctxt).input).col += 7 as i32 });
                                    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                                        (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
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
    return xmlParseEnumeratedType(ctxt, tree);
}
#[no_mangle]
pub extern "C" fn xmlParseAttributeListDecl(mut ctxt: xmlParserCtxtPtr) {
    let mut elemName: *const xmlChar = 0 as *const xmlChar;
    let mut attrName: *const xmlChar = 0 as *const xmlChar;
    let mut tree: xmlEnumerationPtr = 0 as *mut xmlEnumeration;
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == '!' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'A' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'L' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'I' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) }) as i32 == 'S' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(8 as i32 as isize) }) as i32 == 'T' as i32
    {
        let mut inputid: i32 = unsafe { (*(*ctxt).input).id };
        let fresh265 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh265 = unsafe { (*fresh265).offset(9 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 9 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after '<!ATTLIST'\n\0" as *const u8 as *const i8,
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
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        while (unsafe { *(*(*ctxt).input).cur }) as i32 != '>' as i32
            && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32
        {
            let mut type_0: i32 = 0;
            let mut def: i32 = 0;
            let mut defaultValue: *mut xmlChar = 0 as *mut xmlChar;
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            tree = 0 as xmlEnumerationPtr;
            attrName = xmlParseName(ctxt);
            if attrName.is_null() {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_NAME_REQUIRED,
                    b"ATTLIST: no name for Attribute\n\0" as *const u8 as *const i8,
                );
                break;
            } else {
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if xmlSkipBlankChars(ctxt) == 0 as i32 {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_SPACE_REQUIRED,
                        b"Space required after the attribute name\n\0" as *const u8 as *const i8,
                    );
                    break;
                } else {
                    type_0 = xmlParseAttributeType(ctxt, &mut tree);
                    if type_0 <= 0 as i32 {
                        break;
                    }
                    if (unsafe { (*ctxt).progressive }) == 0 as i32
                        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                            < 250 as i32 as i64
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
                            (unsafe { xmlFreeEnumeration(tree) });
                        }
                        break;
                    } else {
                        def = xmlParseDefaultDecl(ctxt, &mut defaultValue);
                        if def <= 0 as i32 {
                            if !defaultValue.is_null() {
                                (unsafe { xmlFree.expect("non-null function pointer")(
                                    defaultValue as *mut libc::c_void,
                                ) });
                            }
                            if !tree.is_null() {
                                (unsafe { xmlFreeEnumeration(tree) });
                            }
                            break;
                        } else {
                            if type_0 != XML_ATTRIBUTE_CDATA as i32 && !defaultValue.is_null() {
                                xmlAttrNormalizeSpace(defaultValue, defaultValue);
                            }
                            if (unsafe { (*ctxt).progressive }) == 0 as i32
                                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                                    < 250 as i32 as i64
                            {
                                xmlGROW(ctxt);
                            }
                            if (unsafe { *(*(*ctxt).input).cur }) as i32 != '>' as i32 {
                                if xmlSkipBlankChars(ctxt) == 0 as i32 {
                                    xmlFatalErrMsg(
                                        ctxt,
                                        XML_ERR_SPACE_REQUIRED,
                                        b"Space required after the attribute default value\n\0"
                                            as *const u8
                                            as *const i8,
                                    );
                                    if !defaultValue.is_null() {
                                        (unsafe { xmlFree.expect("non-null function pointer")(
                                            defaultValue as *mut libc::c_void,
                                        ) });
                                    }
                                    if !tree.is_null() {
                                        (unsafe { xmlFreeEnumeration(tree) });
                                    }
                                    break;
                                }
                            }
                            if !(unsafe { (*ctxt).sax }).is_null()
                                && (unsafe { (*ctxt).disableSAX }) == 0
                                && (unsafe { ((*(*ctxt).sax).attributeDecl).is_some() })
                            {
                                (unsafe { ((*(*ctxt).sax).attributeDecl).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                    elemName,
                                    attrName,
                                    type_0,
                                    def,
                                    defaultValue,
                                    tree,
                                ) });
                            } else if !tree.is_null() {
                                (unsafe { xmlFreeEnumeration(tree) });
                            }
                            if (unsafe { (*ctxt).sax2 }) != 0
                                && !defaultValue.is_null()
                                && def != XML_ATTRIBUTE_IMPLIED as i32
                                && def != XML_ATTRIBUTE_REQUIRED as i32
                            {
                                xmlAddDefAttrs(ctxt, elemName, attrName, defaultValue);
                            }
                            if (unsafe { (*ctxt).sax2 }) != 0 {
                                xmlAddSpecialAttr(ctxt, elemName, attrName, type_0);
                            }
                            if !defaultValue.is_null() {
                                (unsafe { xmlFree.expect("non-null function pointer")(
                                    defaultValue as *mut libc::c_void,
                                ) });
                            }
                            if (unsafe { (*ctxt).progressive }) == 0 as i32
                                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                                    < 250 as i32 as i64
                            {
                                xmlGROW(ctxt);
                            }
                        }
                    }
                }
            }
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '>' as i32 {
            if inputid != (unsafe { (*(*ctxt).input).id }) {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Attribute list declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const i8,
                );
            }
            (unsafe { xmlNextChar(ctxt) });
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlParseElementMixedContentDecl(
    mut ctxt: xmlParserCtxtPtr,
    mut inputchk: i32,
) -> xmlElementContentPtr {
    let mut ret: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut cur: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut n: xmlElementContentPtr = 0 as *mut xmlElementContent;
    let mut elem: *const xmlChar = 0 as *const xmlChar;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '#' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'P' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'C' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'D' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'A' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'A' as i32
    {
        let fresh266 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh266 = unsafe { (*fresh266).offset(7 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 7 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        xmlSkipBlankChars(ctxt);
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                > (2 as i32 * 250 as i32) as i64
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                < (2 as i32 * 250 as i32) as i64
        {
            xmlSHRINK(ctxt);
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == ')' as i32 {
            if (unsafe { (*(*ctxt).input).id }) != inputchk {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Element content declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const i8,
                );
            }
            (unsafe { xmlNextChar(ctxt) });
            ret = unsafe { xmlNewDocElementContent(
                (*ctxt).myDoc,
                0 as *const xmlChar,
                XML_ELEMENT_CONTENT_PCDATA,
            ) };
            if ret.is_null() {
                return 0 as xmlElementContentPtr;
            }
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == '*' as i32 {
                (unsafe { (*ret).ocur = XML_ELEMENT_CONTENT_MULT });
                (unsafe { xmlNextChar(ctxt) });
            }
            return ret;
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '(' as i32 || (unsafe { *(*(*ctxt).input).cur }) as i32 == '|' as i32
        {
            cur = unsafe { xmlNewDocElementContent(
                (*ctxt).myDoc,
                0 as *const xmlChar,
                XML_ELEMENT_CONTENT_PCDATA,
            ) };
            ret = cur;
            if ret.is_null() {
                return 0 as xmlElementContentPtr;
            }
        }
        while (unsafe { *(*(*ctxt).input).cur }) as i32 == '|' as i32
            && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32
        {
            (unsafe { xmlNextChar(ctxt) });
            if elem.is_null() {
                ret = unsafe { xmlNewDocElementContent(
                    (*ctxt).myDoc,
                    0 as *const xmlChar,
                    XML_ELEMENT_CONTENT_OR,
                ) };
                if ret.is_null() {
                    (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, cur) });
                    return 0 as xmlElementContentPtr;
                }
                let fresh267 = unsafe { &mut ((*ret).c1) };
                *fresh267 = cur;
                if !cur.is_null() {
                    let fresh268 = unsafe { &mut ((*cur).parent) };
                    *fresh268 = ret;
                }
                cur = ret;
            } else {
                n = unsafe { xmlNewDocElementContent(
                    (*ctxt).myDoc,
                    0 as *const xmlChar,
                    XML_ELEMENT_CONTENT_OR,
                ) };
                if n.is_null() {
                    (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, ret) });
                    return 0 as xmlElementContentPtr;
                }
                let fresh269 = unsafe { &mut ((*n).c1) };
                *fresh269 =
                    unsafe { xmlNewDocElementContent((*ctxt).myDoc, elem, XML_ELEMENT_CONTENT_ELEMENT) };
                if !(unsafe { (*n).c1 }).is_null() {
                    let fresh270 = unsafe { &mut ((*(*n).c1).parent) };
                    *fresh270 = n;
                }
                let fresh271 = unsafe { &mut ((*cur).c2) };
                *fresh271 = n;
                if !n.is_null() {
                    let fresh272 = unsafe { &mut ((*n).parent) };
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
                (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, ret) });
                return 0 as xmlElementContentPtr;
            }
            xmlSkipBlankChars(ctxt);
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == ')' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '*' as i32
        {
            if !elem.is_null() {
                let fresh273 = unsafe { &mut ((*cur).c2) };
                *fresh273 =
                    unsafe { xmlNewDocElementContent((*ctxt).myDoc, elem, XML_ELEMENT_CONTENT_ELEMENT) };
                if !(unsafe { (*cur).c2 }).is_null() {
                    let fresh274 = unsafe { &mut ((*(*cur).c2).parent) };
                    *fresh274 = cur;
                }
            }
            if !ret.is_null() {
                (unsafe { (*ret).ocur = XML_ELEMENT_CONTENT_MULT });
            }
            if (unsafe { (*(*ctxt).input).id }) != inputchk {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Element content declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const i8,
                );
            }
            let fresh275 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh275 = unsafe { (*fresh275).offset(2 as i32 as isize) };
            (unsafe { (*(*ctxt).input).col += 2 as i32 });
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
            }
        } else {
            (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, ret) });
            xmlFatalErr(ctxt, XML_ERR_MIXED_NOT_STARTED, 0 as *const i8);
            return 0 as xmlElementContentPtr;
        }
    } else {
        xmlFatalErr(ctxt, XML_ERR_PCDATA_REQUIRED, 0 as *const i8);
    }
    return ret;
}
extern "C" fn xmlParseElementChildrenContentDeclPriv(
    mut ctxt: xmlParserCtxtPtr,
    mut inputchk: i32,
    mut depth: i32,
) -> xmlElementContentPtr {
    let mut ret: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut cur: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut last: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut op: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut elem: *const xmlChar = 0 as *const xmlChar;
    let mut type_0: xmlChar = 0 as i32 as xmlChar;
    if depth > 128 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
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
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '(' as i32 {
        let mut inputid: i32 = unsafe { (*(*ctxt).input).id };
        (unsafe { xmlNextChar(ctxt) });
        xmlSkipBlankChars(ctxt);
        ret = xmlParseElementChildrenContentDeclPriv(ctxt, inputid, depth + 1 as i32);
        cur = ret;
        if cur.is_null() {
            return 0 as xmlElementContentPtr;
        }
        xmlSkipBlankChars(ctxt);
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
    } else {
        elem = xmlParseName(ctxt);
        if elem.is_null() {
            xmlFatalErr(ctxt, XML_ERR_ELEMCONTENT_NOT_STARTED, 0 as *const i8);
            return 0 as xmlElementContentPtr;
        }
        ret = unsafe { xmlNewDocElementContent((*ctxt).myDoc, elem, XML_ELEMENT_CONTENT_ELEMENT) };
        cur = ret;
        if cur.is_null() {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            return 0 as xmlElementContentPtr;
        }
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '?' as i32 {
            (unsafe { (*cur).ocur = XML_ELEMENT_CONTENT_OPT });
            (unsafe { xmlNextChar(ctxt) });
        } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '*' as i32 {
            (unsafe { (*cur).ocur = XML_ELEMENT_CONTENT_MULT });
            (unsafe { xmlNextChar(ctxt) });
        } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '+' as i32 {
            (unsafe { (*cur).ocur = XML_ELEMENT_CONTENT_PLUS });
            (unsafe { xmlNextChar(ctxt) });
        } else {
            (unsafe { (*cur).ocur = XML_ELEMENT_CONTENT_ONCE });
        }
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
    }
    xmlSkipBlankChars(ctxt);
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
            > (2 as i32 * 250 as i32) as i64
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    while (unsafe { *(*(*ctxt).input).cur }) as i32 != ')' as i32
        && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32
    {
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == ',' as i32 {
            if type_0 as i32 == 0 as i32 {
                type_0 = unsafe { *(*(*ctxt).input).cur };
            } else if type_0 as i32 != (unsafe { *(*(*ctxt).input).cur }) as i32 {
                xmlFatalErrMsgInt(
                    ctxt,
                    XML_ERR_SEPARATOR_REQUIRED,
                    b"xmlParseElementChildrenContentDecl : '%c' expected\n\0" as *const u8
                        as *const i8,
                    type_0 as i32,
                );
                if !last.is_null() && last != ret {
                    (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, last) });
                }
                if !ret.is_null() {
                    (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, ret) });
                }
                return 0 as xmlElementContentPtr;
            }
            (unsafe { xmlNextChar(ctxt) });
            op = unsafe { xmlNewDocElementContent(
                (*ctxt).myDoc,
                0 as *const xmlChar,
                XML_ELEMENT_CONTENT_SEQ,
            ) };
            if op.is_null() {
                if !last.is_null() && last != ret {
                    (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, last) });
                }
                (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, ret) });
                return 0 as xmlElementContentPtr;
            }
            if last.is_null() {
                let fresh276 = unsafe { &mut ((*op).c1) };
                *fresh276 = ret;
                if !ret.is_null() {
                    let fresh277 = unsafe { &mut ((*ret).parent) };
                    *fresh277 = op;
                }
                cur = op;
                ret = cur;
            } else {
                let fresh278 = unsafe { &mut ((*cur).c2) };
                *fresh278 = op;
                if !op.is_null() {
                    let fresh279 = unsafe { &mut ((*op).parent) };
                    *fresh279 = cur;
                }
                let fresh280 = unsafe { &mut ((*op).c1) };
                *fresh280 = last;
                if !last.is_null() {
                    let fresh281 = unsafe { &mut ((*last).parent) };
                    *fresh281 = op;
                }
                cur = op;
                last = 0 as xmlElementContentPtr;
            }
        } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '|' as i32 {
            if type_0 as i32 == 0 as i32 {
                type_0 = unsafe { *(*(*ctxt).input).cur };
            } else if type_0 as i32 != (unsafe { *(*(*ctxt).input).cur }) as i32 {
                xmlFatalErrMsgInt(
                    ctxt,
                    XML_ERR_SEPARATOR_REQUIRED,
                    b"xmlParseElementChildrenContentDecl : '%c' expected\n\0" as *const u8
                        as *const i8,
                    type_0 as i32,
                );
                if !last.is_null() && last != ret {
                    (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, last) });
                }
                if !ret.is_null() {
                    (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, ret) });
                }
                return 0 as xmlElementContentPtr;
            }
            (unsafe { xmlNextChar(ctxt) });
            op =
                unsafe { xmlNewDocElementContent((*ctxt).myDoc, 0 as *const xmlChar, XML_ELEMENT_CONTENT_OR) };
            if op.is_null() {
                if !last.is_null() && last != ret {
                    (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, last) });
                }
                if !ret.is_null() {
                    (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, ret) });
                }
                return 0 as xmlElementContentPtr;
            }
            if last.is_null() {
                let fresh282 = unsafe { &mut ((*op).c1) };
                *fresh282 = ret;
                if !ret.is_null() {
                    let fresh283 = unsafe { &mut ((*ret).parent) };
                    *fresh283 = op;
                }
                cur = op;
                ret = cur;
            } else {
                let fresh284 = unsafe { &mut ((*cur).c2) };
                *fresh284 = op;
                if !op.is_null() {
                    let fresh285 = unsafe { &mut ((*op).parent) };
                    *fresh285 = cur;
                }
                let fresh286 = unsafe { &mut ((*op).c1) };
                *fresh286 = last;
                if !last.is_null() {
                    let fresh287 = unsafe { &mut ((*last).parent) };
                    *fresh287 = op;
                }
                cur = op;
                last = 0 as xmlElementContentPtr;
            }
        } else {
            xmlFatalErr(ctxt, XML_ERR_ELEMCONTENT_NOT_FINISHED, 0 as *const i8);
            if !last.is_null() && last != ret {
                (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, last) });
            }
            if !ret.is_null() {
                (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, ret) });
            }
            return 0 as xmlElementContentPtr;
        }
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        xmlSkipBlankChars(ctxt);
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '(' as i32 {
            let mut inputid_0: i32 = unsafe { (*(*ctxt).input).id };
            (unsafe { xmlNextChar(ctxt) });
            xmlSkipBlankChars(ctxt);
            last = xmlParseElementChildrenContentDeclPriv(ctxt, inputid_0, depth + 1 as i32);
            if last.is_null() {
                if !ret.is_null() {
                    (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, ret) });
                }
                return 0 as xmlElementContentPtr;
            }
            xmlSkipBlankChars(ctxt);
        } else {
            elem = xmlParseName(ctxt);
            if elem.is_null() {
                xmlFatalErr(ctxt, XML_ERR_ELEMCONTENT_NOT_STARTED, 0 as *const i8);
                if !ret.is_null() {
                    (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, ret) });
                }
                return 0 as xmlElementContentPtr;
            }
            last = unsafe { xmlNewDocElementContent((*ctxt).myDoc, elem, XML_ELEMENT_CONTENT_ELEMENT) };
            if last.is_null() {
                if !ret.is_null() {
                    (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, ret) });
                }
                return 0 as xmlElementContentPtr;
            }
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == '?' as i32 {
                (unsafe { (*last).ocur = XML_ELEMENT_CONTENT_OPT });
                (unsafe { xmlNextChar(ctxt) });
            } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '*' as i32 {
                (unsafe { (*last).ocur = XML_ELEMENT_CONTENT_MULT });
                (unsafe { xmlNextChar(ctxt) });
            } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '+' as i32 {
                (unsafe { (*last).ocur = XML_ELEMENT_CONTENT_PLUS });
                (unsafe { xmlNextChar(ctxt) });
            } else {
                (unsafe { (*last).ocur = XML_ELEMENT_CONTENT_ONCE });
            }
        }
        xmlSkipBlankChars(ctxt);
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
    }
    if !cur.is_null() && !last.is_null() {
        let fresh288 = unsafe { &mut ((*cur).c2) };
        *fresh288 = last;
        if !last.is_null() {
            let fresh289 = unsafe { &mut ((*last).parent) };
            *fresh289 = cur;
        }
    }
    if (unsafe { (*(*ctxt).input).id }) != inputchk {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_ENTITY_BOUNDARY,
            b"Element content declaration doesn't start and stop in the same entity\n\0"
                as *const u8 as *const i8,
        );
    }
    (unsafe { xmlNextChar(ctxt) });
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '?' as i32 {
        if !ret.is_null() {
            if (unsafe { (*ret).ocur }) as u32 == XML_ELEMENT_CONTENT_PLUS as i32 as u32
                || (unsafe { (*ret).ocur }) as u32 == XML_ELEMENT_CONTENT_MULT as i32 as u32
            {
                (unsafe { (*ret).ocur = XML_ELEMENT_CONTENT_MULT });
            } else {
                (unsafe { (*ret).ocur = XML_ELEMENT_CONTENT_OPT });
            }
        }
        (unsafe { xmlNextChar(ctxt) });
    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '*' as i32 {
        if !ret.is_null() {
            (unsafe { (*ret).ocur = XML_ELEMENT_CONTENT_MULT });
            cur = ret;
            while !cur.is_null() && (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_CONTENT_OR as i32 as u32 {
                if !(unsafe { (*cur).c1 }).is_null()
                    && ((unsafe { (*(*cur).c1).ocur }) as u32 == XML_ELEMENT_CONTENT_OPT as i32 as u32
                        || (unsafe { (*(*cur).c1).ocur }) as u32 == XML_ELEMENT_CONTENT_MULT as i32 as u32)
                {
                    (unsafe { (*(*cur).c1).ocur = XML_ELEMENT_CONTENT_ONCE });
                }
                if !(unsafe { (*cur).c2 }).is_null()
                    && ((unsafe { (*(*cur).c2).ocur }) as u32 == XML_ELEMENT_CONTENT_OPT as i32 as u32
                        || (unsafe { (*(*cur).c2).ocur }) as u32 == XML_ELEMENT_CONTENT_MULT as i32 as u32)
                {
                    (unsafe { (*(*cur).c2).ocur = XML_ELEMENT_CONTENT_ONCE });
                }
                cur = unsafe { (*cur).c2 };
            }
        }
        (unsafe { xmlNextChar(ctxt) });
    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '+' as i32 {
        if !ret.is_null() {
            let mut found: i32 = 0 as i32;
            if (unsafe { (*ret).ocur }) as u32 == XML_ELEMENT_CONTENT_OPT as i32 as u32
                || (unsafe { (*ret).ocur }) as u32 == XML_ELEMENT_CONTENT_MULT as i32 as u32
            {
                (unsafe { (*ret).ocur = XML_ELEMENT_CONTENT_MULT });
            } else {
                (unsafe { (*ret).ocur = XML_ELEMENT_CONTENT_PLUS });
            }
            while !cur.is_null() && (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_CONTENT_OR as i32 as u32 {
                if !(unsafe { (*cur).c1 }).is_null()
                    && ((unsafe { (*(*cur).c1).ocur }) as u32 == XML_ELEMENT_CONTENT_OPT as i32 as u32
                        || (unsafe { (*(*cur).c1).ocur }) as u32 == XML_ELEMENT_CONTENT_MULT as i32 as u32)
                {
                    (unsafe { (*(*cur).c1).ocur = XML_ELEMENT_CONTENT_ONCE });
                    found = 1 as i32;
                }
                if !(unsafe { (*cur).c2 }).is_null()
                    && ((unsafe { (*(*cur).c2).ocur }) as u32 == XML_ELEMENT_CONTENT_OPT as i32 as u32
                        || (unsafe { (*(*cur).c2).ocur }) as u32 == XML_ELEMENT_CONTENT_MULT as i32 as u32)
                {
                    (unsafe { (*(*cur).c2).ocur = XML_ELEMENT_CONTENT_ONCE });
                    found = 1 as i32;
                }
                cur = unsafe { (*cur).c2 };
            }
            if found != 0 {
                (unsafe { (*ret).ocur = XML_ELEMENT_CONTENT_MULT });
            }
        }
        (unsafe { xmlNextChar(ctxt) });
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlParseElementChildrenContentDecl(
    mut ctxt: xmlParserCtxtPtr,
    mut inputchk: i32,
) -> xmlElementContentPtr {
    return xmlParseElementChildrenContentDeclPriv(ctxt, inputchk, 1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlParseElementContentDecl(
    mut ctxt: xmlParserCtxtPtr,
    mut name: *const xmlChar,
    mut result: *mut xmlElementContentPtr,
) -> i32 {
    let mut tree: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut inputid: i32 = unsafe { (*(*ctxt).input).id };
    let mut res: i32 = 0;
    (unsafe { *result = 0 as xmlElementContentPtr });
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '(' as i32 {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ELEMCONTENT_NOT_STARTED,
            b"xmlParseElementContentDecl : %s '(' expected\n\0" as *const u8 as *const i8,
            name,
        );
        return -(1 as i32);
    }
    (unsafe { xmlNextChar(ctxt) });
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    xmlSkipBlankChars(ctxt);
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '#' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'P' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'C' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'D' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'A' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'A' as i32
    {
        tree = xmlParseElementMixedContentDecl(ctxt, inputid);
        res = XML_ELEMENT_TYPE_MIXED as i32;
    } else {
        tree = xmlParseElementChildrenContentDeclPriv(ctxt, inputid, 1 as i32);
        res = XML_ELEMENT_TYPE_ELEMENT as i32;
    }
    xmlSkipBlankChars(ctxt);
    (unsafe { *result = tree });
    return res;
}
#[no_mangle]
pub extern "C" fn xmlParseElementDecl(mut ctxt: xmlParserCtxtPtr) -> i32 {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut ret: i32 = -(1 as i32);
    let mut content: xmlElementContentPtr = 0 as xmlElementContentPtr;
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == '!' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'E' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'L' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'E' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'M' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'E' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) }) as i32 == 'N' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(8 as i32 as isize) }) as i32 == 'T' as i32
    {
        let mut inputid: i32 = unsafe { (*(*ctxt).input).id };
        let fresh290 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh290 = unsafe { (*fresh290).offset(9 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 9 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
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
                b"xmlParseElementDecl: no name for Element\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        if xmlSkipBlankChars(ctxt) == 0 as i32 {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after the element name\n\0" as *const u8 as *const i8,
            );
        }
        if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == 'E' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'M' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'P' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'T' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'Y' as i32
        {
            let fresh291 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh291 = unsafe { (*fresh291).offset(5 as i32 as isize) };
            (unsafe { (*(*ctxt).input).col += 5 as i32 });
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
            }
            ret = XML_ELEMENT_TYPE_EMPTY as i32;
        } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == 'A' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == 'N' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == 'Y' as i32
        {
            let fresh292 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh292 = unsafe { (*fresh292).offset(3 as i32 as isize) };
            (unsafe { (*(*ctxt).input).col += 3 as i32 });
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
            }
            ret = XML_ELEMENT_TYPE_ANY as i32;
        } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '(' as i32 {
            ret = xmlParseElementContentDecl(ctxt, name, &mut content);
        } else {
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == '%' as i32
                && (unsafe { (*ctxt).external }) == 0 as i32
                && (unsafe { (*ctxt).inputNr }) == 1 as i32
            {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_PEREF_IN_INT_SUBSET,
                    b"PEReference: forbidden within markup decl in internal subset\n\0" as *const u8
                        as *const i8,
                );
            } else {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ELEMCONTENT_NOT_STARTED,
                    b"xmlParseElementDecl: 'EMPTY', 'ANY' or '(' expected\n\0" as *const u8
                        as *const i8,
                );
            }
            return -(1 as i32);
        }
        xmlSkipBlankChars(ctxt);
        if (unsafe { *(*(*ctxt).input).cur }) as i32 != '>' as i32 {
            xmlFatalErr(ctxt, XML_ERR_GT_REQUIRED, 0 as *const i8);
            if !content.is_null() {
                (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, content) });
            }
        } else {
            if inputid != (unsafe { (*(*ctxt).input).id }) {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Element declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const i8,
                );
            }
            (unsafe { xmlNextChar(ctxt) });
            if !(unsafe { (*ctxt).sax }).is_null()
                && (unsafe { (*ctxt).disableSAX }) == 0
                && (unsafe { ((*(*ctxt).sax).elementDecl).is_some() })
            {
                if !content.is_null() {
                    let fresh293 = unsafe { &mut ((*content).parent) };
                    *fresh293 = 0 as *mut _xmlElementContent;
                }
                (unsafe { ((*(*ctxt).sax).elementDecl).expect("non-null function pointer")(
                    (*ctxt).userData,
                    name,
                    ret,
                    content,
                ) });
                if !content.is_null() && (unsafe { (*content).parent }).is_null() {
                    (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, content) });
                }
            } else if !content.is_null() {
                (unsafe { xmlFreeDocElementContent((*ctxt).myDoc, content) });
            }
        }
    }
    return ret;
}
extern "C" fn xmlParseConditionalSections(mut ctxt: xmlParserCtxtPtr) {
    let mut inputIds: *mut i32 = 0 as *mut i32;
    let mut inputIdsSize: size_t = 0 as i32 as size_t;
    let mut depth: size_t = 0 as i32 as size_t;
    's_11: while (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32 {
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '!' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == '[' as i32
        {
            let mut id: i32 = unsafe { (*(*ctxt).input).id };
            let fresh294 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh294 = unsafe { (*fresh294).offset(3 as i32 as isize) };
            (unsafe { (*(*ctxt).input).col += 3 as i32 });
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
            }
            xmlSkipBlankChars(ctxt);
            if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == 'I' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'N' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'C' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'L' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'U' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'D' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'E' as i32
            {
                let fresh295 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh295 = unsafe { (*fresh295).offset(7 as i32 as isize) };
                (unsafe { (*(*ctxt).input).col += 7 as i32 });
                if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                    (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                }
                xmlSkipBlankChars(ctxt);
                if (unsafe { *(*(*ctxt).input).cur }) as i32 != '[' as i32 {
                    xmlFatalErr(ctxt, XML_ERR_CONDSEC_INVALID, 0 as *const i8);
                    xmlHaltParser(ctxt);
                    break;
                } else {
                    if (unsafe { (*(*ctxt).input).id }) != id {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_ENTITY_BOUNDARY,
                            b"All markup of the conditional section is not in the same entity\n\0"
                                as *const u8 as *const i8,
                        );
                    }
                    (unsafe { xmlNextChar(ctxt) });
                    if inputIdsSize <= depth {
                        let mut tmp: *mut i32 = 0 as *mut i32;
                        inputIdsSize = if inputIdsSize == 0 as i32 as u64 {
                            4 as i32 as u64
                        } else {
                            inputIdsSize.wrapping_mul(2 as i32 as u64)
                        };
                        tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                            inputIds as *mut libc::c_void,
                            inputIdsSize.wrapping_mul(::std::mem::size_of::<i32>() as u64),
                        ) }) as *mut i32;
                        if tmp.is_null() {
                            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                            break;
                        } else {
                            inputIds = tmp;
                        }
                    }
                    (unsafe { *inputIds.offset(depth as isize) = id });
                    depth = depth.wrapping_add(1);
                }
            } else if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32
                == 'I' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'G' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'N' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'O' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'R' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'E' as i32
            {
                let mut state: i32 = 0;
                let mut instate: xmlParserInputState = XML_PARSER_START;
                let mut ignoreDepth: size_t = 0 as i32 as size_t;
                let fresh296 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh296 = unsafe { (*fresh296).offset(6 as i32 as isize) };
                (unsafe { (*(*ctxt).input).col += 6 as i32 });
                if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                    (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                }
                xmlSkipBlankChars(ctxt);
                if (unsafe { *(*(*ctxt).input).cur }) as i32 != '[' as i32 {
                    xmlFatalErr(ctxt, XML_ERR_CONDSEC_INVALID, 0 as *const i8);
                    xmlHaltParser(ctxt);
                    break;
                } else {
                    if (unsafe { (*(*ctxt).input).id }) != id {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_ENTITY_BOUNDARY,
                            b"All markup of the conditional section is not in the same entity\n\0"
                                as *const u8 as *const i8,
                        );
                    }
                    (unsafe { xmlNextChar(ctxt) });
                    state = unsafe { (*ctxt).disableSAX };
                    instate = unsafe { (*ctxt).instate };
                    if (unsafe { (*ctxt).recovery }) == 0 as i32 {
                        (unsafe { (*ctxt).disableSAX = 1 as i32 });
                    }
                    (unsafe { (*ctxt).instate = XML_PARSER_IGNORE });
                    while (unsafe { *(*(*ctxt).input).cur }) as i32 != 0 as i32 {
                        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
                            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32
                                == '!' as i32
                            && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32
                                == '[' as i32
                        {
                            let fresh297 = unsafe { &mut ((*(*ctxt).input).cur) };
                            *fresh297 = unsafe { (*fresh297).offset(3 as i32 as isize) };
                            (unsafe { (*(*ctxt).input).col += 3 as i32 });
                            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                                (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                            }
                            ignoreDepth = ignoreDepth.wrapping_add(1);
                            if !(ignoreDepth == 0 as i32 as u64) {
                                continue;
                            }
                            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                            break 's_11;
                        } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == ']' as i32
                            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32
                                == ']' as i32
                            && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32
                                == '>' as i32
                        {
                            if ignoreDepth == 0 as i32 as u64 {
                                break;
                            }
                            let fresh298 = unsafe { &mut ((*(*ctxt).input).cur) };
                            *fresh298 = unsafe { (*fresh298).offset(3 as i32 as isize) };
                            (unsafe { (*(*ctxt).input).col += 3 as i32 });
                            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                                (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                            }
                            ignoreDepth = ignoreDepth.wrapping_sub(1);
                        } else {
                            (unsafe { xmlNextChar(ctxt) });
                        }
                    }
                    (unsafe { (*ctxt).disableSAX = state });
                    (unsafe { (*ctxt).instate = instate });
                    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                        xmlFatalErr(ctxt, XML_ERR_CONDSEC_NOT_FINISHED, 0 as *const i8);
                        break;
                    } else {
                        if (unsafe { (*(*ctxt).input).id }) != id {
                            xmlFatalErrMsg (ctxt , XML_ERR_ENTITY_BOUNDARY , b"All markup of the conditional section is not in the same entity\n\0" as * const u8 as * const i8 ,) ;
                        }
                        let fresh299 = unsafe { &mut ((*(*ctxt).input).cur) };
                        *fresh299 = unsafe { (*fresh299).offset(3 as i32 as isize) };
                        (unsafe { (*(*ctxt).input).col += 3 as i32 });
                        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                        }
                    }
                }
            } else {
                xmlFatalErr(ctxt, XML_ERR_CONDSEC_INVALID_KEYWORD, 0 as *const i8);
                xmlHaltParser(ctxt);
                break;
            }
        } else if depth > 0 as i32 as u64
            && (unsafe { *(*(*ctxt).input).cur }) as i32 == ']' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == ']' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == '>' as i32
        {
            depth = depth.wrapping_sub(1);
            if (unsafe { (*(*ctxt).input).id }) != (unsafe { *inputIds.offset(depth as isize) }) {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"All markup of the conditional section is not in the same entity\n\0"
                        as *const u8 as *const i8,
                );
            }
            let fresh300 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh300 = unsafe { (*fresh300).offset(3 as i32 as isize) };
            (unsafe { (*(*ctxt).input).col += 3 as i32 });
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
            }
        } else {
            let mut id_0: i32 = unsafe { (*(*ctxt).input).id };
            let mut cons: u64 = (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
            );
            xmlParseMarkupDecl(ctxt);
            if id_0 == (unsafe { (*(*ctxt).input).id })
                && cons
                    == (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                        (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
                    )
            {
                xmlFatalErr(ctxt, XML_ERR_EXT_SUBSET_NOT_FINISHED, 0 as *const i8);
                xmlHaltParser(ctxt);
                break;
            }
        }
        if depth == 0 as i32 as u64 {
            break;
        }
        xmlSkipBlankChars(ctxt);
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
    }
    (unsafe { xmlFree.expect("non-null function pointer")(inputIds as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlParseMarkupDecl(mut ctxt: xmlParserCtxtPtr) {
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32 {
        if (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '!' as i32 {
            match (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 {
                69 => {
                    if (unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) }) as i32 == 'L' as i32 {
                        xmlParseElementDecl(ctxt);
                    } else if (unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) }) as i32 == 'N' as i32
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
        } else if (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '?' as i32 {
            xmlParsePI(ctxt);
        }
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return;
    }
    (unsafe { (*ctxt).instate = XML_PARSER_DTD });
}
#[no_mangle]
pub extern "C" fn xmlParseTextDecl(mut ctxt: xmlParserCtxtPtr) {
    let mut version: *mut xmlChar = 0 as *mut xmlChar;
    let mut encoding: *const xmlChar = 0 as *const xmlChar;
    let mut oldstate: i32 = 0;
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == '?' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'x' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'm' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'l' as i32
        && ((unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 <= 0xa as i32
            || (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 == 0xd as i32)
    {
        let fresh301 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh301 = unsafe { (*fresh301).offset(5 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 5 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
    } else {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_STARTED, 0 as *const i8);
        return;
    }
    oldstate = (unsafe { (*ctxt).instate }) as i32;
    (unsafe { (*ctxt).instate = XML_PARSER_START });
    if xmlSkipBlankChars(ctxt) == 0 as i32 {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_SPACE_REQUIRED,
            b"Space needed after '<?xml'\n\0" as *const u8 as *const i8,
        );
    }
    version = xmlParseVersionInfo(ctxt);
    if version.is_null() {
        version = unsafe { xmlCharStrdup(b"1.0\0" as *const u8 as *const i8) };
    } else if xmlSkipBlankChars(ctxt) == 0 as i32 {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_SPACE_REQUIRED,
            b"Space needed here\n\0" as *const u8 as *const i8,
        );
    }
    let fresh302 = unsafe { &mut ((*(*ctxt).input).version) };
    *fresh302 = version;
    encoding = xmlParseEncodingDecl(ctxt);
    if (unsafe { (*ctxt).errNo }) == XML_ERR_UNSUPPORTED_ENCODING as i32 {
        (unsafe { (*ctxt).instate = oldstate as xmlParserInputState });
        return;
    }
    if encoding.is_null() && (unsafe { (*ctxt).errNo }) == XML_ERR_OK as i32 {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_MISSING_ENCODING,
            b"Missing encoding in text declaration\n\0" as *const u8 as *const i8,
        );
    }
    xmlSkipBlankChars(ctxt);
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '?' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '>' as i32
    {
        let fresh303 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh303 = unsafe { (*fresh303).offset(2 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 2 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '>' as i32 {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, 0 as *const i8);
        (unsafe { xmlNextChar(ctxt) });
    } else {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, 0 as *const i8);
        while (unsafe { *(*(*ctxt).input).cur }) as i32 != 0 && (unsafe { *(*(*ctxt).input).cur }) as i32 != '>' as i32 {
            let fresh304 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh304 = unsafe { (*fresh304).offset(1) };
        }
        (unsafe { xmlNextChar(ctxt) });
    }
    (unsafe { (*ctxt).instate = oldstate as xmlParserInputState });
}
#[no_mangle]
pub extern "C" fn xmlParseExternalSubset(
    mut ctxt: xmlParserCtxtPtr,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) {
    xmlDetectSAX2(ctxt);
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { (*ctxt).encoding }).is_null()
        && (unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64 >= 4 as i32 as i64
    {
        let mut start: [xmlChar; 4] = [0; 4];
        let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
        start[0 as i32 as usize] = unsafe { *(*(*ctxt).input).cur };
        start[1 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) };
        start[2 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) };
        start[3 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) };
        enc = unsafe { xmlDetectCharEncoding(start.as_mut_ptr(), 4 as i32) };
        if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
            (unsafe { xmlSwitchEncoding(ctxt, enc) });
        }
    }
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == '?' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'x' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'm' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'l' as i32
    {
        xmlParseTextDecl(ctxt);
        if (unsafe { (*ctxt).errNo }) == XML_ERR_UNSUPPORTED_ENCODING as i32 {
            xmlHaltParser(ctxt);
            return;
        }
    }
    if (unsafe { (*ctxt).myDoc }).is_null() {
        let fresh305 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh305 = unsafe { xmlNewDoc(b"1.0\0" as *const u8 as *const i8 as *mut xmlChar) };
        if (unsafe { (*ctxt).myDoc }).is_null() {
            (unsafe { xmlErrMemory(ctxt, b"New Doc failed\0" as *const u8 as *const i8) });
            return;
        }
        (unsafe { (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as i32 });
    }
    if !(unsafe { (*ctxt).myDoc }).is_null() && (unsafe { (*(*ctxt).myDoc).intSubset }).is_null() {
        (unsafe { xmlCreateIntSubset((*ctxt).myDoc, 0 as *const xmlChar, ExternalID, SystemID) });
    }
    (unsafe { (*ctxt).instate = XML_PARSER_DTD });
    (unsafe { (*ctxt).external = 1 as i32 });
    xmlSkipBlankChars(ctxt);
    while (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '?' as i32
        || (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '!' as i32
        || (unsafe { *(*(*ctxt).input).cur }) as i32 == '%' as i32
    {
        let mut id: i32 = unsafe { (*(*ctxt).input).id };
        let mut cons: u64 = (unsafe { (*(*ctxt).input).consumed })
            .wrapping_add((unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64);
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '!' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == '[' as i32
        {
            xmlParseConditionalSections(ctxt);
        } else {
            xmlParseMarkupDecl(ctxt);
        }
        xmlSkipBlankChars(ctxt);
        if !(id == (unsafe { (*(*ctxt).input).id })
            && cons
                == (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                    (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
                ))
        {
            continue;
        }
        xmlFatalErr(ctxt, XML_ERR_EXT_SUBSET_NOT_FINISHED, 0 as *const i8);
        break;
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_EXT_SUBSET_NOT_FINISHED, 0 as *const i8);
    }
}
#[no_mangle]
pub extern "C" fn xmlParseReference(mut ctxt: xmlParserCtxtPtr) {
    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    let mut was_checked: i32 = 0;
    let mut list: xmlNodePtr = 0 as xmlNodePtr;
    let mut ret: xmlParserErrors = XML_ERR_OK;
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '&' as i32 {
        return;
    }
    if (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '#' as i32 {
        let mut i: i32 = 0 as i32;
        let mut out: [xmlChar; 16] = [0; 16];
        let mut hex: i32 = (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32;
        let mut value: i32 = xmlParseCharRef(ctxt);
        if value == 0 as i32 {
            return;
        }
        if (unsafe { (*ctxt).charset }) != XML_CHAR_ENCODING_UTF8 as i32 {
            if value <= 0xff as i32 {
                out[0 as i32 as usize] = value as xmlChar;
                out[1 as i32 as usize] = 0 as i32 as xmlChar;
                if !(unsafe { (*ctxt).sax }).is_null()
                    && (unsafe { ((*(*ctxt).sax).characters).is_some() })
                    && (unsafe { (*ctxt).disableSAX }) == 0
                {
                    (unsafe { ((*(*ctxt).sax).characters).expect("non-null function pointer")(
                        (*ctxt).userData,
                        out.as_mut_ptr(),
                        1 as i32,
                    ) });
                }
            } else {
                if hex == 'x' as i32 || hex == 'X' as i32 {
                    (unsafe { snprintf(
                        out.as_mut_ptr() as *mut i8,
                        ::std::mem::size_of::<[xmlChar; 16]>() as u64,
                        b"#x%X\0" as *const u8 as *const i8,
                        value,
                    ) });
                } else {
                    (unsafe { snprintf(
                        out.as_mut_ptr() as *mut i8,
                        ::std::mem::size_of::<[xmlChar; 16]>() as u64,
                        b"#%d\0" as *const u8 as *const i8,
                        value,
                    ) });
                }
                if !(unsafe { (*ctxt).sax }).is_null()
                    && (unsafe { ((*(*ctxt).sax).reference).is_some() })
                    && (unsafe { (*ctxt).disableSAX }) == 0
                {
                    (unsafe { ((*(*ctxt).sax).reference).expect("non-null function pointer")(
                        (*ctxt).userData,
                        out.as_mut_ptr(),
                    ) });
                }
            }
        } else {
            if 0 as i32 == 1 as i32 {
                let fresh306 = i;
                i = i + 1;
                out[fresh306 as usize] = value as xmlChar;
            } else {
                i += unsafe { xmlCopyCharMultiByte(&mut *out.as_mut_ptr().offset(i as isize), value) };
            }
            out[i as usize] = 0 as i32 as xmlChar;
            if !(unsafe { (*ctxt).sax }).is_null()
                && (unsafe { ((*(*ctxt).sax).characters).is_some() })
                && (unsafe { (*ctxt).disableSAX }) == 0
            {
                (unsafe { ((*(*ctxt).sax).characters).expect("non-null function pointer")(
                    (*ctxt).userData,
                    out.as_mut_ptr(),
                    i,
                ) });
            }
        }
        return;
    }
    ent = xmlParseEntityRef(ctxt);
    if ent.is_null() {
        return;
    }
    if (unsafe { (*ctxt).wellFormed }) == 0 {
        return;
    }
    was_checked = unsafe { (*ent).checked };
    if (unsafe { (*ent).name }).is_null()
        || (unsafe { (*ent).etype }) as u32 == XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
    {
        val = unsafe { (*ent).content };
        if val.is_null() {
            return;
        }
        if !(unsafe { (*ctxt).sax }).is_null()
            && (unsafe { ((*(*ctxt).sax).characters).is_some() })
            && (unsafe { (*ctxt).disableSAX }) == 0
        {
            (unsafe { ((*(*ctxt).sax).characters).expect("non-null function pointer")(
                (*ctxt).userData,
                val,
                xmlStrlen(val),
            ) });
        }
        return;
    }
    if ((unsafe { (*ent).checked }) == 0 as i32
        || (unsafe { (*ent).children }).is_null() && (unsafe { (*ctxt).options }) & XML_PARSE_NOENT as i32 != 0)
        && ((unsafe { (*ent).etype }) as u32 != XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32
            || (unsafe { (*ctxt).options }) & (XML_PARSE_NOENT as i32 | XML_PARSE_DTDVALID as i32) != 0)
    {
        let mut oldnbent: u64 = unsafe { (*ctxt).nbentities };
        let mut diff: u64 = 0;
        let mut user_data: *mut libc::c_void = 0 as *mut libc::c_void;
        if (unsafe { (*ctxt).userData }) == ctxt as *mut libc::c_void {
            user_data = 0 as *mut libc::c_void;
        } else {
            user_data = unsafe { (*ctxt).userData };
        }
        if (unsafe { (*ent).etype }) as u32 == XML_INTERNAL_GENERAL_ENTITY as i32 as u32 {
            let fresh307 = unsafe { &mut ((*ctxt).depth) };
            *fresh307 += 1;
            ret = xmlParseBalancedChunkMemoryInternal(ctxt, unsafe { (*ent).content }, user_data, &mut list);
            let fresh308 = unsafe { &mut ((*ctxt).depth) };
            *fresh308 -= 1;
        } else if (unsafe { (*ent).etype }) as u32 == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32 {
            let fresh309 = unsafe { &mut ((*ctxt).depth) };
            *fresh309 += 1;
            ret = xmlParseExternalEntityPrivate(
                unsafe { (*ctxt).myDoc },
                ctxt,
                unsafe { (*ctxt).sax },
                user_data,
                unsafe { (*ctxt).depth },
                unsafe { (*ent).URI },
                unsafe { (*ent).ExternalID },
                &mut list,
            );
            let fresh310 = unsafe { &mut ((*ctxt).depth) };
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
        diff = (unsafe { (*ctxt).nbentities })
            .wrapping_sub(oldnbent)
            .wrapping_add(1 as i32 as u64);
        if diff > (2147483647 as i32 / 2 as i32) as u64 {
            diff = (2147483647 as i32 / 2 as i32) as u64;
        }
        (unsafe { (*ent).checked = diff.wrapping_mul(2 as i32 as u64) as i32 });
        if !(unsafe { (*ent).content }).is_null()
            && !(unsafe { xmlStrchr((*ent).content, '<' as i32 as xmlChar) }).is_null()
        {
            (unsafe { (*ent).checked |= 1 as i32 });
        }
        if ret as u32 == XML_ERR_ENTITY_LOOP as i32 as u32 {
            xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const i8);
            xmlHaltParser(ctxt);
            (unsafe { xmlFreeNodeList(list) });
            return;
        }
        if xmlParserEntityCheck(ctxt, 0 as i32 as size_t, ent, 0 as i32 as size_t) != 0 {
            (unsafe { xmlFreeNodeList(list) });
            return;
        }
        if ret as u32 == XML_ERR_OK as i32 as u32 && !list.is_null() {
            if ((unsafe { (*ent).etype }) as u32 == XML_INTERNAL_GENERAL_ENTITY as i32 as u32
                || (unsafe { (*ent).etype }) as u32 == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32)
                && (unsafe { (*ent).children }).is_null()
            {
                let fresh311 = unsafe { &mut ((*ent).children) };
                *fresh311 = list;
                if (unsafe { (*ctxt).replaceEntities }) == 0 as i32
                    || (unsafe { (*ctxt).parseMode }) as u32 == XML_PARSE_READER as i32 as u32
                    || (unsafe { (*list).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
                        && (unsafe { (*list).next }).is_null()
                {
                    (unsafe { (*ent).owner = 1 as i32 });
                    while !list.is_null() {
                        let fresh312 = unsafe { &mut ((*list).parent) };
                        *fresh312 = ent as xmlNodePtr;
                        if (unsafe { (*list).doc }) != (unsafe { (*ent).doc }) {
                            (unsafe { xmlSetTreeDoc(list, (*ent).doc) });
                        }
                        if (unsafe { (*list).next }).is_null() {
                            let fresh313 = unsafe { &mut ((*ent).last) };
                            *fresh313 = list;
                        }
                        list = unsafe { (*list).next };
                    }
                    list = 0 as xmlNodePtr;
                } else {
                    (unsafe { (*ent).owner = 0 as i32 });
                    while !list.is_null() {
                        let fresh314 = unsafe { &mut ((*list).parent) };
                        *fresh314 = unsafe { (*ctxt).node };
                        let fresh315 = unsafe { &mut ((*list).doc) };
                        *fresh315 = unsafe { (*ctxt).myDoc };
                        if (unsafe { (*list).next }).is_null() {
                            let fresh316 = unsafe { &mut ((*ent).last) };
                            *fresh316 = list;
                        }
                        list = unsafe { (*list).next };
                    }
                    list = unsafe { (*ent).children };
                    if (unsafe { (*ent).etype }) as u32 == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32 {
                        xmlAddEntityReference(ent, list, 0 as xmlNodePtr);
                    }
                }
            } else {
                (unsafe { xmlFreeNodeList(list) });
                list = 0 as xmlNodePtr;
            }
        } else if ret as u32 != XML_ERR_OK as i32 as u32
            && ret as u32 != XML_WAR_UNDECLARED_ENTITY as i32 as u32
        {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNDECLARED_ENTITY,
                b"Entity '%s' failed to parse\n\0" as *const u8 as *const i8,
                unsafe { (*ent).name },
            );
            if !(unsafe { (*ent).content }).is_null() {
                (unsafe { *((*ent).content).offset(0 as i32 as isize) = 0 as i32 as xmlChar });
            }
            xmlParserEntityCheck(ctxt, 0 as i32 as size_t, ent, 0 as i32 as size_t);
        } else if !list.is_null() {
            (unsafe { xmlFreeNodeList(list) });
            list = 0 as xmlNodePtr;
        }
        if (unsafe { (*ent).checked }) == 0 as i32 {
            (unsafe { (*ent).checked = 2 as i32 });
        }
        was_checked = 0 as i32;
    } else if (unsafe { (*ent).checked }) != 1 as i32 {
        let fresh317 = unsafe { &mut ((*ctxt).nbentities) };
        *fresh317 = (*fresh317).wrapping_add(((unsafe { (*ent).checked }) / 2 as i32) as u64);
    }
    if (unsafe { (*ent).children }).is_null() {
        if was_checked != 0 as i32 {
            let mut user_data_0: *mut libc::c_void = 0 as *mut libc::c_void;
            if (unsafe { (*ctxt).userData }) == ctxt as *mut libc::c_void {
                user_data_0 = 0 as *mut libc::c_void;
            } else {
                user_data_0 = unsafe { (*ctxt).userData };
            }
            if (unsafe { (*ent).etype }) as u32 == XML_INTERNAL_GENERAL_ENTITY as i32 as u32 {
                let fresh318 = unsafe { &mut ((*ctxt).depth) };
                *fresh318 += 1;
                ret = xmlParseBalancedChunkMemoryInternal(
                    ctxt,
                    unsafe { (*ent).content },
                    user_data_0,
                    0 as *mut xmlNodePtr,
                );
                let fresh319 = unsafe { &mut ((*ctxt).depth) };
                *fresh319 -= 1;
            } else if (unsafe { (*ent).etype }) as u32 == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32 {
                let fresh320 = unsafe { &mut ((*ctxt).depth) };
                *fresh320 += 1;
                ret = xmlParseExternalEntityPrivate(
                    unsafe { (*ctxt).myDoc },
                    ctxt,
                    unsafe { (*ctxt).sax },
                    user_data_0,
                    unsafe { (*ctxt).depth },
                    unsafe { (*ent).URI },
                    unsafe { (*ent).ExternalID },
                    0 as *mut xmlNodePtr,
                );
                let fresh321 = unsafe { &mut ((*ctxt).depth) };
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
            if ret as u32 == XML_ERR_ENTITY_LOOP as i32 as u32 {
                xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const i8);
                return;
            }
        }
        if !(unsafe { (*ctxt).sax }).is_null()
            && (unsafe { ((*(*ctxt).sax).reference).is_some() })
            && (unsafe { (*ctxt).replaceEntities }) == 0 as i32
            && (unsafe { (*ctxt).disableSAX }) == 0
        {
            (unsafe { ((*(*ctxt).sax).reference).expect("non-null function pointer")(
                (*ctxt).userData,
                (*ent).name,
            ) });
        }
        return;
    }
    if !(unsafe { (*ctxt).sax }).is_null()
        && (unsafe { ((*(*ctxt).sax).reference).is_some() })
        && (unsafe { (*ctxt).replaceEntities }) == 0 as i32
        && (unsafe { (*ctxt).disableSAX }) == 0
    {
        (unsafe { ((*(*ctxt).sax).reference).expect("non-null function pointer")(
            (*ctxt).userData,
            (*ent).name,
        ) });
        return;
    }
    if (unsafe { (*ctxt).replaceEntities }) != 0 || (unsafe { (*ent).children }).is_null() {
        if !(unsafe { (*ctxt).node }).is_null() && !(unsafe { (*ent).children }).is_null() {
            if list.is_null() && (unsafe { (*ent).owner }) == 0 as i32
                || (unsafe { (*ctxt).parseMode }) as u32 == XML_PARSE_READER as i32 as u32
            {
                let mut nw: xmlNodePtr = 0 as xmlNodePtr;
                let mut cur: xmlNodePtr = 0 as *mut xmlNode;
                let mut firstChild: xmlNodePtr = 0 as xmlNodePtr;
                let fresh322 = unsafe { &mut ((*ctxt).sizeentcopy) };
                *fresh322 = (*fresh322).wrapping_add(((unsafe { (*ent).length }) + 5 as i32) as u64);
                if xmlParserEntityCheck(ctxt, 0 as i32 as size_t, ent, unsafe { (*ctxt).sizeentcopy }) != 0 {
                    return;
                }
                cur = unsafe { (*ent).children };
                while !cur.is_null() {
                    nw = unsafe { xmlDocCopyNode(cur, (*ctxt).myDoc, 1 as i32) };
                    if !nw.is_null() {
                        if (unsafe { (*nw)._private }).is_null() {
                            let fresh323 = unsafe { &mut ((*nw)._private) };
                            *fresh323 = unsafe { (*cur)._private };
                        }
                        if firstChild.is_null() {
                            firstChild = nw;
                        }
                        nw = unsafe { xmlAddChild((*ctxt).node, nw) };
                    }
                    if cur == (unsafe { (*ent).last }) {
                        if (unsafe { (*ctxt).parseMode }) as u32 == XML_PARSE_READER as i32 as u32
                            && !nw.is_null()
                            && (unsafe { (*nw).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                            && (unsafe { (*nw).children }).is_null()
                        {
                            (unsafe { (*nw).extra = 1 as i32 as u16 });
                        }
                        break;
                    } else {
                        cur = unsafe { (*cur).next };
                    }
                }
                if (unsafe { (*ent).etype }) as u32 == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32 {
                    xmlAddEntityReference(ent, firstChild, nw);
                }
            } else if list.is_null() || (unsafe { (*ctxt).inputNr }) > 0 as i32 {
                let mut nw_0: xmlNodePtr = 0 as xmlNodePtr;
                let mut cur_0: xmlNodePtr = 0 as *mut xmlNode;
                let mut next: xmlNodePtr = 0 as *mut xmlNode;
                let mut last: xmlNodePtr = 0 as *mut xmlNode;
                let mut firstChild_0: xmlNodePtr = 0 as xmlNodePtr;
                let fresh324 = unsafe { &mut ((*ctxt).sizeentcopy) };
                *fresh324 = (*fresh324).wrapping_add(((unsafe { (*ent).length }) + 5 as i32) as u64);
                if xmlParserEntityCheck(ctxt, 0 as i32 as size_t, ent, unsafe { (*ctxt).sizeentcopy }) != 0 {
                    return;
                }
                cur_0 = unsafe { (*ent).children };
                let fresh325 = unsafe { &mut ((*ent).children) };
                *fresh325 = 0 as *mut _xmlNode;
                last = unsafe { (*ent).last };
                let fresh326 = unsafe { &mut ((*ent).last) };
                *fresh326 = 0 as *mut _xmlNode;
                while !cur_0.is_null() {
                    next = unsafe { (*cur_0).next };
                    let fresh327 = unsafe { &mut ((*cur_0).next) };
                    *fresh327 = 0 as *mut _xmlNode;
                    let fresh328 = unsafe { &mut ((*cur_0).parent) };
                    *fresh328 = 0 as *mut _xmlNode;
                    nw_0 = unsafe { xmlDocCopyNode(cur_0, (*ctxt).myDoc, 1 as i32) };
                    if !nw_0.is_null() {
                        if (unsafe { (*nw_0)._private }).is_null() {
                            let fresh329 = unsafe { &mut ((*nw_0)._private) };
                            *fresh329 = unsafe { (*cur_0)._private };
                        }
                        if firstChild_0.is_null() {
                            firstChild_0 = cur_0;
                        }
                        (unsafe { xmlAddChild(ent as xmlNodePtr, nw_0) });
                        (unsafe { xmlAddChild((*ctxt).node, cur_0) });
                    }
                    if cur_0 == last {
                        break;
                    }
                    cur_0 = next;
                }
                if (unsafe { (*ent).owner }) == 0 as i32 {
                    (unsafe { (*ent).owner = 1 as i32 });
                }
                if (unsafe { (*ent).etype }) as u32 == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32 {
                    xmlAddEntityReference(ent, firstChild_0, nw_0);
                }
            } else {
                let mut nbktext: *const xmlChar = 0 as *const xmlChar;
                nbktext = unsafe { xmlDictLookup(
                    (*ctxt).dict,
                    b"nbktext\0" as *const u8 as *const i8 as *mut xmlChar,
                    -(1 as i32),
                ) };
                if (unsafe { (*(*ent).children).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32 {
                    let fresh330 = unsafe { &mut ((*(*ent).children).name) };
                    *fresh330 = nbktext;
                }
                if (unsafe { (*ent).last }) != (unsafe { (*ent).children })
                    && (unsafe { (*(*ent).last).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
                {
                    let fresh331 = unsafe { &mut ((*(*ent).last).name) };
                    *fresh331 = nbktext;
                }
                (unsafe { xmlAddChildList((*ctxt).node, (*ent).children) });
            }
            (unsafe { (*ctxt).nodemem = 0 as i32 });
            (unsafe { (*ctxt).nodelen = 0 as i32 });
            return;
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlParseEntityRef(mut ctxt: xmlParserCtxtPtr) -> xmlEntityPtr {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut ent: xmlEntityPtr = 0 as xmlEntityPtr;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return 0 as xmlEntityPtr;
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '&' as i32 {
        return 0 as xmlEntityPtr;
    }
    (unsafe { xmlNextChar(ctxt) });
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseEntityRef: no name\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlEntityPtr;
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != ';' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ENTITYREF_SEMICOL_MISSING, 0 as *const i8);
        return 0 as xmlEntityPtr;
    }
    (unsafe { xmlNextChar(ctxt) });
    if (unsafe { (*ctxt).options }) & XML_PARSE_OLDSAX as i32 == 0 as i32 {
        ent = unsafe { xmlGetPredefinedEntity(name) };
        if !ent.is_null() {
            return ent;
        }
    }
    let fresh332 = unsafe { &mut ((*ctxt).nbentities) };
    *fresh332 = (*fresh332).wrapping_add(1);
    if !(unsafe { (*ctxt).sax }).is_null() {
        if unsafe { ((*(*ctxt).sax).getEntity).is_some() } {
            ent = unsafe { ((*(*ctxt).sax).getEntity).expect("non-null function pointer")(
                (*ctxt).userData,
                name,
            ) };
        }
        if (unsafe { (*ctxt).wellFormed }) == 1 as i32
            && ent.is_null()
            && (unsafe { (*ctxt).options }) & XML_PARSE_OLDSAX as i32 != 0
        {
            ent = unsafe { xmlGetPredefinedEntity(name) };
        }
        if (unsafe { (*ctxt).wellFormed }) == 1 as i32
            && ent.is_null()
            && (unsafe { (*ctxt).userData }) == ctxt as *mut libc::c_void
        {
            ent = unsafe { xmlSAX2GetEntity(ctxt as *mut libc::c_void, name) };
        }
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return 0 as xmlEntityPtr;
    }
    if ent.is_null() {
        if (unsafe { (*ctxt).standalone }) == 1 as i32
            || (unsafe { (*ctxt).hasExternalSubset }) == 0 as i32 && (unsafe { (*ctxt).hasPErefs }) == 0 as i32
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
            if (unsafe { (*ctxt).inSubset }) == 0 as i32
                && !(unsafe { (*ctxt).sax }).is_null()
                && (unsafe { ((*(*ctxt).sax).reference).is_some() })
            {
                (unsafe { ((*(*ctxt).sax).reference).expect("non-null function pointer")(
                    (*ctxt).userData,
                    name,
                ) });
            }
        }
        xmlParserEntityCheck(ctxt, 0 as i32 as size_t, ent, 0 as i32 as size_t);
        (unsafe { (*ctxt).valid = 0 as i32 });
    } else if (unsafe { (*ent).etype }) as u32 == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as i32 as u32 {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_UNPARSED_ENTITY,
            b"Entity reference to unparsed entity %s\n\0" as *const u8 as *const i8,
            name,
        );
    } else if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_ATTRIBUTE_VALUE as i32
        && (unsafe { (*ent).etype }) as u32 == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32
    {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ENTITY_IS_EXTERNAL,
            b"Attribute references external entity '%s'\n\0" as *const u8 as *const i8,
            name,
        );
    } else if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_ATTRIBUTE_VALUE as i32
        && !ent.is_null()
        && (unsafe { (*ent).etype }) as u32 != XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
    {
        if ((unsafe { (*ent).checked }) & 1 as i32 != 0 || (unsafe { (*ent).checked }) == 0 as i32)
            && !(unsafe { (*ent).content }).is_null()
            && !(unsafe { xmlStrchr((*ent).content, '<' as i32 as xmlChar) }).is_null()
        {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_LT_IN_ATTRIBUTE,
                b"'<' in entity '%s' is not allowed in attributes values\n\0" as *const u8
                    as *const i8,
                name,
            );
        }
    } else {
        match (unsafe { (*ent).etype }) as u32 {
            4 | 5 => {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_ENTITY_IS_PARAMETER,
                    b"Attempt to reference the parameter entity '%s'\n\0" as *const u8 as *const i8,
                    name,
                );
            }
            _ => {}
        }
    }
    return ent;
}
extern "C" fn xmlParseStringEntityRef(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *mut *const xmlChar,
) -> xmlEntityPtr {
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut ptr: *const xmlChar = 0 as *const xmlChar;
    let mut cur: xmlChar = 0;
    let mut ent: xmlEntityPtr = 0 as xmlEntityPtr;
    if str.is_null() || (unsafe { *str }).is_null() {
        return 0 as xmlEntityPtr;
    }
    ptr = unsafe { *str };
    cur = unsafe { *ptr };
    if cur as i32 != '&' as i32 {
        return 0 as xmlEntityPtr;
    }
    ptr = unsafe { ptr.offset(1) };
    name = xmlParseStringName(ctxt, &mut ptr);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseStringEntityRef: no name\n\0" as *const u8 as *const i8,
        );
        (unsafe { *str = ptr });
        return 0 as xmlEntityPtr;
    }
    if (unsafe { *ptr }) as i32 != ';' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ENTITYREF_SEMICOL_MISSING, 0 as *const i8);
        (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
        (unsafe { *str = ptr });
        return 0 as xmlEntityPtr;
    }
    ptr = unsafe { ptr.offset(1) };
    if (unsafe { (*ctxt).options }) & XML_PARSE_OLDSAX as i32 == 0 as i32 {
        ent = unsafe { xmlGetPredefinedEntity(name) };
        if !ent.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
            (unsafe { *str = ptr });
            return ent;
        }
    }
    let fresh333 = unsafe { &mut ((*ctxt).nbentities) };
    *fresh333 = (*fresh333).wrapping_add(1);
    if !(unsafe { (*ctxt).sax }).is_null() {
        if unsafe { ((*(*ctxt).sax).getEntity).is_some() } {
            ent = unsafe { ((*(*ctxt).sax).getEntity).expect("non-null function pointer")(
                (*ctxt).userData,
                name,
            ) };
        }
        if ent.is_null() && (unsafe { (*ctxt).options }) & XML_PARSE_OLDSAX as i32 != 0 {
            ent = unsafe { xmlGetPredefinedEntity(name) };
        }
        if ent.is_null() && (unsafe { (*ctxt).userData }) == ctxt as *mut libc::c_void {
            ent = unsafe { xmlSAX2GetEntity(ctxt as *mut libc::c_void, name) };
        }
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
        return 0 as xmlEntityPtr;
    }
    if ent.is_null() {
        if (unsafe { (*ctxt).standalone }) == 1 as i32
            || (unsafe { (*ctxt).hasExternalSubset }) == 0 as i32 && (unsafe { (*ctxt).hasPErefs }) == 0 as i32
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
        xmlParserEntityCheck(ctxt, 0 as i32 as size_t, ent, 0 as i32 as size_t);
    } else if (unsafe { (*ent).etype }) as u32 == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as i32 as u32 {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_UNPARSED_ENTITY,
            b"Entity reference to unparsed entity %s\n\0" as *const u8 as *const i8,
            name,
        );
    } else if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_ATTRIBUTE_VALUE as i32
        && (unsafe { (*ent).etype }) as u32 == XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32
    {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ENTITY_IS_EXTERNAL,
            b"Attribute references external entity '%s'\n\0" as *const u8 as *const i8,
            name,
        );
    } else if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_ATTRIBUTE_VALUE as i32
        && !ent.is_null()
        && !(unsafe { (*ent).content }).is_null()
        && (unsafe { (*ent).etype }) as u32 != XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
        && !(unsafe { xmlStrchr((*ent).content, '<' as i32 as xmlChar) }).is_null()
    {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_LT_IN_ATTRIBUTE,
            b"'<' in entity '%s' is not allowed in attributes values\n\0" as *const u8 as *const i8,
            name,
        );
    } else {
        match (unsafe { (*ent).etype }) as u32 {
            4 | 5 => {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_ENTITY_IS_PARAMETER,
                    b"Attempt to reference the parameter entity '%s'\n\0" as *const u8 as *const i8,
                    name,
                );
            }
            _ => {}
        }
    }
    (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
    (unsafe { *str = ptr });
    return ent;
}
#[no_mangle]
pub extern "C" fn xmlParsePEReference(mut ctxt: xmlParserCtxtPtr) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut entity: xmlEntityPtr = 0 as xmlEntityPtr;
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '%' as i32 {
        return;
    }
    (unsafe { xmlNextChar(ctxt) });
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_PEREF_NO_NAME,
            b"PEReference: no name\n\0" as *const u8 as *const i8,
        );
        return;
    }
    if (unsafe { *__xmlParserDebugEntities() }) != 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"PEReference: %s\n\0" as *const u8 as *const i8,
            name,
        ) });
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != ';' as i32 {
        xmlFatalErr(ctxt, XML_ERR_PEREF_SEMICOL_MISSING, 0 as *const i8);
        return;
    }
    (unsafe { xmlNextChar(ctxt) });
    let fresh334 = unsafe { &mut ((*ctxt).nbentities) };
    *fresh334 = (*fresh334).wrapping_add(1);
    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).getParameterEntity).is_some() }) {
        entity = unsafe { ((*(*ctxt).sax).getParameterEntity).expect("non-null function pointer")(
            (*ctxt).userData,
            name,
        ) };
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return;
    }
    if entity.is_null() {
        if (unsafe { (*ctxt).standalone }) == 1 as i32
            || (unsafe { (*ctxt).hasExternalSubset }) == 0 as i32 && (unsafe { (*ctxt).hasPErefs }) == 0 as i32
        {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNDECLARED_ENTITY,
                b"PEReference: %%%s; not found\n\0" as *const u8 as *const i8,
                name,
            );
        } else {
            if (unsafe { (*ctxt).validate }) != 0 && (unsafe { ((*ctxt).vctxt.error).is_some() }) {
                xmlValidityError(
                    ctxt,
                    XML_WAR_UNDECLARED_ENTITY,
                    b"PEReference: %%%s; not found\n\0" as *const u8 as *const i8,
                    name,
                    0 as *const xmlChar,
                );
            } else {
                xmlWarningMsg(
                    ctxt,
                    XML_WAR_UNDECLARED_ENTITY,
                    b"PEReference: %%%s; not found\n\0" as *const u8 as *const i8,
                    name,
                    0 as *const xmlChar,
                );
            }
            (unsafe { (*ctxt).valid = 0 as i32 });
        }
        xmlParserEntityCheck(
            ctxt,
            0 as i32 as size_t,
            0 as xmlEntityPtr,
            0 as i32 as size_t,
        );
    } else if (unsafe { (*entity).etype }) as u32 != XML_INTERNAL_PARAMETER_ENTITY as i32 as u32
        && (unsafe { (*entity).etype }) as u32 != XML_EXTERNAL_PARAMETER_ENTITY as i32 as u32
    {
        xmlWarningMsg(
            ctxt,
            XML_WAR_UNDECLARED_ENTITY,
            b"Internal: %%%s; is not a parameter entity\n\0" as *const u8 as *const i8,
            name,
            0 as *const xmlChar,
        );
    } else {
        let mut start: [xmlChar; 4] = [0; 4];
        let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
        if xmlParserEntityCheck(ctxt, 0 as i32 as size_t, entity, 0 as i32 as size_t) != 0 {
            return;
        }
        if (unsafe { (*entity).etype }) as u32 == XML_EXTERNAL_PARAMETER_ENTITY as i32 as u32
            && (unsafe { (*ctxt).options }) & XML_PARSE_NOENT as i32 == 0 as i32
            && (unsafe { (*ctxt).options }) & XML_PARSE_DTDVALID as i32 == 0 as i32
            && (unsafe { (*ctxt).options }) & XML_PARSE_DTDLOAD as i32 == 0 as i32
            && (unsafe { (*ctxt).options }) & XML_PARSE_DTDATTR as i32 == 0 as i32
            && (unsafe { (*ctxt).replaceEntities }) == 0 as i32
            && (unsafe { (*ctxt).validate }) == 0 as i32
        {
            return;
        }
        input = unsafe { xmlNewEntityInputStream(ctxt, entity) };
        if xmlPushInput(ctxt, input) < 0 as i32 {
            (unsafe { xmlFreeInputStream(input) });
            return;
        }
        if (unsafe { (*entity).etype }) as u32 == XML_EXTERNAL_PARAMETER_ENTITY as i32 as u32 {
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                return;
            }
            if (unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64 >= 4 as i32 as i64 {
                start[0 as i32 as usize] = unsafe { *(*(*ctxt).input).cur };
                start[1 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) };
                start[2 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) };
                start[3 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) };
                enc = unsafe { xmlDetectCharEncoding(start.as_mut_ptr(), 4 as i32) };
                if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
                    (unsafe { xmlSwitchEncoding(ctxt, enc) });
                }
            }
            if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == '?' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'x' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'm' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'l' as i32
                && ((unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32
                        && (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 <= 0xa as i32
                    || (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 == 0xd as i32)
            {
                xmlParseTextDecl(ctxt);
            }
        }
    }
    (unsafe { (*ctxt).hasPErefs = 1 as i32 });
}
extern "C" fn xmlLoadEntityContent(mut ctxt: xmlParserCtxtPtr, mut entity: xmlEntityPtr) -> i32 {
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: xmlBufferPtr = 0 as *mut xmlBuffer;
    let mut l: i32 = 0;
    let mut c: i32 = 0;
    let mut count: i32 = 0 as i32;
    if ctxt.is_null()
        || entity.is_null()
        || (unsafe { (*entity).etype }) as u32 != XML_EXTERNAL_PARAMETER_ENTITY as i32 as u32
            && (unsafe { (*entity).etype }) as u32 != XML_EXTERNAL_GENERAL_PARSED_ENTITY as i32 as u32
        || !(unsafe { (*entity).content }).is_null()
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"xmlLoadEntityContent parameter error\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    if (unsafe { *__xmlParserDebugEntities() }) != 0 {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Reading %s entity content input\n\0" as *const u8 as *const i8,
            (*entity).name,
        ) });
    }
    buf = unsafe { xmlBufferCreate() };
    if buf.is_null() {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"xmlLoadEntityContent parameter error\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    (unsafe { xmlBufferSetAllocationScheme(buf, XML_BUFFER_ALLOC_DOUBLEIT) });
    input = unsafe { xmlNewEntityInputStream(ctxt, entity) };
    if input.is_null() {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"xmlLoadEntityContent input error\0" as *const u8 as *const i8,
        );
        (unsafe { xmlBufferFree(buf) });
        return -(1 as i32);
    }
    if xmlPushInput(ctxt, input) < 0 as i32 {
        (unsafe { xmlBufferFree(buf) });
        (unsafe { xmlFreeInputStream(input) });
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    c = unsafe { xmlCurrentChar(ctxt, &mut l) };
    while (unsafe { (*ctxt).input }) == input
        && (unsafe { (*(*ctxt).input).cur }) < (unsafe { (*(*ctxt).input).end })
        && (if c < 0x100 as i32 {
            (0x9 as i32 <= c && c <= 0xa as i32 || c == 0xd as i32 || 0x20 as i32 <= c) as i32
        } else {
            (0x100 as i32 <= c && c <= 0xd7ff as i32
                || 0xe000 as i32 <= c && c <= 0xfffd as i32
                || 0x10000 as i32 <= c && c <= 0x10ffff as i32) as i32
        }) != 0
    {
        (unsafe { xmlBufferAdd(buf, (*(*ctxt).input).cur, l) });
        let fresh335 = count;
        count = count + 1;
        if fresh335 > 100 as i32 {
            count = 0 as i32;
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                (unsafe { xmlBufferFree(buf) });
                return -(1 as i32);
            }
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
            let fresh336 = unsafe { &mut ((*(*ctxt).input).line) };
            *fresh336 += 1;
            (unsafe { (*(*ctxt).input).col = 1 as i32 });
        } else {
            let fresh337 = unsafe { &mut ((*(*ctxt).input).col) };
            *fresh337 += 1;
        }
        let fresh338 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh338 = unsafe { (*fresh338).offset(l as isize) };
        c = unsafe { xmlCurrentChar(ctxt, &mut l) };
        if c == 0 as i32 {
            count = 0 as i32;
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                (unsafe { xmlBufferFree(buf) });
                return -(1 as i32);
            }
            c = unsafe { xmlCurrentChar(ctxt, &mut l) };
        }
    }
    if (unsafe { (*ctxt).input }) == input && (unsafe { (*(*ctxt).input).cur }) >= (unsafe { (*(*ctxt).input).end }) {
        xmlPopInput(ctxt);
    } else if if c < 0x100 as i32 {
        (0x9 as i32 <= c && c <= 0xa as i32 || c == 0xd as i32 || 0x20 as i32 <= c) as i32
    } else {
        (0x100 as i32 <= c && c <= 0xd7ff as i32
            || 0xe000 as i32 <= c && c <= 0xfffd as i32
            || 0x10000 as i32 <= c && c <= 0x10ffff as i32) as i32
    } == 0
    {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlLoadEntityContent: invalid char value %d\n\0" as *const u8 as *const i8,
            c,
        );
        (unsafe { xmlBufferFree(buf) });
        return -(1 as i32);
    }
    let fresh339 = unsafe { &mut ((*entity).content) };
    *fresh339 = unsafe { (*buf).content };
    let fresh340 = unsafe { &mut ((*buf).content) };
    *fresh340 = 0 as *mut xmlChar;
    (unsafe { xmlBufferFree(buf) });
    return 0 as i32;
}
extern "C" fn xmlParseStringPEReference(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *mut *const xmlChar,
) -> xmlEntityPtr {
    let mut ptr: *const xmlChar = 0 as *const xmlChar;
    let mut cur: xmlChar = 0;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut entity: xmlEntityPtr = 0 as xmlEntityPtr;
    if str.is_null() || (unsafe { *str }).is_null() {
        return 0 as xmlEntityPtr;
    }
    ptr = unsafe { *str };
    cur = unsafe { *ptr };
    if cur as i32 != '%' as i32 {
        return 0 as xmlEntityPtr;
    }
    ptr = unsafe { ptr.offset(1) };
    name = xmlParseStringName(ctxt, &mut ptr);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseStringPEReference: no name\n\0" as *const u8 as *const i8,
        );
        (unsafe { *str = ptr });
        return 0 as xmlEntityPtr;
    }
    cur = unsafe { *ptr };
    if cur as i32 != ';' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ENTITYREF_SEMICOL_MISSING, 0 as *const i8);
        (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
        (unsafe { *str = ptr });
        return 0 as xmlEntityPtr;
    }
    ptr = unsafe { ptr.offset(1) };
    let fresh341 = unsafe { &mut ((*ctxt).nbentities) };
    *fresh341 = (*fresh341).wrapping_add(1);
    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).getParameterEntity).is_some() }) {
        entity = unsafe { ((*(*ctxt).sax).getParameterEntity).expect("non-null function pointer")(
            (*ctxt).userData,
            name,
        ) };
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
        (unsafe { *str = ptr });
        return 0 as xmlEntityPtr;
    }
    if entity.is_null() {
        if (unsafe { (*ctxt).standalone }) == 1 as i32
            || (unsafe { (*ctxt).hasExternalSubset }) == 0 as i32 && (unsafe { (*ctxt).hasPErefs }) == 0 as i32
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
            (unsafe { (*ctxt).valid = 0 as i32 });
        }
        xmlParserEntityCheck(
            ctxt,
            0 as i32 as size_t,
            0 as xmlEntityPtr,
            0 as i32 as size_t,
        );
    } else if (unsafe { (*entity).etype }) as u32 != XML_INTERNAL_PARAMETER_ENTITY as i32 as u32
        && (unsafe { (*entity).etype }) as u32 != XML_EXTERNAL_PARAMETER_ENTITY as i32 as u32
    {
        xmlWarningMsg(
            ctxt,
            XML_WAR_UNDECLARED_ENTITY,
            b"%%%s; is not a parameter entity\n\0" as *const u8 as *const i8,
            name,
            0 as *const xmlChar,
        );
    }
    (unsafe { (*ctxt).hasPErefs = 1 as i32 });
    (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
    (unsafe { *str = ptr });
    return entity;
}
#[no_mangle]
pub extern "C" fn xmlParseDocTypeDecl(mut ctxt: xmlParserCtxtPtr) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let fresh342 = unsafe { &mut ((*(*ctxt).input).cur) };
    *fresh342 = unsafe { (*fresh342).offset(9 as i32 as isize) };
    (unsafe { (*(*ctxt).input).col += 9 as i32 });
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
        (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
    }
    xmlSkipBlankChars(ctxt);
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseDocTypeDecl : no DOCTYPE name !\n\0" as *const u8 as *const i8,
        );
    }
    let fresh343 = unsafe { &mut ((*ctxt).intSubName) };
    *fresh343 = name;
    xmlSkipBlankChars(ctxt);
    URI = xmlParseExternalID(ctxt, &mut ExternalID, 1 as i32);
    if !URI.is_null() || !ExternalID.is_null() {
        (unsafe { (*ctxt).hasExternalSubset = 1 as i32 });
    }
    let fresh344 = unsafe { &mut ((*ctxt).extSubURI) };
    *fresh344 = URI;
    let fresh345 = unsafe { &mut ((*ctxt).extSubSystem) };
    *fresh345 = ExternalID;
    xmlSkipBlankChars(ctxt);
    if !(unsafe { (*ctxt).sax }).is_null()
        && (unsafe { ((*(*ctxt).sax).internalSubset).is_some() })
        && (unsafe { (*ctxt).disableSAX }) == 0
    {
        (unsafe { ((*(*ctxt).sax).internalSubset).expect("non-null function pointer")(
            (*ctxt).userData,
            name,
            ExternalID,
            URI,
        ) });
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return;
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '[' as i32 {
        return;
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '>' as i32 {
        xmlFatalErr(ctxt, XML_ERR_DOCTYPE_NOT_FINISHED, 0 as *const i8);
    }
    (unsafe { xmlNextChar(ctxt) });
}
extern "C" fn xmlParseInternalSubset(mut ctxt: xmlParserCtxtPtr) {
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '[' as i32 {
        let mut baseInputNr: i32 = unsafe { (*ctxt).inputNr };
        (unsafe { (*ctxt).instate = XML_PARSER_DTD });
        (unsafe { xmlNextChar(ctxt) });
        while ((unsafe { *(*(*ctxt).input).cur }) as i32 != ']' as i32 || (unsafe { (*ctxt).inputNr }) > baseInputNr)
            && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32
        {
            let mut id: i32 = unsafe { (*(*ctxt).input).id };
            let mut cons: u64 = (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
            );
            xmlSkipBlankChars(ctxt);
            xmlParseMarkupDecl(ctxt);
            xmlParsePEReference(ctxt);
            if (unsafe { (*ctxt).inputNr }) > 1 as i32
                && !(unsafe { (*(*ctxt).input).filename }).is_null()
                && (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '!' as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == '[' as i32
            {
                xmlParseConditionalSections(ctxt);
            }
            if !(id == (unsafe { (*(*ctxt).input).id })
                && cons
                    == (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                        (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
                    ))
            {
                continue;
            }
            xmlFatalErr(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"xmlParseInternalSubset: error detected in Markup declaration\n\0" as *const u8
                    as *const i8,
            );
            if !((unsafe { (*ctxt).inputNr }) > baseInputNr) {
                break;
            }
            xmlPopInput(ctxt);
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == ']' as i32 {
            (unsafe { xmlNextChar(ctxt) });
            xmlSkipBlankChars(ctxt);
        }
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '>' as i32 {
        xmlFatalErr(ctxt, XML_ERR_DOCTYPE_NOT_FINISHED, 0 as *const i8);
        return;
    }
    (unsafe { xmlNextChar(ctxt) });
}
#[no_mangle]
pub extern "C" fn xmlParseAttribute(
    mut ctxt: xmlParserCtxtPtr,
    mut value: *mut *mut xmlChar,
) -> *const xmlChar {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    (unsafe { *value = 0 as *mut xmlChar });
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
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
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '=' as i32 {
        (unsafe { xmlNextChar(ctxt) });
        xmlSkipBlankChars(ctxt);
        val = xmlParseAttValue(ctxt);
        (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
    } else {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ATTRIBUTE_WITHOUT_VALUE,
            b"Specification mandates value for attribute %s\n\0" as *const u8 as *const i8,
            name,
        );
        return 0 as *const xmlChar;
    }
    if (unsafe { (*ctxt).pedantic }) != 0
        && (unsafe { xmlStrEqual(
            name,
            b"xml:lang\0" as *const u8 as *const i8 as *mut xmlChar,
        ) }) != 0
    {
        if xmlCheckLanguageID(val) == 0 {
            xmlWarningMsg(
                ctxt,
                XML_WAR_LANG_VALUE,
                b"Malformed value for xml:lang : %s\n\0" as *const u8 as *const i8,
                val,
                0 as *const xmlChar,
            );
        }
    }
    if (unsafe { xmlStrEqual(
        name,
        b"xml:space\0" as *const u8 as *const i8 as *mut xmlChar,
    ) }) != 0
    {
        if (unsafe { xmlStrEqual(val, b"default\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
            (unsafe { *(*ctxt).space = 0 as i32 });
        } else if (unsafe { xmlStrEqual(val, b"preserve\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
            (unsafe { *(*ctxt).space = 1 as i32 });
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
    (unsafe { *value = val });
    return name;
}
#[no_mangle]
pub extern "C" fn xmlParseStartTag(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut current_block: u64;
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut attname: *const xmlChar = 0 as *const xmlChar;
    let mut attvalue: *mut xmlChar = 0 as *mut xmlChar;
    let mut atts: *mut *const xmlChar = unsafe { (*ctxt).atts };
    let mut nbatts: i32 = 0 as i32;
    let mut maxatts: i32 = unsafe { (*ctxt).maxatts };
    let mut i: i32 = 0;
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '<' as i32 {
        return 0 as *const xmlChar;
    }
    let fresh346 = unsafe { &mut ((*(*ctxt).input).col) };
    *fresh346 += 1;
    let fresh347 = unsafe { &mut ((*(*ctxt).input).cur) };
    *fresh347 = unsafe { (*fresh347).offset(1) };
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
        (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
    }
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseStartTag: invalid element name\n\0" as *const u8 as *const i8,
        );
        return 0 as *const xmlChar;
    }
    xmlSkipBlankChars(ctxt);
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    while (unsafe { *(*(*ctxt).input).cur }) as i32 != '>' as i32
        && ((unsafe { *(*(*ctxt).input).cur }) as i32 != '/' as i32
            || (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 != '>' as i32)
        && (0x9 as i32 <= (unsafe { *(*(*ctxt).input).cur }) as i32
            && (unsafe { *(*(*ctxt).input).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*(*ctxt).input).cur }) as i32 == 0xd as i32
            || 0x20 as i32 <= (unsafe { *(*(*ctxt).input).cur }) as i32)
        && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32
    {
        let mut id: i32 = unsafe { (*(*ctxt).input).id };
        let mut cons: u64 = (unsafe { (*(*ctxt).input).consumed })
            .wrapping_add((unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64);
        attname = xmlParseAttribute(ctxt, &mut attvalue);
        if !attname.is_null() && !attvalue.is_null() {
            i = 0 as i32;
            loop {
                if !(i < nbatts) {
                    current_block = 3437258052017859086;
                    break;
                }
                if (unsafe { xmlStrEqual(*atts.offset(i as isize), attname) }) != 0 {
                    xmlErrAttributeDup(ctxt, 0 as *const xmlChar, attname);
                    (unsafe { xmlFree.expect("non-null function pointer")(attvalue as *mut libc::c_void) });
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
                        atts = (unsafe { xmlMalloc.expect("non-null function pointer")(
                            (maxatts as u64)
                                .wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
                        ) }) as *mut *const xmlChar;
                        if atts.is_null() {
                            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                            if !attvalue.is_null() {
                                (unsafe { xmlFree.expect("non-null function pointer")(
                                    attvalue as *mut libc::c_void,
                                ) });
                            }
                            current_block = 16521494893250375975;
                        } else {
                            let fresh348 = unsafe { &mut ((*ctxt).atts) };
                            *fresh348 = atts;
                            (unsafe { (*ctxt).maxatts = maxatts });
                            current_block = 11763295167351361500;
                        }
                    } else if nbatts + 4 as i32 > maxatts {
                        let mut n: *mut *const xmlChar = 0 as *mut *const xmlChar;
                        maxatts *= 2 as i32;
                        n = (unsafe { xmlRealloc.expect("non-null function pointer")(
                            atts as *mut libc::c_void,
                            (maxatts as u64)
                                .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as u64),
                        ) }) as *mut *const xmlChar;
                        if n.is_null() {
                            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                            if !attvalue.is_null() {
                                (unsafe { xmlFree.expect("non-null function pointer")(
                                    attvalue as *mut libc::c_void,
                                ) });
                            }
                            current_block = 16521494893250375975;
                        } else {
                            atts = n;
                            let fresh349 = unsafe { &mut ((*ctxt).atts) };
                            *fresh349 = atts;
                            (unsafe { (*ctxt).maxatts = maxatts });
                            current_block = 11763295167351361500;
                        }
                    } else {
                        current_block = 11763295167351361500;
                    }
                    match current_block {
                        16521494893250375975 => {}
                        _ => {
                            let fresh350 = nbatts;
                            nbatts = nbatts + 1;
                            let fresh351 = unsafe { &mut (*atts.offset(fresh350 as isize)) };
                            *fresh351 = attname;
                            let fresh352 = nbatts;
                            nbatts = nbatts + 1;
                            let fresh353 = unsafe { &mut (*atts.offset(fresh352 as isize)) };
                            *fresh353 = attvalue;
                            let fresh354 = unsafe { &mut (*atts.offset(nbatts as isize)) };
                            *fresh354 = 0 as *const xmlChar;
                            let fresh355 = unsafe { &mut (*atts.offset((nbatts + 1 as i32) as isize)) };
                            *fresh355 = 0 as *const xmlChar;
                        }
                    }
                }
            }
        } else if !attvalue.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(attvalue as *mut libc::c_void) });
        }
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '>' as i32
            || (unsafe { *(*(*ctxt).input).cur }) as i32 == '/' as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '>' as i32
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
            == (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
            )
            && id == (unsafe { (*(*ctxt).input).id })
            && attname.is_null()
            && attvalue.is_null()
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"xmlParseStartTag: problem parsing attributes\n\0" as *const u8 as *const i8,
            );
            break;
        } else {
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                    > (2 as i32 * 250 as i32) as i64
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
        }
    }
    if !(unsafe { (*ctxt).sax }).is_null()
        && (unsafe { ((*(*ctxt).sax).startElement).is_some() })
        && (unsafe { (*ctxt).disableSAX }) == 0
    {
        if nbatts > 0 as i32 {
            (unsafe { ((*(*ctxt).sax).startElement).expect("non-null function pointer")(
                (*ctxt).userData,
                name,
                atts,
            ) });
        } else {
            (unsafe { ((*(*ctxt).sax).startElement).expect("non-null function pointer")(
                (*ctxt).userData,
                name,
                0 as *mut *const xmlChar,
            ) });
        }
    }
    if !atts.is_null() {
        i = 1 as i32;
        while i < nbatts {
            if !(unsafe { *atts.offset(i as isize) }).is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(
                    *atts.offset(i as isize) as *mut xmlChar as *mut libc::c_void,
                ) });
            }
            i += 2 as i32;
        }
    }
    return name;
}
extern "C" fn xmlParseEndTag1(mut ctxt: xmlParserCtxtPtr, mut line: i32) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '<' as i32
        || (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 != '/' as i32
    {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_LTSLASH_REQUIRED,
            b"xmlParseEndTag: '</' not found\n\0" as *const u8 as *const i8,
        );
        return;
    }
    let fresh356 = unsafe { &mut ((*(*ctxt).input).cur) };
    *fresh356 = unsafe { (*fresh356).offset(2 as i32 as isize) };
    (unsafe { (*(*ctxt).input).col += 2 as i32 });
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
        (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
    }
    name = xmlParseNameAndCompare(ctxt, unsafe { (*ctxt).name });
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    xmlSkipBlankChars(ctxt);
    if !(0x9 as i32 <= (unsafe { *(*(*ctxt).input).cur }) as i32 && (unsafe { *(*(*ctxt).input).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*(*ctxt).input).cur }) as i32 == 0xd as i32
        || 0x20 as i32 <= (unsafe { *(*(*ctxt).input).cur }) as i32)
        || (unsafe { *(*(*ctxt).input).cur }) as i32 != '>' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_GT_REQUIRED, 0 as *const i8);
    } else {
        let fresh357 = unsafe { &mut ((*(*ctxt).input).col) };
        *fresh357 += 1;
        let fresh358 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh358 = unsafe { (*fresh358).offset(1) };
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
    }
    if name != 1 as i32 as *mut xmlChar as *const xmlChar {
        if name.is_null() {
            name = b"unparsable\0" as *const u8 as *const i8 as *mut xmlChar;
        }
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_TAG_NAME_MISMATCH,
            b"Opening and ending tag mismatch: %s line %d and %s\n\0" as *const u8 as *const i8,
            unsafe { (*ctxt).name },
            line,
            name,
        );
    }
    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).endElement).is_some() }) && (unsafe { (*ctxt).disableSAX }) == 0
    {
        (unsafe { ((*(*ctxt).sax).endElement).expect("non-null function pointer")(
            (*ctxt).userData,
            (*ctxt).name,
        ) });
    }
    namePop(ctxt);
    spacePop(ctxt);
}
#[no_mangle]
pub extern "C" fn xmlParseEndTag(mut ctxt: xmlParserCtxtPtr) {
    xmlParseEndTag1(ctxt, 0 as i32);
}
extern "C" fn xmlGetNamespace(
    mut ctxt: xmlParserCtxtPtr,
    mut prefix: *const xmlChar,
) -> *const xmlChar {
    let mut i: i32 = 0;
    if prefix == (unsafe { (*ctxt).str_xml }) {
        return unsafe { (*ctxt).str_xml_ns };
    }
    i = (unsafe { (*ctxt).nsNr }) - 2 as i32;
    while i >= 0 as i32 {
        if (unsafe { *((*ctxt).nsTab).offset(i as isize) }) == prefix {
            if prefix.is_null()
                && (unsafe { **((*ctxt).nsTab).offset((i + 1 as i32) as isize) }) as i32 == 0 as i32
            {
                return 0 as *const xmlChar;
            }
            return unsafe { *((*ctxt).nsTab).offset((i + 1 as i32) as isize) };
        }
        i -= 2 as i32;
    }
    return 0 as *const xmlChar;
}
extern "C" fn xmlParseQName(
    mut ctxt: xmlParserCtxtPtr,
    mut prefix: *mut *const xmlChar,
) -> *const xmlChar {
    let mut l: *const xmlChar = 0 as *const xmlChar;
    let mut p: *const xmlChar = 0 as *const xmlChar;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    l = xmlParseNCName(ctxt);
    if l.is_null() {
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == ':' as i32 {
            l = xmlParseName(ctxt);
            if !l.is_null() {
                xmlNsErr(
                    ctxt,
                    XML_NS_ERR_QNAME,
                    b"Failed to parse QName '%s'\n\0" as *const u8 as *const i8,
                    l,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                (unsafe { *prefix = 0 as *const xmlChar });
                return l;
            }
        }
        return 0 as *const xmlChar;
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == ':' as i32 {
        (unsafe { xmlNextChar(ctxt) });
        p = l;
        l = xmlParseNCName(ctxt);
        if l.is_null() {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
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
                if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *const xmlChar;
                }
                tmp = unsafe { xmlBuildQName(
                    b"\0" as *const u8 as *const i8 as *mut xmlChar,
                    p,
                    0 as *mut xmlChar,
                    0 as i32,
                ) };
            } else {
                tmp = unsafe { xmlBuildQName(l, p, 0 as *mut xmlChar, 0 as i32) };
                (unsafe { xmlFree.expect("non-null function pointer")(l as *mut i8 as *mut libc::c_void) });
            }
            p = unsafe { xmlDictLookup((*ctxt).dict, tmp, -(1 as i32)) };
            if !tmp.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
            }
            (unsafe { *prefix = 0 as *const xmlChar });
            return p;
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == ':' as i32 {
            let mut tmp_0: *mut xmlChar = 0 as *mut xmlChar;
            xmlNsErr(
                ctxt,
                XML_NS_ERR_QNAME,
                b"Failed to parse QName '%s:%s:'\n\0" as *const u8 as *const i8,
                p,
                l,
                0 as *const xmlChar,
            );
            (unsafe { xmlNextChar(ctxt) });
            tmp_0 = xmlParseName(ctxt) as *mut xmlChar;
            if !tmp_0.is_null() {
                tmp_0 = unsafe { xmlBuildQName(tmp_0, l, 0 as *mut xmlChar, 0 as i32) };
                l = unsafe { xmlDictLookup((*ctxt).dict, tmp_0, -(1 as i32)) };
                if !tmp_0.is_null() {
                    (unsafe { xmlFree.expect("non-null function pointer")(tmp_0 as *mut libc::c_void) });
                }
                (unsafe { *prefix = p });
                return l;
            }
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                return 0 as *const xmlChar;
            }
            tmp_0 = unsafe { xmlBuildQName(
                b"\0" as *const u8 as *const i8 as *mut xmlChar,
                l,
                0 as *mut xmlChar,
                0 as i32,
            ) };
            l = unsafe { xmlDictLookup((*ctxt).dict, tmp_0, -(1 as i32)) };
            if !tmp_0.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(tmp_0 as *mut libc::c_void) });
            }
            (unsafe { *prefix = p });
            return l;
        }
        (unsafe { *prefix = p });
    } else {
        (unsafe { *prefix = 0 as *const xmlChar });
    }
    return l;
}
extern "C" fn xmlParseQNameAndCompare(
    mut ctxt: xmlParserCtxtPtr,
    mut name: *const xmlChar,
    mut prefix: *const xmlChar,
) -> *const xmlChar {
    let mut cmp: *const xmlChar = 0 as *const xmlChar;
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    let mut prefix2: *const xmlChar = 0 as *const xmlChar;
    if prefix.is_null() {
        return xmlParseNameAndCompare(ctxt, name);
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    in_0 = unsafe { (*(*ctxt).input).cur };
    cmp = prefix;
    while (unsafe { *in_0 }) as i32 != 0 as i32 && (unsafe { *in_0 }) as i32 == (unsafe { *cmp }) as i32 {
        in_0 = unsafe { in_0.offset(1) };
        cmp = unsafe { cmp.offset(1) };
    }
    if (unsafe { *cmp }) as i32 == 0 as i32 && (unsafe { *in_0 }) as i32 == ':' as i32 {
        in_0 = unsafe { in_0.offset(1) };
        cmp = name;
        while (unsafe { *in_0 }) as i32 != 0 as i32 && (unsafe { *in_0 }) as i32 == (unsafe { *cmp }) as i32 {
            in_0 = unsafe { in_0.offset(1) };
            cmp = unsafe { cmp.offset(1) };
        }
        if (unsafe { *cmp }) as i32 == 0 as i32
            && ((unsafe { *in_0 }) as i32 == '>' as i32
                || ((unsafe { *in_0 }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *in_0 }) as i32 && (unsafe { *in_0 }) as i32 <= 0xa as i32
                    || (unsafe { *in_0 }) as i32 == 0xd as i32))
        {
            let fresh359 = unsafe { &mut ((*(*ctxt).input).col) };
            *fresh359 = (*fresh359 as i64 + (unsafe { in_0.offset_from((*(*ctxt).input).cur) }) as i64) as i32;
            let fresh360 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh360 = in_0;
            return 1 as i32 as *const xmlChar;
        }
    }
    ret = xmlParseQName(ctxt, &mut prefix2);
    if ret == name && prefix == prefix2 {
        return 1 as i32 as *const xmlChar;
    }
    return ret;
}
extern "C" fn xmlParseAttValueInternal(
    mut ctxt: xmlParserCtxtPtr,
    mut len: *mut i32,
    mut alloc: *mut i32,
    mut normalize: i32,
) -> *mut xmlChar {
    let mut current_block: u64;
    let mut limit: xmlChar = 0 as i32 as xmlChar;
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut start: *const xmlChar = 0 as *const xmlChar;
    let mut end: *const xmlChar = 0 as *const xmlChar;
    let mut last: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut line: i32 = 0;
    let mut col: i32 = 0;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    in_0 = (unsafe { (*(*ctxt).input).cur }) as *mut xmlChar;
    line = unsafe { (*(*ctxt).input).line };
    col = unsafe { (*(*ctxt).input).col };
    if (unsafe { *in_0 }) as i32 != '"' as i32 && (unsafe { *in_0 }) as i32 != '\'' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ATTRIBUTE_NOT_STARTED, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    (unsafe { (*ctxt).instate = XML_PARSER_ATTRIBUTE_VALUE });
    let fresh361 = in_0;
    in_0 = unsafe { in_0.offset(1) };
    limit = unsafe { *fresh361 };
    col += 1;
    end = unsafe { (*(*ctxt).input).end };
    start = in_0;
    if in_0 >= end {
        let mut oldbase: *const xmlChar = unsafe { (*(*ctxt).input).base };
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
            return 0 as *mut xmlChar;
        }
        if oldbase != (unsafe { (*(*ctxt).input).base }) {
            let mut delta: ptrdiff_t = (unsafe { ((*(*ctxt).input).base).offset_from(oldbase) }) as i64;
            start = unsafe { start.offset(delta as isize) };
            in_0 = unsafe { in_0.offset(delta as isize) };
        }
        end = unsafe { (*(*ctxt).input).end };
    }
    if normalize != 0 {
        while in_0 < end
            && (unsafe { *in_0 }) as i32 != limit as i32
            && ((unsafe { *in_0 }) as i32 == 0x20 as i32
                || (unsafe { *in_0 }) as i32 == 0x9 as i32
                || (unsafe { *in_0 }) as i32 == 0xa as i32
                || (unsafe { *in_0 }) as i32 == 0xd as i32)
        {
            if (unsafe { *in_0 }) as i32 == 0xa as i32 {
                line += 1;
                col = 1 as i32;
            } else {
                col += 1;
            }
            in_0 = unsafe { in_0.offset(1) };
            start = in_0;
            if in_0 >= end {
                let mut oldbase_0: *const xmlChar = unsafe { (*(*ctxt).input).base };
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *mut xmlChar;
                }
                if oldbase_0 != (unsafe { (*(*ctxt).input).base }) {
                    let mut delta_0: ptrdiff_t =
                        (unsafe { ((*(*ctxt).input).base).offset_from(oldbase_0) }) as i64;
                    start = unsafe { start.offset(delta_0 as isize) };
                    in_0 = unsafe { in_0.offset(delta_0 as isize) };
                }
                end = unsafe { (*(*ctxt).input).end };
                if (unsafe { in_0.offset_from(start) }) as i64 > 10000000 as i32 as i64
                    && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
                {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ATTRIBUTE_NOT_FINISHED,
                        b"AttValue length too long\n\0" as *const u8 as *const i8,
                    );
                    return 0 as *mut xmlChar;
                }
            }
        }
        while in_0 < end
            && (unsafe { *in_0 }) as i32 != limit as i32
            && (unsafe { *in_0 }) as i32 >= 0x20 as i32
            && (unsafe { *in_0 }) as i32 <= 0x7f as i32
            && (unsafe { *in_0 }) as i32 != '&' as i32
            && (unsafe { *in_0 }) as i32 != '<' as i32
        {
            col += 1;
            let fresh362 = in_0;
            in_0 = unsafe { in_0.offset(1) };
            if (unsafe { *fresh362 }) as i32 == 0x20 as i32 && (unsafe { *in_0 }) as i32 == 0x20 as i32 {
                break;
            }
            if in_0 >= end {
                let mut oldbase_1: *const xmlChar = unsafe { (*(*ctxt).input).base };
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *mut xmlChar;
                }
                if oldbase_1 != (unsafe { (*(*ctxt).input).base }) {
                    let mut delta_1: ptrdiff_t =
                        (unsafe { ((*(*ctxt).input).base).offset_from(oldbase_1) }) as i64;
                    start = unsafe { start.offset(delta_1 as isize) };
                    in_0 = unsafe { in_0.offset(delta_1 as isize) };
                }
                end = unsafe { (*(*ctxt).input).end };
                if (unsafe { in_0.offset_from(start) }) as i64 > 10000000 as i32 as i64
                    && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
                {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ATTRIBUTE_NOT_FINISHED,
                        b"AttValue length too long\n\0" as *const u8 as *const i8,
                    );
                    return 0 as *mut xmlChar;
                }
            }
        }
        last = in_0;
        while (unsafe { *last.offset(-(1 as i32) as isize) }) as i32 == 0x20 as i32 && last > start {
            last = unsafe { last.offset(-1) };
        }
        while in_0 < end
            && (unsafe { *in_0 }) as i32 != limit as i32
            && ((unsafe { *in_0 }) as i32 == 0x20 as i32
                || (unsafe { *in_0 }) as i32 == 0x9 as i32
                || (unsafe { *in_0 }) as i32 == 0xa as i32
                || (unsafe { *in_0 }) as i32 == 0xd as i32)
        {
            if (unsafe { *in_0 }) as i32 == 0xa as i32 {
                line += 1;
                col = 1 as i32;
            } else {
                col += 1;
            }
            in_0 = unsafe { in_0.offset(1) };
            if in_0 >= end {
                let mut oldbase_2: *const xmlChar = unsafe { (*(*ctxt).input).base };
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *mut xmlChar;
                }
                if oldbase_2 != (unsafe { (*(*ctxt).input).base }) {
                    let mut delta_2: ptrdiff_t =
                        (unsafe { ((*(*ctxt).input).base).offset_from(oldbase_2) }) as i64;
                    start = unsafe { start.offset(delta_2 as isize) };
                    in_0 = unsafe { in_0.offset(delta_2 as isize) };
                    last = unsafe { last.offset(delta_2 as isize) };
                }
                end = unsafe { (*(*ctxt).input).end };
                if (unsafe { in_0.offset_from(start) }) as i64 > 10000000 as i32 as i64
                    && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
                {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ATTRIBUTE_NOT_FINISHED,
                        b"AttValue length too long\n\0" as *const u8 as *const i8,
                    );
                    return 0 as *mut xmlChar;
                }
            }
        }
        if (unsafe { in_0.offset_from(start) }) as i64 > 10000000 as i32 as i64
            && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_ATTRIBUTE_NOT_FINISHED,
                b"AttValue length too long\n\0" as *const u8 as *const i8,
            );
            return 0 as *mut xmlChar;
        }
        if (unsafe { *in_0 }) as i32 != limit as i32 {
            current_block = 9760041004302091864;
        } else {
            current_block = 17736998403848444560;
        }
    } else {
        while in_0 < end
            && (unsafe { *in_0 }) as i32 != limit as i32
            && (unsafe { *in_0 }) as i32 >= 0x20 as i32
            && (unsafe { *in_0 }) as i32 <= 0x7f as i32
            && (unsafe { *in_0 }) as i32 != '&' as i32
            && (unsafe { *in_0 }) as i32 != '<' as i32
        {
            in_0 = unsafe { in_0.offset(1) };
            col += 1;
            if in_0 >= end {
                let mut oldbase_3: *const xmlChar = unsafe { (*(*ctxt).input).base };
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                    return 0 as *mut xmlChar;
                }
                if oldbase_3 != (unsafe { (*(*ctxt).input).base }) {
                    let mut delta_3: ptrdiff_t =
                        (unsafe { ((*(*ctxt).input).base).offset_from(oldbase_3) }) as i64;
                    start = unsafe { start.offset(delta_3 as isize) };
                    in_0 = unsafe { in_0.offset(delta_3 as isize) };
                }
                end = unsafe { (*(*ctxt).input).end };
                if (unsafe { in_0.offset_from(start) }) as i64 > 10000000 as i32 as i64
                    && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
                {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ATTRIBUTE_NOT_FINISHED,
                        b"AttValue length too long\n\0" as *const u8 as *const i8,
                    );
                    return 0 as *mut xmlChar;
                }
            }
        }
        last = in_0;
        if (unsafe { in_0.offset_from(start) }) as i64 > 10000000 as i32 as i64
            && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_ATTRIBUTE_NOT_FINISHED,
                b"AttValue length too long\n\0" as *const u8 as *const i8,
            );
            return 0 as *mut xmlChar;
        }
        if (unsafe { *in_0 }) as i32 != limit as i32 {
            current_block = 9760041004302091864;
        } else {
            current_block = 17736998403848444560;
        }
    }
    match current_block {
        9760041004302091864 => {
            if !alloc.is_null() {
                (unsafe { *alloc = 1 as i32 });
            }
            return xmlParseAttValueComplex(ctxt, len, normalize);
        }
        _ => {
            in_0 = unsafe { in_0.offset(1) };
            col += 1;
            if !len.is_null() {
                (unsafe { *len = last.offset_from(start) as i64 as i32 });
                ret = start as *mut xmlChar;
            } else {
                if !alloc.is_null() {
                    (unsafe { *alloc = 1 as i32 });
                }
                ret = unsafe { xmlStrndup(start, last.offset_from(start) as i64 as i32) };
            }
            let fresh363 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh363 = in_0;
            (unsafe { (*(*ctxt).input).line = line });
            (unsafe { (*(*ctxt).input).col = col });
            if !alloc.is_null() {
                (unsafe { *alloc = 0 as i32 });
            }
            return ret;
        }
    };
}
extern "C" fn xmlParseAttribute2(
    mut ctxt: xmlParserCtxtPtr,
    mut pref: *const xmlChar,
    mut elem: *const xmlChar,
    mut prefix: *mut *const xmlChar,
    mut value: *mut *mut xmlChar,
    mut len: *mut i32,
    mut alloc: *mut i32,
) -> *const xmlChar {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    let mut internal_val: *mut xmlChar = 0 as *mut xmlChar;
    let mut normalize: i32 = 0 as i32;
    (unsafe { *value = 0 as *mut xmlChar });
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    name = xmlParseQName(ctxt, prefix);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"error parsing attribute name\n\0" as *const u8 as *const i8,
        );
        return 0 as *const xmlChar;
    }
    if !(unsafe { (*ctxt).attsSpecial }).is_null() {
        let mut type_0: i32 = 0;
        type_0 =
            (unsafe { xmlHashQLookup2((*ctxt).attsSpecial, pref, elem, *prefix, name) }) as ptrdiff_t as i32;
        if type_0 != 0 as i32 {
            normalize = 1 as i32;
        }
    }
    xmlSkipBlankChars(ctxt);
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '=' as i32 {
        (unsafe { xmlNextChar(ctxt) });
        xmlSkipBlankChars(ctxt);
        val = xmlParseAttValueInternal(ctxt, len, alloc, normalize);
        if normalize != 0 {
            if (unsafe { *alloc }) != 0 {
                let mut val2: *const xmlChar = 0 as *const xmlChar;
                val2 = xmlAttrNormalizeSpace2(ctxt, val, len);
                if !val2.is_null() && val2 != val as *const xmlChar {
                    (unsafe { xmlFree.expect("non-null function pointer")(val as *mut libc::c_void) });
                    val = val2 as *mut xmlChar;
                }
            }
        }
        (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
    } else {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ATTRIBUTE_WITHOUT_VALUE,
            b"Specification mandates value for attribute %s\n\0" as *const u8 as *const i8,
            name,
        );
        return 0 as *const xmlChar;
    }
    if (unsafe { *prefix }) == (unsafe { (*ctxt).str_xml }) {
        if (unsafe { (*ctxt).pedantic }) != 0
            && (unsafe { xmlStrEqual(name, b"lang\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0
        {
            internal_val = unsafe { xmlStrndup(val, *len) };
            if xmlCheckLanguageID(internal_val) == 0 {
                xmlWarningMsg(
                    ctxt,
                    XML_WAR_LANG_VALUE,
                    b"Malformed value for xml:lang : %s\n\0" as *const u8 as *const i8,
                    internal_val,
                    0 as *const xmlChar,
                );
            }
        }
        if (unsafe { xmlStrEqual(name, b"space\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0 {
            internal_val = unsafe { xmlStrndup(val, *len) };
            if (unsafe { xmlStrEqual(
                internal_val,
                b"default\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) != 0
            {
                (unsafe { *(*ctxt).space = 0 as i32 });
            } else if (unsafe { xmlStrEqual(
                internal_val,
                b"preserve\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) != 0
            {
                (unsafe { *(*ctxt).space = 1 as i32 });
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
            (unsafe { xmlFree.expect("non-null function pointer")(internal_val as *mut libc::c_void) });
        }
    }
    (unsafe { *value = val });
    return name;
}
extern "C" fn xmlParseStartTag2(
    mut ctxt: xmlParserCtxtPtr,
    mut pref: *mut *const xmlChar,
    mut URI: *mut *const xmlChar,
    mut tlen: *mut i32,
) -> *const xmlChar {
    let mut current_block: u64;
    let mut localname: *const xmlChar = 0 as *const xmlChar;
    let mut prefix: *const xmlChar = 0 as *const xmlChar;
    let mut attname: *const xmlChar = 0 as *const xmlChar;
    let mut aprefix: *const xmlChar = 0 as *const xmlChar;
    let mut nsname: *const xmlChar = 0 as *const xmlChar;
    let mut attvalue: *mut xmlChar = 0 as *mut xmlChar;
    let mut atts: *mut *const xmlChar = unsafe { (*ctxt).atts };
    let mut maxatts: i32 = unsafe { (*ctxt).maxatts };
    let mut nratts: i32 = 0;
    let mut nbatts: i32 = 0;
    let mut nbdef: i32 = 0;
    let mut inputid: i32 = 0;
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    let mut nbNs: i32 = 0;
    let mut attval: i32 = 0;
    let mut cur: u64 = 0;
    let mut nsNr: i32 = unsafe { (*ctxt).nsNr };
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '<' as i32 {
        return 0 as *const xmlChar;
    }
    let fresh364 = unsafe { &mut ((*(*ctxt).input).col) };
    *fresh364 += 1;
    let fresh365 = unsafe { &mut ((*(*ctxt).input).cur) };
    *fresh365 = unsafe { (*fresh365).offset(1) };
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
        (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
            > (2 as i32 * 250 as i32) as i64
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
            < (2 as i32 * 250 as i32) as i64
    {
        xmlSHRINK(ctxt);
    }
    cur = (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64;
    inputid = unsafe { (*(*ctxt).input).id };
    nbatts = 0 as i32;
    nratts = 0 as i32;
    nbdef = 0 as i32;
    nbNs = 0 as i32;
    attval = 0 as i32;
    (unsafe { (*ctxt).nsNr = nsNr });
    localname = xmlParseQName(ctxt, &mut prefix);
    if localname.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"StartTag: invalid element name\n\0" as *const u8 as *const i8,
        );
        return 0 as *const xmlChar;
    }
    (unsafe { *tlen = (((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as i64 as u64)
        .wrapping_sub(cur) as i32 });
    xmlSkipBlankChars(ctxt);
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    loop {
        if !((unsafe { *(*(*ctxt).input).cur }) as i32 != '>' as i32
            && ((unsafe { *(*(*ctxt).input).cur }) as i32 != '/' as i32
                || (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 != '>' as i32)
            && (0x9 as i32 <= (unsafe { *(*(*ctxt).input).cur }) as i32
                && (unsafe { *(*(*ctxt).input).cur }) as i32 <= 0xa as i32
                || (unsafe { *(*(*ctxt).input).cur }) as i32 == 0xd as i32
                || 0x20 as i32 <= (unsafe { *(*(*ctxt).input).cur }) as i32)
            && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32)
        {
            current_block = 9587810615301548814;
            break;
        }
        let mut id: i32 = unsafe { (*(*ctxt).input).id };
        let mut cons: u64 = (unsafe { (*(*ctxt).input).consumed })
            .wrapping_add((unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64);
        let mut len: i32 = -(1 as i32);
        let mut alloc: i32 = 0 as i32;
        attname = xmlParseAttribute2(
            ctxt,
            prefix,
            localname,
            &mut aprefix,
            &mut attvalue,
            &mut len,
            &mut alloc,
        );
        if !(attname.is_null() || attvalue.is_null()) {
            if len < 0 as i32 {
                len = unsafe { xmlStrlen(attvalue) };
            }
            if attname == (unsafe { (*ctxt).str_xmlns }) && aprefix.is_null() {
                let mut URL: *const xmlChar = unsafe { xmlDictLookup((*ctxt).dict, attvalue, len) };
                let mut uri: xmlURIPtr = 0 as *mut xmlURI;
                if URL.is_null() {
                    (unsafe { xmlErrMemory(
                        ctxt,
                        b"dictionary allocation failure\0" as *const u8 as *const i8,
                    ) });
                    if !attvalue.is_null() && alloc != 0 as i32 {
                        (unsafe { xmlFree.expect("non-null function pointer")(attvalue as *mut libc::c_void) });
                    }
                    localname = 0 as *const xmlChar;
                    current_block = 11274969702264896952;
                    break;
                } else {
                    if (unsafe { *URL }) as i32 != 0 as i32 {
                        uri = unsafe { xmlParseURI(URL as *const i8) };
                        if uri.is_null() {
                            xmlNsErr(
                                ctxt,
                                XML_WAR_NS_URI,
                                b"xmlns: '%s' is not a valid URI\n\0" as *const u8 as *const i8,
                                URL,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                            );
                        } else {
                            if (unsafe { (*uri).scheme }).is_null() {
                                xmlNsWarn(
                                    ctxt,
                                    XML_WAR_NS_URI_RELATIVE,
                                    b"xmlns: URI %s is not absolute\n\0" as *const u8 as *const i8,
                                    URL,
                                    0 as *const xmlChar,
                                    0 as *const xmlChar,
                                );
                            }
                            (unsafe { xmlFreeURI(uri) });
                        }
                        if URL == (unsafe { (*ctxt).str_xml_ns }) {
                            if attname != (unsafe { (*ctxt).str_xml }) {
                                xmlNsErr(
                                    ctxt,
                                    XML_NS_ERR_XML_NAMESPACE,
                                    b"xml namespace URI cannot be the default namespace\n\0"
                                        as *const u8
                                        as *const i8,
                                    0 as *const xmlChar,
                                    0 as *const xmlChar,
                                    0 as *const xmlChar,
                                );
                            }
                            current_block = 7554104004771910880;
                        } else if len == 29 as i32
                            && (unsafe { xmlStrEqual(
                                URL,
                                b"http://www.w3.org/2000/xmlns/\0" as *const u8 as *const i8
                                    as *mut xmlChar,
                            ) }) != 0
                        {
                            xmlNsErr(
                                ctxt,
                                XML_NS_ERR_XML_NAMESPACE,
                                b"reuse of the xmlns namespace name is forbidden\n\0" as *const u8
                                    as *const i8,
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
                                if (unsafe { *((*ctxt).nsTab).offset(((*ctxt).nsNr - 2 as i32 * j) as isize) })
                                    .is_null()
                                {
                                    break;
                                }
                                j += 1;
                            }
                            if j <= nbNs {
                                xmlErrAttributeDup(ctxt, 0 as *const xmlChar, attname);
                            } else if nsPush(ctxt, 0 as *const xmlChar, URL) > 0 as i32 {
                                nbNs += 1;
                            }
                        }
                    }
                }
            } else if aprefix == (unsafe { (*ctxt).str_xmlns }) {
                let mut URL_0: *const xmlChar = unsafe { xmlDictLookup((*ctxt).dict, attvalue, len) };
                let mut uri_0: xmlURIPtr = 0 as *mut xmlURI;
                if attname == (unsafe { (*ctxt).str_xml }) {
                    if URL_0 != (unsafe { (*ctxt).str_xml_ns }) {
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
                } else if URL_0 == (unsafe { (*ctxt).str_xml_ns }) {
                    if attname != (unsafe { (*ctxt).str_xml }) {
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
                } else if attname == (unsafe { (*ctxt).str_xmlns }) {
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
                    && (unsafe { xmlStrEqual(
                        URL_0,
                        b"http://www.w3.org/2000/xmlns/\0" as *const u8 as *const i8
                            as *mut xmlChar,
                    ) }) != 0
                {
                    xmlNsErr(
                        ctxt,
                        XML_NS_ERR_XML_NAMESPACE,
                        b"reuse of the xmlns namespace name is forbidden\n\0" as *const u8
                            as *const i8,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                } else if URL_0.is_null() || (unsafe { *URL_0.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
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
                    uri_0 = unsafe { xmlParseURI(URL_0 as *const i8) };
                    if uri_0.is_null() {
                        xmlNsErr(
                            ctxt,
                            XML_WAR_NS_URI,
                            b"xmlns:%s: '%s' is not a valid URI\n\0" as *const u8 as *const i8,
                            attname,
                            URL_0,
                            0 as *const xmlChar,
                        );
                    } else {
                        if (unsafe { (*ctxt).pedantic }) != 0 && (unsafe { (*uri_0).scheme }).is_null() {
                            xmlNsWarn(
                                ctxt,
                                XML_WAR_NS_URI_RELATIVE,
                                b"xmlns:%s: URI %s is not absolute\n\0" as *const u8 as *const i8,
                                attname,
                                URL_0,
                                0 as *const xmlChar,
                            );
                        }
                        (unsafe { xmlFreeURI(uri_0) });
                    }
                    j = 1 as i32;
                    while j <= nbNs {
                        if (unsafe { *((*ctxt).nsTab).offset(((*ctxt).nsNr - 2 as i32 * j) as isize) })
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
                    if xmlCtxtGrowAttrs(ctxt, nbatts + 5 as i32) < 0 as i32 {
                        current_block = 7554104004771910880;
                    } else {
                        maxatts = unsafe { (*ctxt).maxatts };
                        atts = unsafe { (*ctxt).atts };
                        current_block = 2463987395154258233;
                    }
                } else {
                    current_block = 2463987395154258233;
                }
                match current_block {
                    7554104004771910880 => {}
                    _ => {
                        let fresh366 = nratts;
                        nratts = nratts + 1;
                        (unsafe { *((*ctxt).attallocs).offset(fresh366 as isize) = alloc });
                        let fresh367 = nbatts;
                        nbatts = nbatts + 1;
                        let fresh368 = unsafe { &mut (*atts.offset(fresh367 as isize)) };
                        *fresh368 = attname;
                        let fresh369 = nbatts;
                        nbatts = nbatts + 1;
                        let fresh370 = unsafe { &mut (*atts.offset(fresh369 as isize)) };
                        *fresh370 = aprefix;
                        if alloc != 0 {
                            let fresh371 = nbatts;
                            nbatts = nbatts + 1;
                            let fresh372 = unsafe { &mut (*atts.offset(fresh371 as isize)) };
                            *fresh372 = 0 as *const xmlChar;
                        } else {
                            let fresh373 = nbatts;
                            nbatts = nbatts + 1;
                            let fresh374 = unsafe { &mut (*atts.offset(fresh373 as isize)) };
                            *fresh374 = unsafe { (*(*ctxt).input).base };
                        }
                        let fresh375 = nbatts;
                        nbatts = nbatts + 1;
                        let fresh376 = unsafe { &mut (*atts.offset(fresh375 as isize)) };
                        *fresh376 = attvalue;
                        attvalue = unsafe { attvalue.offset(len as isize) };
                        let fresh377 = nbatts;
                        nbatts = nbatts + 1;
                        let fresh378 = unsafe { &mut (*atts.offset(fresh377 as isize)) };
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
            (unsafe { xmlFree.expect("non-null function pointer")(attvalue as *mut libc::c_void) });
            attvalue = 0 as *mut xmlChar;
        }
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
            current_block = 9587810615301548814;
            break;
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '>' as i32
            || (unsafe { *(*(*ctxt).input).cur }) as i32 == '/' as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '>' as i32
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
            == (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
            )
            && id == (unsafe { (*(*ctxt).input).id })
            && attname.is_null()
            && attvalue.is_null()
        {
            xmlFatalErr(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"xmlParseStartTag: problem parsing attributes\n\0" as *const u8 as *const i8,
            );
            current_block = 9587810615301548814;
            break;
        } else if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
    }
    match current_block {
        9587810615301548814 => {
            if (unsafe { (*(*ctxt).input).id }) != inputid {
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
                    if !(unsafe { *atts.offset((i + 2 as i32) as isize) }).is_null() {
                        let mut offset: ptrdiff_t = (unsafe { ((*(*ctxt).input).base)
                            .offset_from(*atts.offset((i + 2 as i32) as isize)) })
                            as i64;
                        let fresh379 = unsafe { &mut (*atts.offset((i + 2 as i32) as isize)) };
                        *fresh379 = 0 as *const xmlChar;
                        let fresh380 = unsafe { &mut (*atts.offset((i + 3 as i32) as isize)) };
                        *fresh380 = unsafe { (*fresh380).offset(offset as isize) };
                        let fresh381 = unsafe { &mut (*atts.offset((i + 4 as i32) as isize)) };
                        *fresh381 = unsafe { (*fresh381).offset(offset as isize) };
                    }
                    i += 5 as i32;
                    j += 1;
                }
                if !(unsafe { (*ctxt).attsDefault }).is_null() {
                    let mut defaults: xmlDefAttrsPtr = 0 as *mut xmlDefAttrs;
                    defaults =
                        (unsafe { xmlHashLookup2((*ctxt).attsDefault, localname, prefix) }) as xmlDefAttrsPtr;
                    if !defaults.is_null() {
                        i = 0 as i32;
                        loop {
                            if !(i < (unsafe { (*defaults).nbAttrs })) {
                                current_block = 981657943452992752;
                                break;
                            }
                            attname = unsafe { *((*defaults).values)
                                .as_mut_ptr()
                                .offset((5 as i32 * i) as isize) };
                            aprefix = unsafe { *((*defaults).values)
                                .as_mut_ptr()
                                .offset((5 as i32 * i + 1 as i32) as isize) };
                            if attname == (unsafe { (*ctxt).str_xmlns }) && aprefix.is_null() {
                                j = 1 as i32;
                                while j <= nbNs {
                                    if (unsafe { *((*ctxt).nsTab)
                                        .offset(((*ctxt).nsNr - 2 as i32 * j) as isize) })
                                    .is_null()
                                    {
                                        break;
                                    }
                                    j += 1;
                                }
                                if !(j <= nbNs) {
                                    nsname = xmlGetNamespace(ctxt, 0 as *const xmlChar);
                                    if nsname
                                        != (unsafe { *((*defaults).values)
                                            .as_mut_ptr()
                                            .offset((5 as i32 * i + 2 as i32) as isize) })
                                    {
                                        if nsPush(
                                            ctxt,
                                            0 as *const xmlChar,
                                            unsafe { *((*defaults).values)
                                                .as_mut_ptr()
                                                .offset((5 as i32 * i + 2 as i32) as isize) },
                                        ) > 0 as i32
                                        {
                                            nbNs += 1;
                                        }
                                    }
                                }
                            } else if aprefix == (unsafe { (*ctxt).str_xmlns }) {
                                j = 1 as i32;
                                while j <= nbNs {
                                    if (unsafe { *((*ctxt).nsTab)
                                        .offset(((*ctxt).nsNr - 2 as i32 * j) as isize) })
                                        == attname
                                    {
                                        break;
                                    }
                                    j += 1;
                                }
                                if !(j <= nbNs) {
                                    nsname = xmlGetNamespace(ctxt, attname);
                                    if nsname
                                        != (unsafe { *((*defaults).values)
                                            .as_mut_ptr()
                                            .offset(2 as i32 as isize) })
                                    {
                                        if nsPush(
                                            ctxt,
                                            attname,
                                            unsafe { *((*defaults).values)
                                                .as_mut_ptr()
                                                .offset((5 as i32 * i + 2 as i32) as isize) },
                                        ) > 0 as i32
                                        {
                                            nbNs += 1;
                                        }
                                    }
                                }
                            } else {
                                j = 0 as i32;
                                while j < nbatts {
                                    if attname == (unsafe { *atts.offset(j as isize) })
                                        && aprefix == (unsafe { *atts.offset((j + 1 as i32) as isize) })
                                    {
                                        break;
                                    }
                                    j += 5 as i32;
                                }
                                if !(j < nbatts) {
                                    if atts.is_null() || nbatts + 5 as i32 > maxatts {
                                        if xmlCtxtGrowAttrs(ctxt, nbatts + 5 as i32) < 0 as i32 {
                                            localname = 0 as *const xmlChar;
                                            current_block = 11274969702264896952;
                                            break;
                                        } else {
                                            maxatts = unsafe { (*ctxt).maxatts };
                                            atts = unsafe { (*ctxt).atts };
                                        }
                                    }
                                    let fresh382 = nbatts;
                                    nbatts = nbatts + 1;
                                    let fresh383 = unsafe { &mut (*atts.offset(fresh382 as isize)) };
                                    *fresh383 = attname;
                                    let fresh384 = nbatts;
                                    nbatts = nbatts + 1;
                                    let fresh385 = unsafe { &mut (*atts.offset(fresh384 as isize)) };
                                    *fresh385 = aprefix;
                                    if aprefix.is_null() {
                                        let fresh386 = nbatts;
                                        nbatts = nbatts + 1;
                                        let fresh387 = unsafe { &mut (*atts.offset(fresh386 as isize)) };
                                        *fresh387 = 0 as *const xmlChar;
                                    } else {
                                        let fresh388 = nbatts;
                                        nbatts = nbatts + 1;
                                        let fresh389 = unsafe { &mut (*atts.offset(fresh388 as isize)) };
                                        *fresh389 = xmlGetNamespace(ctxt, aprefix);
                                    }
                                    let fresh390 = nbatts;
                                    nbatts = nbatts + 1;
                                    let fresh391 = unsafe { &mut (*atts.offset(fresh390 as isize)) };
                                    *fresh391 = unsafe { *((*defaults).values)
                                        .as_mut_ptr()
                                        .offset((5 as i32 * i + 2 as i32) as isize) };
                                    let fresh392 = nbatts;
                                    nbatts = nbatts + 1;
                                    let fresh393 = unsafe { &mut (*atts.offset(fresh392 as isize)) };
                                    *fresh393 = unsafe { *((*defaults).values)
                                        .as_mut_ptr()
                                        .offset((5 as i32 * i + 3 as i32) as isize) };
                                    if (unsafe { (*ctxt).standalone }) == 1 as i32
                                        && !(unsafe { *((*defaults).values)
                                            .as_mut_ptr()
                                            .offset((5 as i32 * i + 4 as i32) as isize) })
                                        .is_null()
                                    {
                                        xmlValidityError (ctxt , XML_DTD_STANDALONE_DEFAULTED , b"standalone: attribute %s on %s defaulted from external subset\n\0" as * const u8 as * const i8 , attname , localname ,) ;
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
                            if !(unsafe { *atts.offset((i + 1 as i32) as isize) }).is_null() {
                                nsname =
                                    xmlGetNamespace(ctxt, unsafe { *atts.offset((i + 1 as i32) as isize) });
                                if nsname.is_null() {
                                    xmlNsErr(
                                        ctxt,
                                        XML_NS_ERR_UNDEFINED_NAMESPACE,
                                        b"Namespace prefix %s for %s on %s is not defined\n\0"
                                            as *const u8
                                            as *const i8,
                                        unsafe { *atts.offset((i + 1 as i32) as isize) },
                                        unsafe { *atts.offset(i as isize) },
                                        localname,
                                    );
                                }
                                let fresh394 = unsafe { &mut (*atts.offset((i + 2 as i32) as isize)) };
                                *fresh394 = nsname;
                            } else {
                                nsname = 0 as *const xmlChar;
                            }
                            j = 0 as i32;
                            while j < i {
                                if (unsafe { *atts.offset(i as isize) }) == (unsafe { *atts.offset(j as isize) }) {
                                    if (unsafe { *atts.offset((i + 1 as i32) as isize) })
                                        == (unsafe { *atts.offset((j + 1 as i32) as isize) })
                                    {
                                        xmlErrAttributeDup(
                                            ctxt,
                                            unsafe { *atts.offset((i + 1 as i32) as isize) },
                                            unsafe { *atts.offset(i as isize) },
                                        );
                                        break;
                                    } else if !nsname.is_null()
                                        && (unsafe { *atts.offset((j + 2 as i32) as isize) }) == nsname
                                    {
                                        xmlNsErr(
                                            ctxt,
                                            XML_NS_ERR_ATTRIBUTE_REDEFINED,
                                            b"Namespaced Attribute %s in '%s' redefined\n\0"
                                                as *const u8
                                                as *const i8,
                                            unsafe { *atts.offset(i as isize) },
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
                        (unsafe { *pref = prefix });
                        (unsafe { *URI = nsname });
                        if !(unsafe { (*ctxt).sax }).is_null()
                            && (unsafe { ((*(*ctxt).sax).startElementNs).is_some() })
                            && (unsafe { (*ctxt).disableSAX }) == 0
                        {
                            if nbNs > 0 as i32 {
                                (unsafe { ((*(*ctxt).sax).startElementNs).expect("non-null function pointer")(
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
                                ) });
                            } else {
                                (unsafe { ((*(*ctxt).sax).startElementNs).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                    localname,
                                    prefix,
                                    nsname,
                                    0 as i32,
                                    0 as *mut *const xmlChar,
                                    nbatts / 5 as i32,
                                    nbdef,
                                    atts,
                                ) });
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
            if (unsafe { *((*ctxt).attallocs).offset(j as isize) }) != 0 as i32
                && !(unsafe { *atts.offset(i as isize) }).is_null()
            {
                (unsafe { xmlFree.expect("non-null function pointer")(
                    *atts.offset(i as isize) as *mut xmlChar as *mut libc::c_void,
                ) });
            }
            i += 5 as i32;
            j += 1;
        }
    }
    return localname;
}
extern "C" fn xmlParseEndTag2(mut ctxt: xmlParserCtxtPtr, mut tag: *const xmlStartTag) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '<' as i32
        || (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 != '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_LTSLASH_REQUIRED, 0 as *const i8);
        return;
    }
    let fresh395 = unsafe { &mut ((*(*ctxt).input).cur) };
    *fresh395 = unsafe { (*fresh395).offset(2 as i32 as isize) };
    (unsafe { (*(*ctxt).input).col += 2 as i32 });
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
        (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
    }
    if (unsafe { (*tag).prefix }).is_null() {
        name = xmlParseNameAndCompare(ctxt, unsafe { (*ctxt).name });
    } else {
        name = xmlParseQNameAndCompare(ctxt, unsafe { (*ctxt).name }, unsafe { (*tag).prefix });
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return;
    }
    xmlSkipBlankChars(ctxt);
    if !(0x9 as i32 <= (unsafe { *(*(*ctxt).input).cur }) as i32 && (unsafe { *(*(*ctxt).input).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*(*ctxt).input).cur }) as i32 == 0xd as i32
        || 0x20 as i32 <= (unsafe { *(*(*ctxt).input).cur }) as i32)
        || (unsafe { *(*(*ctxt).input).cur }) as i32 != '>' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_GT_REQUIRED, 0 as *const i8);
    } else {
        let fresh396 = unsafe { &mut ((*(*ctxt).input).col) };
        *fresh396 += 1;
        let fresh397 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh397 = unsafe { (*fresh397).offset(1) };
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
    }
    if name != 1 as i32 as *mut xmlChar as *const xmlChar {
        if name.is_null() {
            name = b"unparsable\0" as *const u8 as *const i8 as *mut xmlChar;
        }
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_TAG_NAME_MISMATCH,
            b"Opening and ending tag mismatch: %s line %d and %s\n\0" as *const u8 as *const i8,
            unsafe { (*ctxt).name },
            unsafe { (*tag).line },
            name,
        );
    }
    if !(unsafe { (*ctxt).sax }).is_null()
        && (unsafe { ((*(*ctxt).sax).endElementNs).is_some() })
        && (unsafe { (*ctxt).disableSAX }) == 0
    {
        (unsafe { ((*(*ctxt).sax).endElementNs).expect("non-null function pointer")(
            (*ctxt).userData,
            (*ctxt).name,
            (*tag).prefix,
            (*tag).URI,
        ) });
    }
    spacePop(ctxt);
    if (unsafe { (*tag).nsNr }) != 0 as i32 {
        nsPop(ctxt, unsafe { (*tag).nsNr });
    }
}
#[no_mangle]
pub extern "C" fn xmlParseCDSect(mut ctxt: xmlParserCtxtPtr) {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 100 as i32;
    let mut r: i32 = 0;
    let mut rl: i32 = 0;
    let mut s: i32 = 0;
    let mut sl: i32 = 0;
    let mut cur: i32 = 0;
    let mut l: i32 = 0;
    let mut count: i32 = 0 as i32;
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == '!' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == '[' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'C' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'D' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'A' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) }) as i32 == 'A' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(8 as i32 as isize) }) as i32 == '[' as i32
    {
        let fresh398 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh398 = unsafe { (*fresh398).offset(9 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 9 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
    } else {
        return;
    }
    (unsafe { (*ctxt).instate = XML_PARSER_CDATA_SECTION });
    r = unsafe { xmlCurrentChar(ctxt, &mut rl) };
    if if r < 0x100 as i32 {
        (0x9 as i32 <= r && r <= 0xa as i32 || r == 0xd as i32 || 0x20 as i32 <= r) as i32
    } else {
        (0x100 as i32 <= r && r <= 0xd7ff as i32
            || 0xe000 as i32 <= r && r <= 0xfffd as i32
            || 0x10000 as i32 <= r && r <= 0x10ffff as i32) as i32
    } == 0
    {
        xmlFatalErr(ctxt, XML_ERR_CDATA_NOT_FINISHED, 0 as *const i8);
        (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
        return;
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
        let fresh399 = unsafe { &mut ((*(*ctxt).input).line) };
        *fresh399 += 1;
        (unsafe { (*(*ctxt).input).col = 1 as i32 });
    } else {
        let fresh400 = unsafe { &mut ((*(*ctxt).input).col) };
        *fresh400 += 1;
    }
    let fresh401 = unsafe { &mut ((*(*ctxt).input).cur) };
    *fresh401 = unsafe { (*fresh401).offset(rl as isize) };
    s = unsafe { xmlCurrentChar(ctxt, &mut sl) };
    if if s < 0x100 as i32 {
        (0x9 as i32 <= s && s <= 0xa as i32 || s == 0xd as i32 || 0x20 as i32 <= s) as i32
    } else {
        (0x100 as i32 <= s && s <= 0xd7ff as i32
            || 0xe000 as i32 <= s && s <= 0xfffd as i32
            || 0x10000 as i32 <= s && s <= 0x10ffff as i32) as i32
    } == 0
    {
        xmlFatalErr(ctxt, XML_ERR_CDATA_NOT_FINISHED, 0 as *const i8);
        (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
        return;
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
        let fresh402 = unsafe { &mut ((*(*ctxt).input).line) };
        *fresh402 += 1;
        (unsafe { (*(*ctxt).input).col = 1 as i32 });
    } else {
        let fresh403 = unsafe { &mut ((*(*ctxt).input).col) };
        *fresh403 += 1;
    }
    let fresh404 = unsafe { &mut ((*(*ctxt).input).cur) };
    *fresh404 = unsafe { (*fresh404).offset(sl as isize) };
    cur = unsafe { xmlCurrentChar(ctxt, &mut l) };
    buf = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
        (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) }) as *mut xmlChar;
    if buf.is_null() {
        (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
        return;
    }
    while (if cur < 0x100 as i32 {
        (0x9 as i32 <= cur && cur <= 0xa as i32 || cur == 0xd as i32 || 0x20 as i32 <= cur) as i32
    } else {
        (0x100 as i32 <= cur && cur <= 0xd7ff as i32
            || 0xe000 as i32 <= cur && cur <= 0xfffd as i32
            || 0x10000 as i32 <= cur && cur <= 0x10ffff as i32) as i32
    }) != 0
        && (r != ']' as i32 || s != ']' as i32 || cur != '>' as i32)
    {
        if len + 5 as i32 >= size {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            if size > 10000000 as i32 && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32 {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_CDATA_NOT_FINISHED,
                    b"CData section too big found\0" as *const u8 as *const i8,
                    0 as *const xmlChar,
                );
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                return;
            }
            tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                buf as *mut libc::c_void,
                ((size * 2 as i32) as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) }) as *mut xmlChar;
            if tmp.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                return;
            }
            buf = tmp;
            size *= 2 as i32;
        }
        if rl == 1 as i32 {
            let fresh405 = len;
            len = len + 1;
            (unsafe { *buf.offset(fresh405 as isize) = r as xmlChar });
        } else {
            len += unsafe { xmlCopyCharMultiByte(&mut *buf.offset(len as isize), r) };
        }
        r = s;
        rl = sl;
        s = cur;
        sl = l;
        count += 1;
        if count > 50 as i32 {
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                    > (2 as i32 * 250 as i32) as i64
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < (2 as i32 * 250 as i32) as i64
            {
                xmlSHRINK(ctxt);
            }
            if (unsafe { (*ctxt).progressive }) == 0 as i32
                && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                    < 250 as i32 as i64
            {
                xmlGROW(ctxt);
            }
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                return;
            }
            count = 0 as i32;
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
            let fresh406 = unsafe { &mut ((*(*ctxt).input).line) };
            *fresh406 += 1;
            (unsafe { (*(*ctxt).input).col = 1 as i32 });
        } else {
            let fresh407 = unsafe { &mut ((*(*ctxt).input).col) };
            *fresh407 += 1;
        }
        let fresh408 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh408 = unsafe { (*fresh408).offset(l as isize) };
        cur = unsafe { xmlCurrentChar(ctxt, &mut l) };
    }
    (unsafe { *buf.offset(len as isize) = 0 as i32 as xmlChar });
    (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
    if cur != '>' as i32 {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_CDATA_NOT_FINISHED,
            b"CData section not finished\n%.50s\n\0" as *const u8 as *const i8,
            buf,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
        return;
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
        let fresh409 = unsafe { &mut ((*(*ctxt).input).line) };
        *fresh409 += 1;
        (unsafe { (*(*ctxt).input).col = 1 as i32 });
    } else {
        let fresh410 = unsafe { &mut ((*(*ctxt).input).col) };
        *fresh410 += 1;
    }
    let fresh411 = unsafe { &mut ((*(*ctxt).input).cur) };
    *fresh411 = unsafe { (*fresh411).offset(l as isize) };
    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { (*ctxt).disableSAX }) == 0 {
        if unsafe { ((*(*ctxt).sax).cdataBlock).is_some() } {
            (unsafe { ((*(*ctxt).sax).cdataBlock).expect("non-null function pointer")(
                (*ctxt).userData,
                buf,
                len,
            ) });
        } else if unsafe { ((*(*ctxt).sax).characters).is_some() } {
            (unsafe { ((*(*ctxt).sax).characters).expect("non-null function pointer")(
                (*ctxt).userData,
                buf,
                len,
            ) });
        }
    }
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
}
extern "C" fn xmlParseContentInternal(mut ctxt: xmlParserCtxtPtr) {
    let mut nameNr: i32 = unsafe { (*ctxt).nameNr };
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    while (unsafe { *(*(*ctxt).input).cur }) as i32 != 0 as i32
        && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32
    {
        let mut id: i32 = unsafe { (*(*ctxt).input).id };
        let mut cons: u64 = (unsafe { (*(*ctxt).input).consumed })
            .wrapping_add((unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64);
        let mut cur: *const xmlChar = unsafe { (*(*ctxt).input).cur };
        if (unsafe { *cur }) as i32 == '<' as i32 && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '?' as i32 {
            xmlParsePI(ctxt);
        } else if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == '!' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == '[' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'C' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'D' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'A' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'T' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) }) as i32 == 'A' as i32
            && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(8 as i32 as isize) }) as i32 == '[' as i32
        {
            xmlParseCDSect(ctxt);
        } else if (unsafe { *cur }) as i32 == '<' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '!' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == '-' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) }) as i32 == '-' as i32
        {
            xmlParseComment(ctxt);
            (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
        } else if (unsafe { *cur }) as i32 == '<' as i32 {
            if (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32 {
                if (unsafe { (*ctxt).nameNr }) <= nameNr {
                    break;
                }
                xmlParseElementEnd(ctxt);
            } else {
                xmlParseElementStart(ctxt);
            }
        } else if (unsafe { *cur }) as i32 == '&' as i32 {
            xmlParseReference(ctxt);
        } else {
            xmlParseCharData(ctxt, 0 as i32);
        }
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                > (2 as i32 * 250 as i32) as i64
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                < (2 as i32 * 250 as i32) as i64
        {
            xmlSHRINK(ctxt);
        }
        if !(cons
            == (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
            )
            && id == (unsafe { (*(*ctxt).input).id }))
        {
            continue;
        }
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"detected an error in element content\n\0" as *const u8 as *const i8,
        );
        xmlHaltParser(ctxt);
        break;
    }
}
#[no_mangle]
pub extern "C" fn xmlParseContent(mut ctxt: xmlParserCtxtPtr) {
    let mut nameNr: i32 = unsafe { (*ctxt).nameNr };
    xmlParseContentInternal(ctxt);
    if (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32 && (unsafe { (*ctxt).nameNr }) > nameNr {
        let mut name: *const xmlChar =
            unsafe { *((*ctxt).nameTab).offset(((*ctxt).nameNr - 1 as i32) as isize) };
        let mut line: i32 = unsafe { (*((*ctxt).pushTab).offset(((*ctxt).nameNr - 1 as i32) as isize)).line };
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_TAG_NOT_FINISHED,
            b"Premature end of data in tag %s line %d\n\0" as *const u8 as *const i8,
            name,
            line,
            0 as *const xmlChar,
        );
    }
}
#[no_mangle]
pub extern "C" fn xmlParseElement(mut ctxt: xmlParserCtxtPtr) {
    if xmlParseElementStart(ctxt) != 0 as i32 {
        return;
    }
    xmlParseContentInternal(ctxt);
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return;
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
        let mut name: *const xmlChar =
            unsafe { *((*ctxt).nameTab).offset(((*ctxt).nameNr - 1 as i32) as isize) };
        let mut line: i32 = unsafe { (*((*ctxt).pushTab).offset(((*ctxt).nameNr - 1 as i32) as isize)).line };
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_TAG_NOT_FINISHED,
            b"Premature end of data in tag %s line %d\n\0" as *const u8 as *const i8,
            name,
            line,
            0 as *const xmlChar,
        );
        return;
    }
    xmlParseElementEnd(ctxt);
}
extern "C" fn xmlParseElementStart(mut ctxt: xmlParserCtxtPtr) -> i32 {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut prefix: *const xmlChar = 0 as *const xmlChar;
    let mut URI: *const xmlChar = 0 as *const xmlChar;
    let mut node_info: xmlParserNodeInfo = xmlParserNodeInfo {
        node: 0 as *const _xmlNode,
        begin_pos: 0,
        begin_line: 0,
        end_pos: 0,
        end_line: 0,
    };
    let mut line: i32 = 0;
    let mut tlen: i32 = 0 as i32;
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    let mut nsNr: i32 = unsafe { (*ctxt).nsNr };
    if (unsafe { (*ctxt).nameNr }) as u32 > (unsafe { xmlParserMaxDepth })
        && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
    {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"Excessive depth in document: %d use XML_PARSE_HUGE option\n\0" as *const u8
                as *const i8,
            (unsafe { xmlParserMaxDepth }) as i32,
        );
        xmlHaltParser(ctxt);
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).record_info }) != 0 {
        node_info.begin_pos = (unsafe { (*(*ctxt).input).consumed })
            .wrapping_add((unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64);
        node_info.begin_line = (unsafe { (*(*ctxt).input).line }) as u64;
    }
    if (unsafe { (*ctxt).spaceNr }) == 0 as i32 {
        spacePush(ctxt, -(1 as i32));
    } else if (unsafe { *(*ctxt).space }) == -(2 as i32) {
        spacePush(ctxt, -(1 as i32));
    } else {
        spacePush(ctxt, unsafe { *(*ctxt).space });
    }
    line = unsafe { (*(*ctxt).input).line };
    if (unsafe { (*ctxt).sax2 }) != 0 {
        name = xmlParseStartTag2(ctxt, &mut prefix, &mut URI, &mut tlen);
    } else {
        name = xmlParseStartTag(ctxt);
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    if name.is_null() {
        spacePop(ctxt);
        return -(1 as i32);
    }
    nameNsPush(ctxt, name, prefix, URI, line, (unsafe { (*ctxt).nsNr }) - nsNr);
    ret = unsafe { (*ctxt).node };
    if (unsafe { (*ctxt).validate }) != 0
        && (unsafe { (*ctxt).wellFormed }) != 0
        && !(unsafe { (*ctxt).myDoc }).is_null()
        && !(unsafe { (*ctxt).node }).is_null()
        && (unsafe { (*ctxt).node }) == (unsafe { (*(*ctxt).myDoc).children })
    {
        (unsafe { (*ctxt).valid &= xmlValidateRoot(&mut (*ctxt).vctxt, (*ctxt).myDoc) });
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '/' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '>' as i32
    {
        let fresh412 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh412 = unsafe { (*fresh412).offset(2 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 2 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        if (unsafe { (*ctxt).sax2 }) != 0 {
            if !(unsafe { (*ctxt).sax }).is_null()
                && (unsafe { ((*(*ctxt).sax).endElementNs).is_some() })
                && (unsafe { (*ctxt).disableSAX }) == 0
            {
                (unsafe { ((*(*ctxt).sax).endElementNs).expect("non-null function pointer")(
                    (*ctxt).userData,
                    name,
                    prefix,
                    URI,
                ) });
            }
        } else if !(unsafe { (*ctxt).sax }).is_null()
            && (unsafe { ((*(*ctxt).sax).endElement).is_some() })
            && (unsafe { (*ctxt).disableSAX }) == 0
        {
            (unsafe { ((*(*ctxt).sax).endElement).expect("non-null function pointer")((*ctxt).userData, name) });
        }
        namePop(ctxt);
        spacePop(ctxt);
        if nsNr != (unsafe { (*ctxt).nsNr }) {
            nsPop(ctxt, (unsafe { (*ctxt).nsNr }) - nsNr);
        }
        if !ret.is_null() && (unsafe { (*ctxt).record_info }) != 0 {
            node_info.end_pos = (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
            );
            node_info.end_line = (unsafe { (*(*ctxt).input).line }) as u64;
            node_info.node = ret as *const _xmlNode;
            (unsafe { xmlParserAddNodeInfo(ctxt, &mut node_info) });
        }
        return 1 as i32;
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '>' as i32 {
        let fresh413 = unsafe { &mut ((*(*ctxt).input).col) };
        *fresh413 += 1;
        let fresh414 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh414 = unsafe { (*fresh414).offset(1) };
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
    } else {
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_GT_REQUIRED,
            b"Couldn't find end of Start Tag %s line %d\n\0" as *const u8 as *const i8,
            name,
            line,
            0 as *const xmlChar,
        );
        nodePop(ctxt);
        namePop(ctxt);
        spacePop(ctxt);
        if nsNr != (unsafe { (*ctxt).nsNr }) {
            nsPop(ctxt, (unsafe { (*ctxt).nsNr }) - nsNr);
        }
        if !ret.is_null() && (unsafe { (*ctxt).record_info }) != 0 {
            node_info.end_pos = (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
            );
            node_info.end_line = (unsafe { (*(*ctxt).input).line }) as u64;
            node_info.node = ret as *const _xmlNode;
            (unsafe { xmlParserAddNodeInfo(ctxt, &mut node_info) });
        }
        return -(1 as i32);
    }
    return 0 as i32;
}
extern "C" fn xmlParseElementEnd(mut ctxt: xmlParserCtxtPtr) {
    let mut node_info: xmlParserNodeInfo = xmlParserNodeInfo {
        node: 0 as *const _xmlNode,
        begin_pos: 0,
        begin_line: 0,
        end_pos: 0,
        end_line: 0,
    };
    let mut ret: xmlNodePtr = unsafe { (*ctxt).node };
    if (unsafe { (*ctxt).nameNr }) <= 0 as i32 {
        return;
    }
    if (unsafe { (*ctxt).sax2 }) != 0 {
        xmlParseEndTag2(
            ctxt,
            unsafe { &mut *((*ctxt).pushTab).offset(((*ctxt).nameNr - 1 as i32) as isize) },
        );
        namePop(ctxt);
    } else {
        xmlParseEndTag1(ctxt, 0 as i32);
    }
    if !ret.is_null() && (unsafe { (*ctxt).record_info }) != 0 {
        node_info.end_pos = (unsafe { (*(*ctxt).input).consumed })
            .wrapping_add((unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64);
        node_info.end_line = (unsafe { (*(*ctxt).input).line }) as u64;
        node_info.node = ret as *const _xmlNode;
        (unsafe { xmlParserAddNodeInfo(ctxt, &mut node_info) });
    }
}
#[no_mangle]
pub extern "C" fn xmlParseVersionNum(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 10 as i32;
    let mut cur: xmlChar = 0;
    buf = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
        (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) }) as *mut xmlChar;
    if buf.is_null() {
        (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
        return 0 as *mut xmlChar;
    }
    cur = unsafe { *(*(*ctxt).input).cur };
    if !(cur as i32 >= '0' as i32 && cur as i32 <= '9' as i32) {
        (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
        return 0 as *mut xmlChar;
    }
    let fresh415 = len;
    len = len + 1;
    (unsafe { *buf.offset(fresh415 as isize) = cur });
    (unsafe { xmlNextChar(ctxt) });
    cur = unsafe { *(*(*ctxt).input).cur };
    if cur as i32 != '.' as i32 {
        (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
        return 0 as *mut xmlChar;
    }
    let fresh416 = len;
    len = len + 1;
    (unsafe { *buf.offset(fresh416 as isize) = cur });
    (unsafe { xmlNextChar(ctxt) });
    cur = unsafe { *(*(*ctxt).input).cur };
    while cur as i32 >= '0' as i32 && cur as i32 <= '9' as i32 {
        if len + 1 as i32 >= size {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            size *= 2 as i32;
            tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                buf as *mut libc::c_void,
                (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            ) }) as *mut xmlChar;
            if tmp.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                return 0 as *mut xmlChar;
            }
            buf = tmp;
        }
        let fresh417 = len;
        len = len + 1;
        (unsafe { *buf.offset(fresh417 as isize) = cur });
        (unsafe { xmlNextChar(ctxt) });
        cur = unsafe { *(*(*ctxt).input).cur };
    }
    (unsafe { *buf.offset(len as isize) = 0 as i32 as xmlChar });
    return buf;
}
#[no_mangle]
pub extern "C" fn xmlParseVersionInfo(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    let mut version: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == 'v' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'e' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'r' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 's' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'i' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'o' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'n' as i32
    {
        let fresh418 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh418 = unsafe { (*fresh418).offset(7 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 7 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        xmlSkipBlankChars(ctxt);
        if (unsafe { *(*(*ctxt).input).cur }) as i32 != '=' as i32 {
            xmlFatalErr(ctxt, XML_ERR_EQUAL_REQUIRED, 0 as *const i8);
            return 0 as *mut xmlChar;
        }
        (unsafe { xmlNextChar(ctxt) });
        xmlSkipBlankChars(ctxt);
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '"' as i32 {
            (unsafe { xmlNextChar(ctxt) });
            version = xmlParseVersionNum(ctxt);
            if (unsafe { *(*(*ctxt).input).cur }) as i32 != '"' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const i8);
            } else {
                (unsafe { xmlNextChar(ctxt) });
            }
        } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\'' as i32 {
            (unsafe { xmlNextChar(ctxt) });
            version = xmlParseVersionNum(ctxt);
            if (unsafe { *(*(*ctxt).input).cur }) as i32 != '\'' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const i8);
            } else {
                (unsafe { xmlNextChar(ctxt) });
            }
        } else {
            xmlFatalErr(ctxt, XML_ERR_STRING_NOT_STARTED, 0 as *const i8);
        }
    }
    return version;
}
#[no_mangle]
pub extern "C" fn xmlParseEncName(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0 as i32;
    let mut size: i32 = 10 as i32;
    let mut cur: xmlChar = 0;
    cur = unsafe { *(*(*ctxt).input).cur };
    if cur as i32 >= 'a' as i32 && cur as i32 <= 'z' as i32
        || cur as i32 >= 'A' as i32 && cur as i32 <= 'Z' as i32
    {
        buf = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(
            (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        ) }) as *mut xmlChar;
        if buf.is_null() {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            return 0 as *mut xmlChar;
        }
        let fresh419 = len;
        len = len + 1;
        (unsafe { *buf.offset(fresh419 as isize) = cur });
        (unsafe { xmlNextChar(ctxt) });
        cur = unsafe { *(*(*ctxt).input).cur };
        while cur as i32 >= 'a' as i32 && cur as i32 <= 'z' as i32
            || cur as i32 >= 'A' as i32 && cur as i32 <= 'Z' as i32
            || cur as i32 >= '0' as i32 && cur as i32 <= '9' as i32
            || cur as i32 == '.' as i32
            || cur as i32 == '_' as i32
            || cur as i32 == '-' as i32
        {
            if len + 1 as i32 >= size {
                let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                size *= 2 as i32;
                tmp = (unsafe { xmlRealloc.expect("non-null function pointer")(
                    buf as *mut libc::c_void,
                    (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
                ) }) as *mut xmlChar;
                if tmp.is_null() {
                    (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                    return 0 as *mut xmlChar;
                }
                buf = tmp;
            }
            let fresh420 = len;
            len = len + 1;
            (unsafe { *buf.offset(fresh420 as isize) = cur });
            (unsafe { xmlNextChar(ctxt) });
            cur = unsafe { *(*(*ctxt).input).cur };
            if cur as i32 == 0 as i32 {
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                        > (2 as i32 * 250 as i32) as i64
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < (2 as i32 * 250 as i32) as i64
                {
                    xmlSHRINK(ctxt);
                }
                if (unsafe { (*ctxt).progressive }) == 0 as i32
                    && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64)
                        < 250 as i32 as i64
                {
                    xmlGROW(ctxt);
                }
                cur = unsafe { *(*(*ctxt).input).cur };
            }
        }
        (unsafe { *buf.offset(len as isize) = 0 as i32 as xmlChar });
    } else {
        xmlFatalErr(ctxt, XML_ERR_ENCODING_NAME, 0 as *const i8);
    }
    return buf;
}
#[no_mangle]
pub extern "C" fn xmlParseEncodingDecl(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut encoding: *mut xmlChar = 0 as *mut xmlChar;
    xmlSkipBlankChars(ctxt);
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == 'e' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 'n' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'c' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'o' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'd' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'i' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'n' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) }) as i32 == 'g' as i32
    {
        let fresh421 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh421 = unsafe { (*fresh421).offset(8 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 8 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        xmlSkipBlankChars(ctxt);
        if (unsafe { *(*(*ctxt).input).cur }) as i32 != '=' as i32 {
            xmlFatalErr(ctxt, XML_ERR_EQUAL_REQUIRED, 0 as *const i8);
            return 0 as *const xmlChar;
        }
        (unsafe { xmlNextChar(ctxt) });
        xmlSkipBlankChars(ctxt);
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '"' as i32 {
            (unsafe { xmlNextChar(ctxt) });
            encoding = xmlParseEncName(ctxt);
            if (unsafe { *(*(*ctxt).input).cur }) as i32 != '"' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const i8);
                (unsafe { xmlFree.expect("non-null function pointer")(encoding as *mut libc::c_void) });
                return 0 as *const xmlChar;
            } else {
                (unsafe { xmlNextChar(ctxt) });
            }
        } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\'' as i32 {
            (unsafe { xmlNextChar(ctxt) });
            encoding = xmlParseEncName(ctxt);
            if (unsafe { *(*(*ctxt).input).cur }) as i32 != '\'' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const i8);
                (unsafe { xmlFree.expect("non-null function pointer")(encoding as *mut libc::c_void) });
                return 0 as *const xmlChar;
            } else {
                (unsafe { xmlNextChar(ctxt) });
            }
        } else {
            xmlFatalErr(ctxt, XML_ERR_STRING_NOT_STARTED, 0 as *const i8);
        }
        if (unsafe { (*ctxt).options }) & XML_PARSE_IGNORE_ENC as i32 != 0 {
            (unsafe { xmlFree.expect("non-null function pointer")(encoding as *mut libc::c_void) });
            return 0 as *const xmlChar;
        }
        if !encoding.is_null()
            && ((unsafe { xmlStrcasecmp(
                encoding,
                b"UTF-16\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) == 0
                || (unsafe { xmlStrcasecmp(
                    encoding,
                    b"UTF16\0" as *const u8 as *const i8 as *mut xmlChar,
                ) }) == 0)
        {
            if (unsafe { (*ctxt).encoding }).is_null()
                && !(unsafe { (*(*ctxt).input).buf }).is_null()
                && (unsafe { (*(*(*ctxt).input).buf).encoder }).is_null()
            {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_INVALID_ENCODING,
                    b"Document labelled UTF-16 but has UTF-8 content\n\0" as *const u8 as *const i8,
                );
            }
            if !(unsafe { (*ctxt).encoding }).is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(
                    (*ctxt).encoding as *mut xmlChar as *mut libc::c_void,
                ) });
            }
            let fresh422 = unsafe { &mut ((*ctxt).encoding) };
            *fresh422 = encoding;
        } else if !encoding.is_null()
            && ((unsafe { xmlStrcasecmp(
                encoding,
                b"UTF-8\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) == 0
                || (unsafe { xmlStrcasecmp(
                    encoding,
                    b"UTF8\0" as *const u8 as *const i8 as *mut xmlChar,
                ) }) == 0)
        {
            if !(unsafe { (*ctxt).encoding }).is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(
                    (*ctxt).encoding as *mut xmlChar as *mut libc::c_void,
                ) });
            }
            let fresh423 = unsafe { &mut ((*ctxt).encoding) };
            *fresh423 = encoding;
        } else if !encoding.is_null() {
            let mut handler: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
            if !(unsafe { (*(*ctxt).input).encoding }).is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(
                    (*(*ctxt).input).encoding as *mut xmlChar as *mut libc::c_void,
                ) });
            }
            let fresh424 = unsafe { &mut ((*(*ctxt).input).encoding) };
            *fresh424 = encoding;
            handler = unsafe { xmlFindCharEncodingHandler(encoding as *const i8) };
            if !handler.is_null() {
                if (unsafe { xmlSwitchToEncoding(ctxt, handler) }) < 0 as i32 {
                    (unsafe { (*ctxt).errNo = XML_ERR_UNSUPPORTED_ENCODING as i32 });
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
pub extern "C" fn xmlParseSDDecl(mut ctxt: xmlParserCtxtPtr) -> i32 {
    let mut standalone: i32 = -(2 as i32);
    xmlSkipBlankChars(ctxt);
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == 's' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == 't' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'a' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'n' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'd' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'a' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'l' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) }) as i32 == 'o' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(8 as i32 as isize) }) as i32 == 'n' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(9 as i32 as isize) }) as i32 == 'e' as i32
    {
        let fresh425 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh425 = unsafe { (*fresh425).offset(10 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 10 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
        xmlSkipBlankChars(ctxt);
        if (unsafe { *(*(*ctxt).input).cur }) as i32 != '=' as i32 {
            xmlFatalErr(ctxt, XML_ERR_EQUAL_REQUIRED, 0 as *const i8);
            return standalone;
        }
        (unsafe { xmlNextChar(ctxt) });
        xmlSkipBlankChars(ctxt);
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\'' as i32 {
            (unsafe { xmlNextChar(ctxt) });
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 'n' as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == 'o' as i32
            {
                standalone = 0 as i32;
                let fresh426 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh426 = unsafe { (*fresh426).offset(2 as i32 as isize) };
                (unsafe { (*(*ctxt).input).col += 2 as i32 });
                if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                    (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                }
            } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == 'y' as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == 'e' as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == 's' as i32
            {
                standalone = 1 as i32;
                let fresh427 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh427 = unsafe { (*fresh427).offset(3 as i32 as isize) };
                (unsafe { (*(*ctxt).input).col += 3 as i32 });
                if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                    (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                }
            } else {
                xmlFatalErr(ctxt, XML_ERR_STANDALONE_VALUE, 0 as *const i8);
            }
            if (unsafe { *(*(*ctxt).input).cur }) as i32 != '\'' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const i8);
            } else {
                (unsafe { xmlNextChar(ctxt) });
            }
        } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '"' as i32 {
            (unsafe { xmlNextChar(ctxt) });
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 'n' as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == 'o' as i32
            {
                standalone = 0 as i32;
                let fresh428 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh428 = unsafe { (*fresh428).offset(2 as i32 as isize) };
                (unsafe { (*(*ctxt).input).col += 2 as i32 });
                if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                    (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                }
            } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == 'y' as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == 'e' as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == 's' as i32
            {
                standalone = 1 as i32;
                let fresh429 = unsafe { &mut ((*(*ctxt).input).cur) };
                *fresh429 = unsafe { (*fresh429).offset(3 as i32 as isize) };
                (unsafe { (*(*ctxt).input).col += 3 as i32 });
                if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                    (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                }
            } else {
                xmlFatalErr(ctxt, XML_ERR_STANDALONE_VALUE, 0 as *const i8);
            }
            if (unsafe { *(*(*ctxt).input).cur }) as i32 != '"' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const i8);
            } else {
                (unsafe { xmlNextChar(ctxt) });
            }
        } else {
            xmlFatalErr(ctxt, XML_ERR_STRING_NOT_STARTED, 0 as *const i8);
        }
    }
    return standalone;
}
#[no_mangle]
pub extern "C" fn xmlParseXMLDecl(mut ctxt: xmlParserCtxtPtr) {
    let mut version: *mut xmlChar = 0 as *mut xmlChar;
    (unsafe { (*(*ctxt).input).standalone = -(2 as i32) });
    let fresh430 = unsafe { &mut ((*(*ctxt).input).cur) };
    *fresh430 = unsafe { (*fresh430).offset(5 as i32 as isize) };
    (unsafe { (*(*ctxt).input).col += 5 as i32 });
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
        (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
    }
    if !((unsafe { *(*(*ctxt).input).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*(*ctxt).input).cur }) as i32 && (unsafe { *(*(*ctxt).input).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*(*ctxt).input).cur }) as i32 == 0xd as i32)
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
        if (unsafe { xmlStrEqual(
            version,
            b"1.0\0" as *const u8 as *const i8 as *const xmlChar,
        ) }) == 0
        {
            if (unsafe { (*ctxt).options }) & XML_PARSE_OLD10 as i32 != 0 {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_UNKNOWN_VERSION,
                    b"Unsupported version '%s'\n\0" as *const u8 as *const i8,
                    version,
                );
            } else if (unsafe { *version.offset(0 as i32 as isize) }) as i32 == '1' as i32
                && (unsafe { *version.offset(1 as i32 as isize) }) as i32 == '.' as i32
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
        if !(unsafe { (*ctxt).version }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).version as *mut libc::c_void) });
        }
        let fresh431 = unsafe { &mut ((*ctxt).version) };
        *fresh431 = version;
    }
    if !((unsafe { *(*(*ctxt).input).cur }) as i32 == 0x20 as i32
        || 0x9 as i32 <= (unsafe { *(*(*ctxt).input).cur }) as i32 && (unsafe { *(*(*ctxt).input).cur }) as i32 <= 0xa as i32
        || (unsafe { *(*(*ctxt).input).cur }) as i32 == 0xd as i32)
    {
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '?' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '>' as i32
        {
            let fresh432 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh432 = unsafe { (*fresh432).offset(2 as i32 as isize) };
            (unsafe { (*(*ctxt).input).col += 2 as i32 });
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
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
    if (unsafe { (*ctxt).errNo }) == XML_ERR_UNSUPPORTED_ENCODING as i32
        || (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !(unsafe { (*(*ctxt).input).encoding }).is_null()
        && !((unsafe { *(*(*ctxt).input).cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *(*(*ctxt).input).cur }) as i32
                && (unsafe { *(*(*ctxt).input).cur }) as i32 <= 0xa as i32
            || (unsafe { *(*(*ctxt).input).cur }) as i32 == 0xd as i32)
    {
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '?' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '>' as i32
        {
            let fresh433 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh433 = unsafe { (*fresh433).offset(2 as i32 as isize) };
            (unsafe { (*(*ctxt).input).col += 2 as i32 });
            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
            }
            return;
        }
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_SPACE_REQUIRED,
            b"Blank needed here\n\0" as *const u8 as *const i8,
        );
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    xmlSkipBlankChars(ctxt);
    (unsafe { (*(*ctxt).input).standalone = xmlParseSDDecl(ctxt) });
    xmlSkipBlankChars(ctxt);
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '?' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '>' as i32
    {
        let fresh434 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh434 = unsafe { (*fresh434).offset(2 as i32 as isize) };
        (unsafe { (*(*ctxt).input).col += 2 as i32 });
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
        }
    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 == '>' as i32 {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, 0 as *const i8);
        (unsafe { xmlNextChar(ctxt) });
    } else {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, 0 as *const i8);
        while (unsafe { *(*(*ctxt).input).cur }) as i32 != 0 && (unsafe { *(*(*ctxt).input).cur }) as i32 != '>' as i32 {
            let fresh435 = unsafe { &mut ((*(*ctxt).input).cur) };
            *fresh435 = unsafe { (*fresh435).offset(1) };
        }
        (unsafe { xmlNextChar(ctxt) });
    };
}
#[no_mangle]
pub extern "C" fn xmlParseMisc(mut ctxt: xmlParserCtxtPtr) {
    while (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32 {
        xmlSkipBlankChars(ctxt);
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '?' as i32
        {
            xmlParsePI(ctxt);
        } else {
            if !((unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32
                    == '!' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32
                    == '-' as i32
                && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32
                    == '-' as i32)
            {
                break;
            }
            xmlParseComment(ctxt);
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlParseDocument(mut ctxt: xmlParserCtxtPtr) -> i32 {
    let mut start: [xmlChar; 4] = [0; 4];
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    xmlInitParser();
    if ctxt.is_null() || (unsafe { (*ctxt).input }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    xmlDetectSAX2(ctxt);
    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).setDocumentLocator).is_some() }) {
        (unsafe { ((*(*ctxt).sax).setDocumentLocator).expect("non-null function pointer")(
            (*ctxt).userData,
            __xmlDefaultSAXLocator(),
        ) });
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).encoding }).is_null()
        && (unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64 >= 4 as i32 as i64
    {
        start[0 as i32 as usize] = unsafe { *(*(*ctxt).input).cur };
        start[1 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) };
        start[2 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) };
        start[3 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) };
        enc = unsafe { xmlDetectCharEncoding(&mut *start.as_mut_ptr().offset(0 as i32 as isize), 4 as i32) };
        if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
            (unsafe { xmlSwitchEncoding(ctxt, enc) });
        }
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_DOCUMENT_EMPTY, 0 as *const i8);
        return -(1 as i32);
    }
    if ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 35 as i32 as i64 {
        if (unsafe { (*ctxt).progressive }) == 0 as i32
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
        {
            xmlGROW(ctxt);
        }
    }
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == '?' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'x' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'm' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'l' as i32
        && ((unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 <= 0xa as i32
            || (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 == 0xd as i32)
    {
        xmlParseXMLDecl(ctxt);
        if (unsafe { (*ctxt).errNo }) == XML_ERR_UNSUPPORTED_ENCODING as i32
            || (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32
        {
            return -(1 as i32);
        }
        (unsafe { (*ctxt).standalone = (*(*ctxt).input).standalone });
        xmlSkipBlankChars(ctxt);
    } else {
        let fresh436 = unsafe { &mut ((*ctxt).version) };
        *fresh436 = unsafe { xmlCharStrdup(b"1.0\0" as *const u8 as *const i8) };
    }
    if !(unsafe { (*ctxt).sax }).is_null()
        && (unsafe { ((*(*ctxt).sax).startDocument).is_some() })
        && (unsafe { (*ctxt).disableSAX }) == 0
    {
        (unsafe { ((*(*ctxt).sax).startDocument).expect("non-null function pointer")((*ctxt).userData) });
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    if !(unsafe { (*ctxt).myDoc }).is_null()
        && !(unsafe { (*ctxt).input }).is_null()
        && !(unsafe { (*(*ctxt).input).buf }).is_null()
        && (unsafe { (*(*(*ctxt).input).buf).compressed }) >= 0 as i32
    {
        (unsafe { (*(*ctxt).myDoc).compression = (*(*(*ctxt).input).buf).compressed });
    }
    xmlParseMisc(ctxt);
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == '!' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'D' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'O' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'C' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(5 as i32 as isize) }) as i32 == 'T' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(6 as i32 as isize) }) as i32 == 'Y' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(7 as i32 as isize) }) as i32 == 'P' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(8 as i32 as isize) }) as i32 == 'E' as i32
    {
        (unsafe { (*ctxt).inSubset = 1 as i32 });
        xmlParseDocTypeDecl(ctxt);
        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '[' as i32 {
            (unsafe { (*ctxt).instate = XML_PARSER_DTD });
            xmlParseInternalSubset(ctxt);
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                return -(1 as i32);
            }
        }
        (unsafe { (*ctxt).inSubset = 2 as i32 });
        if !(unsafe { (*ctxt).sax }).is_null()
            && (unsafe { ((*(*ctxt).sax).externalSubset).is_some() })
            && (unsafe { (*ctxt).disableSAX }) == 0
        {
            (unsafe { ((*(*ctxt).sax).externalSubset).expect("non-null function pointer")(
                (*ctxt).userData,
                (*ctxt).intSubName,
                (*ctxt).extSubSystem,
                (*ctxt).extSubURI,
            ) });
        }
        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
            return -(1 as i32);
        }
        (unsafe { (*ctxt).inSubset = 0 as i32 });
        xmlCleanSpecialAttr(ctxt);
        (unsafe { (*ctxt).instate = XML_PARSER_PROLOG });
        xmlParseMisc(ctxt);
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 != '<' as i32 {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_DOCUMENT_EMPTY,
            b"Start tag expected, '<' not found\n\0" as *const u8 as *const i8,
        );
    } else {
        (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
        xmlParseElement(ctxt);
        (unsafe { (*ctxt).instate = XML_PARSER_EPILOG });
        xmlParseMisc(ctxt);
        if (unsafe { *(*(*ctxt).input).cur }) as i32 != 0 as i32 {
            xmlFatalErr(ctxt, XML_ERR_DOCUMENT_END, 0 as *const i8);
        }
        (unsafe { (*ctxt).instate = XML_PARSER_EOF });
    }
    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).endDocument).is_some() }) {
        (unsafe { ((*(*ctxt).sax).endDocument).expect("non-null function pointer")((*ctxt).userData) });
    }
    if !(unsafe { (*ctxt).myDoc }).is_null()
        && (unsafe { xmlStrEqual(
            (*(*ctxt).myDoc).version,
            b"SAX compatibility mode document\0" as *const u8 as *const i8 as *mut xmlChar,
        ) }) != 0
    {
        (unsafe { xmlFreeDoc((*ctxt).myDoc) });
        let fresh437 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh437 = 0 as xmlDocPtr;
    }
    if (unsafe { (*ctxt).wellFormed }) != 0 && !(unsafe { (*ctxt).myDoc }).is_null() {
        (unsafe { (*(*ctxt).myDoc).properties |= XML_DOC_WELLFORMED as i32 });
        if (unsafe { (*ctxt).valid }) != 0 {
            (unsafe { (*(*ctxt).myDoc).properties |= XML_DOC_DTDVALID as i32 });
        }
        if (unsafe { (*ctxt).nsWellFormed }) != 0 {
            (unsafe { (*(*ctxt).myDoc).properties |= XML_DOC_NSVALID as i32 });
        }
        if (unsafe { (*ctxt).options }) & XML_PARSE_OLD10 as i32 != 0 {
            (unsafe { (*(*ctxt).myDoc).properties |= XML_DOC_OLD10 as i32 });
        }
    }
    if (unsafe { (*ctxt).wellFormed }) == 0 {
        (unsafe { (*ctxt).valid = 0 as i32 });
        return -(1 as i32);
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlParseExtParsedEnt(mut ctxt: xmlParserCtxtPtr) -> i32 {
    let mut start: [xmlChar; 4] = [0; 4];
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    if ctxt.is_null() || (unsafe { (*ctxt).input }).is_null() {
        return -(1 as i32);
    }
    xmlDetectSAX2(ctxt);
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).setDocumentLocator).is_some() }) {
        (unsafe { ((*(*ctxt).sax).setDocumentLocator).expect("non-null function pointer")(
            (*ctxt).userData,
            __xmlDefaultSAXLocator(),
        ) });
    }
    if (unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64 >= 4 as i32 as i64 {
        start[0 as i32 as usize] = unsafe { *(*(*ctxt).input).cur };
        start[1 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) };
        start[2 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) };
        start[3 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) };
        enc = unsafe { xmlDetectCharEncoding(start.as_mut_ptr(), 4 as i32) };
        if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
            (unsafe { xmlSwitchEncoding(ctxt, enc) });
        }
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_DOCUMENT_EMPTY, 0 as *const i8);
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == '?' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'x' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'm' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'l' as i32
        && ((unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 <= 0xa as i32
            || (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 == 0xd as i32)
    {
        xmlParseXMLDecl(ctxt);
        if (unsafe { (*ctxt).errNo }) == XML_ERR_UNSUPPORTED_ENCODING as i32 {
            return -(1 as i32);
        }
        xmlSkipBlankChars(ctxt);
    } else {
        let fresh438 = unsafe { &mut ((*ctxt).version) };
        *fresh438 = unsafe { xmlCharStrdup(b"1.0\0" as *const u8 as *const i8) };
    }
    if !(unsafe { (*ctxt).sax }).is_null()
        && (unsafe { ((*(*ctxt).sax).startDocument).is_some() })
        && (unsafe { (*ctxt).disableSAX }) == 0
    {
        (unsafe { ((*(*ctxt).sax).startDocument).expect("non-null function pointer")((*ctxt).userData) });
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
    (unsafe { (*ctxt).validate = 0 as i32 });
    (unsafe { (*ctxt).loadsubset = 0 as i32 });
    (unsafe { (*ctxt).depth = 0 as i32 });
    xmlParseContent(ctxt);
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 != 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const i8);
    }
    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).endDocument).is_some() }) {
        (unsafe { ((*(*ctxt).sax).endDocument).expect("non-null function pointer")((*ctxt).userData) });
    }
    if (unsafe { (*ctxt).wellFormed }) == 0 {
        return -(1 as i32);
    }
    return 0 as i32;
}
extern "C" fn xmlParseLookupSequence(
    mut ctxt: xmlParserCtxtPtr,
    mut first: xmlChar,
    mut next: xmlChar,
    mut third: xmlChar,
) -> i32 {
    let mut base: i32 = 0;
    let mut len: i32 = 0;
    let mut in_0: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: *const xmlChar = 0 as *const xmlChar;
    in_0 = unsafe { (*ctxt).input };
    if in_0.is_null() {
        return -(1 as i32);
    }
    base = (unsafe { ((*in_0).cur).offset_from((*in_0).base) }) as i64 as i32;
    if base < 0 as i32 {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).checkIndex }) > base as i64 {
        base = (unsafe { (*ctxt).checkIndex }) as i32;
    }
    if (unsafe { (*in_0).buf }).is_null() {
        buf = unsafe { (*in_0).base };
        len = unsafe { (*in_0).length };
    } else {
        buf = unsafe { xmlBufContent((*(*in_0).buf).buffer as *const xmlBuf) };
        len = (unsafe { xmlBufUse((*(*in_0).buf).buffer) }) as i32;
    }
    if third != 0 {
        len -= 2 as i32;
    } else if next != 0 {
        len -= 1;
    }
    let mut current_block_20: u64;
    while base < len {
        if (unsafe { *buf.offset(base as isize) }) as i32 == first as i32 {
            if third as i32 != 0 as i32 {
                if (unsafe { *buf.offset((base + 1 as i32) as isize) }) as i32 != next as i32
                    || (unsafe { *buf.offset((base + 2 as i32) as isize) }) as i32 != third as i32
                {
                    current_block_20 = 2370887241019905314;
                } else {
                    current_block_20 = 18386322304582297246;
                }
            } else if next as i32 != 0 as i32 {
                if (unsafe { *buf.offset((base + 1 as i32) as isize) }) as i32 != next as i32 {
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
                    (unsafe { (*ctxt).checkIndex = 0 as i32 as i64 });
                    return (base as i64 - (unsafe { ((*in_0).cur).offset_from((*in_0).base) }) as i64) as i32;
                }
            }
        }
        base += 1;
    }
    (unsafe { (*ctxt).checkIndex = base as i64 });
    return -(1 as i32);
}
extern "C" fn xmlParseGetLasts(
    mut ctxt: xmlParserCtxtPtr,
    mut lastlt: *mut *const xmlChar,
    mut lastgt: *mut *const xmlChar,
) {
    let mut tmp: *const xmlChar = 0 as *const xmlChar;
    if ctxt.is_null() || lastlt.is_null() || lastgt.is_null() {
        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"Internal error: xmlParseGetLasts\n\0" as *const u8 as *const i8,
        ) });
        return;
    }
    if (unsafe { (*ctxt).progressive }) != 0 as i32 && (unsafe { (*ctxt).inputNr }) == 1 as i32 {
        tmp = unsafe { (*(*ctxt).input).end };
        tmp = unsafe { tmp.offset(-1) };
        while tmp >= (unsafe { (*(*ctxt).input).base }) && (unsafe { *tmp }) as i32 != '<' as i32 {
            tmp = unsafe { tmp.offset(-1) };
        }
        if tmp < (unsafe { (*(*ctxt).input).base }) {
            (unsafe { *lastlt = 0 as *const xmlChar });
            (unsafe { *lastgt = 0 as *const xmlChar });
        } else {
            (unsafe { *lastlt = tmp });
            tmp = unsafe { tmp.offset(1) };
            while tmp < (unsafe { (*(*ctxt).input).end }) && (unsafe { *tmp }) as i32 != '>' as i32 {
                if (unsafe { *tmp }) as i32 == '\'' as i32 {
                    tmp = unsafe { tmp.offset(1) };
                    while tmp < (unsafe { (*(*ctxt).input).end }) && (unsafe { *tmp }) as i32 != '\'' as i32 {
                        tmp = unsafe { tmp.offset(1) };
                    }
                    if tmp < (unsafe { (*(*ctxt).input).end }) {
                        tmp = unsafe { tmp.offset(1) };
                    }
                } else if (unsafe { *tmp }) as i32 == '"' as i32 {
                    tmp = unsafe { tmp.offset(1) };
                    while tmp < (unsafe { (*(*ctxt).input).end }) && (unsafe { *tmp }) as i32 != '"' as i32 {
                        tmp = unsafe { tmp.offset(1) };
                    }
                    if tmp < (unsafe { (*(*ctxt).input).end }) {
                        tmp = unsafe { tmp.offset(1) };
                    }
                } else {
                    tmp = unsafe { tmp.offset(1) };
                }
            }
            if tmp < (unsafe { (*(*ctxt).input).end }) {
                (unsafe { *lastgt = tmp });
            } else {
                tmp = unsafe { *lastlt };
                tmp = unsafe { tmp.offset(-1) };
                while tmp >= (unsafe { (*(*ctxt).input).base }) && (unsafe { *tmp }) as i32 != '>' as i32 {
                    tmp = unsafe { tmp.offset(-1) };
                }
                if tmp >= (unsafe { (*(*ctxt).input).base }) {
                    (unsafe { *lastgt = tmp });
                } else {
                    (unsafe { *lastgt = 0 as *const xmlChar });
                }
            }
        }
    } else {
        (unsafe { *lastlt = 0 as *const xmlChar });
        (unsafe { *lastgt = 0 as *const xmlChar });
    };
}
extern "C" fn xmlCheckCdataPush(mut utf: *const xmlChar, mut len: i32, mut complete: i32) -> i32 {
    let mut ix: i32 = 0;
    let mut c: u8 = 0;
    let mut codepoint: i32 = 0;
    if utf.is_null() || len <= 0 as i32 {
        return 0 as i32;
    }
    ix = 0 as i32;
    while ix < len {
        c = unsafe { *utf.offset(ix as isize) };
        if c as i32 & 0x80 as i32 == 0 as i32 {
            if c as i32 >= 0x20 as i32 {
                ix += 1;
            } else if c as i32 == 0xa as i32 || c as i32 == 0xd as i32 || c as i32 == 0x9 as i32 {
                ix += 1;
            } else {
                return -ix;
            }
        } else if c as i32 & 0xe0 as i32 == 0xc0 as i32 {
            if ix + 2 as i32 > len {
                return if complete != 0 { -ix } else { ix };
            }
            if (unsafe { *utf.offset((ix + 1 as i32) as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                return -ix;
            }
            codepoint = ((unsafe { *utf.offset(ix as isize) }) as i32 & 0x1f as i32) << 6 as i32;
            codepoint |= (unsafe { *utf.offset((ix + 1 as i32) as isize) }) as i32 & 0x3f as i32;
            if if codepoint < 0x100 as i32 {
                (0x9 as i32 <= codepoint && codepoint <= 0xa as i32
                    || codepoint == 0xd as i32
                    || 0x20 as i32 <= codepoint) as i32
            } else {
                (0x100 as i32 <= codepoint && codepoint <= 0xd7ff as i32
                    || 0xe000 as i32 <= codepoint && codepoint <= 0xfffd as i32
                    || 0x10000 as i32 <= codepoint && codepoint <= 0x10ffff as i32)
                    as i32
            } == 0
            {
                return -ix;
            }
            ix += 2 as i32;
        } else if c as i32 & 0xf0 as i32 == 0xe0 as i32 {
            if ix + 3 as i32 > len {
                return if complete != 0 { -ix } else { ix };
            }
            if (unsafe { *utf.offset((ix + 1 as i32) as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32
                || (unsafe { *utf.offset((ix + 2 as i32) as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32
            {
                return -ix;
            }
            codepoint = ((unsafe { *utf.offset(ix as isize) }) as i32 & 0xf as i32) << 12 as i32;
            codepoint |= ((unsafe { *utf.offset((ix + 1 as i32) as isize) }) as i32 & 0x3f as i32) << 6 as i32;
            codepoint |= (unsafe { *utf.offset((ix + 2 as i32) as isize) }) as i32 & 0x3f as i32;
            if if codepoint < 0x100 as i32 {
                (0x9 as i32 <= codepoint && codepoint <= 0xa as i32
                    || codepoint == 0xd as i32
                    || 0x20 as i32 <= codepoint) as i32
            } else {
                (0x100 as i32 <= codepoint && codepoint <= 0xd7ff as i32
                    || 0xe000 as i32 <= codepoint && codepoint <= 0xfffd as i32
                    || 0x10000 as i32 <= codepoint && codepoint <= 0x10ffff as i32)
                    as i32
            } == 0
            {
                return -ix;
            }
            ix += 3 as i32;
        } else if c as i32 & 0xf8 as i32 == 0xf0 as i32 {
            if ix + 4 as i32 > len {
                return if complete != 0 { -ix } else { ix };
            }
            if (unsafe { *utf.offset((ix + 1 as i32) as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32
                || (unsafe { *utf.offset((ix + 2 as i32) as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32
                || (unsafe { *utf.offset((ix + 3 as i32) as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32
            {
                return -ix;
            }
            codepoint = ((unsafe { *utf.offset(ix as isize) }) as i32 & 0x7 as i32) << 18 as i32;
            codepoint |= ((unsafe { *utf.offset((ix + 1 as i32) as isize) }) as i32 & 0x3f as i32) << 12 as i32;
            codepoint |= ((unsafe { *utf.offset((ix + 2 as i32) as isize) }) as i32 & 0x3f as i32) << 6 as i32;
            codepoint |= (unsafe { *utf.offset((ix + 3 as i32) as isize) }) as i32 & 0x3f as i32;
            if if codepoint < 0x100 as i32 {
                (0x9 as i32 <= codepoint && codepoint <= 0xa as i32
                    || codepoint == 0xd as i32
                    || 0x20 as i32 <= codepoint) as i32
            } else {
                (0x100 as i32 <= codepoint && codepoint <= 0xd7ff as i32
                    || 0xe000 as i32 <= codepoint && codepoint <= 0xfffd as i32
                    || 0x10000 as i32 <= codepoint && codepoint <= 0x10ffff as i32)
                    as i32
            } == 0
            {
                return -ix;
            }
            ix += 4 as i32;
        } else {
            return -ix;
        }
    }
    return ix;
}
extern "C" fn xmlParseTryOrFinish(mut ctxt: xmlParserCtxtPtr, mut terminate: i32) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 0 as i32;
    let mut avail: i32 = 0;
    let mut tlen: i32 = 0;
    let mut cur: xmlChar = 0;
    let mut next: xmlChar = 0;
    let mut lastlt: *const xmlChar = 0 as *const xmlChar;
    let mut lastgt: *const xmlChar = 0 as *const xmlChar;
    if (unsafe { (*ctxt).input }).is_null() {
        return 0 as i32;
    }
    if !(unsafe { (*ctxt).input }).is_null()
        && (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 > 4096 as i32 as i64
    {
        xmlSHRINK(ctxt);
        (unsafe { (*ctxt).checkIndex = 0 as i32 as i64 });
    }
    xmlParseGetLasts(ctxt, &mut lastlt, &mut lastgt);
    loop {
        if !((unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32) {
            current_block = 2814621064645850728;
            break;
        }
        if (unsafe { (*ctxt).errNo }) != XML_ERR_OK as i32 && (unsafe { (*ctxt).disableSAX }) == 1 as i32 {
            return 0 as i32;
        }
        if (unsafe { (*ctxt).input }).is_null() {
            current_block = 2814621064645850728;
            break;
        }
        if (unsafe { (*(*ctxt).input).buf }).is_null() {
            avail = ((unsafe { (*(*ctxt).input).length }) as i64
                - (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64)
                as i32;
        } else {
            if (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_START as i32
                && !(unsafe { (*(*(*ctxt).input).buf).raw }).is_null()
                && (unsafe { xmlBufIsEmpty((*(*(*ctxt).input).buf).raw) }) == 0 as i32
            {
                let mut base: size_t =
                    unsafe { xmlBufGetInputBase((*(*(*ctxt).input).buf).buffer, (*ctxt).input) };
                let mut current: size_t =
                    (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as size_t;
                (unsafe { xmlParserInputBufferPush(
                    (*(*ctxt).input).buf,
                    0 as i32,
                    b"\0" as *const u8 as *const i8,
                ) });
                (unsafe { xmlBufSetInputBaseCur((*(*(*ctxt).input).buf).buffer, (*ctxt).input, base, current) });
            }
            avail = (unsafe { xmlBufUse((*(*(*ctxt).input).buf).buffer) }).wrapping_sub(
                (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
            ) as i32;
        }
        if avail < 1 as i32 {
            current_block = 2814621064645850728;
            break;
        }
        match (unsafe { (*ctxt).instate }) as i32 {
            -1 => {
                current_block = 2814621064645850728;
                break;
            }
            0 => {
                if (unsafe { (*ctxt).charset }) == XML_CHAR_ENCODING_NONE as i32 {
                    let mut start: [xmlChar; 4] = [0; 4];
                    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
                    if avail < 4 as i32 {
                        current_block = 2814621064645850728;
                        break;
                    }
                    start[0 as i32 as usize] = unsafe { *(*(*ctxt).input).cur };
                    start[1 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) };
                    start[2 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) };
                    start[3 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) };
                    enc = unsafe { xmlDetectCharEncoding(start.as_mut_ptr(), 4 as i32) };
                    (unsafe { xmlSwitchEncoding(ctxt, enc) });
                } else {
                    if avail < 2 as i32 {
                        current_block = 2814621064645850728;
                        break;
                    }
                    cur = unsafe { *((*(*ctxt).input).cur).offset(0 as i32 as isize) };
                    next = unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) };
                    if cur as i32 == 0 as i32 {
                        if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).setDocumentLocator).is_some() })
                        {
                            (unsafe { ((*(*ctxt).sax).setDocumentLocator).expect("non-null function pointer")(
                                (*ctxt).userData,
                                __xmlDefaultSAXLocator(),
                            ) });
                        }
                        xmlFatalErr(ctxt, XML_ERR_DOCUMENT_EMPTY, 0 as *const i8);
                        xmlHaltParser(ctxt);
                        if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).endDocument).is_some() }) {
                            (unsafe { ((*(*ctxt).sax).endDocument).expect("non-null function pointer")(
                                (*ctxt).userData,
                            ) });
                        }
                        current_block = 2814621064645850728;
                        break;
                    } else if cur as i32 == '<' as i32 && next as i32 == '?' as i32 {
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
                        if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).setDocumentLocator).is_some() })
                        {
                            (unsafe { ((*(*ctxt).sax).setDocumentLocator).expect("non-null function pointer")(
                                (*ctxt).userData,
                                __xmlDefaultSAXLocator(),
                            ) });
                        }
                        if (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == 'x' as i32
                            && (unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) }) as i32
                                == 'm' as i32
                            && (unsafe { *((*(*ctxt).input).cur).offset(4 as i32 as isize) }) as i32
                                == 'l' as i32
                            && ((unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32
                                == 0x20 as i32
                                || 0x9 as i32
                                    <= (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32
                                    && (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32
                                        <= 0xa as i32
                                || (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32
                                    == 0xd as i32)
                        {
                            ret += 5 as i32;
                            xmlParseXMLDecl(ctxt);
                            if (unsafe { (*ctxt).errNo }) == XML_ERR_UNSUPPORTED_ENCODING as i32 {
                                xmlHaltParser(ctxt);
                                return 0 as i32;
                            }
                            (unsafe { (*ctxt).standalone = (*(*ctxt).input).standalone });
                            if (unsafe { (*ctxt).encoding }).is_null()
                                && !(unsafe { (*(*ctxt).input).encoding }).is_null()
                            {
                                let fresh439 = unsafe { &mut ((*ctxt).encoding) };
                                *fresh439 = unsafe { xmlStrdup((*(*ctxt).input).encoding) };
                            }
                            if !(unsafe { (*ctxt).sax }).is_null()
                                && (unsafe { ((*(*ctxt).sax).startDocument).is_some() })
                                && (unsafe { (*ctxt).disableSAX }) == 0
                            {
                                (unsafe { ((*(*ctxt).sax).startDocument).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                ) });
                            }
                            (unsafe { (*ctxt).instate = XML_PARSER_MISC });
                        } else {
                            let fresh440 = unsafe { &mut ((*ctxt).version) };
                            *fresh440 = unsafe { xmlCharStrdup(b"1.0\0" as *const u8 as *const i8) };
                            if !(unsafe { (*ctxt).sax }).is_null()
                                && (unsafe { ((*(*ctxt).sax).startDocument).is_some() })
                                && (unsafe { (*ctxt).disableSAX }) == 0
                            {
                                (unsafe { ((*(*ctxt).sax).startDocument).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                ) });
                            }
                            (unsafe { (*ctxt).instate = XML_PARSER_MISC });
                        }
                    } else {
                        if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).setDocumentLocator).is_some() })
                        {
                            (unsafe { ((*(*ctxt).sax).setDocumentLocator).expect("non-null function pointer")(
                                (*ctxt).userData,
                                __xmlDefaultSAXLocator(),
                            ) });
                        }
                        let fresh441 = unsafe { &mut ((*ctxt).version) };
                        *fresh441 = unsafe { xmlCharStrdup(b"1.0\0" as *const u8 as *const i8) };
                        if (unsafe { (*ctxt).version }).is_null() {
                            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
                        } else {
                            if !(unsafe { (*ctxt).sax }).is_null()
                                && (unsafe { ((*(*ctxt).sax).startDocument).is_some() })
                                && (unsafe { (*ctxt).disableSAX }) == 0
                            {
                                (unsafe { ((*(*ctxt).sax).startDocument).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                ) });
                            }
                            (unsafe { (*ctxt).instate = XML_PARSER_MISC });
                        }
                    }
                }
            }
            6 => {
                let mut name: *const xmlChar = 0 as *const xmlChar;
                let mut prefix: *const xmlChar = 0 as *const xmlChar;
                let mut URI: *const xmlChar = 0 as *const xmlChar;
                let mut line: i32 = unsafe { (*(*ctxt).input).line };
                let mut nsNr: i32 = unsafe { (*ctxt).nsNr };
                if avail < 2 as i32 && (unsafe { (*ctxt).inputNr }) == 1 as i32 {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = unsafe { *((*(*ctxt).input).cur).offset(0 as i32 as isize) };
                if cur as i32 != '<' as i32 {
                    xmlFatalErr(ctxt, XML_ERR_DOCUMENT_EMPTY, 0 as *const i8);
                    xmlHaltParser(ctxt);
                    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).endDocument).is_some() }) {
                        (unsafe { ((*(*ctxt).sax).endDocument).expect("non-null function pointer")(
                            (*ctxt).userData,
                        ) });
                    }
                    current_block = 2814621064645850728;
                    break;
                } else {
                    if terminate == 0 {
                        if (unsafe { (*ctxt).progressive }) != 0 {
                            if lastgt.is_null() || (unsafe { (*(*ctxt).input).cur }) >= lastgt {
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
                    if (unsafe { (*ctxt).spaceNr }) == 0 as i32 {
                        spacePush(ctxt, -(1 as i32));
                    } else if (unsafe { *(*ctxt).space }) == -(2 as i32) {
                        spacePush(ctxt, -(1 as i32));
                    } else {
                        spacePush(ctxt, unsafe { *(*ctxt).space });
                    }
                    if (unsafe { (*ctxt).sax2 }) != 0 {
                        name = xmlParseStartTag2(ctxt, &mut prefix, &mut URI, &mut tlen);
                    } else {
                        name = xmlParseStartTag(ctxt);
                    }
                    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                        current_block = 2814621064645850728;
                        break;
                    }
                    if name.is_null() {
                        spacePop(ctxt);
                        xmlHaltParser(ctxt);
                        if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).endDocument).is_some() }) {
                            (unsafe { ((*(*ctxt).sax).endDocument).expect("non-null function pointer")(
                                (*ctxt).userData,
                            ) });
                        }
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        if (unsafe { (*ctxt).validate }) != 0
                            && (unsafe { (*ctxt).wellFormed }) != 0
                            && !(unsafe { (*ctxt).myDoc }).is_null()
                            && !(unsafe { (*ctxt).node }).is_null()
                            && (unsafe { (*ctxt).node }) == (unsafe { (*(*ctxt).myDoc).children })
                        {
                            (unsafe { (*ctxt).valid &= xmlValidateRoot(&mut (*ctxt).vctxt, (*ctxt).myDoc) });
                        }
                        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '/' as i32
                            && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32
                                == '>' as i32
                        {
                            let fresh442 = unsafe { &mut ((*(*ctxt).input).cur) };
                            *fresh442 = unsafe { (*fresh442).offset(2 as i32 as isize) };
                            (unsafe { (*(*ctxt).input).col += 2 as i32 });
                            if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                                (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                            }
                            if (unsafe { (*ctxt).sax2 }) != 0 {
                                if !(unsafe { (*ctxt).sax }).is_null()
                                    && (unsafe { ((*(*ctxt).sax).endElementNs).is_some() })
                                    && (unsafe { (*ctxt).disableSAX }) == 0
                                {
                                    (unsafe { ((*(*ctxt).sax).endElementNs)
                                        .expect("non-null function pointer")(
                                        (*ctxt).userData,
                                        name,
                                        prefix,
                                        URI,
                                    ) });
                                }
                                if (unsafe { (*ctxt).nsNr }) - nsNr > 0 as i32 {
                                    nsPop(ctxt, (unsafe { (*ctxt).nsNr }) - nsNr);
                                }
                            } else if !(unsafe { (*ctxt).sax }).is_null()
                                && (unsafe { ((*(*ctxt).sax).endElement).is_some() })
                                && (unsafe { (*ctxt).disableSAX }) == 0
                            {
                                (unsafe { ((*(*ctxt).sax).endElement).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                    name,
                                ) });
                            }
                            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                                current_block = 2814621064645850728;
                                break;
                            }
                            spacePop(ctxt);
                            if (unsafe { (*ctxt).nameNr }) == 0 as i32 {
                                (unsafe { (*ctxt).instate = XML_PARSER_EPILOG });
                            } else {
                                (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
                            }
                            (unsafe { (*ctxt).progressive = 1 as i32 });
                        } else {
                            if (unsafe { *(*(*ctxt).input).cur }) as i32 == '>' as i32 {
                                (unsafe { xmlNextChar(ctxt) });
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
                            nameNsPush(ctxt, name, prefix, URI, line, (unsafe { (*ctxt).nsNr }) - nsNr);
                            (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
                            (unsafe { (*ctxt).progressive = 1 as i32 });
                        }
                    }
                }
            }
            7 => {
                let mut id: i32 = 0;
                let mut cons: u64 = 0;
                if avail < 2 as i32 && (unsafe { (*ctxt).inputNr }) == 1 as i32 {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = unsafe { *((*(*ctxt).input).cur).offset(0 as i32 as isize) };
                next = unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) };
                id = unsafe { (*(*ctxt).input).id };
                cons = (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                    (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
                );
                if cur as i32 == '<' as i32 && next as i32 == '/' as i32 {
                    (unsafe { (*ctxt).instate = XML_PARSER_END_TAG });
                } else {
                    if cur as i32 == '<' as i32 && next as i32 == '?' as i32 {
                        if terminate == 0
                            && xmlParseLookupSequence(
                                ctxt,
                                '?' as i32 as xmlChar,
                                '>' as i32 as xmlChar,
                                0 as i32 as xmlChar,
                            ) < 0 as i32
                        {
                            (unsafe { (*ctxt).progressive = XML_PARSER_PI as i32 });
                            current_block = 2814621064645850728;
                            break;
                        } else {
                            xmlParsePI(ctxt);
                            (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
                            (unsafe { (*ctxt).progressive = 1 as i32 });
                        }
                    } else if cur as i32 == '<' as i32 && next as i32 != '!' as i32 {
                        (unsafe { (*ctxt).instate = XML_PARSER_START_TAG });
                        continue;
                    } else if cur as i32 == '<' as i32
                        && next as i32 == '!' as i32
                        && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == '-' as i32
                        && (unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) }) as i32 == '-' as i32
                    {
                        let mut term: i32 = 0;
                        if avail < 4 as i32 {
                            current_block = 2814621064645850728;
                            break;
                        }
                        let fresh443 = unsafe { &mut ((*(*ctxt).input).cur) };
                        *fresh443 = unsafe { (*fresh443).offset(4 as i32 as isize) };
                        term = xmlParseLookupSequence(
                            ctxt,
                            '-' as i32 as xmlChar,
                            '-' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                        );
                        let fresh444 = unsafe { &mut ((*(*ctxt).input).cur) };
                        *fresh444 = unsafe { (*fresh444).offset(-(4 as i32 as isize)) };
                        if terminate == 0 && term < 0 as i32 {
                            (unsafe { (*ctxt).progressive = XML_PARSER_COMMENT as i32 });
                            current_block = 2814621064645850728;
                            break;
                        } else {
                            xmlParseComment(ctxt);
                            (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
                            (unsafe { (*ctxt).progressive = 1 as i32 });
                        }
                    } else if cur as i32 == '<' as i32
                        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '!' as i32
                        && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == '[' as i32
                        && (unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) }) as i32 == 'C' as i32
                        && (unsafe { *((*(*ctxt).input).cur).offset(4 as i32 as isize) }) as i32 == 'D' as i32
                        && (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 == 'A' as i32
                        && (unsafe { *((*(*ctxt).input).cur).offset(6 as i32 as isize) }) as i32 == 'T' as i32
                        && (unsafe { *((*(*ctxt).input).cur).offset(7 as i32 as isize) }) as i32 == 'A' as i32
                        && (unsafe { *((*(*ctxt).input).cur).offset(8 as i32 as isize) }) as i32 == '[' as i32
                    {
                        let fresh445 = unsafe { &mut ((*(*ctxt).input).cur) };
                        *fresh445 = unsafe { (*fresh445).offset(9 as i32 as isize) };
                        (unsafe { (*(*ctxt).input).col += 9 as i32 });
                        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                        }
                        (unsafe { (*ctxt).instate = XML_PARSER_CDATA_SECTION });
                        continue;
                    } else {
                        if cur as i32 == '<' as i32 && next as i32 == '!' as i32 && avail < 9 as i32
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
                            if (unsafe { (*ctxt).inputNr }) == 1 as i32 && avail < 300 as i32 {
                                if terminate == 0 {
                                    if (unsafe { (*ctxt).progressive }) != 0 {
                                        if lastlt.is_null() || (unsafe { (*(*ctxt).input).cur }) > lastlt {
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
                            (unsafe { (*ctxt).checkIndex = 0 as i32 as i64 });
                            xmlParseCharData(ctxt, 0 as i32);
                        }
                    }
                    if !(cons
                        == (unsafe { (*(*ctxt).input).consumed }).wrapping_add(
                            (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
                        )
                        && id == (unsafe { (*(*ctxt).input).id }))
                    {
                        continue;
                    }
                    xmlFatalErr(
                        ctxt,
                        XML_ERR_INTERNAL_ERROR,
                        b"detected an error in element content\n\0" as *const u8 as *const i8,
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
                    if (unsafe { (*ctxt).progressive }) != 0 {
                        if lastgt.is_null() || (unsafe { (*(*ctxt).input).cur }) >= lastgt {
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
                if (unsafe { (*ctxt).sax2 }) != 0 {
                    xmlParseEndTag2(
                        ctxt,
                        unsafe { &mut *((*ctxt).pushTab).offset(((*ctxt).nameNr - 1 as i32) as isize) },
                    );
                    nameNsPop(ctxt);
                } else {
                    xmlParseEndTag1(ctxt, 0 as i32);
                }
                if !((unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32) {
                    if (unsafe { (*ctxt).nameNr }) == 0 as i32 {
                        (unsafe { (*ctxt).instate = XML_PARSER_EPILOG });
                    } else {
                        (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
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
                    tmp = xmlCheckCdataPush(unsafe { (*(*ctxt).input).cur }, 300 as i32, 0 as i32);
                    if tmp < 0 as i32 {
                        tmp = -tmp;
                        let fresh446 = unsafe { &mut ((*(*ctxt).input).cur) };
                        *fresh446 = unsafe { (*fresh446).offset(tmp as isize) };
                        current_block = 2885357499145876431;
                        break;
                    } else {
                        if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { (*ctxt).disableSAX }) == 0 {
                            if unsafe { ((*(*ctxt).sax).cdataBlock).is_some() } {
                                (unsafe { ((*(*ctxt).sax).cdataBlock).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                    (*(*ctxt).input).cur,
                                    tmp,
                                ) });
                            } else if unsafe { ((*(*ctxt).sax).characters).is_some() } {
                                (unsafe { ((*(*ctxt).sax).characters).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                    (*(*ctxt).input).cur,
                                    tmp,
                                ) });
                            }
                        }
                        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                            current_block = 2814621064645850728;
                            break;
                        }
                        let mut skipl: i32 = 0;
                        skipl = 0 as i32;
                        while skipl < tmp {
                            if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
                                let fresh447 = unsafe { &mut ((*(*ctxt).input).line) };
                                *fresh447 += 1;
                                (unsafe { (*(*ctxt).input).col = 1 as i32 });
                            } else {
                                let fresh448 = unsafe { &mut ((*(*ctxt).input).col) };
                                *fresh448 += 1;
                            }
                            let fresh449 = unsafe { &mut ((*(*ctxt).input).cur) };
                            *fresh449 = unsafe { (*fresh449).offset(1) };
                            skipl += 1;
                        }
                        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                        }
                        (unsafe { (*ctxt).checkIndex = 0 as i32 as i64 });
                        current_block = 2814621064645850728;
                        break;
                    }
                } else {
                    let mut tmp_0: i32 = 0;
                    tmp_0 = xmlCheckCdataPush(unsafe { (*(*ctxt).input).cur }, base_0, 1 as i32);
                    if tmp_0 < 0 as i32 || tmp_0 != base_0 {
                        tmp_0 = -tmp_0;
                        let fresh450 = unsafe { &mut ((*(*ctxt).input).cur) };
                        *fresh450 = unsafe { (*fresh450).offset(tmp_0 as isize) };
                        current_block = 2885357499145876431;
                        break;
                    } else {
                        if !(unsafe { (*ctxt).sax }).is_null()
                            && base_0 == 0 as i32
                            && (unsafe { ((*(*ctxt).sax).cdataBlock).is_some() })
                            && (unsafe { (*ctxt).disableSAX }) == 0
                        {
                            if (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                                >= 9 as i32 as i64
                                && (unsafe { strncmp(
                                    &*((*(*ctxt).input).cur).offset(-(9 as i32) as isize)
                                        as *const xmlChar
                                        as *const i8,
                                    b"<![CDATA[\0" as *const u8 as *const i8,
                                    9 as i32 as u64,
                                ) }) == 0
                            {
                                (unsafe { ((*(*ctxt).sax).cdataBlock).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                    b"\0" as *const u8 as *const i8 as *mut xmlChar,
                                    0 as i32,
                                ) });
                            }
                        } else if !(unsafe { (*ctxt).sax }).is_null()
                            && base_0 > 0 as i32
                            && (unsafe { (*ctxt).disableSAX }) == 0
                        {
                            if unsafe { ((*(*ctxt).sax).cdataBlock).is_some() } {
                                (unsafe { ((*(*ctxt).sax).cdataBlock).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                    (*(*ctxt).input).cur,
                                    base_0,
                                ) });
                            } else if unsafe { ((*(*ctxt).sax).characters).is_some() } {
                                (unsafe { ((*(*ctxt).sax).characters).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                    (*(*ctxt).input).cur,
                                    base_0,
                                ) });
                            }
                        }
                        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                            current_block = 2814621064645850728;
                            break;
                        }
                        let mut skipl_0: i32 = 0;
                        skipl_0 = 0 as i32;
                        while skipl_0 < base_0 + 3 as i32 {
                            if (unsafe { *(*(*ctxt).input).cur }) as i32 == '\n' as i32 {
                                let fresh451 = unsafe { &mut ((*(*ctxt).input).line) };
                                *fresh451 += 1;
                                (unsafe { (*(*ctxt).input).col = 1 as i32 });
                            } else {
                                let fresh452 = unsafe { &mut ((*(*ctxt).input).col) };
                                *fresh452 += 1;
                            }
                            let fresh453 = unsafe { &mut ((*(*ctxt).input).cur) };
                            *fresh453 = unsafe { (*fresh453).offset(1) };
                            skipl_0 += 1;
                        }
                        if (unsafe { *(*(*ctxt).input).cur }) as i32 == 0 as i32 {
                            (unsafe { xmlParserInputGrow((*ctxt).input, 250 as i32) });
                        }
                        (unsafe { (*ctxt).checkIndex = 0 as i32 as i64 });
                        (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
                    }
                }
            }
            1 => {
                xmlSkipBlankChars(ctxt);
                if (unsafe { (*(*ctxt).input).buf }).is_null() {
                    avail = ((unsafe { (*(*ctxt).input).length }) as i64
                        - (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64)
                        as i32;
                } else {
                    avail =
                        (unsafe { xmlBufUse((*(*(*ctxt).input).buf).buffer) })
                            .wrapping_sub((unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) })
                                as i64 as u64) as i32;
                }
                if avail < 2 as i32 {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = unsafe { *((*(*ctxt).input).cur).offset(0 as i32 as isize) };
                next = unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) };
                if cur as i32 == '<' as i32 && next as i32 == '?' as i32 {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '?' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                            0 as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (unsafe { (*ctxt).progressive = XML_PARSER_PI as i32 });
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParsePI(ctxt);
                        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (unsafe { (*ctxt).instate = XML_PARSER_MISC });
                        (unsafe { (*ctxt).progressive = 1 as i32 });
                        (unsafe { (*ctxt).checkIndex = 0 as i32 as i64 });
                    }
                } else if cur as i32 == '<' as i32
                    && next as i32 == '!' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == '-' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) }) as i32 == '-' as i32
                {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '-' as i32 as xmlChar,
                            '-' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (unsafe { (*ctxt).progressive = XML_PARSER_COMMENT as i32 });
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParseComment(ctxt);
                        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (unsafe { (*ctxt).instate = XML_PARSER_MISC });
                        (unsafe { (*ctxt).progressive = 1 as i32 });
                        (unsafe { (*ctxt).checkIndex = 0 as i32 as i64 });
                    }
                } else if cur as i32 == '<' as i32
                    && next as i32 == '!' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == 'D' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) }) as i32 == 'O' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(4 as i32 as isize) }) as i32 == 'C' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 == 'T' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(6 as i32 as isize) }) as i32 == 'Y' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(7 as i32 as isize) }) as i32 == 'P' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(8 as i32 as isize) }) as i32 == 'E' as i32
                {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '>' as i32 as xmlChar,
                            0 as i32 as xmlChar,
                            0 as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (unsafe { (*ctxt).progressive = XML_PARSER_DTD as i32 });
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        (unsafe { (*ctxt).inSubset = 1 as i32 });
                        (unsafe { (*ctxt).progressive = 0 as i32 });
                        (unsafe { (*ctxt).checkIndex = 0 as i32 as i64 });
                        xmlParseDocTypeDecl(ctxt);
                        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                            current_block = 2814621064645850728;
                            break;
                        }
                        if (unsafe { *(*(*ctxt).input).cur }) as i32 == '[' as i32 {
                            (unsafe { (*ctxt).instate = XML_PARSER_DTD });
                        } else {
                            (unsafe { (*ctxt).inSubset = 2 as i32 });
                            if !(unsafe { (*ctxt).sax }).is_null()
                                && (unsafe { (*ctxt).disableSAX }) == 0
                                && (unsafe { ((*(*ctxt).sax).externalSubset).is_some() })
                            {
                                (unsafe { ((*(*ctxt).sax).externalSubset).expect("non-null function pointer")(
                                    (*ctxt).userData,
                                    (*ctxt).intSubName,
                                    (*ctxt).extSubSystem,
                                    (*ctxt).extSubURI,
                                ) });
                            }
                            (unsafe { (*ctxt).inSubset = 0 as i32 });
                            xmlCleanSpecialAttr(ctxt);
                            (unsafe { (*ctxt).instate = XML_PARSER_PROLOG });
                        }
                    }
                } else {
                    if cur as i32 == '<' as i32 && next as i32 == '!' as i32 && avail < 9 as i32 {
                        current_block = 2814621064645850728;
                        break;
                    }
                    (unsafe { (*ctxt).instate = XML_PARSER_START_TAG });
                    (unsafe { (*ctxt).progressive = XML_PARSER_START_TAG as i32 });
                    xmlParseGetLasts(ctxt, &mut lastlt, &mut lastgt);
                }
            }
            4 => {
                xmlSkipBlankChars(ctxt);
                if (unsafe { (*(*ctxt).input).buf }).is_null() {
                    avail = ((unsafe { (*(*ctxt).input).length }) as i64
                        - (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64)
                        as i32;
                } else {
                    avail =
                        (unsafe { xmlBufUse((*(*(*ctxt).input).buf).buffer) })
                            .wrapping_sub((unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) })
                                as i64 as u64) as i32;
                }
                if avail < 2 as i32 {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = unsafe { *((*(*ctxt).input).cur).offset(0 as i32 as isize) };
                next = unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) };
                if cur as i32 == '<' as i32 && next as i32 == '?' as i32 {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '?' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                            0 as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (unsafe { (*ctxt).progressive = XML_PARSER_PI as i32 });
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParsePI(ctxt);
                        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (unsafe { (*ctxt).instate = XML_PARSER_PROLOG });
                        (unsafe { (*ctxt).progressive = 1 as i32 });
                    }
                } else if cur as i32 == '<' as i32
                    && next as i32 == '!' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == '-' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) }) as i32 == '-' as i32
                {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '-' as i32 as xmlChar,
                            '-' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (unsafe { (*ctxt).progressive = XML_PARSER_COMMENT as i32 });
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParseComment(ctxt);
                        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (unsafe { (*ctxt).instate = XML_PARSER_PROLOG });
                        (unsafe { (*ctxt).progressive = 1 as i32 });
                    }
                } else {
                    if cur as i32 == '<' as i32 && next as i32 == '!' as i32 && avail < 4 as i32 {
                        current_block = 2814621064645850728;
                        break;
                    }
                    (unsafe { (*ctxt).instate = XML_PARSER_START_TAG });
                    if (unsafe { (*ctxt).progressive }) == 0 as i32 {
                        (unsafe { (*ctxt).progressive = XML_PARSER_START_TAG as i32 });
                    }
                    xmlParseGetLasts(ctxt, &mut lastlt, &mut lastgt);
                }
            }
            14 => {
                xmlSkipBlankChars(ctxt);
                if (unsafe { (*(*ctxt).input).buf }).is_null() {
                    avail = ((unsafe { (*(*ctxt).input).length }) as i64
                        - (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64)
                        as i32;
                } else {
                    avail =
                        (unsafe { xmlBufUse((*(*(*ctxt).input).buf).buffer) })
                            .wrapping_sub((unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) })
                                as i64 as u64) as i32;
                }
                if avail < 2 as i32 {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = unsafe { *((*(*ctxt).input).cur).offset(0 as i32 as isize) };
                next = unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) };
                if cur as i32 == '<' as i32 && next as i32 == '?' as i32 {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '?' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                            0 as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (unsafe { (*ctxt).progressive = XML_PARSER_PI as i32 });
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParsePI(ctxt);
                        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (unsafe { (*ctxt).instate = XML_PARSER_EPILOG });
                        (unsafe { (*ctxt).progressive = 1 as i32 });
                    }
                } else if cur as i32 == '<' as i32
                    && next as i32 == '!' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) }) as i32 == '-' as i32
                    && (unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) }) as i32 == '-' as i32
                {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '-' as i32 as xmlChar,
                            '-' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                        ) < 0 as i32
                    {
                        (unsafe { (*ctxt).progressive = XML_PARSER_COMMENT as i32 });
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParseComment(ctxt);
                        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (unsafe { (*ctxt).instate = XML_PARSER_EPILOG });
                        (unsafe { (*ctxt).progressive = 1 as i32 });
                    }
                } else {
                    if cur as i32 == '<' as i32 && next as i32 == '!' as i32 && avail < 4 as i32 {
                        current_block = 2814621064645850728;
                        break;
                    }
                    xmlFatalErr(ctxt, XML_ERR_DOCUMENT_END, 0 as *const i8);
                    xmlHaltParser(ctxt);
                    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).endDocument).is_some() }) {
                        (unsafe { ((*(*ctxt).sax).endDocument).expect("non-null function pointer")(
                            (*ctxt).userData,
                        ) });
                    }
                    current_block = 2814621064645850728;
                    break;
                }
            }
            3 => {
                let mut base_1: i32 = 0;
                let mut i: i32 = 0;
                let mut buf: *mut xmlChar = 0 as *mut xmlChar;
                let mut quote: xmlChar = 0 as i32 as xmlChar;
                let mut use_0: size_t = 0;
                base_1 = (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as i32;
                if base_1 < 0 as i32 {
                    return 0 as i32;
                }
                if (unsafe { (*ctxt).checkIndex }) > base_1 as i64 {
                    base_1 = (unsafe { (*ctxt).checkIndex }) as i32;
                }
                buf = unsafe { xmlBufContent((*(*(*ctxt).input).buf).buffer as *const xmlBuf) };
                use_0 = unsafe { xmlBufUse((*(*(*ctxt).input).buf).buffer) };
                's_1946: loop {
                    if !((base_1 as u32 as u64) < use_0) {
                        current_block = 10059826840140668507;
                        break;
                    }
                    if quote as i32 != 0 as i32 {
                        if (unsafe { *buf.offset(base_1 as isize) }) as i32 == quote as i32 {
                            quote = 0 as i32 as xmlChar;
                        }
                    } else {
                        if quote as i32 == 0 as i32
                            && (unsafe { *buf.offset(base_1 as isize) }) as i32 == '<' as i32
                        {
                            let mut found: i32 = 0 as i32;
                            if ((base_1 as u32).wrapping_add(4 as i32 as u32) as u64) < use_0
                                && (unsafe { *buf.offset((base_1 + 1 as i32) as isize) }) as i32 == '!' as i32
                                && (unsafe { *buf.offset((base_1 + 2 as i32) as isize) }) as i32 == '-' as i32
                                && (unsafe { *buf.offset((base_1 + 3 as i32) as isize) }) as i32 == '-' as i32
                            {
                                while ((base_1 as u32).wrapping_add(3 as i32 as u32) as u64) < use_0
                                {
                                    if (unsafe { *buf.offset(base_1 as isize) }) as i32 == '-' as i32
                                        && (unsafe { *buf.offset((base_1 + 1 as i32) as isize) }) as i32
                                            == '-' as i32
                                        && (unsafe { *buf.offset((base_1 + 2 as i32) as isize) }) as i32
                                            == '>' as i32
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
                                if (unsafe { *buf.offset(base_1 as isize) }) as i32 == '"' as i32 {
                                    quote = '"' as i32 as xmlChar;
                                } else if (unsafe { *buf.offset(base_1 as isize) }) as i32 == '\'' as i32 {
                                    quote = '\'' as i32 as xmlChar;
                                } else if (unsafe { *buf.offset(base_1 as isize) }) as i32 == ']' as i32 {
                                    if (base_1 as u32).wrapping_add(1 as i32 as u32) as u64 >= use_0
                                    {
                                        current_block = 10059826840140668507;
                                        break;
                                    }
                                    if (unsafe { *buf.offset((base_1 + 1 as i32) as isize) }) as i32
                                        == ']' as i32
                                    {
                                        base_1 += 1;
                                    } else {
                                        i = 1 as i32;
                                        loop {
                                            if !(((base_1 as u32).wrapping_add(i as u32) as u64)
                                                < use_0)
                                            {
                                                current_block = 10059826840140668507;
                                                break 's_1946;
                                            }
                                            if (unsafe { *buf.offset((base_1 + i) as isize) }) as i32
                                                == '>' as i32
                                            {
                                                current_block = 16939792823138094123;
                                                break 's_1946;
                                            }
                                            if !((unsafe { *buf.offset((base_1 + i) as isize) }) as i32
                                                == 0x20 as i32
                                                || 0x9 as i32
                                                    <= (unsafe { *buf.offset((base_1 + i) as isize) }) as i32
                                                    && (unsafe { *buf.offset((base_1 + i) as isize) }) as i32
                                                        <= 0xa as i32
                                                || (unsafe { *buf.offset((base_1 + i) as isize) }) as i32
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
                            (unsafe { (*ctxt).checkIndex = base_1 as i64 });
                        } else {
                            (unsafe { (*ctxt).checkIndex = 0 as i32 as i64 });
                        }
                        current_block = 2814621064645850728;
                        break;
                    }
                    _ => {
                        (unsafe { (*ctxt).checkIndex = 0 as i32 as i64 });
                        xmlParseInternalSubset(ctxt);
                        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (unsafe { (*ctxt).inSubset = 2 as i32 });
                        if !(unsafe { (*ctxt).sax }).is_null()
                            && (unsafe { (*ctxt).disableSAX }) == 0
                            && (unsafe { ((*(*ctxt).sax).externalSubset).is_some() })
                        {
                            (unsafe { ((*(*ctxt).sax).externalSubset).expect("non-null function pointer")(
                                (*ctxt).userData,
                                (*ctxt).intSubName,
                                (*ctxt).extSubSystem,
                                (*ctxt).extSubURI,
                            ) });
                        }
                        (unsafe { (*ctxt).inSubset = 0 as i32 });
                        xmlCleanSpecialAttr(ctxt);
                        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (unsafe { (*ctxt).instate = XML_PARSER_PROLOG });
                        (unsafe { (*ctxt).checkIndex = 0 as i32 as i64 });
                    }
                }
            }
            5 => {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == COMMENT\n\0" as *const u8 as *const i8,
                ) });
                (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
            }
            15 => {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == IGNORE\0" as *const u8 as *const i8,
                ) });
                (unsafe { (*ctxt).instate = XML_PARSER_DTD });
            }
            2 => {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == PI\n\0" as *const u8 as *const i8,
                ) });
                (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
            }
            10 => {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == ENTITY_DECL\n\0" as *const u8 as *const i8,
                ) });
                (unsafe { (*ctxt).instate = XML_PARSER_DTD });
            }
            11 => {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == ENTITY_VALUE\n\0" as *const u8 as *const i8,
                ) });
                (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
            }
            12 => {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == ATTRIBUTE_VALUE\n\0" as *const u8 as *const i8,
                ) });
                (unsafe { (*ctxt).instate = XML_PARSER_START_TAG });
            }
            13 => {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == SYSTEM_LITERAL\n\0" as *const u8 as *const i8,
                ) });
                (unsafe { (*ctxt).instate = XML_PARSER_START_TAG });
            }
            16 => {
                (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == PUBLIC_LITERAL\n\0" as *const u8 as *const i8,
                ) });
                (unsafe { (*ctxt).instate = XML_PARSER_START_TAG });
            }
            _ => {}
        }
    }
    match current_block {
        2814621064645850728 => return ret,
        _ => {
            let mut buffer: [i8; 150] = [0; 150];
            (unsafe { snprintf(
                buffer.as_mut_ptr(),
                149 as i32 as u64,
                b"Bytes: 0x%02X 0x%02X 0x%02X 0x%02X\n\0" as *const u8 as *const i8,
                *((*(*ctxt).input).cur).offset(0 as i32 as isize) as i32,
                *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32,
                *((*(*ctxt).input).cur).offset(2 as i32 as isize) as i32,
                *((*(*ctxt).input).cur).offset(3 as i32 as isize) as i32,
            ) });
            (unsafe { __xmlErrEncoding(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"Input is not proper UTF-8, indicate encoding !\n%s\0" as *const u8 as *const i8,
                buffer.as_mut_ptr() as *mut xmlChar,
                0 as *const xmlChar,
            ) });
            return 0 as i32;
        }
    };
}
extern "C" fn xmlParseCheckTransition(
    mut ctxt: xmlParserCtxtPtr,
    mut chunk: *const i8,
    mut size: i32,
) -> i32 {
    if ctxt.is_null() || chunk.is_null() || size < 0 as i32 {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_START_TAG as i32 {
        if !(unsafe { memchr(chunk as *const libc::c_void, '>' as i32, size as u64) }).is_null() {
            return 1 as i32;
        }
        return 0 as i32;
    }
    if (unsafe { (*ctxt).progressive }) == XML_PARSER_COMMENT as i32 {
        if !(unsafe { memchr(chunk as *const libc::c_void, '>' as i32, size as u64) }).is_null() {
            return 1 as i32;
        }
        return 0 as i32;
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_CDATA_SECTION as i32 {
        if !(unsafe { memchr(chunk as *const libc::c_void, '>' as i32, size as u64) }).is_null() {
            return 1 as i32;
        }
        return 0 as i32;
    }
    if (unsafe { (*ctxt).progressive }) == XML_PARSER_PI as i32 {
        if !(unsafe { memchr(chunk as *const libc::c_void, '>' as i32, size as u64) }).is_null() {
            return 1 as i32;
        }
        return 0 as i32;
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_END_TAG as i32 {
        if !(unsafe { memchr(chunk as *const libc::c_void, '>' as i32, size as u64) }).is_null() {
            return 1 as i32;
        }
        return 0 as i32;
    }
    if (unsafe { (*ctxt).progressive }) == XML_PARSER_DTD as i32
        || (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_DTD as i32
    {
        if !(unsafe { memchr(chunk as *const libc::c_void, '>' as i32, size as u64) }).is_null() {
            return 1 as i32;
        }
        return 0 as i32;
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlParseChunk(
    mut ctxt: xmlParserCtxtPtr,
    mut chunk: *const i8,
    mut size: i32,
    mut terminate: i32,
) -> i32 {
    let mut end_in_lf: i32 = 0 as i32;
    let mut remain: i32 = 0 as i32;
    let mut old_avail: size_t = 0 as i32 as size_t;
    let mut avail: size_t = 0 as i32 as size_t;
    if ctxt.is_null() {
        return XML_ERR_INTERNAL_ERROR as i32;
    }
    if (unsafe { (*ctxt).errNo }) != XML_ERR_OK as i32 && (unsafe { (*ctxt).disableSAX }) == 1 as i32 {
        return unsafe { (*ctxt).errNo };
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_START as i32 {
        xmlDetectSAX2(ctxt);
    }
    if size > 0 as i32
        && !chunk.is_null()
        && terminate == 0
        && (unsafe { *chunk.offset((size - 1 as i32) as isize) }) as i32 == '\r' as i32
    {
        end_in_lf = 1 as i32;
        size -= 1;
    }
    loop {
        if size > 0 as i32
            && !chunk.is_null()
            && !(unsafe { (*ctxt).input }).is_null()
            && !(unsafe { (*(*ctxt).input).buf }).is_null()
            && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32
        {
            let mut base: size_t =
                unsafe { xmlBufGetInputBase((*(*(*ctxt).input).buf).buffer, (*ctxt).input) };
            let mut cur: size_t =
                (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as size_t;
            let mut res: i32 = 0;
            old_avail = unsafe { xmlBufUse((*(*(*ctxt).input).buf).buffer) };
            if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_START as i32
                && !(unsafe { (*ctxt).input }).is_null()
                && !(unsafe { (*(*ctxt).input).buf }).is_null()
                && !(unsafe { (*(*(*ctxt).input).buf).encoder }).is_null()
            {
                let mut len: u32 = 45 as i32 as u32;
                if !(unsafe { xmlStrcasestr(
                    (*(*(*(*ctxt).input).buf).encoder).name as *mut xmlChar,
                    b"UTF-16\0" as *const u8 as *const i8 as *mut xmlChar,
                ) })
                .is_null()
                    || !(unsafe { xmlStrcasestr(
                        (*(*(*(*ctxt).input).buf).encoder).name as *mut xmlChar,
                        b"UTF16\0" as *const u8 as *const i8 as *mut xmlChar,
                    ) })
                    .is_null()
                {
                    len = 90 as i32 as u32;
                } else if !(unsafe { xmlStrcasestr(
                    (*(*(*(*ctxt).input).buf).encoder).name as *mut xmlChar,
                    b"UCS-4\0" as *const u8 as *const i8 as *mut xmlChar,
                ) })
                .is_null()
                    || !(unsafe { xmlStrcasestr(
                        (*(*(*(*ctxt).input).buf).encoder).name as *mut xmlChar,
                        b"UCS4\0" as *const u8 as *const i8 as *mut xmlChar,
                    ) })
                    .is_null()
                {
                    len = 180 as i32 as u32;
                }
                if (unsafe { (*(*(*ctxt).input).buf).rawconsumed }) < len as u64 {
                    len = (len as u64).wrapping_sub(unsafe { (*(*(*ctxt).input).buf).rawconsumed }) as u32
                        as u32;
                }
                if size as u32 > len {
                    remain = (size as u32).wrapping_sub(len) as i32;
                    size = len as i32;
                } else {
                    remain = 0 as i32;
                }
            }
            res = unsafe { xmlParserInputBufferPush((*(*ctxt).input).buf, size, chunk) };
            (unsafe { xmlBufSetInputBaseCur((*(*(*ctxt).input).buf).buffer, (*ctxt).input, base, cur) });
            if res < 0 as i32 {
                (unsafe { (*ctxt).errNo = XML_PARSER_EOF as i32 });
                xmlHaltParser(ctxt);
                return XML_PARSER_EOF as i32;
            }
        } else if (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32 {
            if !(unsafe { (*ctxt).input }).is_null() && !(unsafe { (*(*ctxt).input).buf }).is_null() {
                let mut in_0: xmlParserInputBufferPtr = unsafe { (*(*ctxt).input).buf };
                if !(unsafe { (*in_0).encoder }).is_null()
                    && !(unsafe { (*in_0).buffer }).is_null()
                    && !(unsafe { (*in_0).raw }).is_null()
                {
                    let mut nbchars: i32 = 0;
                    let mut base_0: size_t = unsafe { xmlBufGetInputBase((*in_0).buffer, (*ctxt).input) };
                    let mut current: size_t =
                        (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as size_t;
                    nbchars = unsafe { xmlCharEncInput(in_0, terminate) };
                    (unsafe { xmlBufSetInputBaseCur((*in_0).buffer, (*ctxt).input, base_0, current) });
                    if nbchars < 0 as i32 {
                        (unsafe { (*__xmlGenericError()).expect("non-null function pointer")(
                            *__xmlGenericErrorContext(),
                            b"xmlParseChunk: encoder error\n\0" as *const u8 as *const i8,
                        ) });
                        xmlHaltParser(ctxt);
                        return XML_ERR_INVALID_ENCODING as i32;
                    }
                }
            }
        }
        if remain != 0 as i32 {
            xmlParseTryOrFinish(ctxt, 0 as i32);
        } else {
            if !(unsafe { (*ctxt).input }).is_null() && !(unsafe { (*(*ctxt).input).buf }).is_null() {
                avail = unsafe { xmlBufUse((*(*(*ctxt).input).buf).buffer) };
            }
            if terminate != 0
                || avail > 10000000 as i32 as u64
                || old_avail == 0 as i32 as u64
                || avail == 0 as i32 as u64
                || xmlParseCheckTransition(
                    ctxt,
                    (unsafe { &*((*(*ctxt).input).base).offset(old_avail as isize) }) as *const xmlChar
                        as *const i8,
                    avail.wrapping_sub(old_avail) as i32,
                ) != 0
            {
                xmlParseTryOrFinish(ctxt, terminate);
            }
        }
        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EOF as i32 {
            return unsafe { (*ctxt).errNo };
        }
        if !(unsafe { (*ctxt).input }).is_null()
            && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64
                > 10000000 as i32 as i64
                || (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64
                    > 10000000 as i32 as i64)
            && (unsafe { (*ctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
        {
            xmlFatalErr(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"Huge input lookup\0" as *const u8 as *const i8,
            );
            xmlHaltParser(ctxt);
        }
        if (unsafe { (*ctxt).errNo }) != XML_ERR_OK as i32 && (unsafe { (*ctxt).disableSAX }) == 1 as i32 {
            return unsafe { (*ctxt).errNo };
        }
        if !(remain != 0 as i32) {
            break;
        }
        chunk = unsafe { chunk.offset(size as isize) };
        size = remain;
        remain = 0 as i32;
    }
    if end_in_lf == 1 as i32 && !(unsafe { (*ctxt).input }).is_null() && !(unsafe { (*(*ctxt).input).buf }).is_null() {
        let mut base_1: size_t = unsafe { xmlBufGetInputBase((*(*(*ctxt).input).buf).buffer, (*ctxt).input) };
        let mut current_0: size_t =
            (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as size_t;
        (unsafe { xmlParserInputBufferPush(
            (*(*ctxt).input).buf,
            1 as i32,
            b"\r\0" as *const u8 as *const i8,
        ) });
        (unsafe { xmlBufSetInputBaseCur(
            (*(*(*ctxt).input).buf).buffer,
            (*ctxt).input,
            base_1,
            current_0,
        ) });
    }
    if terminate != 0 {
        let mut cur_avail: i32 = 0 as i32;
        if !(unsafe { (*ctxt).input }).is_null() {
            if (unsafe { (*(*ctxt).input).buf }).is_null() {
                cur_avail = ((unsafe { (*(*ctxt).input).length }) as i64
                    - (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64)
                    as i32;
            } else {
                cur_avail = (unsafe { xmlBufUse((*(*(*ctxt).input).buf).buffer) }).wrapping_sub(
                    (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64,
                ) as i32;
            }
        }
        if (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32
            && (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EPILOG as i32
        {
            xmlFatalErr(ctxt, XML_ERR_DOCUMENT_END, 0 as *const i8);
        }
        if (unsafe { (*ctxt).instate }) as i32 == XML_PARSER_EPILOG as i32 && cur_avail > 0 as i32 {
            xmlFatalErr(ctxt, XML_ERR_DOCUMENT_END, 0 as *const i8);
        }
        if (unsafe { (*ctxt).instate }) as i32 != XML_PARSER_EOF as i32 {
            if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).endDocument).is_some() }) {
                (unsafe { ((*(*ctxt).sax).endDocument).expect("non-null function pointer")((*ctxt).userData) });
            }
        }
        (unsafe { (*ctxt).instate = XML_PARSER_EOF });
    }
    if (unsafe { (*ctxt).wellFormed }) == 0 as i32 {
        return (unsafe { (*ctxt).errNo }) as xmlParserErrors as i32;
    } else {
        return 0 as i32;
    };
}
#[no_mangle]
pub extern "C" fn xmlCreatePushParserCtxt(
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut chunk: *const i8,
    mut size: i32,
    mut filename: *const i8,
) -> xmlParserCtxtPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    if !chunk.is_null() && size >= 4 as i32 {
        enc = unsafe { xmlDetectCharEncoding(chunk as *const xmlChar, size) };
    }
    buf = unsafe { xmlAllocParserInputBuffer(enc) };
    if buf.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    ctxt = unsafe { xmlNewParserCtxt() };
    if ctxt.is_null() {
        (unsafe { xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"creating parser: out of memory\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { xmlFreeParserInputBuffer(buf) });
        return 0 as xmlParserCtxtPtr;
    }
    (unsafe { (*ctxt).dictNames = 1 as i32 });
    if !sax.is_null() {
        if (unsafe { (*ctxt).sax }) != (unsafe { __xmlDefaultSAXHandler() }) as xmlSAXHandlerPtr {
            (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void) });
        }
        let fresh454 = unsafe { &mut ((*ctxt).sax) };
        *fresh454 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlSAXHandler>() as u64,
        ) }) as xmlSAXHandlerPtr;
        if (unsafe { (*ctxt).sax }).is_null() {
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            (unsafe { xmlFreeParserInputBuffer(buf) });
            (unsafe { xmlFreeParserCtxt(ctxt) });
            return 0 as xmlParserCtxtPtr;
        }
        (unsafe { memset(
            (*ctxt).sax as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlSAXHandler>() as u64,
        ) });
        if (unsafe { (*sax).initialized }) == 0xdeedbeaf as u32 {
            (unsafe { memcpy(
                (*ctxt).sax as *mut libc::c_void,
                sax as *const libc::c_void,
                ::std::mem::size_of::<xmlSAXHandler>() as u64,
            ) });
        } else {
            (unsafe { memcpy(
                (*ctxt).sax as *mut libc::c_void,
                sax as *const libc::c_void,
                ::std::mem::size_of::<xmlSAXHandlerV1>() as u64,
            ) });
        }
        if !user_data.is_null() {
            let fresh455 = unsafe { &mut ((*ctxt).userData) };
            *fresh455 = user_data;
        }
    }
    if filename.is_null() {
        let fresh456 = unsafe { &mut ((*ctxt).directory) };
        *fresh456 = 0 as *mut i8;
    } else {
        let fresh457 = unsafe { &mut ((*ctxt).directory) };
        *fresh457 = unsafe { xmlParserGetDirectory(filename) };
    }
    inputStream = unsafe { xmlNewInputStream(ctxt) };
    if inputStream.is_null() {
        (unsafe { xmlFreeParserCtxt(ctxt) });
        (unsafe { xmlFreeParserInputBuffer(buf) });
        return 0 as xmlParserCtxtPtr;
    }
    if filename.is_null() {
        let fresh458 = unsafe { &mut ((*inputStream).filename) };
        *fresh458 = 0 as *const i8;
    } else {
        let fresh459 = unsafe { &mut ((*inputStream).filename) };
        *fresh459 = (unsafe { xmlCanonicPath(filename as *const xmlChar) }) as *mut i8;
        if (unsafe { (*inputStream).filename }).is_null() {
            (unsafe { xmlFreeParserCtxt(ctxt) });
            (unsafe { xmlFreeParserInputBuffer(buf) });
            return 0 as xmlParserCtxtPtr;
        }
    }
    let fresh460 = unsafe { &mut ((*inputStream).buf) };
    *fresh460 = buf;
    (unsafe { xmlBufResetInput((*(*inputStream).buf).buffer, inputStream) });
    inputPush(ctxt, inputStream);
    if size == 0 as i32 || chunk.is_null() {
        (unsafe { (*ctxt).charset = XML_CHAR_ENCODING_NONE as i32 });
    } else if !(unsafe { (*ctxt).input }).is_null() && !(unsafe { (*(*ctxt).input).buf }).is_null() {
        let mut base: size_t = unsafe { xmlBufGetInputBase((*(*(*ctxt).input).buf).buffer, (*ctxt).input) };
        let mut cur: size_t =
            (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as size_t;
        (unsafe { xmlParserInputBufferPush((*(*ctxt).input).buf, size, chunk) });
        (unsafe { xmlBufSetInputBaseCur((*(*(*ctxt).input).buf).buffer, (*ctxt).input, base, cur) });
    }
    if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
        (unsafe { xmlSwitchEncoding(ctxt, enc) });
    }
    return ctxt;
}
extern "C" fn xmlHaltParser(mut ctxt: xmlParserCtxtPtr) {
    if ctxt.is_null() {
        return;
    }
    (unsafe { (*ctxt).instate = XML_PARSER_EOF });
    (unsafe { (*ctxt).disableSAX = 1 as i32 });
    while (unsafe { (*ctxt).inputNr }) > 1 as i32 {
        (unsafe { xmlFreeInputStream(inputPop(ctxt)) });
    }
    if !(unsafe { (*ctxt).input }).is_null() {
        if unsafe { ((*(*ctxt).input).free).is_some() } {
            (unsafe { ((*(*ctxt).input).free).expect("non-null function pointer")(
                (*(*ctxt).input).base as *mut xmlChar,
            ) });
            let fresh461 = unsafe { &mut ((*(*ctxt).input).free) };
            *fresh461 = None;
        }
        if !(unsafe { (*(*ctxt).input).buf }).is_null() {
            (unsafe { xmlFreeParserInputBuffer((*(*ctxt).input).buf) });
            let fresh462 = unsafe { &mut ((*(*ctxt).input).buf) };
            *fresh462 = 0 as xmlParserInputBufferPtr;
        }
        let fresh463 = unsafe { &mut ((*(*ctxt).input).cur) };
        *fresh463 = b"\0" as *const u8 as *const i8 as *mut xmlChar;
        (unsafe { (*(*ctxt).input).length = 0 as i32 });
        let fresh464 = unsafe { &mut ((*(*ctxt).input).base) };
        *fresh464 = unsafe { (*(*ctxt).input).cur };
        let fresh465 = unsafe { &mut ((*(*ctxt).input).end) };
        *fresh465 = unsafe { (*(*ctxt).input).cur };
    }
}
#[no_mangle]
pub extern "C" fn xmlStopParser(mut ctxt: xmlParserCtxtPtr) {
    if ctxt.is_null() {
        return;
    }
    xmlHaltParser(ctxt);
    (unsafe { (*ctxt).errNo = XML_ERR_USER_STOP as i32 });
}
#[no_mangle]
pub extern "C" fn xmlCreateIOParserCtxt(
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut ioread: xmlInputReadCallback,
    mut ioclose: xmlInputCloseCallback,
    mut ioctx: *mut libc::c_void,
    mut enc: xmlCharEncoding,
) -> xmlParserCtxtPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if ioread.is_none() {
        return 0 as xmlParserCtxtPtr;
    }
    buf = unsafe { xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, enc) };
    if buf.is_null() {
        if ioclose.is_some() {
            (unsafe { ioclose.expect("non-null function pointer")(ioctx) });
        }
        return 0 as xmlParserCtxtPtr;
    }
    ctxt = unsafe { xmlNewParserCtxt() };
    if ctxt.is_null() {
        (unsafe { xmlFreeParserInputBuffer(buf) });
        return 0 as xmlParserCtxtPtr;
    }
    if !sax.is_null() {
        if (unsafe { (*ctxt).sax }) != (unsafe { __xmlDefaultSAXHandler() }) as xmlSAXHandlerPtr {
            (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void) });
        }
        let fresh466 = unsafe { &mut ((*ctxt).sax) };
        *fresh466 = (unsafe { xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlSAXHandler>() as u64,
        ) }) as xmlSAXHandlerPtr;
        if (unsafe { (*ctxt).sax }).is_null() {
            (unsafe { xmlFreeParserInputBuffer(buf) });
            (unsafe { xmlErrMemory(ctxt, 0 as *const i8) });
            (unsafe { xmlFreeParserCtxt(ctxt) });
            return 0 as xmlParserCtxtPtr;
        }
        (unsafe { memset(
            (*ctxt).sax as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlSAXHandler>() as u64,
        ) });
        if (unsafe { (*sax).initialized }) == 0xdeedbeaf as u32 {
            (unsafe { memcpy(
                (*ctxt).sax as *mut libc::c_void,
                sax as *const libc::c_void,
                ::std::mem::size_of::<xmlSAXHandler>() as u64,
            ) });
        } else {
            (unsafe { memcpy(
                (*ctxt).sax as *mut libc::c_void,
                sax as *const libc::c_void,
                ::std::mem::size_of::<xmlSAXHandlerV1>() as u64,
            ) });
        }
        if !user_data.is_null() {
            let fresh467 = unsafe { &mut ((*ctxt).userData) };
            *fresh467 = user_data;
        }
    }
    inputStream = unsafe { xmlNewIOInputStream(ctxt, buf, enc) };
    if inputStream.is_null() {
        (unsafe { xmlFreeParserCtxt(ctxt) });
        return 0 as xmlParserCtxtPtr;
    }
    inputPush(ctxt, inputStream);
    return ctxt;
}
#[no_mangle]
pub extern "C" fn xmlIOParseDTD(
    mut sax: xmlSAXHandlerPtr,
    mut input: xmlParserInputBufferPtr,
    mut enc: xmlCharEncoding,
) -> xmlDtdPtr {
    let mut ret: xmlDtdPtr = 0 as xmlDtdPtr;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pinput: xmlParserInputPtr = 0 as xmlParserInputPtr;
    let mut start: [xmlChar; 4] = [0; 4];
    if input.is_null() {
        return 0 as xmlDtdPtr;
    }
    ctxt = unsafe { xmlNewParserCtxt() };
    if ctxt.is_null() {
        (unsafe { xmlFreeParserInputBuffer(input) });
        return 0 as xmlDtdPtr;
    }
    (unsafe { (*ctxt).options |= XML_PARSE_DTDLOAD as i32 });
    if !sax.is_null() {
        if !(unsafe { (*ctxt).sax }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void) });
        }
        let fresh468 = unsafe { &mut ((*ctxt).sax) };
        *fresh468 = sax;
        let fresh469 = unsafe { &mut ((*ctxt).userData) };
        *fresh469 = ctxt as *mut libc::c_void;
    }
    xmlDetectSAX2(ctxt);
    pinput = unsafe { xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE) };
    if pinput.is_null() {
        if !sax.is_null() {
            let fresh470 = unsafe { &mut ((*ctxt).sax) };
            *fresh470 = 0 as *mut _xmlSAXHandler;
        }
        (unsafe { xmlFreeParserInputBuffer(input) });
        (unsafe { xmlFreeParserCtxt(ctxt) });
        return 0 as xmlDtdPtr;
    }
    if xmlPushInput(ctxt, pinput) < 0 as i32 {
        if !sax.is_null() {
            let fresh471 = unsafe { &mut ((*ctxt).sax) };
            *fresh471 = 0 as *mut _xmlSAXHandler;
        }
        (unsafe { xmlFreeParserCtxt(ctxt) });
        return 0 as xmlDtdPtr;
    }
    if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
        (unsafe { xmlSwitchEncoding(ctxt, enc) });
    }
    let fresh472 = unsafe { &mut ((*pinput).filename) };
    *fresh472 = 0 as *const i8;
    (unsafe { (*pinput).line = 1 as i32 });
    (unsafe { (*pinput).col = 1 as i32 });
    let fresh473 = unsafe { &mut ((*pinput).base) };
    *fresh473 = unsafe { (*(*ctxt).input).cur };
    let fresh474 = unsafe { &mut ((*pinput).cur) };
    *fresh474 = unsafe { (*(*ctxt).input).cur };
    let fresh475 = unsafe { &mut ((*pinput).free) };
    *fresh475 = None;
    (unsafe { (*ctxt).inSubset = 2 as i32 });
    let fresh476 = unsafe { &mut ((*ctxt).myDoc) };
    *fresh476 = unsafe { xmlNewDoc(b"1.0\0" as *const u8 as *const i8 as *mut xmlChar) };
    if (unsafe { (*ctxt).myDoc }).is_null() {
        (unsafe { xmlErrMemory(ctxt, b"New Doc failed\0" as *const u8 as *const i8) });
        return 0 as xmlDtdPtr;
    }
    (unsafe { (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as i32 });
    let fresh477 = unsafe { &mut ((*(*ctxt).myDoc).extSubset) };
    *fresh477 = unsafe { xmlNewDtd(
        (*ctxt).myDoc,
        b"none\0" as *const u8 as *const i8 as *mut xmlChar,
        b"none\0" as *const u8 as *const i8 as *mut xmlChar,
        b"none\0" as *const u8 as *const i8 as *mut xmlChar,
    ) };
    if enc as i32 == XML_CHAR_ENCODING_NONE as i32
        && (unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64 >= 4 as i32 as i64
    {
        start[0 as i32 as usize] = unsafe { *(*(*ctxt).input).cur };
        start[1 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) };
        start[2 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) };
        start[3 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) };
        enc = unsafe { xmlDetectCharEncoding(start.as_mut_ptr(), 4 as i32) };
        if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
            (unsafe { xmlSwitchEncoding(ctxt, enc) });
        }
    }
    xmlParseExternalSubset(
        ctxt,
        b"none\0" as *const u8 as *const i8 as *mut xmlChar,
        b"none\0" as *const u8 as *const i8 as *mut xmlChar,
    );
    if !(unsafe { (*ctxt).myDoc }).is_null() {
        if (unsafe { (*ctxt).wellFormed }) != 0 {
            ret = unsafe { (*(*ctxt).myDoc).extSubset };
            let fresh478 = unsafe { &mut ((*(*ctxt).myDoc).extSubset) };
            *fresh478 = 0 as *mut _xmlDtd;
            if !ret.is_null() {
                let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
                let fresh479 = unsafe { &mut ((*ret).doc) };
                *fresh479 = 0 as *mut _xmlDoc;
                tmp = unsafe { (*ret).children };
                while !tmp.is_null() {
                    let fresh480 = unsafe { &mut ((*tmp).doc) };
                    *fresh480 = 0 as *mut _xmlDoc;
                    tmp = unsafe { (*tmp).next };
                }
            }
        } else {
            ret = 0 as xmlDtdPtr;
        }
        (unsafe { xmlFreeDoc((*ctxt).myDoc) });
        let fresh481 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh481 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let fresh482 = unsafe { &mut ((*ctxt).sax) };
        *fresh482 = 0 as *mut _xmlSAXHandler;
    }
    (unsafe { xmlFreeParserCtxt(ctxt) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSAXParseDTD(
    mut sax: xmlSAXHandlerPtr,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) -> xmlDtdPtr {
    let mut ret: xmlDtdPtr = 0 as xmlDtdPtr;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut input: xmlParserInputPtr = 0 as xmlParserInputPtr;
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    let mut systemIdCanonic: *mut xmlChar = 0 as *mut xmlChar;
    if ExternalID.is_null() && SystemID.is_null() {
        return 0 as xmlDtdPtr;
    }
    ctxt = unsafe { xmlNewParserCtxt() };
    if ctxt.is_null() {
        return 0 as xmlDtdPtr;
    }
    (unsafe { (*ctxt).options |= XML_PARSE_DTDLOAD as i32 });
    if !sax.is_null() {
        if !(unsafe { (*ctxt).sax }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void) });
        }
        let fresh483 = unsafe { &mut ((*ctxt).sax) };
        *fresh483 = sax;
        let fresh484 = unsafe { &mut ((*ctxt).userData) };
        *fresh484 = ctxt as *mut libc::c_void;
    }
    systemIdCanonic = unsafe { xmlCanonicPath(SystemID) };
    if !SystemID.is_null() && systemIdCanonic.is_null() {
        (unsafe { xmlFreeParserCtxt(ctxt) });
        return 0 as xmlDtdPtr;
    }
    if !(unsafe { (*ctxt).sax }).is_null() && (unsafe { ((*(*ctxt).sax).resolveEntity).is_some() }) {
        input = unsafe { ((*(*ctxt).sax).resolveEntity).expect("non-null function pointer")(
            (*ctxt).userData,
            ExternalID,
            systemIdCanonic,
        ) };
    }
    if input.is_null() {
        if !sax.is_null() {
            let fresh485 = unsafe { &mut ((*ctxt).sax) };
            *fresh485 = 0 as *mut _xmlSAXHandler;
        }
        (unsafe { xmlFreeParserCtxt(ctxt) });
        if !systemIdCanonic.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(systemIdCanonic as *mut libc::c_void) });
        }
        return 0 as xmlDtdPtr;
    }
    if xmlPushInput(ctxt, input) < 0 as i32 {
        if !sax.is_null() {
            let fresh486 = unsafe { &mut ((*ctxt).sax) };
            *fresh486 = 0 as *mut _xmlSAXHandler;
        }
        (unsafe { xmlFreeParserCtxt(ctxt) });
        if !systemIdCanonic.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(systemIdCanonic as *mut libc::c_void) });
        }
        return 0 as xmlDtdPtr;
    }
    if (unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64 >= 4 as i32 as i64 {
        enc = unsafe { xmlDetectCharEncoding((*(*ctxt).input).cur, 4 as i32) };
        (unsafe { xmlSwitchEncoding(ctxt, enc) });
    }
    if (unsafe { (*input).filename }).is_null() {
        let fresh487 = unsafe { &mut ((*input).filename) };
        *fresh487 = systemIdCanonic as *mut i8;
    } else {
        (unsafe { xmlFree.expect("non-null function pointer")(systemIdCanonic as *mut libc::c_void) });
    }
    (unsafe { (*input).line = 1 as i32 });
    (unsafe { (*input).col = 1 as i32 });
    let fresh488 = unsafe { &mut ((*input).base) };
    *fresh488 = unsafe { (*(*ctxt).input).cur };
    let fresh489 = unsafe { &mut ((*input).cur) };
    *fresh489 = unsafe { (*(*ctxt).input).cur };
    let fresh490 = unsafe { &mut ((*input).free) };
    *fresh490 = None;
    (unsafe { (*ctxt).inSubset = 2 as i32 });
    let fresh491 = unsafe { &mut ((*ctxt).myDoc) };
    *fresh491 = unsafe { xmlNewDoc(b"1.0\0" as *const u8 as *const i8 as *mut xmlChar) };
    if (unsafe { (*ctxt).myDoc }).is_null() {
        (unsafe { xmlErrMemory(ctxt, b"New Doc failed\0" as *const u8 as *const i8) });
        if !sax.is_null() {
            let fresh492 = unsafe { &mut ((*ctxt).sax) };
            *fresh492 = 0 as *mut _xmlSAXHandler;
        }
        (unsafe { xmlFreeParserCtxt(ctxt) });
        return 0 as xmlDtdPtr;
    }
    (unsafe { (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as i32 });
    let fresh493 = unsafe { &mut ((*(*ctxt).myDoc).extSubset) };
    *fresh493 = unsafe { xmlNewDtd(
        (*ctxt).myDoc,
        b"none\0" as *const u8 as *const i8 as *mut xmlChar,
        ExternalID,
        SystemID,
    ) };
    xmlParseExternalSubset(ctxt, ExternalID, SystemID);
    if !(unsafe { (*ctxt).myDoc }).is_null() {
        if (unsafe { (*ctxt).wellFormed }) != 0 {
            ret = unsafe { (*(*ctxt).myDoc).extSubset };
            let fresh494 = unsafe { &mut ((*(*ctxt).myDoc).extSubset) };
            *fresh494 = 0 as *mut _xmlDtd;
            if !ret.is_null() {
                let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
                let fresh495 = unsafe { &mut ((*ret).doc) };
                *fresh495 = 0 as *mut _xmlDoc;
                tmp = unsafe { (*ret).children };
                while !tmp.is_null() {
                    let fresh496 = unsafe { &mut ((*tmp).doc) };
                    *fresh496 = 0 as *mut _xmlDoc;
                    tmp = unsafe { (*tmp).next };
                }
            }
        } else {
            ret = 0 as xmlDtdPtr;
        }
        (unsafe { xmlFreeDoc((*ctxt).myDoc) });
        let fresh497 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh497 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let fresh498 = unsafe { &mut ((*ctxt).sax) };
        *fresh498 = 0 as *mut _xmlSAXHandler;
    }
    (unsafe { xmlFreeParserCtxt(ctxt) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlParseDTD(
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) -> xmlDtdPtr {
    return xmlSAXParseDTD(0 as xmlSAXHandlerPtr, ExternalID, SystemID);
}
#[no_mangle]
pub extern "C" fn xmlParseCtxtExternalEntity(
    mut ctx: xmlParserCtxtPtr,
    mut URL: *const xmlChar,
    mut ID: *const xmlChar,
    mut lst: *mut xmlNodePtr,
) -> i32 {
    let mut userData: *mut libc::c_void = 0 as *mut libc::c_void;
    if ctx.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*ctx).userData }) == ctx as *mut libc::c_void {
        userData = 0 as *mut libc::c_void;
    } else {
        userData = unsafe { (*ctx).userData };
    }
    return xmlParseExternalEntityPrivate(
        unsafe { (*ctx).myDoc },
        ctx,
        unsafe { (*ctx).sax },
        userData,
        (unsafe { (*ctx).depth }) + 1 as i32,
        URL,
        ID,
        lst,
    ) as i32;
}
extern "C" fn xmlParseExternalEntityPrivate(
    mut doc: xmlDocPtr,
    mut oldctxt: xmlParserCtxtPtr,
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut depth: i32,
    mut URL: *const xmlChar,
    mut ID: *const xmlChar,
    mut list: *mut xmlNodePtr,
) -> xmlParserErrors {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut newDoc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut newRoot: xmlNodePtr = 0 as *mut xmlNode;
    let mut oldsax: xmlSAXHandlerPtr = 0 as xmlSAXHandlerPtr;
    let mut ret: xmlParserErrors = XML_ERR_OK;
    let mut start: [xmlChar; 4] = [0; 4];
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    if depth > 40 as i32
        && (oldctxt.is_null() || (unsafe { (*oldctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32)
        || depth > 1024 as i32
    {
        return XML_ERR_ENTITY_LOOP;
    }
    if !list.is_null() {
        (unsafe { *list = 0 as xmlNodePtr });
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
    let fresh499 = unsafe { &mut ((*ctxt).userData) };
    *fresh499 = ctxt as *mut libc::c_void;
    if !sax.is_null() {
        oldsax = unsafe { (*ctxt).sax };
        let fresh500 = unsafe { &mut ((*ctxt).sax) };
        *fresh500 = sax;
        if !user_data.is_null() {
            let fresh501 = unsafe { &mut ((*ctxt).userData) };
            *fresh501 = user_data;
        }
    }
    xmlDetectSAX2(ctxt);
    newDoc = unsafe { xmlNewDoc(b"1.0\0" as *const u8 as *const i8 as *mut xmlChar) };
    if newDoc.is_null() {
        (unsafe { xmlFreeParserCtxt(ctxt) });
        return XML_ERR_INTERNAL_ERROR;
    }
    (unsafe { (*newDoc).properties = XML_DOC_INTERNAL as i32 });
    if !doc.is_null() {
        let fresh502 = unsafe { &mut ((*newDoc).intSubset) };
        *fresh502 = unsafe { (*doc).intSubset };
        let fresh503 = unsafe { &mut ((*newDoc).extSubset) };
        *fresh503 = unsafe { (*doc).extSubset };
        if !(unsafe { (*doc).dict }).is_null() {
            let fresh504 = unsafe { &mut ((*newDoc).dict) };
            *fresh504 = unsafe { (*doc).dict };
            (unsafe { xmlDictReference((*newDoc).dict) });
        }
        if !(unsafe { (*doc).URL }).is_null() {
            let fresh505 = unsafe { &mut ((*newDoc).URL) };
            *fresh505 = unsafe { xmlStrdup((*doc).URL) };
        }
    }
    newRoot = unsafe { xmlNewDocNode(
        newDoc,
        0 as xmlNsPtr,
        b"pseudoroot\0" as *const u8 as *const i8 as *mut xmlChar,
        0 as *const xmlChar,
    ) };
    if newRoot.is_null() {
        if !sax.is_null() {
            let fresh506 = unsafe { &mut ((*ctxt).sax) };
            *fresh506 = oldsax;
        }
        (unsafe { xmlFreeParserCtxt(ctxt) });
        let fresh507 = unsafe { &mut ((*newDoc).intSubset) };
        *fresh507 = 0 as *mut _xmlDtd;
        let fresh508 = unsafe { &mut ((*newDoc).extSubset) };
        *fresh508 = 0 as *mut _xmlDtd;
        (unsafe { xmlFreeDoc(newDoc) });
        return XML_ERR_INTERNAL_ERROR;
    }
    (unsafe { xmlAddChild(newDoc as xmlNodePtr, newRoot) });
    nodePush(ctxt, unsafe { (*newDoc).children });
    if doc.is_null() {
        let fresh509 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh509 = newDoc;
    } else {
        let fresh510 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh510 = doc;
        let fresh511 = unsafe { &mut ((*newRoot).doc) };
        *fresh511 = doc;
    }
    if (unsafe { (*ctxt).progressive }) == 0 as i32
        && ((unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64) < 250 as i32 as i64
    {
        xmlGROW(ctxt);
    }
    if (unsafe { ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) }) as i64 >= 4 as i32 as i64 {
        start[0 as i32 as usize] = unsafe { *(*(*ctxt).input).cur };
        start[1 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) };
        start[2 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(2 as i32 as isize) };
        start[3 as i32 as usize] = unsafe { *((*(*ctxt).input).cur).offset(3 as i32 as isize) };
        enc = unsafe { xmlDetectCharEncoding(start.as_mut_ptr(), 4 as i32) };
        if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
            (unsafe { xmlSwitchEncoding(ctxt, enc) });
        }
    }
    if (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(0 as i32 as isize) }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(1 as i32 as isize) }) as i32 == '?' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(2 as i32 as isize) }) as i32 == 'x' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(3 as i32 as isize) }) as i32 == 'm' as i32
        && (unsafe { *((*(*ctxt).input).cur as *mut u8).offset(4 as i32 as isize) }) as i32 == 'l' as i32
        && ((unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32
                && (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 <= 0xa as i32
            || (unsafe { *((*(*ctxt).input).cur).offset(5 as i32 as isize) }) as i32 == 0xd as i32)
    {
        xmlParseTextDecl(ctxt);
        if (unsafe { xmlStrEqual(
            (*oldctxt).version,
            b"1.0\0" as *const u8 as *const i8 as *mut xmlChar,
        ) }) != 0
            && (unsafe { xmlStrEqual(
                (*(*ctxt).input).version,
                b"1.0\0" as *const u8 as *const i8 as *mut xmlChar,
            ) }) == 0
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_VERSION_MISMATCH,
                b"Version mismatch between document and entity\n\0" as *const u8 as *const i8,
            );
        }
    }
    (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
    (unsafe { (*ctxt).depth = depth });
    if !oldctxt.is_null() {
        let fresh512 = unsafe { &mut ((*ctxt)._private) };
        *fresh512 = unsafe { (*oldctxt)._private };
        (unsafe { (*ctxt).loadsubset = (*oldctxt).loadsubset });
        (unsafe { (*ctxt).validate = (*oldctxt).validate });
        (unsafe { (*ctxt).valid = (*oldctxt).valid });
        (unsafe { (*ctxt).replaceEntities = (*oldctxt).replaceEntities });
        if (unsafe { (*oldctxt).validate }) != 0 {
            let fresh513 = unsafe { &mut ((*ctxt).vctxt.error) };
            *fresh513 = unsafe { (*oldctxt).vctxt.error };
            let fresh514 = unsafe { &mut ((*ctxt).vctxt.warning) };
            *fresh514 = unsafe { (*oldctxt).vctxt.warning };
            let fresh515 = unsafe { &mut ((*ctxt).vctxt.userData) };
            *fresh515 = unsafe { (*oldctxt).vctxt.userData };
        }
        (unsafe { (*ctxt).external = (*oldctxt).external });
        if !(unsafe { (*ctxt).dict }).is_null() {
            (unsafe { xmlDictFree((*ctxt).dict) });
        }
        let fresh516 = unsafe { &mut ((*ctxt).dict) };
        *fresh516 = unsafe { (*oldctxt).dict };
        let fresh517 = unsafe { &mut ((*ctxt).str_xml) };
        *fresh517 = unsafe { xmlDictLookup(
            (*ctxt).dict,
            b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
            3 as i32,
        ) };
        let fresh518 = unsafe { &mut ((*ctxt).str_xmlns) };
        *fresh518 = unsafe { xmlDictLookup(
            (*ctxt).dict,
            b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
            5 as i32,
        ) };
        let fresh519 = unsafe { &mut ((*ctxt).str_xml_ns) };
        *fresh519 = unsafe { xmlDictLookup(
            (*ctxt).dict,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
            36 as i32,
        ) };
        (unsafe { (*ctxt).dictNames = (*oldctxt).dictNames });
        let fresh520 = unsafe { &mut ((*ctxt).attsDefault) };
        *fresh520 = unsafe { (*oldctxt).attsDefault };
        let fresh521 = unsafe { &mut ((*ctxt).attsSpecial) };
        *fresh521 = unsafe { (*oldctxt).attsSpecial };
        (unsafe { (*ctxt).linenumbers = (*oldctxt).linenumbers });
        (unsafe { (*ctxt).record_info = (*oldctxt).record_info });
        (unsafe { (*ctxt).node_seq.maximum = (*oldctxt).node_seq.maximum });
        (unsafe { (*ctxt).node_seq.length = (*oldctxt).node_seq.length });
        let fresh522 = unsafe { &mut ((*ctxt).node_seq.buffer) };
        *fresh522 = unsafe { (*oldctxt).node_seq.buffer };
    } else {
        let fresh523 = unsafe { &mut ((*ctxt)._private) };
        *fresh523 = 0 as *mut libc::c_void;
        (unsafe { (*ctxt).validate = 0 as i32 });
        (unsafe { (*ctxt).external = 2 as i32 });
        (unsafe { (*ctxt).loadsubset = 0 as i32 });
    }
    xmlParseContent(ctxt);
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 != 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const i8);
    }
    if (unsafe { (*ctxt).node }) != (unsafe { (*newDoc).children }) {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    }
    if (unsafe { (*ctxt).wellFormed }) == 0 {
        if (unsafe { (*ctxt).errNo }) == 0 as i32 {
            ret = XML_ERR_INTERNAL_ERROR;
        } else {
            ret = (unsafe { (*ctxt).errNo }) as xmlParserErrors;
        }
    } else {
        if !list.is_null() {
            let mut cur: xmlNodePtr = 0 as *mut xmlNode;
            cur = unsafe { (*(*newDoc).children).children };
            (unsafe { *list = cur });
            while !cur.is_null() {
                let fresh524 = unsafe { &mut ((*cur).parent) };
                *fresh524 = 0 as *mut _xmlNode;
                cur = unsafe { (*cur).next };
            }
            let fresh525 = unsafe { &mut ((*(*newDoc).children).children) };
            *fresh525 = 0 as *mut _xmlNode;
        }
        ret = XML_ERR_OK;
    }
    if !oldctxt.is_null() {
        let fresh526 = unsafe { &mut ((*oldctxt).nbentities) };
        *fresh526 = (*fresh526).wrapping_add(unsafe { (*ctxt).nbentities });
    }
    if !(unsafe { (*ctxt).input }).is_null() && !oldctxt.is_null() {
        let fresh527 = unsafe { &mut ((*oldctxt).sizeentities) };
        *fresh527 = (*fresh527).wrapping_add(unsafe { (*(*ctxt).input).consumed });
        let fresh528 = unsafe { &mut ((*oldctxt).sizeentities) };
        *fresh528 = (*fresh528)
            .wrapping_add((unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as u64);
    }
    if !oldctxt.is_null() && (unsafe { (*ctxt).lastError.code }) != XML_ERR_OK as i32 {
        (unsafe { xmlCopyError(&mut (*ctxt).lastError, &mut (*oldctxt).lastError) });
    }
    if !sax.is_null() {
        let fresh529 = unsafe { &mut ((*ctxt).sax) };
        *fresh529 = oldsax;
    }
    if !oldctxt.is_null() {
        let fresh530 = unsafe { &mut ((*ctxt).dict) };
        *fresh530 = 0 as xmlDictPtr;
        let fresh531 = unsafe { &mut ((*ctxt).attsDefault) };
        *fresh531 = 0 as xmlHashTablePtr;
        let fresh532 = unsafe { &mut ((*ctxt).attsSpecial) };
        *fresh532 = 0 as xmlHashTablePtr;
        (unsafe { (*oldctxt).validate = (*ctxt).validate });
        (unsafe { (*oldctxt).valid = (*ctxt).valid });
        (unsafe { (*oldctxt).node_seq.maximum = (*ctxt).node_seq.maximum });
        (unsafe { (*oldctxt).node_seq.length = (*ctxt).node_seq.length });
        let fresh533 = unsafe { &mut ((*oldctxt).node_seq.buffer) };
        *fresh533 = unsafe { (*ctxt).node_seq.buffer };
    }
    (unsafe { (*ctxt).node_seq.maximum = 0 as i32 as u64 });
    (unsafe { (*ctxt).node_seq.length = 0 as i32 as u64 });
    let fresh534 = unsafe { &mut ((*ctxt).node_seq.buffer) };
    *fresh534 = 0 as *mut xmlParserNodeInfo;
    (unsafe { xmlFreeParserCtxt(ctxt) });
    let fresh535 = unsafe { &mut ((*newDoc).intSubset) };
    *fresh535 = 0 as *mut _xmlDtd;
    let fresh536 = unsafe { &mut ((*newDoc).extSubset) };
    *fresh536 = 0 as *mut _xmlDtd;
    (unsafe { xmlFreeDoc(newDoc) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlParseExternalEntity(
    mut doc: xmlDocPtr,
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut depth: i32,
    mut URL: *const xmlChar,
    mut ID: *const xmlChar,
    mut lst: *mut xmlNodePtr,
) -> i32 {
    return xmlParseExternalEntityPrivate(
        doc,
        0 as xmlParserCtxtPtr,
        sax,
        user_data,
        depth,
        URL,
        ID,
        lst,
    ) as i32;
}
#[no_mangle]
pub extern "C" fn xmlParseBalancedChunkMemory(
    mut doc: xmlDocPtr,
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut depth: i32,
    mut string: *const xmlChar,
    mut lst: *mut xmlNodePtr,
) -> i32 {
    return xmlParseBalancedChunkMemoryRecover(doc, sax, user_data, depth, string, lst, 0 as i32);
}
extern "C" fn xmlParseBalancedChunkMemoryInternal(
    mut oldctxt: xmlParserCtxtPtr,
    mut string: *const xmlChar,
    mut user_data: *mut libc::c_void,
    mut lst: *mut xmlNodePtr,
) -> xmlParserErrors {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut newDoc: xmlDocPtr = 0 as xmlDocPtr;
    let mut newRoot: xmlNodePtr = 0 as *mut xmlNode;
    let mut oldsax: xmlSAXHandlerPtr = 0 as xmlSAXHandlerPtr;
    let mut content: xmlNodePtr = 0 as xmlNodePtr;
    let mut last: xmlNodePtr = 0 as xmlNodePtr;
    let mut size: i32 = 0;
    let mut ret: xmlParserErrors = XML_ERR_OK;
    let mut i: i32 = 0;
    if (unsafe { (*oldctxt).depth }) > 40 as i32 && (unsafe { (*oldctxt).options }) & XML_PARSE_HUGE as i32 == 0 as i32
        || (unsafe { (*oldctxt).depth }) > 1024 as i32
    {
        return XML_ERR_ENTITY_LOOP;
    }
    if !lst.is_null() {
        (unsafe { *lst = 0 as xmlNodePtr });
    }
    if string.is_null() {
        return XML_ERR_INTERNAL_ERROR;
    }
    size = unsafe { xmlStrlen(string) };
    ctxt = xmlCreateMemoryParserCtxt(string as *mut i8, size);
    if ctxt.is_null() {
        return XML_WAR_UNDECLARED_ENTITY;
    }
    if !user_data.is_null() {
        let fresh537 = unsafe { &mut ((*ctxt).userData) };
        *fresh537 = user_data;
    } else {
        let fresh538 = unsafe { &mut ((*ctxt).userData) };
        *fresh538 = ctxt as *mut libc::c_void;
    }
    if !(unsafe { (*ctxt).dict }).is_null() {
        (unsafe { xmlDictFree((*ctxt).dict) });
    }
    let fresh539 = unsafe { &mut ((*ctxt).dict) };
    *fresh539 = unsafe { (*oldctxt).dict };
    (unsafe { (*ctxt).input_id = (*oldctxt).input_id + 1 as i32 });
    let fresh540 = unsafe { &mut ((*ctxt).str_xml) };
    *fresh540 = unsafe { xmlDictLookup(
        (*ctxt).dict,
        b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
        3 as i32,
    ) };
    let fresh541 = unsafe { &mut ((*ctxt).str_xmlns) };
    *fresh541 = unsafe { xmlDictLookup(
        (*ctxt).dict,
        b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
        5 as i32,
    ) };
    let fresh542 = unsafe { &mut ((*ctxt).str_xml_ns) };
    *fresh542 = unsafe { xmlDictLookup(
        (*ctxt).dict,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
        36 as i32,
    ) };
    i = 0 as i32;
    while i < (unsafe { (*oldctxt).nsNr }) {
        nsPush(
            ctxt,
            unsafe { *((*oldctxt).nsTab).offset(i as isize) },
            unsafe { *((*oldctxt).nsTab).offset((i + 1 as i32) as isize) },
        );
        i += 2 as i32;
    }
    oldsax = unsafe { (*ctxt).sax };
    let fresh543 = unsafe { &mut ((*ctxt).sax) };
    *fresh543 = unsafe { (*oldctxt).sax };
    xmlDetectSAX2(ctxt);
    (unsafe { (*ctxt).replaceEntities = (*oldctxt).replaceEntities });
    (unsafe { (*ctxt).options = (*oldctxt).options });
    let fresh544 = unsafe { &mut ((*ctxt)._private) };
    *fresh544 = unsafe { (*oldctxt)._private };
    if (unsafe { (*oldctxt).myDoc }).is_null() {
        newDoc = unsafe { xmlNewDoc(b"1.0\0" as *const u8 as *const i8 as *mut xmlChar) };
        if newDoc.is_null() {
            let fresh545 = unsafe { &mut ((*ctxt).sax) };
            *fresh545 = oldsax;
            let fresh546 = unsafe { &mut ((*ctxt).dict) };
            *fresh546 = 0 as xmlDictPtr;
            (unsafe { xmlFreeParserCtxt(ctxt) });
            return XML_ERR_INTERNAL_ERROR;
        }
        (unsafe { (*newDoc).properties = XML_DOC_INTERNAL as i32 });
        let fresh547 = unsafe { &mut ((*newDoc).dict) };
        *fresh547 = unsafe { (*ctxt).dict };
        (unsafe { xmlDictReference((*newDoc).dict) });
        let fresh548 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh548 = newDoc;
    } else {
        let fresh549 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh549 = unsafe { (*oldctxt).myDoc };
        content = unsafe { (*(*ctxt).myDoc).children };
        last = unsafe { (*(*ctxt).myDoc).last };
    }
    newRoot = unsafe { xmlNewDocNode(
        (*ctxt).myDoc,
        0 as xmlNsPtr,
        b"pseudoroot\0" as *const u8 as *const i8 as *mut xmlChar,
        0 as *const xmlChar,
    ) };
    if newRoot.is_null() {
        let fresh550 = unsafe { &mut ((*ctxt).sax) };
        *fresh550 = oldsax;
        let fresh551 = unsafe { &mut ((*ctxt).dict) };
        *fresh551 = 0 as xmlDictPtr;
        (unsafe { xmlFreeParserCtxt(ctxt) });
        if !newDoc.is_null() {
            (unsafe { xmlFreeDoc(newDoc) });
        }
        return XML_ERR_INTERNAL_ERROR;
    }
    let fresh552 = unsafe { &mut ((*(*ctxt).myDoc).children) };
    *fresh552 = 0 as *mut _xmlNode;
    let fresh553 = unsafe { &mut ((*(*ctxt).myDoc).last) };
    *fresh553 = 0 as *mut _xmlNode;
    (unsafe { xmlAddChild((*ctxt).myDoc as xmlNodePtr, newRoot) });
    nodePush(ctxt, unsafe { (*(*ctxt).myDoc).children });
    (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
    (unsafe { (*ctxt).depth = (*oldctxt).depth + 1 as i32 });
    (unsafe { (*ctxt).validate = 0 as i32 });
    (unsafe { (*ctxt).loadsubset = (*oldctxt).loadsubset });
    if (unsafe { (*oldctxt).validate }) != 0 || (unsafe { (*oldctxt).replaceEntities }) != 0 as i32 {
        (unsafe { (*ctxt).loadsubset |= 8 as i32 });
    }
    (unsafe { (*ctxt).dictNames = (*oldctxt).dictNames });
    let fresh554 = unsafe { &mut ((*ctxt).attsDefault) };
    *fresh554 = unsafe { (*oldctxt).attsDefault };
    let fresh555 = unsafe { &mut ((*ctxt).attsSpecial) };
    *fresh555 = unsafe { (*oldctxt).attsSpecial };
    xmlParseContent(ctxt);
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 != 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const i8);
    }
    if (unsafe { (*ctxt).node }) != (unsafe { (*(*ctxt).myDoc).children }) {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    }
    if (unsafe { (*ctxt).wellFormed }) == 0 {
        if (unsafe { (*ctxt).errNo }) == 0 as i32 {
            ret = XML_ERR_INTERNAL_ERROR;
        } else {
            ret = (unsafe { (*ctxt).errNo }) as xmlParserErrors;
        }
    } else {
        ret = XML_ERR_OK;
    }
    if !lst.is_null() && ret as u32 == XML_ERR_OK as i32 as u32 {
        let mut cur: xmlNodePtr = 0 as *mut xmlNode;
        cur = unsafe { (*(*(*ctxt).myDoc).children).children };
        (unsafe { *lst = cur });
        while !cur.is_null() {
            if (unsafe { (*oldctxt).validate }) != 0
                && (unsafe { (*oldctxt).wellFormed }) != 0
                && !(unsafe { (*oldctxt).myDoc }).is_null()
                && !(unsafe { (*(*oldctxt).myDoc).intSubset }).is_null()
                && (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
            {
                (unsafe { (*oldctxt).valid &=
                    xmlValidateElement(&mut (*oldctxt).vctxt, (*oldctxt).myDoc, cur) });
            }
            let fresh556 = unsafe { &mut ((*cur).parent) };
            *fresh556 = 0 as *mut _xmlNode;
            cur = unsafe { (*cur).next };
        }
        let fresh557 = unsafe { &mut ((*(*(*ctxt).myDoc).children).children) };
        *fresh557 = 0 as *mut _xmlNode;
    }
    if !(unsafe { (*ctxt).myDoc }).is_null() {
        (unsafe { xmlFreeNode((*(*ctxt).myDoc).children) });
        let fresh558 = unsafe { &mut ((*(*ctxt).myDoc).children) };
        *fresh558 = content;
        let fresh559 = unsafe { &mut ((*(*ctxt).myDoc).last) };
        *fresh559 = last;
    }
    if !oldctxt.is_null() {
        let fresh560 = unsafe { &mut ((*oldctxt).nbentities) };
        *fresh560 = (*fresh560).wrapping_add(unsafe { (*ctxt).nbentities });
    }
    if (unsafe { (*ctxt).lastError.code }) != XML_ERR_OK as i32 {
        (unsafe { xmlCopyError(&mut (*ctxt).lastError, &mut (*oldctxt).lastError) });
    }
    let fresh561 = unsafe { &mut ((*ctxt).sax) };
    *fresh561 = oldsax;
    let fresh562 = unsafe { &mut ((*ctxt).dict) };
    *fresh562 = 0 as xmlDictPtr;
    let fresh563 = unsafe { &mut ((*ctxt).attsDefault) };
    *fresh563 = 0 as xmlHashTablePtr;
    let fresh564 = unsafe { &mut ((*ctxt).attsSpecial) };
    *fresh564 = 0 as xmlHashTablePtr;
    (unsafe { xmlFreeParserCtxt(ctxt) });
    if !newDoc.is_null() {
        (unsafe { xmlFreeDoc(newDoc) });
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlParseInNodeContext(
    mut node: xmlNodePtr,
    mut data: *const i8,
    mut datalen: i32,
    mut options: i32,
    mut lst: *mut xmlNodePtr,
) -> xmlParserErrors {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut doc: xmlDocPtr = 0 as xmlDocPtr;
    let mut fake: xmlNodePtr = 0 as *mut xmlNode;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut nsnr: i32 = 0 as i32;
    let mut ret: xmlParserErrors = XML_ERR_OK;
    if lst.is_null() || node.is_null() || data.is_null() || datalen < 0 as i32 {
        return XML_ERR_INTERNAL_ERROR;
    }
    match (unsafe { (*node).type_0 }) as u32 {
        1 | 2 | 3 | 4 | 5 | 7 | 8 | 9 | 13 => {}
        _ => return XML_ERR_INTERNAL_ERROR,
    }
    while !node.is_null()
        && (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_DOCUMENT_NODE as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        node = unsafe { (*node).parent };
    }
    if node.is_null() {
        return XML_ERR_INTERNAL_ERROR;
    }
    if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
        doc = unsafe { (*node).doc };
    } else {
        doc = node as xmlDocPtr;
    }
    if doc.is_null() {
        return XML_ERR_INTERNAL_ERROR;
    }
    if (unsafe { (*doc).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32 {
        ctxt = xmlCreateMemoryParserCtxt(data as *mut i8, datalen);
    } else if (unsafe { (*doc).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32 {
        ctxt = unsafe { htmlCreateMemoryParserCtxt(data as *mut i8, datalen) };
        options |= HTML_PARSE_NOIMPLIED as i32;
    } else {
        return XML_ERR_INTERNAL_ERROR;
    }
    if ctxt.is_null() {
        return XML_ERR_NO_MEMORY;
    }
    if !(unsafe { (*doc).dict }).is_null() {
        if !(unsafe { (*ctxt).dict }).is_null() {
            (unsafe { xmlDictFree((*ctxt).dict) });
        }
        let fresh565 = unsafe { &mut ((*ctxt).dict) };
        *fresh565 = unsafe { (*doc).dict };
    } else {
        options |= XML_PARSE_NODICT as i32;
    }
    if !(unsafe { (*doc).encoding }).is_null() {
        let mut hdlr: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
        if !(unsafe { (*ctxt).encoding }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(
                (*ctxt).encoding as *mut xmlChar as *mut libc::c_void,
            ) });
        }
        let fresh566 = unsafe { &mut ((*ctxt).encoding) };
        *fresh566 = unsafe { xmlStrdup((*doc).encoding) };
        hdlr = unsafe { xmlFindCharEncodingHandler((*doc).encoding as *const i8) };
        if !hdlr.is_null() {
            (unsafe { xmlSwitchToEncoding(ctxt, hdlr) });
        } else {
            return XML_ERR_UNSUPPORTED_ENCODING;
        }
    }
    xmlCtxtUseOptionsInternal(ctxt, options, 0 as *const i8);
    xmlDetectSAX2(ctxt);
    let fresh567 = unsafe { &mut ((*ctxt).myDoc) };
    *fresh567 = doc;
    (unsafe { (*ctxt).input_id = 2 as i32 });
    (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
    fake = unsafe { xmlNewDocComment((*node).doc, 0 as *const xmlChar) };
    if fake.is_null() {
        (unsafe { xmlFreeParserCtxt(ctxt) });
        return XML_ERR_NO_MEMORY;
    }
    (unsafe { xmlAddChild(node, fake) });
    if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
        nodePush(ctxt, node);
        cur = node;
        while !cur.is_null() && (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            let mut ns: xmlNsPtr = unsafe { (*cur).nsDef };
            let mut iprefix: *const xmlChar = 0 as *const xmlChar;
            let mut ihref: *const xmlChar = 0 as *const xmlChar;
            while !ns.is_null() {
                if !(unsafe { (*ctxt).dict }).is_null() {
                    iprefix = unsafe { xmlDictLookup((*ctxt).dict, (*ns).prefix, -(1 as i32)) };
                    ihref = unsafe { xmlDictLookup((*ctxt).dict, (*ns).href, -(1 as i32)) };
                } else {
                    iprefix = unsafe { (*ns).prefix };
                    ihref = unsafe { (*ns).href };
                }
                if (xmlGetNamespace(ctxt, iprefix)).is_null() {
                    nsPush(ctxt, iprefix, ihref);
                    nsnr += 1;
                }
                ns = unsafe { (*ns).next };
            }
            cur = unsafe { (*cur).parent };
        }
    }
    if (unsafe { (*ctxt).validate }) != 0 || (unsafe { (*ctxt).replaceEntities }) != 0 as i32 {
        (unsafe { (*ctxt).loadsubset |= 8 as i32 });
    }
    if (unsafe { (*doc).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32 {
        (unsafe { __htmlParseContent(ctxt as *mut libc::c_void) });
    } else {
        xmlParseContent(ctxt);
    }
    nsPop(ctxt, nsnr);
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 != 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const i8);
    }
    if !(unsafe { (*ctxt).node }).is_null() && (unsafe { (*ctxt).node }) != node {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
        (unsafe { (*ctxt).wellFormed = 0 as i32 });
    }
    if (unsafe { (*ctxt).wellFormed }) == 0 {
        if (unsafe { (*ctxt).errNo }) == 0 as i32 {
            ret = XML_ERR_INTERNAL_ERROR;
        } else {
            ret = (unsafe { (*ctxt).errNo }) as xmlParserErrors;
        }
    } else {
        ret = XML_ERR_OK;
    }
    cur = unsafe { (*fake).next };
    let fresh568 = unsafe { &mut ((*fake).next) };
    *fresh568 = 0 as *mut _xmlNode;
    let fresh569 = unsafe { &mut ((*node).last) };
    *fresh569 = fake;
    if !cur.is_null() {
        let fresh570 = unsafe { &mut ((*cur).prev) };
        *fresh570 = 0 as *mut _xmlNode;
    }
    (unsafe { *lst = cur });
    while !cur.is_null() {
        let fresh571 = unsafe { &mut ((*cur).parent) };
        *fresh571 = 0 as *mut _xmlNode;
        cur = unsafe { (*cur).next };
    }
    (unsafe { xmlUnlinkNode(fake) });
    (unsafe { xmlFreeNode(fake) });
    if ret as u32 != XML_ERR_OK as i32 as u32 {
        (unsafe { xmlFreeNodeList(*lst) });
        (unsafe { *lst = 0 as xmlNodePtr });
    }
    if !(unsafe { (*doc).dict }).is_null() {
        let fresh572 = unsafe { &mut ((*ctxt).dict) };
        *fresh572 = 0 as xmlDictPtr;
    }
    (unsafe { xmlFreeParserCtxt(ctxt) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlParseBalancedChunkMemoryRecover(
    mut doc: xmlDocPtr,
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut depth: i32,
    mut string: *const xmlChar,
    mut lst: *mut xmlNodePtr,
    mut recover: i32,
) -> i32 {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut newDoc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut oldsax: xmlSAXHandlerPtr = 0 as xmlSAXHandlerPtr;
    let mut content: xmlNodePtr = 0 as *mut xmlNode;
    let mut newRoot: xmlNodePtr = 0 as *mut xmlNode;
    let mut size: i32 = 0;
    let mut ret: i32 = 0 as i32;
    if depth > 40 as i32 {
        return XML_ERR_ENTITY_LOOP as i32;
    }
    if !lst.is_null() {
        (unsafe { *lst = 0 as xmlNodePtr });
    }
    if string.is_null() {
        return -(1 as i32);
    }
    size = unsafe { xmlStrlen(string) };
    ctxt = xmlCreateMemoryParserCtxt(string as *mut i8, size);
    if ctxt.is_null() {
        return -(1 as i32);
    }
    let fresh573 = unsafe { &mut ((*ctxt).userData) };
    *fresh573 = ctxt as *mut libc::c_void;
    if !sax.is_null() {
        oldsax = unsafe { (*ctxt).sax };
        let fresh574 = unsafe { &mut ((*ctxt).sax) };
        *fresh574 = sax;
        if !user_data.is_null() {
            let fresh575 = unsafe { &mut ((*ctxt).userData) };
            *fresh575 = user_data;
        }
    }
    newDoc = unsafe { xmlNewDoc(b"1.0\0" as *const u8 as *const i8 as *mut xmlChar) };
    if newDoc.is_null() {
        (unsafe { xmlFreeParserCtxt(ctxt) });
        return -(1 as i32);
    }
    (unsafe { (*newDoc).properties = XML_DOC_INTERNAL as i32 });
    if !doc.is_null() && !(unsafe { (*doc).dict }).is_null() {
        (unsafe { xmlDictFree((*ctxt).dict) });
        let fresh576 = unsafe { &mut ((*ctxt).dict) };
        *fresh576 = unsafe { (*doc).dict };
        (unsafe { xmlDictReference((*ctxt).dict) });
        let fresh577 = unsafe { &mut ((*ctxt).str_xml) };
        *fresh577 = unsafe { xmlDictLookup(
            (*ctxt).dict,
            b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
            3 as i32,
        ) };
        let fresh578 = unsafe { &mut ((*ctxt).str_xmlns) };
        *fresh578 = unsafe { xmlDictLookup(
            (*ctxt).dict,
            b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
            5 as i32,
        ) };
        let fresh579 = unsafe { &mut ((*ctxt).str_xml_ns) };
        *fresh579 = unsafe { xmlDictLookup(
            (*ctxt).dict,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
            36 as i32,
        ) };
        (unsafe { (*ctxt).dictNames = 1 as i32 });
    } else {
        xmlCtxtUseOptionsInternal(ctxt, XML_PARSE_NODICT as i32, 0 as *const i8);
    }
    if !doc.is_null() {
        let fresh580 = unsafe { &mut ((*newDoc).intSubset) };
        *fresh580 = unsafe { (*doc).intSubset };
        let fresh581 = unsafe { &mut ((*newDoc).extSubset) };
        *fresh581 = unsafe { (*doc).extSubset };
    }
    newRoot = unsafe { xmlNewDocNode(
        newDoc,
        0 as xmlNsPtr,
        b"pseudoroot\0" as *const u8 as *const i8 as *mut xmlChar,
        0 as *const xmlChar,
    ) };
    if newRoot.is_null() {
        if !sax.is_null() {
            let fresh582 = unsafe { &mut ((*ctxt).sax) };
            *fresh582 = oldsax;
        }
        (unsafe { xmlFreeParserCtxt(ctxt) });
        let fresh583 = unsafe { &mut ((*newDoc).intSubset) };
        *fresh583 = 0 as *mut _xmlDtd;
        let fresh584 = unsafe { &mut ((*newDoc).extSubset) };
        *fresh584 = 0 as *mut _xmlDtd;
        (unsafe { xmlFreeDoc(newDoc) });
        return -(1 as i32);
    }
    (unsafe { xmlAddChild(newDoc as xmlNodePtr, newRoot) });
    nodePush(ctxt, newRoot);
    if doc.is_null() {
        let fresh585 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh585 = newDoc;
    } else {
        let fresh586 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh586 = newDoc;
        let fresh587 = unsafe { &mut ((*(*newDoc).children).doc) };
        *fresh587 = doc;
        (unsafe { xmlSearchNsByHref(
            doc,
            doc as xmlNodePtr,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
        ) });
        let fresh588 = unsafe { &mut ((*newDoc).oldNs) };
        *fresh588 = unsafe { (*doc).oldNs };
    }
    (unsafe { (*ctxt).instate = XML_PARSER_CONTENT });
    (unsafe { (*ctxt).input_id = 2 as i32 });
    (unsafe { (*ctxt).depth = depth });
    (unsafe { (*ctxt).validate = 0 as i32 });
    (unsafe { (*ctxt).loadsubset = 0 as i32 });
    xmlDetectSAX2(ctxt);
    if !doc.is_null() {
        content = unsafe { (*doc).children };
        let fresh589 = unsafe { &mut ((*doc).children) };
        *fresh589 = 0 as *mut _xmlNode;
        xmlParseContent(ctxt);
        let fresh590 = unsafe { &mut ((*doc).children) };
        *fresh590 = content;
    } else {
        xmlParseContent(ctxt);
    }
    if (unsafe { *(*(*ctxt).input).cur }) as i32 == '<' as i32
        && (unsafe { *((*(*ctxt).input).cur).offset(1 as i32 as isize) }) as i32 == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    } else if (unsafe { *(*(*ctxt).input).cur }) as i32 != 0 as i32 {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const i8);
    }
    if (unsafe { (*ctxt).node }) != (unsafe { (*newDoc).children }) {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const i8);
    }
    if (unsafe { (*ctxt).wellFormed }) == 0 {
        if (unsafe { (*ctxt).errNo }) == 0 as i32 {
            ret = 1 as i32;
        } else {
            ret = unsafe { (*ctxt).errNo };
        }
    } else {
        ret = 0 as i32;
    }
    if !lst.is_null() && (ret == 0 as i32 || recover == 1 as i32) {
        let mut cur: xmlNodePtr = 0 as *mut xmlNode;
        cur = unsafe { (*(*newDoc).children).children };
        (unsafe { *lst = cur });
        while !cur.is_null() {
            (unsafe { xmlSetTreeDoc(cur, doc) });
            let fresh591 = unsafe { &mut ((*cur).parent) };
            *fresh591 = 0 as *mut _xmlNode;
            cur = unsafe { (*cur).next };
        }
        let fresh592 = unsafe { &mut ((*(*newDoc).children).children) };
        *fresh592 = 0 as *mut _xmlNode;
    }
    if !sax.is_null() {
        let fresh593 = unsafe { &mut ((*ctxt).sax) };
        *fresh593 = oldsax;
    }
    (unsafe { xmlFreeParserCtxt(ctxt) });
    let fresh594 = unsafe { &mut ((*newDoc).intSubset) };
    *fresh594 = 0 as *mut _xmlDtd;
    let fresh595 = unsafe { &mut ((*newDoc).extSubset) };
    *fresh595 = 0 as *mut _xmlDtd;
    let fresh596 = unsafe { &mut ((*newDoc).oldNs) };
    *fresh596 = 0 as *mut _xmlNs;
    (unsafe { xmlFreeDoc(newDoc) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSAXParseEntity(
    mut sax: xmlSAXHandlerPtr,
    mut filename: *const i8,
) -> xmlDocPtr {
    let mut ret: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    ctxt = xmlCreateFileParserCtxt(filename);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        if !(unsafe { (*ctxt).sax }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void) });
        }
        let fresh597 = unsafe { &mut ((*ctxt).sax) };
        *fresh597 = sax;
        let fresh598 = unsafe { &mut ((*ctxt).userData) };
        *fresh598 = 0 as *mut libc::c_void;
    }
    xmlParseExtParsedEnt(ctxt);
    if (unsafe { (*ctxt).wellFormed }) != 0 {
        ret = unsafe { (*ctxt).myDoc };
    } else {
        ret = 0 as xmlDocPtr;
        (unsafe { xmlFreeDoc((*ctxt).myDoc) });
        let fresh599 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh599 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let fresh600 = unsafe { &mut ((*ctxt).sax) };
        *fresh600 = 0 as *mut _xmlSAXHandler;
    }
    (unsafe { xmlFreeParserCtxt(ctxt) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlParseEntity(mut filename: *const i8) -> xmlDocPtr {
    return xmlSAXParseEntity(0 as xmlSAXHandlerPtr, filename);
}
extern "C" fn xmlCreateEntityParserCtxtInternal(
    mut URL: *const xmlChar,
    mut ID: *const xmlChar,
    mut base: *const xmlChar,
    mut pctx: xmlParserCtxtPtr,
) -> xmlParserCtxtPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut directory: *mut i8 = 0 as *mut i8;
    let mut uri: *mut xmlChar = 0 as *mut xmlChar;
    ctxt = unsafe { xmlNewParserCtxt() };
    if ctxt.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    if !pctx.is_null() {
        (unsafe { (*ctxt).options = (*pctx).options });
        let fresh601 = unsafe { &mut ((*ctxt)._private) };
        *fresh601 = unsafe { (*pctx)._private };
        (unsafe { (*ctxt).input_id = (*pctx).input_id + 1 as i32 });
    }
    if (unsafe { xmlStrcmp(URL, b"-\0" as *const u8 as *const i8 as *mut xmlChar) }) == 0 as i32 {
        URL = b"./-\0" as *const u8 as *const i8 as *mut xmlChar;
    }
    uri = unsafe { xmlBuildURI(URL, base) };
    if uri.is_null() {
        inputStream = unsafe { xmlLoadExternalEntity(URL as *mut i8, ID as *mut i8, ctxt) };
        if inputStream.is_null() {
            (unsafe { xmlFreeParserCtxt(ctxt) });
            return 0 as xmlParserCtxtPtr;
        }
        inputPush(ctxt, inputStream);
        if (unsafe { (*ctxt).directory }).is_null() && directory.is_null() {
            directory = unsafe { xmlParserGetDirectory(URL as *mut i8) };
        }
        if (unsafe { (*ctxt).directory }).is_null() && !directory.is_null() {
            let fresh602 = unsafe { &mut ((*ctxt).directory) };
            *fresh602 = directory;
        }
    } else {
        inputStream = unsafe { xmlLoadExternalEntity(uri as *mut i8, ID as *mut i8, ctxt) };
        if inputStream.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(uri as *mut libc::c_void) });
            (unsafe { xmlFreeParserCtxt(ctxt) });
            return 0 as xmlParserCtxtPtr;
        }
        inputPush(ctxt, inputStream);
        if (unsafe { (*ctxt).directory }).is_null() && directory.is_null() {
            directory = unsafe { xmlParserGetDirectory(uri as *mut i8) };
        }
        if (unsafe { (*ctxt).directory }).is_null() && !directory.is_null() {
            let fresh603 = unsafe { &mut ((*ctxt).directory) };
            *fresh603 = directory;
        }
        (unsafe { xmlFree.expect("non-null function pointer")(uri as *mut libc::c_void) });
    }
    return ctxt;
}
#[no_mangle]
pub extern "C" fn xmlCreateEntityParserCtxt(
    mut URL: *const xmlChar,
    mut ID: *const xmlChar,
    mut base: *const xmlChar,
) -> xmlParserCtxtPtr {
    return xmlCreateEntityParserCtxtInternal(URL, ID, base, 0 as xmlParserCtxtPtr);
}
#[no_mangle]
pub extern "C" fn xmlCreateURLParserCtxt(
    mut filename: *const i8,
    mut options: i32,
) -> xmlParserCtxtPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut directory: *mut i8 = 0 as *mut i8;
    ctxt = unsafe { xmlNewParserCtxt() };
    if ctxt.is_null() {
        (unsafe { xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"cannot allocate parser context\0" as *const u8 as *const i8,
        ) });
        return 0 as xmlParserCtxtPtr;
    }
    if options != 0 {
        xmlCtxtUseOptionsInternal(ctxt, options, 0 as *const i8);
    }
    (unsafe { (*ctxt).linenumbers = 1 as i32 });
    inputStream = unsafe { xmlLoadExternalEntity(filename, 0 as *const i8, ctxt) };
    if inputStream.is_null() {
        (unsafe { xmlFreeParserCtxt(ctxt) });
        return 0 as xmlParserCtxtPtr;
    }
    inputPush(ctxt, inputStream);
    if (unsafe { (*ctxt).directory }).is_null() && directory.is_null() {
        directory = unsafe { xmlParserGetDirectory(filename) };
    }
    if (unsafe { (*ctxt).directory }).is_null() && !directory.is_null() {
        let fresh604 = unsafe { &mut ((*ctxt).directory) };
        *fresh604 = directory;
    }
    return ctxt;
}
#[no_mangle]
pub extern "C" fn xmlCreateFileParserCtxt(mut filename: *const i8) -> xmlParserCtxtPtr {
    return xmlCreateURLParserCtxt(filename, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlSAXParseFileWithData(
    mut sax: xmlSAXHandlerPtr,
    mut filename: *const i8,
    mut recovery: i32,
    mut data: *mut libc::c_void,
) -> xmlDocPtr {
    let mut ret: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateFileParserCtxt(filename);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        if !(unsafe { (*ctxt).sax }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void) });
        }
        let fresh605 = unsafe { &mut ((*ctxt).sax) };
        *fresh605 = sax;
    }
    xmlDetectSAX2(ctxt);
    if !data.is_null() {
        let fresh606 = unsafe { &mut ((*ctxt)._private) };
        *fresh606 = data;
    }
    if (unsafe { (*ctxt).directory }).is_null() {
        let fresh607 = unsafe { &mut ((*ctxt).directory) };
        *fresh607 = unsafe { xmlParserGetDirectory(filename) };
    }
    (unsafe { (*ctxt).recovery = recovery });
    xmlParseDocument(ctxt);
    if (unsafe { (*ctxt).wellFormed }) != 0 || recovery != 0 {
        ret = unsafe { (*ctxt).myDoc };
        if !ret.is_null() && !(unsafe { (*(*ctxt).input).buf }).is_null() {
            if (unsafe { (*(*(*ctxt).input).buf).compressed }) > 0 as i32 {
                (unsafe { (*ret).compression = 9 as i32 });
            } else {
                (unsafe { (*ret).compression = (*(*(*ctxt).input).buf).compressed });
            }
        }
    } else {
        ret = 0 as xmlDocPtr;
        (unsafe { xmlFreeDoc((*ctxt).myDoc) });
        let fresh608 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh608 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let fresh609 = unsafe { &mut ((*ctxt).sax) };
        *fresh609 = 0 as *mut _xmlSAXHandler;
    }
    (unsafe { xmlFreeParserCtxt(ctxt) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSAXParseFile(
    mut sax: xmlSAXHandlerPtr,
    mut filename: *const i8,
    mut recovery: i32,
) -> xmlDocPtr {
    return xmlSAXParseFileWithData(sax, filename, recovery, 0 as *mut libc::c_void);
}
#[no_mangle]
pub extern "C" fn xmlRecoverDoc(mut cur: *const xmlChar) -> xmlDocPtr {
    return xmlSAXParseDoc(0 as xmlSAXHandlerPtr, cur, 1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlParseFile(mut filename: *const i8) -> xmlDocPtr {
    return xmlSAXParseFile(0 as xmlSAXHandlerPtr, filename, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlRecoverFile(mut filename: *const i8) -> xmlDocPtr {
    return xmlSAXParseFile(0 as xmlSAXHandlerPtr, filename, 1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlSetupParserForBuffer(
    mut ctxt: xmlParserCtxtPtr,
    mut buffer: *const xmlChar,
    mut filename: *const i8,
) {
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ctxt.is_null() || buffer.is_null() {
        return;
    }
    input = unsafe { xmlNewInputStream(ctxt) };
    if input.is_null() {
        (unsafe { xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"parsing new buffer: out of memory\n\0" as *const u8 as *const i8,
        ) });
        (unsafe { xmlClearParserCtxt(ctxt) });
        return;
    }
    (unsafe { xmlClearParserCtxt(ctxt) });
    if !filename.is_null() {
        let fresh610 = unsafe { &mut ((*input).filename) };
        *fresh610 = (unsafe { xmlCanonicPath(filename as *const xmlChar) }) as *mut i8;
    }
    let fresh611 = unsafe { &mut ((*input).base) };
    *fresh611 = buffer;
    let fresh612 = unsafe { &mut ((*input).cur) };
    *fresh612 = buffer;
    let fresh613 = unsafe { &mut ((*input).end) };
    *fresh613 = (unsafe { &*buffer
        .offset((xmlStrlen as unsafe extern "C" fn(*const xmlChar) -> i32)(buffer) as isize) })
        as *const xmlChar;
    inputPush(ctxt, input);
}
#[no_mangle]
pub extern "C" fn xmlSAXUserParseFile(
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut filename: *const i8,
) -> i32 {
    let mut ret: i32 = 0 as i32;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    ctxt = xmlCreateFileParserCtxt(filename);
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).sax }) != (unsafe { __xmlDefaultSAXHandler() }) as xmlSAXHandlerPtr {
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void) });
    }
    let fresh614 = unsafe { &mut ((*ctxt).sax) };
    *fresh614 = sax;
    xmlDetectSAX2(ctxt);
    if !user_data.is_null() {
        let fresh615 = unsafe { &mut ((*ctxt).userData) };
        *fresh615 = user_data;
    }
    xmlParseDocument(ctxt);
    if (unsafe { (*ctxt).wellFormed }) != 0 {
        ret = 0 as i32;
    } else if (unsafe { (*ctxt).errNo }) != 0 as i32 {
        ret = unsafe { (*ctxt).errNo };
    } else {
        ret = -(1 as i32);
    }
    if !sax.is_null() {
        let fresh616 = unsafe { &mut ((*ctxt).sax) };
        *fresh616 = 0 as *mut _xmlSAXHandler;
    }
    if !(unsafe { (*ctxt).myDoc }).is_null() {
        (unsafe { xmlFreeDoc((*ctxt).myDoc) });
        let fresh617 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh617 = 0 as xmlDocPtr;
    }
    (unsafe { xmlFreeParserCtxt(ctxt) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCreateMemoryParserCtxt(
    mut buffer: *const i8,
    mut size: i32,
) -> xmlParserCtxtPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if buffer.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    if size <= 0 as i32 {
        return 0 as xmlParserCtxtPtr;
    }
    ctxt = unsafe { xmlNewParserCtxt() };
    if ctxt.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    buf = unsafe { xmlParserInputBufferCreateMem(buffer, size, XML_CHAR_ENCODING_NONE) };
    if buf.is_null() {
        (unsafe { xmlFreeParserCtxt(ctxt) });
        return 0 as xmlParserCtxtPtr;
    }
    input = unsafe { xmlNewInputStream(ctxt) };
    if input.is_null() {
        (unsafe { xmlFreeParserInputBuffer(buf) });
        (unsafe { xmlFreeParserCtxt(ctxt) });
        return 0 as xmlParserCtxtPtr;
    }
    let fresh618 = unsafe { &mut ((*input).filename) };
    *fresh618 = 0 as *const i8;
    let fresh619 = unsafe { &mut ((*input).buf) };
    *fresh619 = buf;
    (unsafe { xmlBufResetInput((*(*input).buf).buffer, input) });
    inputPush(ctxt, input);
    return ctxt;
}
#[no_mangle]
pub extern "C" fn xmlSAXParseMemoryWithData(
    mut sax: xmlSAXHandlerPtr,
    mut buffer: *const i8,
    mut size: i32,
    mut recovery: i32,
    mut data: *mut libc::c_void,
) -> xmlDocPtr {
    let mut ret: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        if !(unsafe { (*ctxt).sax }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void) });
        }
        let fresh620 = unsafe { &mut ((*ctxt).sax) };
        *fresh620 = sax;
    }
    xmlDetectSAX2(ctxt);
    if !data.is_null() {
        let fresh621 = unsafe { &mut ((*ctxt)._private) };
        *fresh621 = data;
    }
    (unsafe { (*ctxt).recovery = recovery });
    xmlParseDocument(ctxt);
    if (unsafe { (*ctxt).wellFormed }) != 0 || recovery != 0 {
        ret = unsafe { (*ctxt).myDoc };
    } else {
        ret = 0 as xmlDocPtr;
        (unsafe { xmlFreeDoc((*ctxt).myDoc) });
        let fresh622 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh622 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let fresh623 = unsafe { &mut ((*ctxt).sax) };
        *fresh623 = 0 as *mut _xmlSAXHandler;
    }
    (unsafe { xmlFreeParserCtxt(ctxt) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSAXParseMemory(
    mut sax: xmlSAXHandlerPtr,
    mut buffer: *const i8,
    mut size: i32,
    mut recovery: i32,
) -> xmlDocPtr {
    return xmlSAXParseMemoryWithData(sax, buffer, size, recovery, 0 as *mut libc::c_void);
}
#[no_mangle]
pub extern "C" fn xmlParseMemory(mut buffer: *const i8, mut size: i32) -> xmlDocPtr {
    return xmlSAXParseMemory(0 as xmlSAXHandlerPtr, buffer, size, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlRecoverMemory(mut buffer: *const i8, mut size: i32) -> xmlDocPtr {
    return xmlSAXParseMemory(0 as xmlSAXHandlerPtr, buffer, size, 1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlSAXUserParseMemory(
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut buffer: *const i8,
    mut size: i32,
) -> i32 {
    let mut ret: i32 = 0 as i32;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*ctxt).sax }) != (unsafe { __xmlDefaultSAXHandler() }) as xmlSAXHandlerPtr {
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void) });
    }
    let fresh624 = unsafe { &mut ((*ctxt).sax) };
    *fresh624 = sax;
    xmlDetectSAX2(ctxt);
    if !user_data.is_null() {
        let fresh625 = unsafe { &mut ((*ctxt).userData) };
        *fresh625 = user_data;
    }
    xmlParseDocument(ctxt);
    if (unsafe { (*ctxt).wellFormed }) != 0 {
        ret = 0 as i32;
    } else if (unsafe { (*ctxt).errNo }) != 0 as i32 {
        ret = unsafe { (*ctxt).errNo };
    } else {
        ret = -(1 as i32);
    }
    if !sax.is_null() {
        let fresh626 = unsafe { &mut ((*ctxt).sax) };
        *fresh626 = 0 as *mut _xmlSAXHandler;
    }
    if !(unsafe { (*ctxt).myDoc }).is_null() {
        (unsafe { xmlFreeDoc((*ctxt).myDoc) });
        let fresh627 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh627 = 0 as xmlDocPtr;
    }
    (unsafe { xmlFreeParserCtxt(ctxt) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCreateDocParserCtxt(mut cur: *const xmlChar) -> xmlParserCtxtPtr {
    let mut len: i32 = 0;
    if cur.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    len = unsafe { xmlStrlen(cur) };
    return xmlCreateMemoryParserCtxt(cur as *const i8, len);
}
#[no_mangle]
pub extern "C" fn xmlSAXParseDoc(
    mut sax: xmlSAXHandlerPtr,
    mut cur: *const xmlChar,
    mut recovery: i32,
) -> xmlDocPtr {
    let mut ret: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut oldsax: xmlSAXHandlerPtr = 0 as xmlSAXHandlerPtr;
    if cur.is_null() {
        return 0 as xmlDocPtr;
    }
    ctxt = xmlCreateDocParserCtxt(cur);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        oldsax = unsafe { (*ctxt).sax };
        let fresh628 = unsafe { &mut ((*ctxt).sax) };
        *fresh628 = sax;
        let fresh629 = unsafe { &mut ((*ctxt).userData) };
        *fresh629 = 0 as *mut libc::c_void;
    }
    xmlDetectSAX2(ctxt);
    xmlParseDocument(ctxt);
    if (unsafe { (*ctxt).wellFormed }) != 0 || recovery != 0 {
        ret = unsafe { (*ctxt).myDoc };
    } else {
        ret = 0 as xmlDocPtr;
        (unsafe { xmlFreeDoc((*ctxt).myDoc) });
        let fresh630 = unsafe { &mut ((*ctxt).myDoc) };
        *fresh630 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let fresh631 = unsafe { &mut ((*ctxt).sax) };
        *fresh631 = oldsax;
    }
    (unsafe { xmlFreeParserCtxt(ctxt) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlParseDoc(mut cur: *const xmlChar) -> xmlDocPtr {
    return xmlSAXParseDoc(0 as xmlSAXHandlerPtr, cur, 0 as i32);
}
static mut xmlEntityRefFunc: xmlEntityReferenceFunc = None;
extern "C" fn xmlAddEntityReference(
    mut ent: xmlEntityPtr,
    mut firstNode: xmlNodePtr,
    mut lastNode: xmlNodePtr,
) {
    if unsafe { xmlEntityRefFunc.is_some() } {
        (unsafe { (Some(xmlEntityRefFunc.expect("non-null function pointer")))
            .expect("non-null function pointer")(ent, firstNode, lastNode) });
    }
}
#[no_mangle]
pub extern "C" fn xmlSetEntityReferenceFunc(mut func: xmlEntityReferenceFunc) {
    (unsafe { xmlEntityRefFunc = func });
}
static mut xmlParserInitialized: i32 = 0 as i32;
#[no_mangle]
pub extern "C" fn xmlInitParser() {
    if (unsafe { xmlParserInitialized }) != 0 as i32 {
        return;
    }
    (unsafe { __xmlGlobalInitMutexLock() });
    if (unsafe { xmlParserInitialized }) == 0 as i32 {
        (unsafe { xmlInitThreads() });
        (unsafe { xmlInitGlobals() });
        if (unsafe { *__xmlGenericError() })
            == Some(
                xmlGenericErrorDefaultFunc
                    as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
            )
            || (unsafe { (*__xmlGenericError()).is_none() })
        {
            (unsafe { initGenericErrorDefaultFunc(0 as *mut xmlGenericErrorFunc) });
        }
        (unsafe { xmlInitMemory() });
        (unsafe { xmlInitializeDict() });
        (unsafe { xmlInitCharEncodingHandlers() });
        (unsafe { xmlDefaultSAXHandlerInit() });
        (unsafe { xmlRegisterDefaultInputCallbacks() });
        (unsafe { xmlRegisterDefaultOutputCallbacks() });
        (unsafe { htmlInitAutoClose() });
        (unsafe { htmlDefaultSAXHandlerInit() });
        (unsafe { xmlXPathInit() });
        (unsafe { xmlParserInitialized = 1 as i32 });
    }
    (unsafe { __xmlGlobalInitMutexUnlock() });
}
#[no_mangle]
pub extern "C" fn xmlCleanupParser() {
    if (unsafe { xmlParserInitialized }) == 0 {
        return;
    }
    (unsafe { xmlCleanupCharEncodingHandlers() });
    (unsafe { xmlCatalogCleanup() });
    (unsafe { xmlDictCleanup() });
    (unsafe { xmlCleanupInputCallbacks() });
    (unsafe { xmlCleanupOutputCallbacks() });
    (unsafe { xmlSchemaCleanupTypes() });
    (unsafe { xmlRelaxNGCleanupTypes() });
    (unsafe { xmlCleanupGlobals() });
    (unsafe { xmlCleanupThreads() });
    (unsafe { xmlCleanupMemory() });
    (unsafe { xmlParserInitialized = 0 as i32 });
}
#[no_mangle]
pub extern "C" fn xmlCtxtReset(mut ctxt: xmlParserCtxtPtr) {
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut dict: xmlDictPtr = 0 as *mut xmlDict;
    if ctxt.is_null() {
        return;
    }
    dict = unsafe { (*ctxt).dict };
    loop {
        input = inputPop(ctxt);
        if input.is_null() {
            break;
        }
        (unsafe { xmlFreeInputStream(input) });
    }
    (unsafe { (*ctxt).inputNr = 0 as i32 });
    let fresh632 = unsafe { &mut ((*ctxt).input) };
    *fresh632 = 0 as xmlParserInputPtr;
    (unsafe { (*ctxt).spaceNr = 0 as i32 });
    if !(unsafe { (*ctxt).spaceTab }).is_null() {
        (unsafe { *((*ctxt).spaceTab).offset(0 as i32 as isize) = -(1 as i32) });
        let fresh633 = unsafe { &mut ((*ctxt).space) };
        *fresh633 = (unsafe { &mut *((*ctxt).spaceTab).offset(0 as i32 as isize) }) as *mut i32;
    } else {
        let fresh634 = unsafe { &mut ((*ctxt).space) };
        *fresh634 = 0 as *mut i32;
    }
    (unsafe { (*ctxt).nodeNr = 0 as i32 });
    let fresh635 = unsafe { &mut ((*ctxt).node) };
    *fresh635 = 0 as xmlNodePtr;
    (unsafe { (*ctxt).nameNr = 0 as i32 });
    let fresh636 = unsafe { &mut ((*ctxt).name) };
    *fresh636 = 0 as *const xmlChar;
    (unsafe { (*ctxt).nsNr = 0 as i32 });
    if !(unsafe { (*ctxt).version }).is_null()
        && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*ctxt).version) }) == 0 as i32)
    {
        (unsafe { xmlFree.expect("non-null function pointer")(
            (*ctxt).version as *mut i8 as *mut libc::c_void,
        ) });
    }
    let fresh637 = unsafe { &mut ((*ctxt).version) };
    *fresh637 = 0 as *const xmlChar;
    if !(unsafe { (*ctxt).encoding }).is_null()
        && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*ctxt).encoding) }) == 0 as i32)
    {
        (unsafe { xmlFree.expect("non-null function pointer")(
            (*ctxt).encoding as *mut i8 as *mut libc::c_void,
        ) });
    }
    let fresh638 = unsafe { &mut ((*ctxt).encoding) };
    *fresh638 = 0 as *const xmlChar;
    if !(unsafe { (*ctxt).directory }).is_null()
        && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*ctxt).directory as *const xmlChar) }) == 0 as i32)
    {
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).directory as *mut libc::c_void) });
    }
    let fresh639 = unsafe { &mut ((*ctxt).directory) };
    *fresh639 = 0 as *mut i8;
    if !(unsafe { (*ctxt).extSubURI }).is_null()
        && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*ctxt).extSubURI as *const xmlChar) }) == 0 as i32)
    {
        (unsafe { xmlFree.expect("non-null function pointer")(
            (*ctxt).extSubURI as *mut i8 as *mut libc::c_void,
        ) });
    }
    let fresh640 = unsafe { &mut ((*ctxt).extSubURI) };
    *fresh640 = 0 as *mut xmlChar;
    if !(unsafe { (*ctxt).extSubSystem }).is_null()
        && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*ctxt).extSubSystem as *const xmlChar) }) == 0 as i32)
    {
        (unsafe { xmlFree.expect("non-null function pointer")(
            (*ctxt).extSubSystem as *mut i8 as *mut libc::c_void,
        ) });
    }
    let fresh641 = unsafe { &mut ((*ctxt).extSubSystem) };
    *fresh641 = 0 as *mut xmlChar;
    if !(unsafe { (*ctxt).myDoc }).is_null() {
        (unsafe { xmlFreeDoc((*ctxt).myDoc) });
    }
    let fresh642 = unsafe { &mut ((*ctxt).myDoc) };
    *fresh642 = 0 as xmlDocPtr;
    (unsafe { (*ctxt).standalone = -(1 as i32) });
    (unsafe { (*ctxt).hasExternalSubset = 0 as i32 });
    (unsafe { (*ctxt).hasPErefs = 0 as i32 });
    (unsafe { (*ctxt).html = 0 as i32 });
    (unsafe { (*ctxt).external = 0 as i32 });
    (unsafe { (*ctxt).instate = XML_PARSER_START });
    (unsafe { (*ctxt).token = 0 as i32 });
    (unsafe { (*ctxt).wellFormed = 1 as i32 });
    (unsafe { (*ctxt).nsWellFormed = 1 as i32 });
    (unsafe { (*ctxt).disableSAX = 0 as i32 });
    (unsafe { (*ctxt).valid = 1 as i32 });
    (unsafe { (*ctxt).record_info = 0 as i32 });
    (unsafe { (*ctxt).checkIndex = 0 as i32 as i64 });
    (unsafe { (*ctxt).inSubset = 0 as i32 });
    (unsafe { (*ctxt).errNo = XML_ERR_OK as i32 });
    (unsafe { (*ctxt).depth = 0 as i32 });
    (unsafe { (*ctxt).charset = XML_CHAR_ENCODING_UTF8 as i32 });
    let fresh643 = unsafe { &mut ((*ctxt).catalogs) };
    *fresh643 = 0 as *mut libc::c_void;
    (unsafe { (*ctxt).nbentities = 0 as i32 as u64 });
    (unsafe { (*ctxt).sizeentities = 0 as i32 as u64 });
    (unsafe { (*ctxt).sizeentcopy = 0 as i32 as u64 });
    (unsafe { xmlInitNodeInfoSeq(&mut (*ctxt).node_seq) });
    if !(unsafe { (*ctxt).attsDefault }).is_null() {
        (unsafe { xmlHashFree(
            (*ctxt).attsDefault,
            Some(
                xmlHashDefaultDeallocator
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
        ) });
        let fresh644 = unsafe { &mut ((*ctxt).attsDefault) };
        *fresh644 = 0 as xmlHashTablePtr;
    }
    if !(unsafe { (*ctxt).attsSpecial }).is_null() {
        (unsafe { xmlHashFree((*ctxt).attsSpecial, None) });
        let fresh645 = unsafe { &mut ((*ctxt).attsSpecial) };
        *fresh645 = 0 as xmlHashTablePtr;
    }
    if !(unsafe { (*ctxt).catalogs }).is_null() {
        (unsafe { xmlCatalogFreeLocal((*ctxt).catalogs) });
    }
    if (unsafe { (*ctxt).lastError.code }) != XML_ERR_OK as i32 {
        (unsafe { xmlResetError(&mut (*ctxt).lastError) });
    }
}
#[no_mangle]
pub extern "C" fn xmlCtxtResetPush(
    mut ctxt: xmlParserCtxtPtr,
    mut chunk: *const i8,
    mut size: i32,
    mut filename: *const i8,
    mut encoding: *const i8,
) -> i32 {
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    if ctxt.is_null() {
        return 1 as i32;
    }
    if encoding.is_null() && !chunk.is_null() && size >= 4 as i32 {
        enc = unsafe { xmlDetectCharEncoding(chunk as *const xmlChar, size) };
    }
    buf = unsafe { xmlAllocParserInputBuffer(enc) };
    if buf.is_null() {
        return 1 as i32;
    }
    if ctxt.is_null() {
        (unsafe { xmlFreeParserInputBuffer(buf) });
        return 1 as i32;
    }
    xmlCtxtReset(ctxt);
    if filename.is_null() {
        let fresh646 = unsafe { &mut ((*ctxt).directory) };
        *fresh646 = 0 as *mut i8;
    } else {
        let fresh647 = unsafe { &mut ((*ctxt).directory) };
        *fresh647 = unsafe { xmlParserGetDirectory(filename) };
    }
    inputStream = unsafe { xmlNewInputStream(ctxt) };
    if inputStream.is_null() {
        (unsafe { xmlFreeParserInputBuffer(buf) });
        return 1 as i32;
    }
    if filename.is_null() {
        let fresh648 = unsafe { &mut ((*inputStream).filename) };
        *fresh648 = 0 as *const i8;
    } else {
        let fresh649 = unsafe { &mut ((*inputStream).filename) };
        *fresh649 = (unsafe { xmlCanonicPath(filename as *const xmlChar) }) as *mut i8;
    }
    let fresh650 = unsafe { &mut ((*inputStream).buf) };
    *fresh650 = buf;
    (unsafe { xmlBufResetInput((*buf).buffer, inputStream) });
    inputPush(ctxt, inputStream);
    if size > 0 as i32
        && !chunk.is_null()
        && !(unsafe { (*ctxt).input }).is_null()
        && !(unsafe { (*(*ctxt).input).buf }).is_null()
    {
        let mut base: size_t = unsafe { xmlBufGetInputBase((*(*(*ctxt).input).buf).buffer, (*ctxt).input) };
        let mut cur: size_t =
            (unsafe { ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) }) as i64 as size_t;
        (unsafe { xmlParserInputBufferPush((*(*ctxt).input).buf, size, chunk) });
        (unsafe { xmlBufSetInputBaseCur((*(*(*ctxt).input).buf).buffer, (*ctxt).input, base, cur) });
    }
    if !encoding.is_null() {
        let mut hdlr: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
        if !(unsafe { (*ctxt).encoding }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(
                (*ctxt).encoding as *mut xmlChar as *mut libc::c_void,
            ) });
        }
        let fresh651 = unsafe { &mut ((*ctxt).encoding) };
        *fresh651 = unsafe { xmlStrdup(encoding as *const xmlChar) };
        hdlr = unsafe { xmlFindCharEncodingHandler(encoding) };
        if !hdlr.is_null() {
            (unsafe { xmlSwitchToEncoding(ctxt, hdlr) });
        } else {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNSUPPORTED_ENCODING,
                b"Unsupported encoding %s\n\0" as *const u8 as *const i8,
                encoding as *mut xmlChar,
            );
        }
    } else if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
        (unsafe { xmlSwitchEncoding(ctxt, enc) });
    }
    return 0 as i32;
}
extern "C" fn xmlCtxtUseOptionsInternal(
    mut ctxt: xmlParserCtxtPtr,
    mut options: i32,
    mut encoding: *const i8,
) -> i32 {
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if !encoding.is_null() {
        if !(unsafe { (*ctxt).encoding }).is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(
                (*ctxt).encoding as *mut xmlChar as *mut libc::c_void,
            ) });
        }
        let fresh652 = unsafe { &mut ((*ctxt).encoding) };
        *fresh652 = unsafe { xmlStrdup(encoding as *const xmlChar) };
    }
    if options & XML_PARSE_RECOVER as i32 != 0 {
        (unsafe { (*ctxt).recovery = 1 as i32 });
        options -= XML_PARSE_RECOVER as i32;
        (unsafe { (*ctxt).options |= XML_PARSE_RECOVER as i32 });
    } else {
        (unsafe { (*ctxt).recovery = 0 as i32 });
    }
    if options & XML_PARSE_DTDLOAD as i32 != 0 {
        (unsafe { (*ctxt).loadsubset = 2 as i32 });
        options -= XML_PARSE_DTDLOAD as i32;
        (unsafe { (*ctxt).options |= XML_PARSE_DTDLOAD as i32 });
    } else {
        (unsafe { (*ctxt).loadsubset = 0 as i32 });
    }
    if options & XML_PARSE_DTDATTR as i32 != 0 {
        (unsafe { (*ctxt).loadsubset |= 4 as i32 });
        options -= XML_PARSE_DTDATTR as i32;
        (unsafe { (*ctxt).options |= XML_PARSE_DTDATTR as i32 });
    }
    if options & XML_PARSE_NOENT as i32 != 0 {
        (unsafe { (*ctxt).replaceEntities = 1 as i32 });
        options -= XML_PARSE_NOENT as i32;
        (unsafe { (*ctxt).options |= XML_PARSE_NOENT as i32 });
    } else {
        (unsafe { (*ctxt).replaceEntities = 0 as i32 });
    }
    if options & XML_PARSE_PEDANTIC as i32 != 0 {
        (unsafe { (*ctxt).pedantic = 1 as i32 });
        options -= XML_PARSE_PEDANTIC as i32;
        (unsafe { (*ctxt).options |= XML_PARSE_PEDANTIC as i32 });
    } else {
        (unsafe { (*ctxt).pedantic = 0 as i32 });
    }
    if options & XML_PARSE_NOBLANKS as i32 != 0 {
        (unsafe { (*ctxt).keepBlanks = 0 as i32 });
        let fresh653 = unsafe { &mut ((*(*ctxt).sax).ignorableWhitespace) };
        *fresh653 = Some(
            xmlSAX2IgnorableWhitespace
                as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
        );
        options -= XML_PARSE_NOBLANKS as i32;
        (unsafe { (*ctxt).options |= XML_PARSE_NOBLANKS as i32 });
    } else {
        (unsafe { (*ctxt).keepBlanks = 1 as i32 });
    }
    if options & XML_PARSE_DTDVALID as i32 != 0 {
        (unsafe { (*ctxt).validate = 1 as i32 });
        if options & XML_PARSE_NOWARNING as i32 != 0 {
            let fresh654 = unsafe { &mut ((*ctxt).vctxt.warning) };
            *fresh654 = None;
        }
        if options & XML_PARSE_NOERROR as i32 != 0 {
            let fresh655 = unsafe { &mut ((*ctxt).vctxt.error) };
            *fresh655 = None;
        }
        options -= XML_PARSE_DTDVALID as i32;
        (unsafe { (*ctxt).options |= XML_PARSE_DTDVALID as i32 });
    } else {
        (unsafe { (*ctxt).validate = 0 as i32 });
    }
    if options & XML_PARSE_NOWARNING as i32 != 0 {
        let fresh656 = unsafe { &mut ((*(*ctxt).sax).warning) };
        *fresh656 = None;
        options -= XML_PARSE_NOWARNING as i32;
    }
    if options & XML_PARSE_NOERROR as i32 != 0 {
        let fresh657 = unsafe { &mut ((*(*ctxt).sax).error) };
        *fresh657 = None;
        let fresh658 = unsafe { &mut ((*(*ctxt).sax).fatalError) };
        *fresh658 = None;
        options -= XML_PARSE_NOERROR as i32;
    }
    if options & XML_PARSE_SAX1 as i32 != 0 {
        let fresh659 = unsafe { &mut ((*(*ctxt).sax).startElement) };
        *fresh659 = Some(
            xmlSAX2StartElement
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const xmlChar,
                    *mut *const xmlChar,
                ) -> (),
        );
        let fresh660 = unsafe { &mut ((*(*ctxt).sax).endElement) };
        *fresh660 = Some(
            xmlSAX2EndElement as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        );
        let fresh661 = unsafe { &mut ((*(*ctxt).sax).startElementNs) };
        *fresh661 = None;
        let fresh662 = unsafe { &mut ((*(*ctxt).sax).endElementNs) };
        *fresh662 = None;
        (unsafe { (*(*ctxt).sax).initialized = 1 as i32 as u32 });
        options -= XML_PARSE_SAX1 as i32;
        (unsafe { (*ctxt).options |= XML_PARSE_SAX1 as i32 });
    }
    if options & XML_PARSE_NODICT as i32 != 0 {
        (unsafe { (*ctxt).dictNames = 0 as i32 });
        options -= XML_PARSE_NODICT as i32;
        (unsafe { (*ctxt).options |= XML_PARSE_NODICT as i32 });
    } else {
        (unsafe { (*ctxt).dictNames = 1 as i32 });
    }
    if options & XML_PARSE_NOCDATA as i32 != 0 {
        let fresh663 = unsafe { &mut ((*(*ctxt).sax).cdataBlock) };
        *fresh663 = None;
        options -= XML_PARSE_NOCDATA as i32;
        (unsafe { (*ctxt).options |= XML_PARSE_NOCDATA as i32 });
    }
    if options & XML_PARSE_NSCLEAN as i32 != 0 {
        (unsafe { (*ctxt).options |= XML_PARSE_NSCLEAN as i32 });
        options -= XML_PARSE_NSCLEAN as i32;
    }
    if options & XML_PARSE_NONET as i32 != 0 {
        (unsafe { (*ctxt).options |= XML_PARSE_NONET as i32 });
        options -= XML_PARSE_NONET as i32;
    }
    if options & XML_PARSE_COMPACT as i32 != 0 {
        (unsafe { (*ctxt).options |= XML_PARSE_COMPACT as i32 });
        options -= XML_PARSE_COMPACT as i32;
    }
    if options & XML_PARSE_OLD10 as i32 != 0 {
        (unsafe { (*ctxt).options |= XML_PARSE_OLD10 as i32 });
        options -= XML_PARSE_OLD10 as i32;
    }
    if options & XML_PARSE_NOBASEFIX as i32 != 0 {
        (unsafe { (*ctxt).options |= XML_PARSE_NOBASEFIX as i32 });
        options -= XML_PARSE_NOBASEFIX as i32;
    }
    if options & XML_PARSE_HUGE as i32 != 0 {
        (unsafe { (*ctxt).options |= XML_PARSE_HUGE as i32 });
        options -= XML_PARSE_HUGE as i32;
        if !(unsafe { (*ctxt).dict }).is_null() {
            (unsafe { xmlDictSetLimit((*ctxt).dict, 0 as i32 as size_t) });
        }
    }
    if options & XML_PARSE_OLDSAX as i32 != 0 {
        (unsafe { (*ctxt).options |= XML_PARSE_OLDSAX as i32 });
        options -= XML_PARSE_OLDSAX as i32;
    }
    if options & XML_PARSE_IGNORE_ENC as i32 != 0 {
        (unsafe { (*ctxt).options |= XML_PARSE_IGNORE_ENC as i32 });
        options -= XML_PARSE_IGNORE_ENC as i32;
    }
    if options & XML_PARSE_BIG_LINES as i32 != 0 {
        (unsafe { (*ctxt).options |= XML_PARSE_BIG_LINES as i32 });
        options -= XML_PARSE_BIG_LINES as i32;
    }
    (unsafe { (*ctxt).linenumbers = 1 as i32 });
    return options;
}
#[no_mangle]
pub extern "C" fn xmlCtxtUseOptions(mut ctxt: xmlParserCtxtPtr, mut options: i32) -> i32 {
    return xmlCtxtUseOptionsInternal(ctxt, options, 0 as *const i8);
}
extern "C" fn xmlDoRead(
    mut ctxt: xmlParserCtxtPtr,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
    mut reuse: i32,
) -> xmlDocPtr {
    let mut ret: xmlDocPtr = 0 as *mut xmlDoc;
    xmlCtxtUseOptionsInternal(ctxt, options, encoding);
    if !encoding.is_null() {
        let mut hdlr: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
        hdlr = unsafe { xmlFindCharEncodingHandler(encoding) };
        if !hdlr.is_null() {
            (unsafe { xmlSwitchToEncoding(ctxt, hdlr) });
        }
    }
    if !URL.is_null() && !(unsafe { (*ctxt).input }).is_null() && (unsafe { (*(*ctxt).input).filename }).is_null() {
        let fresh664 = unsafe { &mut ((*(*ctxt).input).filename) };
        *fresh664 = (unsafe { xmlStrdup(URL as *const xmlChar) }) as *mut i8;
    }
    xmlParseDocument(ctxt);
    if (unsafe { (*ctxt).wellFormed }) != 0 || (unsafe { (*ctxt).recovery }) != 0 {
        ret = unsafe { (*ctxt).myDoc };
    } else {
        ret = 0 as xmlDocPtr;
        if !(unsafe { (*ctxt).myDoc }).is_null() {
            (unsafe { xmlFreeDoc((*ctxt).myDoc) });
        }
    }
    let fresh665 = unsafe { &mut ((*ctxt).myDoc) };
    *fresh665 = 0 as xmlDocPtr;
    if reuse == 0 {
        (unsafe { xmlFreeParserCtxt(ctxt) });
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlReadDoc(
    mut cur: *const xmlChar,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlDocPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
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
pub extern "C" fn xmlReadFile(
    mut filename: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlDocPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateURLParserCtxt(filename, options);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    return xmlDoRead(ctxt, 0 as *const i8, encoding, options, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlReadMemory(
    mut buffer: *const i8,
    mut size: i32,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlDocPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    return xmlDoRead(ctxt, URL, encoding, options, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlReadFd(
    mut fd: i32,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlDocPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if fd < 0 as i32 {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    input = unsafe { xmlParserInputBufferCreateFd(fd, XML_CHAR_ENCODING_NONE) };
    if input.is_null() {
        return 0 as xmlDocPtr;
    }
    let fresh666 = unsafe { &mut ((*input).closecallback) };
    *fresh666 = None;
    ctxt = unsafe { xmlNewParserCtxt() };
    if ctxt.is_null() {
        (unsafe { xmlFreeParserInputBuffer(input) });
        return 0 as xmlDocPtr;
    }
    stream = unsafe { xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE) };
    if stream.is_null() {
        (unsafe { xmlFreeParserInputBuffer(input) });
        (unsafe { xmlFreeParserCtxt(ctxt) });
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlReadIO(
    mut ioread: xmlInputReadCallback,
    mut ioclose: xmlInputCloseCallback,
    mut ioctx: *mut libc::c_void,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlDocPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ioread.is_none() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    input = unsafe { xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, XML_CHAR_ENCODING_NONE) };
    if input.is_null() {
        if ioclose.is_some() {
            (unsafe { ioclose.expect("non-null function pointer")(ioctx) });
        }
        return 0 as xmlDocPtr;
    }
    ctxt = unsafe { xmlNewParserCtxt() };
    if ctxt.is_null() {
        (unsafe { xmlFreeParserInputBuffer(input) });
        return 0 as xmlDocPtr;
    }
    stream = unsafe { xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE) };
    if stream.is_null() {
        (unsafe { xmlFreeParserInputBuffer(input) });
        (unsafe { xmlFreeParserCtxt(ctxt) });
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlCtxtReadDoc(
    mut ctxt: xmlParserCtxtPtr,
    mut cur: *const xmlChar,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlDocPtr {
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if cur.is_null() {
        return 0 as xmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    stream = unsafe { xmlNewStringInputStream(ctxt, cur) };
    if stream.is_null() {
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlCtxtReadFile(
    mut ctxt: xmlParserCtxtPtr,
    mut filename: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlDocPtr {
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if filename.is_null() {
        return 0 as xmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    stream = unsafe { xmlLoadExternalEntity(filename, 0 as *const i8, ctxt) };
    if stream.is_null() {
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, 0 as *const i8, encoding, options, 1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlCtxtReadMemory(
    mut ctxt: xmlParserCtxtPtr,
    mut buffer: *const i8,
    mut size: i32,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlDocPtr {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if buffer.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    input = unsafe { xmlParserInputBufferCreateMem(buffer, size, XML_CHAR_ENCODING_NONE) };
    if input.is_null() {
        return 0 as xmlDocPtr;
    }
    stream = unsafe { xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE) };
    if stream.is_null() {
        (unsafe { xmlFreeParserInputBuffer(input) });
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlCtxtReadFd(
    mut ctxt: xmlParserCtxtPtr,
    mut fd: i32,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlDocPtr {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if fd < 0 as i32 {
        return 0 as xmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    input = unsafe { xmlParserInputBufferCreateFd(fd, XML_CHAR_ENCODING_NONE) };
    if input.is_null() {
        return 0 as xmlDocPtr;
    }
    let fresh667 = unsafe { &mut ((*input).closecallback) };
    *fresh667 = None;
    stream = unsafe { xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE) };
    if stream.is_null() {
        (unsafe { xmlFreeParserInputBuffer(input) });
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlCtxtReadIO(
    mut ctxt: xmlParserCtxtPtr,
    mut ioread: xmlInputReadCallback,
    mut ioclose: xmlInputCloseCallback,
    mut ioctx: *mut libc::c_void,
    mut URL: *const i8,
    mut encoding: *const i8,
    mut options: i32,
) -> xmlDocPtr {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ioread.is_none() {
        return 0 as xmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    input = unsafe { xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, XML_CHAR_ENCODING_NONE) };
    if input.is_null() {
        if ioclose.is_some() {
            (unsafe { ioclose.expect("non-null function pointer")(ioctx) });
        }
        return 0 as xmlDocPtr;
    }
    stream = unsafe { xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE) };
    if stream.is_null() {
        (unsafe { xmlFreeParserInputBuffer(input) });
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 1 as i32);
}
