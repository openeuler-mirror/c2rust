use ::libc;
extern "C" {
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlStartTag;
    pub type _xmlBuf;
    pub type _xmlAutomataState;
    pub type _xmlAutomata;
    pub type _xmlValidState;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn xmlStrlen(str: *const xmlChar) -> libc::c_int;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> libc::c_int;
    fn xmlStrncasecmp(
        str1: *const xmlChar,
        str2: *const xmlChar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn xmlStrcasecmp(str1: *const xmlChar, str2: *const xmlChar) -> libc::c_int;
    fn xmlStrcmp(str1: *const xmlChar, str2: *const xmlChar) -> libc::c_int;
    fn xmlStrcasestr(str: *const xmlChar, val: *const xmlChar) -> *const xmlChar;
    fn xmlStrndup(cur: *const xmlChar, len: libc::c_int) -> *mut xmlChar;
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    static mut __xmlRegisterCallbacks: libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strcat(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn __ctype_toupper_loc() -> *mut *const __int32_t;
    fn xmlAllocParserInputBuffer(enc: xmlCharEncoding) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferCreateFd(
        fd: libc::c_int,
        enc: xmlCharEncoding,
    ) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferCreateMem(
        mem: *const libc::c_char,
        size: libc::c_int,
        enc: xmlCharEncoding,
    ) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferCreateIO(
        ioread: xmlInputReadCallback,
        ioclose: xmlInputCloseCallback,
        ioctx: *mut libc::c_void,
        enc: xmlCharEncoding,
    ) -> xmlParserInputBufferPtr;
    fn __xmlRegisterNodeDefaultValue() -> *mut xmlRegisterNodeFunc;
    static mut xmlMallocAtomic: xmlMallocFunc;
    static mut xmlMalloc: xmlMallocFunc;
    fn xmlParseCharEncoding(name: *const libc::c_char) -> xmlCharEncoding;
    fn xmlBufShrink(buf: xmlBufPtr, len: size_t) -> size_t;
    fn __xmlLineNumbersDefaultValue() -> *mut libc::c_int;
    fn __xmlKeepBlanksDefaultValue() -> *mut libc::c_int;
    fn __xmlDefaultSAXLocator() -> *mut xmlSAXLocator;
    fn __xmlDefaultSAXHandler() -> *mut xmlSAXHandlerV1;
    fn __htmlDefaultSAXHandler() -> *mut xmlSAXHandlerV1;
    fn htmlDefaultSAXHandlerInit();
    fn xmlSAX2IgnorableWhitespace(
        ctx: *mut libc::c_void,
        ch: *const xmlChar,
        len: libc::c_int,
    );
    fn xmlParserAddNodeInfo(ctxt: xmlParserCtxtPtr, info: xmlParserNodeInfoPtr);
    fn xmlLoadExternalEntity(
        URL: *const libc::c_char,
        ID: *const libc::c_char,
        ctxt: xmlParserCtxtPtr,
    ) -> xmlParserInputPtr;
    fn xmlInitNodeInfoSeq(seq: xmlParserNodeInfoSeqPtr);
    fn xmlNewIOInputStream(
        ctxt: xmlParserCtxtPtr,
        input: xmlParserInputBufferPtr,
        enc: xmlCharEncoding,
    ) -> xmlParserInputPtr;
    fn xmlFreeParserCtxt(ctxt: xmlParserCtxtPtr);
    fn xmlDictLookup(
        dict: xmlDictPtr,
        name: *const xmlChar,
        len: libc::c_int,
    ) -> *const xmlChar;
    fn xmlFindCharEncodingHandler(
        name: *const libc::c_char,
    ) -> xmlCharEncodingHandlerPtr;
    fn xmlInitParser();
    fn xmlGetIntSubset(doc: *const xmlDoc) -> xmlDtdPtr;
    fn xmlGetLastChild(parent: *const xmlNode) -> xmlNodePtr;
    fn xmlNodeIsText(node: *const xmlNode) -> libc::c_int;
    static mut xmlRealloc: xmlReallocFunc;
    fn __xmlRaiseError(
        schannel: xmlStructuredErrorFunc,
        channel: xmlGenericErrorFunc,
        data: *mut libc::c_void,
        ctx: *mut libc::c_void,
        node: *mut libc::c_void,
        domain: libc::c_int,
        code: libc::c_int,
        level: xmlErrorLevel,
        file: *const libc::c_char,
        line: libc::c_int,
        str1: *const libc::c_char,
        str2: *const libc::c_char,
        str3: *const libc::c_char,
        int1: libc::c_int,
        col: libc::c_int,
        msg: *const libc::c_char,
        _: ...
    );
    fn xmlParserInputGrow(in_0: xmlParserInputPtr, len: libc::c_int) -> libc::c_int;
    static mut xmlFree: xmlFreeFunc;
    fn xmlBufContent(buf: *const xmlBuf) -> *mut xmlChar;
    fn xmlBufUse(buf: xmlBufPtr) -> size_t;
    fn xmlDictCreate() -> xmlDictPtr;
    fn xmlDictOwns(dict: xmlDictPtr, str: *const xmlChar) -> libc::c_int;
    fn xmlCreateIntSubset(
        doc: xmlDocPtr,
        name: *const xmlChar,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    ) -> xmlDtdPtr;
    fn xmlFreeDoc(cur: xmlDocPtr);
    fn xmlHashFree(table: xmlHashTablePtr, f: xmlHashDeallocator);
    fn xmlHashDefaultDeallocator(entry: *mut libc::c_void, name: *const xmlChar);
    fn xmlParserValidityError(ctx: *mut libc::c_void, msg: *const libc::c_char, _: ...);
    fn xmlParserValidityWarning(
        ctx: *mut libc::c_void,
        msg: *const libc::c_char,
        _: ...
    );
    fn xmlDetectCharEncoding(
        in_0: *const libc::c_uchar,
        len: libc::c_int,
    ) -> xmlCharEncoding;
    fn xmlParserInputBufferPush(
        in_0: xmlParserInputBufferPtr,
        len: libc::c_int,
        buf: *const libc::c_char,
    ) -> libc::c_int;
    fn xmlFreeParserInputBuffer(in_0: xmlParserInputBufferPtr);
    fn xmlParserGetDirectory(filename: *const libc::c_char) -> *mut libc::c_char;
    fn xmlCreateMemoryParserCtxt(
        buffer: *const libc::c_char,
        size: libc::c_int,
    ) -> xmlParserCtxtPtr;
    fn xmlSwitchEncoding(ctxt: xmlParserCtxtPtr, enc: xmlCharEncoding) -> libc::c_int;
    fn xmlSwitchToEncoding(
        ctxt: xmlParserCtxtPtr,
        handler: xmlCharEncodingHandlerPtr,
    ) -> libc::c_int;
    fn xmlNewStringInputStream(
        ctxt: xmlParserCtxtPtr,
        buffer: *const xmlChar,
    ) -> xmlParserInputPtr;
    fn xmlPopInput(ctxt: xmlParserCtxtPtr) -> xmlChar;
    fn xmlFreeInputStream(input: xmlParserInputPtr);
    fn xmlNewInputStream(ctxt: xmlParserCtxtPtr) -> xmlParserInputPtr;
    fn nodePop(ctxt: xmlParserCtxtPtr) -> xmlNodePtr;
    fn inputPush(ctxt: xmlParserCtxtPtr, value: xmlParserInputPtr) -> libc::c_int;
    fn inputPop(ctxt: xmlParserCtxtPtr) -> xmlParserInputPtr;
    fn xmlParserInputShrink(in_0: xmlParserInputPtr);
    fn xmlCopyChar(len: libc::c_int, out: *mut xmlChar, val: libc::c_int) -> libc::c_int;
    fn xmlNextChar(ctxt: xmlParserCtxtPtr);
    fn xmlCharInRange(val: libc::c_uint, group: *const xmlChRangeGroup) -> libc::c_int;
    static xmlIsBaseCharGroup: xmlChRangeGroup;
    static xmlIsExtenderGroup: xmlChRangeGroup;
    static xmlIsCombiningGroup: xmlChRangeGroup;
    static xmlIsPubidChar_tab: [libc::c_uchar; 256];
    static xmlIsDigitGroup: xmlChRangeGroup;
    fn xmlCanonicPath(path: *const xmlChar) -> *mut xmlChar;
    fn xmlBufResetInput(buf: xmlBufPtr, input: xmlParserInputPtr) -> libc::c_int;
    fn xmlBufGetInputBase(buf: xmlBufPtr, input: xmlParserInputPtr) -> size_t;
    fn xmlBufSetInputBaseCur(
        buf: xmlBufPtr,
        input: xmlParserInputPtr,
        base: size_t,
        cur: size_t,
    ) -> libc::c_int;
    fn xmlCharEncInput(
        input: xmlParserInputBufferPtr,
        flush: libc::c_int,
    ) -> libc::c_int;
}
pub type xmlChar = libc::c_uchar;
pub type size_t = libc::c_ulong;
pub type __int32_t = libc::c_int;
pub type htmlParserCtxtPtr = xmlParserCtxtPtr;
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
pub type xmlFreeFunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub const XML_ERR_NO_MEMORY: xmlParserErrors = 2;
pub const XML_FROM_PARSER: C2RustUnnamed_0 = 1;
pub type xmlGenericErrorFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type xmlReallocFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
>;
pub const HTML_PARSE_NOIMPLIED: C2RustUnnamed_2 = 8192;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct htmlStartCloseEntry {
    pub oldTag: *const libc::c_char,
    pub newTag: *const libc::c_char,
}
pub type __compar_fn_t = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
pub type xmlDtdPtr = *mut xmlDtd;
pub type xmlDtd = _xmlDtd;
pub type xmlCharEncoding = libc::c_int;
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
pub type xmlParserErrors = libc::c_uint;
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
pub const XML_ERR_INTERNAL_ERROR: xmlParserErrors = 1;
pub const XML_ERR_OK: xmlParserErrors = 0;
pub const XML_FROM_HTML: C2RustUnnamed_0 = 5;
pub type htmlEntityDesc = _htmlEntityDesc;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _htmlEntityDesc {
    pub value: libc::c_uint,
    pub name: *const libc::c_char,
    pub desc: *const libc::c_char,
}
pub type htmlEntityDescPtr = *mut htmlEntityDesc;
pub type xmlChRangeGroup = _xmlChRangeGroup;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChRangeGroup {
    pub nbShortRange: libc::c_int,
    pub nbLongRange: libc::c_int,
    pub shortRange: *const xmlChSRange,
    pub longRange: *const xmlChLRange,
}
pub type xmlChLRange = _xmlChLRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChLRange {
    pub low: libc::c_uint,
    pub high: libc::c_uint,
}
pub type xmlChSRange = _xmlChSRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChSRange {
    pub low: libc::c_ushort,
    pub high: libc::c_ushort,
}
pub type htmlParserNodeInfo = xmlParserNodeInfo;
pub type htmlElemDesc = _htmlElemDesc;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _htmlElemDesc {
    pub name: *const libc::c_char,
    pub startTag: libc::c_char,
    pub endTag: libc::c_char,
    pub saveEndTag: libc::c_char,
    pub empty: libc::c_char,
    pub depr: libc::c_char,
    pub dtd: libc::c_char,
    pub isinline: libc::c_char,
    pub desc: *const libc::c_char,
    pub subelts: *mut *const libc::c_char,
    pub defaultsubelt: *const libc::c_char,
    pub attrs_opt: *mut *const libc::c_char,
    pub attrs_depr: *mut *const libc::c_char,
    pub attrs_req: *mut *const libc::c_char,
}
pub type xmlParserNodeInfoPtr = *mut xmlParserNodeInfo;
pub const HTML_PARSE_IGNORE_ENC: C2RustUnnamed_2 = 2097152;
pub type xmlMallocFunc = Option::<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct elementPriority {
    pub name: *const libc::c_char,
    pub priority: libc::c_int,
}
pub type xmlSAXHandler = _xmlSAXHandler;
pub type xmlSAXHandlerPtr = *mut xmlSAXHandler;
pub type ptrdiff_t = libc::c_long;
pub type C2RustUnnamed = libc::c_uint;
pub const XML_DOC_HTML: C2RustUnnamed = 128;
pub const XML_DOC_INTERNAL: C2RustUnnamed = 64;
pub const XML_DOC_USERBUILT: C2RustUnnamed = 32;
pub const XML_DOC_XINCLUDE: C2RustUnnamed = 16;
pub const XML_DOC_DTDVALID: C2RustUnnamed = 8;
pub const XML_DOC_OLD10: C2RustUnnamed = 4;
pub const XML_DOC_NSVALID: C2RustUnnamed = 2;
pub const XML_DOC_WELLFORMED: C2RustUnnamed = 1;
pub type xmlHashDeallocator = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
>;
pub type C2RustUnnamed_0 = libc::c_uint;
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
pub const XML_FROM_DTD: C2RustUnnamed_0 = 4;
pub const XML_FROM_NAMESPACE: C2RustUnnamed_0 = 3;
pub const XML_FROM_TREE: C2RustUnnamed_0 = 2;
pub const XML_FROM_NONE: C2RustUnnamed_0 = 0;
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
    pub initialized: libc::c_uint,
}
pub type xmlSAXHandlerV1 = _xmlSAXHandlerV1;
pub type C2RustUnnamed_1 = libc::c_uint;
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
pub type xmlRegisterNodeFunc = Option::<unsafe extern "C" fn(xmlNodePtr) -> ()>;
pub type htmlParserCtxt = xmlParserCtxt;
pub type htmlSAXHandler = xmlSAXHandler;
pub type htmlSAXHandlerPtr = xmlSAXHandlerPtr;
pub type htmlParserInput = xmlParserInput;
pub type htmlParserInputPtr = xmlParserInputPtr;
pub type htmlDocPtr = xmlDocPtr;
pub type htmlNodePtr = xmlNodePtr;
pub const HTML_PARSE_NODEFDTD: C2RustUnnamed_2 = 4;
pub type C2RustUnnamed_2 = libc::c_uint;
pub const HTML_PARSE_COMPACT: C2RustUnnamed_2 = 65536;
pub const HTML_PARSE_NONET: C2RustUnnamed_2 = 2048;
pub const HTML_PARSE_NOBLANKS: C2RustUnnamed_2 = 256;
pub const HTML_PARSE_PEDANTIC: C2RustUnnamed_2 = 128;
pub const HTML_PARSE_NOWARNING: C2RustUnnamed_2 = 64;
pub const HTML_PARSE_NOERROR: C2RustUnnamed_2 = 32;
pub const HTML_PARSE_RECOVER: C2RustUnnamed_2 = 1;
pub type htmlStatus = libc::c_uint;
pub const HTML_REQUIRED: htmlStatus = 12;
pub const HTML_VALID: htmlStatus = 4;
pub const HTML_DEPRECATED: htmlStatus = 2;
pub const HTML_INVALID: htmlStatus = 1;
pub const HTML_NA: htmlStatus = 0;
#[inline]
unsafe extern "C" fn toupper(mut __c: libc::c_int) -> libc::c_int {
    return if __c >= -(128 as libc::c_int) && __c < 256 as libc::c_int {
        *(*__ctype_toupper_loc()).offset(__c as isize)
    } else {
        __c
    };
}
#[inline]
unsafe extern "C" fn bsearch(
    mut __key: *const libc::c_void,
    mut __base: *const libc::c_void,
    mut __nmemb: size_t,
    mut __size: size_t,
    mut __compar: __compar_fn_t,
) -> *mut libc::c_void {
    let mut __l: size_t = 0;
    let mut __u: size_t = 0;
    let mut __idx: size_t = 0;
    let mut __p: *const libc::c_void = 0 as *const libc::c_void;
    let mut __comparison: libc::c_int = 0;
    __l = 0 as libc::c_int as size_t;
    __u = __nmemb;
    while __l < __u {
        __idx = __l.wrapping_add(__u).wrapping_div(2 as libc::c_int as libc::c_ulong);
        __p = (__base as *const libc::c_char).offset(__idx.wrapping_mul(__size) as isize)
            as *mut libc::c_void;
        __comparison = (Some(__compar.expect("non-null function pointer")))
            .expect("non-null function pointer")(__key, __p);
        if __comparison < 0 as libc::c_int {
            __u = __idx;
        } else if __comparison > 0 as libc::c_int {
            __l = __idx.wrapping_add(1 as libc::c_int as libc::c_ulong);
        } else {
            return __p as *mut libc::c_void
        }
    }
    return 0 as *mut libc::c_void;
}
static mut htmlOmittedDefaultValue: libc::c_int = 1 as libc::c_int;
unsafe extern "C" fn htmlErrMemory(
    mut ctxt: xmlParserCtxtPtr,
    mut extra: *const libc::c_char,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = XML_ERR_NO_MEMORY as libc::c_int;
        (*ctxt).instate = XML_PARSER_EOF;
        (*ctxt).disableSAX = 1 as libc::c_int;
    }
    if !extra.is_null() {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as libc::c_int,
            XML_ERR_NO_MEMORY as libc::c_int,
            XML_ERR_FATAL,
            0 as *const libc::c_char,
            0 as libc::c_int,
            extra,
            0 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as libc::c_int,
            b"Memory allocation failed : %s\n\0" as *const u8 as *const libc::c_char,
            extra,
        );
    } else {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as libc::c_int,
            XML_ERR_NO_MEMORY as libc::c_int,
            XML_ERR_FATAL,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as libc::c_int,
            b"Memory allocation failed\n\0" as *const u8 as *const libc::c_char,
        );
    };
}
unsafe extern "C" fn htmlParseErr(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as libc::c_int;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_HTML as libc::c_int,
        error as libc::c_int,
        XML_ERR_ERROR,
        0 as *const libc::c_char,
        0 as libc::c_int,
        str1 as *const libc::c_char,
        str2 as *const libc::c_char,
        0 as *const libc::c_char,
        0 as libc::c_int,
        0 as libc::c_int,
        msg,
        str1,
        str2,
    );
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as libc::c_int;
    }
}
unsafe extern "C" fn htmlParseErrInt(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut val: libc::c_int,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as libc::c_int;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_HTML as libc::c_int,
        error as libc::c_int,
        XML_ERR_ERROR,
        0 as *const libc::c_char,
        0 as libc::c_int,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        val,
        0 as libc::c_int,
        msg,
        val,
    );
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as libc::c_int;
    }
}
unsafe extern "C" fn htmlnamePush(
    mut ctxt: htmlParserCtxtPtr,
    mut value: *const xmlChar,
) -> libc::c_int {
    if (*ctxt).html < 3 as libc::c_int
        && xmlStrEqual(
            value,
            b"head\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
    {
        (*ctxt).html = 3 as libc::c_int;
    }
    if (*ctxt).html < 10 as libc::c_int
        && xmlStrEqual(
            value,
            b"body\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
    {
        (*ctxt).html = 10 as libc::c_int;
    }
    if (*ctxt).nameNr >= (*ctxt).nameMax {
        (*ctxt).nameMax *= 2 as libc::c_int;
        let ref mut fresh0 = (*ctxt).nameTab;
        *fresh0 = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).nameTab as *mut *mut xmlChar as *mut libc::c_void,
            ((*ctxt).nameMax as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as libc::c_ulong),
        ) as *mut *const xmlChar;
        if ((*ctxt).nameTab).is_null() {
            htmlErrMemory(ctxt, 0 as *const libc::c_char);
            return 0 as libc::c_int;
        }
    }
    let ref mut fresh1 = *((*ctxt).nameTab).offset((*ctxt).nameNr as isize);
    *fresh1 = value;
    let ref mut fresh2 = (*ctxt).name;
    *fresh2 = value;
    let ref mut fresh3 = (*ctxt).nameNr;
    let fresh4 = *fresh3;
    *fresh3 = *fresh3 + 1;
    return fresh4;
}
unsafe extern "C" fn htmlnamePop(mut ctxt: htmlParserCtxtPtr) -> *const xmlChar {
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    if (*ctxt).nameNr <= 0 as libc::c_int {
        return 0 as *const xmlChar;
    }
    let ref mut fresh5 = (*ctxt).nameNr;
    *fresh5 -= 1;
    if (*ctxt).nameNr < 0 as libc::c_int {
        return 0 as *const xmlChar;
    }
    if (*ctxt).nameNr > 0 as libc::c_int {
        let ref mut fresh6 = (*ctxt).name;
        *fresh6 = *((*ctxt).nameTab)
            .offset(((*ctxt).nameNr - 1 as libc::c_int) as isize);
    } else {
        let ref mut fresh7 = (*ctxt).name;
        *fresh7 = 0 as *const xmlChar;
    }
    ret = *((*ctxt).nameTab).offset((*ctxt).nameNr as isize);
    let ref mut fresh8 = *((*ctxt).nameTab).offset((*ctxt).nameNr as isize);
    *fresh8 = 0 as *const xmlChar;
    return ret;
}
unsafe extern "C" fn htmlNodeInfoPush(
    mut ctxt: htmlParserCtxtPtr,
    mut value: *mut htmlParserNodeInfo,
) -> libc::c_int {
    if (*ctxt).nodeInfoNr >= (*ctxt).nodeInfoMax {
        if (*ctxt).nodeInfoMax == 0 as libc::c_int {
            (*ctxt).nodeInfoMax = 5 as libc::c_int;
        }
        (*ctxt).nodeInfoMax *= 2 as libc::c_int;
        let ref mut fresh9 = (*ctxt).nodeInfoTab;
        *fresh9 = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).nodeInfoTab as *mut htmlParserNodeInfo as *mut libc::c_void,
            ((*ctxt).nodeInfoMax as libc::c_ulong)
                .wrapping_mul(
                    ::std::mem::size_of::<xmlParserNodeInfo>() as libc::c_ulong,
                ),
        ) as *mut htmlParserNodeInfo;
        if ((*ctxt).nodeInfoTab).is_null() {
            htmlErrMemory(ctxt, 0 as *const libc::c_char);
            return 0 as libc::c_int;
        }
    }
    *((*ctxt).nodeInfoTab).offset((*ctxt).nodeInfoNr as isize) = *value;
    let ref mut fresh10 = (*ctxt).nodeInfo;
    *fresh10 = &mut *((*ctxt).nodeInfoTab).offset((*ctxt).nodeInfoNr as isize)
        as *mut xmlParserNodeInfo;
    let ref mut fresh11 = (*ctxt).nodeInfoNr;
    let fresh12 = *fresh11;
    *fresh11 = *fresh11 + 1;
    return fresh12;
}
unsafe extern "C" fn htmlNodeInfoPop(
    mut ctxt: htmlParserCtxtPtr,
) -> *mut htmlParserNodeInfo {
    if (*ctxt).nodeInfoNr <= 0 as libc::c_int {
        return 0 as *mut htmlParserNodeInfo;
    }
    let ref mut fresh13 = (*ctxt).nodeInfoNr;
    *fresh13 -= 1;
    if (*ctxt).nodeInfoNr < 0 as libc::c_int {
        return 0 as *mut htmlParserNodeInfo;
    }
    if (*ctxt).nodeInfoNr > 0 as libc::c_int {
        let ref mut fresh14 = (*ctxt).nodeInfo;
        *fresh14 = &mut *((*ctxt).nodeInfoTab)
            .offset(((*ctxt).nodeInfoNr - 1 as libc::c_int) as isize)
            as *mut xmlParserNodeInfo;
    } else {
        let ref mut fresh15 = (*ctxt).nodeInfo;
        *fresh15 = 0 as *mut xmlParserNodeInfo;
    }
    return &mut *((*ctxt).nodeInfoTab).offset((*ctxt).nodeInfoNr as isize)
        as *mut xmlParserNodeInfo;
}
unsafe extern "C" fn htmlFindEncoding(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    let mut start: *const xmlChar = 0 as *const xmlChar;
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut end: *const xmlChar = 0 as *const xmlChar;
    if ctxt.is_null() || ((*ctxt).input).is_null()
        || !((*(*ctxt).input).encoding).is_null() || ((*(*ctxt).input).buf).is_null()
        || !((*(*(*ctxt).input).buf).encoder).is_null()
    {
        return 0 as *mut xmlChar;
    }
    if ((*(*ctxt).input).cur).is_null() || ((*(*ctxt).input).end).is_null() {
        return 0 as *mut xmlChar;
    }
    start = (*(*ctxt).input).cur;
    end = (*(*ctxt).input).end;
    if *end as libc::c_int != 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    cur = xmlStrcasestr(
        start,
        b"HTTP-EQUIV\0" as *const u8 as *const libc::c_char as *mut xmlChar,
    );
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    cur = xmlStrcasestr(
        cur,
        b"CONTENT\0" as *const u8 as *const libc::c_char as *mut xmlChar,
    );
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    cur = xmlStrcasestr(
        cur,
        b"CHARSET=\0" as *const u8 as *const libc::c_char as *mut xmlChar,
    );
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    cur = cur.offset(8 as libc::c_int as isize);
    start = cur;
    while *cur as libc::c_int >= 'A' as i32 && *cur as libc::c_int <= 'Z' as i32
        || *cur as libc::c_int >= 'a' as i32 && *cur as libc::c_int <= 'z' as i32
        || *cur as libc::c_int >= '0' as i32 && *cur as libc::c_int <= '9' as i32
        || *cur as libc::c_int == '-' as i32 || *cur as libc::c_int == '_' as i32
        || *cur as libc::c_int == ':' as i32 || *cur as libc::c_int == '/' as i32
    {
        cur = cur.offset(1);
    }
    if cur == start {
        return 0 as *mut xmlChar;
    }
    return xmlStrndup(start, cur.offset_from(start) as libc::c_long as libc::c_int);
}
unsafe extern "C" fn htmlCurrentChar(
    mut ctxt: xmlParserCtxtPtr,
    mut len: *mut libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut cur: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut c: libc::c_uchar = 0;
    let mut val: libc::c_uint = 0;
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return 0 as libc::c_int;
    }
    if (*ctxt).token != 0 as libc::c_int {
        *len = 0 as libc::c_int;
        return (*ctxt).token;
    }
    if (*ctxt).charset != XML_CHAR_ENCODING_UTF8 as libc::c_int {
        let mut guess: *mut xmlChar = 0 as *mut xmlChar;
        let mut handler: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
        if (*(*(*ctxt).input).cur as libc::c_int) < 0x80 as libc::c_int {
            *len = 1 as libc::c_int;
            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int
                && (*(*ctxt).input).cur < (*(*ctxt).input).end
            {
                htmlParseErrInt(
                    ctxt,
                    XML_ERR_INVALID_CHAR,
                    b"Char 0x%X out of allowed range\n\0" as *const u8
                        as *const libc::c_char,
                    0 as libc::c_int,
                );
                return ' ' as i32;
            }
            return *(*(*ctxt).input).cur as libc::c_int;
        }
        guess = htmlFindEncoding(ctxt);
        if guess.is_null() {
            xmlSwitchEncoding(ctxt, XML_CHAR_ENCODING_8859_1);
        } else {
            if !((*(*ctxt).input).encoding).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*(*ctxt).input).encoding as *mut xmlChar as *mut libc::c_void);
            }
            let ref mut fresh16 = (*(*ctxt).input).encoding;
            *fresh16 = guess;
            handler = xmlFindCharEncodingHandler(guess as *const libc::c_char);
            if !handler.is_null() {
                if xmlStrEqual(
                    (*handler).name as *mut xmlChar,
                    b"UTF-8\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) == 0
                {
                    xmlSwitchToEncoding(ctxt, handler);
                }
            } else {
                htmlParseErr(
                    ctxt,
                    XML_ERR_INVALID_ENCODING,
                    b"Unsupported encoding %s\0" as *const u8 as *const libc::c_char,
                    guess,
                    0 as *const xmlChar,
                );
            }
        }
        (*ctxt).charset = XML_CHAR_ENCODING_UTF8 as libc::c_int;
    }
    cur = (*(*ctxt).input).cur;
    c = *cur;
    if c as libc::c_int & 0x80 as libc::c_int != 0 {
        if !(c as libc::c_int & 0x40 as libc::c_int == 0 as libc::c_int) {
            if *cur.offset(1 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
            {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                cur = (*(*ctxt).input).cur;
            }
            if !(*cur.offset(1 as libc::c_int as isize) as libc::c_int
                & 0xc0 as libc::c_int != 0x80 as libc::c_int)
            {
                if c as libc::c_int & 0xe0 as libc::c_int == 0xe0 as libc::c_int {
                    if *cur.offset(2 as libc::c_int as isize) as libc::c_int
                        == 0 as libc::c_int
                    {
                        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                        cur = (*(*ctxt).input).cur;
                    }
                    if *cur.offset(2 as libc::c_int as isize) as libc::c_int
                        & 0xc0 as libc::c_int != 0x80 as libc::c_int
                    {
                        current_block = 3454401781937836742;
                    } else if c as libc::c_int & 0xf0 as libc::c_int
                            == 0xf0 as libc::c_int
                        {
                        if *cur.offset(3 as libc::c_int as isize) as libc::c_int
                            == 0 as libc::c_int
                        {
                            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                            cur = (*(*ctxt).input).cur;
                        }
                        if c as libc::c_int & 0xf8 as libc::c_int != 0xf0 as libc::c_int
                            || *cur.offset(3 as libc::c_int as isize) as libc::c_int
                                & 0xc0 as libc::c_int != 0x80 as libc::c_int
                        {
                            current_block = 3454401781937836742;
                        } else {
                            *len = 4 as libc::c_int;
                            val = ((*cur.offset(0 as libc::c_int as isize) as libc::c_int
                                & 0x7 as libc::c_int) << 18 as libc::c_int) as libc::c_uint;
                            val
                                |= ((*cur.offset(1 as libc::c_int as isize) as libc::c_int
                                    & 0x3f as libc::c_int) << 12 as libc::c_int)
                                    as libc::c_uint;
                            val
                                |= ((*cur.offset(2 as libc::c_int as isize) as libc::c_int
                                    & 0x3f as libc::c_int) << 6 as libc::c_int) as libc::c_uint;
                            val
                                |= (*cur.offset(3 as libc::c_int as isize) as libc::c_int
                                    & 0x3f as libc::c_int) as libc::c_uint;
                            if val < 0x10000 as libc::c_int as libc::c_uint {
                                current_block = 3454401781937836742;
                            } else {
                                current_block = 1874315696050160458;
                            }
                        }
                    } else {
                        *len = 3 as libc::c_int;
                        val = ((*cur.offset(0 as libc::c_int as isize) as libc::c_int
                            & 0xf as libc::c_int) << 12 as libc::c_int) as libc::c_uint;
                        val
                            |= ((*cur.offset(1 as libc::c_int as isize) as libc::c_int
                                & 0x3f as libc::c_int) << 6 as libc::c_int) as libc::c_uint;
                        val
                            |= (*cur.offset(2 as libc::c_int as isize) as libc::c_int
                                & 0x3f as libc::c_int) as libc::c_uint;
                        if val < 0x800 as libc::c_int as libc::c_uint {
                            current_block = 3454401781937836742;
                        } else {
                            current_block = 1874315696050160458;
                        }
                    }
                } else {
                    *len = 2 as libc::c_int;
                    val = ((*cur.offset(0 as libc::c_int as isize) as libc::c_int
                        & 0x1f as libc::c_int) << 6 as libc::c_int) as libc::c_uint;
                    val
                        |= (*cur.offset(1 as libc::c_int as isize) as libc::c_int
                            & 0x3f as libc::c_int) as libc::c_uint;
                    if val < 0x80 as libc::c_int as libc::c_uint {
                        current_block = 3454401781937836742;
                    } else {
                        current_block = 1874315696050160458;
                    }
                }
                match current_block {
                    3454401781937836742 => {}
                    _ => {
                        if if val < 0x100 as libc::c_int as libc::c_uint {
                            (0x9 as libc::c_int as libc::c_uint <= val
                                && val <= 0xa as libc::c_int as libc::c_uint
                                || val == 0xd as libc::c_int as libc::c_uint
                                || 0x20 as libc::c_int as libc::c_uint <= val)
                                as libc::c_int
                        } else {
                            (0x100 as libc::c_int as libc::c_uint <= val
                                && val <= 0xd7ff as libc::c_int as libc::c_uint
                                || 0xe000 as libc::c_int as libc::c_uint <= val
                                    && val <= 0xfffd as libc::c_int as libc::c_uint
                                || 0x10000 as libc::c_int as libc::c_uint <= val
                                    && val <= 0x10ffff as libc::c_int as libc::c_uint)
                                as libc::c_int
                        } == 0
                        {
                            htmlParseErrInt(
                                ctxt,
                                XML_ERR_INVALID_CHAR,
                                b"Char 0x%X out of allowed range\n\0" as *const u8
                                    as *const libc::c_char,
                                val as libc::c_int,
                            );
                        }
                        return val as libc::c_int;
                    }
                }
            }
        }
        let mut buffer: [libc::c_char; 150] = [0; 150];
        if ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long
            >= 4 as libc::c_int as libc::c_long
        {
            snprintf(
                buffer.as_mut_ptr(),
                149 as libc::c_int as libc::c_ulong,
                b"Bytes: 0x%02X 0x%02X 0x%02X 0x%02X\n\0" as *const u8
                    as *const libc::c_char,
                *((*(*ctxt).input).cur).offset(0 as libc::c_int as isize) as libc::c_int,
                *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int,
                *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize) as libc::c_int,
                *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize) as libc::c_int,
            );
        } else {
            snprintf(
                buffer.as_mut_ptr(),
                149 as libc::c_int as libc::c_ulong,
                b"Bytes: 0x%02X\n\0" as *const u8 as *const libc::c_char,
                *((*(*ctxt).input).cur).offset(0 as libc::c_int as isize) as libc::c_int,
            );
        }
        htmlParseErr(
            ctxt,
            XML_ERR_INVALID_ENCODING,
            b"Input is not proper UTF-8, indicate encoding !\n\0" as *const u8
                as *const libc::c_char,
            buffer.as_mut_ptr() as *mut xmlChar,
            0 as *const xmlChar,
        );
        if !((*(*ctxt).input).buf).is_null()
            && ((*(*(*ctxt).input).buf).encoder).is_null()
        {
            xmlSwitchEncoding(ctxt, XML_CHAR_ENCODING_8859_1);
        }
        *len = 1 as libc::c_int;
        return *(*(*ctxt).input).cur as libc::c_int;
    } else {
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int
            && (*(*ctxt).input).cur < (*(*ctxt).input).end
        {
            htmlParseErrInt(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"Char 0x%X out of allowed range\n\0" as *const u8
                    as *const libc::c_char,
                0 as libc::c_int,
            );
            *len = 1 as libc::c_int;
            return ' ' as i32;
        }
        *len = 1 as libc::c_int;
        return *(*(*ctxt).input).cur as libc::c_int;
    };
}
unsafe extern "C" fn htmlSkipBlankChars(mut ctxt: xmlParserCtxtPtr) -> libc::c_int {
    let mut res: libc::c_int = 0 as libc::c_int;
    while *(*(*ctxt).input).cur as libc::c_int == 0x20 as libc::c_int
        || 0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
            && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
        || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int
    {
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int
            && xmlParserInputGrow((*ctxt).input, 250 as libc::c_int) <= 0 as libc::c_int
        {
            xmlPopInput(ctxt);
        } else {
            if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                let ref mut fresh17 = (*(*ctxt).input).line;
                *fresh17 += 1;
                (*(*ctxt).input).col = 1 as libc::c_int;
            } else {
                let ref mut fresh18 = (*(*ctxt).input).col;
                *fresh18 += 1;
            }
            let ref mut fresh19 = (*(*ctxt).input).cur;
            *fresh19 = (*fresh19).offset(1);
            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
        }
        if res < 2147483647 as libc::c_int {
            res += 1;
        }
    }
    return res;
}
static mut html_flow: [*const libc::c_char; 64] = [
    b"h1\0" as *const u8 as *const libc::c_char,
    b"h2\0" as *const u8 as *const libc::c_char,
    b"h3\0" as *const u8 as *const libc::c_char,
    b"h4\0" as *const u8 as *const libc::c_char,
    b"h5\0" as *const u8 as *const libc::c_char,
    b"h6\0" as *const u8 as *const libc::c_char,
    b"ul\0" as *const u8 as *const libc::c_char,
    b"ol\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"menu\0" as *const u8 as *const libc::c_char,
    b"pre\0" as *const u8 as *const libc::c_char,
    b"p\0" as *const u8 as *const libc::c_char,
    b"dl\0" as *const u8 as *const libc::c_char,
    b"div\0" as *const u8 as *const libc::c_char,
    b"center\0" as *const u8 as *const libc::c_char,
    b"noscript\0" as *const u8 as *const libc::c_char,
    b"noframes\0" as *const u8 as *const libc::c_char,
    b"blockquote\0" as *const u8 as *const libc::c_char,
    b"form\0" as *const u8 as *const libc::c_char,
    b"isindex\0" as *const u8 as *const libc::c_char,
    b"hr\0" as *const u8 as *const libc::c_char,
    b"table\0" as *const u8 as *const libc::c_char,
    b"fieldset\0" as *const u8 as *const libc::c_char,
    b"address\0" as *const u8 as *const libc::c_char,
    b"tt\0" as *const u8 as *const libc::c_char,
    b"i\0" as *const u8 as *const libc::c_char,
    b"b\0" as *const u8 as *const libc::c_char,
    b"u\0" as *const u8 as *const libc::c_char,
    b"s\0" as *const u8 as *const libc::c_char,
    b"strike\0" as *const u8 as *const libc::c_char,
    b"big\0" as *const u8 as *const libc::c_char,
    b"small\0" as *const u8 as *const libc::c_char,
    b"em\0" as *const u8 as *const libc::c_char,
    b"strong\0" as *const u8 as *const libc::c_char,
    b"dfn\0" as *const u8 as *const libc::c_char,
    b"code\0" as *const u8 as *const libc::c_char,
    b"samp\0" as *const u8 as *const libc::c_char,
    b"kbd\0" as *const u8 as *const libc::c_char,
    b"var\0" as *const u8 as *const libc::c_char,
    b"cite\0" as *const u8 as *const libc::c_char,
    b"abbr\0" as *const u8 as *const libc::c_char,
    b"acronym\0" as *const u8 as *const libc::c_char,
    b"a\0" as *const u8 as *const libc::c_char,
    b"img\0" as *const u8 as *const libc::c_char,
    b"applet\0" as *const u8 as *const libc::c_char,
    b"embed\0" as *const u8 as *const libc::c_char,
    b"object\0" as *const u8 as *const libc::c_char,
    b"font\0" as *const u8 as *const libc::c_char,
    b"basefont\0" as *const u8 as *const libc::c_char,
    b"br\0" as *const u8 as *const libc::c_char,
    b"script\0" as *const u8 as *const libc::c_char,
    b"map\0" as *const u8 as *const libc::c_char,
    b"q\0" as *const u8 as *const libc::c_char,
    b"sub\0" as *const u8 as *const libc::c_char,
    b"sup\0" as *const u8 as *const libc::c_char,
    b"span\0" as *const u8 as *const libc::c_char,
    b"bdo\0" as *const u8 as *const libc::c_char,
    b"iframe\0" as *const u8 as *const libc::c_char,
    b"input\0" as *const u8 as *const libc::c_char,
    b"select\0" as *const u8 as *const libc::c_char,
    b"textarea\0" as *const u8 as *const libc::c_char,
    b"label\0" as *const u8 as *const libc::c_char,
    b"button\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut html_inline: [*const libc::c_char; 40] = [
    b"tt\0" as *const u8 as *const libc::c_char,
    b"i\0" as *const u8 as *const libc::c_char,
    b"b\0" as *const u8 as *const libc::c_char,
    b"u\0" as *const u8 as *const libc::c_char,
    b"s\0" as *const u8 as *const libc::c_char,
    b"strike\0" as *const u8 as *const libc::c_char,
    b"big\0" as *const u8 as *const libc::c_char,
    b"small\0" as *const u8 as *const libc::c_char,
    b"em\0" as *const u8 as *const libc::c_char,
    b"strong\0" as *const u8 as *const libc::c_char,
    b"dfn\0" as *const u8 as *const libc::c_char,
    b"code\0" as *const u8 as *const libc::c_char,
    b"samp\0" as *const u8 as *const libc::c_char,
    b"kbd\0" as *const u8 as *const libc::c_char,
    b"var\0" as *const u8 as *const libc::c_char,
    b"cite\0" as *const u8 as *const libc::c_char,
    b"abbr\0" as *const u8 as *const libc::c_char,
    b"acronym\0" as *const u8 as *const libc::c_char,
    b"a\0" as *const u8 as *const libc::c_char,
    b"img\0" as *const u8 as *const libc::c_char,
    b"applet\0" as *const u8 as *const libc::c_char,
    b"embed\0" as *const u8 as *const libc::c_char,
    b"object\0" as *const u8 as *const libc::c_char,
    b"font\0" as *const u8 as *const libc::c_char,
    b"basefont\0" as *const u8 as *const libc::c_char,
    b"br\0" as *const u8 as *const libc::c_char,
    b"script\0" as *const u8 as *const libc::c_char,
    b"map\0" as *const u8 as *const libc::c_char,
    b"q\0" as *const u8 as *const libc::c_char,
    b"sub\0" as *const u8 as *const libc::c_char,
    b"sup\0" as *const u8 as *const libc::c_char,
    b"span\0" as *const u8 as *const libc::c_char,
    b"bdo\0" as *const u8 as *const libc::c_char,
    b"iframe\0" as *const u8 as *const libc::c_char,
    b"input\0" as *const u8 as *const libc::c_char,
    b"select\0" as *const u8 as *const libc::c_char,
    b"textarea\0" as *const u8 as *const libc::c_char,
    b"label\0" as *const u8 as *const libc::c_char,
    b"button\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut html_pcdata: [*const libc::c_char; 1] = [0 as *const libc::c_char];
static mut html_attrs: [*const libc::c_char; 16] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut core_i18n_attrs: [*const libc::c_char; 7] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut core_attrs: [*const libc::c_char; 5] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut i18n_attrs: [*const libc::c_char; 3] = [
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut a_attrs: [*const libc::c_char; 29] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"charset\0" as *const u8 as *const libc::c_char,
    b"type\0" as *const u8 as *const libc::c_char,
    b"name\0" as *const u8 as *const libc::c_char,
    b"href\0" as *const u8 as *const libc::c_char,
    b"hreflang\0" as *const u8 as *const libc::c_char,
    b"rel\0" as *const u8 as *const libc::c_char,
    b"rev\0" as *const u8 as *const libc::c_char,
    b"accesskey\0" as *const u8 as *const libc::c_char,
    b"shape\0" as *const u8 as *const libc::c_char,
    b"coords\0" as *const u8 as *const libc::c_char,
    b"tabindex\0" as *const u8 as *const libc::c_char,
    b"onfocus\0" as *const u8 as *const libc::c_char,
    b"onblur\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut target_attr: [*const libc::c_char; 2] = [
    b"target\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut rows_cols_attr: [*const libc::c_char; 3] = [
    b"rows\0" as *const u8 as *const libc::c_char,
    b"cols\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut alt_attr: [*const libc::c_char; 2] = [
    b"alt\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut src_alt_attrs: [*const libc::c_char; 3] = [
    b"src\0" as *const u8 as *const libc::c_char,
    b"alt\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut href_attrs: [*const libc::c_char; 2] = [
    b"href\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut clear_attrs: [*const libc::c_char; 2] = [
    b"clear\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut inline_p: [*const libc::c_char; 41] = [
    b"tt\0" as *const u8 as *const libc::c_char,
    b"i\0" as *const u8 as *const libc::c_char,
    b"b\0" as *const u8 as *const libc::c_char,
    b"u\0" as *const u8 as *const libc::c_char,
    b"s\0" as *const u8 as *const libc::c_char,
    b"strike\0" as *const u8 as *const libc::c_char,
    b"big\0" as *const u8 as *const libc::c_char,
    b"small\0" as *const u8 as *const libc::c_char,
    b"em\0" as *const u8 as *const libc::c_char,
    b"strong\0" as *const u8 as *const libc::c_char,
    b"dfn\0" as *const u8 as *const libc::c_char,
    b"code\0" as *const u8 as *const libc::c_char,
    b"samp\0" as *const u8 as *const libc::c_char,
    b"kbd\0" as *const u8 as *const libc::c_char,
    b"var\0" as *const u8 as *const libc::c_char,
    b"cite\0" as *const u8 as *const libc::c_char,
    b"abbr\0" as *const u8 as *const libc::c_char,
    b"acronym\0" as *const u8 as *const libc::c_char,
    b"a\0" as *const u8 as *const libc::c_char,
    b"img\0" as *const u8 as *const libc::c_char,
    b"applet\0" as *const u8 as *const libc::c_char,
    b"embed\0" as *const u8 as *const libc::c_char,
    b"object\0" as *const u8 as *const libc::c_char,
    b"font\0" as *const u8 as *const libc::c_char,
    b"basefont\0" as *const u8 as *const libc::c_char,
    b"br\0" as *const u8 as *const libc::c_char,
    b"script\0" as *const u8 as *const libc::c_char,
    b"map\0" as *const u8 as *const libc::c_char,
    b"q\0" as *const u8 as *const libc::c_char,
    b"sub\0" as *const u8 as *const libc::c_char,
    b"sup\0" as *const u8 as *const libc::c_char,
    b"span\0" as *const u8 as *const libc::c_char,
    b"bdo\0" as *const u8 as *const libc::c_char,
    b"iframe\0" as *const u8 as *const libc::c_char,
    b"input\0" as *const u8 as *const libc::c_char,
    b"select\0" as *const u8 as *const libc::c_char,
    b"textarea\0" as *const u8 as *const libc::c_char,
    b"label\0" as *const u8 as *const libc::c_char,
    b"button\0" as *const u8 as *const libc::c_char,
    b"p\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut flow_param: [*const libc::c_char; 65] = [
    b"h1\0" as *const u8 as *const libc::c_char,
    b"h2\0" as *const u8 as *const libc::c_char,
    b"h3\0" as *const u8 as *const libc::c_char,
    b"h4\0" as *const u8 as *const libc::c_char,
    b"h5\0" as *const u8 as *const libc::c_char,
    b"h6\0" as *const u8 as *const libc::c_char,
    b"ul\0" as *const u8 as *const libc::c_char,
    b"ol\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"menu\0" as *const u8 as *const libc::c_char,
    b"pre\0" as *const u8 as *const libc::c_char,
    b"p\0" as *const u8 as *const libc::c_char,
    b"dl\0" as *const u8 as *const libc::c_char,
    b"div\0" as *const u8 as *const libc::c_char,
    b"center\0" as *const u8 as *const libc::c_char,
    b"noscript\0" as *const u8 as *const libc::c_char,
    b"noframes\0" as *const u8 as *const libc::c_char,
    b"blockquote\0" as *const u8 as *const libc::c_char,
    b"form\0" as *const u8 as *const libc::c_char,
    b"isindex\0" as *const u8 as *const libc::c_char,
    b"hr\0" as *const u8 as *const libc::c_char,
    b"table\0" as *const u8 as *const libc::c_char,
    b"fieldset\0" as *const u8 as *const libc::c_char,
    b"address\0" as *const u8 as *const libc::c_char,
    b"tt\0" as *const u8 as *const libc::c_char,
    b"i\0" as *const u8 as *const libc::c_char,
    b"b\0" as *const u8 as *const libc::c_char,
    b"u\0" as *const u8 as *const libc::c_char,
    b"s\0" as *const u8 as *const libc::c_char,
    b"strike\0" as *const u8 as *const libc::c_char,
    b"big\0" as *const u8 as *const libc::c_char,
    b"small\0" as *const u8 as *const libc::c_char,
    b"em\0" as *const u8 as *const libc::c_char,
    b"strong\0" as *const u8 as *const libc::c_char,
    b"dfn\0" as *const u8 as *const libc::c_char,
    b"code\0" as *const u8 as *const libc::c_char,
    b"samp\0" as *const u8 as *const libc::c_char,
    b"kbd\0" as *const u8 as *const libc::c_char,
    b"var\0" as *const u8 as *const libc::c_char,
    b"cite\0" as *const u8 as *const libc::c_char,
    b"abbr\0" as *const u8 as *const libc::c_char,
    b"acronym\0" as *const u8 as *const libc::c_char,
    b"a\0" as *const u8 as *const libc::c_char,
    b"img\0" as *const u8 as *const libc::c_char,
    b"applet\0" as *const u8 as *const libc::c_char,
    b"embed\0" as *const u8 as *const libc::c_char,
    b"object\0" as *const u8 as *const libc::c_char,
    b"font\0" as *const u8 as *const libc::c_char,
    b"basefont\0" as *const u8 as *const libc::c_char,
    b"br\0" as *const u8 as *const libc::c_char,
    b"script\0" as *const u8 as *const libc::c_char,
    b"map\0" as *const u8 as *const libc::c_char,
    b"q\0" as *const u8 as *const libc::c_char,
    b"sub\0" as *const u8 as *const libc::c_char,
    b"sup\0" as *const u8 as *const libc::c_char,
    b"span\0" as *const u8 as *const libc::c_char,
    b"bdo\0" as *const u8 as *const libc::c_char,
    b"iframe\0" as *const u8 as *const libc::c_char,
    b"input\0" as *const u8 as *const libc::c_char,
    b"select\0" as *const u8 as *const libc::c_char,
    b"textarea\0" as *const u8 as *const libc::c_char,
    b"label\0" as *const u8 as *const libc::c_char,
    b"button\0" as *const u8 as *const libc::c_char,
    b"param\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut applet_attrs: [*const libc::c_char; 14] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"codebase\0" as *const u8 as *const libc::c_char,
    b"archive\0" as *const u8 as *const libc::c_char,
    b"alt\0" as *const u8 as *const libc::c_char,
    b"name\0" as *const u8 as *const libc::c_char,
    b"height\0" as *const u8 as *const libc::c_char,
    b"width\0" as *const u8 as *const libc::c_char,
    b"align\0" as *const u8 as *const libc::c_char,
    b"hspace\0" as *const u8 as *const libc::c_char,
    b"vspace\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut area_attrs: [*const libc::c_char; 9] = [
    b"shape\0" as *const u8 as *const libc::c_char,
    b"coords\0" as *const u8 as *const libc::c_char,
    b"href\0" as *const u8 as *const libc::c_char,
    b"nohref\0" as *const u8 as *const libc::c_char,
    b"tabindex\0" as *const u8 as *const libc::c_char,
    b"accesskey\0" as *const u8 as *const libc::c_char,
    b"onfocus\0" as *const u8 as *const libc::c_char,
    b"onblur\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut basefont_attrs: [*const libc::c_char; 5] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"size\0" as *const u8 as *const libc::c_char,
    b"color\0" as *const u8 as *const libc::c_char,
    b"face\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut quote_attrs: [*const libc::c_char; 17] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"cite\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut body_contents: [*const libc::c_char; 66] = [
    b"h1\0" as *const u8 as *const libc::c_char,
    b"h2\0" as *const u8 as *const libc::c_char,
    b"h3\0" as *const u8 as *const libc::c_char,
    b"h4\0" as *const u8 as *const libc::c_char,
    b"h5\0" as *const u8 as *const libc::c_char,
    b"h6\0" as *const u8 as *const libc::c_char,
    b"ul\0" as *const u8 as *const libc::c_char,
    b"ol\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"menu\0" as *const u8 as *const libc::c_char,
    b"pre\0" as *const u8 as *const libc::c_char,
    b"p\0" as *const u8 as *const libc::c_char,
    b"dl\0" as *const u8 as *const libc::c_char,
    b"div\0" as *const u8 as *const libc::c_char,
    b"center\0" as *const u8 as *const libc::c_char,
    b"noscript\0" as *const u8 as *const libc::c_char,
    b"noframes\0" as *const u8 as *const libc::c_char,
    b"blockquote\0" as *const u8 as *const libc::c_char,
    b"form\0" as *const u8 as *const libc::c_char,
    b"isindex\0" as *const u8 as *const libc::c_char,
    b"hr\0" as *const u8 as *const libc::c_char,
    b"table\0" as *const u8 as *const libc::c_char,
    b"fieldset\0" as *const u8 as *const libc::c_char,
    b"address\0" as *const u8 as *const libc::c_char,
    b"tt\0" as *const u8 as *const libc::c_char,
    b"i\0" as *const u8 as *const libc::c_char,
    b"b\0" as *const u8 as *const libc::c_char,
    b"u\0" as *const u8 as *const libc::c_char,
    b"s\0" as *const u8 as *const libc::c_char,
    b"strike\0" as *const u8 as *const libc::c_char,
    b"big\0" as *const u8 as *const libc::c_char,
    b"small\0" as *const u8 as *const libc::c_char,
    b"em\0" as *const u8 as *const libc::c_char,
    b"strong\0" as *const u8 as *const libc::c_char,
    b"dfn\0" as *const u8 as *const libc::c_char,
    b"code\0" as *const u8 as *const libc::c_char,
    b"samp\0" as *const u8 as *const libc::c_char,
    b"kbd\0" as *const u8 as *const libc::c_char,
    b"var\0" as *const u8 as *const libc::c_char,
    b"cite\0" as *const u8 as *const libc::c_char,
    b"abbr\0" as *const u8 as *const libc::c_char,
    b"acronym\0" as *const u8 as *const libc::c_char,
    b"a\0" as *const u8 as *const libc::c_char,
    b"img\0" as *const u8 as *const libc::c_char,
    b"applet\0" as *const u8 as *const libc::c_char,
    b"embed\0" as *const u8 as *const libc::c_char,
    b"object\0" as *const u8 as *const libc::c_char,
    b"font\0" as *const u8 as *const libc::c_char,
    b"basefont\0" as *const u8 as *const libc::c_char,
    b"br\0" as *const u8 as *const libc::c_char,
    b"script\0" as *const u8 as *const libc::c_char,
    b"map\0" as *const u8 as *const libc::c_char,
    b"q\0" as *const u8 as *const libc::c_char,
    b"sub\0" as *const u8 as *const libc::c_char,
    b"sup\0" as *const u8 as *const libc::c_char,
    b"span\0" as *const u8 as *const libc::c_char,
    b"bdo\0" as *const u8 as *const libc::c_char,
    b"iframe\0" as *const u8 as *const libc::c_char,
    b"input\0" as *const u8 as *const libc::c_char,
    b"select\0" as *const u8 as *const libc::c_char,
    b"textarea\0" as *const u8 as *const libc::c_char,
    b"label\0" as *const u8 as *const libc::c_char,
    b"button\0" as *const u8 as *const libc::c_char,
    b"ins\0" as *const u8 as *const libc::c_char,
    b"del\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut body_attrs: [*const libc::c_char; 18] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"onload\0" as *const u8 as *const libc::c_char,
    b"onunload\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut body_depr: [*const libc::c_char; 7] = [
    b"background\0" as *const u8 as *const libc::c_char,
    b"bgcolor\0" as *const u8 as *const libc::c_char,
    b"text\0" as *const u8 as *const libc::c_char,
    b"link\0" as *const u8 as *const libc::c_char,
    b"vlink\0" as *const u8 as *const libc::c_char,
    b"alink\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut button_attrs: [*const libc::c_char; 24] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"name\0" as *const u8 as *const libc::c_char,
    b"value\0" as *const u8 as *const libc::c_char,
    b"type\0" as *const u8 as *const libc::c_char,
    b"disabled\0" as *const u8 as *const libc::c_char,
    b"tabindex\0" as *const u8 as *const libc::c_char,
    b"accesskey\0" as *const u8 as *const libc::c_char,
    b"onfocus\0" as *const u8 as *const libc::c_char,
    b"onblur\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut col_attrs: [*const libc::c_char; 22] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"span\0" as *const u8 as *const libc::c_char,
    b"width\0" as *const u8 as *const libc::c_char,
    b"align\0" as *const u8 as *const libc::c_char,
    b"char\0" as *const u8 as *const libc::c_char,
    b"charoff\0" as *const u8 as *const libc::c_char,
    b"valign\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut col_elt: [*const libc::c_char; 2] = [
    b"col\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut edit_attrs: [*const libc::c_char; 18] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"datetime\0" as *const u8 as *const libc::c_char,
    b"cite\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut compact_attrs: [*const libc::c_char; 17] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"compact\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut dl_contents: [*const libc::c_char; 3] = [
    b"dt\0" as *const u8 as *const libc::c_char,
    b"dd\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut compact_attr: [*const libc::c_char; 2] = [
    b"compact\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut label_attr: [*const libc::c_char; 2] = [
    b"label\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut fieldset_contents: [*const libc::c_char; 64] = [
    b"h1\0" as *const u8 as *const libc::c_char,
    b"h2\0" as *const u8 as *const libc::c_char,
    b"h3\0" as *const u8 as *const libc::c_char,
    b"h4\0" as *const u8 as *const libc::c_char,
    b"h5\0" as *const u8 as *const libc::c_char,
    b"h6\0" as *const u8 as *const libc::c_char,
    b"ul\0" as *const u8 as *const libc::c_char,
    b"ol\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"menu\0" as *const u8 as *const libc::c_char,
    b"pre\0" as *const u8 as *const libc::c_char,
    b"p\0" as *const u8 as *const libc::c_char,
    b"dl\0" as *const u8 as *const libc::c_char,
    b"div\0" as *const u8 as *const libc::c_char,
    b"center\0" as *const u8 as *const libc::c_char,
    b"noscript\0" as *const u8 as *const libc::c_char,
    b"noframes\0" as *const u8 as *const libc::c_char,
    b"blockquote\0" as *const u8 as *const libc::c_char,
    b"form\0" as *const u8 as *const libc::c_char,
    b"isindex\0" as *const u8 as *const libc::c_char,
    b"hr\0" as *const u8 as *const libc::c_char,
    b"table\0" as *const u8 as *const libc::c_char,
    b"fieldset\0" as *const u8 as *const libc::c_char,
    b"address\0" as *const u8 as *const libc::c_char,
    b"tt\0" as *const u8 as *const libc::c_char,
    b"i\0" as *const u8 as *const libc::c_char,
    b"b\0" as *const u8 as *const libc::c_char,
    b"u\0" as *const u8 as *const libc::c_char,
    b"s\0" as *const u8 as *const libc::c_char,
    b"strike\0" as *const u8 as *const libc::c_char,
    b"big\0" as *const u8 as *const libc::c_char,
    b"small\0" as *const u8 as *const libc::c_char,
    b"em\0" as *const u8 as *const libc::c_char,
    b"strong\0" as *const u8 as *const libc::c_char,
    b"dfn\0" as *const u8 as *const libc::c_char,
    b"code\0" as *const u8 as *const libc::c_char,
    b"samp\0" as *const u8 as *const libc::c_char,
    b"kbd\0" as *const u8 as *const libc::c_char,
    b"var\0" as *const u8 as *const libc::c_char,
    b"cite\0" as *const u8 as *const libc::c_char,
    b"abbr\0" as *const u8 as *const libc::c_char,
    b"acronym\0" as *const u8 as *const libc::c_char,
    b"a\0" as *const u8 as *const libc::c_char,
    b"img\0" as *const u8 as *const libc::c_char,
    b"applet\0" as *const u8 as *const libc::c_char,
    b"embed\0" as *const u8 as *const libc::c_char,
    b"object\0" as *const u8 as *const libc::c_char,
    b"font\0" as *const u8 as *const libc::c_char,
    b"basefont\0" as *const u8 as *const libc::c_char,
    b"br\0" as *const u8 as *const libc::c_char,
    b"script\0" as *const u8 as *const libc::c_char,
    b"map\0" as *const u8 as *const libc::c_char,
    b"q\0" as *const u8 as *const libc::c_char,
    b"sub\0" as *const u8 as *const libc::c_char,
    b"sup\0" as *const u8 as *const libc::c_char,
    b"span\0" as *const u8 as *const libc::c_char,
    b"bdo\0" as *const u8 as *const libc::c_char,
    b"iframe\0" as *const u8 as *const libc::c_char,
    b"input\0" as *const u8 as *const libc::c_char,
    b"select\0" as *const u8 as *const libc::c_char,
    b"textarea\0" as *const u8 as *const libc::c_char,
    b"label\0" as *const u8 as *const libc::c_char,
    b"button\0" as *const u8 as *const libc::c_char,
    b"legend\0" as *const u8 as *const libc::c_char,
];
static mut font_attrs: [*const libc::c_char; 10] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"size\0" as *const u8 as *const libc::c_char,
    b"color\0" as *const u8 as *const libc::c_char,
    b"face\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut form_contents: [*const libc::c_char; 62] = [
    b"h1\0" as *const u8 as *const libc::c_char,
    b"h2\0" as *const u8 as *const libc::c_char,
    b"h3\0" as *const u8 as *const libc::c_char,
    b"h4\0" as *const u8 as *const libc::c_char,
    b"h5\0" as *const u8 as *const libc::c_char,
    b"h6\0" as *const u8 as *const libc::c_char,
    b"ul\0" as *const u8 as *const libc::c_char,
    b"ol\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"menu\0" as *const u8 as *const libc::c_char,
    b"tt\0" as *const u8 as *const libc::c_char,
    b"i\0" as *const u8 as *const libc::c_char,
    b"b\0" as *const u8 as *const libc::c_char,
    b"u\0" as *const u8 as *const libc::c_char,
    b"s\0" as *const u8 as *const libc::c_char,
    b"strike\0" as *const u8 as *const libc::c_char,
    b"big\0" as *const u8 as *const libc::c_char,
    b"small\0" as *const u8 as *const libc::c_char,
    b"em\0" as *const u8 as *const libc::c_char,
    b"strong\0" as *const u8 as *const libc::c_char,
    b"dfn\0" as *const u8 as *const libc::c_char,
    b"code\0" as *const u8 as *const libc::c_char,
    b"samp\0" as *const u8 as *const libc::c_char,
    b"kbd\0" as *const u8 as *const libc::c_char,
    b"var\0" as *const u8 as *const libc::c_char,
    b"cite\0" as *const u8 as *const libc::c_char,
    b"abbr\0" as *const u8 as *const libc::c_char,
    b"acronym\0" as *const u8 as *const libc::c_char,
    b"a\0" as *const u8 as *const libc::c_char,
    b"img\0" as *const u8 as *const libc::c_char,
    b"applet\0" as *const u8 as *const libc::c_char,
    b"embed\0" as *const u8 as *const libc::c_char,
    b"object\0" as *const u8 as *const libc::c_char,
    b"font\0" as *const u8 as *const libc::c_char,
    b"basefont\0" as *const u8 as *const libc::c_char,
    b"br\0" as *const u8 as *const libc::c_char,
    b"script\0" as *const u8 as *const libc::c_char,
    b"map\0" as *const u8 as *const libc::c_char,
    b"q\0" as *const u8 as *const libc::c_char,
    b"sub\0" as *const u8 as *const libc::c_char,
    b"sup\0" as *const u8 as *const libc::c_char,
    b"span\0" as *const u8 as *const libc::c_char,
    b"bdo\0" as *const u8 as *const libc::c_char,
    b"iframe\0" as *const u8 as *const libc::c_char,
    b"input\0" as *const u8 as *const libc::c_char,
    b"select\0" as *const u8 as *const libc::c_char,
    b"textarea\0" as *const u8 as *const libc::c_char,
    b"label\0" as *const u8 as *const libc::c_char,
    b"button\0" as *const u8 as *const libc::c_char,
    b"pre\0" as *const u8 as *const libc::c_char,
    b"p\0" as *const u8 as *const libc::c_char,
    b"div\0" as *const u8 as *const libc::c_char,
    b"center\0" as *const u8 as *const libc::c_char,
    b"noscript\0" as *const u8 as *const libc::c_char,
    b"noframes\0" as *const u8 as *const libc::c_char,
    b"blockquote\0" as *const u8 as *const libc::c_char,
    b"isindex\0" as *const u8 as *const libc::c_char,
    b"hr\0" as *const u8 as *const libc::c_char,
    b"table\0" as *const u8 as *const libc::c_char,
    b"fieldset\0" as *const u8 as *const libc::c_char,
    b"address\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut form_attrs: [*const libc::c_char; 23] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"method\0" as *const u8 as *const libc::c_char,
    b"enctype\0" as *const u8 as *const libc::c_char,
    b"accept\0" as *const u8 as *const libc::c_char,
    b"name\0" as *const u8 as *const libc::c_char,
    b"onsubmit\0" as *const u8 as *const libc::c_char,
    b"onreset\0" as *const u8 as *const libc::c_char,
    b"accept-charset\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut frame_attrs: [*const libc::c_char; 13] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"longdesc\0" as *const u8 as *const libc::c_char,
    b"name\0" as *const u8 as *const libc::c_char,
    b"src\0" as *const u8 as *const libc::c_char,
    b"frameborder\0" as *const u8 as *const libc::c_char,
    b"marginwidth\0" as *const u8 as *const libc::c_char,
    b"marginheight\0" as *const u8 as *const libc::c_char,
    b"noresize\0" as *const u8 as *const libc::c_char,
    b"scrolling\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut frameset_attrs: [*const libc::c_char; 9] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"rows\0" as *const u8 as *const libc::c_char,
    b"cols\0" as *const u8 as *const libc::c_char,
    b"onload\0" as *const u8 as *const libc::c_char,
    b"onunload\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut frameset_contents: [*const libc::c_char; 4] = [
    b"frameset\0" as *const u8 as *const libc::c_char,
    b"frame\0" as *const u8 as *const libc::c_char,
    b"noframes\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut head_attrs: [*const libc::c_char; 4] = [
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"profile\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut head_contents: [*const libc::c_char; 9] = [
    b"title\0" as *const u8 as *const libc::c_char,
    b"isindex\0" as *const u8 as *const libc::c_char,
    b"base\0" as *const u8 as *const libc::c_char,
    b"script\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"meta\0" as *const u8 as *const libc::c_char,
    b"link\0" as *const u8 as *const libc::c_char,
    b"object\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut hr_depr: [*const libc::c_char; 5] = [
    b"align\0" as *const u8 as *const libc::c_char,
    b"noshade\0" as *const u8 as *const libc::c_char,
    b"size\0" as *const u8 as *const libc::c_char,
    b"width\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut version_attr: [*const libc::c_char; 2] = [
    b"version\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut html_content: [*const libc::c_char; 4] = [
    b"head\0" as *const u8 as *const libc::c_char,
    b"body\0" as *const u8 as *const libc::c_char,
    b"frameset\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut iframe_attrs: [*const libc::c_char; 15] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"longdesc\0" as *const u8 as *const libc::c_char,
    b"name\0" as *const u8 as *const libc::c_char,
    b"src\0" as *const u8 as *const libc::c_char,
    b"frameborder\0" as *const u8 as *const libc::c_char,
    b"marginwidth\0" as *const u8 as *const libc::c_char,
    b"marginheight\0" as *const u8 as *const libc::c_char,
    b"scrolling\0" as *const u8 as *const libc::c_char,
    b"align\0" as *const u8 as *const libc::c_char,
    b"height\0" as *const u8 as *const libc::c_char,
    b"width\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut img_attrs: [*const libc::c_char; 22] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"longdesc\0" as *const u8 as *const libc::c_char,
    b"name\0" as *const u8 as *const libc::c_char,
    b"height\0" as *const u8 as *const libc::c_char,
    b"width\0" as *const u8 as *const libc::c_char,
    b"usemap\0" as *const u8 as *const libc::c_char,
    b"ismap\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut embed_attrs: [*const libc::c_char; 23] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"align\0" as *const u8 as *const libc::c_char,
    b"alt\0" as *const u8 as *const libc::c_char,
    b"border\0" as *const u8 as *const libc::c_char,
    b"code\0" as *const u8 as *const libc::c_char,
    b"codebase\0" as *const u8 as *const libc::c_char,
    b"frameborder\0" as *const u8 as *const libc::c_char,
    b"height\0" as *const u8 as *const libc::c_char,
    b"hidden\0" as *const u8 as *const libc::c_char,
    b"hspace\0" as *const u8 as *const libc::c_char,
    b"name\0" as *const u8 as *const libc::c_char,
    b"palette\0" as *const u8 as *const libc::c_char,
    b"pluginspace\0" as *const u8 as *const libc::c_char,
    b"pluginurl\0" as *const u8 as *const libc::c_char,
    b"src\0" as *const u8 as *const libc::c_char,
    b"type\0" as *const u8 as *const libc::c_char,
    b"units\0" as *const u8 as *const libc::c_char,
    b"vspace\0" as *const u8 as *const libc::c_char,
    b"width\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut input_attrs: [*const libc::c_char; 35] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"type\0" as *const u8 as *const libc::c_char,
    b"name\0" as *const u8 as *const libc::c_char,
    b"value\0" as *const u8 as *const libc::c_char,
    b"checked\0" as *const u8 as *const libc::c_char,
    b"disabled\0" as *const u8 as *const libc::c_char,
    b"readonly\0" as *const u8 as *const libc::c_char,
    b"size\0" as *const u8 as *const libc::c_char,
    b"maxlength\0" as *const u8 as *const libc::c_char,
    b"src\0" as *const u8 as *const libc::c_char,
    b"alt\0" as *const u8 as *const libc::c_char,
    b"usemap\0" as *const u8 as *const libc::c_char,
    b"ismap\0" as *const u8 as *const libc::c_char,
    b"tabindex\0" as *const u8 as *const libc::c_char,
    b"accesskey\0" as *const u8 as *const libc::c_char,
    b"onfocus\0" as *const u8 as *const libc::c_char,
    b"onblur\0" as *const u8 as *const libc::c_char,
    b"onselect\0" as *const u8 as *const libc::c_char,
    b"onchange\0" as *const u8 as *const libc::c_char,
    b"accept\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut prompt_attrs: [*const libc::c_char; 8] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"prompt\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut label_attrs: [*const libc::c_char; 20] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"for\0" as *const u8 as *const libc::c_char,
    b"accesskey\0" as *const u8 as *const libc::c_char,
    b"onfocus\0" as *const u8 as *const libc::c_char,
    b"onblur\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut legend_attrs: [*const libc::c_char; 17] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"accesskey\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut align_attr: [*const libc::c_char; 2] = [
    b"align\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut link_attrs: [*const libc::c_char; 23] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"charset\0" as *const u8 as *const libc::c_char,
    b"href\0" as *const u8 as *const libc::c_char,
    b"hreflang\0" as *const u8 as *const libc::c_char,
    b"type\0" as *const u8 as *const libc::c_char,
    b"rel\0" as *const u8 as *const libc::c_char,
    b"rev\0" as *const u8 as *const libc::c_char,
    b"media\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut map_contents: [*const libc::c_char; 26] = [
    b"h1\0" as *const u8 as *const libc::c_char,
    b"h2\0" as *const u8 as *const libc::c_char,
    b"h3\0" as *const u8 as *const libc::c_char,
    b"h4\0" as *const u8 as *const libc::c_char,
    b"h5\0" as *const u8 as *const libc::c_char,
    b"h6\0" as *const u8 as *const libc::c_char,
    b"ul\0" as *const u8 as *const libc::c_char,
    b"ol\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"menu\0" as *const u8 as *const libc::c_char,
    b"pre\0" as *const u8 as *const libc::c_char,
    b"p\0" as *const u8 as *const libc::c_char,
    b"dl\0" as *const u8 as *const libc::c_char,
    b"div\0" as *const u8 as *const libc::c_char,
    b"center\0" as *const u8 as *const libc::c_char,
    b"noscript\0" as *const u8 as *const libc::c_char,
    b"noframes\0" as *const u8 as *const libc::c_char,
    b"blockquote\0" as *const u8 as *const libc::c_char,
    b"form\0" as *const u8 as *const libc::c_char,
    b"isindex\0" as *const u8 as *const libc::c_char,
    b"hr\0" as *const u8 as *const libc::c_char,
    b"table\0" as *const u8 as *const libc::c_char,
    b"fieldset\0" as *const u8 as *const libc::c_char,
    b"address\0" as *const u8 as *const libc::c_char,
    b"area\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut name_attr: [*const libc::c_char; 2] = [
    b"name\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut action_attr: [*const libc::c_char; 2] = [
    b"action\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut blockli_elt: [*const libc::c_char; 26] = [
    b"h1\0" as *const u8 as *const libc::c_char,
    b"h2\0" as *const u8 as *const libc::c_char,
    b"h3\0" as *const u8 as *const libc::c_char,
    b"h4\0" as *const u8 as *const libc::c_char,
    b"h5\0" as *const u8 as *const libc::c_char,
    b"h6\0" as *const u8 as *const libc::c_char,
    b"ul\0" as *const u8 as *const libc::c_char,
    b"ol\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"menu\0" as *const u8 as *const libc::c_char,
    b"pre\0" as *const u8 as *const libc::c_char,
    b"p\0" as *const u8 as *const libc::c_char,
    b"dl\0" as *const u8 as *const libc::c_char,
    b"div\0" as *const u8 as *const libc::c_char,
    b"center\0" as *const u8 as *const libc::c_char,
    b"noscript\0" as *const u8 as *const libc::c_char,
    b"noframes\0" as *const u8 as *const libc::c_char,
    b"blockquote\0" as *const u8 as *const libc::c_char,
    b"form\0" as *const u8 as *const libc::c_char,
    b"isindex\0" as *const u8 as *const libc::c_char,
    b"hr\0" as *const u8 as *const libc::c_char,
    b"table\0" as *const u8 as *const libc::c_char,
    b"fieldset\0" as *const u8 as *const libc::c_char,
    b"address\0" as *const u8 as *const libc::c_char,
    b"li\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut meta_attrs: [*const libc::c_char; 7] = [
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"http-equiv\0" as *const u8 as *const libc::c_char,
    b"name\0" as *const u8 as *const libc::c_char,
    b"scheme\0" as *const u8 as *const libc::c_char,
    b"charset\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut content_attr: [*const libc::c_char; 2] = [
    b"content\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut type_attr: [*const libc::c_char; 2] = [
    b"type\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut noframes_content: [*const libc::c_char; 65] = [
    b"body\0" as *const u8 as *const libc::c_char,
    b"h1\0" as *const u8 as *const libc::c_char,
    b"h2\0" as *const u8 as *const libc::c_char,
    b"h3\0" as *const u8 as *const libc::c_char,
    b"h4\0" as *const u8 as *const libc::c_char,
    b"h5\0" as *const u8 as *const libc::c_char,
    b"h6\0" as *const u8 as *const libc::c_char,
    b"ul\0" as *const u8 as *const libc::c_char,
    b"ol\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"menu\0" as *const u8 as *const libc::c_char,
    b"pre\0" as *const u8 as *const libc::c_char,
    b"p\0" as *const u8 as *const libc::c_char,
    b"dl\0" as *const u8 as *const libc::c_char,
    b"div\0" as *const u8 as *const libc::c_char,
    b"center\0" as *const u8 as *const libc::c_char,
    b"noscript\0" as *const u8 as *const libc::c_char,
    b"noframes\0" as *const u8 as *const libc::c_char,
    b"blockquote\0" as *const u8 as *const libc::c_char,
    b"form\0" as *const u8 as *const libc::c_char,
    b"isindex\0" as *const u8 as *const libc::c_char,
    b"hr\0" as *const u8 as *const libc::c_char,
    b"table\0" as *const u8 as *const libc::c_char,
    b"fieldset\0" as *const u8 as *const libc::c_char,
    b"address\0" as *const u8 as *const libc::c_char,
    b"tt\0" as *const u8 as *const libc::c_char,
    b"i\0" as *const u8 as *const libc::c_char,
    b"b\0" as *const u8 as *const libc::c_char,
    b"u\0" as *const u8 as *const libc::c_char,
    b"s\0" as *const u8 as *const libc::c_char,
    b"strike\0" as *const u8 as *const libc::c_char,
    b"big\0" as *const u8 as *const libc::c_char,
    b"small\0" as *const u8 as *const libc::c_char,
    b"em\0" as *const u8 as *const libc::c_char,
    b"strong\0" as *const u8 as *const libc::c_char,
    b"dfn\0" as *const u8 as *const libc::c_char,
    b"code\0" as *const u8 as *const libc::c_char,
    b"samp\0" as *const u8 as *const libc::c_char,
    b"kbd\0" as *const u8 as *const libc::c_char,
    b"var\0" as *const u8 as *const libc::c_char,
    b"cite\0" as *const u8 as *const libc::c_char,
    b"abbr\0" as *const u8 as *const libc::c_char,
    b"acronym\0" as *const u8 as *const libc::c_char,
    b"a\0" as *const u8 as *const libc::c_char,
    b"img\0" as *const u8 as *const libc::c_char,
    b"applet\0" as *const u8 as *const libc::c_char,
    b"embed\0" as *const u8 as *const libc::c_char,
    b"object\0" as *const u8 as *const libc::c_char,
    b"font\0" as *const u8 as *const libc::c_char,
    b"basefont\0" as *const u8 as *const libc::c_char,
    b"br\0" as *const u8 as *const libc::c_char,
    b"script\0" as *const u8 as *const libc::c_char,
    b"map\0" as *const u8 as *const libc::c_char,
    b"q\0" as *const u8 as *const libc::c_char,
    b"sub\0" as *const u8 as *const libc::c_char,
    b"sup\0" as *const u8 as *const libc::c_char,
    b"span\0" as *const u8 as *const libc::c_char,
    b"bdo\0" as *const u8 as *const libc::c_char,
    b"iframe\0" as *const u8 as *const libc::c_char,
    b"input\0" as *const u8 as *const libc::c_char,
    b"select\0" as *const u8 as *const libc::c_char,
    b"textarea\0" as *const u8 as *const libc::c_char,
    b"label\0" as *const u8 as *const libc::c_char,
    b"button\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut object_contents: [*const libc::c_char; 65] = [
    b"h1\0" as *const u8 as *const libc::c_char,
    b"h2\0" as *const u8 as *const libc::c_char,
    b"h3\0" as *const u8 as *const libc::c_char,
    b"h4\0" as *const u8 as *const libc::c_char,
    b"h5\0" as *const u8 as *const libc::c_char,
    b"h6\0" as *const u8 as *const libc::c_char,
    b"ul\0" as *const u8 as *const libc::c_char,
    b"ol\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"menu\0" as *const u8 as *const libc::c_char,
    b"pre\0" as *const u8 as *const libc::c_char,
    b"p\0" as *const u8 as *const libc::c_char,
    b"dl\0" as *const u8 as *const libc::c_char,
    b"div\0" as *const u8 as *const libc::c_char,
    b"center\0" as *const u8 as *const libc::c_char,
    b"noscript\0" as *const u8 as *const libc::c_char,
    b"noframes\0" as *const u8 as *const libc::c_char,
    b"blockquote\0" as *const u8 as *const libc::c_char,
    b"form\0" as *const u8 as *const libc::c_char,
    b"isindex\0" as *const u8 as *const libc::c_char,
    b"hr\0" as *const u8 as *const libc::c_char,
    b"table\0" as *const u8 as *const libc::c_char,
    b"fieldset\0" as *const u8 as *const libc::c_char,
    b"address\0" as *const u8 as *const libc::c_char,
    b"tt\0" as *const u8 as *const libc::c_char,
    b"i\0" as *const u8 as *const libc::c_char,
    b"b\0" as *const u8 as *const libc::c_char,
    b"u\0" as *const u8 as *const libc::c_char,
    b"s\0" as *const u8 as *const libc::c_char,
    b"strike\0" as *const u8 as *const libc::c_char,
    b"big\0" as *const u8 as *const libc::c_char,
    b"small\0" as *const u8 as *const libc::c_char,
    b"em\0" as *const u8 as *const libc::c_char,
    b"strong\0" as *const u8 as *const libc::c_char,
    b"dfn\0" as *const u8 as *const libc::c_char,
    b"code\0" as *const u8 as *const libc::c_char,
    b"samp\0" as *const u8 as *const libc::c_char,
    b"kbd\0" as *const u8 as *const libc::c_char,
    b"var\0" as *const u8 as *const libc::c_char,
    b"cite\0" as *const u8 as *const libc::c_char,
    b"abbr\0" as *const u8 as *const libc::c_char,
    b"acronym\0" as *const u8 as *const libc::c_char,
    b"a\0" as *const u8 as *const libc::c_char,
    b"img\0" as *const u8 as *const libc::c_char,
    b"applet\0" as *const u8 as *const libc::c_char,
    b"embed\0" as *const u8 as *const libc::c_char,
    b"object\0" as *const u8 as *const libc::c_char,
    b"font\0" as *const u8 as *const libc::c_char,
    b"basefont\0" as *const u8 as *const libc::c_char,
    b"br\0" as *const u8 as *const libc::c_char,
    b"script\0" as *const u8 as *const libc::c_char,
    b"map\0" as *const u8 as *const libc::c_char,
    b"q\0" as *const u8 as *const libc::c_char,
    b"sub\0" as *const u8 as *const libc::c_char,
    b"sup\0" as *const u8 as *const libc::c_char,
    b"span\0" as *const u8 as *const libc::c_char,
    b"bdo\0" as *const u8 as *const libc::c_char,
    b"iframe\0" as *const u8 as *const libc::c_char,
    b"input\0" as *const u8 as *const libc::c_char,
    b"select\0" as *const u8 as *const libc::c_char,
    b"textarea\0" as *const u8 as *const libc::c_char,
    b"label\0" as *const u8 as *const libc::c_char,
    b"button\0" as *const u8 as *const libc::c_char,
    b"param\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut object_attrs: [*const libc::c_char; 29] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"declare\0" as *const u8 as *const libc::c_char,
    b"classid\0" as *const u8 as *const libc::c_char,
    b"codebase\0" as *const u8 as *const libc::c_char,
    b"data\0" as *const u8 as *const libc::c_char,
    b"type\0" as *const u8 as *const libc::c_char,
    b"codetype\0" as *const u8 as *const libc::c_char,
    b"archive\0" as *const u8 as *const libc::c_char,
    b"standby\0" as *const u8 as *const libc::c_char,
    b"height\0" as *const u8 as *const libc::c_char,
    b"width\0" as *const u8 as *const libc::c_char,
    b"usemap\0" as *const u8 as *const libc::c_char,
    b"name\0" as *const u8 as *const libc::c_char,
    b"tabindex\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut object_depr: [*const libc::c_char; 5] = [
    b"align\0" as *const u8 as *const libc::c_char,
    b"border\0" as *const u8 as *const libc::c_char,
    b"hspace\0" as *const u8 as *const libc::c_char,
    b"vspace\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut ol_attrs: [*const libc::c_char; 4] = [
    b"type\0" as *const u8 as *const libc::c_char,
    b"compact\0" as *const u8 as *const libc::c_char,
    b"start\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut option_elt: [*const libc::c_char; 2] = [
    b"option\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut optgroup_attrs: [*const libc::c_char; 17] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"disabled\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut option_attrs: [*const libc::c_char; 20] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"disabled\0" as *const u8 as *const libc::c_char,
    b"label\0" as *const u8 as *const libc::c_char,
    b"selected\0" as *const u8 as *const libc::c_char,
    b"value\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut param_attrs: [*const libc::c_char; 5] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"value\0" as *const u8 as *const libc::c_char,
    b"valuetype\0" as *const u8 as *const libc::c_char,
    b"type\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut width_attr: [*const libc::c_char; 2] = [
    b"width\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut pre_content: [*const libc::c_char; 25] = [
    b"em\0" as *const u8 as *const libc::c_char,
    b"strong\0" as *const u8 as *const libc::c_char,
    b"dfn\0" as *const u8 as *const libc::c_char,
    b"code\0" as *const u8 as *const libc::c_char,
    b"samp\0" as *const u8 as *const libc::c_char,
    b"kbd\0" as *const u8 as *const libc::c_char,
    b"var\0" as *const u8 as *const libc::c_char,
    b"cite\0" as *const u8 as *const libc::c_char,
    b"abbr\0" as *const u8 as *const libc::c_char,
    b"acronym\0" as *const u8 as *const libc::c_char,
    b"tt\0" as *const u8 as *const libc::c_char,
    b"i\0" as *const u8 as *const libc::c_char,
    b"b\0" as *const u8 as *const libc::c_char,
    b"u\0" as *const u8 as *const libc::c_char,
    b"s\0" as *const u8 as *const libc::c_char,
    b"strike\0" as *const u8 as *const libc::c_char,
    b"a\0" as *const u8 as *const libc::c_char,
    b"br\0" as *const u8 as *const libc::c_char,
    b"script\0" as *const u8 as *const libc::c_char,
    b"map\0" as *const u8 as *const libc::c_char,
    b"q\0" as *const u8 as *const libc::c_char,
    b"span\0" as *const u8 as *const libc::c_char,
    b"bdo\0" as *const u8 as *const libc::c_char,
    b"iframe\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut script_attrs: [*const libc::c_char; 6] = [
    b"charset\0" as *const u8 as *const libc::c_char,
    b"src\0" as *const u8 as *const libc::c_char,
    b"defer\0" as *const u8 as *const libc::c_char,
    b"event\0" as *const u8 as *const libc::c_char,
    b"for\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut language_attr: [*const libc::c_char; 2] = [
    b"language\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut select_content: [*const libc::c_char; 3] = [
    b"optgroup\0" as *const u8 as *const libc::c_char,
    b"option\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut select_attrs: [*const libc::c_char; 24] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"name\0" as *const u8 as *const libc::c_char,
    b"size\0" as *const u8 as *const libc::c_char,
    b"multiple\0" as *const u8 as *const libc::c_char,
    b"disabled\0" as *const u8 as *const libc::c_char,
    b"tabindex\0" as *const u8 as *const libc::c_char,
    b"onfocus\0" as *const u8 as *const libc::c_char,
    b"onblur\0" as *const u8 as *const libc::c_char,
    b"onchange\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut style_attrs: [*const libc::c_char; 5] = [
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"media\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut table_attrs: [*const libc::c_char; 24] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"summary\0" as *const u8 as *const libc::c_char,
    b"width\0" as *const u8 as *const libc::c_char,
    b"border\0" as *const u8 as *const libc::c_char,
    b"frame\0" as *const u8 as *const libc::c_char,
    b"rules\0" as *const u8 as *const libc::c_char,
    b"cellspacing\0" as *const u8 as *const libc::c_char,
    b"cellpadding\0" as *const u8 as *const libc::c_char,
    b"datapagesize\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut table_depr: [*const libc::c_char; 3] = [
    b"align\0" as *const u8 as *const libc::c_char,
    b"bgcolor\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut table_contents: [*const libc::c_char; 8] = [
    b"caption\0" as *const u8 as *const libc::c_char,
    b"col\0" as *const u8 as *const libc::c_char,
    b"colgroup\0" as *const u8 as *const libc::c_char,
    b"thead\0" as *const u8 as *const libc::c_char,
    b"tfoot\0" as *const u8 as *const libc::c_char,
    b"tbody\0" as *const u8 as *const libc::c_char,
    b"tr\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut tr_elt: [*const libc::c_char; 2] = [
    b"tr\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut talign_attrs: [*const libc::c_char; 20] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"align\0" as *const u8 as *const libc::c_char,
    b"char\0" as *const u8 as *const libc::c_char,
    b"charoff\0" as *const u8 as *const libc::c_char,
    b"valign\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut th_td_depr: [*const libc::c_char; 5] = [
    b"nowrap\0" as *const u8 as *const libc::c_char,
    b"bgcolor\0" as *const u8 as *const libc::c_char,
    b"width\0" as *const u8 as *const libc::c_char,
    b"height\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut th_td_attr: [*const libc::c_char; 26] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"abbr\0" as *const u8 as *const libc::c_char,
    b"axis\0" as *const u8 as *const libc::c_char,
    b"headers\0" as *const u8 as *const libc::c_char,
    b"scope\0" as *const u8 as *const libc::c_char,
    b"rowspan\0" as *const u8 as *const libc::c_char,
    b"colspan\0" as *const u8 as *const libc::c_char,
    b"align\0" as *const u8 as *const libc::c_char,
    b"char\0" as *const u8 as *const libc::c_char,
    b"charoff\0" as *const u8 as *const libc::c_char,
    b"valign\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut textarea_attrs: [*const libc::c_char; 25] = [
    b"id\0" as *const u8 as *const libc::c_char,
    b"class\0" as *const u8 as *const libc::c_char,
    b"style\0" as *const u8 as *const libc::c_char,
    b"title\0" as *const u8 as *const libc::c_char,
    b"lang\0" as *const u8 as *const libc::c_char,
    b"dir\0" as *const u8 as *const libc::c_char,
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"name\0" as *const u8 as *const libc::c_char,
    b"disabled\0" as *const u8 as *const libc::c_char,
    b"readonly\0" as *const u8 as *const libc::c_char,
    b"tabindex\0" as *const u8 as *const libc::c_char,
    b"accesskey\0" as *const u8 as *const libc::c_char,
    b"onfocus\0" as *const u8 as *const libc::c_char,
    b"onblur\0" as *const u8 as *const libc::c_char,
    b"onselect\0" as *const u8 as *const libc::c_char,
    b"onchange\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut tr_contents: [*const libc::c_char; 3] = [
    b"th\0" as *const u8 as *const libc::c_char,
    b"td\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut bgcolor_attr: [*const libc::c_char; 2] = [
    b"bgcolor\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut li_elt: [*const libc::c_char; 2] = [
    b"li\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut ul_depr: [*const libc::c_char; 3] = [
    b"type\0" as *const u8 as *const libc::c_char,
    b"compact\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut dir_attr: [*const libc::c_char; 2] = [
    b"dir\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut html40ElementTable: [htmlElemDesc; 92] = unsafe {
    [
        {
            let mut init = _htmlElemDesc {
                name: b"a\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"anchor \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: a_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: target_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"abbr\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"abbreviated form\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"acronym\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"address\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"information on author \0" as *const u8 as *const libc::c_char,
                subelts: inline_p.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"applet\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 1 as libc::c_int as libc::c_char,
                dtd: 1 as libc::c_int as libc::c_char,
                isinline: 2 as libc::c_int as libc::c_char,
                desc: b"java applet \0" as *const u8 as *const libc::c_char,
                subelts: flow_param.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: applet_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"area\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 2 as libc::c_int as libc::c_char,
                saveEndTag: 2 as libc::c_int as libc::c_char,
                empty: 1 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"client-side image map area \0" as *const u8
                    as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: area_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: target_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: alt_attr.as_ptr() as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"b\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"bold text style\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"base\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 2 as libc::c_int as libc::c_char,
                saveEndTag: 2 as libc::c_int as libc::c_char,
                empty: 1 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"document base uri \0" as *const u8 as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: target_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: href_attrs.as_ptr() as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"basefont\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 2 as libc::c_int as libc::c_char,
                saveEndTag: 2 as libc::c_int as libc::c_char,
                empty: 1 as libc::c_int as libc::c_char,
                depr: 1 as libc::c_int as libc::c_char,
                dtd: 1 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"base font size \0" as *const u8 as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: basefont_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"bdo\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"i18n bidi over-ride \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: core_i18n_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: dir_attr.as_ptr() as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"big\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"large text style\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"blockquote\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"long quotation \0" as *const u8 as *const libc::c_char,
                subelts: html_flow.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: quote_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"body\0" as *const u8 as *const libc::c_char,
                startTag: 1 as libc::c_int as libc::c_char,
                endTag: 1 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"document body \0" as *const u8 as *const libc::c_char,
                subelts: body_contents.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"div\0" as *const u8 as *const libc::c_char,
                attrs_opt: body_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: body_depr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"br\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 2 as libc::c_int as libc::c_char,
                saveEndTag: 2 as libc::c_int as libc::c_char,
                empty: 1 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"forced line break \0" as *const u8 as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: core_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: clear_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"button\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 2 as libc::c_int as libc::c_char,
                desc: b"push button \0" as *const u8 as *const libc::c_char,
                subelts: html_flow.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: button_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"caption\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"table caption \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"center\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 1 as libc::c_int as libc::c_char,
                dtd: 1 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"shorthand for div align=center \0" as *const u8
                    as *const libc::c_char,
                subelts: html_flow.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"cite\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"citation\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"code\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"computer code fragment\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"col\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 2 as libc::c_int as libc::c_char,
                saveEndTag: 2 as libc::c_int as libc::c_char,
                empty: 1 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"table column \0" as *const u8 as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: col_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"colgroup\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 1 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"table column group \0" as *const u8 as *const libc::c_char,
                subelts: col_elt.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"col\0" as *const u8 as *const libc::c_char,
                attrs_opt: col_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"dd\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 1 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"definition description \0" as *const u8 as *const libc::c_char,
                subelts: html_flow.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"del\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 2 as libc::c_int as libc::c_char,
                desc: b"deleted text \0" as *const u8 as *const libc::c_char,
                subelts: html_flow.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: edit_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"dfn\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"instance definition\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"dir\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 1 as libc::c_int as libc::c_char,
                dtd: 1 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"directory list\0" as *const u8 as *const libc::c_char,
                subelts: blockli_elt.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"li\0" as *const u8 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: compact_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"div\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"generic language/style container\0" as *const u8
                    as *const libc::c_char,
                subelts: html_flow.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: align_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"dl\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"definition list \0" as *const u8 as *const libc::c_char,
                subelts: dl_contents.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"dd\0" as *const u8 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: compact_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"dt\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 1 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"definition term \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"em\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"emphasis\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"embed\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 1 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 1 as libc::c_int as libc::c_char,
                dtd: 1 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"generic embedded object \0" as *const u8 as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: embed_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"fieldset\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"form control group \0" as *const u8 as *const libc::c_char,
                subelts: fieldset_contents.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"font\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 1 as libc::c_int as libc::c_char,
                dtd: 1 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"local change to font \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: font_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"form\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"interactive form \0" as *const u8 as *const libc::c_char,
                subelts: form_contents.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"fieldset\0" as *const u8 as *const libc::c_char,
                attrs_opt: form_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: target_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: action_attr.as_ptr() as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"frame\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 2 as libc::c_int as libc::c_char,
                saveEndTag: 2 as libc::c_int as libc::c_char,
                empty: 1 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 2 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"subwindow \0" as *const u8 as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: frame_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"frameset\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 2 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"window subdivision\0" as *const u8 as *const libc::c_char,
                subelts: frameset_contents.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"noframes\0" as *const u8 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: frameset_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"h1\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"heading \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: align_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"h2\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"heading \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: align_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"h3\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"heading \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: align_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"h4\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"heading \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: align_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"h5\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"heading \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: align_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"h6\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"heading \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: align_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"head\0" as *const u8 as *const libc::c_char,
                startTag: 1 as libc::c_int as libc::c_char,
                endTag: 1 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"document head \0" as *const u8 as *const libc::c_char,
                subelts: head_contents.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: head_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"hr\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 2 as libc::c_int as libc::c_char,
                saveEndTag: 2 as libc::c_int as libc::c_char,
                empty: 1 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"horizontal rule \0" as *const u8 as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: hr_depr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"html\0" as *const u8 as *const libc::c_char,
                startTag: 1 as libc::c_int as libc::c_char,
                endTag: 1 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"document root element \0" as *const u8 as *const libc::c_char,
                subelts: html_content.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: i18n_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: version_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"i\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"italic text style\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"iframe\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 1 as libc::c_int as libc::c_char,
                isinline: 2 as libc::c_int as libc::c_char,
                desc: b"inline subwindow \0" as *const u8 as *const libc::c_char,
                subelts: html_flow.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: iframe_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"img\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 2 as libc::c_int as libc::c_char,
                saveEndTag: 2 as libc::c_int as libc::c_char,
                empty: 1 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"embedded image \0" as *const u8 as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: img_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: align_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: src_alt_attrs.as_ptr() as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"input\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 2 as libc::c_int as libc::c_char,
                saveEndTag: 2 as libc::c_int as libc::c_char,
                empty: 1 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"form control \0" as *const u8 as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: input_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: align_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"ins\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 2 as libc::c_int as libc::c_char,
                desc: b"inserted text\0" as *const u8 as *const libc::c_char,
                subelts: html_flow.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: edit_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"isindex\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 2 as libc::c_int as libc::c_char,
                saveEndTag: 2 as libc::c_int as libc::c_char,
                empty: 1 as libc::c_int as libc::c_char,
                depr: 1 as libc::c_int as libc::c_char,
                dtd: 1 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"single line prompt \0" as *const u8 as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: prompt_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"kbd\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"text to be entered by the user\0" as *const u8
                    as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"label\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"form field label text \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: label_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"legend\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"fieldset legend \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: legend_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: align_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"li\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 1 as libc::c_int as libc::c_char,
                saveEndTag: 1 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"list item \0" as *const u8 as *const libc::c_char,
                subelts: html_flow.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"link\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 2 as libc::c_int as libc::c_char,
                saveEndTag: 2 as libc::c_int as libc::c_char,
                empty: 1 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"a media-independent link \0" as *const u8 as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: link_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: target_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"map\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 2 as libc::c_int as libc::c_char,
                desc: b"client-side image map \0" as *const u8 as *const libc::c_char,
                subelts: map_contents.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: name_attr.as_ptr() as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"menu\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 1 as libc::c_int as libc::c_char,
                dtd: 1 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"menu list \0" as *const u8 as *const libc::c_char,
                subelts: blockli_elt.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: compact_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"meta\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 2 as libc::c_int as libc::c_char,
                saveEndTag: 2 as libc::c_int as libc::c_char,
                empty: 1 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"generic metainformation \0" as *const u8 as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: meta_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: content_attr.as_ptr() as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"noframes\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 2 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"alternate content container for non frame-based rendering \0"
                    as *const u8 as *const libc::c_char,
                subelts: noframes_content.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"body\0" as *const u8 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"noscript\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"alternate content container for non script-based rendering \0"
                    as *const u8 as *const libc::c_char,
                subelts: html_flow.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"div\0" as *const u8 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"object\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 2 as libc::c_int as libc::c_char,
                desc: b"generic embedded object \0" as *const u8 as *const libc::c_char,
                subelts: object_contents.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"div\0" as *const u8 as *const libc::c_char,
                attrs_opt: object_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: object_depr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"ol\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"ordered list \0" as *const u8 as *const libc::c_char,
                subelts: li_elt.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"li\0" as *const u8 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: ol_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"optgroup\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"option group \0" as *const u8 as *const libc::c_char,
                subelts: option_elt.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"option\0" as *const u8 as *const libc::c_char,
                attrs_opt: optgroup_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: label_attr.as_ptr() as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"option\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 1 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"selectable choice \0" as *const u8 as *const libc::c_char,
                subelts: html_pcdata.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: option_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"p\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 1 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"paragraph \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: align_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"param\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 2 as libc::c_int as libc::c_char,
                saveEndTag: 2 as libc::c_int as libc::c_char,
                empty: 1 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"named property value \0" as *const u8 as *const libc::c_char,
                subelts: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: param_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: name_attr.as_ptr() as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"pre\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"preformatted text \0" as *const u8 as *const libc::c_char,
                subelts: pre_content.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: width_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"q\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"short inline quotation \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: quote_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"s\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 1 as libc::c_int as libc::c_char,
                dtd: 1 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"strike-through text style\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"samp\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"sample program output, scripts, etc.\0" as *const u8
                    as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"script\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 2 as libc::c_int as libc::c_char,
                desc: b"script statements \0" as *const u8 as *const libc::c_char,
                subelts: html_pcdata.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: script_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: language_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: type_attr.as_ptr() as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"select\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"option selector \0" as *const u8 as *const libc::c_char,
                subelts: select_content.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: select_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"small\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"small text style\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"span\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"generic language/style container \0" as *const u8
                    as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"strike\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 1 as libc::c_int as libc::c_char,
                dtd: 1 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"strike-through text\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"strong\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"strong emphasis\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"style\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"style info \0" as *const u8 as *const libc::c_char,
                subelts: html_pcdata.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: style_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: type_attr.as_ptr() as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"sub\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"subscript\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"sup\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"superscript \0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"table\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"\0" as *const u8 as *const libc::c_char,
                subelts: table_contents.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"tr\0" as *const u8 as *const libc::c_char,
                attrs_opt: table_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: table_depr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"tbody\0" as *const u8 as *const libc::c_char,
                startTag: 1 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"table body \0" as *const u8 as *const libc::c_char,
                subelts: tr_elt.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"tr\0" as *const u8 as *const libc::c_char,
                attrs_opt: talign_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"td\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"table data cell\0" as *const u8 as *const libc::c_char,
                subelts: html_flow.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: th_td_attr.as_ptr() as *mut *const libc::c_char,
                attrs_depr: th_td_depr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"textarea\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"multi-line text field \0" as *const u8 as *const libc::c_char,
                subelts: html_pcdata.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: textarea_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: rows_cols_attr.as_ptr() as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"tfoot\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 1 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"table footer \0" as *const u8 as *const libc::c_char,
                subelts: tr_elt.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"tr\0" as *const u8 as *const libc::c_char,
                attrs_opt: talign_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"th\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 1 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"table header cell\0" as *const u8 as *const libc::c_char,
                subelts: html_flow.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: th_td_attr.as_ptr() as *mut *const libc::c_char,
                attrs_depr: th_td_depr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"thead\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 1 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"table header \0" as *const u8 as *const libc::c_char,
                subelts: tr_elt.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"tr\0" as *const u8 as *const libc::c_char,
                attrs_opt: talign_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"title\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"document title \0" as *const u8 as *const libc::c_char,
                subelts: html_pcdata.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: i18n_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"tr\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"table row \0" as *const u8 as *const libc::c_char,
                subelts: tr_contents.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"td\0" as *const u8 as *const libc::c_char,
                attrs_opt: talign_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: bgcolor_attr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"tt\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"teletype or monospaced text style\0" as *const u8
                    as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"u\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 3 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 1 as libc::c_int as libc::c_char,
                dtd: 1 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"underlined text style\0" as *const u8 as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_depr: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"ul\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 0 as libc::c_int as libc::c_char,
                desc: b"unordered list \0" as *const u8 as *const libc::c_char,
                subelts: li_elt.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: b"li\0" as *const u8 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: ul_depr.as_ptr() as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
        {
            let mut init = _htmlElemDesc {
                name: b"var\0" as *const u8 as *const libc::c_char,
                startTag: 0 as libc::c_int as libc::c_char,
                endTag: 0 as libc::c_int as libc::c_char,
                saveEndTag: 0 as libc::c_int as libc::c_char,
                empty: 0 as libc::c_int as libc::c_char,
                depr: 0 as libc::c_int as libc::c_char,
                dtd: 0 as libc::c_int as libc::c_char,
                isinline: 1 as libc::c_int as libc::c_char,
                desc: b"instance of a variable or program argument\0" as *const u8
                    as *const libc::c_char,
                subelts: html_inline.as_ptr() as *mut *const libc::c_char,
                defaultsubelt: 0 as *const libc::c_char,
                attrs_opt: html_attrs.as_ptr() as *mut *const libc::c_char,
                attrs_depr: 0 as *const *const libc::c_char as *mut *const libc::c_char,
                attrs_req: 0 as *const *const libc::c_char as *mut *const libc::c_char,
            };
            init
        },
    ]
};
static mut htmlStartClose: [htmlStartCloseEntry; 251] = [
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"a\0" as *const u8 as *const libc::c_char,
            newTag: b"a\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"a\0" as *const u8 as *const libc::c_char,
            newTag: b"fieldset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"a\0" as *const u8 as *const libc::c_char,
            newTag: b"table\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"a\0" as *const u8 as *const libc::c_char,
            newTag: b"td\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"a\0" as *const u8 as *const libc::c_char,
            newTag: b"th\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"address\0" as *const u8 as *const libc::c_char,
            newTag: b"dd\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"address\0" as *const u8 as *const libc::c_char,
            newTag: b"dl\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"address\0" as *const u8 as *const libc::c_char,
            newTag: b"dt\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"address\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"address\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"address\0" as *const u8 as *const libc::c_char,
            newTag: b"ul\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"b\0" as *const u8 as *const libc::c_char,
            newTag: b"center\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"b\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"b\0" as *const u8 as *const libc::c_char,
            newTag: b"td\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"b\0" as *const u8 as *const libc::c_char,
            newTag: b"th\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"big\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"caption\0" as *const u8 as *const libc::c_char,
            newTag: b"col\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"caption\0" as *const u8 as *const libc::c_char,
            newTag: b"colgroup\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"caption\0" as *const u8 as *const libc::c_char,
            newTag: b"tbody\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"caption\0" as *const u8 as *const libc::c_char,
            newTag: b"tfoot\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"caption\0" as *const u8 as *const libc::c_char,
            newTag: b"thead\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"caption\0" as *const u8 as *const libc::c_char,
            newTag: b"tr\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"col\0" as *const u8 as *const libc::c_char,
            newTag: b"col\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"col\0" as *const u8 as *const libc::c_char,
            newTag: b"colgroup\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"col\0" as *const u8 as *const libc::c_char,
            newTag: b"tbody\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"col\0" as *const u8 as *const libc::c_char,
            newTag: b"tfoot\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"col\0" as *const u8 as *const libc::c_char,
            newTag: b"thead\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"col\0" as *const u8 as *const libc::c_char,
            newTag: b"tr\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"colgroup\0" as *const u8 as *const libc::c_char,
            newTag: b"colgroup\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"colgroup\0" as *const u8 as *const libc::c_char,
            newTag: b"tbody\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"colgroup\0" as *const u8 as *const libc::c_char,
            newTag: b"tfoot\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"colgroup\0" as *const u8 as *const libc::c_char,
            newTag: b"thead\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"colgroup\0" as *const u8 as *const libc::c_char,
            newTag: b"tr\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"dd\0" as *const u8 as *const libc::c_char,
            newTag: b"dt\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"dir\0" as *const u8 as *const libc::c_char,
            newTag: b"dd\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"dir\0" as *const u8 as *const libc::c_char,
            newTag: b"dl\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"dir\0" as *const u8 as *const libc::c_char,
            newTag: b"dt\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"dir\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"dir\0" as *const u8 as *const libc::c_char,
            newTag: b"ul\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"dl\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"dl\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"dt\0" as *const u8 as *const libc::c_char,
            newTag: b"dd\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"dt\0" as *const u8 as *const libc::c_char,
            newTag: b"dl\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"font\0" as *const u8 as *const libc::c_char,
            newTag: b"center\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"font\0" as *const u8 as *const libc::c_char,
            newTag: b"td\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"font\0" as *const u8 as *const libc::c_char,
            newTag: b"th\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"form\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h1\0" as *const u8 as *const libc::c_char,
            newTag: b"fieldset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h1\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h1\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h1\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h1\0" as *const u8 as *const libc::c_char,
            newTag: b"table\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h2\0" as *const u8 as *const libc::c_char,
            newTag: b"fieldset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h2\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h2\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h2\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h2\0" as *const u8 as *const libc::c_char,
            newTag: b"table\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h3\0" as *const u8 as *const libc::c_char,
            newTag: b"fieldset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h3\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h3\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h3\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h3\0" as *const u8 as *const libc::c_char,
            newTag: b"table\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h4\0" as *const u8 as *const libc::c_char,
            newTag: b"fieldset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h4\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h4\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h4\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h4\0" as *const u8 as *const libc::c_char,
            newTag: b"table\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h5\0" as *const u8 as *const libc::c_char,
            newTag: b"fieldset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h5\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h5\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h5\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h5\0" as *const u8 as *const libc::c_char,
            newTag: b"table\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h6\0" as *const u8 as *const libc::c_char,
            newTag: b"fieldset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h6\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h6\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h6\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"h6\0" as *const u8 as *const libc::c_char,
            newTag: b"table\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"a\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"abbr\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"acronym\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"address\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"b\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"bdo\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"big\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"blockquote\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"body\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"br\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"center\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"cite\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"code\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"dd\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"dfn\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"dir\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"div\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"dl\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"dt\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"em\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"fieldset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"font\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"frameset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"h1\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"h2\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"h3\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"h4\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"h5\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"h6\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"hr\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"i\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"iframe\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"img\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"kbd\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"listing\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"map\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"menu\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"ol\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"pre\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"q\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"s\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"samp\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"small\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"span\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"strike\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"strong\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"sub\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"sup\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"table\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"tt\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"u\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"ul\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"var\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"head\0" as *const u8 as *const libc::c_char,
            newTag: b"xmp\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"hr\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"i\0" as *const u8 as *const libc::c_char,
            newTag: b"center\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"i\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"i\0" as *const u8 as *const libc::c_char,
            newTag: b"td\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"i\0" as *const u8 as *const libc::c_char,
            newTag: b"th\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"legend\0" as *const u8 as *const libc::c_char,
            newTag: b"fieldset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"li\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"link\0" as *const u8 as *const libc::c_char,
            newTag: b"body\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"link\0" as *const u8 as *const libc::c_char,
            newTag: b"frameset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"listing\0" as *const u8 as *const libc::c_char,
            newTag: b"dd\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"listing\0" as *const u8 as *const libc::c_char,
            newTag: b"dl\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"listing\0" as *const u8 as *const libc::c_char,
            newTag: b"dt\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"listing\0" as *const u8 as *const libc::c_char,
            newTag: b"fieldset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"listing\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"listing\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"listing\0" as *const u8 as *const libc::c_char,
            newTag: b"table\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"listing\0" as *const u8 as *const libc::c_char,
            newTag: b"ul\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"menu\0" as *const u8 as *const libc::c_char,
            newTag: b"dd\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"menu\0" as *const u8 as *const libc::c_char,
            newTag: b"dl\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"menu\0" as *const u8 as *const libc::c_char,
            newTag: b"dt\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"menu\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"menu\0" as *const u8 as *const libc::c_char,
            newTag: b"ul\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"ol\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"ol\0" as *const u8 as *const libc::c_char,
            newTag: b"ul\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"option\0" as *const u8 as *const libc::c_char,
            newTag: b"optgroup\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"option\0" as *const u8 as *const libc::c_char,
            newTag: b"option\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"address\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"blockquote\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"body\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"caption\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"center\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"col\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"colgroup\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"dd\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"dir\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"div\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"dl\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"dt\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"fieldset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"frameset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"h1\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"h2\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"h3\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"h4\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"h5\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"h6\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"head\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"hr\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"listing\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"menu\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"ol\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"pre\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"table\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"tbody\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"td\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"tfoot\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"th\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"title\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"tr\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"ul\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"p\0" as *const u8 as *const libc::c_char,
            newTag: b"xmp\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"pre\0" as *const u8 as *const libc::c_char,
            newTag: b"dd\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"pre\0" as *const u8 as *const libc::c_char,
            newTag: b"dl\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"pre\0" as *const u8 as *const libc::c_char,
            newTag: b"dt\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"pre\0" as *const u8 as *const libc::c_char,
            newTag: b"fieldset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"pre\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"pre\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"pre\0" as *const u8 as *const libc::c_char,
            newTag: b"table\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"pre\0" as *const u8 as *const libc::c_char,
            newTag: b"ul\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"s\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"script\0" as *const u8 as *const libc::c_char,
            newTag: b"noscript\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"small\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"span\0" as *const u8 as *const libc::c_char,
            newTag: b"td\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"span\0" as *const u8 as *const libc::c_char,
            newTag: b"th\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"strike\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"style\0" as *const u8 as *const libc::c_char,
            newTag: b"body\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"style\0" as *const u8 as *const libc::c_char,
            newTag: b"frameset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"tbody\0" as *const u8 as *const libc::c_char,
            newTag: b"tbody\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"tbody\0" as *const u8 as *const libc::c_char,
            newTag: b"tfoot\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"td\0" as *const u8 as *const libc::c_char,
            newTag: b"tbody\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"td\0" as *const u8 as *const libc::c_char,
            newTag: b"td\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"td\0" as *const u8 as *const libc::c_char,
            newTag: b"tfoot\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"td\0" as *const u8 as *const libc::c_char,
            newTag: b"th\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"td\0" as *const u8 as *const libc::c_char,
            newTag: b"tr\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"tfoot\0" as *const u8 as *const libc::c_char,
            newTag: b"tbody\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"th\0" as *const u8 as *const libc::c_char,
            newTag: b"tbody\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"th\0" as *const u8 as *const libc::c_char,
            newTag: b"td\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"th\0" as *const u8 as *const libc::c_char,
            newTag: b"tfoot\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"th\0" as *const u8 as *const libc::c_char,
            newTag: b"th\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"th\0" as *const u8 as *const libc::c_char,
            newTag: b"tr\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"thead\0" as *const u8 as *const libc::c_char,
            newTag: b"tbody\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"thead\0" as *const u8 as *const libc::c_char,
            newTag: b"tfoot\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"title\0" as *const u8 as *const libc::c_char,
            newTag: b"body\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"title\0" as *const u8 as *const libc::c_char,
            newTag: b"frameset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"tr\0" as *const u8 as *const libc::c_char,
            newTag: b"tbody\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"tr\0" as *const u8 as *const libc::c_char,
            newTag: b"tfoot\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"tr\0" as *const u8 as *const libc::c_char,
            newTag: b"tr\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"tt\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"u\0" as *const u8 as *const libc::c_char,
            newTag: b"p\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"u\0" as *const u8 as *const libc::c_char,
            newTag: b"td\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"u\0" as *const u8 as *const libc::c_char,
            newTag: b"th\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"ul\0" as *const u8 as *const libc::c_char,
            newTag: b"address\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"ul\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"ul\0" as *const u8 as *const libc::c_char,
            newTag: b"menu\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"ul\0" as *const u8 as *const libc::c_char,
            newTag: b"ol\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"ul\0" as *const u8 as *const libc::c_char,
            newTag: b"pre\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"xmp\0" as *const u8 as *const libc::c_char,
            newTag: b"dd\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"xmp\0" as *const u8 as *const libc::c_char,
            newTag: b"dl\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"xmp\0" as *const u8 as *const libc::c_char,
            newTag: b"dt\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"xmp\0" as *const u8 as *const libc::c_char,
            newTag: b"fieldset\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"xmp\0" as *const u8 as *const libc::c_char,
            newTag: b"form\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"xmp\0" as *const u8 as *const libc::c_char,
            newTag: b"li\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"xmp\0" as *const u8 as *const libc::c_char,
            newTag: b"table\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = htmlStartCloseEntry {
            oldTag: b"xmp\0" as *const u8 as *const libc::c_char,
            newTag: b"ul\0" as *const u8 as *const libc::c_char,
        };
        init
    },
];
static mut htmlNoContentElements: [*const libc::c_char; 3] = [
    b"html\0" as *const u8 as *const libc::c_char,
    b"head\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
static mut htmlScriptAttributes: [*const libc::c_char; 18] = [
    b"onclick\0" as *const u8 as *const libc::c_char,
    b"ondblclick\0" as *const u8 as *const libc::c_char,
    b"onmousedown\0" as *const u8 as *const libc::c_char,
    b"onmouseup\0" as *const u8 as *const libc::c_char,
    b"onmouseover\0" as *const u8 as *const libc::c_char,
    b"onmousemove\0" as *const u8 as *const libc::c_char,
    b"onmouseout\0" as *const u8 as *const libc::c_char,
    b"onkeypress\0" as *const u8 as *const libc::c_char,
    b"onkeydown\0" as *const u8 as *const libc::c_char,
    b"onkeyup\0" as *const u8 as *const libc::c_char,
    b"onload\0" as *const u8 as *const libc::c_char,
    b"onunload\0" as *const u8 as *const libc::c_char,
    b"onfocus\0" as *const u8 as *const libc::c_char,
    b"onblur\0" as *const u8 as *const libc::c_char,
    b"onsubmit\0" as *const u8 as *const libc::c_char,
    b"onreset\0" as *const u8 as *const libc::c_char,
    b"onchange\0" as *const u8 as *const libc::c_char,
    b"onselect\0" as *const u8 as *const libc::c_char,
];
static mut htmlEndPriority: [elementPriority; 12] = [
    {
        let mut init = elementPriority {
            name: b"div\0" as *const u8 as *const libc::c_char,
            priority: 150 as libc::c_int,
        };
        init
    },
    {
        let mut init = elementPriority {
            name: b"td\0" as *const u8 as *const libc::c_char,
            priority: 160 as libc::c_int,
        };
        init
    },
    {
        let mut init = elementPriority {
            name: b"th\0" as *const u8 as *const libc::c_char,
            priority: 160 as libc::c_int,
        };
        init
    },
    {
        let mut init = elementPriority {
            name: b"tr\0" as *const u8 as *const libc::c_char,
            priority: 170 as libc::c_int,
        };
        init
    },
    {
        let mut init = elementPriority {
            name: b"thead\0" as *const u8 as *const libc::c_char,
            priority: 180 as libc::c_int,
        };
        init
    },
    {
        let mut init = elementPriority {
            name: b"tbody\0" as *const u8 as *const libc::c_char,
            priority: 180 as libc::c_int,
        };
        init
    },
    {
        let mut init = elementPriority {
            name: b"tfoot\0" as *const u8 as *const libc::c_char,
            priority: 180 as libc::c_int,
        };
        init
    },
    {
        let mut init = elementPriority {
            name: b"table\0" as *const u8 as *const libc::c_char,
            priority: 190 as libc::c_int,
        };
        init
    },
    {
        let mut init = elementPriority {
            name: b"head\0" as *const u8 as *const libc::c_char,
            priority: 200 as libc::c_int,
        };
        init
    },
    {
        let mut init = elementPriority {
            name: b"body\0" as *const u8 as *const libc::c_char,
            priority: 200 as libc::c_int,
        };
        init
    },
    {
        let mut init = elementPriority {
            name: b"html\0" as *const u8 as *const libc::c_char,
            priority: 220 as libc::c_int,
        };
        init
    },
    {
        let mut init = elementPriority {
            name: 0 as *const libc::c_char,
            priority: 100 as libc::c_int,
        };
        init
    },
];
#[no_mangle]
pub unsafe extern "C" fn htmlInitAutoClose() {}
unsafe extern "C" fn htmlCompareTags(
    mut key: *const libc::c_void,
    mut member: *const libc::c_void,
) -> libc::c_int {
    let mut tag: *const xmlChar = key as *const xmlChar;
    let mut desc: *const htmlElemDesc = member as *const htmlElemDesc;
    return xmlStrcasecmp(tag, (*desc).name as *mut xmlChar);
}
#[no_mangle]
pub unsafe extern "C" fn htmlTagLookup(mut tag: *const xmlChar) -> *const htmlElemDesc {
    if tag.is_null() {
        return 0 as *const htmlElemDesc;
    }
    return bsearch(
        tag as *const libc::c_void,
        html40ElementTable.as_ptr() as *const libc::c_void,
        (::std::mem::size_of::<[htmlElemDesc; 92]>() as libc::c_ulong)
            .wrapping_div(::std::mem::size_of::<htmlElemDesc>() as libc::c_ulong),
        ::std::mem::size_of::<htmlElemDesc>() as libc::c_ulong,
        Some(
            htmlCompareTags
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    ) as *const htmlElemDesc;
}
unsafe extern "C" fn htmlGetEndPriority(mut name: *const xmlChar) -> libc::c_int {
    let mut i: libc::c_int = 0 as libc::c_int;
    while !(htmlEndPriority[i as usize].name).is_null()
        && xmlStrEqual(htmlEndPriority[i as usize].name as *const xmlChar, name) == 0
    {
        i += 1;
    }
    return htmlEndPriority[i as usize].priority;
}
unsafe extern "C" fn htmlCompareStartClose(
    mut vkey: *const libc::c_void,
    mut member: *const libc::c_void,
) -> libc::c_int {
    let mut key: *const htmlStartCloseEntry = vkey as *const htmlStartCloseEntry;
    let mut entry: *const htmlStartCloseEntry = member as *const htmlStartCloseEntry;
    let mut ret: libc::c_int = 0;
    ret = strcmp((*key).oldTag, (*entry).oldTag);
    if ret == 0 as libc::c_int {
        ret = strcmp((*key).newTag, (*entry).newTag);
    }
    return ret;
}
unsafe extern "C" fn htmlCheckAutoClose(
    mut newtag: *const xmlChar,
    mut oldtag: *const xmlChar,
) -> libc::c_int {
    let mut key: htmlStartCloseEntry = htmlStartCloseEntry {
        oldTag: 0 as *const libc::c_char,
        newTag: 0 as *const libc::c_char,
    };
    let mut res: *mut libc::c_void = 0 as *mut libc::c_void;
    key.oldTag = oldtag as *const libc::c_char;
    key.newTag = newtag as *const libc::c_char;
    res = bsearch(
        &mut key as *mut htmlStartCloseEntry as *const libc::c_void,
        htmlStartClose.as_ptr() as *const libc::c_void,
        (::std::mem::size_of::<[htmlStartCloseEntry; 251]>() as libc::c_ulong)
            .wrapping_div(::std::mem::size_of::<htmlStartCloseEntry>() as libc::c_ulong),
        ::std::mem::size_of::<htmlStartCloseEntry>() as libc::c_ulong,
        Some(
            htmlCompareStartClose
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
    return (res != 0 as *mut libc::c_void) as libc::c_int;
}
unsafe extern "C" fn htmlAutoCloseOnClose(
    mut ctxt: htmlParserCtxtPtr,
    mut newtag: *const xmlChar,
) {
    let mut info: *const htmlElemDesc = 0 as *const htmlElemDesc;
    let mut i: libc::c_int = 0;
    let mut priority: libc::c_int = 0;
    priority = htmlGetEndPriority(newtag);
    i = (*ctxt).nameNr - 1 as libc::c_int;
    while i >= 0 as libc::c_int {
        if xmlStrEqual(newtag, *((*ctxt).nameTab).offset(i as isize)) != 0 {
            break;
        }
        if htmlGetEndPriority(*((*ctxt).nameTab).offset(i as isize)) > priority {
            return;
        }
        i -= 1;
    }
    if i < 0 as libc::c_int {
        return;
    }
    while xmlStrEqual(newtag, (*ctxt).name) == 0 {
        info = htmlTagLookup((*ctxt).name);
        if !info.is_null() && (*info).endTag as libc::c_int == 3 as libc::c_int {
            htmlParseErr(
                ctxt,
                XML_ERR_TAG_NAME_MISMATCH,
                b"Opening and ending tag mismatch: %s and %s\n\0" as *const u8
                    as *const libc::c_char,
                newtag,
                (*ctxt).name,
            );
        }
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElement).is_some() {
            ((*(*ctxt).sax).endElement)
                .expect("non-null function pointer")((*ctxt).userData, (*ctxt).name);
        }
        htmlnamePop(ctxt);
    }
}
unsafe extern "C" fn htmlAutoCloseOnEnd(mut ctxt: htmlParserCtxtPtr) {
    let mut i: libc::c_int = 0;
    if (*ctxt).nameNr == 0 as libc::c_int {
        return;
    }
    i = (*ctxt).nameNr - 1 as libc::c_int;
    while i >= 0 as libc::c_int {
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElement).is_some() {
            ((*(*ctxt).sax).endElement)
                .expect("non-null function pointer")((*ctxt).userData, (*ctxt).name);
        }
        htmlnamePop(ctxt);
        i -= 1;
    }
}
unsafe extern "C" fn htmlAutoClose(
    mut ctxt: htmlParserCtxtPtr,
    mut newtag: *const xmlChar,
) {
    while !newtag.is_null() && !((*ctxt).name).is_null()
        && htmlCheckAutoClose(newtag, (*ctxt).name) != 0
    {
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElement).is_some() {
            ((*(*ctxt).sax).endElement)
                .expect("non-null function pointer")((*ctxt).userData, (*ctxt).name);
        }
        htmlnamePop(ctxt);
    }
    if newtag.is_null() {
        htmlAutoCloseOnEnd(ctxt);
        return;
    }
    while newtag.is_null() && !((*ctxt).name).is_null()
        && (xmlStrEqual(
            (*ctxt).name,
            b"head\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
            || xmlStrEqual(
                (*ctxt).name,
                b"body\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            || xmlStrEqual(
                (*ctxt).name,
                b"html\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0)
    {
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElement).is_some() {
            ((*(*ctxt).sax).endElement)
                .expect("non-null function pointer")((*ctxt).userData, (*ctxt).name);
        }
        htmlnamePop(ctxt);
    }
}
#[no_mangle]
pub unsafe extern "C" fn htmlAutoCloseTag(
    mut doc: htmlDocPtr,
    mut name: *const xmlChar,
    mut elem: htmlNodePtr,
) -> libc::c_int {
    let mut child: htmlNodePtr = 0 as *mut xmlNode;
    if elem.is_null() {
        return 1 as libc::c_int;
    }
    if xmlStrEqual(name, (*elem).name) != 0 {
        return 0 as libc::c_int;
    }
    if htmlCheckAutoClose((*elem).name, name) != 0 {
        return 1 as libc::c_int;
    }
    child = (*elem).children;
    while !child.is_null() {
        if htmlAutoCloseTag(doc, name, child) != 0 {
            return 1 as libc::c_int;
        }
        child = (*child).next;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn htmlIsAutoClosed(
    mut doc: htmlDocPtr,
    mut elem: htmlNodePtr,
) -> libc::c_int {
    let mut child: htmlNodePtr = 0 as *mut xmlNode;
    if elem.is_null() {
        return 1 as libc::c_int;
    }
    child = (*elem).children;
    while !child.is_null() {
        if htmlAutoCloseTag(doc, (*elem).name, child) != 0 {
            return 1 as libc::c_int;
        }
        child = (*child).next;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn htmlCheckImplied(
    mut ctxt: htmlParserCtxtPtr,
    mut newtag: *const xmlChar,
) {
    let mut i: libc::c_int = 0;
    if (*ctxt).options & HTML_PARSE_NOIMPLIED as libc::c_int != 0 {
        return;
    }
    if htmlOmittedDefaultValue == 0 {
        return;
    }
    if xmlStrEqual(newtag, b"html\0" as *const u8 as *const libc::c_char as *mut xmlChar)
        != 0
    {
        return;
    }
    if (*ctxt).nameNr <= 0 as libc::c_int {
        htmlnamePush(
            ctxt,
            b"html\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        );
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).startElement).is_some() {
            ((*(*ctxt).sax).startElement)
                .expect(
                    "non-null function pointer",
                )(
                (*ctxt).userData,
                b"html\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                0 as *mut *const xmlChar,
            );
        }
    }
    if xmlStrEqual(newtag, b"body\0" as *const u8 as *const libc::c_char as *mut xmlChar)
        != 0
        || xmlStrEqual(
            newtag,
            b"head\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
    {
        return;
    }
    if (*ctxt).nameNr <= 1 as libc::c_int
        && (xmlStrEqual(
            newtag,
            b"script\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
            || xmlStrEqual(
                newtag,
                b"style\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            || xmlStrEqual(
                newtag,
                b"meta\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            || xmlStrEqual(
                newtag,
                b"link\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            || xmlStrEqual(
                newtag,
                b"title\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            || xmlStrEqual(
                newtag,
                b"base\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0)
    {
        if (*ctxt).html >= 3 as libc::c_int {
            return;
        }
        htmlnamePush(
            ctxt,
            b"head\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        );
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).startElement).is_some() {
            ((*(*ctxt).sax).startElement)
                .expect(
                    "non-null function pointer",
                )(
                (*ctxt).userData,
                b"head\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                0 as *mut *const xmlChar,
            );
        }
    } else if xmlStrEqual(
            newtag,
            b"noframes\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) == 0
            && xmlStrEqual(
                newtag,
                b"frame\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) == 0
            && xmlStrEqual(
                newtag,
                b"frameset\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) == 0
        {
        if (*ctxt).html >= 10 as libc::c_int {
            return;
        }
        i = 0 as libc::c_int;
        while i < (*ctxt).nameNr {
            if xmlStrEqual(
                *((*ctxt).nameTab).offset(i as isize),
                b"body\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            {
                return;
            }
            if xmlStrEqual(
                *((*ctxt).nameTab).offset(i as isize),
                b"head\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            {
                return;
            }
            i += 1;
        }
        htmlnamePush(
            ctxt,
            b"body\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        );
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).startElement).is_some() {
            ((*(*ctxt).sax).startElement)
                .expect(
                    "non-null function pointer",
                )(
                (*ctxt).userData,
                b"body\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                0 as *mut *const xmlChar,
            );
        }
    }
}
unsafe extern "C" fn htmlCheckParagraph(mut ctxt: htmlParserCtxtPtr) -> libc::c_int {
    let mut tag: *const xmlChar = 0 as *const xmlChar;
    let mut i: libc::c_int = 0;
    if ctxt.is_null() {
        return -(1 as libc::c_int);
    }
    tag = (*ctxt).name;
    if tag.is_null() {
        htmlAutoClose(ctxt, b"p\0" as *const u8 as *const libc::c_char as *mut xmlChar);
        htmlCheckImplied(
            ctxt,
            b"p\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        );
        htmlnamePush(ctxt, b"p\0" as *const u8 as *const libc::c_char as *mut xmlChar);
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).startElement).is_some() {
            ((*(*ctxt).sax).startElement)
                .expect(
                    "non-null function pointer",
                )(
                (*ctxt).userData,
                b"p\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                0 as *mut *const xmlChar,
            );
        }
        return 1 as libc::c_int;
    }
    if htmlOmittedDefaultValue == 0 {
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int;
    while !(htmlNoContentElements[i as usize]).is_null() {
        if xmlStrEqual(tag, htmlNoContentElements[i as usize] as *mut xmlChar) != 0 {
            htmlAutoClose(
                ctxt,
                b"p\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
            htmlCheckImplied(
                ctxt,
                b"p\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
            htmlnamePush(
                ctxt,
                b"p\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).startElement).is_some() {
                ((*(*ctxt).sax).startElement)
                    .expect(
                        "non-null function pointer",
                    )(
                    (*ctxt).userData,
                    b"p\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    0 as *mut *const xmlChar,
                );
            }
            return 1 as libc::c_int;
        }
        i += 1;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn htmlIsScriptAttribute(mut name: *const xmlChar) -> libc::c_int {
    let mut i: libc::c_uint = 0;
    if name.is_null() {
        return 0 as libc::c_int;
    }
    if *name.offset(0 as libc::c_int as isize) as libc::c_int != 'o' as i32
        || *name.offset(1 as libc::c_int as isize) as libc::c_int != 'n' as i32
    {
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (::std::mem::size_of::<[*const libc::c_char; 18]>() as libc::c_ulong)
            .wrapping_div(::std::mem::size_of::<*const libc::c_char>() as libc::c_ulong)
    {
        if xmlStrEqual(name, htmlScriptAttributes[i as usize] as *const xmlChar) != 0 {
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
    }
    return 0 as libc::c_int;
}
static mut html40EntitiesTable: [htmlEntityDesc; 253] = [
    {
        let mut init = _htmlEntityDesc {
            value: 34 as libc::c_int as libc::c_uint,
            name: b"quot\0" as *const u8 as *const libc::c_char,
            desc: b"quotation mark = APL quote, U+0022 ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 38 as libc::c_int as libc::c_uint,
            name: b"amp\0" as *const u8 as *const libc::c_char,
            desc: b"ampersand, U+0026 ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 39 as libc::c_int as libc::c_uint,
            name: b"apos\0" as *const u8 as *const libc::c_char,
            desc: b"single quote\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 60 as libc::c_int as libc::c_uint,
            name: b"lt\0" as *const u8 as *const libc::c_char,
            desc: b"less-than sign, U+003C ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 62 as libc::c_int as libc::c_uint,
            name: b"gt\0" as *const u8 as *const libc::c_char,
            desc: b"greater-than sign, U+003E ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 160 as libc::c_int as libc::c_uint,
            name: b"nbsp\0" as *const u8 as *const libc::c_char,
            desc: b"no-break space = non-breaking space, U+00A0 ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 161 as libc::c_int as libc::c_uint,
            name: b"iexcl\0" as *const u8 as *const libc::c_char,
            desc: b"inverted exclamation mark, U+00A1 ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 162 as libc::c_int as libc::c_uint,
            name: b"cent\0" as *const u8 as *const libc::c_char,
            desc: b"cent sign, U+00A2 ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 163 as libc::c_int as libc::c_uint,
            name: b"pound\0" as *const u8 as *const libc::c_char,
            desc: b"pound sign, U+00A3 ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 164 as libc::c_int as libc::c_uint,
            name: b"curren\0" as *const u8 as *const libc::c_char,
            desc: b"currency sign, U+00A4 ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 165 as libc::c_int as libc::c_uint,
            name: b"yen\0" as *const u8 as *const libc::c_char,
            desc: b"yen sign = yuan sign, U+00A5 ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 166 as libc::c_int as libc::c_uint,
            name: b"brvbar\0" as *const u8 as *const libc::c_char,
            desc: b"broken bar = broken vertical bar, U+00A6 ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 167 as libc::c_int as libc::c_uint,
            name: b"sect\0" as *const u8 as *const libc::c_char,
            desc: b"section sign, U+00A7 ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 168 as libc::c_int as libc::c_uint,
            name: b"uml\0" as *const u8 as *const libc::c_char,
            desc: b"diaeresis = spacing diaeresis, U+00A8 ISOdia\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 169 as libc::c_int as libc::c_uint,
            name: b"copy\0" as *const u8 as *const libc::c_char,
            desc: b"copyright sign, U+00A9 ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 170 as libc::c_int as libc::c_uint,
            name: b"ordf\0" as *const u8 as *const libc::c_char,
            desc: b"feminine ordinal indicator, U+00AA ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 171 as libc::c_int as libc::c_uint,
            name: b"laquo\0" as *const u8 as *const libc::c_char,
            desc: b"left-pointing double angle quotation mark = left pointing guillemet, U+00AB ISOnum\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 172 as libc::c_int as libc::c_uint,
            name: b"not\0" as *const u8 as *const libc::c_char,
            desc: b"not sign, U+00AC ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 173 as libc::c_int as libc::c_uint,
            name: b"shy\0" as *const u8 as *const libc::c_char,
            desc: b"soft hyphen = discretionary hyphen, U+00AD ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 174 as libc::c_int as libc::c_uint,
            name: b"reg\0" as *const u8 as *const libc::c_char,
            desc: b"registered sign = registered trade mark sign, U+00AE ISOnum\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 175 as libc::c_int as libc::c_uint,
            name: b"macr\0" as *const u8 as *const libc::c_char,
            desc: b"macron = spacing macron = overline = APL overbar, U+00AF ISOdia\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 176 as libc::c_int as libc::c_uint,
            name: b"deg\0" as *const u8 as *const libc::c_char,
            desc: b"degree sign, U+00B0 ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 177 as libc::c_int as libc::c_uint,
            name: b"plusmn\0" as *const u8 as *const libc::c_char,
            desc: b"plus-minus sign = plus-or-minus sign, U+00B1 ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 178 as libc::c_int as libc::c_uint,
            name: b"sup2\0" as *const u8 as *const libc::c_char,
            desc: b"superscript two = superscript digit two = squared, U+00B2 ISOnum\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 179 as libc::c_int as libc::c_uint,
            name: b"sup3\0" as *const u8 as *const libc::c_char,
            desc: b"superscript three = superscript digit three = cubed, U+00B3 ISOnum\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 180 as libc::c_int as libc::c_uint,
            name: b"acute\0" as *const u8 as *const libc::c_char,
            desc: b"acute accent = spacing acute, U+00B4 ISOdia\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 181 as libc::c_int as libc::c_uint,
            name: b"micro\0" as *const u8 as *const libc::c_char,
            desc: b"micro sign, U+00B5 ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 182 as libc::c_int as libc::c_uint,
            name: b"para\0" as *const u8 as *const libc::c_char,
            desc: b"pilcrow sign = paragraph sign, U+00B6 ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 183 as libc::c_int as libc::c_uint,
            name: b"middot\0" as *const u8 as *const libc::c_char,
            desc: b"middle dot = Georgian comma Greek middle dot, U+00B7 ISOnum\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 184 as libc::c_int as libc::c_uint,
            name: b"cedil\0" as *const u8 as *const libc::c_char,
            desc: b"cedilla = spacing cedilla, U+00B8 ISOdia\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 185 as libc::c_int as libc::c_uint,
            name: b"sup1\0" as *const u8 as *const libc::c_char,
            desc: b"superscript one = superscript digit one, U+00B9 ISOnum\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 186 as libc::c_int as libc::c_uint,
            name: b"ordm\0" as *const u8 as *const libc::c_char,
            desc: b"masculine ordinal indicator, U+00BA ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 187 as libc::c_int as libc::c_uint,
            name: b"raquo\0" as *const u8 as *const libc::c_char,
            desc: b"right-pointing double angle quotation mark right pointing guillemet, U+00BB ISOnum\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 188 as libc::c_int as libc::c_uint,
            name: b"frac14\0" as *const u8 as *const libc::c_char,
            desc: b"vulgar fraction one quarter = fraction one quarter, U+00BC ISOnum\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 189 as libc::c_int as libc::c_uint,
            name: b"frac12\0" as *const u8 as *const libc::c_char,
            desc: b"vulgar fraction one half = fraction one half, U+00BD ISOnum\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 190 as libc::c_int as libc::c_uint,
            name: b"frac34\0" as *const u8 as *const libc::c_char,
            desc: b"vulgar fraction three quarters = fraction three quarters, U+00BE ISOnum\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 191 as libc::c_int as libc::c_uint,
            name: b"iquest\0" as *const u8 as *const libc::c_char,
            desc: b"inverted question mark = turned question mark, U+00BF ISOnum\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 192 as libc::c_int as libc::c_uint,
            name: b"Agrave\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter A with grave = latin capital letter A grave, U+00C0 ISOlat1\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 193 as libc::c_int as libc::c_uint,
            name: b"Aacute\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter A with acute, U+00C1 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 194 as libc::c_int as libc::c_uint,
            name: b"Acirc\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter A with circumflex, U+00C2 ISOlat1\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 195 as libc::c_int as libc::c_uint,
            name: b"Atilde\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter A with tilde, U+00C3 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 196 as libc::c_int as libc::c_uint,
            name: b"Auml\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter A with diaeresis, U+00C4 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 197 as libc::c_int as libc::c_uint,
            name: b"Aring\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter A with ring above = latin capital letter A ring, U+00C5 ISOlat1\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 198 as libc::c_int as libc::c_uint,
            name: b"AElig\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter AE = latin capital ligature AE, U+00C6 ISOlat1\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 199 as libc::c_int as libc::c_uint,
            name: b"Ccedil\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter C with cedilla, U+00C7 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 200 as libc::c_int as libc::c_uint,
            name: b"Egrave\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter E with grave, U+00C8 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 201 as libc::c_int as libc::c_uint,
            name: b"Eacute\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter E with acute, U+00C9 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 202 as libc::c_int as libc::c_uint,
            name: b"Ecirc\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter E with circumflex, U+00CA ISOlat1\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 203 as libc::c_int as libc::c_uint,
            name: b"Euml\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter E with diaeresis, U+00CB ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 204 as libc::c_int as libc::c_uint,
            name: b"Igrave\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter I with grave, U+00CC ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 205 as libc::c_int as libc::c_uint,
            name: b"Iacute\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter I with acute, U+00CD ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 206 as libc::c_int as libc::c_uint,
            name: b"Icirc\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter I with circumflex, U+00CE ISOlat1\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 207 as libc::c_int as libc::c_uint,
            name: b"Iuml\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter I with diaeresis, U+00CF ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 208 as libc::c_int as libc::c_uint,
            name: b"ETH\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter ETH, U+00D0 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 209 as libc::c_int as libc::c_uint,
            name: b"Ntilde\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter N with tilde, U+00D1 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 210 as libc::c_int as libc::c_uint,
            name: b"Ograve\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter O with grave, U+00D2 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 211 as libc::c_int as libc::c_uint,
            name: b"Oacute\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter O with acute, U+00D3 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 212 as libc::c_int as libc::c_uint,
            name: b"Ocirc\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter O with circumflex, U+00D4 ISOlat1\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 213 as libc::c_int as libc::c_uint,
            name: b"Otilde\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter O with tilde, U+00D5 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 214 as libc::c_int as libc::c_uint,
            name: b"Ouml\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter O with diaeresis, U+00D6 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 215 as libc::c_int as libc::c_uint,
            name: b"times\0" as *const u8 as *const libc::c_char,
            desc: b"multiplication sign, U+00D7 ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 216 as libc::c_int as libc::c_uint,
            name: b"Oslash\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter O with stroke latin capital letter O slash, U+00D8 ISOlat1\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 217 as libc::c_int as libc::c_uint,
            name: b"Ugrave\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter U with grave, U+00D9 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 218 as libc::c_int as libc::c_uint,
            name: b"Uacute\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter U with acute, U+00DA ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 219 as libc::c_int as libc::c_uint,
            name: b"Ucirc\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter U with circumflex, U+00DB ISOlat1\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 220 as libc::c_int as libc::c_uint,
            name: b"Uuml\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter U with diaeresis, U+00DC ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 221 as libc::c_int as libc::c_uint,
            name: b"Yacute\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter Y with acute, U+00DD ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 222 as libc::c_int as libc::c_uint,
            name: b"THORN\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter THORN, U+00DE ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 223 as libc::c_int as libc::c_uint,
            name: b"szlig\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter sharp s = ess-zed, U+00DF ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 224 as libc::c_int as libc::c_uint,
            name: b"agrave\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter a with grave = latin small letter a grave, U+00E0 ISOlat1\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 225 as libc::c_int as libc::c_uint,
            name: b"aacute\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter a with acute, U+00E1 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 226 as libc::c_int as libc::c_uint,
            name: b"acirc\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter a with circumflex, U+00E2 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 227 as libc::c_int as libc::c_uint,
            name: b"atilde\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter a with tilde, U+00E3 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 228 as libc::c_int as libc::c_uint,
            name: b"auml\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter a with diaeresis, U+00E4 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 229 as libc::c_int as libc::c_uint,
            name: b"aring\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter a with ring above = latin small letter a ring, U+00E5 ISOlat1\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 230 as libc::c_int as libc::c_uint,
            name: b"aelig\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter ae = latin small ligature ae, U+00E6 ISOlat1\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 231 as libc::c_int as libc::c_uint,
            name: b"ccedil\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter c with cedilla, U+00E7 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 232 as libc::c_int as libc::c_uint,
            name: b"egrave\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter e with grave, U+00E8 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 233 as libc::c_int as libc::c_uint,
            name: b"eacute\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter e with acute, U+00E9 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 234 as libc::c_int as libc::c_uint,
            name: b"ecirc\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter e with circumflex, U+00EA ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 235 as libc::c_int as libc::c_uint,
            name: b"euml\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter e with diaeresis, U+00EB ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 236 as libc::c_int as libc::c_uint,
            name: b"igrave\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter i with grave, U+00EC ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 237 as libc::c_int as libc::c_uint,
            name: b"iacute\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter i with acute, U+00ED ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 238 as libc::c_int as libc::c_uint,
            name: b"icirc\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter i with circumflex, U+00EE ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 239 as libc::c_int as libc::c_uint,
            name: b"iuml\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter i with diaeresis, U+00EF ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 240 as libc::c_int as libc::c_uint,
            name: b"eth\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter eth, U+00F0 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 241 as libc::c_int as libc::c_uint,
            name: b"ntilde\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter n with tilde, U+00F1 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 242 as libc::c_int as libc::c_uint,
            name: b"ograve\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter o with grave, U+00F2 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 243 as libc::c_int as libc::c_uint,
            name: b"oacute\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter o with acute, U+00F3 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 244 as libc::c_int as libc::c_uint,
            name: b"ocirc\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter o with circumflex, U+00F4 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 245 as libc::c_int as libc::c_uint,
            name: b"otilde\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter o with tilde, U+00F5 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 246 as libc::c_int as libc::c_uint,
            name: b"ouml\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter o with diaeresis, U+00F6 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 247 as libc::c_int as libc::c_uint,
            name: b"divide\0" as *const u8 as *const libc::c_char,
            desc: b"division sign, U+00F7 ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 248 as libc::c_int as libc::c_uint,
            name: b"oslash\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter o with stroke, = latin small letter o slash, U+00F8 ISOlat1\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 249 as libc::c_int as libc::c_uint,
            name: b"ugrave\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter u with grave, U+00F9 ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 250 as libc::c_int as libc::c_uint,
            name: b"uacute\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter u with acute, U+00FA ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 251 as libc::c_int as libc::c_uint,
            name: b"ucirc\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter u with circumflex, U+00FB ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 252 as libc::c_int as libc::c_uint,
            name: b"uuml\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter u with diaeresis, U+00FC ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 253 as libc::c_int as libc::c_uint,
            name: b"yacute\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter y with acute, U+00FD ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 254 as libc::c_int as libc::c_uint,
            name: b"thorn\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter thorn with, U+00FE ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 255 as libc::c_int as libc::c_uint,
            name: b"yuml\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter y with diaeresis, U+00FF ISOlat1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 338 as libc::c_int as libc::c_uint,
            name: b"OElig\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital ligature OE, U+0152 ISOlat2\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 339 as libc::c_int as libc::c_uint,
            name: b"oelig\0" as *const u8 as *const libc::c_char,
            desc: b"latin small ligature oe, U+0153 ISOlat2\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 352 as libc::c_int as libc::c_uint,
            name: b"Scaron\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter S with caron, U+0160 ISOlat2\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 353 as libc::c_int as libc::c_uint,
            name: b"scaron\0" as *const u8 as *const libc::c_char,
            desc: b"latin small letter s with caron, U+0161 ISOlat2\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 376 as libc::c_int as libc::c_uint,
            name: b"Yuml\0" as *const u8 as *const libc::c_char,
            desc: b"latin capital letter Y with diaeresis, U+0178 ISOlat2\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 402 as libc::c_int as libc::c_uint,
            name: b"fnof\0" as *const u8 as *const libc::c_char,
            desc: b"latin small f with hook = function = florin, U+0192 ISOtech\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 710 as libc::c_int as libc::c_uint,
            name: b"circ\0" as *const u8 as *const libc::c_char,
            desc: b"modifier letter circumflex accent, U+02C6 ISOpub\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 732 as libc::c_int as libc::c_uint,
            name: b"tilde\0" as *const u8 as *const libc::c_char,
            desc: b"small tilde, U+02DC ISOdia\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 913 as libc::c_int as libc::c_uint,
            name: b"Alpha\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter alpha, U+0391\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 914 as libc::c_int as libc::c_uint,
            name: b"Beta\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter beta, U+0392\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 915 as libc::c_int as libc::c_uint,
            name: b"Gamma\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter gamma, U+0393 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 916 as libc::c_int as libc::c_uint,
            name: b"Delta\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter delta, U+0394 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 917 as libc::c_int as libc::c_uint,
            name: b"Epsilon\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter epsilon, U+0395\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 918 as libc::c_int as libc::c_uint,
            name: b"Zeta\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter zeta, U+0396\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 919 as libc::c_int as libc::c_uint,
            name: b"Eta\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter eta, U+0397\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 920 as libc::c_int as libc::c_uint,
            name: b"Theta\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter theta, U+0398 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 921 as libc::c_int as libc::c_uint,
            name: b"Iota\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter iota, U+0399\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 922 as libc::c_int as libc::c_uint,
            name: b"Kappa\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter kappa, U+039A\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 923 as libc::c_int as libc::c_uint,
            name: b"Lambda\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter lambda, U+039B ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 924 as libc::c_int as libc::c_uint,
            name: b"Mu\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter mu, U+039C\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 925 as libc::c_int as libc::c_uint,
            name: b"Nu\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter nu, U+039D\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 926 as libc::c_int as libc::c_uint,
            name: b"Xi\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter xi, U+039E ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 927 as libc::c_int as libc::c_uint,
            name: b"Omicron\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter omicron, U+039F\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 928 as libc::c_int as libc::c_uint,
            name: b"Pi\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter pi, U+03A0 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 929 as libc::c_int as libc::c_uint,
            name: b"Rho\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter rho, U+03A1\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 931 as libc::c_int as libc::c_uint,
            name: b"Sigma\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter sigma, U+03A3 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 932 as libc::c_int as libc::c_uint,
            name: b"Tau\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter tau, U+03A4\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 933 as libc::c_int as libc::c_uint,
            name: b"Upsilon\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter upsilon, U+03A5 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 934 as libc::c_int as libc::c_uint,
            name: b"Phi\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter phi, U+03A6 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 935 as libc::c_int as libc::c_uint,
            name: b"Chi\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter chi, U+03A7\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 936 as libc::c_int as libc::c_uint,
            name: b"Psi\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter psi, U+03A8 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 937 as libc::c_int as libc::c_uint,
            name: b"Omega\0" as *const u8 as *const libc::c_char,
            desc: b"greek capital letter omega, U+03A9 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 945 as libc::c_int as libc::c_uint,
            name: b"alpha\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter alpha, U+03B1 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 946 as libc::c_int as libc::c_uint,
            name: b"beta\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter beta, U+03B2 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 947 as libc::c_int as libc::c_uint,
            name: b"gamma\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter gamma, U+03B3 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 948 as libc::c_int as libc::c_uint,
            name: b"delta\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter delta, U+03B4 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 949 as libc::c_int as libc::c_uint,
            name: b"epsilon\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter epsilon, U+03B5 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 950 as libc::c_int as libc::c_uint,
            name: b"zeta\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter zeta, U+03B6 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 951 as libc::c_int as libc::c_uint,
            name: b"eta\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter eta, U+03B7 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 952 as libc::c_int as libc::c_uint,
            name: b"theta\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter theta, U+03B8 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 953 as libc::c_int as libc::c_uint,
            name: b"iota\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter iota, U+03B9 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 954 as libc::c_int as libc::c_uint,
            name: b"kappa\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter kappa, U+03BA ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 955 as libc::c_int as libc::c_uint,
            name: b"lambda\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter lambda, U+03BB ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 956 as libc::c_int as libc::c_uint,
            name: b"mu\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter mu, U+03BC ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 957 as libc::c_int as libc::c_uint,
            name: b"nu\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter nu, U+03BD ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 958 as libc::c_int as libc::c_uint,
            name: b"xi\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter xi, U+03BE ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 959 as libc::c_int as libc::c_uint,
            name: b"omicron\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter omicron, U+03BF NEW\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 960 as libc::c_int as libc::c_uint,
            name: b"pi\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter pi, U+03C0 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 961 as libc::c_int as libc::c_uint,
            name: b"rho\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter rho, U+03C1 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 962 as libc::c_int as libc::c_uint,
            name: b"sigmaf\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter final sigma, U+03C2 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 963 as libc::c_int as libc::c_uint,
            name: b"sigma\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter sigma, U+03C3 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 964 as libc::c_int as libc::c_uint,
            name: b"tau\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter tau, U+03C4 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 965 as libc::c_int as libc::c_uint,
            name: b"upsilon\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter upsilon, U+03C5 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 966 as libc::c_int as libc::c_uint,
            name: b"phi\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter phi, U+03C6 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 967 as libc::c_int as libc::c_uint,
            name: b"chi\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter chi, U+03C7 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 968 as libc::c_int as libc::c_uint,
            name: b"psi\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter psi, U+03C8 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 969 as libc::c_int as libc::c_uint,
            name: b"omega\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter omega, U+03C9 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 977 as libc::c_int as libc::c_uint,
            name: b"thetasym\0" as *const u8 as *const libc::c_char,
            desc: b"greek small letter theta symbol, U+03D1 NEW\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 978 as libc::c_int as libc::c_uint,
            name: b"upsih\0" as *const u8 as *const libc::c_char,
            desc: b"greek upsilon with hook symbol, U+03D2 NEW\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 982 as libc::c_int as libc::c_uint,
            name: b"piv\0" as *const u8 as *const libc::c_char,
            desc: b"greek pi symbol, U+03D6 ISOgrk3\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8194 as libc::c_int as libc::c_uint,
            name: b"ensp\0" as *const u8 as *const libc::c_char,
            desc: b"en space, U+2002 ISOpub\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8195 as libc::c_int as libc::c_uint,
            name: b"emsp\0" as *const u8 as *const libc::c_char,
            desc: b"em space, U+2003 ISOpub\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8201 as libc::c_int as libc::c_uint,
            name: b"thinsp\0" as *const u8 as *const libc::c_char,
            desc: b"thin space, U+2009 ISOpub\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8204 as libc::c_int as libc::c_uint,
            name: b"zwnj\0" as *const u8 as *const libc::c_char,
            desc: b"zero width non-joiner, U+200C NEW RFC 2070\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8205 as libc::c_int as libc::c_uint,
            name: b"zwj\0" as *const u8 as *const libc::c_char,
            desc: b"zero width joiner, U+200D NEW RFC 2070\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8206 as libc::c_int as libc::c_uint,
            name: b"lrm\0" as *const u8 as *const libc::c_char,
            desc: b"left-to-right mark, U+200E NEW RFC 2070\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8207 as libc::c_int as libc::c_uint,
            name: b"rlm\0" as *const u8 as *const libc::c_char,
            desc: b"right-to-left mark, U+200F NEW RFC 2070\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8211 as libc::c_int as libc::c_uint,
            name: b"ndash\0" as *const u8 as *const libc::c_char,
            desc: b"en dash, U+2013 ISOpub\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8212 as libc::c_int as libc::c_uint,
            name: b"mdash\0" as *const u8 as *const libc::c_char,
            desc: b"em dash, U+2014 ISOpub\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8216 as libc::c_int as libc::c_uint,
            name: b"lsquo\0" as *const u8 as *const libc::c_char,
            desc: b"left single quotation mark, U+2018 ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8217 as libc::c_int as libc::c_uint,
            name: b"rsquo\0" as *const u8 as *const libc::c_char,
            desc: b"right single quotation mark, U+2019 ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8218 as libc::c_int as libc::c_uint,
            name: b"sbquo\0" as *const u8 as *const libc::c_char,
            desc: b"single low-9 quotation mark, U+201A NEW\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8220 as libc::c_int as libc::c_uint,
            name: b"ldquo\0" as *const u8 as *const libc::c_char,
            desc: b"left double quotation mark, U+201C ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8221 as libc::c_int as libc::c_uint,
            name: b"rdquo\0" as *const u8 as *const libc::c_char,
            desc: b"right double quotation mark, U+201D ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8222 as libc::c_int as libc::c_uint,
            name: b"bdquo\0" as *const u8 as *const libc::c_char,
            desc: b"double low-9 quotation mark, U+201E NEW\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8224 as libc::c_int as libc::c_uint,
            name: b"dagger\0" as *const u8 as *const libc::c_char,
            desc: b"dagger, U+2020 ISOpub\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8225 as libc::c_int as libc::c_uint,
            name: b"Dagger\0" as *const u8 as *const libc::c_char,
            desc: b"double dagger, U+2021 ISOpub\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8226 as libc::c_int as libc::c_uint,
            name: b"bull\0" as *const u8 as *const libc::c_char,
            desc: b"bullet = black small circle, U+2022 ISOpub\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8230 as libc::c_int as libc::c_uint,
            name: b"hellip\0" as *const u8 as *const libc::c_char,
            desc: b"horizontal ellipsis = three dot leader, U+2026 ISOpub\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8240 as libc::c_int as libc::c_uint,
            name: b"permil\0" as *const u8 as *const libc::c_char,
            desc: b"per mille sign, U+2030 ISOtech\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8242 as libc::c_int as libc::c_uint,
            name: b"prime\0" as *const u8 as *const libc::c_char,
            desc: b"prime = minutes = feet, U+2032 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8243 as libc::c_int as libc::c_uint,
            name: b"Prime\0" as *const u8 as *const libc::c_char,
            desc: b"double prime = seconds = inches, U+2033 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8249 as libc::c_int as libc::c_uint,
            name: b"lsaquo\0" as *const u8 as *const libc::c_char,
            desc: b"single left-pointing angle quotation mark, U+2039 ISO proposed\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8250 as libc::c_int as libc::c_uint,
            name: b"rsaquo\0" as *const u8 as *const libc::c_char,
            desc: b"single right-pointing angle quotation mark, U+203A ISO proposed\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8254 as libc::c_int as libc::c_uint,
            name: b"oline\0" as *const u8 as *const libc::c_char,
            desc: b"overline = spacing overscore, U+203E NEW\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8260 as libc::c_int as libc::c_uint,
            name: b"frasl\0" as *const u8 as *const libc::c_char,
            desc: b"fraction slash, U+2044 NEW\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8364 as libc::c_int as libc::c_uint,
            name: b"euro\0" as *const u8 as *const libc::c_char,
            desc: b"euro sign, U+20AC NEW\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8465 as libc::c_int as libc::c_uint,
            name: b"image\0" as *const u8 as *const libc::c_char,
            desc: b"blackletter capital I = imaginary part, U+2111 ISOamso\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8472 as libc::c_int as libc::c_uint,
            name: b"weierp\0" as *const u8 as *const libc::c_char,
            desc: b"script capital P = power set = Weierstrass p, U+2118 ISOamso\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8476 as libc::c_int as libc::c_uint,
            name: b"real\0" as *const u8 as *const libc::c_char,
            desc: b"blackletter capital R = real part symbol, U+211C ISOamso\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8482 as libc::c_int as libc::c_uint,
            name: b"trade\0" as *const u8 as *const libc::c_char,
            desc: b"trade mark sign, U+2122 ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8501 as libc::c_int as libc::c_uint,
            name: b"alefsym\0" as *const u8 as *const libc::c_char,
            desc: b"alef symbol = first transfinite cardinal, U+2135 NEW\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8592 as libc::c_int as libc::c_uint,
            name: b"larr\0" as *const u8 as *const libc::c_char,
            desc: b"leftwards arrow, U+2190 ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8593 as libc::c_int as libc::c_uint,
            name: b"uarr\0" as *const u8 as *const libc::c_char,
            desc: b"upwards arrow, U+2191 ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8594 as libc::c_int as libc::c_uint,
            name: b"rarr\0" as *const u8 as *const libc::c_char,
            desc: b"rightwards arrow, U+2192 ISOnum\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8595 as libc::c_int as libc::c_uint,
            name: b"darr\0" as *const u8 as *const libc::c_char,
            desc: b"downwards arrow, U+2193 ISOnum\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8596 as libc::c_int as libc::c_uint,
            name: b"harr\0" as *const u8 as *const libc::c_char,
            desc: b"left right arrow, U+2194 ISOamsa\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8629 as libc::c_int as libc::c_uint,
            name: b"crarr\0" as *const u8 as *const libc::c_char,
            desc: b"downwards arrow with corner leftwards = carriage return, U+21B5 NEW\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8656 as libc::c_int as libc::c_uint,
            name: b"lArr\0" as *const u8 as *const libc::c_char,
            desc: b"leftwards double arrow, U+21D0 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8657 as libc::c_int as libc::c_uint,
            name: b"uArr\0" as *const u8 as *const libc::c_char,
            desc: b"upwards double arrow, U+21D1 ISOamsa\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8658 as libc::c_int as libc::c_uint,
            name: b"rArr\0" as *const u8 as *const libc::c_char,
            desc: b"rightwards double arrow, U+21D2 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8659 as libc::c_int as libc::c_uint,
            name: b"dArr\0" as *const u8 as *const libc::c_char,
            desc: b"downwards double arrow, U+21D3 ISOamsa\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8660 as libc::c_int as libc::c_uint,
            name: b"hArr\0" as *const u8 as *const libc::c_char,
            desc: b"left right double arrow, U+21D4 ISOamsa\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8704 as libc::c_int as libc::c_uint,
            name: b"forall\0" as *const u8 as *const libc::c_char,
            desc: b"for all, U+2200 ISOtech\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8706 as libc::c_int as libc::c_uint,
            name: b"part\0" as *const u8 as *const libc::c_char,
            desc: b"partial differential, U+2202 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8707 as libc::c_int as libc::c_uint,
            name: b"exist\0" as *const u8 as *const libc::c_char,
            desc: b"there exists, U+2203 ISOtech\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8709 as libc::c_int as libc::c_uint,
            name: b"empty\0" as *const u8 as *const libc::c_char,
            desc: b"empty set = null set = diameter, U+2205 ISOamso\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8711 as libc::c_int as libc::c_uint,
            name: b"nabla\0" as *const u8 as *const libc::c_char,
            desc: b"nabla = backward difference, U+2207 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8712 as libc::c_int as libc::c_uint,
            name: b"isin\0" as *const u8 as *const libc::c_char,
            desc: b"element of, U+2208 ISOtech\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8713 as libc::c_int as libc::c_uint,
            name: b"notin\0" as *const u8 as *const libc::c_char,
            desc: b"not an element of, U+2209 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8715 as libc::c_int as libc::c_uint,
            name: b"ni\0" as *const u8 as *const libc::c_char,
            desc: b"contains as member, U+220B ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8719 as libc::c_int as libc::c_uint,
            name: b"prod\0" as *const u8 as *const libc::c_char,
            desc: b"n-ary product = product sign, U+220F ISOamsb\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8721 as libc::c_int as libc::c_uint,
            name: b"sum\0" as *const u8 as *const libc::c_char,
            desc: b"n-ary summation, U+2211 ISOamsb\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8722 as libc::c_int as libc::c_uint,
            name: b"minus\0" as *const u8 as *const libc::c_char,
            desc: b"minus sign, U+2212 ISOtech\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8727 as libc::c_int as libc::c_uint,
            name: b"lowast\0" as *const u8 as *const libc::c_char,
            desc: b"asterisk operator, U+2217 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8730 as libc::c_int as libc::c_uint,
            name: b"radic\0" as *const u8 as *const libc::c_char,
            desc: b"square root = radical sign, U+221A ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8733 as libc::c_int as libc::c_uint,
            name: b"prop\0" as *const u8 as *const libc::c_char,
            desc: b"proportional to, U+221D ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8734 as libc::c_int as libc::c_uint,
            name: b"infin\0" as *const u8 as *const libc::c_char,
            desc: b"infinity, U+221E ISOtech\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8736 as libc::c_int as libc::c_uint,
            name: b"ang\0" as *const u8 as *const libc::c_char,
            desc: b"angle, U+2220 ISOamso\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8743 as libc::c_int as libc::c_uint,
            name: b"and\0" as *const u8 as *const libc::c_char,
            desc: b"logical and = wedge, U+2227 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8744 as libc::c_int as libc::c_uint,
            name: b"or\0" as *const u8 as *const libc::c_char,
            desc: b"logical or = vee, U+2228 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8745 as libc::c_int as libc::c_uint,
            name: b"cap\0" as *const u8 as *const libc::c_char,
            desc: b"intersection = cap, U+2229 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8746 as libc::c_int as libc::c_uint,
            name: b"cup\0" as *const u8 as *const libc::c_char,
            desc: b"union = cup, U+222A ISOtech\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8747 as libc::c_int as libc::c_uint,
            name: b"int\0" as *const u8 as *const libc::c_char,
            desc: b"integral, U+222B ISOtech\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8756 as libc::c_int as libc::c_uint,
            name: b"there4\0" as *const u8 as *const libc::c_char,
            desc: b"therefore, U+2234 ISOtech\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8764 as libc::c_int as libc::c_uint,
            name: b"sim\0" as *const u8 as *const libc::c_char,
            desc: b"tilde operator = varies with = similar to, U+223C ISOtech\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8773 as libc::c_int as libc::c_uint,
            name: b"cong\0" as *const u8 as *const libc::c_char,
            desc: b"approximately equal to, U+2245 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8776 as libc::c_int as libc::c_uint,
            name: b"asymp\0" as *const u8 as *const libc::c_char,
            desc: b"almost equal to = asymptotic to, U+2248 ISOamsr\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8800 as libc::c_int as libc::c_uint,
            name: b"ne\0" as *const u8 as *const libc::c_char,
            desc: b"not equal to, U+2260 ISOtech\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8801 as libc::c_int as libc::c_uint,
            name: b"equiv\0" as *const u8 as *const libc::c_char,
            desc: b"identical to, U+2261 ISOtech\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8804 as libc::c_int as libc::c_uint,
            name: b"le\0" as *const u8 as *const libc::c_char,
            desc: b"less-than or equal to, U+2264 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8805 as libc::c_int as libc::c_uint,
            name: b"ge\0" as *const u8 as *const libc::c_char,
            desc: b"greater-than or equal to, U+2265 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8834 as libc::c_int as libc::c_uint,
            name: b"sub\0" as *const u8 as *const libc::c_char,
            desc: b"subset of, U+2282 ISOtech\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8835 as libc::c_int as libc::c_uint,
            name: b"sup\0" as *const u8 as *const libc::c_char,
            desc: b"superset of, U+2283 ISOtech\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8836 as libc::c_int as libc::c_uint,
            name: b"nsub\0" as *const u8 as *const libc::c_char,
            desc: b"not a subset of, U+2284 ISOamsn\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8838 as libc::c_int as libc::c_uint,
            name: b"sube\0" as *const u8 as *const libc::c_char,
            desc: b"subset of or equal to, U+2286 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8839 as libc::c_int as libc::c_uint,
            name: b"supe\0" as *const u8 as *const libc::c_char,
            desc: b"superset of or equal to, U+2287 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8853 as libc::c_int as libc::c_uint,
            name: b"oplus\0" as *const u8 as *const libc::c_char,
            desc: b"circled plus = direct sum, U+2295 ISOamsb\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8855 as libc::c_int as libc::c_uint,
            name: b"otimes\0" as *const u8 as *const libc::c_char,
            desc: b"circled times = vector product, U+2297 ISOamsb\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8869 as libc::c_int as libc::c_uint,
            name: b"perp\0" as *const u8 as *const libc::c_char,
            desc: b"up tack = orthogonal to = perpendicular, U+22A5 ISOtech\0"
                as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8901 as libc::c_int as libc::c_uint,
            name: b"sdot\0" as *const u8 as *const libc::c_char,
            desc: b"dot operator, U+22C5 ISOamsb\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8968 as libc::c_int as libc::c_uint,
            name: b"lceil\0" as *const u8 as *const libc::c_char,
            desc: b"left ceiling = apl upstile, U+2308 ISOamsc\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8969 as libc::c_int as libc::c_uint,
            name: b"rceil\0" as *const u8 as *const libc::c_char,
            desc: b"right ceiling, U+2309 ISOamsc\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8970 as libc::c_int as libc::c_uint,
            name: b"lfloor\0" as *const u8 as *const libc::c_char,
            desc: b"left floor = apl downstile, U+230A ISOamsc\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 8971 as libc::c_int as libc::c_uint,
            name: b"rfloor\0" as *const u8 as *const libc::c_char,
            desc: b"right floor, U+230B ISOamsc\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 9001 as libc::c_int as libc::c_uint,
            name: b"lang\0" as *const u8 as *const libc::c_char,
            desc: b"left-pointing angle bracket = bra, U+2329 ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 9002 as libc::c_int as libc::c_uint,
            name: b"rang\0" as *const u8 as *const libc::c_char,
            desc: b"right-pointing angle bracket = ket, U+232A ISOtech\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 9674 as libc::c_int as libc::c_uint,
            name: b"loz\0" as *const u8 as *const libc::c_char,
            desc: b"lozenge, U+25CA ISOpub\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 9824 as libc::c_int as libc::c_uint,
            name: b"spades\0" as *const u8 as *const libc::c_char,
            desc: b"black spade suit, U+2660 ISOpub\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 9827 as libc::c_int as libc::c_uint,
            name: b"clubs\0" as *const u8 as *const libc::c_char,
            desc: b"black club suit = shamrock, U+2663 ISOpub\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 9829 as libc::c_int as libc::c_uint,
            name: b"hearts\0" as *const u8 as *const libc::c_char,
            desc: b"black heart suit = valentine, U+2665 ISOpub\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
    {
        let mut init = _htmlEntityDesc {
            value: 9830 as libc::c_int as libc::c_uint,
            name: b"diams\0" as *const u8 as *const libc::c_char,
            desc: b"black diamond suit, U+2666 ISOpub\0" as *const u8
                as *const libc::c_char,
        };
        init
    },
];
#[no_mangle]
pub unsafe extern "C" fn htmlEntityLookup(
    mut name: *const xmlChar,
) -> *const htmlEntityDesc {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (::std::mem::size_of::<[htmlEntityDesc; 253]>() as libc::c_ulong)
            .wrapping_div(::std::mem::size_of::<htmlEntityDesc>() as libc::c_ulong)
    {
        if xmlStrEqual(name, html40EntitiesTable[i as usize].name as *mut xmlChar) != 0 {
            return &*html40EntitiesTable.as_ptr().offset(i as isize)
                as *const htmlEntityDesc as htmlEntityDescPtr as *const htmlEntityDesc;
        }
        i = i.wrapping_add(1);
    }
    return 0 as *const htmlEntityDesc;
}
#[no_mangle]
pub unsafe extern "C" fn htmlEntityValueLookup(
    mut value: libc::c_uint,
) -> *const htmlEntityDesc {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (::std::mem::size_of::<[htmlEntityDesc; 253]>() as libc::c_ulong)
            .wrapping_div(::std::mem::size_of::<htmlEntityDesc>() as libc::c_ulong)
    {
        if html40EntitiesTable[i as usize].value >= value {
            if html40EntitiesTable[i as usize].value > value {
                break;
            }
            return &*html40EntitiesTable.as_ptr().offset(i as isize)
                as *const htmlEntityDesc as htmlEntityDescPtr as *const htmlEntityDesc;
        } else {
            i = i.wrapping_add(1);
        }
    }
    return 0 as *const htmlEntityDesc;
}
#[no_mangle]
pub unsafe extern "C" fn UTF8ToHtml(
    mut out: *mut libc::c_uchar,
    mut outlen: *mut libc::c_int,
    mut in_0: *const libc::c_uchar,
    mut inlen: *mut libc::c_int,
) -> libc::c_int {
    let mut processed: *const libc::c_uchar = in_0;
    let mut outend: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut outstart: *const libc::c_uchar = out;
    let mut instart: *const libc::c_uchar = in_0;
    // let mut inend: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut inend: *const u8 = 0 as *const libc::c_void as *const u8;
    let mut c: libc::c_uint = 0;
    let mut d: libc::c_uint = 0;
    let mut trailing: libc::c_int = 0;
    if out.is_null() || outlen.is_null() || inlen.is_null() {
        return -(1 as libc::c_int);
    }
    if in_0.is_null() {
        *outlen = 0 as libc::c_int;
        *inlen = 0 as libc::c_int;
        return 0 as libc::c_int;
    }
    inend = in_0.offset(*inlen as isize);
    outend = out.offset(*outlen as isize);
    while in_0 < inend {
        let fresh20 = in_0;
        in_0 = in_0.offset(1);
        d = *fresh20 as libc::c_uint;
        if d < 0x80 as libc::c_int as libc::c_uint {
            c = d;
            trailing = 0 as libc::c_int;
        } else if d < 0xc0 as libc::c_int as libc::c_uint {
            *outlen = out.offset_from(outstart) as libc::c_long as libc::c_int;
            *inlen = processed.offset_from(instart) as libc::c_long as libc::c_int;
            return -(2 as libc::c_int);
        } else {
            if d < 0xe0 as libc::c_int as libc::c_uint {
                c = d & 0x1f as libc::c_int as libc::c_uint;
                trailing = 1 as libc::c_int;
            } else if d < 0xf0 as libc::c_int as libc::c_uint {
                c = d & 0xf as libc::c_int as libc::c_uint;
                trailing = 2 as libc::c_int;
            } else if d < 0xf8 as libc::c_int as libc::c_uint {
                c = d & 0x7 as libc::c_int as libc::c_uint;
                trailing = 3 as libc::c_int;
            } else {
                *outlen = out.offset_from(outstart) as libc::c_long as libc::c_int;
                *inlen = processed.offset_from(instart) as libc::c_long as libc::c_int;
                return -(2 as libc::c_int);
            }
        }
        if (inend.offset_from(in_0) as libc::c_long) < trailing as libc::c_long {
            break;
        }
        while trailing != 0 {
            if in_0 >= inend
                || {
                    let fresh21 = in_0;
                    in_0 = in_0.offset(1);
                    d = *fresh21 as libc::c_uint;
                    d & 0xc0 as libc::c_int as libc::c_uint
                        != 0x80 as libc::c_int as libc::c_uint
                }
            {
                break;
            }
            c <<= 6 as libc::c_int;
            c |= d & 0x3f as libc::c_int as libc::c_uint;
            trailing -= 1;
        }
        if c < 0x80 as libc::c_int as libc::c_uint {
            if out.offset(1 as libc::c_int as isize) >= outend as *mut libc::c_uchar {
                break;
            }
            let fresh22 = out;
            out = out.offset(1);
            *fresh22 = c as libc::c_uchar;
        } else {
            let mut len: libc::c_int = 0;
            let mut ent: *const htmlEntityDesc = 0 as *const htmlEntityDesc;
            let mut cp: *const libc::c_char = 0 as *const libc::c_char;
            let mut nbuf: [libc::c_char; 16] = [0; 16];
            ent = htmlEntityValueLookup(c);
            if ent.is_null() {
                snprintf(
                    nbuf.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
                    b"#%u\0" as *const u8 as *const libc::c_char,
                    c,
                );
                cp = nbuf.as_mut_ptr();
            } else {
                cp = (*ent).name;
            }
            len = strlen(cp) as libc::c_int;
            if out.offset(2 as libc::c_int as isize).offset(len as isize)
                >= outend as *mut libc::c_uchar
            {
                break;
            }
            let fresh23 = out;
            out = out.offset(1);
            *fresh23 = '&' as i32 as libc::c_uchar;
            memcpy(
                out as *mut libc::c_void,
                cp as *const libc::c_void,
                len as libc::c_ulong,
            );
            out = out.offset(len as isize);
            let fresh24 = out;
            out = out.offset(1);
            *fresh24 = ';' as i32 as libc::c_uchar;
        }
        processed = in_0;
    }
    *outlen = out.offset_from(outstart) as libc::c_long as libc::c_int;
    *inlen = processed.offset_from(instart) as libc::c_long as libc::c_int;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn htmlEncodeEntities(
    mut out: *mut libc::c_uchar,
    mut outlen: *mut libc::c_int,
    mut in_0: *const libc::c_uchar,
    mut inlen: *mut libc::c_int,
    mut quoteChar: libc::c_int,
) -> libc::c_int {
    let mut processed: *const libc::c_uchar = in_0;
    let mut outend: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut outstart: *const libc::c_uchar = out;
    let mut instart: *const libc::c_uchar = in_0;
    let mut inend: *const libc::c_uchar = 0 as *const libc::c_void as *const libc::c_uchar;
    let mut c: libc::c_uint = 0;
    let mut d: libc::c_uint = 0;
    let mut trailing: libc::c_int = 0;
    if out.is_null() || outlen.is_null() || inlen.is_null() || in_0.is_null() {
        return -(1 as libc::c_int);
    }
    outend = out.offset(*outlen as isize);
    inend = in_0.offset(*inlen as isize);
    while in_0 < inend {
        let fresh25 = in_0;
        in_0 = in_0.offset(1);
        d = *fresh25 as libc::c_uint;
        if d < 0x80 as libc::c_int as libc::c_uint {
            c = d;
            trailing = 0 as libc::c_int;
        } else if d < 0xc0 as libc::c_int as libc::c_uint {
            *outlen = out.offset_from(outstart) as libc::c_long as libc::c_int;
            *inlen = processed.offset_from(instart) as libc::c_long as libc::c_int;
            return -(2 as libc::c_int);
        } else {
            if d < 0xe0 as libc::c_int as libc::c_uint {
                c = d & 0x1f as libc::c_int as libc::c_uint;
                trailing = 1 as libc::c_int;
            } else if d < 0xf0 as libc::c_int as libc::c_uint {
                c = d & 0xf as libc::c_int as libc::c_uint;
                trailing = 2 as libc::c_int;
            } else if d < 0xf8 as libc::c_int as libc::c_uint {
                c = d & 0x7 as libc::c_int as libc::c_uint;
                trailing = 3 as libc::c_int;
            } else {
                *outlen = out.offset_from(outstart) as libc::c_long as libc::c_int;
                *inlen = processed.offset_from(instart) as libc::c_long as libc::c_int;
                return -(2 as libc::c_int);
            }
        }
        if (inend.offset_from(in_0) as libc::c_long) < trailing as libc::c_long {
            break;
        }
        loop {
            let fresh26 = trailing;
            trailing = trailing - 1;
            if !(fresh26 != 0) {
                break;
            }
            let fresh27 = in_0;
            in_0 = in_0.offset(1);
            d = *fresh27 as libc::c_uint;
            if d & 0xc0 as libc::c_int as libc::c_uint
                != 0x80 as libc::c_int as libc::c_uint
            {
                *outlen = out.offset_from(outstart) as libc::c_long as libc::c_int;
                *inlen = processed.offset_from(instart) as libc::c_long as libc::c_int;
                return -(2 as libc::c_int);
            }
            c <<= 6 as libc::c_int;
            c |= d & 0x3f as libc::c_int as libc::c_uint;
        }
        if c < 0x80 as libc::c_int as libc::c_uint && c != quoteChar as libc::c_uint
            && c != '&' as i32 as libc::c_uint && c != '<' as i32 as libc::c_uint
            && c != '>' as i32 as libc::c_uint
        {
            if out >= outend as *mut libc::c_uchar {
                break;
            }
            let fresh28 = out;
            out = out.offset(1);
            *fresh28 = c as libc::c_uchar;
        } else {
            let mut ent: *const htmlEntityDesc = 0 as *const htmlEntityDesc;
            let mut cp: *const libc::c_char = 0 as *const libc::c_char;
            let mut nbuf: [libc::c_char; 16] = [0; 16];
            let mut len: libc::c_int = 0;
            ent = htmlEntityValueLookup(c);
            if ent.is_null() {
                snprintf(
                    nbuf.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
                    b"#%u\0" as *const u8 as *const libc::c_char,
                    c,
                );
                cp = nbuf.as_mut_ptr();
            } else {
                cp = (*ent).name;
            }
            len = strlen(cp) as libc::c_int;
            if out.offset(2 as libc::c_int as isize).offset(len as isize)
                > outend as *mut libc::c_uchar
            {
                break;
            }
            let fresh29 = out;
            out = out.offset(1);
            *fresh29 = '&' as i32 as libc::c_uchar;
            memcpy(
                out as *mut libc::c_void,
                cp as *const libc::c_void,
                len as libc::c_ulong,
            );
            out = out.offset(len as isize);
            let fresh30 = out;
            out = out.offset(1);
            *fresh30 = ';' as i32 as libc::c_uchar;
        }
        processed = in_0;
    }
    *outlen = out.offset_from(outstart) as libc::c_long as libc::c_int;
    *inlen = processed.offset_from(instart) as libc::c_long as libc::c_int;
    return 0 as libc::c_int;
}
unsafe extern "C" fn htmlNewInputStream(
    mut ctxt: htmlParserCtxtPtr,
) -> htmlParserInputPtr {
    let mut input: htmlParserInputPtr = 0 as *mut xmlParserInput;
    input = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<htmlParserInput>() as libc::c_ulong)
        as xmlParserInputPtr;
    if input.is_null() {
        htmlErrMemory(
            ctxt,
            b"couldn't allocate a new input stream\n\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as htmlParserInputPtr;
    }
    memset(
        input as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<htmlParserInput>() as libc::c_ulong,
    );
    let ref mut fresh31 = (*input).filename;
    *fresh31 = 0 as *const libc::c_char;
    let ref mut fresh32 = (*input).directory;
    *fresh32 = 0 as *const libc::c_char;
    let ref mut fresh33 = (*input).base;
    *fresh33 = 0 as *const xmlChar;
    let ref mut fresh34 = (*input).cur;
    *fresh34 = 0 as *const xmlChar;
    let ref mut fresh35 = (*input).buf;
    *fresh35 = 0 as xmlParserInputBufferPtr;
    (*input).line = 1 as libc::c_int;
    (*input).col = 1 as libc::c_int;
    let ref mut fresh36 = (*input).buf;
    *fresh36 = 0 as xmlParserInputBufferPtr;
    let ref mut fresh37 = (*input).free;
    *fresh37 = None;
    let ref mut fresh38 = (*input).version;
    *fresh38 = 0 as *const xmlChar;
    (*input).consumed = 0 as libc::c_int as libc::c_ulong;
    (*input).length = 0 as libc::c_int;
    return input;
}
static mut allowPCData: [*const libc::c_char; 53] = [
    b"a\0" as *const u8 as *const libc::c_char,
    b"abbr\0" as *const u8 as *const libc::c_char,
    b"acronym\0" as *const u8 as *const libc::c_char,
    b"address\0" as *const u8 as *const libc::c_char,
    b"applet\0" as *const u8 as *const libc::c_char,
    b"b\0" as *const u8 as *const libc::c_char,
    b"bdo\0" as *const u8 as *const libc::c_char,
    b"big\0" as *const u8 as *const libc::c_char,
    b"blockquote\0" as *const u8 as *const libc::c_char,
    b"body\0" as *const u8 as *const libc::c_char,
    b"button\0" as *const u8 as *const libc::c_char,
    b"caption\0" as *const u8 as *const libc::c_char,
    b"center\0" as *const u8 as *const libc::c_char,
    b"cite\0" as *const u8 as *const libc::c_char,
    b"code\0" as *const u8 as *const libc::c_char,
    b"dd\0" as *const u8 as *const libc::c_char,
    b"del\0" as *const u8 as *const libc::c_char,
    b"dfn\0" as *const u8 as *const libc::c_char,
    b"div\0" as *const u8 as *const libc::c_char,
    b"dt\0" as *const u8 as *const libc::c_char,
    b"em\0" as *const u8 as *const libc::c_char,
    b"font\0" as *const u8 as *const libc::c_char,
    b"form\0" as *const u8 as *const libc::c_char,
    b"h1\0" as *const u8 as *const libc::c_char,
    b"h2\0" as *const u8 as *const libc::c_char,
    b"h3\0" as *const u8 as *const libc::c_char,
    b"h4\0" as *const u8 as *const libc::c_char,
    b"h5\0" as *const u8 as *const libc::c_char,
    b"h6\0" as *const u8 as *const libc::c_char,
    b"i\0" as *const u8 as *const libc::c_char,
    b"iframe\0" as *const u8 as *const libc::c_char,
    b"ins\0" as *const u8 as *const libc::c_char,
    b"kbd\0" as *const u8 as *const libc::c_char,
    b"label\0" as *const u8 as *const libc::c_char,
    b"legend\0" as *const u8 as *const libc::c_char,
    b"li\0" as *const u8 as *const libc::c_char,
    b"noframes\0" as *const u8 as *const libc::c_char,
    b"noscript\0" as *const u8 as *const libc::c_char,
    b"object\0" as *const u8 as *const libc::c_char,
    b"p\0" as *const u8 as *const libc::c_char,
    b"pre\0" as *const u8 as *const libc::c_char,
    b"q\0" as *const u8 as *const libc::c_char,
    b"s\0" as *const u8 as *const libc::c_char,
    b"samp\0" as *const u8 as *const libc::c_char,
    b"small\0" as *const u8 as *const libc::c_char,
    b"span\0" as *const u8 as *const libc::c_char,
    b"strike\0" as *const u8 as *const libc::c_char,
    b"strong\0" as *const u8 as *const libc::c_char,
    b"td\0" as *const u8 as *const libc::c_char,
    b"th\0" as *const u8 as *const libc::c_char,
    b"tt\0" as *const u8 as *const libc::c_char,
    b"u\0" as *const u8 as *const libc::c_char,
    b"var\0" as *const u8 as *const libc::c_char,
];
unsafe extern "C" fn areBlanks(
    mut ctxt: htmlParserCtxtPtr,
    mut str: *const xmlChar,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_int = 0;
    let mut lastChild: xmlNodePtr = 0 as *mut xmlNode;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    j = 0 as libc::c_int;
    while j < len {
        if !(*str.offset(j as isize) as libc::c_int == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= *str.offset(j as isize) as libc::c_int
                && *str.offset(j as isize) as libc::c_int <= 0xa as libc::c_int
            || *str.offset(j as isize) as libc::c_int == 0xd as libc::c_int)
        {
            return 0 as libc::c_int;
        }
        j += 1;
    }
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    if *(*(*ctxt).input).cur as libc::c_int != '<' as i32 {
        return 0 as libc::c_int;
    }
    if ((*ctxt).name).is_null() {
        return 1 as libc::c_int;
    }
    if xmlStrEqual(
        (*ctxt).name,
        b"html\0" as *const u8 as *const libc::c_char as *mut xmlChar,
    ) != 0
    {
        return 1 as libc::c_int;
    }
    if xmlStrEqual(
        (*ctxt).name,
        b"head\0" as *const u8 as *const libc::c_char as *mut xmlChar,
    ) != 0
    {
        return 1 as libc::c_int;
    }
    if xmlStrEqual(
        (*ctxt).name,
        b"body\0" as *const u8 as *const libc::c_char as *mut xmlChar,
    ) != 0 && !((*ctxt).myDoc).is_null()
    {
        dtd = xmlGetIntSubset((*ctxt).myDoc as *const xmlDoc);
        if !dtd.is_null() && !((*dtd).ExternalID).is_null() {
            if xmlStrcasecmp(
                (*dtd).ExternalID,
                b"-//W3C//DTD HTML 4.01//EN\0" as *const u8 as *const libc::c_char
                    as *mut xmlChar,
            ) == 0
                || xmlStrcasecmp(
                    (*dtd).ExternalID,
                    b"-//W3C//DTD HTML 4//EN\0" as *const u8 as *const libc::c_char
                        as *mut xmlChar,
                ) == 0
            {
                return 1 as libc::c_int;
            }
        }
    }
    if ((*ctxt).node).is_null() {
        return 0 as libc::c_int;
    }
    lastChild = xmlGetLastChild((*ctxt).node as *const xmlNode);
    while !lastChild.is_null()
        && (*lastChild).type_0 as libc::c_uint
            == XML_COMMENT_NODE as libc::c_int as libc::c_uint
    {
        lastChild = (*lastChild).prev;
    }
    if lastChild.is_null() {
        if (*(*ctxt).node).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
            && !((*(*ctxt).node).content).is_null()
        {
            return 0 as libc::c_int;
        }
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong)
            < (::std::mem::size_of::<[*const libc::c_char; 53]>() as libc::c_ulong)
                .wrapping_div(
                    ::std::mem::size_of::<*const libc::c_char>() as libc::c_ulong,
                )
        {
            if xmlStrEqual((*ctxt).name, allowPCData[i as usize] as *mut xmlChar) != 0 {
                return 0 as libc::c_int;
            }
            i = i.wrapping_add(1);
        }
    } else if xmlNodeIsText(lastChild as *const xmlNode) != 0 {
        return 0 as libc::c_int
    } else {
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong)
            < (::std::mem::size_of::<[*const libc::c_char; 53]>() as libc::c_ulong)
                .wrapping_div(
                    ::std::mem::size_of::<*const libc::c_char>() as libc::c_ulong,
                )
        {
            if xmlStrEqual((*lastChild).name, allowPCData[i as usize] as *mut xmlChar)
                != 0
            {
                return 0 as libc::c_int;
            }
            i = i.wrapping_add(1);
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn htmlNewDocNoDtD(
    mut URI: *const xmlChar,
    mut ExternalID: *const xmlChar,
) -> htmlDocPtr {
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlDoc>() as libc::c_ulong) as xmlDocPtr;
    if cur.is_null() {
        htmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"HTML document creation failed\n\0" as *const u8 as *const libc::c_char,
        );
        return 0 as htmlDocPtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlDoc>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_HTML_DOCUMENT_NODE;
    let ref mut fresh39 = (*cur).version;
    *fresh39 = 0 as *const xmlChar;
    let ref mut fresh40 = (*cur).intSubset;
    *fresh40 = 0 as *mut _xmlDtd;
    let ref mut fresh41 = (*cur).doc;
    *fresh41 = cur;
    let ref mut fresh42 = (*cur).name;
    *fresh42 = 0 as *mut libc::c_char;
    let ref mut fresh43 = (*cur).children;
    *fresh43 = 0 as *mut _xmlNode;
    let ref mut fresh44 = (*cur).extSubset;
    *fresh44 = 0 as *mut _xmlDtd;
    let ref mut fresh45 = (*cur).oldNs;
    *fresh45 = 0 as *mut _xmlNs;
    let ref mut fresh46 = (*cur).encoding;
    *fresh46 = 0 as *const xmlChar;
    (*cur).standalone = 1 as libc::c_int;
    (*cur).compression = 0 as libc::c_int;
    let ref mut fresh47 = (*cur).ids;
    *fresh47 = 0 as *mut libc::c_void;
    let ref mut fresh48 = (*cur).refs;
    *fresh48 = 0 as *mut libc::c_void;
    let ref mut fresh49 = (*cur)._private;
    *fresh49 = 0 as *mut libc::c_void;
    (*cur).charset = XML_CHAR_ENCODING_UTF8 as libc::c_int;
    (*cur).properties = XML_DOC_HTML as libc::c_int | XML_DOC_USERBUILT as libc::c_int;
    if !ExternalID.is_null() || !URI.is_null() {
        xmlCreateIntSubset(
            cur,
            b"html\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ExternalID,
            URI,
        );
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue())
            .expect("non-null function pointer")(cur as xmlNodePtr);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn htmlNewDoc(
    mut URI: *const xmlChar,
    mut ExternalID: *const xmlChar,
) -> htmlDocPtr {
    if URI.is_null() && ExternalID.is_null() {
        return htmlNewDocNoDtD(
            b"http://www.w3.org/TR/REC-html40/loose.dtd\0" as *const u8
                as *const libc::c_char as *mut xmlChar,
            b"-//W3C//DTD HTML 4.0 Transitional//EN\0" as *const u8
                as *const libc::c_char as *mut xmlChar,
        );
    }
    return htmlNewDocNoDtD(URI, ExternalID);
}
unsafe extern "C" fn htmlSkipBogusComment(mut ctxt: htmlParserCtxtPtr) {
    let mut c: libc::c_int = 0;
    htmlParseErr(
        ctxt,
        XML_HTML_INCORRECTLY_OPENED_COMMENT,
        b"Incorrectly opened comment\n\0" as *const u8 as *const libc::c_char,
        0 as *const xmlChar,
        0 as *const xmlChar,
    );
    loop {
        c = *(*(*ctxt).input).cur as libc::c_int;
        if c == 0 as libc::c_int {
            break;
        }
        xmlNextChar(ctxt);
        if !(c != '>' as i32) {
            break;
        }
    };
}
unsafe extern "C" fn htmlParseHTMLName(mut ctxt: htmlParserCtxtPtr) -> *const xmlChar {
    let mut i: libc::c_int = 0 as libc::c_int;
    let mut loc: [xmlChar; 100] = [0; 100];
    if !(0x41 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
        && *(*(*ctxt).input).cur as libc::c_int <= 0x5a as libc::c_int
        || 0x61 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
            && *(*(*ctxt).input).cur as libc::c_int <= 0x7a as libc::c_int)
        && *(*(*ctxt).input).cur as libc::c_int != '_' as i32
        && *(*(*ctxt).input).cur as libc::c_int != ':' as i32
        && *(*(*ctxt).input).cur as libc::c_int != '.' as i32
    {
        return 0 as *const xmlChar;
    }
    while i < 100 as libc::c_int
        && (0x41 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
            && *(*(*ctxt).input).cur as libc::c_int <= 0x5a as libc::c_int
            || 0x61 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
                && *(*(*ctxt).input).cur as libc::c_int <= 0x7a as libc::c_int
            || 0x30 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
                && *(*(*ctxt).input).cur as libc::c_int <= 0x39 as libc::c_int
            || *(*(*ctxt).input).cur as libc::c_int == ':' as i32
            || *(*(*ctxt).input).cur as libc::c_int == '-' as i32
            || *(*(*ctxt).input).cur as libc::c_int == '_' as i32
            || *(*(*ctxt).input).cur as libc::c_int == '.' as i32)
    {
        if *(*(*ctxt).input).cur as libc::c_int >= 'A' as i32
            && *(*(*ctxt).input).cur as libc::c_int <= 'Z' as i32
        {
            loc[i
                as usize] = (*(*(*ctxt).input).cur as libc::c_int + 0x20 as libc::c_int)
                as xmlChar;
        } else {
            loc[i as usize] = *(*(*ctxt).input).cur as libc::c_int as xmlChar;
        }
        i += 1;
        xmlNextChar(ctxt);
    }
    return xmlDictLookup((*ctxt).dict, loc.as_mut_ptr(), i);
}
unsafe extern "C" fn htmlParseHTMLName_nonInvasive(
    mut ctxt: htmlParserCtxtPtr,
) -> *const xmlChar {
    let mut i: libc::c_int = 0 as libc::c_int;
    let mut loc: [xmlChar; 100] = [0; 100];
    if !(0x41 as libc::c_int
        <= *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            <= 0x5a as libc::c_int
        || 0x61 as libc::c_int
            <= *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                <= 0x7a as libc::c_int)
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            != '_' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            != ':' as i32
    {
        return 0 as *const xmlChar;
    }
    while i < 100 as libc::c_int
        && (0x41 as libc::c_int
            <= *((*(*ctxt).input).cur).offset((1 as libc::c_int + i) as isize)
                as libc::c_int
            && *((*(*ctxt).input).cur).offset((1 as libc::c_int + i) as isize)
                as libc::c_int <= 0x5a as libc::c_int
            || 0x61 as libc::c_int
                <= *((*(*ctxt).input).cur).offset((1 as libc::c_int + i) as isize)
                    as libc::c_int
                && *((*(*ctxt).input).cur).offset((1 as libc::c_int + i) as isize)
                    as libc::c_int <= 0x7a as libc::c_int
            || 0x30 as libc::c_int
                <= *((*(*ctxt).input).cur).offset((1 as libc::c_int + i) as isize)
                    as libc::c_int
                && *((*(*ctxt).input).cur).offset((1 as libc::c_int + i) as isize)
                    as libc::c_int <= 0x39 as libc::c_int
            || *((*(*ctxt).input).cur).offset((1 as libc::c_int + i) as isize)
                as libc::c_int == ':' as i32
            || *((*(*ctxt).input).cur).offset((1 as libc::c_int + i) as isize)
                as libc::c_int == '-' as i32
            || *((*(*ctxt).input).cur).offset((1 as libc::c_int + i) as isize)
                as libc::c_int == '_' as i32)
    {
        if *((*(*ctxt).input).cur).offset((1 as libc::c_int + i) as isize) as libc::c_int
            >= 'A' as i32
            && *((*(*ctxt).input).cur).offset((1 as libc::c_int + i) as isize)
                as libc::c_int <= 'Z' as i32
        {
            loc[i
                as usize] = (*((*(*ctxt).input).cur)
                .offset((1 as libc::c_int + i) as isize) as libc::c_int
                + 0x20 as libc::c_int) as xmlChar;
        } else {
            loc[i
                as usize] = *((*(*ctxt).input).cur)
                .offset((1 as libc::c_int + i) as isize);
        }
        i += 1;
    }
    return xmlDictLookup((*ctxt).dict, loc.as_mut_ptr(), i);
}
unsafe extern "C" fn htmlParseName(mut ctxt: htmlParserCtxtPtr) -> *const xmlChar {
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    let mut count: libc::c_int = 0 as libc::c_int;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
    in_0 = (*(*ctxt).input).cur;
    if *in_0 as libc::c_int >= 0x61 as libc::c_int
        && *in_0 as libc::c_int <= 0x7a as libc::c_int
        || *in_0 as libc::c_int >= 0x41 as libc::c_int
            && *in_0 as libc::c_int <= 0x5a as libc::c_int
        || *in_0 as libc::c_int == '_' as i32 || *in_0 as libc::c_int == ':' as i32
    {
        in_0 = in_0.offset(1);
        while *in_0 as libc::c_int >= 0x61 as libc::c_int
            && *in_0 as libc::c_int <= 0x7a as libc::c_int
            || *in_0 as libc::c_int >= 0x41 as libc::c_int
                && *in_0 as libc::c_int <= 0x5a as libc::c_int
            || *in_0 as libc::c_int >= 0x30 as libc::c_int
                && *in_0 as libc::c_int <= 0x39 as libc::c_int
            || *in_0 as libc::c_int == '_' as i32 || *in_0 as libc::c_int == '-' as i32
            || *in_0 as libc::c_int == ':' as i32 || *in_0 as libc::c_int == '.' as i32
        {
            in_0 = in_0.offset(1);
        }
        if in_0 == (*(*ctxt).input).end {
            return 0 as *const xmlChar;
        }
        if *in_0 as libc::c_int > 0 as libc::c_int
            && (*in_0 as libc::c_int) < 0x80 as libc::c_int
        {
            count = in_0.offset_from((*(*ctxt).input).cur) as libc::c_long
                as libc::c_int;
            ret = xmlDictLookup((*ctxt).dict, (*(*ctxt).input).cur, count);
            let ref mut fresh50 = (*(*ctxt).input).cur;
            *fresh50 = in_0;
            (*(*ctxt).input).col += count;
            return ret;
        }
    }
    return htmlParseNameComplex(ctxt);
}
unsafe extern "C" fn htmlParseNameComplex(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut l: libc::c_int = 0;
    let mut c: libc::c_int = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    let mut base: *const xmlChar = (*(*ctxt).input).base;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
    c = htmlCurrentChar(ctxt, &mut l);
    if c == ' ' as i32 || c == '>' as i32 || c == '/' as i32
        || !((if c < 0x100 as libc::c_int {
            (0x41 as libc::c_int <= c && c <= 0x5a as libc::c_int
                || 0x61 as libc::c_int <= c && c <= 0x7a as libc::c_int
                || 0xc0 as libc::c_int <= c && c <= 0xd6 as libc::c_int
                || 0xd8 as libc::c_int <= c && c <= 0xf6 as libc::c_int
                || 0xf8 as libc::c_int <= c) as libc::c_int
        } else {
            xmlCharInRange(c as libc::c_uint, &xmlIsBaseCharGroup)
        }) != 0
            || (if c < 0x100 as libc::c_int {
                0 as libc::c_int
            } else {
                (0x4e00 as libc::c_int <= c && c <= 0x9fa5 as libc::c_int
                    || c == 0x3007 as libc::c_int
                    || 0x3021 as libc::c_int <= c && c <= 0x3029 as libc::c_int)
                    as libc::c_int
            }) != 0) && c != '_' as i32 && c != ':' as i32
    {
        return 0 as *const xmlChar;
    }
    while c != ' ' as i32 && c != '>' as i32 && c != '/' as i32
        && ((if c < 0x100 as libc::c_int {
            (0x41 as libc::c_int <= c && c <= 0x5a as libc::c_int
                || 0x61 as libc::c_int <= c && c <= 0x7a as libc::c_int
                || 0xc0 as libc::c_int <= c && c <= 0xd6 as libc::c_int
                || 0xd8 as libc::c_int <= c && c <= 0xf6 as libc::c_int
                || 0xf8 as libc::c_int <= c) as libc::c_int
        } else {
            xmlCharInRange(c as libc::c_uint, &xmlIsBaseCharGroup)
        }) != 0
            || (if c < 0x100 as libc::c_int {
                0 as libc::c_int
            } else {
                (0x4e00 as libc::c_int <= c && c <= 0x9fa5 as libc::c_int
                    || c == 0x3007 as libc::c_int
                    || 0x3021 as libc::c_int <= c && c <= 0x3029 as libc::c_int)
                    as libc::c_int
            }) != 0
            || (if c < 0x100 as libc::c_int {
                (0x30 as libc::c_int <= c && c <= 0x39 as libc::c_int) as libc::c_int
            } else {
                xmlCharInRange(c as libc::c_uint, &xmlIsDigitGroup)
            }) != 0 || c == '.' as i32 || c == '-' as i32 || c == '_' as i32
            || c == ':' as i32
            || (if c < 0x100 as libc::c_int {
                0 as libc::c_int
            } else {
                xmlCharInRange(c as libc::c_uint, &xmlIsCombiningGroup)
            }) != 0
            || (if c < 0x100 as libc::c_int {
                (c == 0xb7 as libc::c_int) as libc::c_int
            } else {
                xmlCharInRange(c as libc::c_uint, &xmlIsExtenderGroup)
            }) != 0)
    {
        let fresh51 = count;
        count = count + 1;
        if fresh51 > 100 as libc::c_int {
            count = 0 as libc::c_int;
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
        }
        len += l;
        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
            let ref mut fresh52 = (*(*ctxt).input).line;
            *fresh52 += 1;
            (*(*ctxt).input).col = 1 as libc::c_int;
        } else {
            let ref mut fresh53 = (*(*ctxt).input).col;
            *fresh53 += 1;
        }
        (*ctxt).token = 0 as libc::c_int;
        let ref mut fresh54 = (*(*ctxt).input).cur;
        *fresh54 = (*fresh54).offset(l as isize);
        c = htmlCurrentChar(ctxt, &mut l);
        if (*(*ctxt).input).base != base {
            return htmlParseNameComplex(ctxt);
        }
    }
    if (((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long)
        < len as libc::c_long
    {
        htmlParseErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"unexpected change of input buffer\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as *const xmlChar;
    }
    return xmlDictLookup(
        (*ctxt).dict,
        ((*(*ctxt).input).cur).offset(-(len as isize)),
        len,
    );
}
unsafe extern "C" fn htmlParseHTMLAttribute(
    mut ctxt: htmlParserCtxtPtr,
    stop: xmlChar,
) -> *mut xmlChar {
    let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
    let mut buffer_size: libc::c_int = 0 as libc::c_int;
    let mut out: *mut xmlChar = 0 as *mut xmlChar;
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut ent: *const htmlEntityDesc = 0 as *const htmlEntityDesc;
    buffer_size = 100 as libc::c_int;
    buffer = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (buffer_size as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if buffer.is_null() {
        htmlErrMemory(
            ctxt,
            b"buffer allocation failed\n\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut xmlChar;
    }
    out = buffer;
    while *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int
        && *(*(*ctxt).input).cur as libc::c_int != stop as libc::c_int
    {
        if stop as libc::c_int == 0 as libc::c_int
            && *(*(*ctxt).input).cur as libc::c_int == '>' as i32
        {
            break;
        }
        if stop as libc::c_int == 0 as libc::c_int
            && (*(*(*ctxt).input).cur as libc::c_int == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
                    && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
                || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int)
        {
            break;
        }
        if *(*(*ctxt).input).cur as libc::c_int == '&' as i32 {
            if *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '#' as i32
            {
                let mut c: libc::c_uint = 0;
                let mut bits: libc::c_int = 0;
                c = htmlParseCharRef(ctxt) as libc::c_uint;
                if c < 0x80 as libc::c_int as libc::c_uint {
                    let fresh55 = out;
                    out = out.offset(1);
                    *fresh55 = c as xmlChar;
                    bits = -(6 as libc::c_int);
                } else if c < 0x800 as libc::c_int as libc::c_uint {
                    let fresh56 = out;
                    out = out.offset(1);
                    *fresh56 = (c >> 6 as libc::c_int
                        & 0x1f as libc::c_int as libc::c_uint
                        | 0xc0 as libc::c_int as libc::c_uint) as xmlChar;
                    bits = 0 as libc::c_int;
                } else if c < 0x10000 as libc::c_int as libc::c_uint {
                    let fresh57 = out;
                    out = out.offset(1);
                    *fresh57 = (c >> 12 as libc::c_int
                        & 0xf as libc::c_int as libc::c_uint
                        | 0xe0 as libc::c_int as libc::c_uint) as xmlChar;
                    bits = 6 as libc::c_int;
                } else {
                    let fresh58 = out;
                    out = out.offset(1);
                    *fresh58 = (c >> 18 as libc::c_int
                        & 0x7 as libc::c_int as libc::c_uint
                        | 0xf0 as libc::c_int as libc::c_uint) as xmlChar;
                    bits = 12 as libc::c_int;
                }
                while bits >= 0 as libc::c_int {
                    let fresh59 = out;
                    out = out.offset(1);
                    *fresh59 = (c >> bits & 0x3f as libc::c_int as libc::c_uint
                        | 0x80 as libc::c_int as libc::c_uint) as xmlChar;
                    bits -= 6 as libc::c_int;
                }
                if out.offset_from(buffer) as libc::c_long
                    > (buffer_size - 100 as libc::c_int) as libc::c_long
                {
                    let mut indx: libc::c_int = out.offset_from(buffer) as libc::c_long
                        as libc::c_int;
                    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                    buffer_size *= 2 as libc::c_int;
                    tmp = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(
                        buffer as *mut libc::c_void,
                        (buffer_size as libc::c_ulong)
                            .wrapping_mul(
                                ::std::mem::size_of::<xmlChar>() as libc::c_ulong,
                            ),
                    ) as *mut xmlChar;
                    if tmp.is_null() {
                        htmlErrMemory(
                            ctxt,
                            b"growing buffer\n\0" as *const u8 as *const libc::c_char,
                        );
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                    buffer = tmp;
                    out = &mut *buffer.offset(indx as isize) as *mut xmlChar;
                }
            } else {
                ent = htmlParseEntityRef(ctxt, &mut name);
                if name.is_null() {
                    let fresh60 = out;
                    out = out.offset(1);
                    *fresh60 = '&' as i32 as xmlChar;
                    if out.offset_from(buffer) as libc::c_long
                        > (buffer_size - 100 as libc::c_int) as libc::c_long
                    {
                        let mut indx_0: libc::c_int = out.offset_from(buffer)
                            as libc::c_long as libc::c_int;
                        let mut tmp_0: *mut xmlChar = 0 as *mut xmlChar;
                        buffer_size *= 2 as libc::c_int;
                        tmp_0 = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(
                            buffer as *mut libc::c_void,
                            (buffer_size as libc::c_ulong)
                                .wrapping_mul(
                                    ::std::mem::size_of::<xmlChar>() as libc::c_ulong,
                                ),
                        ) as *mut xmlChar;
                        if tmp_0.is_null() {
                            htmlErrMemory(
                                ctxt,
                                b"growing buffer\n\0" as *const u8 as *const libc::c_char,
                            );
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(buffer as *mut libc::c_void);
                            return 0 as *mut xmlChar;
                        }
                        buffer = tmp_0;
                        out = &mut *buffer.offset(indx_0 as isize) as *mut xmlChar;
                    }
                } else if ent.is_null() {
                    let fresh61 = out;
                    out = out.offset(1);
                    *fresh61 = '&' as i32 as xmlChar;
                    cur = name;
                    while *cur as libc::c_int != 0 as libc::c_int {
                        if out.offset_from(buffer) as libc::c_long
                            > (buffer_size - 100 as libc::c_int) as libc::c_long
                        {
                            let mut indx_1: libc::c_int = out.offset_from(buffer)
                                as libc::c_long as libc::c_int;
                            let mut tmp_1: *mut xmlChar = 0 as *mut xmlChar;
                            buffer_size *= 2 as libc::c_int;
                            tmp_1 = xmlRealloc
                                .expect(
                                    "non-null function pointer",
                                )(
                                buffer as *mut libc::c_void,
                                (buffer_size as libc::c_ulong)
                                    .wrapping_mul(
                                        ::std::mem::size_of::<xmlChar>() as libc::c_ulong,
                                    ),
                            ) as *mut xmlChar;
                            if tmp_1.is_null() {
                                htmlErrMemory(
                                    ctxt,
                                    b"growing buffer\n\0" as *const u8 as *const libc::c_char,
                                );
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(buffer as *mut libc::c_void);
                                return 0 as *mut xmlChar;
                            }
                            buffer = tmp_1;
                            out = &mut *buffer.offset(indx_1 as isize) as *mut xmlChar;
                        }
                        let fresh62 = cur;
                        cur = cur.offset(1);
                        let fresh63 = out;
                        out = out.offset(1);
                        *fresh63 = *fresh62;
                    }
                } else {
                    let mut c_0: libc::c_uint = 0;
                    let mut bits_0: libc::c_int = 0;
                    if out.offset_from(buffer) as libc::c_long
                        > (buffer_size - 100 as libc::c_int) as libc::c_long
                    {
                        let mut indx_2: libc::c_int = out.offset_from(buffer)
                            as libc::c_long as libc::c_int;
                        let mut tmp_2: *mut xmlChar = 0 as *mut xmlChar;
                        buffer_size *= 2 as libc::c_int;
                        tmp_2 = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(
                            buffer as *mut libc::c_void,
                            (buffer_size as libc::c_ulong)
                                .wrapping_mul(
                                    ::std::mem::size_of::<xmlChar>() as libc::c_ulong,
                                ),
                        ) as *mut xmlChar;
                        if tmp_2.is_null() {
                            htmlErrMemory(
                                ctxt,
                                b"growing buffer\n\0" as *const u8 as *const libc::c_char,
                            );
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(buffer as *mut libc::c_void);
                            return 0 as *mut xmlChar;
                        }
                        buffer = tmp_2;
                        out = &mut *buffer.offset(indx_2 as isize) as *mut xmlChar;
                    }
                    c_0 = (*ent).value;
                    if c_0 < 0x80 as libc::c_int as libc::c_uint {
                        let fresh64 = out;
                        out = out.offset(1);
                        *fresh64 = c_0 as xmlChar;
                        bits_0 = -(6 as libc::c_int);
                    } else if c_0 < 0x800 as libc::c_int as libc::c_uint {
                        let fresh65 = out;
                        out = out.offset(1);
                        *fresh65 = (c_0 >> 6 as libc::c_int
                            & 0x1f as libc::c_int as libc::c_uint
                            | 0xc0 as libc::c_int as libc::c_uint) as xmlChar;
                        bits_0 = 0 as libc::c_int;
                    } else if c_0 < 0x10000 as libc::c_int as libc::c_uint {
                        let fresh66 = out;
                        out = out.offset(1);
                        *fresh66 = (c_0 >> 12 as libc::c_int
                            & 0xf as libc::c_int as libc::c_uint
                            | 0xe0 as libc::c_int as libc::c_uint) as xmlChar;
                        bits_0 = 6 as libc::c_int;
                    } else {
                        let fresh67 = out;
                        out = out.offset(1);
                        *fresh67 = (c_0 >> 18 as libc::c_int
                            & 0x7 as libc::c_int as libc::c_uint
                            | 0xf0 as libc::c_int as libc::c_uint) as xmlChar;
                        bits_0 = 12 as libc::c_int;
                    }
                    while bits_0 >= 0 as libc::c_int {
                        let fresh68 = out;
                        out = out.offset(1);
                        *fresh68 = (c_0 >> bits_0 & 0x3f as libc::c_int as libc::c_uint
                            | 0x80 as libc::c_int as libc::c_uint) as xmlChar;
                        bits_0 -= 6 as libc::c_int;
                    }
                }
            }
        } else {
            let mut c_1: libc::c_uint = 0;
            let mut bits_1: libc::c_int = 0;
            let mut l: libc::c_int = 0;
            if out.offset_from(buffer) as libc::c_long
                > (buffer_size - 100 as libc::c_int) as libc::c_long
            {
                let mut indx_3: libc::c_int = out.offset_from(buffer) as libc::c_long
                    as libc::c_int;
                let mut tmp_3: *mut xmlChar = 0 as *mut xmlChar;
                buffer_size *= 2 as libc::c_int;
                tmp_3 = xmlRealloc
                    .expect(
                        "non-null function pointer",
                    )(
                    buffer as *mut libc::c_void,
                    (buffer_size as libc::c_ulong)
                        .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
                ) as *mut xmlChar;
                if tmp_3.is_null() {
                    htmlErrMemory(
                        ctxt,
                        b"growing buffer\n\0" as *const u8 as *const libc::c_char,
                    );
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(buffer as *mut libc::c_void);
                    return 0 as *mut xmlChar;
                }
                buffer = tmp_3;
                out = &mut *buffer.offset(indx_3 as isize) as *mut xmlChar;
            }
            c_1 = htmlCurrentChar(ctxt, &mut l) as libc::c_uint;
            if c_1 < 0x80 as libc::c_int as libc::c_uint {
                let fresh69 = out;
                out = out.offset(1);
                *fresh69 = c_1 as xmlChar;
                bits_1 = -(6 as libc::c_int);
            } else if c_1 < 0x800 as libc::c_int as libc::c_uint {
                let fresh70 = out;
                out = out.offset(1);
                *fresh70 = (c_1 >> 6 as libc::c_int & 0x1f as libc::c_int as libc::c_uint
                    | 0xc0 as libc::c_int as libc::c_uint) as xmlChar;
                bits_1 = 0 as libc::c_int;
            } else if c_1 < 0x10000 as libc::c_int as libc::c_uint {
                let fresh71 = out;
                out = out.offset(1);
                *fresh71 = (c_1 >> 12 as libc::c_int & 0xf as libc::c_int as libc::c_uint
                    | 0xe0 as libc::c_int as libc::c_uint) as xmlChar;
                bits_1 = 6 as libc::c_int;
            } else {
                let fresh72 = out;
                out = out.offset(1);
                *fresh72 = (c_1 >> 18 as libc::c_int & 0x7 as libc::c_int as libc::c_uint
                    | 0xf0 as libc::c_int as libc::c_uint) as xmlChar;
                bits_1 = 12 as libc::c_int;
            }
            while bits_1 >= 0 as libc::c_int {
                let fresh73 = out;
                out = out.offset(1);
                *fresh73 = (c_1 >> bits_1 & 0x3f as libc::c_int as libc::c_uint
                    | 0x80 as libc::c_int as libc::c_uint) as xmlChar;
                bits_1 -= 6 as libc::c_int;
            }
            xmlNextChar(ctxt);
        }
    }
    *out = 0 as libc::c_int as xmlChar;
    return buffer;
}
#[no_mangle]
pub unsafe extern "C" fn htmlParseEntityRef(
    mut ctxt: htmlParserCtxtPtr,
    mut str: *mut *const xmlChar,
) -> *const htmlEntityDesc {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut ent: *const htmlEntityDesc = 0 as *const htmlEntityDesc;
    if !str.is_null() {
        *str = 0 as *const xmlChar;
    }
    if ctxt.is_null() || ((*ctxt).input).is_null() {
        return 0 as *const htmlEntityDesc;
    }
    if *(*(*ctxt).input).cur as libc::c_int == '&' as i32 {
        xmlNextChar(ctxt);
        name = htmlParseName(ctxt);
        if name.is_null() {
            htmlParseErr(
                ctxt,
                XML_ERR_NAME_REQUIRED,
                b"htmlParseEntityRef: no name\n\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        } else {
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
            if *(*(*ctxt).input).cur as libc::c_int == ';' as i32 {
                if !str.is_null() {
                    *str = name;
                }
                ent = htmlEntityLookup(name);
                if !ent.is_null() {
                    xmlNextChar(ctxt);
                }
            } else {
                htmlParseErr(
                    ctxt,
                    XML_ERR_ENTITYREF_SEMICOL_MISSING,
                    b"htmlParseEntityRef: expecting ';'\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                if !str.is_null() {
                    *str = name;
                }
            }
        }
    }
    return ent;
}
unsafe extern "C" fn htmlParseAttValue(mut ctxt: htmlParserCtxtPtr) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if *(*(*ctxt).input).cur as libc::c_int == '"' as i32 {
        xmlNextChar(ctxt);
        ret = htmlParseHTMLAttribute(ctxt, '"' as i32 as xmlChar);
        if *(*(*ctxt).input).cur as libc::c_int != '"' as i32 {
            htmlParseErr(
                ctxt,
                XML_ERR_ATTRIBUTE_NOT_FINISHED,
                b"AttValue: \" expected\n\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        } else {
            xmlNextChar(ctxt);
        }
    } else if *(*(*ctxt).input).cur as libc::c_int == '\'' as i32 {
        xmlNextChar(ctxt);
        ret = htmlParseHTMLAttribute(ctxt, '\'' as i32 as xmlChar);
        if *(*(*ctxt).input).cur as libc::c_int != '\'' as i32 {
            htmlParseErr(
                ctxt,
                XML_ERR_ATTRIBUTE_NOT_FINISHED,
                b"AttValue: ' expected\n\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        } else {
            xmlNextChar(ctxt);
        }
    } else {
        ret = htmlParseHTMLAttribute(ctxt, 0 as libc::c_int as xmlChar);
        if ret.is_null() {
            htmlParseErr(
                ctxt,
                XML_ERR_ATTRIBUTE_WITHOUT_VALUE,
                b"AttValue: no value found\n\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
    }
    return ret;
}
unsafe extern "C" fn htmlParseSystemLiteral(
    mut ctxt: htmlParserCtxtPtr,
) -> *mut xmlChar {
    let mut len: size_t = 0 as libc::c_int as size_t;
    let mut startPosition: size_t = 0 as libc::c_int as size_t;
    let mut err: libc::c_int = 0 as libc::c_int;
    let mut quote: libc::c_int = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if *(*(*ctxt).input).cur as libc::c_int != '"' as i32
        && *(*(*ctxt).input).cur as libc::c_int != '\'' as i32
    {
        htmlParseErr(
            ctxt,
            XML_ERR_LITERAL_NOT_STARTED,
            b"SystemLiteral \" or ' expected\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as *mut xmlChar;
    }
    quote = *(*(*ctxt).input).cur as libc::c_int;
    xmlNextChar(ctxt);
    if (*(*ctxt).input).cur < (*(*ctxt).input).base {
        return ret;
    }
    startPosition = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
        as libc::c_long as size_t;
    while *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int
        && *(*(*ctxt).input).cur as libc::c_int != quote
    {
        if !(0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
            && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
            || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int
            || 0x20 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int)
        {
            htmlParseErrInt(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"Invalid char in SystemLiteral 0x%X\n\0" as *const u8
                    as *const libc::c_char,
                *(*(*ctxt).input).cur as libc::c_int,
            );
            err = 1 as libc::c_int;
        }
        xmlNextChar(ctxt);
        len = len.wrapping_add(1);
    }
    if *(*(*ctxt).input).cur as libc::c_int != quote {
        htmlParseErr(
            ctxt,
            XML_ERR_LITERAL_NOT_FINISHED,
            b"Unfinished SystemLiteral\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    } else {
        xmlNextChar(ctxt);
        if err == 0 as libc::c_int {
            ret = xmlStrndup(
                ((*(*ctxt).input).base).offset(startPosition as isize),
                len as libc::c_int,
            );
        }
    }
    return ret;
}
unsafe extern "C" fn htmlParsePubidLiteral(mut ctxt: htmlParserCtxtPtr) -> *mut xmlChar {
    let mut len: size_t = 0 as libc::c_int as size_t;
    let mut startPosition: size_t = 0 as libc::c_int as size_t;
    let mut err: libc::c_int = 0 as libc::c_int;
    let mut quote: libc::c_int = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if *(*(*ctxt).input).cur as libc::c_int != '"' as i32
        && *(*(*ctxt).input).cur as libc::c_int != '\'' as i32
    {
        htmlParseErr(
            ctxt,
            XML_ERR_LITERAL_NOT_STARTED,
            b"PubidLiteral \" or ' expected\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as *mut xmlChar;
    }
    quote = *(*(*ctxt).input).cur as libc::c_int;
    xmlNextChar(ctxt);
    if (*(*ctxt).input).cur < (*(*ctxt).input).base {
        return ret;
    }
    startPosition = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
        as libc::c_long as size_t;
    while *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int
        && *(*(*ctxt).input).cur as libc::c_int != quote
    {
        if xmlIsPubidChar_tab[*(*(*ctxt).input).cur as libc::c_int as usize] == 0 {
            htmlParseErrInt(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"Invalid char in PubidLiteral 0x%X\n\0" as *const u8
                    as *const libc::c_char,
                *(*(*ctxt).input).cur as libc::c_int,
            );
            err = 1 as libc::c_int;
        }
        len = len.wrapping_add(1);
        xmlNextChar(ctxt);
    }
    if *(*(*ctxt).input).cur as libc::c_int != quote {
        htmlParseErr(
            ctxt,
            XML_ERR_LITERAL_NOT_FINISHED,
            b"Unfinished PubidLiteral\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    } else {
        xmlNextChar(ctxt);
        if err == 0 as libc::c_int {
            ret = xmlStrndup(
                ((*(*ctxt).input).base).offset(startPosition as isize),
                len as libc::c_int,
            );
        }
    }
    return ret;
}
unsafe extern "C" fn htmlParseScript(mut ctxt: htmlParserCtxtPtr) {
    let mut buf: [xmlChar; 1005] = [0; 1005];
    let mut nbchar: libc::c_int = 0 as libc::c_int;
    let mut cur: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    if ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
        > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlParserInputShrink((*ctxt).input);
    }
    cur = htmlCurrentChar(ctxt, &mut l);
    while cur != 0 as libc::c_int {
        if cur == '<' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '/' as i32
        {
            if (*ctxt).recovery != 0 {
                if xmlStrncasecmp(
                    (*ctxt).name,
                    ((*(*ctxt).input).cur).offset(2 as libc::c_int as isize),
                    xmlStrlen((*ctxt).name),
                ) == 0 as libc::c_int
                {
                    break;
                } else {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_TAG_NAME_MISMATCH,
                        b"Element %s embeds close tag\n\0" as *const u8
                            as *const libc::c_char,
                        (*ctxt).name,
                        0 as *const xmlChar,
                    );
                }
            } else if *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                    as libc::c_int >= 'A' as i32
                    && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                        as libc::c_int <= 'Z' as i32
                    || *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                        as libc::c_int >= 'a' as i32
                        && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                            as libc::c_int <= 'z' as i32
                {
                break;
            }
        }
        if if cur < 0x100 as libc::c_int {
            (0x9 as libc::c_int <= cur && cur <= 0xa as libc::c_int
                || cur == 0xd as libc::c_int || 0x20 as libc::c_int <= cur)
                as libc::c_int
        } else {
            (0x100 as libc::c_int <= cur && cur <= 0xd7ff as libc::c_int
                || 0xe000 as libc::c_int <= cur && cur <= 0xfffd as libc::c_int
                || 0x10000 as libc::c_int <= cur && cur <= 0x10ffff as libc::c_int)
                as libc::c_int
        } != 0
        {
            if l == 1 as libc::c_int {
                let fresh74 = nbchar;
                nbchar = nbchar + 1;
                buf[fresh74 as usize] = cur as xmlChar;
            } else {
                nbchar
                    += xmlCopyChar(
                        l,
                        &mut *buf.as_mut_ptr().offset(nbchar as isize),
                        cur,
                    );
            }
        } else {
            htmlParseErrInt(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"Invalid char in CDATA 0x%X\n\0" as *const u8 as *const libc::c_char,
                cur,
            );
        }
        if nbchar >= 1000 as libc::c_int {
            buf[nbchar as usize] = 0 as libc::c_int as xmlChar;
            if ((*(*ctxt).sax).cdataBlock).is_some() {
                ((*(*ctxt).sax).cdataBlock)
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
            } else if ((*(*ctxt).sax).characters).is_some() {
                ((*(*ctxt).sax).characters)
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
            }
            nbchar = 0 as libc::c_int;
        }
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
            let ref mut fresh75 = (*(*ctxt).input).line;
            *fresh75 += 1;
            (*(*ctxt).input).col = 1 as libc::c_int;
        } else {
            let ref mut fresh76 = (*(*ctxt).input).col;
            *fresh76 += 1;
        }
        (*ctxt).token = 0 as libc::c_int;
        let ref mut fresh77 = (*(*ctxt).input).cur;
        *fresh77 = (*fresh77).offset(l as isize);
        cur = htmlCurrentChar(ctxt, &mut l);
    }
    if nbchar != 0 as libc::c_int && !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
    {
        buf[nbchar as usize] = 0 as libc::c_int as xmlChar;
        if ((*(*ctxt).sax).cdataBlock).is_some() {
            ((*(*ctxt).sax).cdataBlock)
                .expect(
                    "non-null function pointer",
                )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
        } else if ((*(*ctxt).sax).characters).is_some() {
            ((*(*ctxt).sax).characters)
                .expect(
                    "non-null function pointer",
                )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
        }
    }
}
unsafe extern "C" fn htmlParseCharDataInternal(
    mut ctxt: htmlParserCtxtPtr,
    mut readahead: libc::c_int,
) {
    let mut buf: [xmlChar; 1006] = [0; 1006];
    let mut nbchar: libc::c_int = 0 as libc::c_int;
    let mut cur: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    let mut chunk: libc::c_int = 0 as libc::c_int;
    if readahead != 0 {
        let fresh78 = nbchar;
        nbchar = nbchar + 1;
        buf[fresh78 as usize] = readahead as xmlChar;
    }
    if ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
        > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlParserInputShrink((*ctxt).input);
    }
    cur = htmlCurrentChar(ctxt, &mut l);
    while (cur != '<' as i32 || (*ctxt).token == '<' as i32)
        && (cur != '&' as i32 || (*ctxt).token == '&' as i32) && cur != 0 as libc::c_int
    {
        if if cur < 0x100 as libc::c_int {
            (0x9 as libc::c_int <= cur && cur <= 0xa as libc::c_int
                || cur == 0xd as libc::c_int || 0x20 as libc::c_int <= cur)
                as libc::c_int
        } else {
            (0x100 as libc::c_int <= cur && cur <= 0xd7ff as libc::c_int
                || 0xe000 as libc::c_int <= cur && cur <= 0xfffd as libc::c_int
                || 0x10000 as libc::c_int <= cur && cur <= 0x10ffff as libc::c_int)
                as libc::c_int
        } == 0
        {
            htmlParseErrInt(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"Invalid char in CDATA 0x%X\n\0" as *const u8 as *const libc::c_char,
                cur,
            );
        } else if l == 1 as libc::c_int {
            let fresh79 = nbchar;
            nbchar = nbchar + 1;
            buf[fresh79 as usize] = cur as xmlChar;
        } else {
            nbchar
                += xmlCopyChar(l, &mut *buf.as_mut_ptr().offset(nbchar as isize), cur);
        }
        if nbchar >= 1000 as libc::c_int {
            buf[nbchar as usize] = 0 as libc::c_int as xmlChar;
            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0 {
                if areBlanks(ctxt, buf.as_mut_ptr(), nbchar) != 0 {
                    if (*ctxt).keepBlanks != 0 {
                        if ((*(*ctxt).sax).characters).is_some() {
                            ((*(*ctxt).sax).characters)
                                .expect(
                                    "non-null function pointer",
                                )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                        }
                    } else if ((*(*ctxt).sax).ignorableWhitespace).is_some() {
                        ((*(*ctxt).sax).ignorableWhitespace)
                            .expect(
                                "non-null function pointer",
                            )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                    }
                } else {
                    htmlCheckParagraph(ctxt);
                    if ((*(*ctxt).sax).characters).is_some() {
                        ((*(*ctxt).sax).characters)
                            .expect(
                                "non-null function pointer",
                            )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                    }
                }
            }
            nbchar = 0 as libc::c_int;
        }
        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
            let ref mut fresh80 = (*(*ctxt).input).line;
            *fresh80 += 1;
            (*(*ctxt).input).col = 1 as libc::c_int;
        } else {
            let ref mut fresh81 = (*(*ctxt).input).col;
            *fresh81 += 1;
        }
        (*ctxt).token = 0 as libc::c_int;
        let ref mut fresh82 = (*(*ctxt).input).cur;
        *fresh82 = (*fresh82).offset(l as isize);
        chunk += 1;
        if chunk > 100 as libc::c_int {
            chunk = 0 as libc::c_int;
            if ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long)
                    < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            {
                xmlParserInputShrink((*ctxt).input);
            }
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
        }
        cur = htmlCurrentChar(ctxt, &mut l);
        if cur == 0 as libc::c_int {
            if ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long)
                    < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            {
                xmlParserInputShrink((*ctxt).input);
            }
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
            cur = htmlCurrentChar(ctxt, &mut l);
        }
    }
    if nbchar != 0 as libc::c_int {
        buf[nbchar as usize] = 0 as libc::c_int as xmlChar;
        if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0 {
            if areBlanks(ctxt, buf.as_mut_ptr(), nbchar) != 0 {
                if (*ctxt).keepBlanks != 0 {
                    if ((*(*ctxt).sax).characters).is_some() {
                        ((*(*ctxt).sax).characters)
                            .expect(
                                "non-null function pointer",
                            )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                    }
                } else if ((*(*ctxt).sax).ignorableWhitespace).is_some() {
                    ((*(*ctxt).sax).ignorableWhitespace)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                }
            } else {
                htmlCheckParagraph(ctxt);
                if ((*(*ctxt).sax).characters).is_some() {
                    ((*(*ctxt).sax).characters)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                }
            }
        }
    } else if cur == 0 as libc::c_int {
        (*ctxt).instate = XML_PARSER_EOF;
    }
}
unsafe extern "C" fn htmlParseCharData(mut ctxt: htmlParserCtxtPtr) {
    htmlParseCharDataInternal(ctxt, 0 as libc::c_int);
}
unsafe extern "C" fn htmlParseExternalID(
    mut ctxt: htmlParserCtxtPtr,
    mut publicID: *mut *mut xmlChar,
) -> *mut xmlChar {
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    if ({
        let mut __res: libc::c_int = 0;
        if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
            > 1 as libc::c_int as libc::c_ulong
        {
            if 0 != 0 {
                let mut __c: libc::c_int = *(*(*ctxt).input).cur as libc::c_int;
                __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                    __c
                } else {
                    *(*__ctype_toupper_loc()).offset(__c as isize)
                });
            } else {
                __res = toupper(*(*(*ctxt).input).cur as libc::c_int);
            }
        } else {
            __res = *(*__ctype_toupper_loc())
                .offset(*(*(*ctxt).input).cur as libc::c_int as isize);
        }
        __res
    }) == 'S' as i32
        && ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                        .offset(1 as libc::c_int as isize) as libc::c_int;
                    __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_toupper_loc()).offset(__c as isize)
                    });
                } else {
                    __res = toupper(
                        *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                            as libc::c_int,
                    );
                }
            } else {
                __res = *(*__ctype_toupper_loc())
                    .offset(
                        *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                            as libc::c_int as isize,
                    );
            }
            __res
        }) == 'Y' as i32
        && ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                        .offset(2 as libc::c_int as isize) as libc::c_int;
                    __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_toupper_loc()).offset(__c as isize)
                    });
                } else {
                    __res = toupper(
                        *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                            as libc::c_int,
                    );
                }
            } else {
                __res = *(*__ctype_toupper_loc())
                    .offset(
                        *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                            as libc::c_int as isize,
                    );
            }
            __res
        }) == 'S' as i32
        && ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                        .offset(3 as libc::c_int as isize) as libc::c_int;
                    __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_toupper_loc()).offset(__c as isize)
                    });
                } else {
                    __res = toupper(
                        *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                            as libc::c_int,
                    );
                }
            } else {
                __res = *(*__ctype_toupper_loc())
                    .offset(
                        *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                            as libc::c_int as isize,
                    );
            }
            __res
        }) == 'T' as i32
        && ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                        .offset(4 as libc::c_int as isize) as libc::c_int;
                    __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_toupper_loc()).offset(__c as isize)
                    });
                } else {
                    __res = toupper(
                        *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                            as libc::c_int,
                    );
                }
            } else {
                __res = *(*__ctype_toupper_loc())
                    .offset(
                        *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                            as libc::c_int as isize,
                    );
            }
            __res
        }) == 'E' as i32
        && ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                        .offset(5 as libc::c_int as isize) as libc::c_int;
                    __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_toupper_loc()).offset(__c as isize)
                    });
                } else {
                    __res = toupper(
                        *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                            as libc::c_int,
                    );
                }
            } else {
                __res = *(*__ctype_toupper_loc())
                    .offset(
                        *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                            as libc::c_int as isize,
                    );
            }
            __res
        }) == 'M' as i32
    {
        let ref mut fresh83 = (*(*ctxt).input).cur;
        *fresh83 = (*fresh83).offset(6 as libc::c_int as isize);
        (*(*ctxt).input).col += 6 as libc::c_int;
        if !(*(*(*ctxt).input).cur as libc::c_int == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
                && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
            || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int)
        {
            htmlParseErr(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after 'SYSTEM'\n\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        htmlSkipBlankChars(ctxt);
        URI = htmlParseSystemLiteral(ctxt);
        if URI.is_null() {
            htmlParseErr(
                ctxt,
                XML_ERR_URI_REQUIRED,
                b"htmlParseExternalID: SYSTEM, no URI\n\0" as *const u8
                    as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
    } else if ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *(*(*ctxt).input).cur as libc::c_int;
                    __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_toupper_loc()).offset(__c as isize)
                    });
                } else {
                    __res = toupper(*(*(*ctxt).input).cur as libc::c_int);
                }
            } else {
                __res = *(*__ctype_toupper_loc())
                    .offset(*(*(*ctxt).input).cur as libc::c_int as isize);
            }
            __res
        }) == 'P' as i32
            && ({
                let mut __res: libc::c_int = 0;
                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                    > 1 as libc::c_int as libc::c_ulong
                {
                    if 0 != 0 {
                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                            .offset(1 as libc::c_int as isize) as libc::c_int;
                        __res = (if __c < -(128 as libc::c_int)
                            || __c > 255 as libc::c_int
                        {
                            __c
                        } else {
                            *(*__ctype_toupper_loc()).offset(__c as isize)
                        });
                    } else {
                        __res = toupper(
                            *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                as libc::c_int,
                        );
                    }
                } else {
                    __res = *(*__ctype_toupper_loc())
                        .offset(
                            *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                as libc::c_int as isize,
                        );
                }
                __res
            }) == 'U' as i32
            && ({
                let mut __res: libc::c_int = 0;
                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                    > 1 as libc::c_int as libc::c_ulong
                {
                    if 0 != 0 {
                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                            .offset(2 as libc::c_int as isize) as libc::c_int;
                        __res = (if __c < -(128 as libc::c_int)
                            || __c > 255 as libc::c_int
                        {
                            __c
                        } else {
                            *(*__ctype_toupper_loc()).offset(__c as isize)
                        });
                    } else {
                        __res = toupper(
                            *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                as libc::c_int,
                        );
                    }
                } else {
                    __res = *(*__ctype_toupper_loc())
                        .offset(
                            *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                as libc::c_int as isize,
                        );
                }
                __res
            }) == 'B' as i32
            && ({
                let mut __res: libc::c_int = 0;
                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                    > 1 as libc::c_int as libc::c_ulong
                {
                    if 0 != 0 {
                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                            .offset(3 as libc::c_int as isize) as libc::c_int;
                        __res = (if __c < -(128 as libc::c_int)
                            || __c > 255 as libc::c_int
                        {
                            __c
                        } else {
                            *(*__ctype_toupper_loc()).offset(__c as isize)
                        });
                    } else {
                        __res = toupper(
                            *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                as libc::c_int,
                        );
                    }
                } else {
                    __res = *(*__ctype_toupper_loc())
                        .offset(
                            *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                as libc::c_int as isize,
                        );
                }
                __res
            }) == 'L' as i32
            && ({
                let mut __res: libc::c_int = 0;
                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                    > 1 as libc::c_int as libc::c_ulong
                {
                    if 0 != 0 {
                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                            .offset(4 as libc::c_int as isize) as libc::c_int;
                        __res = (if __c < -(128 as libc::c_int)
                            || __c > 255 as libc::c_int
                        {
                            __c
                        } else {
                            *(*__ctype_toupper_loc()).offset(__c as isize)
                        });
                    } else {
                        __res = toupper(
                            *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                as libc::c_int,
                        );
                    }
                } else {
                    __res = *(*__ctype_toupper_loc())
                        .offset(
                            *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                as libc::c_int as isize,
                        );
                }
                __res
            }) == 'I' as i32
            && ({
                let mut __res: libc::c_int = 0;
                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                    > 1 as libc::c_int as libc::c_ulong
                {
                    if 0 != 0 {
                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                            .offset(5 as libc::c_int as isize) as libc::c_int;
                        __res = (if __c < -(128 as libc::c_int)
                            || __c > 255 as libc::c_int
                        {
                            __c
                        } else {
                            *(*__ctype_toupper_loc()).offset(__c as isize)
                        });
                    } else {
                        __res = toupper(
                            *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                as libc::c_int,
                        );
                    }
                } else {
                    __res = *(*__ctype_toupper_loc())
                        .offset(
                            *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                as libc::c_int as isize,
                        );
                }
                __res
            }) == 'C' as i32
        {
        let ref mut fresh84 = (*(*ctxt).input).cur;
        *fresh84 = (*fresh84).offset(6 as libc::c_int as isize);
        (*(*ctxt).input).col += 6 as libc::c_int;
        if !(*(*(*ctxt).input).cur as libc::c_int == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
                && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
            || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int)
        {
            htmlParseErr(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after 'PUBLIC'\n\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        htmlSkipBlankChars(ctxt);
        *publicID = htmlParsePubidLiteral(ctxt);
        if (*publicID).is_null() {
            htmlParseErr(
                ctxt,
                XML_ERR_PUBID_REQUIRED,
                b"htmlParseExternalID: PUBLIC, no Public Identifier\n\0" as *const u8
                    as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        htmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as libc::c_int == '"' as i32
            || *(*(*ctxt).input).cur as libc::c_int == '\'' as i32
        {
            URI = htmlParseSystemLiteral(ctxt);
        }
    }
    return URI;
}
unsafe extern "C" fn htmlParsePI(mut ctxt: htmlParserCtxtPtr) {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut size: libc::c_int = 100 as libc::c_int;
    let mut cur: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    let mut target: *const xmlChar = 0 as *const xmlChar;
    let mut state: xmlParserInputState = XML_PARSER_START;
    let mut count: libc::c_int = 0 as libc::c_int;
    if (if (*ctxt).token != 0 {
        -(1 as libc::c_int)
    } else {
        *(*(*ctxt).input).cur as libc::c_int
    }) == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '?' as i32
    {
        state = (*ctxt).instate;
        (*ctxt).instate = XML_PARSER_PI;
        let ref mut fresh85 = (*(*ctxt).input).cur;
        *fresh85 = (*fresh85).offset(2 as libc::c_int as isize);
        (*(*ctxt).input).col += 2 as libc::c_int;
        if ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        {
            xmlParserInputShrink((*ctxt).input);
        }
        target = htmlParseName(ctxt);
        if !target.is_null() {
            if (if (*ctxt).token != 0 {
                -(1 as libc::c_int)
            } else {
                *(*(*ctxt).input).cur as libc::c_int
            }) == '>' as i32
            {
                let ref mut fresh86 = (*(*ctxt).input).cur;
                *fresh86 = (*fresh86).offset(1 as libc::c_int as isize);
                (*(*ctxt).input).col += 1 as libc::c_int;
                if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                    && ((*(*ctxt).sax).processingInstruction).is_some()
                {
                    ((*(*ctxt).sax).processingInstruction)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, target, 0 as *const xmlChar);
                }
                (*ctxt).instate = state;
                return;
            }
            buf = xmlMallocAtomic
                .expect(
                    "non-null function pointer",
                )(
                (size as libc::c_ulong)
                    .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
            ) as *mut xmlChar;
            if buf.is_null() {
                htmlErrMemory(ctxt, 0 as *const libc::c_char);
                (*ctxt).instate = state;
                return;
            }
            cur = *(*(*ctxt).input).cur as libc::c_int;
            if if cur < 0x100 as libc::c_int {
                (cur == 0x20 as libc::c_int
                    || 0x9 as libc::c_int <= cur && cur <= 0xa as libc::c_int
                    || cur == 0xd as libc::c_int) as libc::c_int
            } else {
                0 as libc::c_int
            } == 0
            {
                htmlParseErr(
                    ctxt,
                    XML_ERR_SPACE_REQUIRED,
                    b"ParsePI: PI %s space expected\n\0" as *const u8
                        as *const libc::c_char,
                    target,
                    0 as *const xmlChar,
                );
            }
            htmlSkipBlankChars(ctxt);
            cur = htmlCurrentChar(ctxt, &mut l);
            while cur != 0 as libc::c_int && cur != '>' as i32 {
                if len + 5 as libc::c_int >= size {
                    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                    size *= 2 as libc::c_int;
                    tmp = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(
                        buf as *mut libc::c_void,
                        (size as libc::c_ulong)
                            .wrapping_mul(
                                ::std::mem::size_of::<xmlChar>() as libc::c_ulong,
                            ),
                    ) as *mut xmlChar;
                    if tmp.is_null() {
                        htmlErrMemory(ctxt, 0 as *const libc::c_char);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buf as *mut libc::c_void);
                        (*ctxt).instate = state;
                        return;
                    }
                    buf = tmp;
                }
                count += 1;
                if count > 50 as libc::c_int {
                    if (*ctxt).progressive == 0 as libc::c_int
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as libc::c_long) < 250 as libc::c_int as libc::c_long
                    {
                        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                    }
                    count = 0 as libc::c_int;
                }
                if if cur < 0x100 as libc::c_int {
                    (0x9 as libc::c_int <= cur && cur <= 0xa as libc::c_int
                        || cur == 0xd as libc::c_int || 0x20 as libc::c_int <= cur)
                        as libc::c_int
                } else {
                    (0x100 as libc::c_int <= cur && cur <= 0xd7ff as libc::c_int
                        || 0xe000 as libc::c_int <= cur && cur <= 0xfffd as libc::c_int
                        || 0x10000 as libc::c_int <= cur
                            && cur <= 0x10ffff as libc::c_int) as libc::c_int
                } != 0
                {
                    if l == 1 as libc::c_int {
                        let fresh87 = len;
                        len = len + 1;
                        *buf.offset(fresh87 as isize) = cur as xmlChar;
                    } else {
                        len += xmlCopyChar(l, &mut *buf.offset(len as isize), cur);
                    }
                } else {
                    htmlParseErrInt(
                        ctxt,
                        XML_ERR_INVALID_CHAR,
                        b"Invalid char in processing instruction 0x%X\n\0" as *const u8
                            as *const libc::c_char,
                        cur,
                    );
                }
                if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                    let ref mut fresh88 = (*(*ctxt).input).line;
                    *fresh88 += 1;
                    (*(*ctxt).input).col = 1 as libc::c_int;
                } else {
                    let ref mut fresh89 = (*(*ctxt).input).col;
                    *fresh89 += 1;
                }
                (*ctxt).token = 0 as libc::c_int;
                let ref mut fresh90 = (*(*ctxt).input).cur;
                *fresh90 = (*fresh90).offset(l as isize);
                cur = htmlCurrentChar(ctxt, &mut l);
                if cur == 0 as libc::c_int {
                    if ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long
                        > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as libc::c_long)
                            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                    {
                        xmlParserInputShrink((*ctxt).input);
                    }
                    if (*ctxt).progressive == 0 as libc::c_int
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as libc::c_long) < 250 as libc::c_int as libc::c_long
                    {
                        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                    }
                    cur = htmlCurrentChar(ctxt, &mut l);
                }
            }
            *buf.offset(len as isize) = 0 as libc::c_int as xmlChar;
            if cur != '>' as i32 {
                htmlParseErr(
                    ctxt,
                    XML_ERR_PI_NOT_FINISHED,
                    b"ParsePI: PI %s never end ...\n\0" as *const u8
                        as *const libc::c_char,
                    target,
                    0 as *const xmlChar,
                );
            } else {
                let ref mut fresh91 = (*(*ctxt).input).cur;
                *fresh91 = (*fresh91).offset(1 as libc::c_int as isize);
                (*(*ctxt).input).col += 1 as libc::c_int;
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
            htmlParseErr(
                ctxt,
                XML_ERR_PI_NOT_STARTED,
                b"PI is not started correctly\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        (*ctxt).instate = state;
    }
}
unsafe extern "C" fn htmlParseComment(mut ctxt: htmlParserCtxtPtr) {
    let mut current_block: u64;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0;
    let mut size: libc::c_int = 100 as libc::c_int;
    let mut q: libc::c_int = 0;
    let mut ql: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut rl: libc::c_int = 0;
    let mut cur: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    let mut next: libc::c_int = 0;
    let mut nl: libc::c_int = 0;
    let mut state: xmlParserInputState = XML_PARSER_START;
    if (if (*ctxt).token != 0 {
        -(1 as libc::c_int)
    } else {
        *(*(*ctxt).input).cur as libc::c_int
    }) != '<' as i32
        || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            != '!' as i32
        || *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize) as libc::c_int
            != '-' as i32
        || *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize) as libc::c_int
            != '-' as i32
    {
        return;
    }
    state = (*ctxt).instate;
    (*ctxt).instate = XML_PARSER_COMMENT;
    if ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
        > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlParserInputShrink((*ctxt).input);
    }
    let ref mut fresh92 = (*(*ctxt).input).cur;
    *fresh92 = (*fresh92).offset(4 as libc::c_int as isize);
    (*(*ctxt).input).col += 4 as libc::c_int;
    buf = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (size as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if buf.is_null() {
        htmlErrMemory(
            ctxt,
            b"buffer allocation failed\n\0" as *const u8 as *const libc::c_char,
        );
        (*ctxt).instate = state;
        return;
    }
    len = 0 as libc::c_int;
    *buf.offset(len as isize) = 0 as libc::c_int as xmlChar;
    q = htmlCurrentChar(ctxt, &mut ql);
    if !(q == 0 as libc::c_int) {
        if q == '>' as i32 {
            htmlParseErr(
                ctxt,
                XML_ERR_COMMENT_ABRUPTLY_ENDED,
                b"Comment abruptly ended\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            cur = '>' as i32;
            current_block = 930129051762374678;
        } else {
            if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                let ref mut fresh93 = (*(*ctxt).input).line;
                *fresh93 += 1;
                (*(*ctxt).input).col = 1 as libc::c_int;
            } else {
                let ref mut fresh94 = (*(*ctxt).input).col;
                *fresh94 += 1;
            }
            (*ctxt).token = 0 as libc::c_int;
            let ref mut fresh95 = (*(*ctxt).input).cur;
            *fresh95 = (*fresh95).offset(ql as isize);
            r = htmlCurrentChar(ctxt, &mut rl);
            if r == 0 as libc::c_int {
                current_block = 10773895329197502661;
            } else {
                if q == '-' as i32 && r == '>' as i32 {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_COMMENT_ABRUPTLY_ENDED,
                        b"Comment abruptly ended\0" as *const u8 as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    cur = '>' as i32;
                } else {
                    if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                        let ref mut fresh96 = (*(*ctxt).input).line;
                        *fresh96 += 1;
                        (*(*ctxt).input).col = 1 as libc::c_int;
                    } else {
                        let ref mut fresh97 = (*(*ctxt).input).col;
                        *fresh97 += 1;
                    }
                    (*ctxt).token = 0 as libc::c_int;
                    let ref mut fresh98 = (*(*ctxt).input).cur;
                    *fresh98 = (*fresh98).offset(rl as isize);
                    cur = htmlCurrentChar(ctxt, &mut l);
                    while cur != 0 as libc::c_int
                        && (cur != '>' as i32 || r != '-' as i32 || q != '-' as i32)
                    {
                        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                            let ref mut fresh99 = (*(*ctxt).input).line;
                            *fresh99 += 1;
                            (*(*ctxt).input).col = 1 as libc::c_int;
                        } else {
                            let ref mut fresh100 = (*(*ctxt).input).col;
                            *fresh100 += 1;
                        }
                        (*ctxt).token = 0 as libc::c_int;
                        let ref mut fresh101 = (*(*ctxt).input).cur;
                        *fresh101 = (*fresh101).offset(l as isize);
                        next = htmlCurrentChar(ctxt, &mut nl);
                        if next == 0 as libc::c_int {
                            if ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as libc::c_long
                                > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                    as libc::c_long)
                                    < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                            {
                                xmlParserInputShrink((*ctxt).input);
                            }
                            if (*ctxt).progressive == 0 as libc::c_int
                                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                    as libc::c_long) < 250 as libc::c_int as libc::c_long
                            {
                                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                            }
                            next = htmlCurrentChar(ctxt, &mut nl);
                        }
                        if q == '-' as i32 && r == '-' as i32 && cur == '!' as i32
                            && next == '>' as i32
                        {
                            htmlParseErr(
                                ctxt,
                                XML_ERR_COMMENT_NOT_FINISHED,
                                b"Comment incorrectly closed by '--!>'\0" as *const u8
                                    as *const libc::c_char,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                            );
                            cur = '>' as i32;
                            break;
                        } else {
                            if len + 5 as libc::c_int >= size {
                                let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                                size *= 2 as libc::c_int;
                                tmp = xmlRealloc
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    buf as *mut libc::c_void,
                                    (size as libc::c_ulong)
                                        .wrapping_mul(
                                            ::std::mem::size_of::<xmlChar>() as libc::c_ulong,
                                        ),
                                ) as *mut xmlChar;
                                if tmp.is_null() {
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(buf as *mut libc::c_void);
                                    htmlErrMemory(
                                        ctxt,
                                        b"growing buffer failed\n\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                    (*ctxt).instate = state;
                                    return;
                                }
                                buf = tmp;
                            }
                            if if q < 0x100 as libc::c_int {
                                (0x9 as libc::c_int <= q && q <= 0xa as libc::c_int
                                    || q == 0xd as libc::c_int || 0x20 as libc::c_int <= q)
                                    as libc::c_int
                            } else {
                                (0x100 as libc::c_int <= q && q <= 0xd7ff as libc::c_int
                                    || 0xe000 as libc::c_int <= q && q <= 0xfffd as libc::c_int
                                    || 0x10000 as libc::c_int <= q
                                        && q <= 0x10ffff as libc::c_int) as libc::c_int
                            } != 0
                            {
                                if ql == 1 as libc::c_int {
                                    let fresh102 = len;
                                    len = len + 1;
                                    *buf.offset(fresh102 as isize) = q as xmlChar;
                                } else {
                                    len += xmlCopyChar(ql, &mut *buf.offset(len as isize), q);
                                }
                            } else {
                                htmlParseErrInt(
                                    ctxt,
                                    XML_ERR_INVALID_CHAR,
                                    b"Invalid char in comment 0x%X\n\0" as *const u8
                                        as *const libc::c_char,
                                    q,
                                );
                            }
                            q = r;
                            ql = rl;
                            r = cur;
                            rl = l;
                            cur = next;
                            l = nl;
                        }
                    }
                }
                current_block = 930129051762374678;
            }
        }
        match current_block {
            10773895329197502661 => {}
            _ => {
                *buf.offset(len as isize) = 0 as libc::c_int as xmlChar;
                if cur == '>' as i32 {
                    xmlNextChar(ctxt);
                    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).comment).is_some()
                        && (*ctxt).disableSAX == 0
                    {
                        ((*(*ctxt).sax).comment)
                            .expect("non-null function pointer")((*ctxt).userData, buf);
                    }
                    xmlFree
                        .expect("non-null function pointer")(buf as *mut libc::c_void);
                    (*ctxt).instate = state;
                    return;
                }
            }
        }
    }
    htmlParseErr(
        ctxt,
        XML_ERR_COMMENT_NOT_FINISHED,
        b"Comment not terminated \n<!--%.50s\n\0" as *const u8 as *const libc::c_char,
        buf,
        0 as *const xmlChar,
    );
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn htmlParseCharRef(mut ctxt: htmlParserCtxtPtr) -> libc::c_int {
    let mut val: libc::c_int = 0 as libc::c_int;
    if ctxt.is_null() || ((*ctxt).input).is_null() {
        htmlParseErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"htmlParseCharRef: context error\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as libc::c_int;
    }
    if *(*(*ctxt).input).cur as libc::c_int == '&' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '#' as i32
        && (*((*(*ctxt).input).cur).offset(2 as libc::c_int as isize) as libc::c_int
            == 'x' as i32
            || *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize) as libc::c_int
                == 'X' as i32)
    {
        let ref mut fresh103 = (*(*ctxt).input).cur;
        *fresh103 = (*fresh103).offset(3 as libc::c_int as isize);
        (*(*ctxt).input).col += 3 as libc::c_int;
        while *(*(*ctxt).input).cur as libc::c_int != ';' as i32 {
            if *(*(*ctxt).input).cur as libc::c_int >= '0' as i32
                && *(*(*ctxt).input).cur as libc::c_int <= '9' as i32
            {
                if val < 0x110000 as libc::c_int {
                    val = val * 16 as libc::c_int
                        + (*(*(*ctxt).input).cur as libc::c_int - '0' as i32);
                }
            } else if *(*(*ctxt).input).cur as libc::c_int >= 'a' as i32
                    && *(*(*ctxt).input).cur as libc::c_int <= 'f' as i32
                {
                if val < 0x110000 as libc::c_int {
                    val = val * 16 as libc::c_int
                        + (*(*(*ctxt).input).cur as libc::c_int - 'a' as i32)
                        + 10 as libc::c_int;
                }
            } else if *(*(*ctxt).input).cur as libc::c_int >= 'A' as i32
                    && *(*(*ctxt).input).cur as libc::c_int <= 'F' as i32
                {
                if val < 0x110000 as libc::c_int {
                    val = val * 16 as libc::c_int
                        + (*(*(*ctxt).input).cur as libc::c_int - 'A' as i32)
                        + 10 as libc::c_int;
                }
            } else {
                htmlParseErr(
                    ctxt,
                    XML_ERR_INVALID_HEX_CHARREF,
                    b"htmlParseCharRef: missing semicolon\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                break;
            }
            xmlNextChar(ctxt);
        }
        if *(*(*ctxt).input).cur as libc::c_int == ';' as i32 {
            xmlNextChar(ctxt);
        }
    } else if *(*(*ctxt).input).cur as libc::c_int == '&' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '#' as i32
        {
        let ref mut fresh104 = (*(*ctxt).input).cur;
        *fresh104 = (*fresh104).offset(2 as libc::c_int as isize);
        (*(*ctxt).input).col += 2 as libc::c_int;
        while *(*(*ctxt).input).cur as libc::c_int != ';' as i32 {
            if *(*(*ctxt).input).cur as libc::c_int >= '0' as i32
                && *(*(*ctxt).input).cur as libc::c_int <= '9' as i32
            {
                if val < 0x110000 as libc::c_int {
                    val = val * 10 as libc::c_int
                        + (*(*(*ctxt).input).cur as libc::c_int - '0' as i32);
                }
                xmlNextChar(ctxt);
            } else {
                htmlParseErr(
                    ctxt,
                    XML_ERR_INVALID_DEC_CHARREF,
                    b"htmlParseCharRef: missing semicolon\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                break;
            }
        }
        if *(*(*ctxt).input).cur as libc::c_int == ';' as i32 {
            xmlNextChar(ctxt);
        }
    } else {
        htmlParseErr(
            ctxt,
            XML_ERR_INVALID_CHARREF,
            b"htmlParseCharRef: invalid value\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    }
    if if val < 0x100 as libc::c_int {
        (0x9 as libc::c_int <= val && val <= 0xa as libc::c_int
            || val == 0xd as libc::c_int || 0x20 as libc::c_int <= val) as libc::c_int
    } else {
        (0x100 as libc::c_int <= val && val <= 0xd7ff as libc::c_int
            || 0xe000 as libc::c_int <= val && val <= 0xfffd as libc::c_int
            || 0x10000 as libc::c_int <= val && val <= 0x10ffff as libc::c_int)
            as libc::c_int
    } != 0
    {
        return val
    } else {
        if val >= 0x110000 as libc::c_int {
            htmlParseErr(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"htmlParseCharRef: value too large\n\0" as *const u8
                    as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        } else {
            htmlParseErrInt(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"htmlParseCharRef: invalid xmlChar value %d\n\0" as *const u8
                    as *const libc::c_char,
                val,
            );
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn htmlParseDocTypeDecl(mut ctxt: htmlParserCtxtPtr) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let ref mut fresh105 = (*(*ctxt).input).cur;
    *fresh105 = (*fresh105).offset(9 as libc::c_int as isize);
    (*(*ctxt).input).col += 9 as libc::c_int;
    htmlSkipBlankChars(ctxt);
    name = htmlParseName(ctxt);
    if name.is_null() {
        htmlParseErr(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"htmlParseDocTypeDecl : no DOCTYPE name !\n\0" as *const u8
                as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    }
    htmlSkipBlankChars(ctxt);
    URI = htmlParseExternalID(ctxt, &mut ExternalID);
    htmlSkipBlankChars(ctxt);
    if *(*(*ctxt).input).cur as libc::c_int != '>' as i32 {
        htmlParseErr(
            ctxt,
            XML_ERR_DOCTYPE_NOT_FINISHED,
            b"DOCTYPE improperly terminated\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        while *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int
            && *(*(*ctxt).input).cur as libc::c_int != '>' as i32
        {
            xmlNextChar(ctxt);
        }
    }
    if *(*(*ctxt).input).cur as libc::c_int == '>' as i32 {
        xmlNextChar(ctxt);
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).internalSubset).is_some()
        && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).internalSubset)
            .expect(
                "non-null function pointer",
            )((*ctxt).userData, name, ExternalID, URI);
    }
    if !URI.is_null() {
        xmlFree.expect("non-null function pointer")(URI as *mut libc::c_void);
    }
    if !ExternalID.is_null() {
        xmlFree.expect("non-null function pointer")(ExternalID as *mut libc::c_void);
    }
}
unsafe extern "C" fn htmlParseAttribute(
    mut ctxt: htmlParserCtxtPtr,
    mut value: *mut *mut xmlChar,
) -> *const xmlChar {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    *value = 0 as *mut xmlChar;
    name = htmlParseHTMLName(ctxt);
    if name.is_null() {
        htmlParseErr(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"error parsing attribute name\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as *const xmlChar;
    }
    htmlSkipBlankChars(ctxt);
    if *(*(*ctxt).input).cur as libc::c_int == '=' as i32 {
        xmlNextChar(ctxt);
        htmlSkipBlankChars(ctxt);
        val = htmlParseAttValue(ctxt);
    }
    *value = val;
    return name;
}
unsafe extern "C" fn htmlCheckEncodingDirect(
    mut ctxt: htmlParserCtxtPtr,
    mut encoding: *const xmlChar,
) {
    if ctxt.is_null() || encoding.is_null()
        || (*ctxt).options & HTML_PARSE_IGNORE_ENC as libc::c_int != 0
    {
        return;
    }
    if !((*(*ctxt).input).encoding).is_null() {
        return;
    }
    if !encoding.is_null() {
        let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
        let mut handler: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
        while *encoding as libc::c_int == ' ' as i32
            || *encoding as libc::c_int == '\t' as i32
        {
            encoding = encoding.offset(1);
        }
        if !((*(*ctxt).input).encoding).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*(*ctxt).input).encoding as *mut xmlChar as *mut libc::c_void);
        }
        let ref mut fresh106 = (*(*ctxt).input).encoding;
        *fresh106 = xmlStrdup(encoding);
        enc = xmlParseCharEncoding(encoding as *const libc::c_char);
        if enc as libc::c_int != XML_CHAR_ENCODING_ERROR as libc::c_int {
            if (enc as libc::c_int == XML_CHAR_ENCODING_UTF16LE as libc::c_int
                || enc as libc::c_int == XML_CHAR_ENCODING_UTF16BE as libc::c_int
                || enc as libc::c_int == XML_CHAR_ENCODING_UCS4LE as libc::c_int
                || enc as libc::c_int == XML_CHAR_ENCODING_UCS4BE as libc::c_int)
                && !((*(*ctxt).input).buf).is_null()
                && ((*(*(*ctxt).input).buf).encoder).is_null()
            {
                htmlParseErr(
                    ctxt,
                    XML_ERR_INVALID_ENCODING,
                    b"htmlCheckEncoding: wrong encoding meta\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
            } else {
                xmlSwitchEncoding(ctxt, enc);
            }
            (*ctxt).charset = XML_CHAR_ENCODING_UTF8 as libc::c_int;
        } else {
            handler = xmlFindCharEncodingHandler(encoding as *const libc::c_char);
            if !handler.is_null() {
                xmlSwitchToEncoding(ctxt, handler);
                (*ctxt).charset = XML_CHAR_ENCODING_UTF8 as libc::c_int;
            } else {
                htmlParseErr(
                    ctxt,
                    XML_ERR_UNSUPPORTED_ENCODING,
                    b"htmlCheckEncoding: unknown encoding %s\n\0" as *const u8
                        as *const libc::c_char,
                    encoding,
                    0 as *const xmlChar,
                );
            }
        }
        if !((*(*ctxt).input).buf).is_null()
            && !((*(*(*ctxt).input).buf).encoder).is_null()
            && !((*(*(*ctxt).input).buf).raw).is_null()
            && !((*(*(*ctxt).input).buf).buffer).is_null()
        {
            let mut nbchars: libc::c_int = 0;
            let mut processed: libc::c_int = 0;
            processed = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                as libc::c_long as libc::c_int;
            xmlBufShrink((*(*(*ctxt).input).buf).buffer, processed as size_t);
            nbchars = xmlCharEncInput((*(*ctxt).input).buf, 1 as libc::c_int);
            xmlBufResetInput((*(*(*ctxt).input).buf).buffer, (*ctxt).input);
            if nbchars < 0 as libc::c_int {
                htmlParseErr(
                    ctxt,
                    XML_ERR_INVALID_ENCODING,
                    b"htmlCheckEncoding: encoder error\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
            }
        }
    }
}
unsafe extern "C" fn htmlCheckEncoding(
    mut ctxt: htmlParserCtxtPtr,
    mut attvalue: *const xmlChar,
) {
    let mut encoding: *const xmlChar = 0 as *const xmlChar;
    if attvalue.is_null() {
        return;
    }
    encoding = xmlStrcasestr(
        attvalue,
        b"charset\0" as *const u8 as *const libc::c_char as *mut xmlChar,
    );
    if !encoding.is_null() {
        encoding = encoding.offset(7 as libc::c_int as isize);
    }
    if !encoding.is_null()
        && (*encoding as libc::c_int == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= *encoding as libc::c_int
                && *encoding as libc::c_int <= 0xa as libc::c_int
            || *encoding as libc::c_int == 0xd as libc::c_int)
    {
        encoding = xmlStrcasestr(
            attvalue,
            b"=\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        );
    }
    if !encoding.is_null() && *encoding as libc::c_int == '=' as i32 {
        encoding = encoding.offset(1);
        htmlCheckEncodingDirect(ctxt, encoding);
    }
}
unsafe extern "C" fn htmlCheckMeta(
    mut ctxt: htmlParserCtxtPtr,
    mut atts: *mut *const xmlChar,
) {
    let mut i: libc::c_int = 0;
    let mut att: *const xmlChar = 0 as *const xmlChar;
    let mut value: *const xmlChar = 0 as *const xmlChar;
    let mut http: libc::c_int = 0 as libc::c_int;
    let mut content: *const xmlChar = 0 as *const xmlChar;
    if ctxt.is_null() || atts.is_null() {
        return;
    }
    i = 0 as libc::c_int;
    let fresh107 = i;
    i = i + 1;
    att = *atts.offset(fresh107 as isize);
    while !att.is_null() {
        let fresh108 = i;
        i = i + 1;
        value = *atts.offset(fresh108 as isize);
        if !value.is_null()
            && xmlStrcasecmp(
                att,
                b"http-equiv\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) == 0
            && xmlStrcasecmp(
                value,
                b"Content-Type\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) == 0
        {
            http = 1 as libc::c_int;
        } else if !value.is_null()
                && xmlStrcasecmp(
                    att,
                    b"charset\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) == 0
            {
            htmlCheckEncodingDirect(ctxt, value);
        } else if !value.is_null()
                && xmlStrcasecmp(
                    att,
                    b"content\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) == 0
            {
            content = value;
        }
        let fresh109 = i;
        i = i + 1;
        att = *atts.offset(fresh109 as isize);
    }
    if http != 0 && !content.is_null() {
        htmlCheckEncoding(ctxt, content);
    }
}
unsafe extern "C" fn htmlParseStartTag(mut ctxt: htmlParserCtxtPtr) -> libc::c_int {
    let mut current_block: u64;
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut attname: *const xmlChar = 0 as *const xmlChar;
    let mut attvalue: *mut xmlChar = 0 as *mut xmlChar;
    let mut atts: *mut *const xmlChar = 0 as *mut *const xmlChar;
    let mut nbatts: libc::c_int = 0 as libc::c_int;
    let mut maxatts: libc::c_int = 0;
    let mut meta: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut discardtag: libc::c_int = 0 as libc::c_int;
    if ctxt.is_null() || ((*ctxt).input).is_null() {
        htmlParseErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"htmlParseStartTag: context error\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return -(1 as libc::c_int);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return -(1 as libc::c_int);
    }
    if *(*(*ctxt).input).cur as libc::c_int != '<' as i32 {
        return -(1 as libc::c_int);
    }
    xmlNextChar(ctxt);
    atts = (*ctxt).atts;
    maxatts = (*ctxt).maxatts;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
    name = htmlParseHTMLName(ctxt);
    if name.is_null() {
        htmlParseErr(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"htmlParseStartTag: invalid element name\n\0" as *const u8
                as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        while *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int
            && *(*(*ctxt).input).cur as libc::c_int != '>' as i32
            && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
        {
            xmlNextChar(ctxt);
        }
        return -(1 as libc::c_int);
    }
    if xmlStrEqual(name, b"meta\0" as *const u8 as *const libc::c_char as *mut xmlChar)
        != 0
    {
        meta = 1 as libc::c_int;
    }
    htmlAutoClose(ctxt, name);
    htmlCheckImplied(ctxt, name);
    if (*ctxt).nameNr > 0 as libc::c_int
        && xmlStrEqual(
            name,
            b"html\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
    {
        htmlParseErr(
            ctxt,
            XML_HTML_STRUCURE_ERROR,
            b"htmlParseStartTag: misplaced <html> tag\n\0" as *const u8
                as *const libc::c_char,
            name,
            0 as *const xmlChar,
        );
        discardtag = 1 as libc::c_int;
        let ref mut fresh110 = (*ctxt).depth;
        *fresh110 += 1;
    }
    if (*ctxt).nameNr != 1 as libc::c_int
        && xmlStrEqual(
            name,
            b"head\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
    {
        htmlParseErr(
            ctxt,
            XML_HTML_STRUCURE_ERROR,
            b"htmlParseStartTag: misplaced <head> tag\n\0" as *const u8
                as *const libc::c_char,
            name,
            0 as *const xmlChar,
        );
        discardtag = 1 as libc::c_int;
        let ref mut fresh111 = (*ctxt).depth;
        *fresh111 += 1;
    }
    if xmlStrEqual(name, b"body\0" as *const u8 as *const libc::c_char as *mut xmlChar)
        != 0
    {
        let mut indx: libc::c_int = 0;
        indx = 0 as libc::c_int;
        while indx < (*ctxt).nameNr {
            if xmlStrEqual(
                *((*ctxt).nameTab).offset(indx as isize),
                b"body\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            {
                htmlParseErr(
                    ctxt,
                    XML_HTML_STRUCURE_ERROR,
                    b"htmlParseStartTag: misplaced <body> tag\n\0" as *const u8
                        as *const libc::c_char,
                    name,
                    0 as *const xmlChar,
                );
                discardtag = 1 as libc::c_int;
                let ref mut fresh112 = (*ctxt).depth;
                *fresh112 += 1;
            }
            indx += 1;
        }
    }
    htmlSkipBlankChars(ctxt);
    while *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int
        && *(*(*ctxt).input).cur as libc::c_int != '>' as i32
        && (*(*(*ctxt).input).cur as libc::c_int != '/' as i32
            || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                != '>' as i32)
    {
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        attname = htmlParseAttribute(ctxt, &mut attvalue);
        if !attname.is_null() {
            i = 0 as libc::c_int;
            loop {
                if !(i < nbatts) {
                    current_block = 16415152177862271243;
                    break;
                }
                if xmlStrEqual(*atts.offset(i as isize), attname) != 0 {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_ATTRIBUTE_REDEFINED,
                        b"Attribute %s redefined\n\0" as *const u8
                            as *const libc::c_char,
                        attname,
                        0 as *const xmlChar,
                    );
                    if !attvalue.is_null() {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(attvalue as *mut libc::c_void);
                    }
                    current_block = 12272308212492661223;
                    break;
                } else {
                    i += 2 as libc::c_int;
                }
            }
            match current_block {
                12272308212492661223 => {}
                _ => {
                    if atts.is_null() {
                        maxatts = 22 as libc::c_int;
                        atts = xmlMalloc
                            .expect(
                                "non-null function pointer",
                            )(
                            (maxatts as libc::c_ulong)
                                .wrapping_mul(
                                    ::std::mem::size_of::<*mut xmlChar>() as libc::c_ulong,
                                ),
                        ) as *mut *const xmlChar;
                        if atts.is_null() {
                            htmlErrMemory(ctxt, 0 as *const libc::c_char);
                            if !attvalue.is_null() {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(attvalue as *mut libc::c_void);
                            }
                            current_block = 12272308212492661223;
                        } else {
                            let ref mut fresh113 = (*ctxt).atts;
                            *fresh113 = atts;
                            (*ctxt).maxatts = maxatts;
                            current_block = 10435735846551762309;
                        }
                    } else if nbatts + 4 as libc::c_int > maxatts {
                        let mut n: *mut *const xmlChar = 0 as *mut *const xmlChar;
                        maxatts *= 2 as libc::c_int;
                        n = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(
                            atts as *mut libc::c_void,
                            (maxatts as libc::c_ulong)
                                .wrapping_mul(
                                    ::std::mem::size_of::<*const xmlChar>() as libc::c_ulong,
                                ),
                        ) as *mut *const xmlChar;
                        if n.is_null() {
                            htmlErrMemory(ctxt, 0 as *const libc::c_char);
                            if !attvalue.is_null() {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(attvalue as *mut libc::c_void);
                            }
                            current_block = 12272308212492661223;
                        } else {
                            atts = n;
                            let ref mut fresh114 = (*ctxt).atts;
                            *fresh114 = atts;
                            (*ctxt).maxatts = maxatts;
                            current_block = 10435735846551762309;
                        }
                    } else {
                        current_block = 10435735846551762309;
                    }
                    match current_block {
                        12272308212492661223 => {}
                        _ => {
                            let fresh115 = nbatts;
                            nbatts = nbatts + 1;
                            let ref mut fresh116 = *atts.offset(fresh115 as isize);
                            *fresh116 = attname;
                            let fresh117 = nbatts;
                            nbatts = nbatts + 1;
                            let ref mut fresh118 = *atts.offset(fresh117 as isize);
                            *fresh118 = attvalue;
                            let ref mut fresh119 = *atts.offset(nbatts as isize);
                            *fresh119 = 0 as *const xmlChar;
                            let ref mut fresh120 = *atts
                                .offset((nbatts + 1 as libc::c_int) as isize);
                            *fresh120 = 0 as *const xmlChar;
                        }
                    }
                }
            }
        } else {
            if !attvalue.is_null() {
                xmlFree
                    .expect("non-null function pointer")(attvalue as *mut libc::c_void);
            }
            while *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int
                && !(*(*(*ctxt).input).cur as libc::c_int == 0x20 as libc::c_int
                    || 0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
                        && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
                    || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int)
                && *(*(*ctxt).input).cur as libc::c_int != '>' as i32
                && (*(*(*ctxt).input).cur as libc::c_int != '/' as i32
                    || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int != '>' as i32)
            {
                xmlNextChar(ctxt);
            }
        }
        htmlSkipBlankChars(ctxt);
    }
    if meta != 0 && nbatts != 0 as libc::c_int {
        htmlCheckMeta(ctxt, atts);
    }
    if discardtag == 0 {
        htmlnamePush(ctxt, name);
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).startElement).is_some() {
            if nbatts != 0 as libc::c_int {
                ((*(*ctxt).sax).startElement)
                    .expect("non-null function pointer")((*ctxt).userData, name, atts);
            } else {
                ((*(*ctxt).sax).startElement)
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).userData, name, 0 as *mut *const xmlChar);
            }
        }
    }
    if !atts.is_null() {
        i = 1 as libc::c_int;
        while i < nbatts {
            if !(*atts.offset(i as isize)).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(*atts.offset(i as isize) as *mut xmlChar as *mut libc::c_void);
            }
            i += 2 as libc::c_int;
        }
    }
    return discardtag;
}
unsafe extern "C" fn htmlParseEndTag(mut ctxt: htmlParserCtxtPtr) -> libc::c_int {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut oldname: *const xmlChar = 0 as *const xmlChar;
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    if *(*(*ctxt).input).cur as libc::c_int != '<' as i32
        || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            != '/' as i32
    {
        htmlParseErr(
            ctxt,
            XML_ERR_LTSLASH_REQUIRED,
            b"htmlParseEndTag: '</' not found\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as libc::c_int;
    }
    let ref mut fresh121 = (*(*ctxt).input).cur;
    *fresh121 = (*fresh121).offset(2 as libc::c_int as isize);
    (*(*ctxt).input).col += 2 as libc::c_int;
    name = htmlParseHTMLName(ctxt);
    if name.is_null() {
        return 0 as libc::c_int;
    }
    htmlSkipBlankChars(ctxt);
    if *(*(*ctxt).input).cur as libc::c_int != '>' as i32 {
        htmlParseErr(
            ctxt,
            XML_ERR_GT_REQUIRED,
            b"End tag : expected '>'\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        while *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int
            && *(*(*ctxt).input).cur as libc::c_int != '>' as i32
        {
            xmlNextChar(ctxt);
        }
    }
    if *(*(*ctxt).input).cur as libc::c_int == '>' as i32 {
        xmlNextChar(ctxt);
    }
    if (*ctxt).depth > 0 as libc::c_int
        && (xmlStrEqual(
            name,
            b"html\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
            || xmlStrEqual(
                name,
                b"body\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            || xmlStrEqual(
                name,
                b"head\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0)
    {
        let ref mut fresh122 = (*ctxt).depth;
        *fresh122 -= 1;
        return 0 as libc::c_int;
    }
    i = (*ctxt).nameNr - 1 as libc::c_int;
    while i >= 0 as libc::c_int {
        if xmlStrEqual(name, *((*ctxt).nameTab).offset(i as isize)) != 0 {
            break;
        }
        i -= 1;
    }
    if i < 0 as libc::c_int {
        htmlParseErr(
            ctxt,
            XML_ERR_TAG_NAME_MISMATCH,
            b"Unexpected end tag : %s\n\0" as *const u8 as *const libc::c_char,
            name,
            0 as *const xmlChar,
        );
        return 0 as libc::c_int;
    }
    htmlAutoCloseOnClose(ctxt, name);
    if !((*ctxt).name).is_null() && xmlStrEqual((*ctxt).name, name) == 0 {
        htmlParseErr(
            ctxt,
            XML_ERR_TAG_NAME_MISMATCH,
            b"Opening and ending tag mismatch: %s and %s\n\0" as *const u8
                as *const libc::c_char,
            name,
            (*ctxt).name,
        );
    }
    oldname = (*ctxt).name;
    if !oldname.is_null() && xmlStrEqual(oldname, name) != 0 {
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElement).is_some() {
            ((*(*ctxt).sax).endElement)
                .expect("non-null function pointer")((*ctxt).userData, name);
        }
        htmlNodeInfoPop(ctxt);
        htmlnamePop(ctxt);
        ret = 1 as libc::c_int;
    } else {
        ret = 0 as libc::c_int;
    }
    return ret;
}
unsafe extern "C" fn htmlParseReference(mut ctxt: htmlParserCtxtPtr) {
    let mut ent: *const htmlEntityDesc = 0 as *const htmlEntityDesc;
    let mut out: [xmlChar; 6] = [0; 6];
    let mut name: *const xmlChar = 0 as *const xmlChar;
    if *(*(*ctxt).input).cur as libc::c_int != '&' as i32 {
        return;
    }
    if *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
        == '#' as i32
    {
        let mut c: libc::c_uint = 0;
        let mut bits: libc::c_int = 0;
        let mut i: libc::c_int = 0 as libc::c_int;
        c = htmlParseCharRef(ctxt) as libc::c_uint;
        if c == 0 as libc::c_int as libc::c_uint {
            return;
        }
        if c < 0x80 as libc::c_int as libc::c_uint {
            let fresh123 = i;
            i = i + 1;
            out[fresh123 as usize] = c as xmlChar;
            bits = -(6 as libc::c_int);
        } else if c < 0x800 as libc::c_int as libc::c_uint {
            let fresh124 = i;
            i = i + 1;
            out[fresh124
                as usize] = (c >> 6 as libc::c_int & 0x1f as libc::c_int as libc::c_uint
                | 0xc0 as libc::c_int as libc::c_uint) as xmlChar;
            bits = 0 as libc::c_int;
        } else if c < 0x10000 as libc::c_int as libc::c_uint {
            let fresh125 = i;
            i = i + 1;
            out[fresh125
                as usize] = (c >> 12 as libc::c_int & 0xf as libc::c_int as libc::c_uint
                | 0xe0 as libc::c_int as libc::c_uint) as xmlChar;
            bits = 6 as libc::c_int;
        } else {
            let fresh126 = i;
            i = i + 1;
            out[fresh126
                as usize] = (c >> 18 as libc::c_int & 0x7 as libc::c_int as libc::c_uint
                | 0xf0 as libc::c_int as libc::c_uint) as xmlChar;
            bits = 12 as libc::c_int;
        }
        while bits >= 0 as libc::c_int {
            let fresh127 = i;
            i = i + 1;
            out[fresh127
                as usize] = (c >> bits & 0x3f as libc::c_int as libc::c_uint
                | 0x80 as libc::c_int as libc::c_uint) as xmlChar;
            bits -= 6 as libc::c_int;
        }
        out[i as usize] = 0 as libc::c_int as xmlChar;
        htmlCheckParagraph(ctxt);
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).characters).is_some() {
            ((*(*ctxt).sax).characters)
                .expect(
                    "non-null function pointer",
                )((*ctxt).userData, out.as_mut_ptr(), i);
        }
    } else {
        ent = htmlParseEntityRef(ctxt, &mut name);
        if name.is_null() {
            htmlCheckParagraph(ctxt);
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).characters).is_some() {
                ((*(*ctxt).sax).characters)
                    .expect(
                        "non-null function pointer",
                    )(
                    (*ctxt).userData,
                    b"&\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    1 as libc::c_int,
                );
            }
            return;
        }
        if ent.is_null() || !((*ent).value > 0 as libc::c_int as libc::c_uint) {
            htmlCheckParagraph(ctxt);
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).characters).is_some() {
                ((*(*ctxt).sax).characters)
                    .expect(
                        "non-null function pointer",
                    )(
                    (*ctxt).userData,
                    b"&\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    1 as libc::c_int,
                );
                ((*(*ctxt).sax).characters)
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).userData, name, xmlStrlen(name));
            }
        } else {
            let mut c_0: libc::c_uint = 0;
            let mut bits_0: libc::c_int = 0;
            let mut i_0: libc::c_int = 0 as libc::c_int;
            c_0 = (*ent).value;
            if c_0 < 0x80 as libc::c_int as libc::c_uint {
                let fresh128 = i_0;
                i_0 = i_0 + 1;
                out[fresh128 as usize] = c_0 as xmlChar;
                bits_0 = -(6 as libc::c_int);
            } else if c_0 < 0x800 as libc::c_int as libc::c_uint {
                let fresh129 = i_0;
                i_0 = i_0 + 1;
                out[fresh129
                    as usize] = (c_0 >> 6 as libc::c_int
                    & 0x1f as libc::c_int as libc::c_uint
                    | 0xc0 as libc::c_int as libc::c_uint) as xmlChar;
                bits_0 = 0 as libc::c_int;
            } else if c_0 < 0x10000 as libc::c_int as libc::c_uint {
                let fresh130 = i_0;
                i_0 = i_0 + 1;
                out[fresh130
                    as usize] = (c_0 >> 12 as libc::c_int
                    & 0xf as libc::c_int as libc::c_uint
                    | 0xe0 as libc::c_int as libc::c_uint) as xmlChar;
                bits_0 = 6 as libc::c_int;
            } else {
                let fresh131 = i_0;
                i_0 = i_0 + 1;
                out[fresh131
                    as usize] = (c_0 >> 18 as libc::c_int
                    & 0x7 as libc::c_int as libc::c_uint
                    | 0xf0 as libc::c_int as libc::c_uint) as xmlChar;
                bits_0 = 12 as libc::c_int;
            }
            while bits_0 >= 0 as libc::c_int {
                let fresh132 = i_0;
                i_0 = i_0 + 1;
                out[fresh132
                    as usize] = (c_0 >> bits_0 & 0x3f as libc::c_int as libc::c_uint
                    | 0x80 as libc::c_int as libc::c_uint) as xmlChar;
                bits_0 -= 6 as libc::c_int;
            }
            out[i_0 as usize] = 0 as libc::c_int as xmlChar;
            htmlCheckParagraph(ctxt);
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).characters).is_some() {
                ((*(*ctxt).sax).characters)
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).userData, out.as_mut_ptr(), i_0);
            }
        }
    };
}
unsafe extern "C" fn htmlParseContent(mut ctxt: htmlParserCtxtPtr) {
    let mut currentNode: *mut xmlChar = 0 as *mut xmlChar;
    let mut depth: libc::c_int = 0;
    let mut name: *const xmlChar = 0 as *const xmlChar;
    currentNode = xmlStrdup((*ctxt).name);
    depth = (*ctxt).nameNr;
    loop {
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
            break;
        }
        if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '/' as i32
        {
            if htmlParseEndTag(ctxt) != 0
                && (!currentNode.is_null() || (*ctxt).nameNr == 0 as libc::c_int)
            {
                if !currentNode.is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(currentNode as *mut libc::c_void);
                }
                return;
            }
        } else {
            if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
                && (0x41 as libc::c_int
                    <= *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int
                    && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int <= 0x5a as libc::c_int
                    || 0x61 as libc::c_int
                        <= *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                            as libc::c_int
                        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                            as libc::c_int <= 0x7a as libc::c_int
                    || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int == '_' as i32
                    || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int == ':' as i32)
            {
                name = htmlParseHTMLName_nonInvasive(ctxt);
                if name.is_null() {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_NAME_REQUIRED,
                        b"htmlParseStartTag: invalid element name\n\0" as *const u8
                            as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    while *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int
                        && *(*(*ctxt).input).cur as libc::c_int != '>' as i32
                    {
                        xmlNextChar(ctxt);
                    }
                    if !currentNode.is_null() {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(currentNode as *mut libc::c_void);
                    }
                    return;
                }
                if !((*ctxt).name).is_null() {
                    if htmlCheckAutoClose(name, (*ctxt).name) == 1 as libc::c_int {
                        htmlAutoClose(ctxt, name);
                        continue;
                    }
                }
            }
            if (*ctxt).nameNr > 0 as libc::c_int && depth >= (*ctxt).nameNr
                && xmlStrEqual(currentNode, (*ctxt).name) == 0
            {
                if !currentNode.is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(currentNode as *mut libc::c_void);
                }
                return;
            }
            if *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int
                && (xmlStrEqual(
                    currentNode,
                    b"script\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) != 0
                    || xmlStrEqual(
                        currentNode,
                        b"style\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    ) != 0)
            {
                htmlParseScript(ctxt);
            } else if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
                    && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int == '!' as i32
                {
                if ({
                    let mut __res: libc::c_int = 0;
                    if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                        > 1 as libc::c_int as libc::c_ulong
                    {
                        if 0 != 0 {
                            let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                .offset(2 as libc::c_int as isize) as libc::c_int;
                            __res = (if __c < -(128 as libc::c_int)
                                || __c > 255 as libc::c_int
                            {
                                __c
                            } else {
                                *(*__ctype_toupper_loc()).offset(__c as isize)
                            });
                        } else {
                            __res = toupper(
                                *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                    as libc::c_int,
                            );
                        }
                    } else {
                        __res = *(*__ctype_toupper_loc())
                            .offset(
                                *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                    as libc::c_int as isize,
                            );
                    }
                    __res
                }) == 'D' as i32
                    && ({
                        let mut __res: libc::c_int = 0;
                        if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                            > 1 as libc::c_int as libc::c_ulong
                        {
                            if 0 != 0 {
                                let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                    .offset(3 as libc::c_int as isize) as libc::c_int;
                                __res = (if __c < -(128 as libc::c_int)
                                    || __c > 255 as libc::c_int
                                {
                                    __c
                                } else {
                                    *(*__ctype_toupper_loc()).offset(__c as isize)
                                });
                            } else {
                                __res = toupper(
                                    *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                        as libc::c_int,
                                );
                            }
                        } else {
                            __res = *(*__ctype_toupper_loc())
                                .offset(
                                    *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                        as libc::c_int as isize,
                                );
                        }
                        __res
                    }) == 'O' as i32
                    && ({
                        let mut __res: libc::c_int = 0;
                        if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                            > 1 as libc::c_int as libc::c_ulong
                        {
                            if 0 != 0 {
                                let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                    .offset(4 as libc::c_int as isize) as libc::c_int;
                                __res = (if __c < -(128 as libc::c_int)
                                    || __c > 255 as libc::c_int
                                {
                                    __c
                                } else {
                                    *(*__ctype_toupper_loc()).offset(__c as isize)
                                });
                            } else {
                                __res = toupper(
                                    *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                        as libc::c_int,
                                );
                            }
                        } else {
                            __res = *(*__ctype_toupper_loc())
                                .offset(
                                    *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                        as libc::c_int as isize,
                                );
                        }
                        __res
                    }) == 'C' as i32
                    && ({
                        let mut __res: libc::c_int = 0;
                        if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                            > 1 as libc::c_int as libc::c_ulong
                        {
                            if 0 != 0 {
                                let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                    .offset(5 as libc::c_int as isize) as libc::c_int;
                                __res = (if __c < -(128 as libc::c_int)
                                    || __c > 255 as libc::c_int
                                {
                                    __c
                                } else {
                                    *(*__ctype_toupper_loc()).offset(__c as isize)
                                });
                            } else {
                                __res = toupper(
                                    *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                        as libc::c_int,
                                );
                            }
                        } else {
                            __res = *(*__ctype_toupper_loc())
                                .offset(
                                    *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                        as libc::c_int as isize,
                                );
                        }
                        __res
                    }) == 'T' as i32
                    && ({
                        let mut __res: libc::c_int = 0;
                        if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                            > 1 as libc::c_int as libc::c_ulong
                        {
                            if 0 != 0 {
                                let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                    .offset(6 as libc::c_int as isize) as libc::c_int;
                                __res = (if __c < -(128 as libc::c_int)
                                    || __c > 255 as libc::c_int
                                {
                                    __c
                                } else {
                                    *(*__ctype_toupper_loc()).offset(__c as isize)
                                });
                            } else {
                                __res = toupper(
                                    *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                                        as libc::c_int,
                                );
                            }
                        } else {
                            __res = *(*__ctype_toupper_loc())
                                .offset(
                                    *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                                        as libc::c_int as isize,
                                );
                        }
                        __res
                    }) == 'Y' as i32
                    && ({
                        let mut __res: libc::c_int = 0;
                        if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                            > 1 as libc::c_int as libc::c_ulong
                        {
                            if 0 != 0 {
                                let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                    .offset(7 as libc::c_int as isize) as libc::c_int;
                                __res = (if __c < -(128 as libc::c_int)
                                    || __c > 255 as libc::c_int
                                {
                                    __c
                                } else {
                                    *(*__ctype_toupper_loc()).offset(__c as isize)
                                });
                            } else {
                                __res = toupper(
                                    *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                                        as libc::c_int,
                                );
                            }
                        } else {
                            __res = *(*__ctype_toupper_loc())
                                .offset(
                                    *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                                        as libc::c_int as isize,
                                );
                        }
                        __res
                    }) == 'P' as i32
                    && ({
                        let mut __res: libc::c_int = 0;
                        if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                            > 1 as libc::c_int as libc::c_ulong
                        {
                            if 0 != 0 {
                                let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                    .offset(8 as libc::c_int as isize) as libc::c_int;
                                __res = (if __c < -(128 as libc::c_int)
                                    || __c > 255 as libc::c_int
                                {
                                    __c
                                } else {
                                    *(*__ctype_toupper_loc()).offset(__c as isize)
                                });
                            } else {
                                __res = toupper(
                                    *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                                        as libc::c_int,
                                );
                            }
                        } else {
                            __res = *(*__ctype_toupper_loc())
                                .offset(
                                    *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                                        as libc::c_int as isize,
                                );
                        }
                        __res
                    }) == 'E' as i32
                {
                    htmlParseErr(
                        ctxt,
                        XML_HTML_STRUCURE_ERROR,
                        b"Misplaced DOCTYPE declaration\n\0" as *const u8
                            as *const libc::c_char,
                        b"DOCTYPE\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                        0 as *const xmlChar,
                    );
                    htmlParseDocTypeDecl(ctxt);
                } else if *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                        as libc::c_int == '-' as i32
                        && *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                            as libc::c_int == '-' as i32
                    {
                    htmlParseComment(ctxt);
                } else {
                    htmlSkipBogusComment(ctxt);
                }
            } else if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
                    && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int == '?' as i32
                {
                htmlParsePI(ctxt);
            } else if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
                    && (0x41 as libc::c_int
                        <= *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                            as libc::c_int
                        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                            as libc::c_int <= 0x5a as libc::c_int
                        || 0x61 as libc::c_int
                            <= *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                as libc::c_int
                            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                as libc::c_int <= 0x7a as libc::c_int)
                {
                htmlParseElement(ctxt);
            } else if *(*(*ctxt).input).cur as libc::c_int == '<' as i32 {
                if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                    && ((*(*ctxt).sax).characters).is_some()
                {
                    ((*(*ctxt).sax).characters)
                        .expect(
                            "non-null function pointer",
                        )(
                        (*ctxt).userData,
                        b"<\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                        1 as libc::c_int,
                    );
                }
                xmlNextChar(ctxt);
            } else if *(*(*ctxt).input).cur as libc::c_int == '&' as i32 {
                htmlParseReference(ctxt);
            } else if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                htmlAutoCloseOnEnd(ctxt);
                break;
            } else {
                htmlParseCharData(ctxt);
            }
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
        }
    }
    if !currentNode.is_null() {
        xmlFree.expect("non-null function pointer")(currentNode as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn htmlParseElement(mut ctxt: htmlParserCtxtPtr) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut currentNode: *mut xmlChar = 0 as *mut xmlChar;
    let mut info: *const htmlElemDesc = 0 as *const htmlElemDesc;
    let mut node_info: htmlParserNodeInfo = htmlParserNodeInfo {
        node: 0 as *const _xmlNode,
        begin_pos: 0,
        begin_line: 0,
        end_pos: 0,
        end_line: 0,
    };
    let mut failed: libc::c_int = 0;
    let mut depth: libc::c_int = 0;
    let mut oldptr: *const xmlChar = 0 as *const xmlChar;
    if ctxt.is_null() || ((*ctxt).input).is_null() {
        htmlParseErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"htmlParseElement: context error\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return;
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return;
    }
    if (*ctxt).record_info != 0 {
        node_info
            .begin_pos = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                    as libc::c_ulong,
            );
        node_info.begin_line = (*(*ctxt).input).line as libc::c_ulong;
    }
    failed = htmlParseStartTag(ctxt);
    name = (*ctxt).name;
    if failed == -(1 as libc::c_int) || name.is_null() {
        if *(*(*ctxt).input).cur as libc::c_int == '>' as i32 {
            xmlNextChar(ctxt);
        }
        return;
    }
    info = htmlTagLookup(name);
    if info.is_null() {
        htmlParseErr(
            ctxt,
            XML_HTML_UNKNOWN_TAG,
            b"Tag %s invalid\n\0" as *const u8 as *const libc::c_char,
            name,
            0 as *const xmlChar,
        );
    }
    if *(*(*ctxt).input).cur as libc::c_int == '/' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '>' as i32
    {
        let ref mut fresh133 = (*(*ctxt).input).cur;
        *fresh133 = (*fresh133).offset(2 as libc::c_int as isize);
        (*(*ctxt).input).col += 2 as libc::c_int;
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElement).is_some() {
            ((*(*ctxt).sax).endElement)
                .expect("non-null function pointer")((*ctxt).userData, name);
        }
        htmlnamePop(ctxt);
        return;
    }
    if *(*(*ctxt).input).cur as libc::c_int == '>' as i32 {
        xmlNextChar(ctxt);
    } else {
        htmlParseErr(
            ctxt,
            XML_ERR_GT_REQUIRED,
            b"Couldn't find end of Start Tag %s\n\0" as *const u8 as *const libc::c_char,
            name,
            0 as *const xmlChar,
        );
        if xmlStrEqual(name, (*ctxt).name) != 0 {
            nodePop(ctxt);
            htmlnamePop(ctxt);
        }
        if (*ctxt).record_info != 0 {
            node_info
                .end_pos = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long as libc::c_ulong,
                );
            node_info.end_line = (*(*ctxt).input).line as libc::c_ulong;
            node_info.node = (*ctxt).node as *const _xmlNode;
            xmlParserAddNodeInfo(ctxt, &mut node_info);
        }
        return;
    }
    if !info.is_null() && (*info).empty as libc::c_int != 0 {
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElement).is_some() {
            ((*(*ctxt).sax).endElement)
                .expect("non-null function pointer")((*ctxt).userData, name);
        }
        htmlnamePop(ctxt);
        return;
    }
    currentNode = xmlStrdup((*ctxt).name);
    depth = (*ctxt).nameNr;
    while *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int {
        oldptr = (*(*ctxt).input).cur;
        htmlParseContent(ctxt);
        if oldptr == (*(*ctxt).input).cur {
            break;
        }
        if (*ctxt).nameNr < depth {
            break;
        }
    }
    if !currentNode.is_null() && (*ctxt).record_info != 0 {
        node_info
            .end_pos = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                    as libc::c_ulong,
            );
        node_info.end_line = (*(*ctxt).input).line as libc::c_ulong;
        node_info.node = (*ctxt).node as *const _xmlNode;
        xmlParserAddNodeInfo(ctxt, &mut node_info);
    }
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        htmlAutoCloseOnEnd(ctxt);
    }
    if !currentNode.is_null() {
        xmlFree.expect("non-null function pointer")(currentNode as *mut libc::c_void);
    }
}
unsafe extern "C" fn htmlParserFinishElementParsing(mut ctxt: htmlParserCtxtPtr) {
    if !((*ctxt).node).is_null() && (*ctxt).record_info != 0 {
        (*(*ctxt).nodeInfo)
            .end_pos = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                    as libc::c_ulong,
            );
        (*(*ctxt).nodeInfo).end_line = (*(*ctxt).input).line as libc::c_ulong;
        let ref mut fresh134 = (*(*ctxt).nodeInfo).node;
        *fresh134 = (*ctxt).node as *const _xmlNode;
        xmlParserAddNodeInfo(ctxt, (*ctxt).nodeInfo);
        htmlNodeInfoPop(ctxt);
    }
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        htmlAutoCloseOnEnd(ctxt);
    }
}
unsafe extern "C" fn htmlParseElementInternal(mut ctxt: htmlParserCtxtPtr) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut info: *const htmlElemDesc = 0 as *const htmlElemDesc;
    let mut node_info: htmlParserNodeInfo = {
        let mut init = _xmlParserNodeInfo {
            node: 0 as *const _xmlNode,
            begin_pos: 0 as libc::c_int as libc::c_ulong,
            begin_line: 0 as libc::c_int as libc::c_ulong,
            end_pos: 0 as libc::c_int as libc::c_ulong,
            end_line: 0 as libc::c_int as libc::c_ulong,
        };
        init
    };
    let mut failed: libc::c_int = 0;
    if ctxt.is_null() || ((*ctxt).input).is_null() {
        htmlParseErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"htmlParseElementInternal: context error\n\0" as *const u8
                as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return;
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return;
    }
    if (*ctxt).record_info != 0 {
        node_info
            .begin_pos = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                    as libc::c_ulong,
            );
        node_info.begin_line = (*(*ctxt).input).line as libc::c_ulong;
    }
    failed = htmlParseStartTag(ctxt);
    name = (*ctxt).name;
    if failed == -(1 as libc::c_int) || name.is_null() {
        if *(*(*ctxt).input).cur as libc::c_int == '>' as i32 {
            xmlNextChar(ctxt);
        }
        return;
    }
    info = htmlTagLookup(name);
    if info.is_null() {
        htmlParseErr(
            ctxt,
            XML_HTML_UNKNOWN_TAG,
            b"Tag %s invalid\n\0" as *const u8 as *const libc::c_char,
            name,
            0 as *const xmlChar,
        );
    }
    if *(*(*ctxt).input).cur as libc::c_int == '/' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '>' as i32
    {
        let ref mut fresh135 = (*(*ctxt).input).cur;
        *fresh135 = (*fresh135).offset(2 as libc::c_int as isize);
        (*(*ctxt).input).col += 2 as libc::c_int;
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElement).is_some() {
            ((*(*ctxt).sax).endElement)
                .expect("non-null function pointer")((*ctxt).userData, name);
        }
        htmlnamePop(ctxt);
        return;
    }
    if *(*(*ctxt).input).cur as libc::c_int == '>' as i32 {
        xmlNextChar(ctxt);
    } else {
        htmlParseErr(
            ctxt,
            XML_ERR_GT_REQUIRED,
            b"Couldn't find end of Start Tag %s\n\0" as *const u8 as *const libc::c_char,
            name,
            0 as *const xmlChar,
        );
        if xmlStrEqual(name, (*ctxt).name) != 0 {
            nodePop(ctxt);
            htmlnamePop(ctxt);
        }
        if (*ctxt).record_info != 0 {
            htmlNodeInfoPush(ctxt, &mut node_info);
        }
        htmlParserFinishElementParsing(ctxt);
        return;
    }
    if !info.is_null() && (*info).empty as libc::c_int != 0 {
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElement).is_some() {
            ((*(*ctxt).sax).endElement)
                .expect("non-null function pointer")((*ctxt).userData, name);
        }
        htmlnamePop(ctxt);
        return;
    }
    if (*ctxt).record_info != 0 {
        htmlNodeInfoPush(ctxt, &mut node_info);
    }
}
unsafe extern "C" fn htmlParseContentInternal(mut ctxt: htmlParserCtxtPtr) {
    let mut currentNode: *mut xmlChar = 0 as *mut xmlChar;
    let mut depth: libc::c_int = 0;
    let mut name: *const xmlChar = 0 as *const xmlChar;
    currentNode = xmlStrdup((*ctxt).name);
    depth = (*ctxt).nameNr;
    loop {
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
            break;
        }
        if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '/' as i32
        {
            if htmlParseEndTag(ctxt) != 0
                && (!currentNode.is_null() || (*ctxt).nameNr == 0 as libc::c_int)
            {
                if !currentNode.is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(currentNode as *mut libc::c_void);
                }
                currentNode = xmlStrdup((*ctxt).name);
                depth = (*ctxt).nameNr;
            }
        } else {
            if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
                && (0x41 as libc::c_int
                    <= *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int
                    && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int <= 0x5a as libc::c_int
                    || 0x61 as libc::c_int
                        <= *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                            as libc::c_int
                        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                            as libc::c_int <= 0x7a as libc::c_int
                    || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int == '_' as i32
                    || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int == ':' as i32)
            {
                name = htmlParseHTMLName_nonInvasive(ctxt);
                if name.is_null() {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_NAME_REQUIRED,
                        b"htmlParseStartTag: invalid element name\n\0" as *const u8
                            as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    while *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int
                        && *(*(*ctxt).input).cur as libc::c_int != '>' as i32
                    {
                        xmlNextChar(ctxt);
                    }
                    htmlParserFinishElementParsing(ctxt);
                    if !currentNode.is_null() {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(currentNode as *mut libc::c_void);
                    }
                    currentNode = xmlStrdup((*ctxt).name);
                    depth = (*ctxt).nameNr;
                    continue;
                } else if !((*ctxt).name).is_null() {
                    if htmlCheckAutoClose(name, (*ctxt).name) == 1 as libc::c_int {
                        htmlAutoClose(ctxt, name);
                        continue;
                    }
                }
            }
            if (*ctxt).nameNr > 0 as libc::c_int && depth >= (*ctxt).nameNr
                && xmlStrEqual(currentNode, (*ctxt).name) == 0
            {
                htmlParserFinishElementParsing(ctxt);
                if !currentNode.is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(currentNode as *mut libc::c_void);
                }
                currentNode = xmlStrdup((*ctxt).name);
                depth = (*ctxt).nameNr;
            } else {
                if *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int
                    && (xmlStrEqual(
                        currentNode,
                        b"script\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    ) != 0
                        || xmlStrEqual(
                            currentNode,
                            b"style\0" as *const u8 as *const libc::c_char
                                as *mut xmlChar,
                        ) != 0)
                {
                    htmlParseScript(ctxt);
                } else if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
                        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                            as libc::c_int == '!' as i32
                    {
                    if ({
                        let mut __res: libc::c_int = 0;
                        if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                            > 1 as libc::c_int as libc::c_ulong
                        {
                            if 0 != 0 {
                                let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                    .offset(2 as libc::c_int as isize) as libc::c_int;
                                __res = (if __c < -(128 as libc::c_int)
                                    || __c > 255 as libc::c_int
                                {
                                    __c
                                } else {
                                    *(*__ctype_toupper_loc()).offset(__c as isize)
                                });
                            } else {
                                __res = toupper(
                                    *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                        as libc::c_int,
                                );
                            }
                        } else {
                            __res = *(*__ctype_toupper_loc())
                                .offset(
                                    *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                        as libc::c_int as isize,
                                );
                        }
                        __res
                    }) == 'D' as i32
                        && ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(3 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'O' as i32
                        && ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(4 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'C' as i32
                        && ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(5 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'T' as i32
                        && ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(6 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'Y' as i32
                        && ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(7 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'P' as i32
                        && ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(8 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'E' as i32
                    {
                        htmlParseErr(
                            ctxt,
                            XML_HTML_STRUCURE_ERROR,
                            b"Misplaced DOCTYPE declaration\n\0" as *const u8
                                as *const libc::c_char,
                            b"DOCTYPE\0" as *const u8 as *const libc::c_char
                                as *mut xmlChar,
                            0 as *const xmlChar,
                        );
                        htmlParseDocTypeDecl(ctxt);
                    } else if *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                            as libc::c_int == '-' as i32
                            && *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                as libc::c_int == '-' as i32
                        {
                        htmlParseComment(ctxt);
                    } else {
                        htmlSkipBogusComment(ctxt);
                    }
                } else if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
                        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                            as libc::c_int == '?' as i32
                    {
                    htmlParsePI(ctxt);
                } else if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
                        && (0x41 as libc::c_int
                            <= *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                as libc::c_int
                            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                as libc::c_int <= 0x5a as libc::c_int
                            || 0x61 as libc::c_int
                                <= *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                    as libc::c_int
                                && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                    as libc::c_int <= 0x7a as libc::c_int)
                    {
                    htmlParseElementInternal(ctxt);
                    if !currentNode.is_null() {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(currentNode as *mut libc::c_void);
                    }
                    currentNode = xmlStrdup((*ctxt).name);
                    depth = (*ctxt).nameNr;
                } else if *(*(*ctxt).input).cur as libc::c_int == '<' as i32 {
                    if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                        && ((*(*ctxt).sax).characters).is_some()
                    {
                        ((*(*ctxt).sax).characters)
                            .expect(
                                "non-null function pointer",
                            )(
                            (*ctxt).userData,
                            b"<\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                            1 as libc::c_int,
                        );
                    }
                    xmlNextChar(ctxt);
                } else if *(*(*ctxt).input).cur as libc::c_int == '&' as i32 {
                    htmlParseReference(ctxt);
                } else if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                    htmlAutoCloseOnEnd(ctxt);
                    break;
                } else {
                    htmlParseCharData(ctxt);
                }
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                }
            }
        }
    }
    if !currentNode.is_null() {
        xmlFree.expect("non-null function pointer")(currentNode as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn __htmlParseContent(mut ctxt: *mut libc::c_void) {
    if !ctxt.is_null() {
        htmlParseContentInternal(ctxt as htmlParserCtxtPtr);
    }
}
#[no_mangle]
pub unsafe extern "C" fn htmlParseDocument(mut ctxt: htmlParserCtxtPtr) -> libc::c_int {
    let mut start: [xmlChar; 4] = [0; 4];
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    xmlInitParser();
    htmlDefaultSAXHandlerInit();
    if ctxt.is_null() || ((*ctxt).input).is_null() {
        htmlParseErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"htmlParseDocument: context error\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return XML_ERR_INTERNAL_ERROR as libc::c_int;
    }
    (*ctxt).html = 1 as libc::c_int;
    (*ctxt).linenumbers = 1 as libc::c_int;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).setDocumentLocator).is_some() {
        ((*(*ctxt).sax).setDocumentLocator)
            .expect(
                "non-null function pointer",
            )((*ctxt).userData, __xmlDefaultSAXLocator());
    }
    if ((*ctxt).encoding).is_null()
        && ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long
            >= 4 as libc::c_int as libc::c_long
    {
        start[0 as libc::c_int
            as usize] = (if (*ctxt).token != 0 {
            -(1 as libc::c_int)
        } else {
            *(*(*ctxt).input).cur as libc::c_int
        }) as xmlChar;
        start[1 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize);
        start[2 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize);
        start[3 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize);
        enc = xmlDetectCharEncoding(
            &mut *start.as_mut_ptr().offset(0 as libc::c_int as isize),
            4 as libc::c_int,
        );
        if enc as libc::c_int != XML_CHAR_ENCODING_NONE as libc::c_int {
            xmlSwitchEncoding(ctxt, enc);
        }
    }
    htmlSkipBlankChars(ctxt);
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        htmlParseErr(
            ctxt,
            XML_ERR_DOCUMENT_EMPTY,
            b"Document is empty\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).startDocument).is_some()
        && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).startDocument)
            .expect("non-null function pointer")((*ctxt).userData);
    }
    while *(*(*ctxt).input).cur as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '!' as i32
        && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize) as libc::c_int
            == '-' as i32
        && *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize) as libc::c_int
            == '-' as i32
        || *(*(*ctxt).input).cur as libc::c_int == '<' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '?' as i32
    {
        htmlParseComment(ctxt);
        htmlParsePI(ctxt);
        htmlSkipBlankChars(ctxt);
    }
    if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '!' as i32
        && ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                        .offset(2 as libc::c_int as isize) as libc::c_int;
                    __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_toupper_loc()).offset(__c as isize)
                    });
                } else {
                    __res = toupper(
                        *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                            as libc::c_int,
                    );
                }
            } else {
                __res = *(*__ctype_toupper_loc())
                    .offset(
                        *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                            as libc::c_int as isize,
                    );
            }
            __res
        }) == 'D' as i32
        && ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                        .offset(3 as libc::c_int as isize) as libc::c_int;
                    __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_toupper_loc()).offset(__c as isize)
                    });
                } else {
                    __res = toupper(
                        *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                            as libc::c_int,
                    );
                }
            } else {
                __res = *(*__ctype_toupper_loc())
                    .offset(
                        *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                            as libc::c_int as isize,
                    );
            }
            __res
        }) == 'O' as i32
        && ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                        .offset(4 as libc::c_int as isize) as libc::c_int;
                    __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_toupper_loc()).offset(__c as isize)
                    });
                } else {
                    __res = toupper(
                        *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                            as libc::c_int,
                    );
                }
            } else {
                __res = *(*__ctype_toupper_loc())
                    .offset(
                        *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                            as libc::c_int as isize,
                    );
            }
            __res
        }) == 'C' as i32
        && ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                        .offset(5 as libc::c_int as isize) as libc::c_int;
                    __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_toupper_loc()).offset(__c as isize)
                    });
                } else {
                    __res = toupper(
                        *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                            as libc::c_int,
                    );
                }
            } else {
                __res = *(*__ctype_toupper_loc())
                    .offset(
                        *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                            as libc::c_int as isize,
                    );
            }
            __res
        }) == 'T' as i32
        && ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                        .offset(6 as libc::c_int as isize) as libc::c_int;
                    __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_toupper_loc()).offset(__c as isize)
                    });
                } else {
                    __res = toupper(
                        *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                            as libc::c_int,
                    );
                }
            } else {
                __res = *(*__ctype_toupper_loc())
                    .offset(
                        *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                            as libc::c_int as isize,
                    );
            }
            __res
        }) == 'Y' as i32
        && ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                        .offset(7 as libc::c_int as isize) as libc::c_int;
                    __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_toupper_loc()).offset(__c as isize)
                    });
                } else {
                    __res = toupper(
                        *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                            as libc::c_int,
                    );
                }
            } else {
                __res = *(*__ctype_toupper_loc())
                    .offset(
                        *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                            as libc::c_int as isize,
                    );
            }
            __res
        }) == 'P' as i32
        && ({
            let mut __res: libc::c_int = 0;
            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                > 1 as libc::c_int as libc::c_ulong
            {
                if 0 != 0 {
                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                        .offset(8 as libc::c_int as isize) as libc::c_int;
                    __res = (if __c < -(128 as libc::c_int) || __c > 255 as libc::c_int {
                        __c
                    } else {
                        *(*__ctype_toupper_loc()).offset(__c as isize)
                    });
                } else {
                    __res = toupper(
                        *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                            as libc::c_int,
                    );
                }
            } else {
                __res = *(*__ctype_toupper_loc())
                    .offset(
                        *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                            as libc::c_int as isize,
                    );
            }
            __res
        }) == 'E' as i32
    {
        htmlParseDocTypeDecl(ctxt);
    }
    htmlSkipBlankChars(ctxt);
    while *(*(*ctxt).input).cur as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '!' as i32
        && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize) as libc::c_int
            == '-' as i32
        && *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize) as libc::c_int
            == '-' as i32
        || *(*(*ctxt).input).cur as libc::c_int == '<' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '?' as i32
    {
        htmlParseComment(ctxt);
        htmlParsePI(ctxt);
        htmlSkipBlankChars(ctxt);
    }
    htmlParseContentInternal(ctxt);
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        htmlAutoCloseOnEnd(ctxt);
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some() {
        ((*(*ctxt).sax).endDocument)
            .expect("non-null function pointer")((*ctxt).userData);
    }
    if (*ctxt).options & HTML_PARSE_NODEFDTD as libc::c_int == 0
        && !((*ctxt).myDoc).is_null()
    {
        dtd = xmlGetIntSubset((*ctxt).myDoc as *const xmlDoc);
        if dtd.is_null() {
            let ref mut fresh136 = (*(*ctxt).myDoc).intSubset;
            *fresh136 = xmlCreateIntSubset(
                (*ctxt).myDoc,
                b"html\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                b"-//W3C//DTD HTML 4.0 Transitional//EN\0" as *const u8
                    as *const libc::c_char as *mut xmlChar,
                b"http://www.w3.org/TR/REC-html40/loose.dtd\0" as *const u8
                    as *const libc::c_char as *mut xmlChar,
            );
        }
    }
    if (*ctxt).wellFormed == 0 {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn htmlInitParserCtxt(mut ctxt: htmlParserCtxtPtr) -> libc::c_int {
    let mut sax: *mut htmlSAXHandler = 0 as *mut htmlSAXHandler;
    if ctxt.is_null() {
        return -(1 as libc::c_int);
    }
    memset(
        ctxt as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<htmlParserCtxt>() as libc::c_ulong,
    );
    let ref mut fresh137 = (*ctxt).dict;
    *fresh137 = xmlDictCreate();
    if ((*ctxt).dict).is_null() {
        htmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"htmlInitParserCtxt: out of memory\n\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    sax = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<htmlSAXHandler>() as libc::c_ulong)
        as *mut htmlSAXHandler;
    if sax.is_null() {
        htmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"htmlInitParserCtxt: out of memory\n\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    } else {
        memset(
            sax as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<htmlSAXHandler>() as libc::c_ulong,
        );
    }
    let ref mut fresh138 = (*ctxt).inputTab;
    *fresh138 = xmlMalloc
        .expect(
            "non-null function pointer",
        )(
        (5 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<htmlParserInputPtr>() as libc::c_ulong),
    ) as *mut htmlParserInputPtr;
    if ((*ctxt).inputTab).is_null() {
        htmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"htmlInitParserCtxt: out of memory\n\0" as *const u8 as *const libc::c_char,
        );
        (*ctxt).inputNr = 0 as libc::c_int;
        (*ctxt).inputMax = 0 as libc::c_int;
        let ref mut fresh139 = (*ctxt).input;
        *fresh139 = 0 as xmlParserInputPtr;
        return -(1 as libc::c_int);
    }
    (*ctxt).inputNr = 0 as libc::c_int;
    (*ctxt).inputMax = 5 as libc::c_int;
    let ref mut fresh140 = (*ctxt).input;
    *fresh140 = 0 as xmlParserInputPtr;
    let ref mut fresh141 = (*ctxt).version;
    *fresh141 = 0 as *const xmlChar;
    let ref mut fresh142 = (*ctxt).encoding;
    *fresh142 = 0 as *const xmlChar;
    (*ctxt).standalone = -(1 as libc::c_int);
    (*ctxt).instate = XML_PARSER_START;
    let ref mut fresh143 = (*ctxt).nodeTab;
    *fresh143 = xmlMalloc
        .expect(
            "non-null function pointer",
        )(
        (10 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<htmlNodePtr>() as libc::c_ulong),
    ) as *mut htmlNodePtr;
    if ((*ctxt).nodeTab).is_null() {
        htmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"htmlInitParserCtxt: out of memory\n\0" as *const u8 as *const libc::c_char,
        );
        (*ctxt).nodeNr = 0 as libc::c_int;
        (*ctxt).nodeMax = 0 as libc::c_int;
        let ref mut fresh144 = (*ctxt).node;
        *fresh144 = 0 as xmlNodePtr;
        (*ctxt).inputNr = 0 as libc::c_int;
        (*ctxt).inputMax = 0 as libc::c_int;
        let ref mut fresh145 = (*ctxt).input;
        *fresh145 = 0 as xmlParserInputPtr;
        return -(1 as libc::c_int);
    }
    (*ctxt).nodeNr = 0 as libc::c_int;
    (*ctxt).nodeMax = 10 as libc::c_int;
    let ref mut fresh146 = (*ctxt).node;
    *fresh146 = 0 as xmlNodePtr;
    let ref mut fresh147 = (*ctxt).nameTab;
    *fresh147 = xmlMalloc
        .expect(
            "non-null function pointer",
        )(
        (10 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as libc::c_ulong),
    ) as *mut *const xmlChar;
    if ((*ctxt).nameTab).is_null() {
        htmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"htmlInitParserCtxt: out of memory\n\0" as *const u8 as *const libc::c_char,
        );
        (*ctxt).nameNr = 0 as libc::c_int;
        (*ctxt).nameMax = 0 as libc::c_int;
        let ref mut fresh148 = (*ctxt).name;
        *fresh148 = 0 as *const xmlChar;
        (*ctxt).nodeNr = 0 as libc::c_int;
        (*ctxt).nodeMax = 0 as libc::c_int;
        let ref mut fresh149 = (*ctxt).node;
        *fresh149 = 0 as xmlNodePtr;
        (*ctxt).inputNr = 0 as libc::c_int;
        (*ctxt).inputMax = 0 as libc::c_int;
        let ref mut fresh150 = (*ctxt).input;
        *fresh150 = 0 as xmlParserInputPtr;
        return -(1 as libc::c_int);
    }
    (*ctxt).nameNr = 0 as libc::c_int;
    (*ctxt).nameMax = 10 as libc::c_int;
    let ref mut fresh151 = (*ctxt).name;
    *fresh151 = 0 as *const xmlChar;
    let ref mut fresh152 = (*ctxt).nodeInfoTab;
    *fresh152 = 0 as *mut xmlParserNodeInfo;
    (*ctxt).nodeInfoNr = 0 as libc::c_int;
    (*ctxt).nodeInfoMax = 0 as libc::c_int;
    if sax.is_null() {
        let ref mut fresh153 = (*ctxt).sax;
        *fresh153 = __htmlDefaultSAXHandler() as xmlSAXHandlerPtr;
    } else {
        let ref mut fresh154 = (*ctxt).sax;
        *fresh154 = sax;
        memcpy(
            sax as *mut libc::c_void,
            __htmlDefaultSAXHandler() as *const libc::c_void,
            ::std::mem::size_of::<xmlSAXHandlerV1>() as libc::c_ulong,
        );
    }
    let ref mut fresh155 = (*ctxt).userData;
    *fresh155 = ctxt as *mut libc::c_void;
    let ref mut fresh156 = (*ctxt).myDoc;
    *fresh156 = 0 as xmlDocPtr;
    (*ctxt).wellFormed = 1 as libc::c_int;
    (*ctxt).replaceEntities = 0 as libc::c_int;
    (*ctxt).linenumbers = *__xmlLineNumbersDefaultValue();
    (*ctxt).keepBlanks = *__xmlKeepBlanksDefaultValue();
    (*ctxt).html = 1 as libc::c_int;
    (*ctxt).vctxt.flags = (1 as libc::c_uint) << 1 as libc::c_int;
    let ref mut fresh157 = (*ctxt).vctxt.userData;
    *fresh157 = ctxt as *mut libc::c_void;
    let ref mut fresh158 = (*ctxt).vctxt.error;
    *fresh158 = Some(
        xmlParserValidityError
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    );
    let ref mut fresh159 = (*ctxt).vctxt.warning;
    *fresh159 = Some(
        xmlParserValidityWarning
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    );
    (*ctxt).record_info = 0 as libc::c_int;
    (*ctxt).validate = 0 as libc::c_int;
    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
    let ref mut fresh160 = (*ctxt).catalogs;
    *fresh160 = 0 as *mut libc::c_void;
    xmlInitNodeInfoSeq(&mut (*ctxt).node_seq);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn htmlFreeParserCtxt(mut ctxt: htmlParserCtxtPtr) {
    xmlFreeParserCtxt(ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn htmlNewParserCtxt() -> htmlParserCtxtPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    ctxt = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlParserCtxt>() as libc::c_ulong) as xmlParserCtxtPtr;
    if ctxt.is_null() {
        htmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"NewParserCtxt: out of memory\n\0" as *const u8 as *const libc::c_char,
        );
        return 0 as htmlParserCtxtPtr;
    }
    memset(
        ctxt as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlParserCtxt>() as libc::c_ulong,
    );
    if htmlInitParserCtxt(ctxt) < 0 as libc::c_int {
        htmlFreeParserCtxt(ctxt);
        return 0 as htmlParserCtxtPtr;
    }
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn htmlCreateMemoryParserCtxt(
    mut buffer: *const libc::c_char,
    mut size: libc::c_int,
) -> htmlParserCtxtPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if buffer.is_null() {
        return 0 as htmlParserCtxtPtr;
    }
    if size <= 0 as libc::c_int {
        return 0 as htmlParserCtxtPtr;
    }
    ctxt = htmlNewParserCtxt();
    if ctxt.is_null() {
        return 0 as htmlParserCtxtPtr;
    }
    buf = xmlParserInputBufferCreateMem(buffer, size, XML_CHAR_ENCODING_NONE);
    if buf.is_null() {
        return 0 as htmlParserCtxtPtr;
    }
    input = xmlNewInputStream(ctxt);
    if input.is_null() {
        xmlFreeParserInputBuffer(buf);
        xmlFreeParserCtxt(ctxt);
        return 0 as htmlParserCtxtPtr;
    }
    let ref mut fresh161 = (*input).filename;
    *fresh161 = 0 as *const libc::c_char;
    let ref mut fresh162 = (*input).buf;
    *fresh162 = buf;
    xmlBufResetInput((*buf).buffer, input);
    inputPush(ctxt, input);
    return ctxt;
}
unsafe extern "C" fn htmlCreateDocParserCtxt(
    mut cur: *const xmlChar,
    mut encoding: *const libc::c_char,
) -> htmlParserCtxtPtr {
    let mut len: libc::c_int = 0;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    if cur.is_null() {
        return 0 as htmlParserCtxtPtr;
    }
    len = xmlStrlen(cur);
    ctxt = htmlCreateMemoryParserCtxt(cur as *mut libc::c_char, len);
    if ctxt.is_null() {
        return 0 as htmlParserCtxtPtr;
    }
    if !encoding.is_null() {
        let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
        let mut handler: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
        if !((*(*ctxt).input).encoding).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*(*ctxt).input).encoding as *mut xmlChar as *mut libc::c_void);
        }
        let ref mut fresh163 = (*(*ctxt).input).encoding;
        *fresh163 = xmlStrdup(encoding as *const xmlChar);
        enc = xmlParseCharEncoding(encoding);
        if enc as libc::c_int != XML_CHAR_ENCODING_ERROR as libc::c_int {
            xmlSwitchEncoding(ctxt, enc);
            if (*ctxt).errNo == XML_ERR_UNSUPPORTED_ENCODING as libc::c_int {
                htmlParseErr(
                    ctxt,
                    XML_ERR_UNSUPPORTED_ENCODING,
                    b"Unsupported encoding %s\n\0" as *const u8 as *const libc::c_char,
                    encoding as *const xmlChar,
                    0 as *const xmlChar,
                );
            }
        } else {
            handler = xmlFindCharEncodingHandler(encoding);
            if !handler.is_null() {
                xmlSwitchToEncoding(ctxt, handler);
            } else {
                htmlParseErr(
                    ctxt,
                    XML_ERR_UNSUPPORTED_ENCODING,
                    b"Unsupported encoding %s\n\0" as *const u8 as *const libc::c_char,
                    encoding as *const xmlChar,
                    0 as *const xmlChar,
                );
            }
        }
    }
    return ctxt;
}
unsafe extern "C" fn htmlParseLookupSequence(
    mut ctxt: htmlParserCtxtPtr,
    mut first: xmlChar,
    mut next: xmlChar,
    mut third: xmlChar,
    mut ignoreattrval: libc::c_int,
) -> libc::c_int {
    let mut base: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut in_0: htmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: *const xmlChar = 0 as *const xmlChar;
    let mut invalue: libc::c_int = 0 as libc::c_int;
    let mut valdellim: libc::c_char = 0 as libc::c_int as libc::c_char;
    in_0 = (*ctxt).input;
    if in_0.is_null() {
        return -(1 as libc::c_int);
    }
    base = ((*in_0).cur).offset_from((*in_0).base) as libc::c_long as libc::c_int;
    if base < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if (*ctxt).checkIndex > base as libc::c_long {
        base = (*ctxt).checkIndex as libc::c_int;
        invalue = if (*ctxt).hasPErefs & 1 as libc::c_int != 0 {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        };
    }
    if ((*in_0).buf).is_null() {
        buf = (*in_0).base;
        len = (*in_0).length;
    } else {
        buf = xmlBufContent((*(*in_0).buf).buffer as *const xmlBuf);
        len = xmlBufUse((*(*in_0).buf).buffer) as libc::c_int;
    }
    if third != 0 {
        len -= 2 as libc::c_int;
    } else if next != 0 {
        len -= 1;
    }
    let mut current_block_25: u64;
    while base < len {
        if ignoreattrval != 0 {
            if *buf.offset(base as isize) as libc::c_int == '"' as i32
                || *buf.offset(base as isize) as libc::c_int == '\'' as i32
            {
                if invalue != 0 {
                    if *buf.offset(base as isize) as libc::c_int
                        == valdellim as libc::c_int
                    {
                        invalue = 0 as libc::c_int;
                        current_block_25 = 2668756484064249700;
                    } else {
                        current_block_25 = 18153031941552419006;
                    }
                } else {
                    valdellim = *buf.offset(base as isize) as libc::c_char;
                    invalue = 1 as libc::c_int;
                    current_block_25 = 2668756484064249700;
                }
            } else if invalue != 0 {
                current_block_25 = 2668756484064249700;
            } else {
                current_block_25 = 18153031941552419006;
            }
        } else {
            current_block_25 = 18153031941552419006;
        }
        match current_block_25 {
            18153031941552419006 => {
                if *buf.offset(base as isize) as libc::c_int == first as libc::c_int {
                    if third as libc::c_int != 0 as libc::c_int {
                        if *buf.offset((base + 1 as libc::c_int) as isize) as libc::c_int
                            != next as libc::c_int
                            || *buf.offset((base + 2 as libc::c_int) as isize)
                                as libc::c_int != third as libc::c_int
                        {
                            current_block_25 = 2668756484064249700;
                        } else {
                            current_block_25 = 3934796541983872331;
                        }
                    } else if next as libc::c_int != 0 as libc::c_int {
                        if *buf.offset((base + 1 as libc::c_int) as isize) as libc::c_int
                            != next as libc::c_int
                        {
                            current_block_25 = 2668756484064249700;
                        } else {
                            current_block_25 = 3934796541983872331;
                        }
                    } else {
                        current_block_25 = 3934796541983872331;
                    }
                    match current_block_25 {
                        2668756484064249700 => {}
                        _ => {
                            (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                            return (base as libc::c_long
                                - ((*in_0).cur).offset_from((*in_0).base) as libc::c_long)
                                as libc::c_int;
                        }
                    }
                }
            }
            _ => {}
        }
        base += 1;
    }
    (*ctxt).checkIndex = base as libc::c_long;
    if invalue != 0 {
        (*ctxt).hasPErefs |= 1 as libc::c_int;
    } else {
        (*ctxt).hasPErefs &= !(1 as libc::c_int);
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn htmlParseLookupCommentEnd(
    mut ctxt: htmlParserCtxtPtr,
) -> libc::c_int {
    let mut mark: libc::c_int = 0 as libc::c_int;
    let mut cur: libc::c_int = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
        as libc::c_long as libc::c_int;
    while mark >= 0 as libc::c_int {
        mark = htmlParseLookupSequence(
            ctxt,
            '-' as i32 as xmlChar,
            '-' as i32 as xmlChar,
            0 as libc::c_int as xmlChar,
            0 as libc::c_int,
        );
        if mark < 0 as libc::c_int
            || *((*(*ctxt).input).cur).offset((mark + 2 as libc::c_int) as isize)
                as libc::c_int == '>' as i32
            || *((*(*ctxt).input).cur).offset((mark + 2 as libc::c_int) as isize)
                as libc::c_int == '!' as i32
                && *((*(*ctxt).input).cur).offset((mark + 3 as libc::c_int) as isize)
                    as libc::c_int == '>' as i32
        {
            return mark;
        }
        (*ctxt).checkIndex = (cur + mark + 1 as libc::c_int) as libc::c_long;
    }
    return mark;
}
unsafe extern "C" fn htmlParseTryOrFinish(
    mut ctxt: htmlParserCtxtPtr,
    mut terminate: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut in_0: htmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut avail: ptrdiff_t = 0 as libc::c_int as ptrdiff_t;
    let mut cur: xmlChar = 0;
    let mut next: xmlChar = 0;
    let mut node_info: htmlParserNodeInfo = htmlParserNodeInfo {
        node: 0 as *const _xmlNode,
        begin_pos: 0,
        begin_line: 0,
        end_pos: 0,
        end_line: 0,
    };
    loop {
        in_0 = (*ctxt).input;
        if in_0.is_null() {
            break;
        }
        if ((*in_0).buf).is_null() {
            avail = (*in_0).length as libc::c_long
                - ((*in_0).cur).offset_from((*in_0).base) as libc::c_long;
        } else {
            avail = xmlBufUse((*(*in_0).buf).buffer) as ptrdiff_t
                - ((*in_0).cur).offset_from((*in_0).base) as libc::c_long;
        }
        if avail == 0 as libc::c_int as libc::c_long && terminate != 0 {
            htmlAutoCloseOnEnd(ctxt);
            if (*ctxt).nameNr == 0 as libc::c_int
                && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
            {
                (*ctxt).instate = XML_PARSER_EOF;
                if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some() {
                    ((*(*ctxt).sax).endDocument)
                        .expect("non-null function pointer")((*ctxt).userData);
                }
            }
        }
        if avail < 1 as libc::c_int as libc::c_long {
            break;
        }
        cur = *((*in_0).cur).offset(0 as libc::c_int as isize);
        if cur as libc::c_int == 0 as libc::c_int {
            let ref mut fresh164 = (*(*ctxt).input).cur;
            *fresh164 = (*fresh164).offset(1 as libc::c_int as isize);
            (*(*ctxt).input).col += 1 as libc::c_int;
        } else {
            match (*ctxt).instate as libc::c_int {
                -1 => {
                    break;
                }
                0 => {
                    cur = *((*in_0).cur).offset(0 as libc::c_int as isize);
                    if cur as libc::c_int == 0x20 as libc::c_int
                        || 0x9 as libc::c_int <= cur as libc::c_int
                            && cur as libc::c_int <= 0xa as libc::c_int
                        || cur as libc::c_int == 0xd as libc::c_int
                    {
                        htmlSkipBlankChars(ctxt);
                        if ((*in_0).buf).is_null() {
                            avail = (*in_0).length as libc::c_long
                                - ((*in_0).cur).offset_from((*in_0).base) as libc::c_long;
                        } else {
                            avail = xmlBufUse((*(*in_0).buf).buffer) as ptrdiff_t
                                - ((*in_0).cur).offset_from((*in_0).base) as libc::c_long;
                        }
                    }
                    if !((*ctxt).sax).is_null()
                        && ((*(*ctxt).sax).setDocumentLocator).is_some()
                    {
                        ((*(*ctxt).sax).setDocumentLocator)
                            .expect(
                                "non-null function pointer",
                            )((*ctxt).userData, __xmlDefaultSAXLocator());
                    }
                    if !((*ctxt).sax).is_null()
                        && ((*(*ctxt).sax).startDocument).is_some()
                        && (*ctxt).disableSAX == 0
                    {
                        ((*(*ctxt).sax).startDocument)
                            .expect("non-null function pointer")((*ctxt).userData);
                    }
                    cur = *((*in_0).cur).offset(0 as libc::c_int as isize);
                    next = *((*in_0).cur).offset(1 as libc::c_int as isize);
                    if cur as libc::c_int == '<' as i32
                        && next as libc::c_int == '!' as i32
                        && ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(2 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'D' as i32
                        && ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(3 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'O' as i32
                        && ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(4 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'C' as i32
                        && ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(5 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'T' as i32
                        && ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(6 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'Y' as i32
                        && ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(7 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'P' as i32
                        && ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(8 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'E' as i32
                    {
                        if terminate == 0
                            && htmlParseLookupSequence(
                                ctxt,
                                '>' as i32 as xmlChar,
                                0 as libc::c_int as xmlChar,
                                0 as libc::c_int as xmlChar,
                                1 as libc::c_int,
                            ) < 0 as libc::c_int
                        {
                            break;
                        }
                        htmlParseDocTypeDecl(ctxt);
                        (*ctxt).instate = XML_PARSER_PROLOG;
                    } else {
                        (*ctxt).instate = XML_PARSER_MISC;
                    }
                }
                1 => {
                    htmlSkipBlankChars(ctxt);
                    if ((*in_0).buf).is_null() {
                        avail = (*in_0).length as libc::c_long
                            - ((*in_0).cur).offset_from((*in_0).base) as libc::c_long;
                    } else {
                        avail = xmlBufUse((*(*in_0).buf).buffer) as ptrdiff_t
                            - ((*in_0).cur).offset_from((*in_0).base) as libc::c_long;
                    }
                    if avail < 1 as libc::c_int as libc::c_long {
                        break;
                    }
                    if avail < 2 as libc::c_int as libc::c_long {
                        if terminate == 0 {
                            break;
                        }
                        next = ' ' as i32 as xmlChar;
                    } else {
                        next = *((*in_0).cur).offset(1 as libc::c_int as isize);
                    }
                    cur = *((*in_0).cur).offset(0 as libc::c_int as isize);
                    if cur as libc::c_int == '<' as i32
                        && next as libc::c_int == '!' as i32
                        && *((*in_0).cur).offset(2 as libc::c_int as isize)
                            as libc::c_int == '-' as i32
                        && *((*in_0).cur).offset(3 as libc::c_int as isize)
                            as libc::c_int == '-' as i32
                    {
                        if terminate == 0
                            && htmlParseLookupCommentEnd(ctxt) < 0 as libc::c_int
                        {
                            break;
                        }
                        htmlParseComment(ctxt);
                        (*ctxt).instate = XML_PARSER_MISC;
                    } else if cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '?' as i32
                        {
                        if terminate == 0
                            && htmlParseLookupSequence(
                                ctxt,
                                '>' as i32 as xmlChar,
                                0 as libc::c_int as xmlChar,
                                0 as libc::c_int as xmlChar,
                                0 as libc::c_int,
                            ) < 0 as libc::c_int
                        {
                            break;
                        }
                        htmlParsePI(ctxt);
                        (*ctxt).instate = XML_PARSER_MISC;
                    } else if cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '!' as i32
                            && ({
                                let mut __res: libc::c_int = 0;
                                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                    > 1 as libc::c_int as libc::c_ulong
                                {
                                    if 0 != 0 {
                                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                            .offset(2 as libc::c_int as isize) as libc::c_int;
                                        __res = (if __c < -(128 as libc::c_int)
                                            || __c > 255 as libc::c_int
                                        {
                                            __c
                                        } else {
                                            *(*__ctype_toupper_loc()).offset(__c as isize)
                                        });
                                    } else {
                                        __res = toupper(
                                            *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                                as libc::c_int,
                                        );
                                    }
                                } else {
                                    __res = *(*__ctype_toupper_loc())
                                        .offset(
                                            *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                                as libc::c_int as isize,
                                        );
                                }
                                __res
                            }) == 'D' as i32
                            && ({
                                let mut __res: libc::c_int = 0;
                                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                    > 1 as libc::c_int as libc::c_ulong
                                {
                                    if 0 != 0 {
                                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                            .offset(3 as libc::c_int as isize) as libc::c_int;
                                        __res = (if __c < -(128 as libc::c_int)
                                            || __c > 255 as libc::c_int
                                        {
                                            __c
                                        } else {
                                            *(*__ctype_toupper_loc()).offset(__c as isize)
                                        });
                                    } else {
                                        __res = toupper(
                                            *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                                as libc::c_int,
                                        );
                                    }
                                } else {
                                    __res = *(*__ctype_toupper_loc())
                                        .offset(
                                            *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                                as libc::c_int as isize,
                                        );
                                }
                                __res
                            }) == 'O' as i32
                            && ({
                                let mut __res: libc::c_int = 0;
                                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                    > 1 as libc::c_int as libc::c_ulong
                                {
                                    if 0 != 0 {
                                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                            .offset(4 as libc::c_int as isize) as libc::c_int;
                                        __res = (if __c < -(128 as libc::c_int)
                                            || __c > 255 as libc::c_int
                                        {
                                            __c
                                        } else {
                                            *(*__ctype_toupper_loc()).offset(__c as isize)
                                        });
                                    } else {
                                        __res = toupper(
                                            *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                                as libc::c_int,
                                        );
                                    }
                                } else {
                                    __res = *(*__ctype_toupper_loc())
                                        .offset(
                                            *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                                as libc::c_int as isize,
                                        );
                                }
                                __res
                            }) == 'C' as i32
                            && ({
                                let mut __res: libc::c_int = 0;
                                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                    > 1 as libc::c_int as libc::c_ulong
                                {
                                    if 0 != 0 {
                                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                            .offset(5 as libc::c_int as isize) as libc::c_int;
                                        __res = (if __c < -(128 as libc::c_int)
                                            || __c > 255 as libc::c_int
                                        {
                                            __c
                                        } else {
                                            *(*__ctype_toupper_loc()).offset(__c as isize)
                                        });
                                    } else {
                                        __res = toupper(
                                            *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                                as libc::c_int,
                                        );
                                    }
                                } else {
                                    __res = *(*__ctype_toupper_loc())
                                        .offset(
                                            *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                                as libc::c_int as isize,
                                        );
                                }
                                __res
                            }) == 'T' as i32
                            && ({
                                let mut __res: libc::c_int = 0;
                                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                    > 1 as libc::c_int as libc::c_ulong
                                {
                                    if 0 != 0 {
                                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                            .offset(6 as libc::c_int as isize) as libc::c_int;
                                        __res = (if __c < -(128 as libc::c_int)
                                            || __c > 255 as libc::c_int
                                        {
                                            __c
                                        } else {
                                            *(*__ctype_toupper_loc()).offset(__c as isize)
                                        });
                                    } else {
                                        __res = toupper(
                                            *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                                                as libc::c_int,
                                        );
                                    }
                                } else {
                                    __res = *(*__ctype_toupper_loc())
                                        .offset(
                                            *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                                                as libc::c_int as isize,
                                        );
                                }
                                __res
                            }) == 'Y' as i32
                            && ({
                                let mut __res: libc::c_int = 0;
                                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                    > 1 as libc::c_int as libc::c_ulong
                                {
                                    if 0 != 0 {
                                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                            .offset(7 as libc::c_int as isize) as libc::c_int;
                                        __res = (if __c < -(128 as libc::c_int)
                                            || __c > 255 as libc::c_int
                                        {
                                            __c
                                        } else {
                                            *(*__ctype_toupper_loc()).offset(__c as isize)
                                        });
                                    } else {
                                        __res = toupper(
                                            *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                                                as libc::c_int,
                                        );
                                    }
                                } else {
                                    __res = *(*__ctype_toupper_loc())
                                        .offset(
                                            *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                                                as libc::c_int as isize,
                                        );
                                }
                                __res
                            }) == 'P' as i32
                            && ({
                                let mut __res: libc::c_int = 0;
                                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                    > 1 as libc::c_int as libc::c_ulong
                                {
                                    if 0 != 0 {
                                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                            .offset(8 as libc::c_int as isize) as libc::c_int;
                                        __res = (if __c < -(128 as libc::c_int)
                                            || __c > 255 as libc::c_int
                                        {
                                            __c
                                        } else {
                                            *(*__ctype_toupper_loc()).offset(__c as isize)
                                        });
                                    } else {
                                        __res = toupper(
                                            *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                                                as libc::c_int,
                                        );
                                    }
                                } else {
                                    __res = *(*__ctype_toupper_loc())
                                        .offset(
                                            *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                                                as libc::c_int as isize,
                                        );
                                }
                                __res
                            }) == 'E' as i32
                        {
                        if terminate == 0
                            && htmlParseLookupSequence(
                                ctxt,
                                '>' as i32 as xmlChar,
                                0 as libc::c_int as xmlChar,
                                0 as libc::c_int as xmlChar,
                                1 as libc::c_int,
                            ) < 0 as libc::c_int
                        {
                            break;
                        }
                        htmlParseDocTypeDecl(ctxt);
                        (*ctxt).instate = XML_PARSER_PROLOG;
                    } else {
                        if cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '!' as i32
                            && avail < 9 as libc::c_int as libc::c_long
                        {
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_CONTENT;
                    }
                }
                4 => {
                    htmlSkipBlankChars(ctxt);
                    if ((*in_0).buf).is_null() {
                        avail = (*in_0).length as libc::c_long
                            - ((*in_0).cur).offset_from((*in_0).base) as libc::c_long;
                    } else {
                        avail = xmlBufUse((*(*in_0).buf).buffer) as ptrdiff_t
                            - ((*in_0).cur).offset_from((*in_0).base) as libc::c_long;
                    }
                    if avail < 2 as libc::c_int as libc::c_long {
                        break;
                    }
                    cur = *((*in_0).cur).offset(0 as libc::c_int as isize);
                    next = *((*in_0).cur).offset(1 as libc::c_int as isize);
                    if cur as libc::c_int == '<' as i32
                        && next as libc::c_int == '!' as i32
                        && *((*in_0).cur).offset(2 as libc::c_int as isize)
                            as libc::c_int == '-' as i32
                        && *((*in_0).cur).offset(3 as libc::c_int as isize)
                            as libc::c_int == '-' as i32
                    {
                        if terminate == 0
                            && htmlParseLookupCommentEnd(ctxt) < 0 as libc::c_int
                        {
                            break;
                        }
                        htmlParseComment(ctxt);
                        (*ctxt).instate = XML_PARSER_PROLOG;
                    } else if cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '?' as i32
                        {
                        if terminate == 0
                            && htmlParseLookupSequence(
                                ctxt,
                                '>' as i32 as xmlChar,
                                0 as libc::c_int as xmlChar,
                                0 as libc::c_int as xmlChar,
                                0 as libc::c_int,
                            ) < 0 as libc::c_int
                        {
                            break;
                        }
                        htmlParsePI(ctxt);
                        (*ctxt).instate = XML_PARSER_PROLOG;
                    } else {
                        if cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '!' as i32
                            && avail < 4 as libc::c_int as libc::c_long
                        {
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_CONTENT;
                    }
                }
                14 => {
                    if ((*in_0).buf).is_null() {
                        avail = (*in_0).length as libc::c_long
                            - ((*in_0).cur).offset_from((*in_0).base) as libc::c_long;
                    } else {
                        avail = xmlBufUse((*(*in_0).buf).buffer) as ptrdiff_t
                            - ((*in_0).cur).offset_from((*in_0).base) as libc::c_long;
                    }
                    if avail < 1 as libc::c_int as libc::c_long {
                        break;
                    }
                    cur = *((*in_0).cur).offset(0 as libc::c_int as isize);
                    if cur as libc::c_int == 0x20 as libc::c_int
                        || 0x9 as libc::c_int <= cur as libc::c_int
                            && cur as libc::c_int <= 0xa as libc::c_int
                        || cur as libc::c_int == 0xd as libc::c_int
                    {
                        htmlParseCharData(ctxt);
                        break;
                    } else {
                        if avail < 2 as libc::c_int as libc::c_long {
                            break;
                        }
                        next = *((*in_0).cur).offset(1 as libc::c_int as isize);
                        if cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '!' as i32
                            && *((*in_0).cur).offset(2 as libc::c_int as isize)
                                as libc::c_int == '-' as i32
                            && *((*in_0).cur).offset(3 as libc::c_int as isize)
                                as libc::c_int == '-' as i32
                        {
                            if terminate == 0
                                && htmlParseLookupCommentEnd(ctxt) < 0 as libc::c_int
                            {
                                break;
                            }
                            htmlParseComment(ctxt);
                            (*ctxt).instate = XML_PARSER_EPILOG;
                        } else if cur as libc::c_int == '<' as i32
                                && next as libc::c_int == '?' as i32
                            {
                            if terminate == 0
                                && htmlParseLookupSequence(
                                    ctxt,
                                    '>' as i32 as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int,
                                ) < 0 as libc::c_int
                            {
                                break;
                            }
                            htmlParsePI(ctxt);
                            (*ctxt).instate = XML_PARSER_EPILOG;
                        } else {
                            if cur as libc::c_int == '<' as i32
                                && next as libc::c_int == '!' as i32
                                && avail < 4 as libc::c_int as libc::c_long
                            {
                                break;
                            }
                            (*ctxt).errNo = XML_ERR_DOCUMENT_END as libc::c_int;
                            (*ctxt).wellFormed = 0 as libc::c_int;
                            (*ctxt).instate = XML_PARSER_EOF;
                            if !((*ctxt).sax).is_null()
                                && ((*(*ctxt).sax).endDocument).is_some()
                            {
                                ((*(*ctxt).sax).endDocument)
                                    .expect("non-null function pointer")((*ctxt).userData);
                            }
                            break;
                        }
                    }
                }
                6 => {
                    let mut name: *const xmlChar = 0 as *const xmlChar;
                    let mut failed: libc::c_int = 0;
                    let mut info: *const htmlElemDesc = 0 as *const htmlElemDesc;
                    if avail < 1 as libc::c_int as libc::c_long {
                        break;
                    }
                    if avail < 2 as libc::c_int as libc::c_long {
                        if terminate == 0 {
                            break;
                        }
                        next = ' ' as i32 as xmlChar;
                    } else {
                        next = *((*in_0).cur).offset(1 as libc::c_int as isize);
                    }
                    cur = *((*in_0).cur).offset(0 as libc::c_int as isize);
                    if cur as libc::c_int != '<' as i32 {
                        (*ctxt).instate = XML_PARSER_CONTENT;
                    } else if next as libc::c_int == '/' as i32 {
                        (*ctxt).instate = XML_PARSER_END_TAG;
                        (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                    } else {
                        if terminate == 0
                            && htmlParseLookupSequence(
                                ctxt,
                                '>' as i32 as xmlChar,
                                0 as libc::c_int as xmlChar,
                                0 as libc::c_int as xmlChar,
                                1 as libc::c_int,
                            ) < 0 as libc::c_int
                        {
                            break;
                        }
                        if (*ctxt).record_info != 0 {
                            node_info
                                .begin_pos = ((*(*ctxt).input).consumed)
                                .wrapping_add(
                                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                        as libc::c_long as libc::c_ulong,
                                );
                            node_info
                                .begin_line = (*(*ctxt).input).line as libc::c_ulong;
                        }
                        failed = htmlParseStartTag(ctxt);
                        name = (*ctxt).name;
                        if failed == -(1 as libc::c_int) || name.is_null() {
                            if *(*(*ctxt).input).cur as libc::c_int == '>' as i32 {
                                xmlNextChar(ctxt);
                            }
                        } else {
                            info = htmlTagLookup(name);
                            if info.is_null() {
                                htmlParseErr(
                                    ctxt,
                                    XML_HTML_UNKNOWN_TAG,
                                    b"Tag %s invalid\n\0" as *const u8 as *const libc::c_char,
                                    name,
                                    0 as *const xmlChar,
                                );
                            }
                            if *(*(*ctxt).input).cur as libc::c_int == '/' as i32
                                && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                    as libc::c_int == '>' as i32
                            {
                                let ref mut fresh165 = (*(*ctxt).input).cur;
                                *fresh165 = (*fresh165).offset(2 as libc::c_int as isize);
                                (*(*ctxt).input).col += 2 as libc::c_int;
                                if !((*ctxt).sax).is_null()
                                    && ((*(*ctxt).sax).endElement).is_some()
                                {
                                    ((*(*ctxt).sax).endElement)
                                        .expect(
                                            "non-null function pointer",
                                        )((*ctxt).userData, name);
                                }
                                htmlnamePop(ctxt);
                                (*ctxt).instate = XML_PARSER_CONTENT;
                            } else if *(*(*ctxt).input).cur as libc::c_int == '>' as i32
                                {
                                xmlNextChar(ctxt);
                                if !info.is_null() && (*info).empty as libc::c_int != 0 {
                                    if !((*ctxt).sax).is_null()
                                        && ((*(*ctxt).sax).endElement).is_some()
                                    {
                                        ((*(*ctxt).sax).endElement)
                                            .expect(
                                                "non-null function pointer",
                                            )((*ctxt).userData, name);
                                    }
                                    htmlnamePop(ctxt);
                                }
                                if (*ctxt).record_info != 0 {
                                    htmlNodeInfoPush(ctxt, &mut node_info);
                                }
                                (*ctxt).instate = XML_PARSER_CONTENT;
                            } else {
                                htmlParseErr(
                                    ctxt,
                                    XML_ERR_GT_REQUIRED,
                                    b"Couldn't find end of Start Tag %s\n\0" as *const u8
                                        as *const libc::c_char,
                                    name,
                                    0 as *const xmlChar,
                                );
                                if xmlStrEqual(name, (*ctxt).name) != 0 {
                                    nodePop(ctxt);
                                    htmlnamePop(ctxt);
                                }
                                if (*ctxt).record_info != 0 {
                                    htmlNodeInfoPush(ctxt, &mut node_info);
                                }
                                (*ctxt).instate = XML_PARSER_CONTENT;
                            }
                        }
                    }
                }
                7 => {
                    let mut chr: [xmlChar; 2] = [
                        0 as libc::c_int as xmlChar,
                        0 as libc::c_int as xmlChar,
                    ];
                    if (*ctxt).token != 0 as libc::c_int {
                        chr[0 as libc::c_int as usize] = (*ctxt).token as xmlChar;
                        htmlCheckParagraph(ctxt);
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).characters).is_some()
                        {
                            ((*(*ctxt).sax).characters)
                                .expect(
                                    "non-null function pointer",
                                )((*ctxt).userData, chr.as_mut_ptr(), 1 as libc::c_int);
                        }
                        (*ctxt).token = 0 as libc::c_int;
                        (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                    }
                    if avail == 1 as libc::c_int as libc::c_long && terminate != 0 {
                        cur = *((*in_0).cur).offset(0 as libc::c_int as isize);
                        if cur as libc::c_int != '<' as i32
                            && cur as libc::c_int != '&' as i32
                        {
                            if !((*ctxt).sax).is_null() {
                                chr[0 as libc::c_int as usize] = cur;
                                if cur as libc::c_int == 0x20 as libc::c_int
                                    || 0x9 as libc::c_int <= cur as libc::c_int
                                        && cur as libc::c_int <= 0xa as libc::c_int
                                    || cur as libc::c_int == 0xd as libc::c_int
                                {
                                    if (*ctxt).keepBlanks != 0 {
                                        if ((*(*ctxt).sax).characters).is_some() {
                                            ((*(*ctxt).sax).characters)
                                                .expect(
                                                    "non-null function pointer",
                                                )((*ctxt).userData, chr.as_mut_ptr(), 1 as libc::c_int);
                                        }
                                    } else if ((*(*ctxt).sax).ignorableWhitespace).is_some() {
                                        ((*(*ctxt).sax).ignorableWhitespace)
                                            .expect(
                                                "non-null function pointer",
                                            )((*ctxt).userData, chr.as_mut_ptr(), 1 as libc::c_int);
                                    }
                                } else {
                                    htmlCheckParagraph(ctxt);
                                    if ((*(*ctxt).sax).characters).is_some() {
                                        ((*(*ctxt).sax).characters)
                                            .expect(
                                                "non-null function pointer",
                                            )((*ctxt).userData, chr.as_mut_ptr(), 1 as libc::c_int);
                                    }
                                }
                            }
                            (*ctxt).token = 0 as libc::c_int;
                            (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                            let ref mut fresh166 = (*in_0).cur;
                            *fresh166 = (*fresh166).offset(1);
                            continue;
                        }
                    }
                    if avail < 2 as libc::c_int as libc::c_long {
                        break;
                    }
                    cur = *((*in_0).cur).offset(0 as libc::c_int as isize);
                    next = *((*in_0).cur).offset(1 as libc::c_int as isize);
                    if xmlStrEqual(
                        (*ctxt).name,
                        b"script\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    ) != 0
                        || xmlStrEqual(
                            (*ctxt).name,
                            b"style\0" as *const u8 as *const libc::c_char
                                as *mut xmlChar,
                        ) != 0
                    {
                        if terminate == 0 {
                            let mut idx: libc::c_int = 0;
                            let mut val: xmlChar = 0;
                            idx = htmlParseLookupSequence(
                                ctxt,
                                '<' as i32 as xmlChar,
                                '/' as i32 as xmlChar,
                                0 as libc::c_int as xmlChar,
                                0 as libc::c_int,
                            );
                            if idx < 0 as libc::c_int {
                                break;
                            }
                            val = *((*in_0).cur)
                                .offset((idx + 2 as libc::c_int) as isize);
                            if val as libc::c_int == 0 as libc::c_int {
                                break;
                            }
                        }
                        htmlParseScript(ctxt);
                        if !(cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '/' as i32)
                        {
                            continue;
                        }
                        (*ctxt).instate = XML_PARSER_END_TAG;
                        (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                    } else if cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '!' as i32
                        {
                        if ({
                            let mut __res: libc::c_int = 0;
                            if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                        .offset(2 as libc::c_int as isize) as libc::c_int;
                                    __res = (if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    });
                                } else {
                                    __res = toupper(
                                        *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                            as libc::c_int,
                                    );
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(
                                        *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                            as libc::c_int as isize,
                                    );
                            }
                            __res
                        }) == 'D' as i32
                            && ({
                                let mut __res: libc::c_int = 0;
                                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                    > 1 as libc::c_int as libc::c_ulong
                                {
                                    if 0 != 0 {
                                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                            .offset(3 as libc::c_int as isize) as libc::c_int;
                                        __res = (if __c < -(128 as libc::c_int)
                                            || __c > 255 as libc::c_int
                                        {
                                            __c
                                        } else {
                                            *(*__ctype_toupper_loc()).offset(__c as isize)
                                        });
                                    } else {
                                        __res = toupper(
                                            *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                                as libc::c_int,
                                        );
                                    }
                                } else {
                                    __res = *(*__ctype_toupper_loc())
                                        .offset(
                                            *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                                as libc::c_int as isize,
                                        );
                                }
                                __res
                            }) == 'O' as i32
                            && ({
                                let mut __res: libc::c_int = 0;
                                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                    > 1 as libc::c_int as libc::c_ulong
                                {
                                    if 0 != 0 {
                                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                            .offset(4 as libc::c_int as isize) as libc::c_int;
                                        __res = (if __c < -(128 as libc::c_int)
                                            || __c > 255 as libc::c_int
                                        {
                                            __c
                                        } else {
                                            *(*__ctype_toupper_loc()).offset(__c as isize)
                                        });
                                    } else {
                                        __res = toupper(
                                            *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                                as libc::c_int,
                                        );
                                    }
                                } else {
                                    __res = *(*__ctype_toupper_loc())
                                        .offset(
                                            *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                                as libc::c_int as isize,
                                        );
                                }
                                __res
                            }) == 'C' as i32
                            && ({
                                let mut __res: libc::c_int = 0;
                                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                    > 1 as libc::c_int as libc::c_ulong
                                {
                                    if 0 != 0 {
                                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                            .offset(5 as libc::c_int as isize) as libc::c_int;
                                        __res = (if __c < -(128 as libc::c_int)
                                            || __c > 255 as libc::c_int
                                        {
                                            __c
                                        } else {
                                            *(*__ctype_toupper_loc()).offset(__c as isize)
                                        });
                                    } else {
                                        __res = toupper(
                                            *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                                as libc::c_int,
                                        );
                                    }
                                } else {
                                    __res = *(*__ctype_toupper_loc())
                                        .offset(
                                            *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                                as libc::c_int as isize,
                                        );
                                }
                                __res
                            }) == 'T' as i32
                            && ({
                                let mut __res: libc::c_int = 0;
                                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                    > 1 as libc::c_int as libc::c_ulong
                                {
                                    if 0 != 0 {
                                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                            .offset(6 as libc::c_int as isize) as libc::c_int;
                                        __res = (if __c < -(128 as libc::c_int)
                                            || __c > 255 as libc::c_int
                                        {
                                            __c
                                        } else {
                                            *(*__ctype_toupper_loc()).offset(__c as isize)
                                        });
                                    } else {
                                        __res = toupper(
                                            *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                                                as libc::c_int,
                                        );
                                    }
                                } else {
                                    __res = *(*__ctype_toupper_loc())
                                        .offset(
                                            *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                                                as libc::c_int as isize,
                                        );
                                }
                                __res
                            }) == 'Y' as i32
                            && ({
                                let mut __res: libc::c_int = 0;
                                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                    > 1 as libc::c_int as libc::c_ulong
                                {
                                    if 0 != 0 {
                                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                            .offset(7 as libc::c_int as isize) as libc::c_int;
                                        __res = (if __c < -(128 as libc::c_int)
                                            || __c > 255 as libc::c_int
                                        {
                                            __c
                                        } else {
                                            *(*__ctype_toupper_loc()).offset(__c as isize)
                                        });
                                    } else {
                                        __res = toupper(
                                            *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                                                as libc::c_int,
                                        );
                                    }
                                } else {
                                    __res = *(*__ctype_toupper_loc())
                                        .offset(
                                            *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                                                as libc::c_int as isize,
                                        );
                                }
                                __res
                            }) == 'P' as i32
                            && ({
                                let mut __res: libc::c_int = 0;
                                if ::std::mem::size_of::<xmlChar>() as libc::c_ulong
                                    > 1 as libc::c_int as libc::c_ulong
                                {
                                    if 0 != 0 {
                                        let mut __c: libc::c_int = *((*(*ctxt).input).cur)
                                            .offset(8 as libc::c_int as isize) as libc::c_int;
                                        __res = (if __c < -(128 as libc::c_int)
                                            || __c > 255 as libc::c_int
                                        {
                                            __c
                                        } else {
                                            *(*__ctype_toupper_loc()).offset(__c as isize)
                                        });
                                    } else {
                                        __res = toupper(
                                            *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                                                as libc::c_int,
                                        );
                                    }
                                } else {
                                    __res = *(*__ctype_toupper_loc())
                                        .offset(
                                            *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                                                as libc::c_int as isize,
                                        );
                                }
                                __res
                            }) == 'E' as i32
                        {
                            if terminate == 0
                                && htmlParseLookupSequence(
                                    ctxt,
                                    '>' as i32 as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                    1 as libc::c_int,
                                ) < 0 as libc::c_int
                            {
                                break;
                            }
                            htmlParseErr(
                                ctxt,
                                XML_HTML_STRUCURE_ERROR,
                                b"Misplaced DOCTYPE declaration\n\0" as *const u8
                                    as *const libc::c_char,
                                b"DOCTYPE\0" as *const u8 as *const libc::c_char
                                    as *mut xmlChar,
                                0 as *const xmlChar,
                            );
                            htmlParseDocTypeDecl(ctxt);
                        } else if *((*in_0).cur).offset(2 as libc::c_int as isize)
                                as libc::c_int == '-' as i32
                                && *((*in_0).cur).offset(3 as libc::c_int as isize)
                                    as libc::c_int == '-' as i32
                            {
                            if terminate == 0
                                && htmlParseLookupCommentEnd(ctxt) < 0 as libc::c_int
                            {
                                break;
                            }
                            htmlParseComment(ctxt);
                            (*ctxt).instate = XML_PARSER_CONTENT;
                        } else {
                            if terminate == 0
                                && htmlParseLookupSequence(
                                    ctxt,
                                    '>' as i32 as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int,
                                ) < 0 as libc::c_int
                            {
                                break;
                            }
                            htmlSkipBogusComment(ctxt);
                        }
                    } else if cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '?' as i32
                        {
                        if terminate == 0
                            && htmlParseLookupSequence(
                                ctxt,
                                '>' as i32 as xmlChar,
                                0 as libc::c_int as xmlChar,
                                0 as libc::c_int as xmlChar,
                                0 as libc::c_int,
                            ) < 0 as libc::c_int
                        {
                            break;
                        }
                        htmlParsePI(ctxt);
                        (*ctxt).instate = XML_PARSER_CONTENT;
                    } else {
                        if cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '!' as i32
                            && avail < 4 as libc::c_int as libc::c_long
                        {
                            break;
                        }
                        if cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '/' as i32
                        {
                            (*ctxt).instate = XML_PARSER_END_TAG;
                            (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                        } else if cur as libc::c_int == '<' as i32
                                && (0x41 as libc::c_int <= next as libc::c_int
                                    && next as libc::c_int <= 0x5a as libc::c_int
                                    || 0x61 as libc::c_int <= next as libc::c_int
                                        && next as libc::c_int <= 0x7a as libc::c_int)
                            {
                            if terminate == 0 && next as libc::c_int == 0 as libc::c_int
                            {
                                break;
                            }
                            (*ctxt).instate = XML_PARSER_START_TAG;
                            (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                        } else if cur as libc::c_int == '<' as i32 {
                            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                                && ((*(*ctxt).sax).characters).is_some()
                            {
                                ((*(*ctxt).sax).characters)
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    (*ctxt).userData,
                                    b"<\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                                    1 as libc::c_int,
                                );
                            }
                            xmlNextChar(ctxt);
                        } else {
                            if terminate == 0
                                && htmlParseLookupSequence(
                                    ctxt,
                                    '<' as i32 as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int,
                                ) < 0 as libc::c_int
                            {
                                break;
                            }
                            (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                            while (*ctxt).instate as libc::c_int
                                != XML_PARSER_EOF as libc::c_int
                                && cur as libc::c_int != '<' as i32
                                && (*in_0).cur < (*in_0).end
                            {
                                if cur as libc::c_int == '&' as i32 {
                                    htmlParseReference(ctxt);
                                } else {
                                    htmlParseCharData(ctxt);
                                }
                                cur = *((*in_0).cur).offset(0 as libc::c_int as isize);
                            }
                        }
                    }
                }
                9 => {
                    if avail < 2 as libc::c_int as libc::c_long {
                        break;
                    }
                    if terminate == 0
                        && htmlParseLookupSequence(
                            ctxt,
                            '>' as i32 as xmlChar,
                            0 as libc::c_int as xmlChar,
                            0 as libc::c_int as xmlChar,
                            0 as libc::c_int,
                        ) < 0 as libc::c_int
                    {
                        break;
                    }
                    htmlParseEndTag(ctxt);
                    if (*ctxt).nameNr == 0 as libc::c_int {
                        (*ctxt).instate = XML_PARSER_EPILOG;
                    } else {
                        (*ctxt).instate = XML_PARSER_CONTENT;
                    }
                    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                }
                8 => {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_INTERNAL_ERROR,
                        b"HPP: internal error, state == CDATA\n\0" as *const u8
                            as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    (*ctxt).instate = XML_PARSER_CONTENT;
                    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                }
                3 => {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_INTERNAL_ERROR,
                        b"HPP: internal error, state == DTD\n\0" as *const u8
                            as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    (*ctxt).instate = XML_PARSER_CONTENT;
                    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                }
                5 => {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_INTERNAL_ERROR,
                        b"HPP: internal error, state == COMMENT\n\0" as *const u8
                            as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    (*ctxt).instate = XML_PARSER_CONTENT;
                    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                }
                2 => {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_INTERNAL_ERROR,
                        b"HPP: internal error, state == PI\n\0" as *const u8
                            as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    (*ctxt).instate = XML_PARSER_CONTENT;
                    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                }
                10 => {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_INTERNAL_ERROR,
                        b"HPP: internal error, state == ENTITY_DECL\n\0" as *const u8
                            as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    (*ctxt).instate = XML_PARSER_CONTENT;
                    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                }
                11 => {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_INTERNAL_ERROR,
                        b"HPP: internal error, state == ENTITY_VALUE\n\0" as *const u8
                            as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    (*ctxt).instate = XML_PARSER_CONTENT;
                    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                }
                12 => {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_INTERNAL_ERROR,
                        b"HPP: internal error, state == ATTRIBUTE_VALUE\n\0" as *const u8
                            as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    (*ctxt).instate = XML_PARSER_START_TAG;
                    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                }
                13 => {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_INTERNAL_ERROR,
                        b"HPP: internal error, state == XML_PARSER_SYSTEM_LITERAL\n\0"
                            as *const u8 as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    (*ctxt).instate = XML_PARSER_CONTENT;
                    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                }
                15 => {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_INTERNAL_ERROR,
                        b"HPP: internal error, state == XML_PARSER_IGNORE\n\0"
                            as *const u8 as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    (*ctxt).instate = XML_PARSER_CONTENT;
                    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                }
                16 => {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_INTERNAL_ERROR,
                        b"HPP: internal error, state == XML_PARSER_LITERAL\n\0"
                            as *const u8 as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    (*ctxt).instate = XML_PARSER_CONTENT;
                    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                }
                _ => {}
            }
        }
    }
    if avail == 0 as libc::c_int as libc::c_long && terminate != 0 {
        htmlAutoCloseOnEnd(ctxt);
        if (*ctxt).nameNr == 0 as libc::c_int
            && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
        {
            (*ctxt).instate = XML_PARSER_EOF;
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some() {
                ((*(*ctxt).sax).endDocument)
                    .expect("non-null function pointer")((*ctxt).userData);
            }
        }
    }
    if (*ctxt).options & HTML_PARSE_NODEFDTD as libc::c_int == 0
        && !((*ctxt).myDoc).is_null()
        && (terminate != 0
            || (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
            || (*ctxt).instate as libc::c_int == XML_PARSER_EPILOG as libc::c_int)
    {
        let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
        dtd = xmlGetIntSubset((*ctxt).myDoc as *const xmlDoc);
        if dtd.is_null() {
            let ref mut fresh167 = (*(*ctxt).myDoc).intSubset;
            *fresh167 = xmlCreateIntSubset(
                (*ctxt).myDoc,
                b"html\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                b"-//W3C//DTD HTML 4.0 Transitional//EN\0" as *const u8
                    as *const libc::c_char as *mut xmlChar,
                b"http://www.w3.org/TR/REC-html40/loose.dtd\0" as *const u8
                    as *const libc::c_char as *mut xmlChar,
            );
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn htmlParseChunk(
    mut ctxt: htmlParserCtxtPtr,
    mut chunk: *const libc::c_char,
    mut size: libc::c_int,
    mut terminate: libc::c_int,
) -> libc::c_int {
    if ctxt.is_null() || ((*ctxt).input).is_null() {
        htmlParseErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"htmlParseChunk: context error\n\0" as *const u8 as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return XML_ERR_INTERNAL_ERROR as libc::c_int;
    }
    if size > 0 as libc::c_int && !chunk.is_null() && !((*ctxt).input).is_null()
        && !((*(*ctxt).input).buf).is_null()
        && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
    {
        let mut base: size_t = xmlBufGetInputBase(
            (*(*(*ctxt).input).buf).buffer,
            (*ctxt).input,
        );
        let mut cur: size_t = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
            as libc::c_long as size_t;
        let mut res: libc::c_int = 0;
        res = xmlParserInputBufferPush((*(*ctxt).input).buf, size, chunk);
        xmlBufSetInputBaseCur((*(*(*ctxt).input).buf).buffer, (*ctxt).input, base, cur);
        if res < 0 as libc::c_int {
            (*ctxt).errNo = XML_PARSER_EOF as libc::c_int;
            (*ctxt).disableSAX = 1 as libc::c_int;
            return XML_PARSER_EOF as libc::c_int;
        }
    } else if (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int {
        if !((*ctxt).input).is_null() && !((*(*ctxt).input).buf).is_null() {
            let mut in_0: xmlParserInputBufferPtr = (*(*ctxt).input).buf;
            if !((*in_0).encoder).is_null() && !((*in_0).buffer).is_null()
                && !((*in_0).raw).is_null()
            {
                let mut nbchars: libc::c_int = 0;
                let mut base_0: size_t = xmlBufGetInputBase(
                    (*in_0).buffer,
                    (*ctxt).input,
                );
                let mut current: size_t = ((*(*ctxt).input).cur)
                    .offset_from((*(*ctxt).input).base) as libc::c_long as size_t;
                nbchars = xmlCharEncInput(in_0, terminate);
                xmlBufSetInputBaseCur((*in_0).buffer, (*ctxt).input, base_0, current);
                if nbchars < 0 as libc::c_int {
                    htmlParseErr(
                        ctxt,
                        XML_ERR_INVALID_ENCODING,
                        b"encoder error\n\0" as *const u8 as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    return XML_ERR_INVALID_ENCODING as libc::c_int;
                }
            }
        }
    }
    htmlParseTryOrFinish(ctxt, terminate);
    if terminate != 0 {
        if (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
            && (*ctxt).instate as libc::c_int != XML_PARSER_EPILOG as libc::c_int
            && (*ctxt).instate as libc::c_int != XML_PARSER_MISC as libc::c_int
        {
            (*ctxt).errNo = XML_ERR_DOCUMENT_END as libc::c_int;
            (*ctxt).wellFormed = 0 as libc::c_int;
        }
        if (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int {
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some() {
                ((*(*ctxt).sax).endDocument)
                    .expect("non-null function pointer")((*ctxt).userData);
            }
        }
        (*ctxt).instate = XML_PARSER_EOF;
    }
    return (*ctxt).errNo as xmlParserErrors as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn htmlCreatePushParserCtxt(
    mut sax: htmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut chunk: *const libc::c_char,
    mut size: libc::c_int,
    mut filename: *const libc::c_char,
    mut enc: xmlCharEncoding,
) -> htmlParserCtxtPtr {
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut inputStream: htmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    xmlInitParser();
    buf = xmlAllocParserInputBuffer(enc);
    if buf.is_null() {
        return 0 as htmlParserCtxtPtr;
    }
    ctxt = htmlNewParserCtxt();
    if ctxt.is_null() {
        xmlFreeParserInputBuffer(buf);
        return 0 as htmlParserCtxtPtr;
    }
    if enc as libc::c_int == XML_CHAR_ENCODING_UTF8 as libc::c_int
        || !((*buf).encoder).is_null()
    {
        (*ctxt).charset = XML_CHAR_ENCODING_UTF8 as libc::c_int;
    }
    if !sax.is_null() {
        if (*ctxt).sax != __htmlDefaultSAXHandler() as xmlSAXHandlerPtr {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let ref mut fresh168 = (*ctxt).sax;
        *fresh168 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<htmlSAXHandler>() as libc::c_ulong)
            as htmlSAXHandlerPtr;
        if ((*ctxt).sax).is_null() {
            xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
            xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void);
            return 0 as htmlParserCtxtPtr;
        }
        memcpy(
            (*ctxt).sax as *mut libc::c_void,
            sax as *const libc::c_void,
            ::std::mem::size_of::<htmlSAXHandler>() as libc::c_ulong,
        );
        if !user_data.is_null() {
            let ref mut fresh169 = (*ctxt).userData;
            *fresh169 = user_data;
        }
    }
    if filename.is_null() {
        let ref mut fresh170 = (*ctxt).directory;
        *fresh170 = 0 as *mut libc::c_char;
    } else {
        let ref mut fresh171 = (*ctxt).directory;
        *fresh171 = xmlParserGetDirectory(filename);
    }
    inputStream = htmlNewInputStream(ctxt);
    if inputStream.is_null() {
        xmlFreeParserCtxt(ctxt);
        xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
        return 0 as htmlParserCtxtPtr;
    }
    if filename.is_null() {
        let ref mut fresh172 = (*inputStream).filename;
        *fresh172 = 0 as *const libc::c_char;
    } else {
        let ref mut fresh173 = (*inputStream).filename;
        *fresh173 = xmlCanonicPath(filename as *const xmlChar) as *mut libc::c_char;
    }
    let ref mut fresh174 = (*inputStream).buf;
    *fresh174 = buf;
    xmlBufResetInput((*buf).buffer, inputStream);
    inputPush(ctxt, inputStream);
    if size > 0 as libc::c_int && !chunk.is_null() && !((*ctxt).input).is_null()
        && !((*(*ctxt).input).buf).is_null()
    {
        let mut base: size_t = xmlBufGetInputBase(
            (*(*(*ctxt).input).buf).buffer,
            (*ctxt).input,
        );
        let mut cur: size_t = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
            as libc::c_long as size_t;
        xmlParserInputBufferPush((*(*ctxt).input).buf, size, chunk);
        xmlBufSetInputBaseCur((*(*(*ctxt).input).buf).buffer, (*ctxt).input, base, cur);
    }
    (*ctxt).progressive = 1 as libc::c_int;
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn htmlSAXParseDoc(
    mut cur: *const xmlChar,
    mut encoding: *const libc::c_char,
    mut sax: htmlSAXHandlerPtr,
    mut userData: *mut libc::c_void,
) -> htmlDocPtr {
    let mut ret: htmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    if cur.is_null() {
        return 0 as htmlDocPtr;
    }
    ctxt = htmlCreateDocParserCtxt(cur, encoding);
    if ctxt.is_null() {
        return 0 as htmlDocPtr;
    }
    if !sax.is_null() {
        if !((*ctxt).sax).is_null() {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let ref mut fresh175 = (*ctxt).sax;
        *fresh175 = sax;
        let ref mut fresh176 = (*ctxt).userData;
        *fresh176 = userData;
    }
    htmlParseDocument(ctxt);
    ret = (*ctxt).myDoc;
    if !sax.is_null() {
        let ref mut fresh177 = (*ctxt).sax;
        *fresh177 = 0 as *mut _xmlSAXHandler;
        let ref mut fresh178 = (*ctxt).userData;
        *fresh178 = 0 as *mut libc::c_void;
    }
    htmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn htmlParseDoc(
    mut cur: *const xmlChar,
    mut encoding: *const libc::c_char,
) -> htmlDocPtr {
    return htmlSAXParseDoc(
        cur,
        encoding,
        0 as htmlSAXHandlerPtr,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn htmlCreateFileParserCtxt(
    mut filename: *const libc::c_char,
    mut encoding: *const libc::c_char,
) -> htmlParserCtxtPtr {
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut inputStream: htmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut canonicFilename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut content_line: *mut xmlChar = b"charset=\0" as *const u8
        as *const libc::c_char as *mut xmlChar;
    if filename.is_null() {
        return 0 as htmlParserCtxtPtr;
    }
    ctxt = htmlNewParserCtxt();
    if ctxt.is_null() {
        return 0 as htmlParserCtxtPtr;
    }
    canonicFilename = xmlCanonicPath(filename as *const xmlChar) as *mut libc::c_char;
    if canonicFilename.is_null() {
        if ((*__xmlDefaultSAXHandler()).error).is_some() {
            ((*__xmlDefaultSAXHandler()).error)
                .expect(
                    "non-null function pointer",
                )(
                0 as *mut libc::c_void,
                b"out of memory\n\0" as *const u8 as *const libc::c_char,
            );
        }
        xmlFreeParserCtxt(ctxt);
        return 0 as htmlParserCtxtPtr;
    }
    inputStream = xmlLoadExternalEntity(canonicFilename, 0 as *const libc::c_char, ctxt);
    xmlFree.expect("non-null function pointer")(canonicFilename as *mut libc::c_void);
    if inputStream.is_null() {
        xmlFreeParserCtxt(ctxt);
        return 0 as htmlParserCtxtPtr;
    }
    inputPush(ctxt, inputStream);
    if !encoding.is_null() {
        let mut l: size_t = strlen(encoding);
        if l < 1000 as libc::c_int as libc::c_ulong {
            content = xmlMallocAtomic
                .expect(
                    "non-null function pointer",
                )(
                (xmlStrlen(content_line) as libc::c_ulong)
                    .wrapping_add(l)
                    .wrapping_add(1 as libc::c_int as libc::c_ulong),
            ) as *mut xmlChar;
            if !content.is_null() {
                strcpy(content as *mut libc::c_char, content_line as *mut libc::c_char);
                strcat(content as *mut libc::c_char, encoding as *mut libc::c_char);
                htmlCheckEncoding(ctxt, content);
                xmlFree
                    .expect("non-null function pointer")(content as *mut libc::c_void);
            }
        }
    }
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn htmlSAXParseFile(
    mut filename: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut sax: htmlSAXHandlerPtr,
    mut userData: *mut libc::c_void,
) -> htmlDocPtr {
    let mut ret: htmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut oldsax: htmlSAXHandlerPtr = 0 as htmlSAXHandlerPtr;
    xmlInitParser();
    ctxt = htmlCreateFileParserCtxt(filename, encoding);
    if ctxt.is_null() {
        return 0 as htmlDocPtr;
    }
    if !sax.is_null() {
        oldsax = (*ctxt).sax;
        let ref mut fresh179 = (*ctxt).sax;
        *fresh179 = sax;
        let ref mut fresh180 = (*ctxt).userData;
        *fresh180 = userData;
    }
    htmlParseDocument(ctxt);
    ret = (*ctxt).myDoc;
    if !sax.is_null() {
        let ref mut fresh181 = (*ctxt).sax;
        *fresh181 = oldsax;
        let ref mut fresh182 = (*ctxt).userData;
        *fresh182 = 0 as *mut libc::c_void;
    }
    htmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn htmlParseFile(
    mut filename: *const libc::c_char,
    mut encoding: *const libc::c_char,
) -> htmlDocPtr {
    return htmlSAXParseFile(
        filename,
        encoding,
        0 as htmlSAXHandlerPtr,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn htmlHandleOmittedElem(mut val: libc::c_int) -> libc::c_int {
    let mut old: libc::c_int = htmlOmittedDefaultValue;
    htmlOmittedDefaultValue = val;
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn htmlElementAllowedHere(
    mut parent: *const htmlElemDesc,
    mut elt: *const xmlChar,
) -> libc::c_int {
    let mut p: *mut *const libc::c_char = 0 as *mut *const libc::c_char;
    if elt.is_null() || parent.is_null() || ((*parent).subelts).is_null() {
        return 0 as libc::c_int;
    }
    p = (*parent).subelts;
    while !(*p).is_null() {
        if xmlStrcmp(*p as *const xmlChar, elt) == 0 {
            return 1 as libc::c_int;
        }
        p = p.offset(1);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn htmlElementStatusHere(
    mut parent: *const htmlElemDesc,
    mut elt: *const htmlElemDesc,
) -> htmlStatus {
    if parent.is_null() || elt.is_null() {
        return HTML_INVALID;
    }
    if htmlElementAllowedHere(parent, (*elt).name as *const xmlChar) == 0 {
        return HTML_INVALID;
    }
    return (if (*elt).dtd as libc::c_int == 0 as libc::c_int {
        HTML_VALID as libc::c_int
    } else {
        HTML_DEPRECATED as libc::c_int
    }) as htmlStatus;
}
#[no_mangle]
pub unsafe extern "C" fn htmlAttrAllowed(
    mut elt: *const htmlElemDesc,
    mut attr: *const xmlChar,
    mut legacy: libc::c_int,
) -> htmlStatus {
    let mut p: *mut *const libc::c_char = 0 as *mut *const libc::c_char;
    if elt.is_null() || attr.is_null() {
        return HTML_INVALID;
    }
    if !((*elt).attrs_req).is_null() {
        p = (*elt).attrs_req;
        while !(*p).is_null() {
            if xmlStrcmp(*p as *const xmlChar, attr) == 0 {
                return HTML_REQUIRED;
            }
            p = p.offset(1);
        }
    }
    if !((*elt).attrs_opt).is_null() {
        p = (*elt).attrs_opt;
        while !(*p).is_null() {
            if xmlStrcmp(*p as *const xmlChar, attr) == 0 {
                return HTML_VALID;
            }
            p = p.offset(1);
        }
    }
    if legacy != 0 && !((*elt).attrs_depr).is_null() {
        p = (*elt).attrs_depr;
        while !(*p).is_null() {
            if xmlStrcmp(*p as *const xmlChar, attr) == 0 {
                return HTML_DEPRECATED;
            }
            p = p.offset(1);
        }
    }
    return HTML_INVALID;
}
#[no_mangle]
pub unsafe extern "C" fn htmlNodeStatus(
    node: htmlNodePtr,
    mut legacy: libc::c_int,
) -> htmlStatus {
    if node.is_null() {
        return HTML_INVALID;
    }
    match (*node).type_0 as libc::c_uint {
        1 => {
            return (if legacy != 0 {
                (if htmlElementAllowedHere(
                    htmlTagLookup((*(*node).parent).name),
                    (*node).name,
                ) != 0
                {
                    HTML_VALID as libc::c_int
                } else {
                    HTML_INVALID as libc::c_int
                }) as libc::c_uint
            } else {
                htmlElementStatusHere(
                    htmlTagLookup((*(*node).parent).name),
                    htmlTagLookup((*node).name),
                ) as libc::c_uint
            }) as htmlStatus;
        }
        2 => {
            return htmlAttrAllowed(
                htmlTagLookup((*(*node).parent).name),
                (*node).name,
                legacy,
            );
        }
        _ => return HTML_NA,
    };
}
#[no_mangle]
pub unsafe extern "C" fn htmlCtxtReset(mut ctxt: htmlParserCtxtPtr) {
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut dict: xmlDictPtr = 0 as *mut xmlDict;
    if ctxt.is_null() {
        return;
    }
    xmlInitParser();
    dict = (*ctxt).dict;
    loop {
        input = inputPop(ctxt);
        if input.is_null() {
            break;
        }
        xmlFreeInputStream(input);
    }
    (*ctxt).inputNr = 0 as libc::c_int;
    let ref mut fresh183 = (*ctxt).input;
    *fresh183 = 0 as xmlParserInputPtr;
    (*ctxt).spaceNr = 0 as libc::c_int;
    if !((*ctxt).spaceTab).is_null() {
        *((*ctxt).spaceTab).offset(0 as libc::c_int as isize) = -(1 as libc::c_int);
        let ref mut fresh184 = (*ctxt).space;
        *fresh184 = &mut *((*ctxt).spaceTab).offset(0 as libc::c_int as isize)
            as *mut libc::c_int;
    } else {
        let ref mut fresh185 = (*ctxt).space;
        *fresh185 = 0 as *mut libc::c_int;
    }
    (*ctxt).nodeNr = 0 as libc::c_int;
    let ref mut fresh186 = (*ctxt).node;
    *fresh186 = 0 as xmlNodePtr;
    (*ctxt).nameNr = 0 as libc::c_int;
    let ref mut fresh187 = (*ctxt).name;
    *fresh187 = 0 as *const xmlChar;
    (*ctxt).nsNr = 0 as libc::c_int;
    if !((*ctxt).version).is_null()
        && (dict.is_null() || xmlDictOwns(dict, (*ctxt).version) == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).version as *mut libc::c_char as *mut libc::c_void);
    }
    let ref mut fresh188 = (*ctxt).version;
    *fresh188 = 0 as *const xmlChar;
    if !((*ctxt).encoding).is_null()
        && (dict.is_null() || xmlDictOwns(dict, (*ctxt).encoding) == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).encoding as *mut libc::c_char as *mut libc::c_void);
    }
    let ref mut fresh189 = (*ctxt).encoding;
    *fresh189 = 0 as *const xmlChar;
    if !((*ctxt).directory).is_null()
        && (dict.is_null()
            || xmlDictOwns(dict, (*ctxt).directory as *const xmlChar)
                == 0 as libc::c_int)
    {
        xmlFree
            .expect("non-null function pointer")((*ctxt).directory as *mut libc::c_void);
    }
    let ref mut fresh190 = (*ctxt).directory;
    *fresh190 = 0 as *mut libc::c_char;
    if !((*ctxt).extSubURI).is_null()
        && (dict.is_null()
            || xmlDictOwns(dict, (*ctxt).extSubURI as *const xmlChar)
                == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).extSubURI as *mut libc::c_char as *mut libc::c_void);
    }
    let ref mut fresh191 = (*ctxt).extSubURI;
    *fresh191 = 0 as *mut xmlChar;
    if !((*ctxt).extSubSystem).is_null()
        && (dict.is_null()
            || xmlDictOwns(dict, (*ctxt).extSubSystem as *const xmlChar)
                == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).extSubSystem as *mut libc::c_char as *mut libc::c_void);
    }
    let ref mut fresh192 = (*ctxt).extSubSystem;
    *fresh192 = 0 as *mut xmlChar;
    if !((*ctxt).myDoc).is_null() {
        xmlFreeDoc((*ctxt).myDoc);
    }
    let ref mut fresh193 = (*ctxt).myDoc;
    *fresh193 = 0 as xmlDocPtr;
    (*ctxt).standalone = -(1 as libc::c_int);
    (*ctxt).hasExternalSubset = 0 as libc::c_int;
    (*ctxt).hasPErefs = 0 as libc::c_int;
    (*ctxt).html = 1 as libc::c_int;
    (*ctxt).external = 0 as libc::c_int;
    (*ctxt).instate = XML_PARSER_START;
    (*ctxt).token = 0 as libc::c_int;
    (*ctxt).wellFormed = 1 as libc::c_int;
    (*ctxt).nsWellFormed = 1 as libc::c_int;
    (*ctxt).disableSAX = 0 as libc::c_int;
    (*ctxt).valid = 1 as libc::c_int;
    let ref mut fresh194 = (*ctxt).vctxt.userData;
    *fresh194 = ctxt as *mut libc::c_void;
    let ref mut fresh195 = (*ctxt).vctxt.error;
    *fresh195 = Some(
        xmlParserValidityError
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    );
    let ref mut fresh196 = (*ctxt).vctxt.warning;
    *fresh196 = Some(
        xmlParserValidityWarning
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    );
    (*ctxt).record_info = 0 as libc::c_int;
    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
    (*ctxt).inSubset = 0 as libc::c_int;
    (*ctxt).errNo = XML_ERR_OK as libc::c_int;
    (*ctxt).depth = 0 as libc::c_int;
    (*ctxt).charset = XML_CHAR_ENCODING_NONE as libc::c_int;
    let ref mut fresh197 = (*ctxt).catalogs;
    *fresh197 = 0 as *mut libc::c_void;
    xmlInitNodeInfoSeq(&mut (*ctxt).node_seq);
    if !((*ctxt).attsDefault).is_null() {
        xmlHashFree(
            (*ctxt).attsDefault,
            Some(
                xmlHashDefaultDeallocator
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
        );
        let ref mut fresh198 = (*ctxt).attsDefault;
        *fresh198 = 0 as xmlHashTablePtr;
    }
    if !((*ctxt).attsSpecial).is_null() {
        xmlHashFree((*ctxt).attsSpecial, None);
        let ref mut fresh199 = (*ctxt).attsSpecial;
        *fresh199 = 0 as xmlHashTablePtr;
    }
}
#[no_mangle]
pub unsafe extern "C" fn htmlCtxtUseOptions(
    mut ctxt: htmlParserCtxtPtr,
    mut options: libc::c_int,
) -> libc::c_int {
    if ctxt.is_null() {
        return -(1 as libc::c_int);
    }
    if options & HTML_PARSE_NOWARNING as libc::c_int != 0 {
        let ref mut fresh200 = (*(*ctxt).sax).warning;
        *fresh200 = None;
        let ref mut fresh201 = (*ctxt).vctxt.warning;
        *fresh201 = None;
        options -= XML_PARSE_NOWARNING as libc::c_int;
        (*ctxt).options |= XML_PARSE_NOWARNING as libc::c_int;
    }
    if options & HTML_PARSE_NOERROR as libc::c_int != 0 {
        let ref mut fresh202 = (*(*ctxt).sax).error;
        *fresh202 = None;
        let ref mut fresh203 = (*ctxt).vctxt.error;
        *fresh203 = None;
        let ref mut fresh204 = (*(*ctxt).sax).fatalError;
        *fresh204 = None;
        options -= XML_PARSE_NOERROR as libc::c_int;
        (*ctxt).options |= XML_PARSE_NOERROR as libc::c_int;
    }
    if options & HTML_PARSE_PEDANTIC as libc::c_int != 0 {
        (*ctxt).pedantic = 1 as libc::c_int;
        options -= XML_PARSE_PEDANTIC as libc::c_int;
        (*ctxt).options |= XML_PARSE_PEDANTIC as libc::c_int;
    } else {
        (*ctxt).pedantic = 0 as libc::c_int;
    }
    if options & XML_PARSE_NOBLANKS as libc::c_int != 0 {
        (*ctxt).keepBlanks = 0 as libc::c_int;
        let ref mut fresh205 = (*(*ctxt).sax).ignorableWhitespace;
        *fresh205 = Some(
            xmlSAX2IgnorableWhitespace
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const xmlChar,
                    libc::c_int,
                ) -> (),
        );
        options -= XML_PARSE_NOBLANKS as libc::c_int;
        (*ctxt).options |= XML_PARSE_NOBLANKS as libc::c_int;
    } else {
        (*ctxt).keepBlanks = 1 as libc::c_int;
    }
    if options & HTML_PARSE_RECOVER as libc::c_int != 0 {
        (*ctxt).recovery = 1 as libc::c_int;
        options -= HTML_PARSE_RECOVER as libc::c_int;
    } else {
        (*ctxt).recovery = 0 as libc::c_int;
    }
    if options & HTML_PARSE_COMPACT as libc::c_int != 0 {
        (*ctxt).options |= HTML_PARSE_COMPACT as libc::c_int;
        options -= HTML_PARSE_COMPACT as libc::c_int;
    }
    if options & XML_PARSE_HUGE as libc::c_int != 0 {
        (*ctxt).options |= XML_PARSE_HUGE as libc::c_int;
        options -= XML_PARSE_HUGE as libc::c_int;
    }
    if options & HTML_PARSE_NODEFDTD as libc::c_int != 0 {
        (*ctxt).options |= HTML_PARSE_NODEFDTD as libc::c_int;
        options -= HTML_PARSE_NODEFDTD as libc::c_int;
    }
    if options & HTML_PARSE_IGNORE_ENC as libc::c_int != 0 {
        (*ctxt).options |= HTML_PARSE_IGNORE_ENC as libc::c_int;
        options -= HTML_PARSE_IGNORE_ENC as libc::c_int;
    }
    if options & HTML_PARSE_NOIMPLIED as libc::c_int != 0 {
        (*ctxt).options |= HTML_PARSE_NOIMPLIED as libc::c_int;
        options -= HTML_PARSE_NOIMPLIED as libc::c_int;
    }
    (*ctxt).dictNames = 0 as libc::c_int;
    return options;
}
unsafe extern "C" fn htmlDoRead(
    mut ctxt: htmlParserCtxtPtr,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
    mut reuse: libc::c_int,
) -> htmlDocPtr {
    let mut ret: htmlDocPtr = 0 as *mut xmlDoc;
    htmlCtxtUseOptions(ctxt, options);
    (*ctxt).html = 1 as libc::c_int;
    if !encoding.is_null() {
        let mut hdlr: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
        hdlr = xmlFindCharEncodingHandler(encoding);
        if !hdlr.is_null() {
            xmlSwitchToEncoding(ctxt, hdlr);
            if !((*(*ctxt).input).encoding).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*(*ctxt).input).encoding as *mut xmlChar as *mut libc::c_void);
            }
            let ref mut fresh206 = (*(*ctxt).input).encoding;
            *fresh206 = xmlStrdup(encoding as *mut xmlChar);
        }
    }
    if !URL.is_null() && !((*ctxt).input).is_null()
        && ((*(*ctxt).input).filename).is_null()
    {
        let ref mut fresh207 = (*(*ctxt).input).filename;
        *fresh207 = xmlStrdup(URL as *const xmlChar) as *mut libc::c_char;
    }
    htmlParseDocument(ctxt);
    ret = (*ctxt).myDoc;
    let ref mut fresh208 = (*ctxt).myDoc;
    *fresh208 = 0 as xmlDocPtr;
    if reuse == 0 {
        if (*ctxt).dictNames != 0 && !ret.is_null() && (*ret).dict == (*ctxt).dict {
            let ref mut fresh209 = (*ctxt).dict;
            *fresh209 = 0 as xmlDictPtr;
        }
        xmlFreeParserCtxt(ctxt);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn htmlReadDoc(
    mut cur: *const xmlChar,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> htmlDocPtr {
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    if cur.is_null() {
        return 0 as htmlDocPtr;
    }
    xmlInitParser();
    ctxt = htmlCreateDocParserCtxt(cur, 0 as *const libc::c_char);
    if ctxt.is_null() {
        return 0 as htmlDocPtr;
    }
    return htmlDoRead(ctxt, URL, encoding, options, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn htmlReadFile(
    mut filename: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> htmlDocPtr {
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = htmlCreateFileParserCtxt(filename, encoding);
    if ctxt.is_null() {
        return 0 as htmlDocPtr;
    }
    return htmlDoRead(
        ctxt,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        options,
        0 as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn htmlReadMemory(
    mut buffer: *const libc::c_char,
    mut size: libc::c_int,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> htmlDocPtr {
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if ctxt.is_null() {
        return 0 as htmlDocPtr;
    }
    htmlDefaultSAXHandlerInit();
    if !((*ctxt).sax).is_null() {
        memcpy(
            (*ctxt).sax as *mut libc::c_void,
            __htmlDefaultSAXHandler() as *const libc::c_void,
            ::std::mem::size_of::<xmlSAXHandlerV1>() as libc::c_ulong,
        );
    }
    return htmlDoRead(ctxt, URL, encoding, options, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn htmlReadFd(
    mut fd: libc::c_int,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> htmlDocPtr {
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: htmlParserInputPtr = 0 as *mut xmlParserInput;
    if fd < 0 as libc::c_int {
        return 0 as htmlDocPtr;
    }
    xmlInitParser();
    input = xmlParserInputBufferCreateFd(fd, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        return 0 as htmlDocPtr;
    }
    let ref mut fresh210 = (*input).closecallback;
    *fresh210 = None;
    ctxt = htmlNewParserCtxt();
    if ctxt.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as htmlDocPtr;
    }
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        htmlFreeParserCtxt(ctxt);
        return 0 as htmlDocPtr;
    }
    inputPush(ctxt, stream);
    return htmlDoRead(ctxt, URL, encoding, options, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn htmlReadIO(
    mut ioread: xmlInputReadCallback,
    mut ioclose: xmlInputCloseCallback,
    mut ioctx: *mut libc::c_void,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> htmlDocPtr {
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ioread.is_none() {
        return 0 as htmlDocPtr;
    }
    xmlInitParser();
    input = xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        if ioclose.is_some() {
            ioclose.expect("non-null function pointer")(ioctx);
        }
        return 0 as htmlDocPtr;
    }
    ctxt = htmlNewParserCtxt();
    if ctxt.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as htmlDocPtr;
    }
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        xmlFreeParserCtxt(ctxt);
        return 0 as htmlDocPtr;
    }
    inputPush(ctxt, stream);
    return htmlDoRead(ctxt, URL, encoding, options, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn htmlCtxtReadDoc(
    mut ctxt: htmlParserCtxtPtr,
    mut cur: *const xmlChar,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> htmlDocPtr {
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if cur.is_null() {
        return 0 as htmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as htmlDocPtr;
    }
    xmlInitParser();
    htmlCtxtReset(ctxt);
    stream = xmlNewStringInputStream(ctxt, cur);
    if stream.is_null() {
        return 0 as htmlDocPtr;
    }
    inputPush(ctxt, stream);
    return htmlDoRead(ctxt, URL, encoding, options, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn htmlCtxtReadFile(
    mut ctxt: htmlParserCtxtPtr,
    mut filename: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> htmlDocPtr {
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if filename.is_null() {
        return 0 as htmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as htmlDocPtr;
    }
    xmlInitParser();
    htmlCtxtReset(ctxt);
    stream = xmlLoadExternalEntity(filename, 0 as *const libc::c_char, ctxt);
    if stream.is_null() {
        return 0 as htmlDocPtr;
    }
    inputPush(ctxt, stream);
    return htmlDoRead(
        ctxt,
        0 as *const libc::c_char,
        encoding,
        options,
        1 as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn htmlCtxtReadMemory(
    mut ctxt: htmlParserCtxtPtr,
    mut buffer: *const libc::c_char,
    mut size: libc::c_int,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> htmlDocPtr {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ctxt.is_null() {
        return 0 as htmlDocPtr;
    }
    if buffer.is_null() {
        return 0 as htmlDocPtr;
    }
    xmlInitParser();
    htmlCtxtReset(ctxt);
    input = xmlParserInputBufferCreateMem(buffer, size, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        return 0 as htmlDocPtr;
    }
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as htmlDocPtr;
    }
    inputPush(ctxt, stream);
    return htmlDoRead(ctxt, URL, encoding, options, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn htmlCtxtReadFd(
    mut ctxt: htmlParserCtxtPtr,
    mut fd: libc::c_int,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> htmlDocPtr {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if fd < 0 as libc::c_int {
        return 0 as htmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as htmlDocPtr;
    }
    xmlInitParser();
    htmlCtxtReset(ctxt);
    input = xmlParserInputBufferCreateFd(fd, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        return 0 as htmlDocPtr;
    }
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as htmlDocPtr;
    }
    inputPush(ctxt, stream);
    return htmlDoRead(ctxt, URL, encoding, options, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn htmlCtxtReadIO(
    mut ctxt: htmlParserCtxtPtr,
    mut ioread: xmlInputReadCallback,
    mut ioclose: xmlInputCloseCallback,
    mut ioctx: *mut libc::c_void,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> htmlDocPtr {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ioread.is_none() {
        return 0 as htmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as htmlDocPtr;
    }
    xmlInitParser();
    htmlCtxtReset(ctxt);
    input = xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        if ioclose.is_some() {
            ioclose.expect("non-null function pointer")(ioctx);
        }
        return 0 as htmlDocPtr;
    }
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as htmlDocPtr;
    }
    inputPush(ctxt, stream);
    return htmlDoRead(ctxt, URL, encoding, options, 1 as libc::c_int);
}
