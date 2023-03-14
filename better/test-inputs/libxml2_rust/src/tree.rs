use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type _xmlBuf;
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlStartTag;
    pub type _xmlAutomataState;
    pub type _xmlAutomata;
    pub type _xmlValidState;
    pub type _xmlRegexp;
    static mut stdout: *mut FILE;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn fwrite(
        _: *const libc::c_void,
        _: libc::c_ulong,
        _: libc::c_ulong,
        _: *mut FILE,
    ) -> libc::c_ulong;
    fn xmlStrncatNew(
        str1: *const xmlChar,
        str2: *const xmlChar,
        len: libc::c_int,
    ) -> *mut xmlChar;
    fn xmlStrncat(
        cur: *mut xmlChar,
        add: *const xmlChar,
        len: libc::c_int,
    ) -> *mut xmlChar;
    fn xmlStrcat(cur: *mut xmlChar, add: *const xmlChar) -> *mut xmlChar;
    fn xmlStrlen(str: *const xmlChar) -> libc::c_int;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> libc::c_int;
    fn xmlStrcasecmp(str1: *const xmlChar, str2: *const xmlChar) -> libc::c_int;
    fn xmlStrncmp(
        str1: *const xmlChar,
        str2: *const xmlChar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn xmlStrchr(str: *const xmlChar, val: xmlChar) -> *const xmlChar;
    fn xmlStrndup(cur: *const xmlChar, len: libc::c_int) -> *mut xmlChar;
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    static mut xmlMalloc: xmlMallocFunc;
    static mut xmlMallocAtomic: xmlMallocFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlFree: xmlFreeFunc;
    static mut xmlMemStrdup: xmlStrdupFunc;
    fn __xmlBufferAllocScheme() -> *mut xmlBufferAllocationScheme;
    fn __xmlDefaultBufferSize() -> *mut libc::c_int;
    fn __xmlRegisterNodeDefaultValue() -> *mut xmlRegisterNodeFunc;
    fn xmlDictFree(dict: xmlDictPtr);
    fn xmlDictLookup(
        dict: xmlDictPtr,
        name: *const xmlChar,
        len: libc::c_int,
    ) -> *const xmlChar;
    fn xmlDictOwns(dict: xmlDictPtr, str: *const xmlChar) -> libc::c_int;
    fn __xmlSimpleError(
        domain: libc::c_int,
        code: libc::c_int,
        node: xmlNodePtr,
        msg: *const libc::c_char,
        extra: *const libc::c_char,
    );
    fn xmlFreeEntitiesTable(table: xmlEntitiesTablePtr);
    fn xmlFreeAttributeTable(table: xmlAttributeTablePtr);
    fn xmlFreeElementTable(table: xmlElementTablePtr);
    fn xmlFreeNotationTable(table: xmlNotationTablePtr);
    fn __xmlDeregisterNodeDefaultValue() -> *mut xmlDeregisterNodeFunc;
    fn xmlHashRemoveEntry(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        f: xmlHashDeallocator,
    ) -> libc::c_int;
    fn xmlHashLookup(table: xmlHashTablePtr, name: *const xmlChar) -> *mut libc::c_void;
    fn xmlFreeRefTable(table: xmlRefTablePtr);
    fn xmlFreeIDTable(table: xmlIDTablePtr);
    fn xmlRemoveID(doc: xmlDocPtr, attr: xmlAttrPtr) -> libc::c_int;
    fn xmlGetDtdQAttrDesc(
        dtd: xmlDtdPtr,
        elem: *const xmlChar,
        name: *const xmlChar,
        prefix: *const xmlChar,
    ) -> xmlAttributePtr;
    fn xmlGetDocEntity(doc: *const xmlDoc, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlAddID(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        value: *const xmlChar,
        attr: xmlAttrPtr,
    ) -> xmlIDPtr;
    fn xmlIsID(doc: xmlDocPtr, elem: xmlNodePtr, attr: xmlAttrPtr) -> libc::c_int;
    fn xmlEncodeEntitiesReentrant(doc: xmlDocPtr, input: *const xmlChar) -> *mut xmlChar;
    fn xmlGetDtdQElementDesc(
        dtd: xmlDtdPtr,
        name: *const xmlChar,
        prefix: *const xmlChar,
    ) -> xmlElementPtr;
    fn xmlCopyEntitiesTable(table: xmlEntitiesTablePtr) -> xmlEntitiesTablePtr;
    fn xmlCopyAttributeTable(table: xmlAttributeTablePtr) -> xmlAttributeTablePtr;
    fn xmlCopyElementTable(table: xmlElementTablePtr) -> xmlElementTablePtr;
    fn xmlCopyNotationTable(table: xmlNotationTablePtr) -> xmlNotationTablePtr;
    fn xmlGetDtdAttrDesc(
        dtd: xmlDtdPtr,
        elem: *const xmlChar,
        name: *const xmlChar,
    ) -> xmlAttributePtr;
    fn xmlEncodeSpecialChars(doc: *const xmlDoc, input: *const xmlChar) -> *mut xmlChar;
    fn xmlBuildURI(URI: *const xmlChar, base: *const xmlChar) -> *mut xmlChar;
    fn xmlPathToURI(path: *const xmlChar) -> *mut xmlChar;
    fn xmlStringCurrentChar(
        ctxt: xmlParserCtxtPtr,
        cur: *const xmlChar,
        len: *mut libc::c_int,
    ) -> libc::c_int;
    fn xmlCopyCharMultiByte(out: *mut xmlChar, val: libc::c_int) -> libc::c_int;
    static xmlIsBaseCharGroup: xmlChRangeGroup;
    static xmlIsDigitGroup: xmlChRangeGroup;
    static xmlIsCombiningGroup: xmlChRangeGroup;
    fn xmlCharInRange(val: libc::c_uint, group: *const xmlChRangeGroup) -> libc::c_int;
    static xmlIsExtenderGroup: xmlChRangeGroup;
    fn xmlBufCreate() -> xmlBufPtr;
    fn xmlBufCreateSize(size: size_t) -> xmlBufPtr;
    fn xmlBufSetAllocationScheme(
        buf: xmlBufPtr,
        scheme: xmlBufferAllocationScheme,
    ) -> libc::c_int;
    fn xmlBufFree(buf: xmlBufPtr);
    fn xmlBufAdd(buf: xmlBufPtr, str: *const xmlChar, len: libc::c_int) -> libc::c_int;
    fn xmlBufCat(buf: xmlBufPtr, str: *const xmlChar) -> libc::c_int;
    fn xmlBufIsEmpty(buf: xmlBufPtr) -> libc::c_int;
    fn xmlBufDetach(buf: xmlBufPtr) -> *mut xmlChar;
    fn xmlBufFromBuffer(buffer: xmlBufferPtr) -> xmlBufPtr;
    fn xmlBufBackToBuffer(buf: xmlBufPtr) -> xmlBufferPtr;
    fn xmlEncodeAttributeEntities(doc: xmlDocPtr, input: *const xmlChar) -> *mut xmlChar;
}
pub type xmlChar = libc::c_uchar;
pub type size_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type ptrdiff_t = libc::c_long;
pub type xmlFreeFunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type xmlMallocFunc = Option::<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type xmlReallocFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
>;
pub type xmlStrdupFunc = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
>;
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
pub type xmlBufferAllocationScheme = libc::c_uint;
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
    pub use_0: libc::c_uint,
    pub size: libc::c_uint,
    pub alloc: xmlBufferAllocationScheme,
    pub contentIO: *mut xmlChar,
}
pub type xmlBuffer = _xmlBuffer;
pub type xmlBufferPtr = *mut xmlBuffer;
pub type xmlAttributeDefault = libc::c_uint;
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
pub type xmlElementTypeVal = libc::c_uint;
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
    pub lineno: libc::c_int,
    pub doc: *mut _xmlDoc,
}
pub type xmlID = _xmlID;
pub type xmlIDPtr = *mut xmlID;
pub type C2RustUnnamed = libc::c_uint;
pub const XML_DOC_HTML: C2RustUnnamed = 128;
pub const XML_DOC_INTERNAL: C2RustUnnamed = 64;
pub const XML_DOC_USERBUILT: C2RustUnnamed = 32;
pub const XML_DOC_XINCLUDE: C2RustUnnamed = 16;
pub const XML_DOC_DTDVALID: C2RustUnnamed = 8;
pub const XML_DOC_OLD10: C2RustUnnamed = 4;
pub const XML_DOC_NSVALID: C2RustUnnamed = 2;
pub const XML_DOC_WELLFORMED: C2RustUnnamed = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDOMWrapCtxt {
    pub _private: *mut libc::c_void,
    pub type_0: libc::c_int,
    pub namespaceMap: *mut libc::c_void,
    pub getNsForNodeFunc: xmlDOMWrapAcquireNsFunction,
}
pub type xmlDOMWrapAcquireNsFunction = Option::<
    unsafe extern "C" fn(
        xmlDOMWrapCtxtPtr,
        xmlNodePtr,
        *const xmlChar,
        *const xmlChar,
    ) -> xmlNsPtr,
>;
pub type xmlDOMWrapCtxtPtr = *mut xmlDOMWrapCtxt;
pub type xmlDOMWrapCtxt = _xmlDOMWrapCtxt;
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
pub const XML_ERR_NO_MEMORY: C2RustUnnamed_1 = 2;
pub const XML_FROM_TREE: C2RustUnnamed_0 = 2;
pub type xmlRegisterNodeFunc = Option::<unsafe extern "C" fn(xmlNodePtr) -> ()>;
pub type xmlEntitiesTablePtr = *mut xmlEntitiesTable;
pub type xmlEntitiesTable = _xmlHashTable;
pub type xmlAttributeTablePtr = *mut xmlAttributeTable;
pub type xmlAttributeTable = _xmlHashTable;
pub type xmlElementTablePtr = *mut xmlElementTable;
pub type xmlElementTable = _xmlHashTable;
pub type xmlNotationTablePtr = *mut xmlNotationTable;
pub type xmlNotationTable = _xmlHashTable;
pub type xmlDeregisterNodeFunc = Option::<unsafe extern "C" fn(xmlNodePtr) -> ()>;
pub type xmlHashDeallocator = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
>;
pub type xmlRefTablePtr = *mut xmlRefTable;
pub type xmlRefTable = _xmlHashTable;
pub type xmlIDTablePtr = *mut xmlIDTable;
pub type xmlIDTable = _xmlHashTable;
pub const XML_CHAR_ENCODING_UTF8: C2RustUnnamed_2 = 1;
pub const XML_TREE_UNTERMINATED_ENTITY: C2RustUnnamed_1 = 1302;
pub const XML_TREE_NOT_UTF8: C2RustUnnamed_1 = 1303;
pub const XML_TREE_INVALID_DEC: C2RustUnnamed_1 = 1301;
pub const XML_TREE_INVALID_HEX: C2RustUnnamed_1 = 1300;
pub type xmlValidCtxtPtr = *mut xmlValidCtxt;
pub type xmlNsMapPtr = *mut xmlNsMap;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlNsMap {
    pub first: xmlNsMapItemPtr,
    pub last: xmlNsMapItemPtr,
    pub pool: xmlNsMapItemPtr,
}
pub type xmlNsMapItemPtr = *mut xmlNsMapItem;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlNsMapItem {
    pub next: xmlNsMapItemPtr,
    pub prev: xmlNsMapItemPtr,
    pub oldNs: xmlNsPtr,
    pub newNs: xmlNsPtr,
    pub shadowDepth: libc::c_int,
    pub depth: libc::c_int,
}
pub const XML_DOM_RECONNS_REMOVEREDUND: xmlDOMReconcileNSOptions = 1;
pub type xmlDOMReconcileNSOptions = libc::c_uint;
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
pub const XML_FROM_HTML: C2RustUnnamed_0 = 5;
pub const XML_FROM_DTD: C2RustUnnamed_0 = 4;
pub const XML_FROM_NAMESPACE: C2RustUnnamed_0 = 3;
pub const XML_FROM_PARSER: C2RustUnnamed_0 = 1;
pub const XML_FROM_NONE: C2RustUnnamed_0 = 0;
pub type C2RustUnnamed_1 = libc::c_uint;
pub const XML_BUF_OVERFLOW: C2RustUnnamed_1 = 7000;
pub const XML_I18N_NO_OUTPUT: C2RustUnnamed_1 = 6004;
pub const XML_I18N_CONV_FAILED: C2RustUnnamed_1 = 6003;
pub const XML_I18N_EXCESS_HANDLER: C2RustUnnamed_1 = 6002;
pub const XML_I18N_NO_HANDLER: C2RustUnnamed_1 = 6001;
pub const XML_I18N_NO_NAME: C2RustUnnamed_1 = 6000;
pub const XML_CHECK_NAME_NOT_NULL: C2RustUnnamed_1 = 5037;
pub const XML_CHECK_WRONG_NAME: C2RustUnnamed_1 = 5036;
pub const XML_CHECK_OUTSIDE_DICT: C2RustUnnamed_1 = 5035;
pub const XML_CHECK_NOT_NCNAME: C2RustUnnamed_1 = 5034;
pub const XML_CHECK_NO_DICT: C2RustUnnamed_1 = 5033;
pub const XML_CHECK_NOT_UTF8: C2RustUnnamed_1 = 5032;
pub const XML_CHECK_NS_ANCESTOR: C2RustUnnamed_1 = 5031;
pub const XML_CHECK_NS_SCOPE: C2RustUnnamed_1 = 5030;
pub const XML_CHECK_WRONG_PARENT: C2RustUnnamed_1 = 5029;
pub const XML_CHECK_NO_HREF: C2RustUnnamed_1 = 5028;
pub const XML_CHECK_NOT_NS_DECL: C2RustUnnamed_1 = 5027;
pub const XML_CHECK_NOT_ENTITY_DECL: C2RustUnnamed_1 = 5026;
pub const XML_CHECK_NOT_ELEM_DECL: C2RustUnnamed_1 = 5025;
pub const XML_CHECK_NOT_ATTR_DECL: C2RustUnnamed_1 = 5024;
pub const XML_CHECK_NOT_ATTR: C2RustUnnamed_1 = 5023;
pub const XML_CHECK_NOT_DTD: C2RustUnnamed_1 = 5022;
pub const XML_CHECK_WRONG_NEXT: C2RustUnnamed_1 = 5021;
pub const XML_CHECK_NO_NEXT: C2RustUnnamed_1 = 5020;
pub const XML_CHECK_WRONG_PREV: C2RustUnnamed_1 = 5019;
pub const XML_CHECK_NO_PREV: C2RustUnnamed_1 = 5018;
pub const XML_CHECK_WRONG_DOC: C2RustUnnamed_1 = 5017;
pub const XML_CHECK_NO_ELEM: C2RustUnnamed_1 = 5016;
pub const XML_CHECK_NO_NAME: C2RustUnnamed_1 = 5015;
pub const XML_CHECK_NO_DOC: C2RustUnnamed_1 = 5014;
pub const XML_CHECK_NO_PARENT: C2RustUnnamed_1 = 5013;
pub const XML_CHECK_ENTITY_TYPE: C2RustUnnamed_1 = 5012;
pub const XML_CHECK_UNKNOWN_NODE: C2RustUnnamed_1 = 5011;
pub const XML_CHECK_FOUND_NOTATION: C2RustUnnamed_1 = 5010;
pub const XML_CHECK_FOUND_FRAGMENT: C2RustUnnamed_1 = 5009;
pub const XML_CHECK_FOUND_DOCTYPE: C2RustUnnamed_1 = 5008;
pub const XML_CHECK_FOUND_COMMENT: C2RustUnnamed_1 = 5007;
pub const XML_CHECK_FOUND_PI: C2RustUnnamed_1 = 5006;
pub const XML_CHECK_FOUND_ENTITY: C2RustUnnamed_1 = 5005;
pub const XML_CHECK_FOUND_ENTITYREF: C2RustUnnamed_1 = 5004;
pub const XML_CHECK_FOUND_CDATA: C2RustUnnamed_1 = 5003;
pub const XML_CHECK_FOUND_TEXT: C2RustUnnamed_1 = 5002;
pub const XML_CHECK_FOUND_ATTRIBUTE: C2RustUnnamed_1 = 5001;
pub const XML_CHECK_FOUND_ELEMENT: C2RustUnnamed_1 = 5000;
pub const XML_MODULE_CLOSE: C2RustUnnamed_1 = 4901;
pub const XML_MODULE_OPEN: C2RustUnnamed_1 = 4900;
pub const XML_SCHEMATRONV_REPORT: C2RustUnnamed_1 = 4001;
pub const XML_SCHEMATRONV_ASSERT: C2RustUnnamed_1 = 4000;
pub const XML_SCHEMAP_COS_ALL_LIMITED: C2RustUnnamed_1 = 3091;
pub const XML_SCHEMAP_A_PROPS_CORRECT_3: C2RustUnnamed_1 = 3090;
pub const XML_SCHEMAP_AU_PROPS_CORRECT: C2RustUnnamed_1 = 3089;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_2: C2RustUnnamed_1 = 3088;
pub const XML_SCHEMAP_AG_PROPS_CORRECT: C2RustUnnamed_1 = 3087;
pub const XML_SCHEMAP_WARN_ATTR_POINTLESS_PROH: C2RustUnnamed_1 = 3086;
pub const XML_SCHEMAP_WARN_ATTR_REDECL_PROH: C2RustUnnamed_1 = 3085;
pub const XML_SCHEMAP_WARN_UNLOCATED_SCHEMA: C2RustUnnamed_1 = 3084;
pub const XML_SCHEMAP_WARN_SKIP_SCHEMA: C2RustUnnamed_1 = 3083;
pub const XML_SCHEMAP_SRC_IMPORT: C2RustUnnamed_1 = 3082;
pub const XML_SCHEMAP_SRC_REDEFINE: C2RustUnnamed_1 = 3081;
pub const XML_SCHEMAP_C_PROPS_CORRECT: C2RustUnnamed_1 = 3080;
pub const XML_SCHEMAP_A_PROPS_CORRECT_2: C2RustUnnamed_1 = 3079;
pub const XML_SCHEMAP_AU_PROPS_CORRECT_2: C2RustUnnamed_1 = 3078;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_3: C2RustUnnamed_1 = 3077;
pub const XML_SCHEMAP_SRC_CT_1: C2RustUnnamed_1 = 3076;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_2: C2RustUnnamed_1 = 3075;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_1: C2RustUnnamed_1 = 3074;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_3: C2RustUnnamed_1 = 3073;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_2: C2RustUnnamed_1 = 3072;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_1: C2RustUnnamed_1 = 3071;
pub const XML_SCHEMAP_NOT_DETERMINISTIC: C2RustUnnamed_1 = 3070;
pub const XML_SCHEMAP_INTERNAL: C2RustUnnamed_1 = 3069;
pub const XML_SCHEMAP_SRC_IMPORT_2_2: C2RustUnnamed_1 = 3068;
pub const XML_SCHEMAP_SRC_IMPORT_2_1: C2RustUnnamed_1 = 3067;
pub const XML_SCHEMAP_SRC_IMPORT_2: C2RustUnnamed_1 = 3066;
pub const XML_SCHEMAP_SRC_IMPORT_1_2: C2RustUnnamed_1 = 3065;
pub const XML_SCHEMAP_SRC_IMPORT_1_1: C2RustUnnamed_1 = 3064;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_1: C2RustUnnamed_1 = 3063;
pub const XML_SCHEMAP_CVC_SIMPLE_TYPE: C2RustUnnamed_1 = 3062;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_2: C2RustUnnamed_1 = 3061;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_1: C2RustUnnamed_1 = 3060;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_1: C2RustUnnamed_1 = 3059;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_1: C2RustUnnamed_1 = 3058;
pub const XML_SCHEMAP_NO_XSI: C2RustUnnamed_1 = 3057;
pub const XML_SCHEMAP_NO_XMLNS: C2RustUnnamed_1 = 3056;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_4: C2RustUnnamed_1 = 3055;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_2: C2RustUnnamed_1 = 3054;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_1: C2RustUnnamed_1 = 3053;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_2: C2RustUnnamed_1 = 3052;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_1: C2RustUnnamed_1 = 3051;
pub const XML_SCHEMAP_SRC_INCLUDE: C2RustUnnamed_1 = 3050;
pub const XML_SCHEMAP_E_PROPS_CORRECT_6: C2RustUnnamed_1 = 3049;
pub const XML_SCHEMAP_E_PROPS_CORRECT_5: C2RustUnnamed_1 = 3048;
pub const XML_SCHEMAP_E_PROPS_CORRECT_4: C2RustUnnamed_1 = 3047;
pub const XML_SCHEMAP_E_PROPS_CORRECT_3: C2RustUnnamed_1 = 3046;
pub const XML_SCHEMAP_E_PROPS_CORRECT_2: C2RustUnnamed_1 = 3045;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_2: C2RustUnnamed_1 = 3044;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_1: C2RustUnnamed_1 = 3043;
pub const XML_SCHEMAP_P_PROPS_CORRECT_1: C2RustUnnamed_1 = 3042;
pub const XML_SCHEMAP_SRC_ELEMENT_3: C2RustUnnamed_1 = 3041;
pub const XML_SCHEMAP_SRC_ELEMENT_2_2: C2RustUnnamed_1 = 3040;
pub const XML_SCHEMAP_SRC_ELEMENT_2_1: C2RustUnnamed_1 = 3039;
pub const XML_SCHEMAP_SRC_ELEMENT_1: C2RustUnnamed_1 = 3038;
pub const XML_SCHEMAP_S4S_ATTR_INVALID_VALUE: C2RustUnnamed_1 = 3037;
pub const XML_SCHEMAP_S4S_ATTR_MISSING: C2RustUnnamed_1 = 3036;
pub const XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED: C2RustUnnamed_1 = 3035;
pub const XML_SCHEMAP_S4S_ELEM_MISSING: C2RustUnnamed_1 = 3034;
pub const XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED: C2RustUnnamed_1 = 3033;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_2: C2RustUnnamed_1 = 3032;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_1: C2RustUnnamed_1 = 3031;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_5: C2RustUnnamed_1 = 3030;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_4: C2RustUnnamed_1 = 3029;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_3: C2RustUnnamed_1 = 3028;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_1: C2RustUnnamed_1 = 3027;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_2: C2RustUnnamed_1 = 3026;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1_2: C2RustUnnamed_1 = 3025;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1: C2RustUnnamed_1 = 3024;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_1: C2RustUnnamed_1 = 3023;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_5: C2RustUnnamed_1 = 3022;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_4: C2RustUnnamed_1 = 3021;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_3: C2RustUnnamed_1 = 3020;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_2: C2RustUnnamed_1 = 3019;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_1: C2RustUnnamed_1 = 3018;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_2: C2RustUnnamed_1 = 3017;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_1: C2RustUnnamed_1 = 3016;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_1: C2RustUnnamed_1 = 3015;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_2: C2RustUnnamed_1 = 3014;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_1: C2RustUnnamed_1 = 3013;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_2: C2RustUnnamed_1 = 3012;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_1: C2RustUnnamed_1 = 3011;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_3: C2RustUnnamed_1 = 3010;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_2: C2RustUnnamed_1 = 3009;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_1: C2RustUnnamed_1 = 3008;
pub const XML_SCHEMAP_SRC_UNION_MEMBERTYPES_OR_SIMPLETYPES: C2RustUnnamed_1 = 3007;
pub const XML_SCHEMAP_SRC_LIST_ITEMTYPE_OR_SIMPLETYPE: C2RustUnnamed_1 = 3006;
pub const XML_SCHEMAP_SRC_RESTRICTION_BASE_OR_SIMPLETYPE: C2RustUnnamed_1 = 3005;
pub const XML_SCHEMAP_SRC_RESOLVE: C2RustUnnamed_1 = 3004;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_4: C2RustUnnamed_1 = 3003;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_3: C2RustUnnamed_1 = 3002;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_2: C2RustUnnamed_1 = 3001;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_1: C2RustUnnamed_1 = 3000;
pub const XML_HTTP_UNKNOWN_HOST: C2RustUnnamed_1 = 2022;
pub const XML_HTTP_USE_IP: C2RustUnnamed_1 = 2021;
pub const XML_HTTP_URL_SYNTAX: C2RustUnnamed_1 = 2020;
pub const XML_FTP_URL_SYNTAX: C2RustUnnamed_1 = 2003;
pub const XML_FTP_ACCNT: C2RustUnnamed_1 = 2002;
pub const XML_FTP_EPSV_ANSWER: C2RustUnnamed_1 = 2001;
pub const XML_FTP_PASV_ANSWER: C2RustUnnamed_1 = 2000;
pub const XML_C14N_RELATIVE_NAMESPACE: C2RustUnnamed_1 = 1955;
pub const XML_C14N_UNKNOW_NODE: C2RustUnnamed_1 = 1954;
pub const XML_C14N_INVALID_NODE: C2RustUnnamed_1 = 1953;
pub const XML_C14N_CREATE_STACK: C2RustUnnamed_1 = 1952;
pub const XML_C14N_REQUIRES_UTF8: C2RustUnnamed_1 = 1951;
pub const XML_C14N_CREATE_CTXT: C2RustUnnamed_1 = 1950;
pub const XML_XPTR_EXTRA_OBJECTS: C2RustUnnamed_1 = 1903;
pub const XML_XPTR_EVAL_FAILED: C2RustUnnamed_1 = 1902;
pub const XML_XPTR_CHILDSEQ_START: C2RustUnnamed_1 = 1901;
pub const XML_XPTR_UNKNOWN_SCHEME: C2RustUnnamed_1 = 1900;
pub const XML_SCHEMAV_MISC: C2RustUnnamed_1 = 1879;
pub const XML_SCHEMAV_CVC_WILDCARD: C2RustUnnamed_1 = 1878;
pub const XML_SCHEMAV_CVC_IDC: C2RustUnnamed_1 = 1877;
pub const XML_SCHEMAV_CVC_TYPE_2: C2RustUnnamed_1 = 1876;
pub const XML_SCHEMAV_CVC_TYPE_1: C2RustUnnamed_1 = 1875;
pub const XML_SCHEMAV_CVC_AU: C2RustUnnamed_1 = 1874;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_1: C2RustUnnamed_1 = 1873;
pub const XML_SCHEMAV_DOCUMENT_ELEMENT_MISSING: C2RustUnnamed_1 = 1872;
pub const XML_SCHEMAV_ELEMENT_CONTENT: C2RustUnnamed_1 = 1871;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_2: C2RustUnnamed_1 = 1870;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_1: C2RustUnnamed_1 = 1869;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_4: C2RustUnnamed_1 = 1868;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_2: C2RustUnnamed_1 = 1867;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_1: C2RustUnnamed_1 = 1866;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_1: C2RustUnnamed_1 = 1865;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_4: C2RustUnnamed_1 = 1864;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_3: C2RustUnnamed_1 = 1863;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_2: C2RustUnnamed_1 = 1862;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_1: C2RustUnnamed_1 = 1861;
pub const XML_SCHEMAV_CVC_ELT_7: C2RustUnnamed_1 = 1860;
pub const XML_SCHEMAV_CVC_ELT_6: C2RustUnnamed_1 = 1859;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_2: C2RustUnnamed_1 = 1858;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_1: C2RustUnnamed_1 = 1857;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_1: C2RustUnnamed_1 = 1856;
pub const XML_SCHEMAV_CVC_ELT_5_2_1: C2RustUnnamed_1 = 1855;
pub const XML_SCHEMAV_CVC_ELT_5_1_2: C2RustUnnamed_1 = 1854;
pub const XML_SCHEMAV_CVC_ELT_5_1_1: C2RustUnnamed_1 = 1853;
pub const XML_SCHEMAV_CVC_ELT_4_3: C2RustUnnamed_1 = 1852;
pub const XML_SCHEMAV_CVC_ELT_4_2: C2RustUnnamed_1 = 1851;
pub const XML_SCHEMAV_CVC_ELT_4_1: C2RustUnnamed_1 = 1850;
pub const XML_SCHEMAV_CVC_ELT_3_2_2: C2RustUnnamed_1 = 1849;
pub const XML_SCHEMAV_CVC_ELT_3_2_1: C2RustUnnamed_1 = 1848;
pub const XML_SCHEMAV_CVC_ELT_3_1: C2RustUnnamed_1 = 1847;
pub const XML_SCHEMAV_CVC_ELT_2: C2RustUnnamed_1 = 1846;
pub const XML_SCHEMAV_CVC_ELT_1: C2RustUnnamed_1 = 1845;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_4: C2RustUnnamed_1 = 1844;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_3: C2RustUnnamed_1 = 1843;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2: C2RustUnnamed_1 = 1842;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_1: C2RustUnnamed_1 = 1841;
pub const XML_SCHEMAV_CVC_ENUMERATION_VALID: C2RustUnnamed_1 = 1840;
pub const XML_SCHEMAV_CVC_PATTERN_VALID: C2RustUnnamed_1 = 1839;
pub const XML_SCHEMAV_CVC_FRACTIONDIGITS_VALID: C2RustUnnamed_1 = 1838;
pub const XML_SCHEMAV_CVC_TOTALDIGITS_VALID: C2RustUnnamed_1 = 1837;
pub const XML_SCHEMAV_CVC_MAXEXCLUSIVE_VALID: C2RustUnnamed_1 = 1836;
pub const XML_SCHEMAV_CVC_MINEXCLUSIVE_VALID: C2RustUnnamed_1 = 1835;
pub const XML_SCHEMAV_CVC_MAXINCLUSIVE_VALID: C2RustUnnamed_1 = 1834;
pub const XML_SCHEMAV_CVC_MININCLUSIVE_VALID: C2RustUnnamed_1 = 1833;
pub const XML_SCHEMAV_CVC_MAXLENGTH_VALID: C2RustUnnamed_1 = 1832;
pub const XML_SCHEMAV_CVC_MINLENGTH_VALID: C2RustUnnamed_1 = 1831;
pub const XML_SCHEMAV_CVC_LENGTH_VALID: C2RustUnnamed_1 = 1830;
pub const XML_SCHEMAV_CVC_FACET_VALID: C2RustUnnamed_1 = 1829;
pub const XML_SCHEMAV_CVC_TYPE_3_1_2: C2RustUnnamed_1 = 1828;
pub const XML_SCHEMAV_CVC_TYPE_3_1_1: C2RustUnnamed_1 = 1827;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_3: C2RustUnnamed_1 = 1826;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2: C2RustUnnamed_1 = 1825;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1: C2RustUnnamed_1 = 1824;
pub const XML_SCHEMAV_FACET: C2RustUnnamed_1 = 1823;
pub const XML_SCHEMAV_VALUE: C2RustUnnamed_1 = 1822;
pub const XML_SCHEMAV_ATTRINVALID: C2RustUnnamed_1 = 1821;
pub const XML_SCHEMAV_ATTRUNKNOWN: C2RustUnnamed_1 = 1820;
pub const XML_SCHEMAV_NOTSIMPLE: C2RustUnnamed_1 = 1819;
pub const XML_SCHEMAV_INTERNAL: C2RustUnnamed_1 = 1818;
pub const XML_SCHEMAV_CONSTRUCT: C2RustUnnamed_1 = 1817;
pub const XML_SCHEMAV_NOTDETERMINIST: C2RustUnnamed_1 = 1816;
pub const XML_SCHEMAV_INVALIDELEM: C2RustUnnamed_1 = 1815;
pub const XML_SCHEMAV_INVALIDATTR: C2RustUnnamed_1 = 1814;
pub const XML_SCHEMAV_EXTRACONTENT: C2RustUnnamed_1 = 1813;
pub const XML_SCHEMAV_NOTNILLABLE: C2RustUnnamed_1 = 1812;
pub const XML_SCHEMAV_HAVEDEFAULT: C2RustUnnamed_1 = 1811;
pub const XML_SCHEMAV_ELEMCONT: C2RustUnnamed_1 = 1810;
pub const XML_SCHEMAV_NOTEMPTY: C2RustUnnamed_1 = 1809;
pub const XML_SCHEMAV_ISABSTRACT: C2RustUnnamed_1 = 1808;
pub const XML_SCHEMAV_NOROLLBACK: C2RustUnnamed_1 = 1807;
pub const XML_SCHEMAV_NOTYPE: C2RustUnnamed_1 = 1806;
pub const XML_SCHEMAV_WRONGELEM: C2RustUnnamed_1 = 1805;
pub const XML_SCHEMAV_MISSING: C2RustUnnamed_1 = 1804;
pub const XML_SCHEMAV_NOTTOPLEVEL: C2RustUnnamed_1 = 1803;
pub const XML_SCHEMAV_UNDECLAREDELEM: C2RustUnnamed_1 = 1802;
pub const XML_SCHEMAV_NOROOT: C2RustUnnamed_1 = 1801;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_3: C2RustUnnamed_1 = 1800;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_3: C2RustUnnamed_1 = 1799;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_2: C2RustUnnamed_1 = 1798;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_1: C2RustUnnamed_1 = 1797;
pub const XML_SCHEMAP_SRC_IMPORT_3_2: C2RustUnnamed_1 = 1796;
pub const XML_SCHEMAP_SRC_IMPORT_3_1: C2RustUnnamed_1 = 1795;
pub const XML_SCHEMAP_UNION_NOT_EXPRESSIBLE: C2RustUnnamed_1 = 1794;
pub const XML_SCHEMAP_INTERSECTION_NOT_EXPRESSIBLE: C2RustUnnamed_1 = 1793;
pub const XML_SCHEMAP_WILDCARD_INVALID_NS_MEMBER: C2RustUnnamed_1 = 1792;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_3: C2RustUnnamed_1 = 1791;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_2: C2RustUnnamed_1 = 1790;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_2: C2RustUnnamed_1 = 1789;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_1: C2RustUnnamed_1 = 1788;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_1: C2RustUnnamed_1 = 1787;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_5: C2RustUnnamed_1 = 1786;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_4: C2RustUnnamed_1 = 1785;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_3: C2RustUnnamed_1 = 1784;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_2: C2RustUnnamed_1 = 1783;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_1: C2RustUnnamed_1 = 1782;
pub const XML_SCHEMAP_REF_AND_CONTENT: C2RustUnnamed_1 = 1781;
pub const XML_SCHEMAP_INVALID_ATTR_NAME: C2RustUnnamed_1 = 1780;
pub const XML_SCHEMAP_MISSING_SIMPLETYPE_CHILD: C2RustUnnamed_1 = 1779;
pub const XML_SCHEMAP_INVALID_ATTR_INLINE_COMBINATION: C2RustUnnamed_1 = 1778;
pub const XML_SCHEMAP_INVALID_ATTR_COMBINATION: C2RustUnnamed_1 = 1777;
pub const XML_SCHEMAP_SUPERNUMEROUS_LIST_ITEM_TYPE: C2RustUnnamed_1 = 1776;
pub const XML_SCHEMAP_RECURSIVE: C2RustUnnamed_1 = 1775;
pub const XML_SCHEMAP_INVALID_ATTR_USE: C2RustUnnamed_1 = 1774;
pub const XML_SCHEMAP_UNKNOWN_MEMBER_TYPE: C2RustUnnamed_1 = 1773;
pub const XML_SCHEMAP_NOT_SCHEMA: C2RustUnnamed_1 = 1772;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NO_URI: C2RustUnnamed_1 = 1771;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NOT_URI: C2RustUnnamed_1 = 1770;
pub const XML_SCHEMAP_UNKNOWN_INCLUDE_CHILD: C2RustUnnamed_1 = 1769;
pub const XML_SCHEMAP_DEF_AND_PREFIX: C2RustUnnamed_1 = 1768;
pub const XML_SCHEMAP_UNKNOWN_PREFIX: C2RustUnnamed_1 = 1767;
pub const XML_SCHEMAP_FAILED_PARSE: C2RustUnnamed_1 = 1766;
pub const XML_SCHEMAP_REDEFINED_NOTATION: C2RustUnnamed_1 = 1765;
pub const XML_SCHEMAP_REDEFINED_ATTR: C2RustUnnamed_1 = 1764;
pub const XML_SCHEMAP_REDEFINED_ATTRGROUP: C2RustUnnamed_1 = 1763;
pub const XML_SCHEMAP_REDEFINED_ELEMENT: C2RustUnnamed_1 = 1762;
pub const XML_SCHEMAP_REDEFINED_TYPE: C2RustUnnamed_1 = 1761;
pub const XML_SCHEMAP_REDEFINED_GROUP: C2RustUnnamed_1 = 1760;
pub const XML_SCHEMAP_NOROOT: C2RustUnnamed_1 = 1759;
pub const XML_SCHEMAP_NOTHING_TO_PARSE: C2RustUnnamed_1 = 1758;
pub const XML_SCHEMAP_FAILED_LOAD: C2RustUnnamed_1 = 1757;
pub const XML_SCHEMAP_REGEXP_INVALID: C2RustUnnamed_1 = 1756;
pub const XML_SCHEMAP_ELEM_DEFAULT_FIXED: C2RustUnnamed_1 = 1755;
pub const XML_SCHEMAP_UNKNOWN_UNION_CHILD: C2RustUnnamed_1 = 1754;
pub const XML_SCHEMAP_UNKNOWN_TYPE: C2RustUnnamed_1 = 1753;
pub const XML_SCHEMAP_UNKNOWN_SIMPLETYPE_CHILD: C2RustUnnamed_1 = 1752;
pub const XML_SCHEMAP_UNKNOWN_SIMPLECONTENT_CHILD: C2RustUnnamed_1 = 1751;
pub const XML_SCHEMAP_UNKNOWN_SEQUENCE_CHILD: C2RustUnnamed_1 = 1750;
pub const XML_SCHEMAP_UNKNOWN_SCHEMAS_CHILD: C2RustUnnamed_1 = 1749;
pub const XML_SCHEMAP_UNKNOWN_RESTRICTION_CHILD: C2RustUnnamed_1 = 1748;
pub const XML_SCHEMAP_UNKNOWN_REF: C2RustUnnamed_1 = 1747;
pub const XML_SCHEMAP_UNKNOWN_PROCESSCONTENT_CHILD: C2RustUnnamed_1 = 1746;
pub const XML_SCHEMAP_UNKNOWN_NOTATION_CHILD: C2RustUnnamed_1 = 1745;
pub const XML_SCHEMAP_UNKNOWN_LIST_CHILD: C2RustUnnamed_1 = 1744;
pub const XML_SCHEMAP_UNKNOWN_IMPORT_CHILD: C2RustUnnamed_1 = 1743;
pub const XML_SCHEMAP_UNKNOWN_GROUP_CHILD: C2RustUnnamed_1 = 1742;
pub const XML_SCHEMAP_UNKNOWN_FACET_TYPE: C2RustUnnamed_1 = 1741;
pub const XML_SCHEMAP_UNKNOWN_FACET_CHILD: C2RustUnnamed_1 = 1740;
pub const XML_SCHEMAP_UNKNOWN_EXTENSION_CHILD: C2RustUnnamed_1 = 1739;
pub const XML_SCHEMAP_UNKNOWN_ELEM_CHILD: C2RustUnnamed_1 = 1738;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXTYPE_CHILD: C2RustUnnamed_1 = 1737;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXCONTENT_CHILD: C2RustUnnamed_1 = 1736;
pub const XML_SCHEMAP_UNKNOWN_CHOICE_CHILD: C2RustUnnamed_1 = 1735;
pub const XML_SCHEMAP_UNKNOWN_BASE_TYPE: C2RustUnnamed_1 = 1734;
pub const XML_SCHEMAP_UNKNOWN_ATTRIBUTE_GROUP: C2RustUnnamed_1 = 1733;
pub const XML_SCHEMAP_UNKNOWN_ATTRGRP_CHILD: C2RustUnnamed_1 = 1732;
pub const XML_SCHEMAP_UNKNOWN_ATTR_CHILD: C2RustUnnamed_1 = 1731;
pub const XML_SCHEMAP_UNKNOWN_ANYATTRIBUTE_CHILD: C2RustUnnamed_1 = 1730;
pub const XML_SCHEMAP_UNKNOWN_ALL_CHILD: C2RustUnnamed_1 = 1729;
pub const XML_SCHEMAP_TYPE_AND_SUBTYPE: C2RustUnnamed_1 = 1728;
pub const XML_SCHEMAP_SIMPLETYPE_NONAME: C2RustUnnamed_1 = 1727;
pub const XML_SCHEMAP_RESTRICTION_NONAME_NOREF: C2RustUnnamed_1 = 1726;
pub const XML_SCHEMAP_REF_AND_SUBTYPE: C2RustUnnamed_1 = 1725;
pub const XML_SCHEMAP_NOTYPE_NOREF: C2RustUnnamed_1 = 1724;
pub const XML_SCHEMAP_NOTATION_NO_NAME: C2RustUnnamed_1 = 1723;
pub const XML_SCHEMAP_NOATTR_NOREF: C2RustUnnamed_1 = 1722;
pub const XML_SCHEMAP_INVALID_WHITE_SPACE: C2RustUnnamed_1 = 1721;
pub const XML_SCHEMAP_INVALID_REF_AND_SUBTYPE: C2RustUnnamed_1 = 1720;
pub const XML_SCHEMAP_INVALID_MINOCCURS: C2RustUnnamed_1 = 1719;
pub const XML_SCHEMAP_INVALID_MAXOCCURS: C2RustUnnamed_1 = 1718;
pub const XML_SCHEMAP_INVALID_FACET_VALUE: C2RustUnnamed_1 = 1717;
pub const XML_SCHEMAP_INVALID_FACET: C2RustUnnamed_1 = 1716;
pub const XML_SCHEMAP_INVALID_ENUM: C2RustUnnamed_1 = 1715;
pub const XML_SCHEMAP_INVALID_BOOLEAN: C2RustUnnamed_1 = 1714;
pub const XML_SCHEMAP_IMPORT_SCHEMA_NOT_URI: C2RustUnnamed_1 = 1713;
pub const XML_SCHEMAP_IMPORT_REDEFINE_NSNAME: C2RustUnnamed_1 = 1712;
pub const XML_SCHEMAP_IMPORT_NAMESPACE_NOT_URI: C2RustUnnamed_1 = 1711;
pub const XML_SCHEMAP_GROUP_NONAME_NOREF: C2RustUnnamed_1 = 1710;
pub const XML_SCHEMAP_FAILED_BUILD_IMPORT: C2RustUnnamed_1 = 1709;
pub const XML_SCHEMAP_FACET_NO_VALUE: C2RustUnnamed_1 = 1708;
pub const XML_SCHEMAP_EXTENSION_NO_BASE: C2RustUnnamed_1 = 1707;
pub const XML_SCHEMAP_ELEM_NONAME_NOREF: C2RustUnnamed_1 = 1706;
pub const XML_SCHEMAP_ELEMFORMDEFAULT_VALUE: C2RustUnnamed_1 = 1705;
pub const XML_SCHEMAP_COMPLEXTYPE_NONAME_NOREF: C2RustUnnamed_1 = 1704;
pub const XML_SCHEMAP_ATTR_NONAME_NOREF: C2RustUnnamed_1 = 1703;
pub const XML_SCHEMAP_ATTRGRP_NONAME_NOREF: C2RustUnnamed_1 = 1702;
pub const XML_SCHEMAP_ATTRFORMDEFAULT_VALUE: C2RustUnnamed_1 = 1701;
pub const XML_SCHEMAP_PREFIX_UNDEFINED: C2RustUnnamed_1 = 1700;
pub const XML_CATALOG_RECURSION: C2RustUnnamed_1 = 1654;
pub const XML_CATALOG_NOT_CATALOG: C2RustUnnamed_1 = 1653;
pub const XML_CATALOG_PREFER_VALUE: C2RustUnnamed_1 = 1652;
pub const XML_CATALOG_ENTRY_BROKEN: C2RustUnnamed_1 = 1651;
pub const XML_CATALOG_MISSING_ATTR: C2RustUnnamed_1 = 1650;
pub const XML_XINCLUDE_FRAGMENT_ID: C2RustUnnamed_1 = 1618;
pub const XML_XINCLUDE_DEPRECATED_NS: C2RustUnnamed_1 = 1617;
pub const XML_XINCLUDE_FALLBACK_NOT_IN_INCLUDE: C2RustUnnamed_1 = 1616;
pub const XML_XINCLUDE_FALLBACKS_IN_INCLUDE: C2RustUnnamed_1 = 1615;
pub const XML_XINCLUDE_INCLUDE_IN_INCLUDE: C2RustUnnamed_1 = 1614;
pub const XML_XINCLUDE_XPTR_RESULT: C2RustUnnamed_1 = 1613;
pub const XML_XINCLUDE_XPTR_FAILED: C2RustUnnamed_1 = 1612;
pub const XML_XINCLUDE_MULTIPLE_ROOT: C2RustUnnamed_1 = 1611;
pub const XML_XINCLUDE_UNKNOWN_ENCODING: C2RustUnnamed_1 = 1610;
pub const XML_XINCLUDE_BUILD_FAILED: C2RustUnnamed_1 = 1609;
pub const XML_XINCLUDE_INVALID_CHAR: C2RustUnnamed_1 = 1608;
pub const XML_XINCLUDE_TEXT_DOCUMENT: C2RustUnnamed_1 = 1607;
pub const XML_XINCLUDE_TEXT_FRAGMENT: C2RustUnnamed_1 = 1606;
pub const XML_XINCLUDE_HREF_URI: C2RustUnnamed_1 = 1605;
pub const XML_XINCLUDE_NO_FALLBACK: C2RustUnnamed_1 = 1604;
pub const XML_XINCLUDE_NO_HREF: C2RustUnnamed_1 = 1603;
pub const XML_XINCLUDE_ENTITY_DEF_MISMATCH: C2RustUnnamed_1 = 1602;
pub const XML_XINCLUDE_PARSE_VALUE: C2RustUnnamed_1 = 1601;
pub const XML_XINCLUDE_RECURSION: C2RustUnnamed_1 = 1600;
pub const XML_IO_EAFNOSUPPORT: C2RustUnnamed_1 = 1556;
pub const XML_IO_EALREADY: C2RustUnnamed_1 = 1555;
pub const XML_IO_EADDRINUSE: C2RustUnnamed_1 = 1554;
pub const XML_IO_ENETUNREACH: C2RustUnnamed_1 = 1553;
pub const XML_IO_ECONNREFUSED: C2RustUnnamed_1 = 1552;
pub const XML_IO_EISCONN: C2RustUnnamed_1 = 1551;
pub const XML_IO_ENOTSOCK: C2RustUnnamed_1 = 1550;
pub const XML_IO_LOAD_ERROR: C2RustUnnamed_1 = 1549;
pub const XML_IO_BUFFER_FULL: C2RustUnnamed_1 = 1548;
pub const XML_IO_NO_INPUT: C2RustUnnamed_1 = 1547;
pub const XML_IO_WRITE: C2RustUnnamed_1 = 1546;
pub const XML_IO_FLUSH: C2RustUnnamed_1 = 1545;
pub const XML_IO_ENCODER: C2RustUnnamed_1 = 1544;
pub const XML_IO_NETWORK_ATTEMPT: C2RustUnnamed_1 = 1543;
pub const XML_IO_EXDEV: C2RustUnnamed_1 = 1542;
pub const XML_IO_ETIMEDOUT: C2RustUnnamed_1 = 1541;
pub const XML_IO_ESRCH: C2RustUnnamed_1 = 1540;
pub const XML_IO_ESPIPE: C2RustUnnamed_1 = 1539;
pub const XML_IO_EROFS: C2RustUnnamed_1 = 1538;
pub const XML_IO_ERANGE: C2RustUnnamed_1 = 1537;
pub const XML_IO_EPIPE: C2RustUnnamed_1 = 1536;
pub const XML_IO_EPERM: C2RustUnnamed_1 = 1535;
pub const XML_IO_ENXIO: C2RustUnnamed_1 = 1534;
pub const XML_IO_ENOTTY: C2RustUnnamed_1 = 1533;
pub const XML_IO_ENOTSUP: C2RustUnnamed_1 = 1532;
pub const XML_IO_ENOTEMPTY: C2RustUnnamed_1 = 1531;
pub const XML_IO_ENOTDIR: C2RustUnnamed_1 = 1530;
pub const XML_IO_ENOSYS: C2RustUnnamed_1 = 1529;
pub const XML_IO_ENOSPC: C2RustUnnamed_1 = 1528;
pub const XML_IO_ENOMEM: C2RustUnnamed_1 = 1527;
pub const XML_IO_ENOLCK: C2RustUnnamed_1 = 1526;
pub const XML_IO_ENOEXEC: C2RustUnnamed_1 = 1525;
pub const XML_IO_ENOENT: C2RustUnnamed_1 = 1524;
pub const XML_IO_ENODEV: C2RustUnnamed_1 = 1523;
pub const XML_IO_ENFILE: C2RustUnnamed_1 = 1522;
pub const XML_IO_ENAMETOOLONG: C2RustUnnamed_1 = 1521;
pub const XML_IO_EMSGSIZE: C2RustUnnamed_1 = 1520;
pub const XML_IO_EMLINK: C2RustUnnamed_1 = 1519;
pub const XML_IO_EMFILE: C2RustUnnamed_1 = 1518;
pub const XML_IO_EISDIR: C2RustUnnamed_1 = 1517;
pub const XML_IO_EIO: C2RustUnnamed_1 = 1516;
pub const XML_IO_EINVAL: C2RustUnnamed_1 = 1515;
pub const XML_IO_EINTR: C2RustUnnamed_1 = 1514;
pub const XML_IO_EINPROGRESS: C2RustUnnamed_1 = 1513;
pub const XML_IO_EFBIG: C2RustUnnamed_1 = 1512;
pub const XML_IO_EFAULT: C2RustUnnamed_1 = 1511;
pub const XML_IO_EEXIST: C2RustUnnamed_1 = 1510;
pub const XML_IO_EDOM: C2RustUnnamed_1 = 1509;
pub const XML_IO_EDEADLK: C2RustUnnamed_1 = 1508;
pub const XML_IO_ECHILD: C2RustUnnamed_1 = 1507;
pub const XML_IO_ECANCELED: C2RustUnnamed_1 = 1506;
pub const XML_IO_EBUSY: C2RustUnnamed_1 = 1505;
pub const XML_IO_EBADMSG: C2RustUnnamed_1 = 1504;
pub const XML_IO_EBADF: C2RustUnnamed_1 = 1503;
pub const XML_IO_EAGAIN: C2RustUnnamed_1 = 1502;
pub const XML_IO_EACCES: C2RustUnnamed_1 = 1501;
pub const XML_IO_UNKNOWN: C2RustUnnamed_1 = 1500;
pub const XML_REGEXP_COMPILE_ERROR: C2RustUnnamed_1 = 1450;
pub const XML_SAVE_UNKNOWN_ENCODING: C2RustUnnamed_1 = 1403;
pub const XML_SAVE_NO_DOCTYPE: C2RustUnnamed_1 = 1402;
pub const XML_SAVE_CHAR_INVALID: C2RustUnnamed_1 = 1401;
pub const XML_SAVE_NOT_UTF8: C2RustUnnamed_1 = 1400;
pub const XML_XPATH_INVALID_CHAR_ERROR: C2RustUnnamed_1 = 1221;
pub const XML_XPATH_ENCODING_ERROR: C2RustUnnamed_1 = 1220;
pub const XML_XPATH_UNDEF_PREFIX_ERROR: C2RustUnnamed_1 = 1219;
pub const XML_XPTR_SUB_RESOURCE_ERROR: C2RustUnnamed_1 = 1218;
pub const XML_XPTR_RESOURCE_ERROR: C2RustUnnamed_1 = 1217;
pub const XML_XPTR_SYNTAX_ERROR: C2RustUnnamed_1 = 1216;
pub const XML_XPATH_MEMORY_ERROR: C2RustUnnamed_1 = 1215;
pub const XML_XPATH_INVALID_CTXT_POSITION: C2RustUnnamed_1 = 1214;
pub const XML_XPATH_INVALID_CTXT_SIZE: C2RustUnnamed_1 = 1213;
pub const XML_XPATH_INVALID_ARITY: C2RustUnnamed_1 = 1212;
pub const XML_XPATH_INVALID_TYPE: C2RustUnnamed_1 = 1211;
pub const XML_XPATH_INVALID_OPERAND: C2RustUnnamed_1 = 1210;
pub const XML_XPATH_UNKNOWN_FUNC_ERROR: C2RustUnnamed_1 = 1209;
pub const XML_XPATH_UNCLOSED_ERROR: C2RustUnnamed_1 = 1208;
pub const XML_XPATH_EXPR_ERROR: C2RustUnnamed_1 = 1207;
pub const XML_XPATH_INVALID_PREDICATE_ERROR: C2RustUnnamed_1 = 1206;
pub const XML_XPATH_UNDEF_VARIABLE_ERROR: C2RustUnnamed_1 = 1205;
pub const XML_XPATH_VARIABLE_REF_ERROR: C2RustUnnamed_1 = 1204;
pub const XML_XPATH_START_LITERAL_ERROR: C2RustUnnamed_1 = 1203;
pub const XML_XPATH_UNFINISHED_LITERAL_ERROR: C2RustUnnamed_1 = 1202;
pub const XML_XPATH_NUMBER_ERROR: C2RustUnnamed_1 = 1201;
pub const XML_XPATH_EXPRESSION_OK: C2RustUnnamed_1 = 1200;
pub const XML_RNGP_XML_NS: C2RustUnnamed_1 = 1122;
pub const XML_RNGP_XMLNS_NAME: C2RustUnnamed_1 = 1121;
pub const XML_RNGP_VALUE_NO_CONTENT: C2RustUnnamed_1 = 1120;
pub const XML_RNGP_VALUE_EMPTY: C2RustUnnamed_1 = 1119;
pub const XML_RNGP_URI_NOT_ABSOLUTE: C2RustUnnamed_1 = 1118;
pub const XML_RNGP_URI_FRAGMENT: C2RustUnnamed_1 = 1117;
pub const XML_RNGP_UNKNOWN_TYPE_LIB: C2RustUnnamed_1 = 1116;
pub const XML_RNGP_UNKNOWN_CONSTRUCT: C2RustUnnamed_1 = 1115;
pub const XML_RNGP_UNKNOWN_COMBINE: C2RustUnnamed_1 = 1114;
pub const XML_RNGP_UNKNOWN_ATTRIBUTE: C2RustUnnamed_1 = 1113;
pub const XML_RNGP_TYPE_VALUE: C2RustUnnamed_1 = 1112;
pub const XML_RNGP_TYPE_NOT_FOUND: C2RustUnnamed_1 = 1111;
pub const XML_RNGP_TYPE_MISSING: C2RustUnnamed_1 = 1110;
pub const XML_RNGP_TEXT_HAS_CHILD: C2RustUnnamed_1 = 1109;
pub const XML_RNGP_TEXT_EXPECTED: C2RustUnnamed_1 = 1108;
pub const XML_RNGP_START_MISSING: C2RustUnnamed_1 = 1107;
pub const XML_RNGP_START_EMPTY: C2RustUnnamed_1 = 1106;
pub const XML_RNGP_START_CONTENT: C2RustUnnamed_1 = 1105;
pub const XML_RNGP_START_CHOICE_AND_INTERLEAVE: C2RustUnnamed_1 = 1104;
pub const XML_RNGP_REF_NOT_EMPTY: C2RustUnnamed_1 = 1103;
pub const XML_RNGP_REF_NO_NAME: C2RustUnnamed_1 = 1102;
pub const XML_RNGP_REF_NO_DEF: C2RustUnnamed_1 = 1101;
pub const XML_RNGP_REF_NAME_INVALID: C2RustUnnamed_1 = 1100;
pub const XML_RNGP_REF_CYCLE: C2RustUnnamed_1 = 1099;
pub const XML_RNGP_REF_CREATE_FAILED: C2RustUnnamed_1 = 1098;
pub const XML_RNGP_PREFIX_UNDEFINED: C2RustUnnamed_1 = 1097;
pub const XML_RNGP_PAT_START_VALUE: C2RustUnnamed_1 = 1096;
pub const XML_RNGP_PAT_START_TEXT: C2RustUnnamed_1 = 1095;
pub const XML_RNGP_PAT_START_ONEMORE: C2RustUnnamed_1 = 1094;
pub const XML_RNGP_PAT_START_LIST: C2RustUnnamed_1 = 1093;
pub const XML_RNGP_PAT_START_INTERLEAVE: C2RustUnnamed_1 = 1092;
pub const XML_RNGP_PAT_START_GROUP: C2RustUnnamed_1 = 1091;
pub const XML_RNGP_PAT_START_EMPTY: C2RustUnnamed_1 = 1090;
pub const XML_RNGP_PAT_START_DATA: C2RustUnnamed_1 = 1089;
pub const XML_RNGP_PAT_START_ATTR: C2RustUnnamed_1 = 1088;
pub const XML_RNGP_PAT_ONEMORE_INTERLEAVE_ATTR: C2RustUnnamed_1 = 1087;
pub const XML_RNGP_PAT_ONEMORE_GROUP_ATTR: C2RustUnnamed_1 = 1086;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_NSNAME: C2RustUnnamed_1 = 1085;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_ANYNAME: C2RustUnnamed_1 = 1084;
pub const XML_RNGP_PAT_LIST_TEXT: C2RustUnnamed_1 = 1083;
pub const XML_RNGP_PAT_LIST_REF: C2RustUnnamed_1 = 1082;
pub const XML_RNGP_PAT_LIST_LIST: C2RustUnnamed_1 = 1081;
pub const XML_RNGP_PAT_LIST_INTERLEAVE: C2RustUnnamed_1 = 1080;
pub const XML_RNGP_PAT_LIST_ELEM: C2RustUnnamed_1 = 1079;
pub const XML_RNGP_PAT_LIST_ATTR: C2RustUnnamed_1 = 1078;
pub const XML_RNGP_PAT_DATA_EXCEPT_TEXT: C2RustUnnamed_1 = 1077;
pub const XML_RNGP_PAT_DATA_EXCEPT_REF: C2RustUnnamed_1 = 1076;
pub const XML_RNGP_PAT_DATA_EXCEPT_ONEMORE: C2RustUnnamed_1 = 1075;
pub const XML_RNGP_PAT_DATA_EXCEPT_LIST: C2RustUnnamed_1 = 1074;
pub const XML_RNGP_PAT_DATA_EXCEPT_INTERLEAVE: C2RustUnnamed_1 = 1073;
pub const XML_RNGP_PAT_DATA_EXCEPT_GROUP: C2RustUnnamed_1 = 1072;
pub const XML_RNGP_PAT_DATA_EXCEPT_EMPTY: C2RustUnnamed_1 = 1071;
pub const XML_RNGP_PAT_DATA_EXCEPT_ELEM: C2RustUnnamed_1 = 1070;
pub const XML_RNGP_PAT_DATA_EXCEPT_ATTR: C2RustUnnamed_1 = 1069;
pub const XML_RNGP_PAT_ATTR_ELEM: C2RustUnnamed_1 = 1068;
pub const XML_RNGP_PAT_ATTR_ATTR: C2RustUnnamed_1 = 1067;
pub const XML_RNGP_PAT_ANYNAME_EXCEPT_ANYNAME: C2RustUnnamed_1 = 1066;
pub const XML_RNGP_PARSE_ERROR: C2RustUnnamed_1 = 1065;
pub const XML_RNGP_PARENTREF_NOT_EMPTY: C2RustUnnamed_1 = 1064;
pub const XML_RNGP_PARENTREF_NO_PARENT: C2RustUnnamed_1 = 1063;
pub const XML_RNGP_PARENTREF_NO_NAME: C2RustUnnamed_1 = 1062;
pub const XML_RNGP_PARENTREF_NAME_INVALID: C2RustUnnamed_1 = 1061;
pub const XML_RNGP_PARENTREF_CREATE_FAILED: C2RustUnnamed_1 = 1060;
pub const XML_RNGP_PARAM_NAME_MISSING: C2RustUnnamed_1 = 1059;
pub const XML_RNGP_PARAM_FORBIDDEN: C2RustUnnamed_1 = 1058;
pub const XML_RNGP_NSNAME_NO_NS: C2RustUnnamed_1 = 1057;
pub const XML_RNGP_NSNAME_ATTR_ANCESTOR: C2RustUnnamed_1 = 1056;
pub const XML_RNGP_NOTALLOWED_NOT_EMPTY: C2RustUnnamed_1 = 1055;
pub const XML_RNGP_NEED_COMBINE: C2RustUnnamed_1 = 1054;
pub const XML_RNGP_NAME_MISSING: C2RustUnnamed_1 = 1053;
pub const XML_RNGP_MISSING_HREF: C2RustUnnamed_1 = 1052;
pub const XML_RNGP_INVALID_VALUE: C2RustUnnamed_1 = 1051;
pub const XML_RNGP_INVALID_URI: C2RustUnnamed_1 = 1050;
pub const XML_RNGP_INVALID_DEFINE_NAME: C2RustUnnamed_1 = 1049;
pub const XML_RNGP_INTERLEAVE_NO_CONTENT: C2RustUnnamed_1 = 1048;
pub const XML_RNGP_INTERLEAVE_EMPTY: C2RustUnnamed_1 = 1047;
pub const XML_RNGP_INTERLEAVE_CREATE_FAILED: C2RustUnnamed_1 = 1046;
pub const XML_RNGP_INTERLEAVE_ADD: C2RustUnnamed_1 = 1045;
pub const XML_RNGP_INCLUDE_RECURSE: C2RustUnnamed_1 = 1044;
pub const XML_RNGP_INCLUDE_FAILURE: C2RustUnnamed_1 = 1043;
pub const XML_RNGP_INCLUDE_EMPTY: C2RustUnnamed_1 = 1042;
pub const XML_RNGP_HREF_ERROR: C2RustUnnamed_1 = 1041;
pub const XML_RNGP_GROUP_ATTR_CONFLICT: C2RustUnnamed_1 = 1040;
pub const XML_RNGP_GRAMMAR_NO_START: C2RustUnnamed_1 = 1039;
pub const XML_RNGP_GRAMMAR_MISSING: C2RustUnnamed_1 = 1038;
pub const XML_RNGP_GRAMMAR_EMPTY: C2RustUnnamed_1 = 1037;
pub const XML_RNGP_GRAMMAR_CONTENT: C2RustUnnamed_1 = 1036;
pub const XML_RNGP_FOREIGN_ELEMENT: C2RustUnnamed_1 = 1035;
pub const XML_RNGP_FORBIDDEN_ATTRIBUTE: C2RustUnnamed_1 = 1034;
pub const XML_RNGP_EXTERNALREF_RECURSE: C2RustUnnamed_1 = 1033;
pub const XML_RNGP_EXTERNAL_REF_FAILURE: C2RustUnnamed_1 = 1032;
pub const XML_RNGP_EXTERNALREF_EMTPY: C2RustUnnamed_1 = 1031;
pub const XML_RNGP_EXCEPT_NO_CONTENT: C2RustUnnamed_1 = 1030;
pub const XML_RNGP_EXCEPT_MULTIPLE: C2RustUnnamed_1 = 1029;
pub const XML_RNGP_EXCEPT_MISSING: C2RustUnnamed_1 = 1028;
pub const XML_RNGP_EXCEPT_EMPTY: C2RustUnnamed_1 = 1027;
pub const XML_RNGP_ERROR_TYPE_LIB: C2RustUnnamed_1 = 1026;
pub const XML_RNGP_EMPTY_NOT_EMPTY: C2RustUnnamed_1 = 1025;
pub const XML_RNGP_EMPTY_CONTENT: C2RustUnnamed_1 = 1024;
pub const XML_RNGP_EMPTY_CONSTRUCT: C2RustUnnamed_1 = 1023;
pub const XML_RNGP_EMPTY: C2RustUnnamed_1 = 1022;
pub const XML_RNGP_ELEM_TEXT_CONFLICT: C2RustUnnamed_1 = 1021;
pub const XML_RNGP_ELEMENT_NO_CONTENT: C2RustUnnamed_1 = 1020;
pub const XML_RNGP_ELEMENT_NAME: C2RustUnnamed_1 = 1019;
pub const XML_RNGP_ELEMENT_CONTENT: C2RustUnnamed_1 = 1018;
pub const XML_RNGP_ELEMENT_EMPTY: C2RustUnnamed_1 = 1017;
pub const XML_RNGP_ELEM_CONTENT_ERROR: C2RustUnnamed_1 = 1016;
pub const XML_RNGP_ELEM_CONTENT_EMPTY: C2RustUnnamed_1 = 1015;
pub const XML_RNGP_DEFINE_NAME_MISSING: C2RustUnnamed_1 = 1014;
pub const XML_RNGP_DEFINE_MISSING: C2RustUnnamed_1 = 1013;
pub const XML_RNGP_DEFINE_EMPTY: C2RustUnnamed_1 = 1012;
pub const XML_RNGP_DEFINE_CREATE_FAILED: C2RustUnnamed_1 = 1011;
pub const XML_RNGP_DEF_CHOICE_AND_INTERLEAVE: C2RustUnnamed_1 = 1010;
pub const XML_RNGP_DATA_CONTENT: C2RustUnnamed_1 = 1009;
pub const XML_RNGP_CREATE_FAILURE: C2RustUnnamed_1 = 1008;
pub const XML_RNGP_CHOICE_EMPTY: C2RustUnnamed_1 = 1007;
pub const XML_RNGP_CHOICE_CONTENT: C2RustUnnamed_1 = 1006;
pub const XML_RNGP_ATTRIBUTE_NOOP: C2RustUnnamed_1 = 1005;
pub const XML_RNGP_ATTRIBUTE_EMPTY: C2RustUnnamed_1 = 1004;
pub const XML_RNGP_ATTRIBUTE_CONTENT: C2RustUnnamed_1 = 1003;
pub const XML_RNGP_ATTRIBUTE_CHILDREN: C2RustUnnamed_1 = 1002;
pub const XML_RNGP_ATTR_CONFLICT: C2RustUnnamed_1 = 1001;
pub const XML_RNGP_ANYNAME_ATTR_ANCESTOR: C2RustUnnamed_1 = 1000;
pub const XML_HTML_INCORRECTLY_OPENED_COMMENT: C2RustUnnamed_1 = 802;
pub const XML_HTML_UNKNOWN_TAG: C2RustUnnamed_1 = 801;
pub const XML_HTML_STRUCURE_ERROR: C2RustUnnamed_1 = 800;
pub const XML_DTD_DUP_TOKEN: C2RustUnnamed_1 = 541;
pub const XML_DTD_XMLID_TYPE: C2RustUnnamed_1 = 540;
pub const XML_DTD_XMLID_VALUE: C2RustUnnamed_1 = 539;
pub const XML_DTD_STANDALONE_DEFAULTED: C2RustUnnamed_1 = 538;
pub const XML_DTD_UNKNOWN_NOTATION: C2RustUnnamed_1 = 537;
pub const XML_DTD_UNKNOWN_ID: C2RustUnnamed_1 = 536;
pub const XML_DTD_UNKNOWN_ENTITY: C2RustUnnamed_1 = 535;
pub const XML_DTD_UNKNOWN_ELEM: C2RustUnnamed_1 = 534;
pub const XML_DTD_UNKNOWN_ATTRIBUTE: C2RustUnnamed_1 = 533;
pub const XML_DTD_STANDALONE_WHITE_SPACE: C2RustUnnamed_1 = 532;
pub const XML_DTD_ROOT_NAME: C2RustUnnamed_1 = 531;
pub const XML_DTD_NOT_STANDALONE: C2RustUnnamed_1 = 530;
pub const XML_DTD_NOT_PCDATA: C2RustUnnamed_1 = 529;
pub const XML_DTD_NOT_EMPTY: C2RustUnnamed_1 = 528;
pub const XML_DTD_NOTATION_VALUE: C2RustUnnamed_1 = 527;
pub const XML_DTD_NOTATION_REDEFINED: C2RustUnnamed_1 = 526;
pub const XML_DTD_NO_ROOT: C2RustUnnamed_1 = 525;
pub const XML_DTD_NO_PREFIX: C2RustUnnamed_1 = 524;
pub const XML_DTD_NO_ELEM_NAME: C2RustUnnamed_1 = 523;
pub const XML_DTD_NO_DTD: C2RustUnnamed_1 = 522;
pub const XML_DTD_NO_DOC: C2RustUnnamed_1 = 521;
pub const XML_DTD_MULTIPLE_ID: C2RustUnnamed_1 = 520;
pub const XML_DTD_MIXED_CORRUPT: C2RustUnnamed_1 = 519;
pub const XML_DTD_MISSING_ATTRIBUTE: C2RustUnnamed_1 = 518;
pub const XML_DTD_LOAD_ERROR: C2RustUnnamed_1 = 517;
pub const XML_DTD_INVALID_DEFAULT: C2RustUnnamed_1 = 516;
pub const XML_DTD_INVALID_CHILD: C2RustUnnamed_1 = 515;
pub const XML_DTD_ID_SUBSET: C2RustUnnamed_1 = 514;
pub const XML_DTD_ID_REDEFINED: C2RustUnnamed_1 = 513;
pub const XML_DTD_ID_FIXED: C2RustUnnamed_1 = 512;
pub const XML_DTD_ENTITY_TYPE: C2RustUnnamed_1 = 511;
pub const XML_DTD_EMPTY_NOTATION: C2RustUnnamed_1 = 510;
pub const XML_DTD_ELEM_REDEFINED: C2RustUnnamed_1 = 509;
pub const XML_DTD_ELEM_NAMESPACE: C2RustUnnamed_1 = 508;
pub const XML_DTD_ELEM_DEFAULT_NAMESPACE: C2RustUnnamed_1 = 507;
pub const XML_DTD_DIFFERENT_PREFIX: C2RustUnnamed_1 = 506;
pub const XML_DTD_CONTENT_NOT_DETERMINIST: C2RustUnnamed_1 = 505;
pub const XML_DTD_CONTENT_MODEL: C2RustUnnamed_1 = 504;
pub const XML_DTD_CONTENT_ERROR: C2RustUnnamed_1 = 503;
pub const XML_DTD_ATTRIBUTE_VALUE: C2RustUnnamed_1 = 502;
pub const XML_DTD_ATTRIBUTE_REDEFINED: C2RustUnnamed_1 = 501;
pub const XML_DTD_ATTRIBUTE_DEFAULT: C2RustUnnamed_1 = 500;
pub const XML_NS_ERR_COLON: C2RustUnnamed_1 = 205;
pub const XML_NS_ERR_EMPTY: C2RustUnnamed_1 = 204;
pub const XML_NS_ERR_ATTRIBUTE_REDEFINED: C2RustUnnamed_1 = 203;
pub const XML_NS_ERR_QNAME: C2RustUnnamed_1 = 202;
pub const XML_NS_ERR_UNDEFINED_NAMESPACE: C2RustUnnamed_1 = 201;
pub const XML_NS_ERR_XML_NAMESPACE: C2RustUnnamed_1 = 200;
pub const XML_ERR_COMMENT_ABRUPTLY_ENDED: C2RustUnnamed_1 = 112;
pub const XML_ERR_USER_STOP: C2RustUnnamed_1 = 111;
pub const XML_ERR_NAME_TOO_LONG: C2RustUnnamed_1 = 110;
pub const XML_ERR_VERSION_MISMATCH: C2RustUnnamed_1 = 109;
pub const XML_ERR_UNKNOWN_VERSION: C2RustUnnamed_1 = 108;
pub const XML_WAR_ENTITY_REDEFINED: C2RustUnnamed_1 = 107;
pub const XML_WAR_NS_COLUMN: C2RustUnnamed_1 = 106;
pub const XML_ERR_NOTATION_PROCESSING: C2RustUnnamed_1 = 105;
pub const XML_ERR_ENTITY_PROCESSING: C2RustUnnamed_1 = 104;
pub const XML_ERR_NOT_STANDALONE: C2RustUnnamed_1 = 103;
pub const XML_WAR_SPACE_VALUE: C2RustUnnamed_1 = 102;
pub const XML_ERR_MISSING_ENCODING: C2RustUnnamed_1 = 101;
pub const XML_WAR_NS_URI_RELATIVE: C2RustUnnamed_1 = 100;
pub const XML_WAR_NS_URI: C2RustUnnamed_1 = 99;
pub const XML_WAR_LANG_VALUE: C2RustUnnamed_1 = 98;
pub const XML_WAR_UNKNOWN_VERSION: C2RustUnnamed_1 = 97;
pub const XML_ERR_VERSION_MISSING: C2RustUnnamed_1 = 96;
pub const XML_ERR_CONDSEC_INVALID_KEYWORD: C2RustUnnamed_1 = 95;
pub const XML_ERR_NO_DTD: C2RustUnnamed_1 = 94;
pub const XML_WAR_CATALOG_PI: C2RustUnnamed_1 = 93;
pub const XML_ERR_URI_FRAGMENT: C2RustUnnamed_1 = 92;
pub const XML_ERR_INVALID_URI: C2RustUnnamed_1 = 91;
pub const XML_ERR_ENTITY_BOUNDARY: C2RustUnnamed_1 = 90;
pub const XML_ERR_ENTITY_LOOP: C2RustUnnamed_1 = 89;
pub const XML_ERR_ENTITY_PE_INTERNAL: C2RustUnnamed_1 = 88;
pub const XML_ERR_ENTITY_CHAR_ERROR: C2RustUnnamed_1 = 87;
pub const XML_ERR_EXTRA_CONTENT: C2RustUnnamed_1 = 86;
pub const XML_ERR_NOT_WELL_BALANCED: C2RustUnnamed_1 = 85;
pub const XML_ERR_VALUE_REQUIRED: C2RustUnnamed_1 = 84;
pub const XML_ERR_CONDSEC_INVALID: C2RustUnnamed_1 = 83;
pub const XML_ERR_EXT_ENTITY_STANDALONE: C2RustUnnamed_1 = 82;
pub const XML_ERR_INVALID_ENCODING: C2RustUnnamed_1 = 81;
pub const XML_ERR_HYPHEN_IN_COMMENT: C2RustUnnamed_1 = 80;
pub const XML_ERR_ENCODING_NAME: C2RustUnnamed_1 = 79;
pub const XML_ERR_STANDALONE_VALUE: C2RustUnnamed_1 = 78;
pub const XML_ERR_TAG_NOT_FINISHED: C2RustUnnamed_1 = 77;
pub const XML_ERR_TAG_NAME_MISMATCH: C2RustUnnamed_1 = 76;
pub const XML_ERR_EQUAL_REQUIRED: C2RustUnnamed_1 = 75;
pub const XML_ERR_LTSLASH_REQUIRED: C2RustUnnamed_1 = 74;
pub const XML_ERR_GT_REQUIRED: C2RustUnnamed_1 = 73;
pub const XML_ERR_LT_REQUIRED: C2RustUnnamed_1 = 72;
pub const XML_ERR_PUBID_REQUIRED: C2RustUnnamed_1 = 71;
pub const XML_ERR_URI_REQUIRED: C2RustUnnamed_1 = 70;
pub const XML_ERR_PCDATA_REQUIRED: C2RustUnnamed_1 = 69;
pub const XML_ERR_NAME_REQUIRED: C2RustUnnamed_1 = 68;
pub const XML_ERR_NMTOKEN_REQUIRED: C2RustUnnamed_1 = 67;
pub const XML_ERR_SEPARATOR_REQUIRED: C2RustUnnamed_1 = 66;
pub const XML_ERR_SPACE_REQUIRED: C2RustUnnamed_1 = 65;
pub const XML_ERR_RESERVED_XML_NAME: C2RustUnnamed_1 = 64;
pub const XML_ERR_CDATA_NOT_FINISHED: C2RustUnnamed_1 = 63;
pub const XML_ERR_MISPLACED_CDATA_END: C2RustUnnamed_1 = 62;
pub const XML_ERR_DOCTYPE_NOT_FINISHED: C2RustUnnamed_1 = 61;
pub const XML_ERR_EXT_SUBSET_NOT_FINISHED: C2RustUnnamed_1 = 60;
pub const XML_ERR_CONDSEC_NOT_FINISHED: C2RustUnnamed_1 = 59;
pub const XML_ERR_CONDSEC_NOT_STARTED: C2RustUnnamed_1 = 58;
pub const XML_ERR_XMLDECL_NOT_FINISHED: C2RustUnnamed_1 = 57;
pub const XML_ERR_XMLDECL_NOT_STARTED: C2RustUnnamed_1 = 56;
pub const XML_ERR_ELEMCONTENT_NOT_FINISHED: C2RustUnnamed_1 = 55;
pub const XML_ERR_ELEMCONTENT_NOT_STARTED: C2RustUnnamed_1 = 54;
pub const XML_ERR_MIXED_NOT_FINISHED: C2RustUnnamed_1 = 53;
pub const XML_ERR_MIXED_NOT_STARTED: C2RustUnnamed_1 = 52;
pub const XML_ERR_ATTLIST_NOT_FINISHED: C2RustUnnamed_1 = 51;
pub const XML_ERR_ATTLIST_NOT_STARTED: C2RustUnnamed_1 = 50;
pub const XML_ERR_NOTATION_NOT_FINISHED: C2RustUnnamed_1 = 49;
pub const XML_ERR_NOTATION_NOT_STARTED: C2RustUnnamed_1 = 48;
pub const XML_ERR_PI_NOT_FINISHED: C2RustUnnamed_1 = 47;
pub const XML_ERR_PI_NOT_STARTED: C2RustUnnamed_1 = 46;
pub const XML_ERR_COMMENT_NOT_FINISHED: C2RustUnnamed_1 = 45;
pub const XML_ERR_LITERAL_NOT_FINISHED: C2RustUnnamed_1 = 44;
pub const XML_ERR_LITERAL_NOT_STARTED: C2RustUnnamed_1 = 43;
pub const XML_ERR_ATTRIBUTE_REDEFINED: C2RustUnnamed_1 = 42;
pub const XML_ERR_ATTRIBUTE_WITHOUT_VALUE: C2RustUnnamed_1 = 41;
pub const XML_ERR_ATTRIBUTE_NOT_FINISHED: C2RustUnnamed_1 = 40;
pub const XML_ERR_ATTRIBUTE_NOT_STARTED: C2RustUnnamed_1 = 39;
pub const XML_ERR_LT_IN_ATTRIBUTE: C2RustUnnamed_1 = 38;
pub const XML_ERR_ENTITY_NOT_FINISHED: C2RustUnnamed_1 = 37;
pub const XML_ERR_ENTITY_NOT_STARTED: C2RustUnnamed_1 = 36;
pub const XML_ERR_NS_DECL_ERROR: C2RustUnnamed_1 = 35;
pub const XML_ERR_STRING_NOT_CLOSED: C2RustUnnamed_1 = 34;
pub const XML_ERR_STRING_NOT_STARTED: C2RustUnnamed_1 = 33;
pub const XML_ERR_UNSUPPORTED_ENCODING: C2RustUnnamed_1 = 32;
pub const XML_ERR_UNKNOWN_ENCODING: C2RustUnnamed_1 = 31;
pub const XML_ERR_ENTITY_IS_PARAMETER: C2RustUnnamed_1 = 30;
pub const XML_ERR_ENTITY_IS_EXTERNAL: C2RustUnnamed_1 = 29;
pub const XML_ERR_UNPARSED_ENTITY: C2RustUnnamed_1 = 28;
pub const XML_WAR_UNDECLARED_ENTITY: C2RustUnnamed_1 = 27;
pub const XML_ERR_UNDECLARED_ENTITY: C2RustUnnamed_1 = 26;
pub const XML_ERR_PEREF_SEMICOL_MISSING: C2RustUnnamed_1 = 25;
pub const XML_ERR_PEREF_NO_NAME: C2RustUnnamed_1 = 24;
pub const XML_ERR_ENTITYREF_SEMICOL_MISSING: C2RustUnnamed_1 = 23;
pub const XML_ERR_ENTITYREF_NO_NAME: C2RustUnnamed_1 = 22;
pub const XML_ERR_PEREF_IN_INT_SUBSET: C2RustUnnamed_1 = 21;
pub const XML_ERR_PEREF_IN_EPILOG: C2RustUnnamed_1 = 20;
pub const XML_ERR_PEREF_IN_PROLOG: C2RustUnnamed_1 = 19;
pub const XML_ERR_PEREF_AT_EOF: C2RustUnnamed_1 = 18;
pub const XML_ERR_ENTITYREF_IN_DTD: C2RustUnnamed_1 = 17;
pub const XML_ERR_ENTITYREF_IN_EPILOG: C2RustUnnamed_1 = 16;
pub const XML_ERR_ENTITYREF_IN_PROLOG: C2RustUnnamed_1 = 15;
pub const XML_ERR_ENTITYREF_AT_EOF: C2RustUnnamed_1 = 14;
pub const XML_ERR_CHARREF_IN_DTD: C2RustUnnamed_1 = 13;
pub const XML_ERR_CHARREF_IN_EPILOG: C2RustUnnamed_1 = 12;
pub const XML_ERR_CHARREF_IN_PROLOG: C2RustUnnamed_1 = 11;
pub const XML_ERR_CHARREF_AT_EOF: C2RustUnnamed_1 = 10;
pub const XML_ERR_INVALID_CHAR: C2RustUnnamed_1 = 9;
pub const XML_ERR_INVALID_CHARREF: C2RustUnnamed_1 = 8;
pub const XML_ERR_INVALID_DEC_CHARREF: C2RustUnnamed_1 = 7;
pub const XML_ERR_INVALID_HEX_CHARREF: C2RustUnnamed_1 = 6;
pub const XML_ERR_DOCUMENT_END: C2RustUnnamed_1 = 5;
pub const XML_ERR_DOCUMENT_EMPTY: C2RustUnnamed_1 = 4;
pub const XML_ERR_DOCUMENT_START: C2RustUnnamed_1 = 3;
pub const XML_ERR_INTERNAL_ERROR: C2RustUnnamed_1 = 1;
pub const XML_ERR_OK: C2RustUnnamed_1 = 0;
pub type C2RustUnnamed_2 = libc::c_int;
pub const XML_CHAR_ENCODING_ASCII: C2RustUnnamed_2 = 22;
pub const XML_CHAR_ENCODING_EUC_JP: C2RustUnnamed_2 = 21;
pub const XML_CHAR_ENCODING_SHIFT_JIS: C2RustUnnamed_2 = 20;
pub const XML_CHAR_ENCODING_2022_JP: C2RustUnnamed_2 = 19;
pub const XML_CHAR_ENCODING_8859_9: C2RustUnnamed_2 = 18;
pub const XML_CHAR_ENCODING_8859_8: C2RustUnnamed_2 = 17;
pub const XML_CHAR_ENCODING_8859_7: C2RustUnnamed_2 = 16;
pub const XML_CHAR_ENCODING_8859_6: C2RustUnnamed_2 = 15;
pub const XML_CHAR_ENCODING_8859_5: C2RustUnnamed_2 = 14;
pub const XML_CHAR_ENCODING_8859_4: C2RustUnnamed_2 = 13;
pub const XML_CHAR_ENCODING_8859_3: C2RustUnnamed_2 = 12;
pub const XML_CHAR_ENCODING_8859_2: C2RustUnnamed_2 = 11;
pub const XML_CHAR_ENCODING_8859_1: C2RustUnnamed_2 = 10;
pub const XML_CHAR_ENCODING_UCS2: C2RustUnnamed_2 = 9;
pub const XML_CHAR_ENCODING_UCS4_3412: C2RustUnnamed_2 = 8;
pub const XML_CHAR_ENCODING_UCS4_2143: C2RustUnnamed_2 = 7;
pub const XML_CHAR_ENCODING_EBCDIC: C2RustUnnamed_2 = 6;
pub const XML_CHAR_ENCODING_UCS4BE: C2RustUnnamed_2 = 5;
pub const XML_CHAR_ENCODING_UCS4LE: C2RustUnnamed_2 = 4;
pub const XML_CHAR_ENCODING_UTF16BE: C2RustUnnamed_2 = 3;
pub const XML_CHAR_ENCODING_UTF16LE: C2RustUnnamed_2 = 2;
pub const XML_CHAR_ENCODING_NONE: C2RustUnnamed_2 = 0;
pub const XML_CHAR_ENCODING_ERROR: C2RustUnnamed_2 = -1;
#[no_mangle]
pub static mut __xmlRegisterCallbacks: libc::c_int = 0 as libc::c_int;
unsafe extern "C" fn xmlTreeErrMemory(mut extra: *const libc::c_char) {
    __xmlSimpleError(
        XML_FROM_TREE as libc::c_int,
        XML_ERR_NO_MEMORY as libc::c_int,
        0 as xmlNodePtr,
        0 as *const libc::c_char,
        extra,
    );
}
unsafe extern "C" fn xmlTreeErr(
    mut code: libc::c_int,
    mut node: xmlNodePtr,
    mut extra: *const libc::c_char,
) {
    let mut msg: *const libc::c_char = 0 as *const libc::c_char;
    match code {
        1300 => {
            msg = b"invalid hexadecimal character value\n\0" as *const u8
                as *const libc::c_char;
        }
        1301 => {
            msg = b"invalid decimal character value\n\0" as *const u8
                as *const libc::c_char;
        }
        1302 => {
            msg = b"unterminated entity reference %15s\n\0" as *const u8
                as *const libc::c_char;
        }
        1303 => {
            msg = b"string is not in UTF-8\n\0" as *const u8 as *const libc::c_char;
        }
        _ => {
            msg = b"unexpected error number\n\0" as *const u8 as *const libc::c_char;
        }
    }
    __xmlSimpleError(XML_FROM_TREE as libc::c_int, code, node, msg, extra);
}
#[no_mangle]
pub static mut xmlStringText: [xmlChar; 5] = [
    't' as i32 as xmlChar,
    'e' as i32 as xmlChar,
    'x' as i32 as xmlChar,
    't' as i32 as xmlChar,
    0 as libc::c_int as xmlChar,
];
#[no_mangle]
pub static mut xmlStringTextNoenc: [xmlChar; 10] = [
    't' as i32 as xmlChar,
    'e' as i32 as xmlChar,
    'x' as i32 as xmlChar,
    't' as i32 as xmlChar,
    'n' as i32 as xmlChar,
    'o' as i32 as xmlChar,
    'e' as i32 as xmlChar,
    'n' as i32 as xmlChar,
    'c' as i32 as xmlChar,
    0 as libc::c_int as xmlChar,
];
#[no_mangle]
pub static mut xmlStringComment: [xmlChar; 8] = [
    'c' as i32 as xmlChar,
    'o' as i32 as xmlChar,
    'm' as i32 as xmlChar,
    'm' as i32 as xmlChar,
    'e' as i32 as xmlChar,
    'n' as i32 as xmlChar,
    't' as i32 as xmlChar,
    0 as libc::c_int as xmlChar,
];
static mut xmlCompressMode: libc::c_int = 0 as libc::c_int;
static mut xmlCheckDTD: libc::c_int = 1 as libc::c_int;
unsafe extern "C" fn xmlGetEntityFromDtd(
    mut dtd: *const xmlDtd,
    mut name: *const xmlChar,
) -> xmlEntityPtr {
    let mut table: xmlEntitiesTablePtr = 0 as *mut xmlEntitiesTable;
    if !dtd.is_null() && !((*dtd).entities).is_null() {
        table = (*dtd).entities as xmlEntitiesTablePtr;
        return xmlHashLookup(table, name) as xmlEntityPtr;
    }
    return 0 as xmlEntityPtr;
}
unsafe extern "C" fn xmlGetParameterEntityFromDtd(
    mut dtd: *const xmlDtd,
    mut name: *const xmlChar,
) -> xmlEntityPtr {
    let mut table: xmlEntitiesTablePtr = 0 as *mut xmlEntitiesTable;
    if !dtd.is_null() && !((*dtd).pentities).is_null() {
        table = (*dtd).pentities as xmlEntitiesTablePtr;
        return xmlHashLookup(table, name) as xmlEntityPtr;
    }
    return 0 as xmlEntityPtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBuildQName(
    mut ncname: *const xmlChar,
    mut prefix: *const xmlChar,
    mut memory: *mut xmlChar,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut lenn: libc::c_int = 0;
    let mut lenp: libc::c_int = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if ncname.is_null() {
        return 0 as *mut xmlChar;
    }
    if prefix.is_null() {
        return ncname as *mut xmlChar;
    }
    lenn = strlen(ncname as *mut libc::c_char) as libc::c_int;
    lenp = strlen(prefix as *mut libc::c_char) as libc::c_int;
    if memory.is_null() || len < lenn + lenp + 2 as libc::c_int {
        ret = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )((lenn + lenp + 2 as libc::c_int) as size_t) as *mut xmlChar;
        if ret.is_null() {
            xmlTreeErrMemory(b"building QName\0" as *const u8 as *const libc::c_char);
            return 0 as *mut xmlChar;
        }
    } else {
        ret = memory;
    }
    memcpy(
        &mut *ret.offset(0 as libc::c_int as isize) as *mut xmlChar as *mut libc::c_void,
        prefix as *const libc::c_void,
        lenp as libc::c_ulong,
    );
    *ret.offset(lenp as isize) = ':' as i32 as xmlChar;
    memcpy(
        &mut *ret.offset((lenp + 1 as libc::c_int) as isize) as *mut xmlChar
            as *mut libc::c_void,
        ncname as *const libc::c_void,
        lenn as libc::c_ulong,
    );
    *ret.offset((lenn + lenp + 1 as libc::c_int) as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSplitQName2(
    mut name: *const xmlChar,
    mut prefix: *mut *mut xmlChar,
) -> *mut xmlChar {
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if prefix.is_null() {
        return 0 as *mut xmlChar;
    }
    *prefix = 0 as *mut xmlChar;
    if name.is_null() {
        return 0 as *mut xmlChar;
    }
    if *name.offset(0 as libc::c_int as isize) as libc::c_int == ':' as i32 {
        return 0 as *mut xmlChar;
    }
    while *name.offset(len as isize) as libc::c_int != 0 as libc::c_int
        && *name.offset(len as isize) as libc::c_int != ':' as i32
    {
        len += 1;
    }
    if *name.offset(len as isize) as libc::c_int == 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    *prefix = xmlStrndup(name, len);
    if (*prefix).is_null() {
        xmlTreeErrMemory(b"QName split\0" as *const u8 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    ret = xmlStrdup(&*name.offset((len + 1 as libc::c_int) as isize));
    if ret.is_null() {
        xmlTreeErrMemory(b"QName split\0" as *const u8 as *const libc::c_char);
        if !(*prefix).is_null() {
            xmlFree.expect("non-null function pointer")(*prefix as *mut libc::c_void);
            *prefix = 0 as *mut xmlChar;
        }
        return 0 as *mut xmlChar;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSplitQName3(
    mut name: *const xmlChar,
    mut len: *mut libc::c_int,
) -> *const xmlChar {
    let mut l: libc::c_int = 0 as libc::c_int;
    if name.is_null() {
        return 0 as *const xmlChar;
    }
    if len.is_null() {
        return 0 as *const xmlChar;
    }
    if *name.offset(0 as libc::c_int as isize) as libc::c_int == ':' as i32 {
        return 0 as *const xmlChar;
    }
    while *name.offset(l as isize) as libc::c_int != 0 as libc::c_int
        && *name.offset(l as isize) as libc::c_int != ':' as i32
    {
        l += 1;
    }
    if *name.offset(l as isize) as libc::c_int == 0 as libc::c_int {
        return 0 as *const xmlChar;
    }
    *len = l;
    return &*name.offset((l + 1 as libc::c_int) as isize) as *const xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateNCName(
    mut value: *const xmlChar,
    mut space: libc::c_int,
) -> libc::c_int {
    let mut cur: *const xmlChar = value;
    let mut c: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    if value.is_null() {
        return -(1 as libc::c_int);
    }
    if space != 0 {
        while *cur as libc::c_int == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= *cur as libc::c_int
                && *cur as libc::c_int <= 0xa as libc::c_int
            || *cur as libc::c_int == 0xd as libc::c_int
        {
            cur = cur.offset(1);
        }
    }
    if *cur as libc::c_int >= 'a' as i32 && *cur as libc::c_int <= 'z' as i32
        || *cur as libc::c_int >= 'A' as i32 && *cur as libc::c_int <= 'Z' as i32
        || *cur as libc::c_int == '_' as i32
    {
        cur = cur.offset(1);
        while *cur as libc::c_int >= 'a' as i32 && *cur as libc::c_int <= 'z' as i32
            || *cur as libc::c_int >= 'A' as i32 && *cur as libc::c_int <= 'Z' as i32
            || *cur as libc::c_int >= '0' as i32 && *cur as libc::c_int <= '9' as i32
            || *cur as libc::c_int == '_' as i32 || *cur as libc::c_int == '-' as i32
            || *cur as libc::c_int == '.' as i32
        {
            cur = cur.offset(1);
        }
        if space != 0 {
            while *cur as libc::c_int == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= *cur as libc::c_int
                    && *cur as libc::c_int <= 0xa as libc::c_int
                || *cur as libc::c_int == 0xd as libc::c_int
            {
                cur = cur.offset(1);
            }
        }
        if *cur as libc::c_int == 0 as libc::c_int {
            return 0 as libc::c_int;
        }
    }
    cur = value;
    c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
    if space != 0 {
        while if c < 0x100 as libc::c_int {
            (c == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= c && c <= 0xa as libc::c_int
                || c == 0xd as libc::c_int) as libc::c_int
        } else {
            0 as libc::c_int
        } != 0
        {
            cur = cur.offset(l as isize);
            c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
        }
    }
    if !((if c < 0x100 as libc::c_int {
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
        }) != 0) && c != '_' as i32
    {
        return 1 as libc::c_int;
    }
    cur = cur.offset(l as isize);
    c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
    while (if c < 0x100 as libc::c_int {
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
        || (if c < 0x100 as libc::c_int {
            0 as libc::c_int
        } else {
            xmlCharInRange(c as libc::c_uint, &xmlIsCombiningGroup)
        }) != 0
        || (if c < 0x100 as libc::c_int {
            (c == 0xb7 as libc::c_int) as libc::c_int
        } else {
            xmlCharInRange(c as libc::c_uint, &xmlIsExtenderGroup)
        }) != 0
    {
        cur = cur.offset(l as isize);
        c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
    }
    if space != 0 {
        while if c < 0x100 as libc::c_int {
            (c == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= c && c <= 0xa as libc::c_int
                || c == 0xd as libc::c_int) as libc::c_int
        } else {
            0 as libc::c_int
        } != 0
        {
            cur = cur.offset(l as isize);
            c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
        }
    }
    if c != 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateQName(
    mut value: *const xmlChar,
    mut space: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut cur: *const xmlChar = value;
    let mut c: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    if value.is_null() {
        return -(1 as libc::c_int);
    }
    if space != 0 {
        while *cur as libc::c_int == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= *cur as libc::c_int
                && *cur as libc::c_int <= 0xa as libc::c_int
            || *cur as libc::c_int == 0xd as libc::c_int
        {
            cur = cur.offset(1);
        }
    }
    if *cur as libc::c_int >= 'a' as i32 && *cur as libc::c_int <= 'z' as i32
        || *cur as libc::c_int >= 'A' as i32 && *cur as libc::c_int <= 'Z' as i32
        || *cur as libc::c_int == '_' as i32
    {
        cur = cur.offset(1);
        while *cur as libc::c_int >= 'a' as i32 && *cur as libc::c_int <= 'z' as i32
            || *cur as libc::c_int >= 'A' as i32 && *cur as libc::c_int <= 'Z' as i32
            || *cur as libc::c_int >= '0' as i32 && *cur as libc::c_int <= '9' as i32
            || *cur as libc::c_int == '_' as i32 || *cur as libc::c_int == '-' as i32
            || *cur as libc::c_int == '.' as i32
        {
            cur = cur.offset(1);
        }
        if *cur as libc::c_int == ':' as i32 {
            cur = cur.offset(1);
            if *cur as libc::c_int >= 'a' as i32 && *cur as libc::c_int <= 'z' as i32
                || *cur as libc::c_int >= 'A' as i32 && *cur as libc::c_int <= 'Z' as i32
                || *cur as libc::c_int == '_' as i32
            {
                cur = cur.offset(1);
                while *cur as libc::c_int >= 'a' as i32
                    && *cur as libc::c_int <= 'z' as i32
                    || *cur as libc::c_int >= 'A' as i32
                        && *cur as libc::c_int <= 'Z' as i32
                    || *cur as libc::c_int >= '0' as i32
                        && *cur as libc::c_int <= '9' as i32
                    || *cur as libc::c_int == '_' as i32
                    || *cur as libc::c_int == '-' as i32
                    || *cur as libc::c_int == '.' as i32
                {
                    cur = cur.offset(1);
                }
                current_block = 1054647088692577877;
            } else {
                current_block = 9464916090564301178;
            }
        } else {
            current_block = 1054647088692577877;
        }
        match current_block {
            9464916090564301178 => {}
            _ => {
                if space != 0 {
                    while *cur as libc::c_int == 0x20 as libc::c_int
                        || 0x9 as libc::c_int <= *cur as libc::c_int
                            && *cur as libc::c_int <= 0xa as libc::c_int
                        || *cur as libc::c_int == 0xd as libc::c_int
                    {
                        cur = cur.offset(1);
                    }
                }
                if *cur as libc::c_int == 0 as libc::c_int {
                    return 0 as libc::c_int;
                }
            }
        }
    }
    cur = value;
    c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
    if space != 0 {
        while if c < 0x100 as libc::c_int {
            (c == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= c && c <= 0xa as libc::c_int
                || c == 0xd as libc::c_int) as libc::c_int
        } else {
            0 as libc::c_int
        } != 0
        {
            cur = cur.offset(l as isize);
            c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
        }
    }
    if !((if c < 0x100 as libc::c_int {
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
        }) != 0) && c != '_' as i32
    {
        return 1 as libc::c_int;
    }
    cur = cur.offset(l as isize);
    c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
    while (if c < 0x100 as libc::c_int {
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
        || (if c < 0x100 as libc::c_int {
            0 as libc::c_int
        } else {
            xmlCharInRange(c as libc::c_uint, &xmlIsCombiningGroup)
        }) != 0
        || (if c < 0x100 as libc::c_int {
            (c == 0xb7 as libc::c_int) as libc::c_int
        } else {
            xmlCharInRange(c as libc::c_uint, &xmlIsExtenderGroup)
        }) != 0
    {
        cur = cur.offset(l as isize);
        c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
    }
    if c == ':' as i32 {
        cur = cur.offset(l as isize);
        c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
        if !((if c < 0x100 as libc::c_int {
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
            }) != 0) && c != '_' as i32
        {
            return 1 as libc::c_int;
        }
        cur = cur.offset(l as isize);
        c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
        while (if c < 0x100 as libc::c_int {
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
            || (if c < 0x100 as libc::c_int {
                0 as libc::c_int
            } else {
                xmlCharInRange(c as libc::c_uint, &xmlIsCombiningGroup)
            }) != 0
            || (if c < 0x100 as libc::c_int {
                (c == 0xb7 as libc::c_int) as libc::c_int
            } else {
                xmlCharInRange(c as libc::c_uint, &xmlIsExtenderGroup)
            }) != 0
        {
            cur = cur.offset(l as isize);
            c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
        }
    }
    if space != 0 {
        while if c < 0x100 as libc::c_int {
            (c == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= c && c <= 0xa as libc::c_int
                || c == 0xd as libc::c_int) as libc::c_int
        } else {
            0 as libc::c_int
        } != 0
        {
            cur = cur.offset(l as isize);
            c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
        }
    }
    if c != 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateName(
    mut value: *const xmlChar,
    mut space: libc::c_int,
) -> libc::c_int {
    let mut cur: *const xmlChar = value;
    let mut c: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    if value.is_null() {
        return -(1 as libc::c_int);
    }
    if space != 0 {
        while *cur as libc::c_int == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= *cur as libc::c_int
                && *cur as libc::c_int <= 0xa as libc::c_int
            || *cur as libc::c_int == 0xd as libc::c_int
        {
            cur = cur.offset(1);
        }
    }
    if *cur as libc::c_int >= 'a' as i32 && *cur as libc::c_int <= 'z' as i32
        || *cur as libc::c_int >= 'A' as i32 && *cur as libc::c_int <= 'Z' as i32
        || *cur as libc::c_int == '_' as i32 || *cur as libc::c_int == ':' as i32
    {
        cur = cur.offset(1);
        while *cur as libc::c_int >= 'a' as i32 && *cur as libc::c_int <= 'z' as i32
            || *cur as libc::c_int >= 'A' as i32 && *cur as libc::c_int <= 'Z' as i32
            || *cur as libc::c_int >= '0' as i32 && *cur as libc::c_int <= '9' as i32
            || *cur as libc::c_int == '_' as i32 || *cur as libc::c_int == '-' as i32
            || *cur as libc::c_int == '.' as i32 || *cur as libc::c_int == ':' as i32
        {
            cur = cur.offset(1);
        }
        if space != 0 {
            while *cur as libc::c_int == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= *cur as libc::c_int
                    && *cur as libc::c_int <= 0xa as libc::c_int
                || *cur as libc::c_int == 0xd as libc::c_int
            {
                cur = cur.offset(1);
            }
        }
        if *cur as libc::c_int == 0 as libc::c_int {
            return 0 as libc::c_int;
        }
    }
    cur = value;
    c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
    if space != 0 {
        while if c < 0x100 as libc::c_int {
            (c == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= c && c <= 0xa as libc::c_int
                || c == 0xd as libc::c_int) as libc::c_int
        } else {
            0 as libc::c_int
        } != 0
        {
            cur = cur.offset(l as isize);
            c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
        }
    }
    if !((if c < 0x100 as libc::c_int {
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
        return 1 as libc::c_int;
    }
    cur = cur.offset(l as isize);
    c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
    while (if c < 0x100 as libc::c_int {
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
        }) != 0 || c == '.' as i32 || c == ':' as i32 || c == '-' as i32
        || c == '_' as i32
        || (if c < 0x100 as libc::c_int {
            0 as libc::c_int
        } else {
            xmlCharInRange(c as libc::c_uint, &xmlIsCombiningGroup)
        }) != 0
        || (if c < 0x100 as libc::c_int {
            (c == 0xb7 as libc::c_int) as libc::c_int
        } else {
            xmlCharInRange(c as libc::c_uint, &xmlIsExtenderGroup)
        }) != 0
    {
        cur = cur.offset(l as isize);
        c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
    }
    if space != 0 {
        while if c < 0x100 as libc::c_int {
            (c == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= c && c <= 0xa as libc::c_int
                || c == 0xd as libc::c_int) as libc::c_int
        } else {
            0 as libc::c_int
        } != 0
        {
            cur = cur.offset(l as isize);
            c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
        }
    }
    if c != 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateNMToken(
    mut value: *const xmlChar,
    mut space: libc::c_int,
) -> libc::c_int {
    let mut cur: *const xmlChar = value;
    let mut c: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    if value.is_null() {
        return -(1 as libc::c_int);
    }
    if space != 0 {
        while *cur as libc::c_int == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= *cur as libc::c_int
                && *cur as libc::c_int <= 0xa as libc::c_int
            || *cur as libc::c_int == 0xd as libc::c_int
        {
            cur = cur.offset(1);
        }
    }
    if *cur as libc::c_int >= 'a' as i32 && *cur as libc::c_int <= 'z' as i32
        || *cur as libc::c_int >= 'A' as i32 && *cur as libc::c_int <= 'Z' as i32
        || *cur as libc::c_int >= '0' as i32 && *cur as libc::c_int <= '9' as i32
        || *cur as libc::c_int == '_' as i32 || *cur as libc::c_int == '-' as i32
        || *cur as libc::c_int == '.' as i32 || *cur as libc::c_int == ':' as i32
    {
        cur = cur.offset(1);
        while *cur as libc::c_int >= 'a' as i32 && *cur as libc::c_int <= 'z' as i32
            || *cur as libc::c_int >= 'A' as i32 && *cur as libc::c_int <= 'Z' as i32
            || *cur as libc::c_int >= '0' as i32 && *cur as libc::c_int <= '9' as i32
            || *cur as libc::c_int == '_' as i32 || *cur as libc::c_int == '-' as i32
            || *cur as libc::c_int == '.' as i32 || *cur as libc::c_int == ':' as i32
        {
            cur = cur.offset(1);
        }
        if space != 0 {
            while *cur as libc::c_int == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= *cur as libc::c_int
                    && *cur as libc::c_int <= 0xa as libc::c_int
                || *cur as libc::c_int == 0xd as libc::c_int
            {
                cur = cur.offset(1);
            }
        }
        if *cur as libc::c_int == 0 as libc::c_int {
            return 0 as libc::c_int;
        }
    }
    cur = value;
    c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
    if space != 0 {
        while if c < 0x100 as libc::c_int {
            (c == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= c && c <= 0xa as libc::c_int
                || c == 0xd as libc::c_int) as libc::c_int
        } else {
            0 as libc::c_int
        } != 0
        {
            cur = cur.offset(l as isize);
            c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
        }
    }
    if !((if c < 0x100 as libc::c_int {
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
        }) != 0 || c == '.' as i32 || c == ':' as i32 || c == '-' as i32
        || c == '_' as i32
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
        return 1 as libc::c_int;
    }
    cur = cur.offset(l as isize);
    c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
    while (if c < 0x100 as libc::c_int {
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
        }) != 0 || c == '.' as i32 || c == ':' as i32 || c == '-' as i32
        || c == '_' as i32
        || (if c < 0x100 as libc::c_int {
            0 as libc::c_int
        } else {
            xmlCharInRange(c as libc::c_uint, &xmlIsCombiningGroup)
        }) != 0
        || (if c < 0x100 as libc::c_int {
            (c == 0xb7 as libc::c_int) as libc::c_int
        } else {
            xmlCharInRange(c as libc::c_uint, &xmlIsExtenderGroup)
        }) != 0
    {
        cur = cur.offset(l as isize);
        c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
    }
    if space != 0 {
        while if c < 0x100 as libc::c_int {
            (c == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= c && c <= 0xa as libc::c_int
                || c == 0xd as libc::c_int) as libc::c_int
        } else {
            0 as libc::c_int
        } != 0
        {
            cur = cur.offset(l as isize);
            c = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l);
        }
    }
    if c != 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetBufferAllocationScheme(
    mut scheme: xmlBufferAllocationScheme,
) {
    if scheme as libc::c_uint == XML_BUFFER_ALLOC_EXACT as libc::c_int as libc::c_uint
        || scheme as libc::c_uint
            == XML_BUFFER_ALLOC_DOUBLEIT as libc::c_int as libc::c_uint
        || scheme as libc::c_uint
            == XML_BUFFER_ALLOC_HYBRID as libc::c_int as libc::c_uint
    {
        *__xmlBufferAllocScheme() = scheme;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetBufferAllocationScheme() -> xmlBufferAllocationScheme {
    return *__xmlBufferAllocScheme();
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewNs(
    mut node: xmlNodePtr,
    mut href: *const xmlChar,
    mut prefix: *const xmlChar,
) -> xmlNsPtr {
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    if !node.is_null()
        && (*node).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        return 0 as xmlNsPtr;
    }
    if !prefix.is_null()
        && xmlStrEqual(
            prefix,
            b"xml\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
    {
        if xmlStrEqual(
            href,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
                as *const xmlChar,
        ) != 0
        {
            return 0 as xmlNsPtr;
        }
    }
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNs>() as libc::c_ulong) as xmlNsPtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building namespace\0" as *const u8 as *const libc::c_char);
        return 0 as xmlNsPtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNs>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_NAMESPACE_DECL;
    if !href.is_null() {
        let ref mut fresh0 = (*cur).href;
        *fresh0 = xmlStrdup(href);
    }
    if !prefix.is_null() {
        let ref mut fresh1 = (*cur).prefix;
        *fresh1 = xmlStrdup(prefix);
    }
    if !node.is_null() {
        if ((*node).nsDef).is_null() {
            let ref mut fresh2 = (*node).nsDef;
            *fresh2 = cur;
        } else {
            let mut prev: xmlNsPtr = (*node).nsDef;
            if ((*prev).prefix).is_null() && ((*cur).prefix).is_null()
                || xmlStrEqual((*prev).prefix, (*cur).prefix) != 0
            {
                xmlFreeNs(cur);
                return 0 as xmlNsPtr;
            }
            while !((*prev).next).is_null() {
                prev = (*prev).next;
                if ((*prev).prefix).is_null() && ((*cur).prefix).is_null()
                    || xmlStrEqual((*prev).prefix, (*cur).prefix) != 0
                {
                    xmlFreeNs(cur);
                    return 0 as xmlNsPtr;
                }
            }
            let ref mut fresh3 = (*prev).next;
            *fresh3 = cur;
        }
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetNs(mut node: xmlNodePtr, mut ns: xmlNsPtr) {
    if node.is_null() {
        return;
    }
    if (*node).type_0 as libc::c_uint == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        || (*node).type_0 as libc::c_uint
            == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
    {
        let ref mut fresh4 = (*node).ns;
        *fresh4 = ns;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeNs(mut cur: xmlNsPtr) {
    if cur.is_null() {
        return;
    }
    if !((*cur).href).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*cur).href as *mut libc::c_char as *mut libc::c_void);
    }
    if !((*cur).prefix).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*cur).prefix as *mut libc::c_char as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeNsList(mut cur: xmlNsPtr) {
    let mut next: xmlNsPtr = 0 as *mut xmlNs;
    if cur.is_null() {
        return;
    }
    while !cur.is_null() {
        next = (*cur).next;
        xmlFreeNs(cur);
        cur = next;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewDtd(
    mut doc: xmlDocPtr,
    mut name: *const xmlChar,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) -> xmlDtdPtr {
    let mut cur: xmlDtdPtr = 0 as *mut xmlDtd;
    if !doc.is_null() && !((*doc).extSubset).is_null() {
        return 0 as xmlDtdPtr;
    }
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlDtd>() as libc::c_ulong) as xmlDtdPtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building DTD\0" as *const u8 as *const libc::c_char);
        return 0 as xmlDtdPtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlDtd>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_DTD_NODE;
    if !name.is_null() {
        let ref mut fresh5 = (*cur).name;
        *fresh5 = xmlStrdup(name);
    }
    if !ExternalID.is_null() {
        let ref mut fresh6 = (*cur).ExternalID;
        *fresh6 = xmlStrdup(ExternalID);
    }
    if !SystemID.is_null() {
        let ref mut fresh7 = (*cur).SystemID;
        *fresh7 = xmlStrdup(SystemID);
    }
    if !doc.is_null() {
        let ref mut fresh8 = (*doc).extSubset;
        *fresh8 = cur;
    }
    let ref mut fresh9 = (*cur).doc;
    *fresh9 = doc;
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue())
            .expect("non-null function pointer")(cur as xmlNodePtr);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetIntSubset(mut doc: *const xmlDoc) -> xmlDtdPtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if doc.is_null() {
        return 0 as xmlDtdPtr;
    }
    cur = (*doc).children;
    while !cur.is_null() {
        if (*cur).type_0 as libc::c_uint == XML_DTD_NODE as libc::c_int as libc::c_uint {
            return cur as xmlDtdPtr;
        }
        cur = (*cur).next;
    }
    return (*doc).intSubset as xmlDtdPtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateIntSubset(
    mut doc: xmlDocPtr,
    mut name: *const xmlChar,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) -> xmlDtdPtr {
    let mut cur: xmlDtdPtr = 0 as *mut xmlDtd;
    if !doc.is_null() && !(xmlGetIntSubset(doc as *const xmlDoc)).is_null() {
        return 0 as xmlDtdPtr;
    }
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlDtd>() as libc::c_ulong) as xmlDtdPtr;
    if cur.is_null() {
        xmlTreeErrMemory(
            b"building internal subset\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlDtdPtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlDtd>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_DTD_NODE;
    if !name.is_null() {
        let ref mut fresh10 = (*cur).name;
        *fresh10 = xmlStrdup(name);
        if ((*cur).name).is_null() {
            xmlTreeErrMemory(
                b"building internal subset\0" as *const u8 as *const libc::c_char,
            );
            xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
            return 0 as xmlDtdPtr;
        }
    }
    if !ExternalID.is_null() {
        let ref mut fresh11 = (*cur).ExternalID;
        *fresh11 = xmlStrdup(ExternalID);
        if ((*cur).ExternalID).is_null() {
            xmlTreeErrMemory(
                b"building internal subset\0" as *const u8 as *const libc::c_char,
            );
            if !((*cur).name).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*cur).name as *mut libc::c_char as *mut libc::c_void);
            }
            xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
            return 0 as xmlDtdPtr;
        }
    }
    if !SystemID.is_null() {
        let ref mut fresh12 = (*cur).SystemID;
        *fresh12 = xmlStrdup(SystemID);
        if ((*cur).SystemID).is_null() {
            xmlTreeErrMemory(
                b"building internal subset\0" as *const u8 as *const libc::c_char,
            );
            if !((*cur).name).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*cur).name as *mut libc::c_char as *mut libc::c_void);
            }
            if !((*cur).ExternalID).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*cur).ExternalID as *mut libc::c_char as *mut libc::c_void);
            }
            xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
            return 0 as xmlDtdPtr;
        }
    }
    if !doc.is_null() {
        let ref mut fresh13 = (*doc).intSubset;
        *fresh13 = cur;
        let ref mut fresh14 = (*cur).parent;
        *fresh14 = doc;
        let ref mut fresh15 = (*cur).doc;
        *fresh15 = doc;
        if ((*doc).children).is_null() {
            let ref mut fresh16 = (*doc).children;
            *fresh16 = cur as xmlNodePtr;
            let ref mut fresh17 = (*doc).last;
            *fresh17 = cur as xmlNodePtr;
        } else if (*doc).type_0 as libc::c_uint
                == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
            {
            let mut prev: xmlNodePtr = 0 as *mut xmlNode;
            prev = (*doc).children;
            let ref mut fresh18 = (*prev).prev;
            *fresh18 = cur as xmlNodePtr;
            let ref mut fresh19 = (*cur).next;
            *fresh19 = prev;
            let ref mut fresh20 = (*doc).children;
            *fresh20 = cur as xmlNodePtr;
        } else {
            let mut next: xmlNodePtr = 0 as *mut xmlNode;
            next = (*doc).children;
            while !next.is_null()
                && (*next).type_0 as libc::c_uint
                    != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
            {
                next = (*next).next;
            }
            if next.is_null() {
                let ref mut fresh21 = (*cur).prev;
                *fresh21 = (*doc).last;
                let ref mut fresh22 = (*(*cur).prev).next;
                *fresh22 = cur as xmlNodePtr;
                let ref mut fresh23 = (*cur).next;
                *fresh23 = 0 as *mut _xmlNode;
                let ref mut fresh24 = (*doc).last;
                *fresh24 = cur as xmlNodePtr;
            } else {
                let ref mut fresh25 = (*cur).next;
                *fresh25 = next;
                let ref mut fresh26 = (*cur).prev;
                *fresh26 = (*next).prev;
                if ((*cur).prev).is_null() {
                    let ref mut fresh27 = (*doc).children;
                    *fresh27 = cur as xmlNodePtr;
                } else {
                    let ref mut fresh28 = (*(*cur).prev).next;
                    *fresh28 = cur as xmlNodePtr;
                }
                let ref mut fresh29 = (*next).prev;
                *fresh29 = cur as xmlNodePtr;
            }
        }
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue())
            .expect("non-null function pointer")(cur as xmlNodePtr);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeDtd(mut cur: xmlDtdPtr) {
    let mut dict: xmlDictPtr = 0 as xmlDictPtr;
    if cur.is_null() {
        return;
    }
    if !((*cur).doc).is_null() {
        dict = (*(*cur).doc).dict;
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlDeregisterNodeDefaultValue()).is_some() {
        (*__xmlDeregisterNodeDefaultValue())
            .expect("non-null function pointer")(cur as xmlNodePtr);
    }
    if !((*cur).children).is_null() {
        let mut next: xmlNodePtr = 0 as *mut xmlNode;
        let mut c: xmlNodePtr = (*cur).children;
        while !c.is_null() {
            next = (*c).next;
            if (*c).type_0 as libc::c_uint
                != XML_NOTATION_NODE as libc::c_int as libc::c_uint
                && (*c).type_0 as libc::c_uint
                    != XML_ELEMENT_DECL as libc::c_int as libc::c_uint
                && (*c).type_0 as libc::c_uint
                    != XML_ATTRIBUTE_DECL as libc::c_int as libc::c_uint
                && (*c).type_0 as libc::c_uint
                    != XML_ENTITY_DECL as libc::c_int as libc::c_uint
            {
                xmlUnlinkNode(c);
                xmlFreeNode(c);
            }
            c = next;
        }
    }
    if !((*cur).name).is_null()
        && (dict.is_null() || xmlDictOwns(dict, (*cur).name) == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*cur).name as *mut libc::c_char as *mut libc::c_void);
    }
    if !((*cur).SystemID).is_null()
        && (dict.is_null() || xmlDictOwns(dict, (*cur).SystemID) == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*cur).SystemID as *mut libc::c_char as *mut libc::c_void);
    }
    if !((*cur).ExternalID).is_null()
        && (dict.is_null() || xmlDictOwns(dict, (*cur).ExternalID) == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*cur).ExternalID as *mut libc::c_char as *mut libc::c_void);
    }
    if !((*cur).notations).is_null() {
        xmlFreeNotationTable((*cur).notations as xmlNotationTablePtr);
    }
    if !((*cur).elements).is_null() {
        xmlFreeElementTable((*cur).elements as xmlElementTablePtr);
    }
    if !((*cur).attributes).is_null() {
        xmlFreeAttributeTable((*cur).attributes as xmlAttributeTablePtr);
    }
    if !((*cur).entities).is_null() {
        xmlFreeEntitiesTable((*cur).entities as xmlEntitiesTablePtr);
    }
    if !((*cur).pentities).is_null() {
        xmlFreeEntitiesTable((*cur).pentities as xmlEntitiesTablePtr);
    }
    xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewDoc(mut version: *const xmlChar) -> xmlDocPtr {
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    if version.is_null() {
        version = b"1.0\0" as *const u8 as *const libc::c_char as *const xmlChar;
    }
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlDoc>() as libc::c_ulong) as xmlDocPtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building doc\0" as *const u8 as *const libc::c_char);
        return 0 as xmlDocPtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlDoc>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_DOCUMENT_NODE;
    let ref mut fresh30 = (*cur).version;
    *fresh30 = xmlStrdup(version);
    if ((*cur).version).is_null() {
        xmlTreeErrMemory(b"building doc\0" as *const u8 as *const libc::c_char);
        xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
        return 0 as xmlDocPtr;
    }
    (*cur).standalone = -(1 as libc::c_int);
    (*cur).compression = -(1 as libc::c_int);
    let ref mut fresh31 = (*cur).doc;
    *fresh31 = cur;
    (*cur).parseFlags = 0 as libc::c_int;
    (*cur).properties = XML_DOC_USERBUILT as libc::c_int;
    (*cur).charset = XML_CHAR_ENCODING_UTF8 as libc::c_int;
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue())
            .expect("non-null function pointer")(cur as xmlNodePtr);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeDoc(mut cur: xmlDocPtr) {
    let mut extSubset: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut intSubset: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut dict: xmlDictPtr = 0 as xmlDictPtr;
    if cur.is_null() {
        return;
    }
    if !cur.is_null() {
        dict = (*cur).dict;
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlDeregisterNodeDefaultValue()).is_some() {
        (*__xmlDeregisterNodeDefaultValue())
            .expect("non-null function pointer")(cur as xmlNodePtr);
    }
    if !((*cur).ids).is_null() {
        xmlFreeIDTable((*cur).ids as xmlIDTablePtr);
    }
    let ref mut fresh32 = (*cur).ids;
    *fresh32 = 0 as *mut libc::c_void;
    if !((*cur).refs).is_null() {
        xmlFreeRefTable((*cur).refs as xmlRefTablePtr);
    }
    let ref mut fresh33 = (*cur).refs;
    *fresh33 = 0 as *mut libc::c_void;
    extSubset = (*cur).extSubset;
    intSubset = (*cur).intSubset;
    if intSubset == extSubset {
        extSubset = 0 as xmlDtdPtr;
    }
    if !extSubset.is_null() {
        xmlUnlinkNode((*cur).extSubset as xmlNodePtr);
        let ref mut fresh34 = (*cur).extSubset;
        *fresh34 = 0 as *mut _xmlDtd;
        xmlFreeDtd(extSubset);
    }
    if !intSubset.is_null() {
        xmlUnlinkNode((*cur).intSubset as xmlNodePtr);
        let ref mut fresh35 = (*cur).intSubset;
        *fresh35 = 0 as *mut _xmlDtd;
        xmlFreeDtd(intSubset);
    }
    if !((*cur).children).is_null() {
        xmlFreeNodeList((*cur).children);
    }
    if !((*cur).oldNs).is_null() {
        xmlFreeNsList((*cur).oldNs);
    }
    if !((*cur).version).is_null()
        && (dict.is_null() || xmlDictOwns(dict, (*cur).version) == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*cur).version as *mut libc::c_char as *mut libc::c_void);
    }
    if !((*cur).name).is_null()
        && (dict.is_null()
            || xmlDictOwns(dict, (*cur).name as *const xmlChar) == 0 as libc::c_int)
    {
        xmlFree.expect("non-null function pointer")((*cur).name as *mut libc::c_void);
    }
    if !((*cur).encoding).is_null()
        && (dict.is_null() || xmlDictOwns(dict, (*cur).encoding) == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*cur).encoding as *mut libc::c_char as *mut libc::c_void);
    }
    if !((*cur).URL).is_null()
        && (dict.is_null() || xmlDictOwns(dict, (*cur).URL) == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*cur).URL as *mut libc::c_char as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
    if !dict.is_null() {
        xmlDictFree(dict);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlStringLenGetNodeList(
    mut doc: *const xmlDoc,
    mut value: *const xmlChar,
    mut len: libc::c_int,
) -> xmlNodePtr {
    let mut current_block: u64;
    let mut ret: xmlNodePtr = 0 as xmlNodePtr;
    let mut last: xmlNodePtr = 0 as xmlNodePtr;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut end: *const xmlChar = 0 as *const xmlChar;
    let mut q: *const xmlChar = 0 as *const xmlChar;
    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut buf: xmlBufPtr = 0 as *mut xmlBuf;
    if value.is_null() {
        return 0 as xmlNodePtr;
    }
    cur = value;
    end = cur.offset(len as isize);
    buf = xmlBufCreateSize(0 as libc::c_int as size_t);
    if buf.is_null() {
        return 0 as xmlNodePtr;
    }
    xmlBufSetAllocationScheme(buf, XML_BUFFER_ALLOC_DOUBLEIT);
    q = cur;
    loop {
        if !(cur < end && *cur as libc::c_int != 0 as libc::c_int) {
            current_block = 8656139126282042408;
            break;
        }
        if *cur.offset(0 as libc::c_int as isize) as libc::c_int == '&' as i32 {
            let mut charval: libc::c_int = 0 as libc::c_int;
            let mut tmp: xmlChar = 0;
            if cur != q {
                if xmlBufAdd(buf, q, cur.offset_from(q) as libc::c_long as libc::c_int)
                    != 0
                {
                    current_block = 13579860642496470364;
                    break;
                }
            }
            q = cur;
            if cur.offset(2 as libc::c_int as isize) < end
                && *cur.offset(1 as libc::c_int as isize) as libc::c_int == '#' as i32
                && *cur.offset(2 as libc::c_int as isize) as libc::c_int == 'x' as i32
            {
                cur = cur.offset(3 as libc::c_int as isize);
                if cur < end {
                    tmp = *cur;
                } else {
                    tmp = 0 as libc::c_int as xmlChar;
                }
                while tmp as libc::c_int != ';' as i32 {
                    if tmp as libc::c_int >= '0' as i32
                        && tmp as libc::c_int <= '9' as i32
                    {
                        charval = charval * 16 as libc::c_int
                            + (tmp as libc::c_int - '0' as i32);
                    } else if tmp as libc::c_int >= 'a' as i32
                            && tmp as libc::c_int <= 'f' as i32
                        {
                        charval = charval * 16 as libc::c_int
                            + (tmp as libc::c_int - 'a' as i32) + 10 as libc::c_int;
                    } else if tmp as libc::c_int >= 'A' as i32
                            && tmp as libc::c_int <= 'F' as i32
                        {
                        charval = charval * 16 as libc::c_int
                            + (tmp as libc::c_int - 'A' as i32) + 10 as libc::c_int;
                    } else {
                        xmlTreeErr(
                            XML_TREE_INVALID_HEX as libc::c_int,
                            doc as xmlNodePtr,
                            0 as *const libc::c_char,
                        );
                        charval = 0 as libc::c_int;
                        break;
                    }
                    cur = cur.offset(1);
                    if cur < end {
                        tmp = *cur;
                    } else {
                        tmp = 0 as libc::c_int as xmlChar;
                    }
                }
                if tmp as libc::c_int == ';' as i32 {
                    cur = cur.offset(1);
                }
                q = cur;
            } else if cur.offset(1 as libc::c_int as isize) < end
                    && *cur.offset(1 as libc::c_int as isize) as libc::c_int
                        == '#' as i32
                {
                cur = cur.offset(2 as libc::c_int as isize);
                if cur < end {
                    tmp = *cur;
                } else {
                    tmp = 0 as libc::c_int as xmlChar;
                }
                while tmp as libc::c_int != ';' as i32 {
                    if tmp as libc::c_int >= '0' as i32
                        && tmp as libc::c_int <= '9' as i32
                    {
                        charval = charval * 10 as libc::c_int
                            + (tmp as libc::c_int - '0' as i32);
                        cur = cur.offset(1);
                        if cur < end {
                            tmp = *cur;
                        } else {
                            tmp = 0 as libc::c_int as xmlChar;
                        }
                    } else {
                        xmlTreeErr(
                            XML_TREE_INVALID_DEC as libc::c_int,
                            doc as xmlNodePtr,
                            0 as *const libc::c_char,
                        );
                        charval = 0 as libc::c_int;
                        break;
                    }
                }
                if tmp as libc::c_int == ';' as i32 {
                    cur = cur.offset(1);
                }
                q = cur;
            } else {
                cur = cur.offset(1);
                q = cur;
                while cur < end && *cur as libc::c_int != 0 as libc::c_int
                    && *cur as libc::c_int != ';' as i32
                {
                    cur = cur.offset(1);
                }
                if cur >= end || *cur as libc::c_int == 0 as libc::c_int {
                    xmlTreeErr(
                        XML_TREE_UNTERMINATED_ENTITY as libc::c_int,
                        doc as xmlNodePtr,
                        q as *const libc::c_char,
                    );
                    current_block = 13579860642496470364;
                    break;
                } else {
                    if cur != q {
                        val = xmlStrndup(
                            q,
                            cur.offset_from(q) as libc::c_long as libc::c_int,
                        );
                        ent = xmlGetDocEntity(doc, val);
                        if !ent.is_null()
                            && (*ent).etype as libc::c_uint
                                == XML_INTERNAL_PREDEFINED_ENTITY as libc::c_int
                                    as libc::c_uint
                        {
                            if xmlBufCat(buf, (*ent).content) != 0 {
                                current_block = 13579860642496470364;
                                break;
                            }
                        } else {
                            if xmlBufIsEmpty(buf) == 0 {
                                node = xmlNewDocText(doc, 0 as *const xmlChar);
                                if node.is_null() {
                                    if !val.is_null() {
                                        xmlFree
                                            .expect(
                                                "non-null function pointer",
                                            )(val as *mut libc::c_void);
                                    }
                                    current_block = 13579860642496470364;
                                    break;
                                } else {
                                    let ref mut fresh36 = (*node).content;
                                    *fresh36 = xmlBufDetach(buf);
                                    if last.is_null() {
                                        ret = node;
                                        last = ret;
                                    } else {
                                        last = xmlAddNextSibling(last, node);
                                    }
                                }
                            }
                            node = xmlNewReference(doc, val);
                            if node.is_null() {
                                if !val.is_null() {
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(val as *mut libc::c_void);
                                }
                                current_block = 13579860642496470364;
                                break;
                            } else {
                                if !ent.is_null() && ((*ent).children).is_null() {
                                    let mut temp: xmlNodePtr = 0 as *mut xmlNode;
                                    let ref mut fresh37 = (*ent).children;
                                    *fresh37 = -(1 as libc::c_int) as xmlNodePtr;
                                    let ref mut fresh38 = (*ent).children;
                                    *fresh38 = xmlStringGetNodeList(
                                        doc,
                                        (*node).content as *const xmlChar,
                                    );
                                    (*ent).owner = 1 as libc::c_int;
                                    temp = (*ent).children;
                                    while !temp.is_null() {
                                        let ref mut fresh39 = (*temp).parent;
                                        *fresh39 = ent as xmlNodePtr;
                                        let ref mut fresh40 = (*ent).last;
                                        *fresh40 = temp;
                                        temp = (*temp).next;
                                    }
                                }
                                if last.is_null() {
                                    ret = node;
                                    last = ret;
                                } else {
                                    last = xmlAddNextSibling(last, node);
                                }
                            }
                        }
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(val as *mut libc::c_void);
                    }
                    cur = cur.offset(1);
                    q = cur;
                }
            }
            if !(charval != 0 as libc::c_int) {
                continue;
            }
            let mut buffer: [xmlChar; 10] = [0; 10];
            let mut l: libc::c_int = 0;
            l = xmlCopyCharMultiByte(buffer.as_mut_ptr(), charval);
            buffer[l as usize] = 0 as libc::c_int as xmlChar;
            if xmlBufCat(buf, buffer.as_mut_ptr()) != 0 {
                current_block = 13579860642496470364;
                break;
            }
            charval = 0 as libc::c_int;
        } else {
            cur = cur.offset(1);
        }
    }
    match current_block {
        8656139126282042408 => {
            if cur != q {
                if xmlBufAdd(buf, q, cur.offset_from(q) as libc::c_long as libc::c_int)
                    != 0
                {
                    current_block = 13579860642496470364;
                } else {
                    current_block = 14953815020842398287;
                }
            } else {
                current_block = 14953815020842398287;
            }
            match current_block {
                13579860642496470364 => {}
                _ => {
                    if xmlBufIsEmpty(buf) == 0 {
                        node = xmlNewDocText(doc, 0 as *const xmlChar);
                        if !node.is_null() {
                            let ref mut fresh41 = (*node).content;
                            *fresh41 = xmlBufDetach(buf);
                            if last.is_null() {
                                ret = node;
                            } else {
                                xmlAddNextSibling(last, node);
                            }
                        }
                    } else if ret.is_null() {
                        ret = xmlNewDocText(
                            doc,
                            b"\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                        );
                    }
                }
            }
        }
        _ => {}
    }
    xmlBufFree(buf);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStringGetNodeList(
    mut doc: *const xmlDoc,
    mut value: *const xmlChar,
) -> xmlNodePtr {
    let mut current_block: u64;
    let mut ret: xmlNodePtr = 0 as xmlNodePtr;
    let mut last: xmlNodePtr = 0 as xmlNodePtr;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *const xmlChar = value;
    let mut q: *const xmlChar = 0 as *const xmlChar;
    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut buf: xmlBufPtr = 0 as *mut xmlBuf;
    if value.is_null() {
        return 0 as xmlNodePtr;
    }
    buf = xmlBufCreateSize(0 as libc::c_int as size_t);
    if buf.is_null() {
        return 0 as xmlNodePtr;
    }
    xmlBufSetAllocationScheme(buf, XML_BUFFER_ALLOC_DOUBLEIT);
    q = cur;
    loop {
        if !(*cur as libc::c_int != 0 as libc::c_int) {
            current_block = 3217137713928741134;
            break;
        }
        if *cur.offset(0 as libc::c_int as isize) as libc::c_int == '&' as i32 {
            let mut charval: libc::c_int = 0 as libc::c_int;
            let mut tmp: xmlChar = 0;
            if cur != q {
                if xmlBufAdd(buf, q, cur.offset_from(q) as libc::c_long as libc::c_int)
                    != 0
                {
                    current_block = 16011119045367533822;
                    break;
                }
            }
            q = cur;
            if *cur.offset(1 as libc::c_int as isize) as libc::c_int == '#' as i32
                && *cur.offset(2 as libc::c_int as isize) as libc::c_int == 'x' as i32
            {
                cur = cur.offset(3 as libc::c_int as isize);
                tmp = *cur;
                while tmp as libc::c_int != ';' as i32 {
                    if tmp as libc::c_int >= '0' as i32
                        && tmp as libc::c_int <= '9' as i32
                    {
                        charval = charval * 16 as libc::c_int
                            + (tmp as libc::c_int - '0' as i32);
                    } else if tmp as libc::c_int >= 'a' as i32
                            && tmp as libc::c_int <= 'f' as i32
                        {
                        charval = charval * 16 as libc::c_int
                            + (tmp as libc::c_int - 'a' as i32) + 10 as libc::c_int;
                    } else if tmp as libc::c_int >= 'A' as i32
                            && tmp as libc::c_int <= 'F' as i32
                        {
                        charval = charval * 16 as libc::c_int
                            + (tmp as libc::c_int - 'A' as i32) + 10 as libc::c_int;
                    } else {
                        xmlTreeErr(
                            XML_TREE_INVALID_HEX as libc::c_int,
                            doc as xmlNodePtr,
                            0 as *const libc::c_char,
                        );
                        charval = 0 as libc::c_int;
                        break;
                    }
                    cur = cur.offset(1);
                    tmp = *cur;
                }
                if tmp as libc::c_int == ';' as i32 {
                    cur = cur.offset(1);
                }
                q = cur;
            } else if *cur.offset(1 as libc::c_int as isize) as libc::c_int == '#' as i32
                {
                cur = cur.offset(2 as libc::c_int as isize);
                tmp = *cur;
                while tmp as libc::c_int != ';' as i32 {
                    if tmp as libc::c_int >= '0' as i32
                        && tmp as libc::c_int <= '9' as i32
                    {
                        charval = charval * 10 as libc::c_int
                            + (tmp as libc::c_int - '0' as i32);
                        cur = cur.offset(1);
                        tmp = *cur;
                    } else {
                        xmlTreeErr(
                            XML_TREE_INVALID_DEC as libc::c_int,
                            doc as xmlNodePtr,
                            0 as *const libc::c_char,
                        );
                        charval = 0 as libc::c_int;
                        break;
                    }
                }
                if tmp as libc::c_int == ';' as i32 {
                    cur = cur.offset(1);
                }
                q = cur;
            } else {
                cur = cur.offset(1);
                q = cur;
                while *cur as libc::c_int != 0 as libc::c_int
                    && *cur as libc::c_int != ';' as i32
                {
                    cur = cur.offset(1);
                }
                if *cur as libc::c_int == 0 as libc::c_int {
                    xmlTreeErr(
                        XML_TREE_UNTERMINATED_ENTITY as libc::c_int,
                        doc as xmlNodePtr,
                        q as *const libc::c_char,
                    );
                    current_block = 16011119045367533822;
                    break;
                } else {
                    if cur != q {
                        val = xmlStrndup(
                            q,
                            cur.offset_from(q) as libc::c_long as libc::c_int,
                        );
                        ent = xmlGetDocEntity(doc, val);
                        if !ent.is_null()
                            && (*ent).etype as libc::c_uint
                                == XML_INTERNAL_PREDEFINED_ENTITY as libc::c_int
                                    as libc::c_uint
                        {
                            if xmlBufCat(buf, (*ent).content) != 0 {
                                current_block = 16011119045367533822;
                                break;
                            }
                        } else {
                            if xmlBufIsEmpty(buf) == 0 {
                                node = xmlNewDocText(doc, 0 as *const xmlChar);
                                if node.is_null() {
                                    if !val.is_null() {
                                        xmlFree
                                            .expect(
                                                "non-null function pointer",
                                            )(val as *mut libc::c_void);
                                    }
                                    current_block = 16011119045367533822;
                                    break;
                                } else {
                                    let ref mut fresh42 = (*node).content;
                                    *fresh42 = xmlBufDetach(buf);
                                    if last.is_null() {
                                        ret = node;
                                        last = ret;
                                    } else {
                                        last = xmlAddNextSibling(last, node);
                                    }
                                }
                            }
                            node = xmlNewReference(doc, val);
                            if node.is_null() {
                                if !val.is_null() {
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(val as *mut libc::c_void);
                                }
                                current_block = 16011119045367533822;
                                break;
                            } else {
                                if !ent.is_null() && ((*ent).children).is_null() {
                                    let mut temp: xmlNodePtr = 0 as *mut xmlNode;
                                    let ref mut fresh43 = (*ent).children;
                                    *fresh43 = -(1 as libc::c_int) as xmlNodePtr;
                                    let ref mut fresh44 = (*ent).children;
                                    *fresh44 = xmlStringGetNodeList(
                                        doc,
                                        (*node).content as *const xmlChar,
                                    );
                                    (*ent).owner = 1 as libc::c_int;
                                    temp = (*ent).children;
                                    while !temp.is_null() {
                                        let ref mut fresh45 = (*temp).parent;
                                        *fresh45 = ent as xmlNodePtr;
                                        let ref mut fresh46 = (*ent).last;
                                        *fresh46 = temp;
                                        temp = (*temp).next;
                                    }
                                }
                                if last.is_null() {
                                    ret = node;
                                    last = ret;
                                } else {
                                    last = xmlAddNextSibling(last, node);
                                }
                            }
                        }
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(val as *mut libc::c_void);
                    }
                    cur = cur.offset(1);
                    q = cur;
                }
            }
            if !(charval != 0 as libc::c_int) {
                continue;
            }
            let mut buffer: [xmlChar; 10] = [0; 10];
            let mut len: libc::c_int = 0;
            len = xmlCopyCharMultiByte(buffer.as_mut_ptr(), charval);
            buffer[len as usize] = 0 as libc::c_int as xmlChar;
            if xmlBufCat(buf, buffer.as_mut_ptr()) != 0 {
                current_block = 16011119045367533822;
                break;
            }
            charval = 0 as libc::c_int;
        } else {
            cur = cur.offset(1);
        }
    }
    match current_block {
        3217137713928741134 => {
            if cur != q || ret.is_null() {
                xmlBufAdd(buf, q, cur.offset_from(q) as libc::c_long as libc::c_int);
            }
            if xmlBufIsEmpty(buf) == 0 {
                node = xmlNewDocText(doc, 0 as *const xmlChar);
                if node.is_null() {
                    xmlBufFree(buf);
                    return 0 as xmlNodePtr;
                }
                let ref mut fresh47 = (*node).content;
                *fresh47 = xmlBufDetach(buf);
                if last.is_null() {
                    ret = node;
                } else {
                    xmlAddNextSibling(last, node);
                }
            }
        }
        _ => {}
    }
    xmlBufFree(buf);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeListGetString(
    mut doc: xmlDocPtr,
    mut list: *const xmlNode,
    mut inLine: libc::c_int,
) -> *mut xmlChar {
    let mut node: *const xmlNode = list;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut attr: libc::c_int = 0;
    if list.is_null() {
        return 0 as *mut xmlChar;
    }
    if !((*list).parent).is_null()
        && (*(*list).parent).type_0 as libc::c_uint
            == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
    {
        attr = 1 as libc::c_int;
    } else {
        attr = 0 as libc::c_int;
    }
    while !node.is_null() {
        if (*node).type_0 as libc::c_uint == XML_TEXT_NODE as libc::c_int as libc::c_uint
            || (*node).type_0 as libc::c_uint
                == XML_CDATA_SECTION_NODE as libc::c_int as libc::c_uint
        {
            if inLine != 0 {
                ret = xmlStrcat(ret, (*node).content);
            } else {
                let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
                if attr != 0 {
                    buffer = xmlEncodeAttributeEntities(doc, (*node).content);
                } else {
                    buffer = xmlEncodeEntitiesReentrant(doc, (*node).content);
                }
                if !buffer.is_null() {
                    ret = xmlStrcat(ret, buffer);
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(buffer as *mut libc::c_void);
                }
            }
        } else if (*node).type_0 as libc::c_uint
                == XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
            {
            if inLine != 0 {
                ent = xmlGetDocEntity(doc as *const xmlDoc, (*node).name);
                if !ent.is_null() {
                    let mut buffer_0: *mut xmlChar = 0 as *mut xmlChar;
                    buffer_0 = xmlNodeListGetString(
                        doc,
                        (*ent).children,
                        1 as libc::c_int,
                    );
                    if !buffer_0.is_null() {
                        ret = xmlStrcat(ret, buffer_0);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer_0 as *mut libc::c_void);
                    }
                } else {
                    ret = xmlStrcat(ret, (*node).content);
                }
            } else {
                let mut buf: [xmlChar; 2] = [0; 2];
                buf[0 as libc::c_int as usize] = '&' as i32 as xmlChar;
                buf[1 as libc::c_int as usize] = 0 as libc::c_int as xmlChar;
                ret = xmlStrncat(ret, buf.as_mut_ptr(), 1 as libc::c_int);
                ret = xmlStrcat(ret, (*node).name);
                buf[0 as libc::c_int as usize] = ';' as i32 as xmlChar;
                buf[1 as libc::c_int as usize] = 0 as libc::c_int as xmlChar;
                ret = xmlStrncat(ret, buf.as_mut_ptr(), 1 as libc::c_int);
            }
        }
        node = (*node).next;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeListGetRawString(
    mut doc: *const xmlDoc,
    mut list: *const xmlNode,
    mut inLine: libc::c_int,
) -> *mut xmlChar {
    let mut node: *const xmlNode = list;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
    if list.is_null() {
        return 0 as *mut xmlChar;
    }
    while !node.is_null() {
        if (*node).type_0 as libc::c_uint == XML_TEXT_NODE as libc::c_int as libc::c_uint
            || (*node).type_0 as libc::c_uint
                == XML_CDATA_SECTION_NODE as libc::c_int as libc::c_uint
        {
            if inLine != 0 {
                ret = xmlStrcat(ret, (*node).content);
            } else {
                let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
                buffer = xmlEncodeSpecialChars(doc, (*node).content);
                if !buffer.is_null() {
                    ret = xmlStrcat(ret, buffer);
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(buffer as *mut libc::c_void);
                }
            }
        } else if (*node).type_0 as libc::c_uint
                == XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
            {
            if inLine != 0 {
                ent = xmlGetDocEntity(doc, (*node).name);
                if !ent.is_null() {
                    let mut buffer_0: *mut xmlChar = 0 as *mut xmlChar;
                    buffer_0 = xmlNodeListGetRawString(
                        doc,
                        (*ent).children,
                        1 as libc::c_int,
                    );
                    if !buffer_0.is_null() {
                        ret = xmlStrcat(ret, buffer_0);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer_0 as *mut libc::c_void);
                    }
                } else {
                    ret = xmlStrcat(ret, (*node).content);
                }
            } else {
                let mut buf: [xmlChar; 2] = [0; 2];
                buf[0 as libc::c_int as usize] = '&' as i32 as xmlChar;
                buf[1 as libc::c_int as usize] = 0 as libc::c_int as xmlChar;
                ret = xmlStrncat(ret, buf.as_mut_ptr(), 1 as libc::c_int);
                ret = xmlStrcat(ret, (*node).name);
                buf[0 as libc::c_int as usize] = ';' as i32 as xmlChar;
                buf[1 as libc::c_int as usize] = 0 as libc::c_int as xmlChar;
                ret = xmlStrncat(ret, buf.as_mut_ptr(), 1 as libc::c_int);
            }
        }
        node = (*node).next;
    }
    return ret;
}
unsafe extern "C" fn xmlNewPropInternal(
    mut node: xmlNodePtr,
    mut ns: xmlNsPtr,
    mut name: *const xmlChar,
    mut value: *const xmlChar,
    mut eatname: libc::c_int,
) -> xmlAttrPtr {
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut doc: xmlDocPtr = 0 as xmlDocPtr;
    if !node.is_null()
        && (*node).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        if eatname == 1 as libc::c_int
            && (((*node).doc).is_null() || xmlDictOwns((*(*node).doc).dict, name) == 0)
        {
            xmlFree
                .expect(
                    "non-null function pointer",
                )(name as *mut xmlChar as *mut libc::c_void);
        }
        return 0 as xmlAttrPtr;
    }
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlAttr>() as libc::c_ulong) as xmlAttrPtr;
    if cur.is_null() {
        if eatname == 1 as libc::c_int
            && (node.is_null() || ((*node).doc).is_null()
                || xmlDictOwns((*(*node).doc).dict, name) == 0)
        {
            xmlFree
                .expect(
                    "non-null function pointer",
                )(name as *mut xmlChar as *mut libc::c_void);
        }
        xmlTreeErrMemory(b"building attribute\0" as *const u8 as *const libc::c_char);
        return 0 as xmlAttrPtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlAttr>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_ATTRIBUTE_NODE;
    let ref mut fresh48 = (*cur).parent;
    *fresh48 = node;
    if !node.is_null() {
        doc = (*node).doc;
        let ref mut fresh49 = (*cur).doc;
        *fresh49 = doc;
    }
    let ref mut fresh50 = (*cur).ns;
    *fresh50 = ns;
    if eatname == 0 as libc::c_int {
        if !doc.is_null() && !((*doc).dict).is_null() {
            let ref mut fresh51 = (*cur).name;
            *fresh51 = xmlDictLookup((*doc).dict, name, -(1 as libc::c_int))
                as *mut xmlChar;
        } else {
            let ref mut fresh52 = (*cur).name;
            *fresh52 = xmlStrdup(name);
        }
    } else {
        let ref mut fresh53 = (*cur).name;
        *fresh53 = name;
    }
    if !value.is_null() {
        let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
        let ref mut fresh54 = (*cur).children;
        *fresh54 = xmlNewDocText(doc as *const xmlDoc, value);
        let ref mut fresh55 = (*cur).last;
        *fresh55 = 0 as *mut _xmlNode;
        tmp = (*cur).children;
        while !tmp.is_null() {
            let ref mut fresh56 = (*tmp).parent;
            *fresh56 = cur as xmlNodePtr;
            if ((*tmp).next).is_null() {
                let ref mut fresh57 = (*cur).last;
                *fresh57 = tmp;
            }
            tmp = (*tmp).next;
        }
    }
    if !node.is_null() {
        if ((*node).properties).is_null() {
            let ref mut fresh58 = (*node).properties;
            *fresh58 = cur;
        } else {
            let mut prev: xmlAttrPtr = (*node).properties;
            while !((*prev).next).is_null() {
                prev = (*prev).next;
            }
            let ref mut fresh59 = (*prev).next;
            *fresh59 = cur;
            let ref mut fresh60 = (*cur).prev;
            *fresh60 = prev;
        }
    }
    if !value.is_null() && !node.is_null()
        && xmlIsID((*node).doc, node, cur) == 1 as libc::c_int
    {
        xmlAddID(0 as xmlValidCtxtPtr, (*node).doc, value, cur);
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue())
            .expect("non-null function pointer")(cur as xmlNodePtr);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewProp(
    mut node: xmlNodePtr,
    mut name: *const xmlChar,
    mut value: *const xmlChar,
) -> xmlAttrPtr {
    if name.is_null() {
        return 0 as xmlAttrPtr;
    }
    return xmlNewPropInternal(node, 0 as xmlNsPtr, name, value, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewNsProp(
    mut node: xmlNodePtr,
    mut ns: xmlNsPtr,
    mut name: *const xmlChar,
    mut value: *const xmlChar,
) -> xmlAttrPtr {
    if name.is_null() {
        return 0 as xmlAttrPtr;
    }
    return xmlNewPropInternal(node, ns, name, value, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewNsPropEatName(
    mut node: xmlNodePtr,
    mut ns: xmlNsPtr,
    mut name: *mut xmlChar,
    mut value: *const xmlChar,
) -> xmlAttrPtr {
    if name.is_null() {
        return 0 as xmlAttrPtr;
    }
    return xmlNewPropInternal(node, ns, name, value, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewDocProp(
    mut doc: xmlDocPtr,
    mut name: *const xmlChar,
    mut value: *const xmlChar,
) -> xmlAttrPtr {
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    if name.is_null() {
        return 0 as xmlAttrPtr;
    }
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlAttr>() as libc::c_ulong) as xmlAttrPtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building attribute\0" as *const u8 as *const libc::c_char);
        return 0 as xmlAttrPtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlAttr>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_ATTRIBUTE_NODE;
    if !doc.is_null() && !((*doc).dict).is_null() {
        let ref mut fresh61 = (*cur).name;
        *fresh61 = xmlDictLookup((*doc).dict, name, -(1 as libc::c_int));
    } else {
        let ref mut fresh62 = (*cur).name;
        *fresh62 = xmlStrdup(name);
    }
    let ref mut fresh63 = (*cur).doc;
    *fresh63 = doc;
    if !value.is_null() {
        let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
        let ref mut fresh64 = (*cur).children;
        *fresh64 = xmlStringGetNodeList(doc as *const xmlDoc, value);
        let ref mut fresh65 = (*cur).last;
        *fresh65 = 0 as *mut _xmlNode;
        tmp = (*cur).children;
        while !tmp.is_null() {
            let ref mut fresh66 = (*tmp).parent;
            *fresh66 = cur as xmlNodePtr;
            if ((*tmp).next).is_null() {
                let ref mut fresh67 = (*cur).last;
                *fresh67 = tmp;
            }
            tmp = (*tmp).next;
        }
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue())
            .expect("non-null function pointer")(cur as xmlNodePtr);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreePropList(mut cur: xmlAttrPtr) {
    let mut next: xmlAttrPtr = 0 as *mut xmlAttr;
    if cur.is_null() {
        return;
    }
    while !cur.is_null() {
        next = (*cur).next;
        xmlFreeProp(cur);
        cur = next;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeProp(mut cur: xmlAttrPtr) {
    let mut dict: xmlDictPtr = 0 as xmlDictPtr;
    if cur.is_null() {
        return;
    }
    if !((*cur).doc).is_null() {
        dict = (*(*cur).doc).dict;
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlDeregisterNodeDefaultValue()).is_some() {
        (*__xmlDeregisterNodeDefaultValue())
            .expect("non-null function pointer")(cur as xmlNodePtr);
    }
    if !((*cur).doc).is_null()
        && (*cur).atype as libc::c_uint
            == XML_ATTRIBUTE_ID as libc::c_int as libc::c_uint
    {
        xmlRemoveID((*cur).doc, cur);
    }
    if !((*cur).children).is_null() {
        xmlFreeNodeList((*cur).children);
    }
    if !((*cur).name).is_null()
        && (dict.is_null() || xmlDictOwns(dict, (*cur).name) == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*cur).name as *mut libc::c_char as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlRemoveProp(mut cur: xmlAttrPtr) -> libc::c_int {
    let mut tmp: xmlAttrPtr = 0 as *mut xmlAttr;
    if cur.is_null() {
        return -(1 as libc::c_int);
    }
    if ((*cur).parent).is_null() {
        return -(1 as libc::c_int);
    }
    tmp = (*(*cur).parent).properties;
    if tmp == cur {
        let ref mut fresh68 = (*(*cur).parent).properties;
        *fresh68 = (*cur).next;
        if !((*cur).next).is_null() {
            let ref mut fresh69 = (*(*cur).next).prev;
            *fresh69 = 0 as *mut _xmlAttr;
        }
        xmlFreeProp(cur);
        return 0 as libc::c_int;
    }
    while !tmp.is_null() {
        if (*tmp).next == cur {
            let ref mut fresh70 = (*tmp).next;
            *fresh70 = (*cur).next;
            if !((*tmp).next).is_null() {
                let ref mut fresh71 = (*(*tmp).next).prev;
                *fresh71 = tmp;
            }
            xmlFreeProp(cur);
            return 0 as libc::c_int;
        }
        tmp = (*tmp).next;
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewDocPI(
    mut doc: xmlDocPtr,
    mut name: *const xmlChar,
    mut content: *const xmlChar,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNode>() as libc::c_ulong) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building PI\0" as *const u8 as *const libc::c_char);
        return 0 as xmlNodePtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNode>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_PI_NODE;
    if !doc.is_null() && !((*doc).dict).is_null() {
        let ref mut fresh72 = (*cur).name;
        *fresh72 = xmlDictLookup((*doc).dict, name, -(1 as libc::c_int));
    } else {
        let ref mut fresh73 = (*cur).name;
        *fresh73 = xmlStrdup(name);
    }
    if !content.is_null() {
        let ref mut fresh74 = (*cur).content;
        *fresh74 = xmlStrdup(content);
    }
    let ref mut fresh75 = (*cur).doc;
    *fresh75 = doc;
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewPI(
    mut name: *const xmlChar,
    mut content: *const xmlChar,
) -> xmlNodePtr {
    return xmlNewDocPI(0 as xmlDocPtr, name, content);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewNode(
    mut ns: xmlNsPtr,
    mut name: *const xmlChar,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNode>() as libc::c_ulong) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building node\0" as *const u8 as *const libc::c_char);
        return 0 as xmlNodePtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNode>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_ELEMENT_NODE;
    let ref mut fresh76 = (*cur).name;
    *fresh76 = xmlStrdup(name);
    let ref mut fresh77 = (*cur).ns;
    *fresh77 = ns;
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewNodeEatName(
    mut ns: xmlNsPtr,
    mut name: *mut xmlChar,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNode>() as libc::c_ulong) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building node\0" as *const u8 as *const libc::c_char);
        return 0 as xmlNodePtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNode>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_ELEMENT_NODE;
    let ref mut fresh78 = (*cur).name;
    *fresh78 = name;
    let ref mut fresh79 = (*cur).ns;
    *fresh79 = ns;
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewDocNode(
    mut doc: xmlDocPtr,
    mut ns: xmlNsPtr,
    mut name: *const xmlChar,
    mut content: *const xmlChar,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if !doc.is_null() && !((*doc).dict).is_null() {
        cur = xmlNewNodeEatName(
            ns,
            xmlDictLookup((*doc).dict, name, -(1 as libc::c_int)) as *mut xmlChar,
        );
    } else {
        cur = xmlNewNode(ns, name);
    }
    if !cur.is_null() {
        let ref mut fresh80 = (*cur).doc;
        *fresh80 = doc;
        if !content.is_null() {
            let ref mut fresh81 = (*cur).children;
            *fresh81 = xmlStringGetNodeList(doc as *const xmlDoc, content);
            if !cur.is_null() {
                let mut ulccur: xmlNodePtr = (*cur).children;
                if ulccur.is_null() {
                    let ref mut fresh82 = (*cur).last;
                    *fresh82 = 0 as *mut _xmlNode;
                } else {
                    while !((*ulccur).next).is_null() {
                        let ref mut fresh83 = (*ulccur).parent;
                        *fresh83 = cur;
                        ulccur = (*ulccur).next;
                    }
                    let ref mut fresh84 = (*ulccur).parent;
                    *fresh84 = cur;
                    let ref mut fresh85 = (*cur).last;
                    *fresh85 = ulccur;
                }
            }
        }
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewDocNodeEatName(
    mut doc: xmlDocPtr,
    mut ns: xmlNsPtr,
    mut name: *mut xmlChar,
    mut content: *const xmlChar,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    cur = xmlNewNodeEatName(ns, name);
    if !cur.is_null() {
        let ref mut fresh86 = (*cur).doc;
        *fresh86 = doc;
        if !content.is_null() {
            let ref mut fresh87 = (*cur).children;
            *fresh87 = xmlStringGetNodeList(doc as *const xmlDoc, content);
            if !cur.is_null() {
                let mut ulccur: xmlNodePtr = (*cur).children;
                if ulccur.is_null() {
                    let ref mut fresh88 = (*cur).last;
                    *fresh88 = 0 as *mut _xmlNode;
                } else {
                    while !((*ulccur).next).is_null() {
                        let ref mut fresh89 = (*ulccur).parent;
                        *fresh89 = cur;
                        ulccur = (*ulccur).next;
                    }
                    let ref mut fresh90 = (*ulccur).parent;
                    *fresh90 = cur;
                    let ref mut fresh91 = (*cur).last;
                    *fresh91 = ulccur;
                }
            }
        }
    } else if !name.is_null() && !doc.is_null() && xmlDictOwns((*doc).dict, name) == 0 {
        xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewDocRawNode(
    mut doc: xmlDocPtr,
    mut ns: xmlNsPtr,
    mut name: *const xmlChar,
    mut content: *const xmlChar,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    cur = xmlNewDocNode(doc, ns, name, 0 as *const xmlChar);
    if !cur.is_null() {
        let ref mut fresh92 = (*cur).doc;
        *fresh92 = doc;
        if !content.is_null() {
            let ref mut fresh93 = (*cur).children;
            *fresh93 = xmlNewDocText(doc as *const xmlDoc, content);
            if !cur.is_null() {
                let mut ulccur: xmlNodePtr = (*cur).children;
                if ulccur.is_null() {
                    let ref mut fresh94 = (*cur).last;
                    *fresh94 = 0 as *mut _xmlNode;
                } else {
                    while !((*ulccur).next).is_null() {
                        let ref mut fresh95 = (*ulccur).parent;
                        *fresh95 = cur;
                        ulccur = (*ulccur).next;
                    }
                    let ref mut fresh96 = (*ulccur).parent;
                    *fresh96 = cur;
                    let ref mut fresh97 = (*cur).last;
                    *fresh97 = ulccur;
                }
            }
        }
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewDocFragment(mut doc: xmlDocPtr) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNode>() as libc::c_ulong) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building fragment\0" as *const u8 as *const libc::c_char);
        return 0 as xmlNodePtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNode>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_DOCUMENT_FRAG_NODE;
    let ref mut fresh98 = (*cur).doc;
    *fresh98 = doc;
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewText(mut content: *const xmlChar) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNode>() as libc::c_ulong) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building text\0" as *const u8 as *const libc::c_char);
        return 0 as xmlNodePtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNode>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_TEXT_NODE;
    let ref mut fresh99 = (*cur).name;
    *fresh99 = xmlStringText.as_ptr();
    if !content.is_null() {
        let ref mut fresh100 = (*cur).content;
        *fresh100 = xmlStrdup(content);
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewTextChild(
    mut parent: xmlNodePtr,
    mut ns: xmlNsPtr,
    mut name: *const xmlChar,
    mut content: *const xmlChar,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut prev: xmlNodePtr = 0 as *mut xmlNode;
    if parent.is_null() {
        return 0 as xmlNodePtr;
    }
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    if (*parent).type_0 as libc::c_uint
        == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        if ns.is_null() {
            cur = xmlNewDocRawNode((*parent).doc, (*parent).ns, name, content);
        } else {
            cur = xmlNewDocRawNode((*parent).doc, ns, name, content);
        }
    } else if (*parent).type_0 as libc::c_uint
            == XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
            || (*parent).type_0 as libc::c_uint
                == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
        {
        if ns.is_null() {
            cur = xmlNewDocRawNode(parent as xmlDocPtr, 0 as xmlNsPtr, name, content);
        } else {
            cur = xmlNewDocRawNode(parent as xmlDocPtr, ns, name, content);
        }
    } else if (*parent).type_0 as libc::c_uint
            == XML_DOCUMENT_FRAG_NODE as libc::c_int as libc::c_uint
        {
        cur = xmlNewDocRawNode((*parent).doc, ns, name, content);
    } else {
        return 0 as xmlNodePtr
    }
    if cur.is_null() {
        return 0 as xmlNodePtr;
    }
    (*cur).type_0 = XML_ELEMENT_NODE;
    let ref mut fresh101 = (*cur).parent;
    *fresh101 = parent;
    let ref mut fresh102 = (*cur).doc;
    *fresh102 = (*parent).doc;
    if ((*parent).children).is_null() {
        let ref mut fresh103 = (*parent).children;
        *fresh103 = cur;
        let ref mut fresh104 = (*parent).last;
        *fresh104 = cur;
    } else {
        prev = (*parent).last;
        let ref mut fresh105 = (*prev).next;
        *fresh105 = cur;
        let ref mut fresh106 = (*cur).prev;
        *fresh106 = prev;
        let ref mut fresh107 = (*parent).last;
        *fresh107 = cur;
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewCharRef(
    mut doc: xmlDocPtr,
    mut name: *const xmlChar,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNode>() as libc::c_ulong) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(
            b"building character reference\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlNodePtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNode>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_ENTITY_REF_NODE;
    let ref mut fresh108 = (*cur).doc;
    *fresh108 = doc;
    if *name.offset(0 as libc::c_int as isize) as libc::c_int == '&' as i32 {
        let mut len: libc::c_int = 0;
        name = name.offset(1);
        len = xmlStrlen(name);
        if *name.offset((len - 1 as libc::c_int) as isize) as libc::c_int == ';' as i32 {
            let ref mut fresh109 = (*cur).name;
            *fresh109 = xmlStrndup(name, len - 1 as libc::c_int);
        } else {
            let ref mut fresh110 = (*cur).name;
            *fresh110 = xmlStrndup(name, len);
        }
    } else {
        let ref mut fresh111 = (*cur).name;
        *fresh111 = xmlStrdup(name);
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewReference(
    mut doc: *const xmlDoc,
    mut name: *const xmlChar,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNode>() as libc::c_ulong) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building reference\0" as *const u8 as *const libc::c_char);
        return 0 as xmlNodePtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNode>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_ENTITY_REF_NODE;
    let ref mut fresh112 = (*cur).doc;
    *fresh112 = doc as *mut xmlDoc;
    if *name.offset(0 as libc::c_int as isize) as libc::c_int == '&' as i32 {
        let mut len: libc::c_int = 0;
        name = name.offset(1);
        len = xmlStrlen(name);
        if *name.offset((len - 1 as libc::c_int) as isize) as libc::c_int == ';' as i32 {
            let ref mut fresh113 = (*cur).name;
            *fresh113 = xmlStrndup(name, len - 1 as libc::c_int);
        } else {
            let ref mut fresh114 = (*cur).name;
            *fresh114 = xmlStrndup(name, len);
        }
    } else {
        let ref mut fresh115 = (*cur).name;
        *fresh115 = xmlStrdup(name);
    }
    ent = xmlGetDocEntity(doc, (*cur).name);
    if !ent.is_null() {
        let ref mut fresh116 = (*cur).content;
        *fresh116 = (*ent).content;
        let ref mut fresh117 = (*cur).children;
        *fresh117 = ent as xmlNodePtr;
        let ref mut fresh118 = (*cur).last;
        *fresh118 = ent as xmlNodePtr;
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewDocText(
    mut doc: *const xmlDoc,
    mut content: *const xmlChar,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    cur = xmlNewText(content);
    if !cur.is_null() {
        let ref mut fresh119 = (*cur).doc;
        *fresh119 = doc as *mut xmlDoc;
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewTextLen(
    mut content: *const xmlChar,
    mut len: libc::c_int,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNode>() as libc::c_ulong) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building text\0" as *const u8 as *const libc::c_char);
        return 0 as xmlNodePtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNode>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_TEXT_NODE;
    let ref mut fresh120 = (*cur).name;
    *fresh120 = xmlStringText.as_ptr();
    if !content.is_null() {
        let ref mut fresh121 = (*cur).content;
        *fresh121 = xmlStrndup(content, len);
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewDocTextLen(
    mut doc: xmlDocPtr,
    mut content: *const xmlChar,
    mut len: libc::c_int,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    cur = xmlNewTextLen(content, len);
    if !cur.is_null() {
        let ref mut fresh122 = (*cur).doc;
        *fresh122 = doc;
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewComment(mut content: *const xmlChar) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNode>() as libc::c_ulong) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building comment\0" as *const u8 as *const libc::c_char);
        return 0 as xmlNodePtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNode>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_COMMENT_NODE;
    let ref mut fresh123 = (*cur).name;
    *fresh123 = xmlStringComment.as_ptr();
    if !content.is_null() {
        let ref mut fresh124 = (*cur).content;
        *fresh124 = xmlStrdup(content);
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewCDataBlock(
    mut doc: xmlDocPtr,
    mut content: *const xmlChar,
    mut len: libc::c_int,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNode>() as libc::c_ulong) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building CDATA\0" as *const u8 as *const libc::c_char);
        return 0 as xmlNodePtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNode>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_CDATA_SECTION_NODE;
    let ref mut fresh125 = (*cur).doc;
    *fresh125 = doc;
    if !content.is_null() {
        let ref mut fresh126 = (*cur).content;
        *fresh126 = xmlStrndup(content, len);
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
        (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewDocComment(
    mut doc: xmlDocPtr,
    mut content: *const xmlChar,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    cur = xmlNewComment(content);
    if !cur.is_null() {
        let ref mut fresh127 = (*cur).doc;
        *fresh127 = doc;
    }
    return cur;
}
unsafe extern "C" fn _copyStringForNewDictIfNeeded(
    mut oldDict: xmlDictPtr,
    mut newDict: xmlDictPtr,
    mut oldValue: *const xmlChar,
) -> *const xmlChar {
    let mut newValue: *const xmlChar = oldValue;
    if !oldValue.is_null() {
        let mut oldDictOwnsOldValue: libc::c_int = (!oldDict.is_null()
            && xmlDictOwns(oldDict, oldValue) == 1 as libc::c_int) as libc::c_int;
        if oldDictOwnsOldValue != 0 {
            if !newDict.is_null() {
                newValue = xmlDictLookup(newDict, oldValue, -(1 as libc::c_int));
            } else {
                newValue = xmlStrdup(oldValue);
            }
        }
    }
    return newValue;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetTreeDoc(mut tree: xmlNodePtr, mut doc: xmlDocPtr) {
    let mut prop: xmlAttrPtr = 0 as *mut xmlAttr;
    if tree.is_null()
        || (*tree).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return;
    }
    if (*tree).doc != doc {
        let mut oldTreeDict: xmlDictPtr = if !((*tree).doc).is_null() {
            (*(*tree).doc).dict
        } else {
            0 as *mut _xmlDict
        };
        let mut newDict: xmlDictPtr = if !doc.is_null() {
            (*doc).dict
        } else {
            0 as *mut _xmlDict
        };
        if (*tree).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            prop = (*tree).properties;
            while !prop.is_null() {
                if (*prop).atype as libc::c_uint
                    == XML_ATTRIBUTE_ID as libc::c_int as libc::c_uint
                {
                    xmlRemoveID((*tree).doc, prop);
                }
                if (*prop).doc != doc {
                    let mut oldPropDict: xmlDictPtr = if !((*prop).doc).is_null() {
                        (*(*prop).doc).dict
                    } else {
                        0 as *mut _xmlDict
                    };
                    let ref mut fresh128 = (*prop).name;
                    *fresh128 = _copyStringForNewDictIfNeeded(
                        oldPropDict,
                        newDict,
                        (*prop).name,
                    );
                    let ref mut fresh129 = (*prop).doc;
                    *fresh129 = doc;
                }
                xmlSetListDoc((*prop).children, doc);
                prop = (*prop).next;
            }
        }
        if (*tree).type_0 as libc::c_uint
            == XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
        {
            let ref mut fresh130 = (*tree).children;
            *fresh130 = 0 as *mut _xmlNode;
        } else if !((*tree).children).is_null() {
            xmlSetListDoc((*tree).children, doc);
        }
        let ref mut fresh131 = (*tree).name;
        *fresh131 = _copyStringForNewDictIfNeeded(oldTreeDict, newDict, (*tree).name);
        let ref mut fresh132 = (*tree).content;
        *fresh132 = _copyStringForNewDictIfNeeded(
            oldTreeDict,
            0 as xmlDictPtr,
            (*tree).content,
        ) as *mut xmlChar;
        let ref mut fresh133 = (*tree).doc;
        *fresh133 = doc;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetListDoc(mut list: xmlNodePtr, mut doc: xmlDocPtr) {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if list.is_null()
        || (*list).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return;
    }
    cur = list;
    while !cur.is_null() {
        if (*cur).doc != doc {
            xmlSetTreeDoc(cur, doc);
        }
        cur = (*cur).next;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewChild(
    mut parent: xmlNodePtr,
    mut ns: xmlNsPtr,
    mut name: *const xmlChar,
    mut content: *const xmlChar,
) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut prev: xmlNodePtr = 0 as *mut xmlNode;
    if parent.is_null() {
        return 0 as xmlNodePtr;
    }
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    if (*parent).type_0 as libc::c_uint
        == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        if ns.is_null() {
            cur = xmlNewDocNode((*parent).doc, (*parent).ns, name, content);
        } else {
            cur = xmlNewDocNode((*parent).doc, ns, name, content);
        }
    } else if (*parent).type_0 as libc::c_uint
            == XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
            || (*parent).type_0 as libc::c_uint
                == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
        {
        if ns.is_null() {
            cur = xmlNewDocNode(parent as xmlDocPtr, 0 as xmlNsPtr, name, content);
        } else {
            cur = xmlNewDocNode(parent as xmlDocPtr, ns, name, content);
        }
    } else if (*parent).type_0 as libc::c_uint
            == XML_DOCUMENT_FRAG_NODE as libc::c_int as libc::c_uint
        {
        cur = xmlNewDocNode((*parent).doc, ns, name, content);
    } else {
        return 0 as xmlNodePtr
    }
    if cur.is_null() {
        return 0 as xmlNodePtr;
    }
    (*cur).type_0 = XML_ELEMENT_NODE;
    let ref mut fresh134 = (*cur).parent;
    *fresh134 = parent;
    let ref mut fresh135 = (*cur).doc;
    *fresh135 = (*parent).doc;
    if ((*parent).children).is_null() {
        let ref mut fresh136 = (*parent).children;
        *fresh136 = cur;
        let ref mut fresh137 = (*parent).last;
        *fresh137 = cur;
    } else {
        prev = (*parent).last;
        let ref mut fresh138 = (*prev).next;
        *fresh138 = cur;
        let ref mut fresh139 = (*cur).prev;
        *fresh139 = prev;
        let ref mut fresh140 = (*parent).last;
        *fresh140 = cur;
    }
    return cur;
}
unsafe extern "C" fn xmlAddPropSibling(
    mut prev: xmlNodePtr,
    mut cur: xmlNodePtr,
    mut prop: xmlNodePtr,
) -> xmlNodePtr {
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    if cur.is_null()
        || (*cur).type_0 as libc::c_uint
            != XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint || prop.is_null()
        || (*prop).type_0 as libc::c_uint
            != XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
        || !prev.is_null()
            && (*prev).type_0 as libc::c_uint
                != XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
    {
        return 0 as xmlNodePtr;
    }
    if ((*prop).ns).is_null() {
        attr = xmlHasNsProp((*cur).parent, (*prop).name, 0 as *const xmlChar);
    } else {
        attr = xmlHasNsProp((*cur).parent, (*prop).name, (*(*prop).ns).href);
    }
    if (*prop).doc != (*cur).doc {
        xmlSetTreeDoc(prop, (*cur).doc);
    }
    let ref mut fresh141 = (*prop).parent;
    *fresh141 = (*cur).parent;
    let ref mut fresh142 = (*prop).prev;
    *fresh142 = prev;
    if !prev.is_null() {
        let ref mut fresh143 = (*prop).next;
        *fresh143 = (*prev).next;
        let ref mut fresh144 = (*prev).next;
        *fresh144 = prop;
        if !((*prop).next).is_null() {
            let ref mut fresh145 = (*(*prop).next).prev;
            *fresh145 = prop;
        }
    } else {
        let ref mut fresh146 = (*prop).next;
        *fresh146 = cur;
        let ref mut fresh147 = (*cur).prev;
        *fresh147 = prop;
    }
    if ((*prop).prev).is_null() && !((*prop).parent).is_null() {
        let ref mut fresh148 = (*(*prop).parent).properties;
        *fresh148 = prop as xmlAttrPtr;
    }
    if !attr.is_null()
        && (*attr).type_0 as libc::c_uint
            != XML_ATTRIBUTE_DECL as libc::c_int as libc::c_uint
    {
        xmlRemoveProp(attr);
    }
    return prop;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAddNextSibling(
    mut cur: xmlNodePtr,
    mut elem: xmlNodePtr,
) -> xmlNodePtr {
    if cur.is_null()
        || (*cur).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNodePtr;
    }
    if elem.is_null()
        || (*elem).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNodePtr;
    }
    if cur == elem {
        return 0 as xmlNodePtr;
    }
    xmlUnlinkNode(elem);
    if (*elem).type_0 as libc::c_uint == XML_TEXT_NODE as libc::c_int as libc::c_uint {
        if (*cur).type_0 as libc::c_uint == XML_TEXT_NODE as libc::c_int as libc::c_uint
        {
            xmlNodeAddContent(cur, (*elem).content);
            xmlFreeNode(elem);
            return cur;
        }
        if !((*cur).next).is_null()
            && (*(*cur).next).type_0 as libc::c_uint
                == XML_TEXT_NODE as libc::c_int as libc::c_uint
            && (*cur).name == (*(*cur).next).name
        {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            tmp = xmlStrdup((*elem).content);
            tmp = xmlStrcat(tmp, (*(*cur).next).content);
            xmlNodeSetContent((*cur).next, tmp);
            xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void);
            xmlFreeNode(elem);
            return (*cur).next;
        }
    } else if (*elem).type_0 as libc::c_uint
            == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
        {
        return xmlAddPropSibling(cur, cur, elem)
    }
    if (*elem).doc != (*cur).doc {
        xmlSetTreeDoc(elem, (*cur).doc);
    }
    let ref mut fresh149 = (*elem).parent;
    *fresh149 = (*cur).parent;
    let ref mut fresh150 = (*elem).prev;
    *fresh150 = cur;
    let ref mut fresh151 = (*elem).next;
    *fresh151 = (*cur).next;
    let ref mut fresh152 = (*cur).next;
    *fresh152 = elem;
    if !((*elem).next).is_null() {
        let ref mut fresh153 = (*(*elem).next).prev;
        *fresh153 = elem;
    }
    if !((*elem).parent).is_null() && (*(*elem).parent).last == cur {
        let ref mut fresh154 = (*(*elem).parent).last;
        *fresh154 = elem;
    }
    return elem;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAddPrevSibling(
    mut cur: xmlNodePtr,
    mut elem: xmlNodePtr,
) -> xmlNodePtr {
    if cur.is_null()
        || (*cur).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNodePtr;
    }
    if elem.is_null()
        || (*elem).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNodePtr;
    }
    if cur == elem {
        return 0 as xmlNodePtr;
    }
    xmlUnlinkNode(elem);
    if (*elem).type_0 as libc::c_uint == XML_TEXT_NODE as libc::c_int as libc::c_uint {
        if (*cur).type_0 as libc::c_uint == XML_TEXT_NODE as libc::c_int as libc::c_uint
        {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            tmp = xmlStrdup((*elem).content);
            tmp = xmlStrcat(tmp, (*cur).content);
            xmlNodeSetContent(cur, tmp);
            xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void);
            xmlFreeNode(elem);
            return cur;
        }
        if !((*cur).prev).is_null()
            && (*(*cur).prev).type_0 as libc::c_uint
                == XML_TEXT_NODE as libc::c_int as libc::c_uint
            && (*cur).name == (*(*cur).prev).name
        {
            xmlNodeAddContent((*cur).prev, (*elem).content);
            xmlFreeNode(elem);
            return (*cur).prev;
        }
    } else if (*elem).type_0 as libc::c_uint
            == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
        {
        return xmlAddPropSibling((*cur).prev, cur, elem)
    }
    if (*elem).doc != (*cur).doc {
        xmlSetTreeDoc(elem, (*cur).doc);
    }
    let ref mut fresh155 = (*elem).parent;
    *fresh155 = (*cur).parent;
    let ref mut fresh156 = (*elem).next;
    *fresh156 = cur;
    let ref mut fresh157 = (*elem).prev;
    *fresh157 = (*cur).prev;
    let ref mut fresh158 = (*cur).prev;
    *fresh158 = elem;
    if !((*elem).prev).is_null() {
        let ref mut fresh159 = (*(*elem).prev).next;
        *fresh159 = elem;
    }
    if !((*elem).parent).is_null() && (*(*elem).parent).children == cur {
        let ref mut fresh160 = (*(*elem).parent).children;
        *fresh160 = elem;
    }
    return elem;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAddSibling(
    mut cur: xmlNodePtr,
    mut elem: xmlNodePtr,
) -> xmlNodePtr {
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    if cur.is_null()
        || (*cur).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNodePtr;
    }
    if elem.is_null()
        || (*elem).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNodePtr;
    }
    if cur == elem {
        return 0 as xmlNodePtr;
    }
    if (*cur).type_0 as libc::c_uint != XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
        && !((*cur).parent).is_null() && !((*(*cur).parent).children).is_null()
        && !((*(*cur).parent).last).is_null()
        && ((*(*(*cur).parent).last).next).is_null()
    {
        cur = (*(*cur).parent).last;
    } else {
        while !((*cur).next).is_null() {
            cur = (*cur).next;
        }
    }
    xmlUnlinkNode(elem);
    if (*cur).type_0 as libc::c_uint == XML_TEXT_NODE as libc::c_int as libc::c_uint
        && (*elem).type_0 as libc::c_uint == XML_TEXT_NODE as libc::c_int as libc::c_uint
        && (*cur).name == (*elem).name
    {
        xmlNodeAddContent(cur, (*elem).content);
        xmlFreeNode(elem);
        return cur;
    } else {
        if (*elem).type_0 as libc::c_uint
            == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
        {
            return xmlAddPropSibling(cur, cur, elem);
        }
    }
    if (*elem).doc != (*cur).doc {
        xmlSetTreeDoc(elem, (*cur).doc);
    }
    parent = (*cur).parent;
    let ref mut fresh161 = (*elem).prev;
    *fresh161 = cur;
    let ref mut fresh162 = (*elem).next;
    *fresh162 = 0 as *mut _xmlNode;
    let ref mut fresh163 = (*elem).parent;
    *fresh163 = parent;
    let ref mut fresh164 = (*cur).next;
    *fresh164 = elem;
    if !parent.is_null() {
        let ref mut fresh165 = (*parent).last;
        *fresh165 = elem;
    }
    return elem;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAddChildList(
    mut parent: xmlNodePtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    let mut prev: xmlNodePtr = 0 as *mut xmlNode;
    if parent.is_null()
        || (*parent).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNodePtr;
    }
    if cur.is_null()
        || (*cur).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNodePtr;
    }
    !((*cur).doc).is_null() && !((*parent).doc).is_null() && (*cur).doc != (*parent).doc;
    if ((*parent).children).is_null() {
        let ref mut fresh166 = (*parent).children;
        *fresh166 = cur;
    } else {
        if (*cur).type_0 as libc::c_uint == XML_TEXT_NODE as libc::c_int as libc::c_uint
            && (*(*parent).last).type_0 as libc::c_uint
                == XML_TEXT_NODE as libc::c_int as libc::c_uint
            && (*cur).name == (*(*parent).last).name
        {
            xmlNodeAddContent((*parent).last, (*cur).content);
            if ((*cur).next).is_null() {
                xmlFreeNode(cur);
                return (*parent).last;
            }
            prev = cur;
            cur = (*cur).next;
            xmlFreeNode(prev);
        }
        prev = (*parent).last;
        let ref mut fresh167 = (*prev).next;
        *fresh167 = cur;
        let ref mut fresh168 = (*cur).prev;
        *fresh168 = prev;
    }
    while !((*cur).next).is_null() {
        let ref mut fresh169 = (*cur).parent;
        *fresh169 = parent;
        if (*cur).doc != (*parent).doc {
            xmlSetTreeDoc(cur, (*parent).doc);
        }
        cur = (*cur).next;
    }
    let ref mut fresh170 = (*cur).parent;
    *fresh170 = parent;
    if (*cur).doc != (*parent).doc {
        xmlSetTreeDoc(cur, (*parent).doc);
    }
    let ref mut fresh171 = (*parent).last;
    *fresh171 = cur;
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAddChild(
    mut parent: xmlNodePtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    let mut prev: xmlNodePtr = 0 as *mut xmlNode;
    if parent.is_null()
        || (*parent).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNodePtr;
    }
    if cur.is_null()
        || (*cur).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNodePtr;
    }
    if parent == cur {
        return 0 as xmlNodePtr;
    }
    if (*cur).type_0 as libc::c_uint == XML_TEXT_NODE as libc::c_int as libc::c_uint {
        if (*parent).type_0 as libc::c_uint
            == XML_TEXT_NODE as libc::c_int as libc::c_uint
            && !((*parent).content).is_null() && (*parent).name == (*cur).name
        {
            xmlNodeAddContent(parent, (*cur).content);
            xmlFreeNode(cur);
            return parent;
        }
        if !((*parent).last).is_null()
            && (*(*parent).last).type_0 as libc::c_uint
                == XML_TEXT_NODE as libc::c_int as libc::c_uint
            && (*(*parent).last).name == (*cur).name && (*parent).last != cur
        {
            xmlNodeAddContent((*parent).last, (*cur).content);
            xmlFreeNode(cur);
            return (*parent).last;
        }
    }
    prev = (*cur).parent;
    let ref mut fresh172 = (*cur).parent;
    *fresh172 = parent;
    if (*cur).doc != (*parent).doc {
        xmlSetTreeDoc(cur, (*parent).doc);
    }
    if prev == parent {
        return cur;
    }
    if (*parent).type_0 as libc::c_uint == XML_TEXT_NODE as libc::c_int as libc::c_uint
        && !((*parent).content).is_null() && parent != cur
    {
        xmlNodeAddContent(parent, (*cur).content);
        xmlFreeNode(cur);
        return parent;
    }
    if (*cur).type_0 as libc::c_uint == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
    {
        if (*parent).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            return 0 as xmlNodePtr;
        }
        if !((*parent).properties).is_null() {
            let mut lastattr: xmlAttrPtr = 0 as *mut xmlAttr;
            if ((*cur).ns).is_null() {
                lastattr = xmlHasNsProp(
                    parent as *const xmlNode,
                    (*cur).name,
                    0 as *const xmlChar,
                );
            } else {
                lastattr = xmlHasNsProp(
                    parent as *const xmlNode,
                    (*cur).name,
                    (*(*cur).ns).href,
                );
            }
            if !lastattr.is_null() && lastattr != cur as xmlAttrPtr
                && (*lastattr).type_0 as libc::c_uint
                    != XML_ATTRIBUTE_DECL as libc::c_int as libc::c_uint
            {
                xmlUnlinkNode(lastattr as xmlNodePtr);
                xmlFreeProp(lastattr);
            }
            if lastattr == cur as xmlAttrPtr {
                return cur;
            }
        }
        if ((*parent).properties).is_null() {
            let ref mut fresh173 = (*parent).properties;
            *fresh173 = cur as xmlAttrPtr;
        } else {
            let mut lastattr_0: xmlAttrPtr = (*parent).properties;
            while !((*lastattr_0).next).is_null() {
                lastattr_0 = (*lastattr_0).next;
            }
            let ref mut fresh174 = (*lastattr_0).next;
            *fresh174 = cur as xmlAttrPtr;
            let ref mut fresh175 = (*(cur as xmlAttrPtr)).prev;
            *fresh175 = lastattr_0;
        }
    } else if ((*parent).children).is_null() {
        let ref mut fresh176 = (*parent).children;
        *fresh176 = cur;
        let ref mut fresh177 = (*parent).last;
        *fresh177 = cur;
    } else {
        prev = (*parent).last;
        let ref mut fresh178 = (*prev).next;
        *fresh178 = cur;
        let ref mut fresh179 = (*cur).prev;
        *fresh179 = prev;
        let ref mut fresh180 = (*parent).last;
        *fresh180 = cur;
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetLastChild(mut parent: *const xmlNode) -> xmlNodePtr {
    if parent.is_null()
        || (*parent).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNodePtr;
    }
    return (*parent).last;
}
#[no_mangle]
pub unsafe extern "C" fn xmlChildElementCount(mut parent: xmlNodePtr) -> libc::c_ulong {
    let mut ret: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
    let mut cur: xmlNodePtr = 0 as xmlNodePtr;
    if parent.is_null() {
        return 0 as libc::c_int as libc::c_ulong;
    }
    match (*parent).type_0 as libc::c_uint {
        1 | 6 | 9 | 11 | 13 => {
            cur = (*parent).children;
        }
        _ => return 0 as libc::c_int as libc::c_ulong,
    }
    while !cur.is_null() {
        if (*cur).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            ret = ret.wrapping_add(1);
        }
        cur = (*cur).next;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFirstElementChild(mut parent: xmlNodePtr) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as xmlNodePtr;
    if parent.is_null() {
        return 0 as xmlNodePtr;
    }
    match (*parent).type_0 as libc::c_uint {
        1 | 6 | 9 | 11 | 13 => {
            cur = (*parent).children;
        }
        _ => return 0 as xmlNodePtr,
    }
    while !cur.is_null() {
        if (*cur).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            return cur;
        }
        cur = (*cur).next;
    }
    return 0 as xmlNodePtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlLastElementChild(mut parent: xmlNodePtr) -> xmlNodePtr {
    let mut cur: xmlNodePtr = 0 as xmlNodePtr;
    if parent.is_null() {
        return 0 as xmlNodePtr;
    }
    match (*parent).type_0 as libc::c_uint {
        1 | 6 | 9 | 11 | 13 => {
            cur = (*parent).last;
        }
        _ => return 0 as xmlNodePtr,
    }
    while !cur.is_null() {
        if (*cur).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            return cur;
        }
        cur = (*cur).prev;
    }
    return 0 as xmlNodePtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlPreviousElementSibling(mut node: xmlNodePtr) -> xmlNodePtr {
    if node.is_null() {
        return 0 as xmlNodePtr;
    }
    match (*node).type_0 as libc::c_uint {
        1 | 3 | 4 | 5 | 6 | 7 | 8 | 19 | 20 => {
            node = (*node).prev;
        }
        _ => return 0 as xmlNodePtr,
    }
    while !node.is_null() {
        if (*node).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            return node;
        }
        node = (*node).prev;
    }
    return 0 as xmlNodePtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNextElementSibling(mut node: xmlNodePtr) -> xmlNodePtr {
    if node.is_null() {
        return 0 as xmlNodePtr;
    }
    match (*node).type_0 as libc::c_uint {
        1 | 3 | 4 | 5 | 6 | 7 | 8 | 14 | 19 | 20 => {
            node = (*node).next;
        }
        _ => return 0 as xmlNodePtr,
    }
    while !node.is_null() {
        if (*node).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            return node;
        }
        node = (*node).next;
    }
    return 0 as xmlNodePtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeNodeList(mut cur: xmlNodePtr) {
    let mut next: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut dict: xmlDictPtr = 0 as xmlDictPtr;
    let mut depth: size_t = 0 as libc::c_int as size_t;
    if cur.is_null() {
        return;
    }
    if (*cur).type_0 as libc::c_uint == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        xmlFreeNsList(cur as xmlNsPtr);
        return;
    }
    if !((*cur).doc).is_null() {
        dict = (*(*cur).doc).dict;
    }
    loop {
        while !((*cur).children).is_null()
            && (*cur).type_0 as libc::c_uint
                != XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
            && (*cur).type_0 as libc::c_uint
                != XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
            && (*cur).type_0 as libc::c_uint
                != XML_DTD_NODE as libc::c_int as libc::c_uint
            && (*cur).type_0 as libc::c_uint
                != XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
        {
            cur = (*cur).children;
            depth = (depth as libc::c_ulong)
                .wrapping_add(1 as libc::c_int as libc::c_ulong) as size_t as size_t;
        }
        next = (*cur).next;
        parent = (*cur).parent;
        if (*cur).type_0 as libc::c_uint
            == XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
            || (*cur).type_0 as libc::c_uint
                == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
        {
            xmlFreeDoc(cur as xmlDocPtr);
        } else if (*cur).type_0 as libc::c_uint
                != XML_DTD_NODE as libc::c_int as libc::c_uint
            {
            if __xmlRegisterCallbacks != 0
                && (*__xmlDeregisterNodeDefaultValue()).is_some()
            {
                (*__xmlDeregisterNodeDefaultValue())
                    .expect("non-null function pointer")(cur);
            }
            if ((*cur).type_0 as libc::c_uint
                == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                || (*cur).type_0 as libc::c_uint
                    == XML_XINCLUDE_START as libc::c_int as libc::c_uint
                || (*cur).type_0 as libc::c_uint
                    == XML_XINCLUDE_END as libc::c_int as libc::c_uint)
                && !((*cur).properties).is_null()
            {
                xmlFreePropList((*cur).properties);
            }
            if (*cur).type_0 as libc::c_uint
                != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                && (*cur).type_0 as libc::c_uint
                    != XML_XINCLUDE_START as libc::c_int as libc::c_uint
                && (*cur).type_0 as libc::c_uint
                    != XML_XINCLUDE_END as libc::c_int as libc::c_uint
                && (*cur).type_0 as libc::c_uint
                    != XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
                && (*cur).content
                    != &mut (*cur).properties as *mut *mut _xmlAttr as *mut xmlChar
            {
                if !((*cur).content).is_null()
                    && (dict.is_null()
                        || xmlDictOwns(dict, (*cur).content as *const xmlChar)
                            == 0 as libc::c_int)
                {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )((*cur).content as *mut libc::c_char as *mut libc::c_void);
                }
            }
            if ((*cur).type_0 as libc::c_uint
                == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                || (*cur).type_0 as libc::c_uint
                    == XML_XINCLUDE_START as libc::c_int as libc::c_uint
                || (*cur).type_0 as libc::c_uint
                    == XML_XINCLUDE_END as libc::c_int as libc::c_uint)
                && !((*cur).nsDef).is_null()
            {
                xmlFreeNsList((*cur).nsDef);
            }
            if !((*cur).name).is_null()
                && (*cur).type_0 as libc::c_uint
                    != XML_TEXT_NODE as libc::c_int as libc::c_uint
                && (*cur).type_0 as libc::c_uint
                    != XML_COMMENT_NODE as libc::c_int as libc::c_uint
            {
                if !((*cur).name).is_null()
                    && (dict.is_null()
                        || xmlDictOwns(dict, (*cur).name) == 0 as libc::c_int)
                {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )((*cur).name as *mut libc::c_char as *mut libc::c_void);
                }
            }
            xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
        }
        if !next.is_null() {
            cur = next;
        } else {
            if depth == 0 as libc::c_int as libc::c_ulong || parent.is_null() {
                break;
            }
            depth = (depth as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as size_t as size_t;
            cur = parent;
            let ref mut fresh181 = (*cur).children;
            *fresh181 = 0 as *mut _xmlNode;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeNode(mut cur: xmlNodePtr) {
    let mut dict: xmlDictPtr = 0 as xmlDictPtr;
    if cur.is_null() {
        return;
    }
    if (*cur).type_0 as libc::c_uint == XML_DTD_NODE as libc::c_int as libc::c_uint {
        xmlFreeDtd(cur as xmlDtdPtr);
        return;
    }
    if (*cur).type_0 as libc::c_uint == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        xmlFreeNs(cur as xmlNsPtr);
        return;
    }
    if (*cur).type_0 as libc::c_uint == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
    {
        xmlFreeProp(cur as xmlAttrPtr);
        return;
    }
    if __xmlRegisterCallbacks != 0 && (*__xmlDeregisterNodeDefaultValue()).is_some() {
        (*__xmlDeregisterNodeDefaultValue()).expect("non-null function pointer")(cur);
    }
    if !((*cur).doc).is_null() {
        dict = (*(*cur).doc).dict;
    }
    if (*cur).type_0 as libc::c_uint == XML_ENTITY_DECL as libc::c_int as libc::c_uint {
        let mut ent: xmlEntityPtr = cur as xmlEntityPtr;
        if !((*ent).SystemID).is_null()
            && (dict.is_null() || xmlDictOwns(dict, (*ent).SystemID) == 0 as libc::c_int)
        {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ent).SystemID as *mut libc::c_char as *mut libc::c_void);
        }
        if !((*ent).ExternalID).is_null()
            && (dict.is_null()
                || xmlDictOwns(dict, (*ent).ExternalID) == 0 as libc::c_int)
        {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ent).ExternalID as *mut libc::c_char as *mut libc::c_void);
        }
    }
    if !((*cur).children).is_null()
        && (*cur).type_0 as libc::c_uint
            != XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
    {
        xmlFreeNodeList((*cur).children);
    }
    if (*cur).type_0 as libc::c_uint == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        || (*cur).type_0 as libc::c_uint
            == XML_XINCLUDE_START as libc::c_int as libc::c_uint
        || (*cur).type_0 as libc::c_uint
            == XML_XINCLUDE_END as libc::c_int as libc::c_uint
    {
        if !((*cur).properties).is_null() {
            xmlFreePropList((*cur).properties);
        }
        if !((*cur).nsDef).is_null() {
            xmlFreeNsList((*cur).nsDef);
        }
    } else if !((*cur).content).is_null()
            && (*cur).type_0 as libc::c_uint
                != XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
            && (*cur).content
                != &mut (*cur).properties as *mut *mut _xmlAttr as *mut xmlChar
        {
        if !((*cur).content).is_null()
            && (dict.is_null()
                || xmlDictOwns(dict, (*cur).content as *const xmlChar)
                    == 0 as libc::c_int)
        {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*cur).content as *mut libc::c_char as *mut libc::c_void);
        }
    }
    if !((*cur).name).is_null()
        && (*cur).type_0 as libc::c_uint != XML_TEXT_NODE as libc::c_int as libc::c_uint
        && (*cur).type_0 as libc::c_uint
            != XML_COMMENT_NODE as libc::c_int as libc::c_uint
    {
        if !((*cur).name).is_null()
            && (dict.is_null() || xmlDictOwns(dict, (*cur).name) == 0 as libc::c_int)
        {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*cur).name as *mut libc::c_char as *mut libc::c_void);
        }
    }
    xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUnlinkNode(mut cur: xmlNodePtr) {
    if cur.is_null() {
        return;
    }
    if (*cur).type_0 as libc::c_uint == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return;
    }
    if (*cur).type_0 as libc::c_uint == XML_DTD_NODE as libc::c_int as libc::c_uint {
        let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
        doc = (*cur).doc;
        if !doc.is_null() {
            if (*doc).intSubset == cur as xmlDtdPtr {
                let ref mut fresh182 = (*doc).intSubset;
                *fresh182 = 0 as *mut _xmlDtd;
            }
            if (*doc).extSubset == cur as xmlDtdPtr {
                let ref mut fresh183 = (*doc).extSubset;
                *fresh183 = 0 as *mut _xmlDtd;
            }
        }
    }
    if (*cur).type_0 as libc::c_uint == XML_ENTITY_DECL as libc::c_int as libc::c_uint {
        let mut doc_0: xmlDocPtr = 0 as *mut xmlDoc;
        doc_0 = (*cur).doc;
        if !doc_0.is_null() {
            if !((*doc_0).intSubset).is_null() {
                if xmlHashLookup(
                    (*(*doc_0).intSubset).entities as xmlHashTablePtr,
                    (*cur).name,
                ) == cur as *mut libc::c_void
                {
                    xmlHashRemoveEntry(
                        (*(*doc_0).intSubset).entities as xmlHashTablePtr,
                        (*cur).name,
                        None,
                    );
                }
                if xmlHashLookup(
                    (*(*doc_0).intSubset).pentities as xmlHashTablePtr,
                    (*cur).name,
                ) == cur as *mut libc::c_void
                {
                    xmlHashRemoveEntry(
                        (*(*doc_0).intSubset).pentities as xmlHashTablePtr,
                        (*cur).name,
                        None,
                    );
                }
            }
            if !((*doc_0).extSubset).is_null() {
                if xmlHashLookup(
                    (*(*doc_0).extSubset).entities as xmlHashTablePtr,
                    (*cur).name,
                ) == cur as *mut libc::c_void
                {
                    xmlHashRemoveEntry(
                        (*(*doc_0).extSubset).entities as xmlHashTablePtr,
                        (*cur).name,
                        None,
                    );
                }
                if xmlHashLookup(
                    (*(*doc_0).extSubset).pentities as xmlHashTablePtr,
                    (*cur).name,
                ) == cur as *mut libc::c_void
                {
                    xmlHashRemoveEntry(
                        (*(*doc_0).extSubset).pentities as xmlHashTablePtr,
                        (*cur).name,
                        None,
                    );
                }
            }
        }
    }
    if !((*cur).parent).is_null() {
        let mut parent: xmlNodePtr = 0 as *mut xmlNode;
        parent = (*cur).parent;
        if (*cur).type_0 as libc::c_uint
            == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
        {
            if (*parent).properties == cur as xmlAttrPtr {
                let ref mut fresh184 = (*parent).properties;
                *fresh184 = (*(cur as xmlAttrPtr)).next;
            }
        } else {
            if (*parent).children == cur {
                let ref mut fresh185 = (*parent).children;
                *fresh185 = (*cur).next;
            }
            if (*parent).last == cur {
                let ref mut fresh186 = (*parent).last;
                *fresh186 = (*cur).prev;
            }
        }
        let ref mut fresh187 = (*cur).parent;
        *fresh187 = 0 as *mut _xmlNode;
    }
    if !((*cur).next).is_null() {
        let ref mut fresh188 = (*(*cur).next).prev;
        *fresh188 = (*cur).prev;
    }
    if !((*cur).prev).is_null() {
        let ref mut fresh189 = (*(*cur).prev).next;
        *fresh189 = (*cur).next;
    }
    let ref mut fresh190 = (*cur).prev;
    *fresh190 = 0 as *mut _xmlNode;
    let ref mut fresh191 = (*cur).next;
    *fresh191 = *fresh190;
}
#[no_mangle]
pub unsafe extern "C" fn xmlReplaceNode(
    mut old: xmlNodePtr,
    mut cur: xmlNodePtr,
) -> xmlNodePtr {
    if old == cur {
        return 0 as xmlNodePtr;
    }
    if old.is_null()
        || (*old).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
        || ((*old).parent).is_null()
    {
        return 0 as xmlNodePtr;
    }
    if cur.is_null()
        || (*cur).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        xmlUnlinkNode(old);
        return old;
    }
    if cur == old {
        return old;
    }
    if (*old).type_0 as libc::c_uint == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
        && (*cur).type_0 as libc::c_uint
            != XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
    {
        return old;
    }
    if (*cur).type_0 as libc::c_uint == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
        && (*old).type_0 as libc::c_uint
            != XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
    {
        return old;
    }
    xmlUnlinkNode(cur);
    xmlSetTreeDoc(cur, (*old).doc);
    let ref mut fresh192 = (*cur).parent;
    *fresh192 = (*old).parent;
    let ref mut fresh193 = (*cur).next;
    *fresh193 = (*old).next;
    if !((*cur).next).is_null() {
        let ref mut fresh194 = (*(*cur).next).prev;
        *fresh194 = cur;
    }
    let ref mut fresh195 = (*cur).prev;
    *fresh195 = (*old).prev;
    if !((*cur).prev).is_null() {
        let ref mut fresh196 = (*(*cur).prev).next;
        *fresh196 = cur;
    }
    if !((*cur).parent).is_null() {
        if (*cur).type_0 as libc::c_uint
            == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
        {
            if (*(*cur).parent).properties == old as xmlAttrPtr {
                let ref mut fresh197 = (*(*cur).parent).properties;
                *fresh197 = cur as xmlAttrPtr;
            }
        } else {
            if (*(*cur).parent).children == old {
                let ref mut fresh198 = (*(*cur).parent).children;
                *fresh198 = cur;
            }
            if (*(*cur).parent).last == old {
                let ref mut fresh199 = (*(*cur).parent).last;
                *fresh199 = cur;
            }
        }
    }
    let ref mut fresh200 = (*old).prev;
    *fresh200 = 0 as *mut _xmlNode;
    let ref mut fresh201 = (*old).next;
    *fresh201 = *fresh200;
    let ref mut fresh202 = (*old).parent;
    *fresh202 = 0 as *mut _xmlNode;
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyNamespace(mut cur: xmlNsPtr) -> xmlNsPtr {
    let mut ret: xmlNsPtr = 0 as *mut xmlNs;
    if cur.is_null() {
        return 0 as xmlNsPtr;
    }
    match (*cur).type_0 as libc::c_uint {
        18 => {
            ret = xmlNewNs(0 as xmlNodePtr, (*cur).href, (*cur).prefix);
        }
        _ => return 0 as xmlNsPtr,
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyNamespaceList(mut cur: xmlNsPtr) -> xmlNsPtr {
    let mut ret: xmlNsPtr = 0 as xmlNsPtr;
    let mut p: xmlNsPtr = 0 as xmlNsPtr;
    let mut q: xmlNsPtr = 0 as *mut xmlNs;
    while !cur.is_null() {
        q = xmlCopyNamespace(cur);
        if p.is_null() {
            p = q;
            ret = p;
        } else {
            let ref mut fresh203 = (*p).next;
            *fresh203 = q;
            p = q;
        }
        cur = (*cur).next;
    }
    return ret;
}
unsafe extern "C" fn xmlCopyPropInternal(
    mut doc: xmlDocPtr,
    mut target: xmlNodePtr,
    mut cur: xmlAttrPtr,
) -> xmlAttrPtr {
    let mut ret: xmlAttrPtr = 0 as *mut xmlAttr;
    if cur.is_null() {
        return 0 as xmlAttrPtr;
    }
    if !target.is_null()
        && (*target).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        return 0 as xmlAttrPtr;
    }
    if !target.is_null() {
        ret = xmlNewDocProp((*target).doc, (*cur).name, 0 as *const xmlChar);
    } else if !doc.is_null() {
        ret = xmlNewDocProp(doc, (*cur).name, 0 as *const xmlChar);
    } else if !((*cur).parent).is_null() {
        ret = xmlNewDocProp((*(*cur).parent).doc, (*cur).name, 0 as *const xmlChar);
    } else if !((*cur).children).is_null() {
        ret = xmlNewDocProp((*(*cur).children).doc, (*cur).name, 0 as *const xmlChar);
    } else {
        ret = xmlNewDocProp(0 as xmlDocPtr, (*cur).name, 0 as *const xmlChar);
    }
    if ret.is_null() {
        return 0 as xmlAttrPtr;
    }
    let ref mut fresh204 = (*ret).parent;
    *fresh204 = target;
    if !((*cur).ns).is_null() && !target.is_null() {
        let mut ns: xmlNsPtr = 0 as *mut xmlNs;
        ns = xmlSearchNs((*target).doc, target, (*(*cur).ns).prefix);
        if ns.is_null() {
            ns = xmlSearchNs((*cur).doc, (*cur).parent, (*(*cur).ns).prefix);
            if !ns.is_null() {
                let mut root: xmlNodePtr = target;
                let mut pred: xmlNodePtr = 0 as xmlNodePtr;
                while !((*root).parent).is_null() {
                    pred = root;
                    root = (*root).parent;
                }
                if root == (*target).doc as xmlNodePtr {
                    root = pred;
                }
                let ref mut fresh205 = (*ret).ns;
                *fresh205 = xmlNewNs(root, (*ns).href, (*ns).prefix);
            }
        } else if xmlStrEqual((*ns).href, (*(*cur).ns).href) != 0 {
            let ref mut fresh206 = (*ret).ns;
            *fresh206 = ns;
        } else {
            let ref mut fresh207 = (*ret).ns;
            *fresh207 = xmlNewReconciledNs((*target).doc, target, (*cur).ns);
        }
    } else {
        let ref mut fresh208 = (*ret).ns;
        *fresh208 = 0 as *mut xmlNs;
    }
    if !((*cur).children).is_null() {
        let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
        let ref mut fresh209 = (*ret).children;
        *fresh209 = xmlStaticCopyNodeList(
            (*cur).children,
            (*ret).doc,
            ret as xmlNodePtr,
        );
        let ref mut fresh210 = (*ret).last;
        *fresh210 = 0 as *mut _xmlNode;
        tmp = (*ret).children;
        while !tmp.is_null() {
            if ((*tmp).next).is_null() {
                let ref mut fresh211 = (*ret).last;
                *fresh211 = tmp;
            }
            tmp = (*tmp).next;
        }
    }
    if !target.is_null() && !cur.is_null() && !((*target).doc).is_null()
        && !((*cur).doc).is_null() && !((*(*cur).doc).ids).is_null()
        && !((*cur).parent).is_null()
    {
        if xmlIsID((*cur).doc, (*cur).parent, cur) != 0 {
            let mut id: *mut xmlChar = 0 as *mut xmlChar;
            id = xmlNodeListGetString((*cur).doc, (*cur).children, 1 as libc::c_int);
            if !id.is_null() {
                xmlAddID(0 as xmlValidCtxtPtr, (*target).doc, id, ret);
                xmlFree.expect("non-null function pointer")(id as *mut libc::c_void);
            }
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyProp(
    mut target: xmlNodePtr,
    mut cur: xmlAttrPtr,
) -> xmlAttrPtr {
    return xmlCopyPropInternal(0 as xmlDocPtr, target, cur);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyPropList(
    mut target: xmlNodePtr,
    mut cur: xmlAttrPtr,
) -> xmlAttrPtr {
    let mut ret: xmlAttrPtr = 0 as xmlAttrPtr;
    let mut p: xmlAttrPtr = 0 as xmlAttrPtr;
    let mut q: xmlAttrPtr = 0 as *mut xmlAttr;
    if !target.is_null()
        && (*target).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        return 0 as xmlAttrPtr;
    }
    while !cur.is_null() {
        q = xmlCopyProp(target, cur);
        if q.is_null() {
            return 0 as xmlAttrPtr;
        }
        if p.is_null() {
            p = q;
            ret = p;
        } else {
            let ref mut fresh212 = (*p).next;
            *fresh212 = q;
            let ref mut fresh213 = (*q).prev;
            *fresh213 = p;
            p = q;
        }
        cur = (*cur).next;
    }
    return ret;
}
unsafe extern "C" fn xmlStaticCopyNode(
    mut node: xmlNodePtr,
    mut doc: xmlDocPtr,
    mut parent: xmlNodePtr,
    mut extended: libc::c_int,
) -> xmlNodePtr {
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    if node.is_null() {
        return 0 as xmlNodePtr;
    }
    match (*node).type_0 as libc::c_uint {
        2 => return xmlCopyPropInternal(doc, parent, node as xmlAttrPtr) as xmlNodePtr,
        18 => return xmlCopyNamespaceList(node as xmlNsPtr) as xmlNodePtr,
        9 | 13 => return xmlCopyDoc(node as xmlDocPtr, extended) as xmlNodePtr,
        10 | 12 | 14 | 15 | 16 | 17 => return 0 as xmlNodePtr,
        3 | 4 | 1 | 11 | 5 | 6 | 7 | 8 | 19 | 20 | _ => {}
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNode>() as libc::c_ulong) as xmlNodePtr;
    if ret.is_null() {
        xmlTreeErrMemory(b"copying node\0" as *const u8 as *const libc::c_char);
        return 0 as xmlNodePtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNode>() as libc::c_ulong,
    );
    (*ret).type_0 = (*node).type_0;
    let ref mut fresh214 = (*ret).doc;
    *fresh214 = doc;
    let ref mut fresh215 = (*ret).parent;
    *fresh215 = parent;
    if (*node).name == xmlStringText.as_ptr() {
        let ref mut fresh216 = (*ret).name;
        *fresh216 = xmlStringText.as_ptr();
    } else if (*node).name == xmlStringTextNoenc.as_ptr() {
        let ref mut fresh217 = (*ret).name;
        *fresh217 = xmlStringTextNoenc.as_ptr();
    } else if (*node).name == xmlStringComment.as_ptr() {
        let ref mut fresh218 = (*ret).name;
        *fresh218 = xmlStringComment.as_ptr();
    } else if !((*node).name).is_null() {
        if !doc.is_null() && !((*doc).dict).is_null() {
            let ref mut fresh219 = (*ret).name;
            *fresh219 = xmlDictLookup((*doc).dict, (*node).name, -(1 as libc::c_int));
        } else {
            let ref mut fresh220 = (*ret).name;
            *fresh220 = xmlStrdup((*node).name);
        }
    }
    if (*node).type_0 as libc::c_uint != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        && !((*node).content).is_null()
        && (*node).type_0 as libc::c_uint
            != XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
        && (*node).type_0 as libc::c_uint
            != XML_XINCLUDE_END as libc::c_int as libc::c_uint
        && (*node).type_0 as libc::c_uint
            != XML_XINCLUDE_START as libc::c_int as libc::c_uint
    {
        let ref mut fresh221 = (*ret).content;
        *fresh221 = xmlStrdup((*node).content);
    } else if (*node).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
        (*ret).line = (*node).line;
    }
    if !parent.is_null() {
        let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
        if __xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some() {
            (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(ret);
        }
        tmp = xmlAddChild(parent, ret);
        if tmp != ret {
            return tmp;
        }
    }
    if !(extended == 0) {
        if ((*node).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
            || (*node).type_0 as libc::c_uint
                == XML_XINCLUDE_START as libc::c_int as libc::c_uint)
            && !((*node).nsDef).is_null()
        {
            let ref mut fresh222 = (*ret).nsDef;
            *fresh222 = xmlCopyNamespaceList((*node).nsDef);
        }
        if !((*node).ns).is_null() {
            let mut ns: xmlNsPtr = 0 as *mut xmlNs;
            ns = xmlSearchNs(doc, ret, (*(*node).ns).prefix);
            if ns.is_null() {
                ns = xmlSearchNs((*node).doc, node, (*(*node).ns).prefix);
                if !ns.is_null() {
                    let mut root: xmlNodePtr = ret;
                    while !((*root).parent).is_null() {
                        root = (*root).parent;
                    }
                    let ref mut fresh223 = (*ret).ns;
                    *fresh223 = xmlNewNs(root, (*ns).href, (*ns).prefix);
                } else {
                    let ref mut fresh224 = (*ret).ns;
                    *fresh224 = xmlNewReconciledNs(doc, ret, (*node).ns);
                }
            } else {
                let ref mut fresh225 = (*ret).ns;
                *fresh225 = ns;
            }
        }
        if ((*node).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
            || (*node).type_0 as libc::c_uint
                == XML_XINCLUDE_START as libc::c_int as libc::c_uint)
            && !((*node).properties).is_null()
        {
            let ref mut fresh226 = (*ret).properties;
            *fresh226 = xmlCopyPropList(ret, (*node).properties);
        }
        if (*node).type_0 as libc::c_uint
            == XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
        {
            if doc.is_null() || (*node).doc != doc {
                let ref mut fresh227 = (*ret).children;
                *fresh227 = xmlGetDocEntity(doc as *const xmlDoc, (*ret).name)
                    as xmlNodePtr;
            } else {
                let ref mut fresh228 = (*ret).children;
                *fresh228 = (*node).children;
            }
            let ref mut fresh229 = (*ret).last;
            *fresh229 = (*ret).children;
        } else if !((*node).children).is_null() && extended != 2 as libc::c_int {
            let mut cur: xmlNodePtr = 0 as *mut xmlNode;
            let mut insert: xmlNodePtr = 0 as *mut xmlNode;
            cur = (*node).children;
            insert = ret;
            while !cur.is_null() {
                let mut copy: xmlNodePtr = xmlStaticCopyNode(
                    cur,
                    doc,
                    insert,
                    2 as libc::c_int,
                );
                if copy.is_null() {
                    xmlFreeNode(ret);
                    return 0 as xmlNodePtr;
                }
                if (*insert).last != copy {
                    if ((*insert).last).is_null() {
                        let ref mut fresh230 = (*insert).children;
                        *fresh230 = copy;
                    } else {
                        let ref mut fresh231 = (*copy).prev;
                        *fresh231 = (*insert).last;
                        let ref mut fresh232 = (*(*insert).last).next;
                        *fresh232 = copy;
                    }
                    let ref mut fresh233 = (*insert).last;
                    *fresh233 = copy;
                }
                if (*cur).type_0 as libc::c_uint
                    != XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
                    && !((*cur).children).is_null()
                {
                    cur = (*cur).children;
                    insert = copy;
                } else {
                    loop {
                        if !((*cur).next).is_null() {
                            cur = (*cur).next;
                            break;
                        } else {
                            cur = (*cur).parent;
                            insert = (*insert).parent;
                            if !(cur == node) {
                                continue;
                            }
                            cur = 0 as xmlNodePtr;
                            break;
                        }
                    }
                }
            }
        }
    }
    if parent.is_null()
        && (__xmlRegisterCallbacks != 0 && (*__xmlRegisterNodeDefaultValue()).is_some())
    {
        (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(ret);
    }
    return ret;
}
unsafe extern "C" fn xmlStaticCopyNodeList(
    mut node: xmlNodePtr,
    mut doc: xmlDocPtr,
    mut parent: xmlNodePtr,
) -> xmlNodePtr {
    let mut ret: xmlNodePtr = 0 as xmlNodePtr;
    let mut p: xmlNodePtr = 0 as xmlNodePtr;
    let mut q: xmlNodePtr = 0 as *mut xmlNode;
    while !node.is_null() {
        if (*node).type_0 as libc::c_uint == XML_DTD_NODE as libc::c_int as libc::c_uint
        {
            if doc.is_null() {
                node = (*node).next;
                continue;
            } else if ((*doc).intSubset).is_null() {
                q = xmlCopyDtd(node as xmlDtdPtr) as xmlNodePtr;
                if q.is_null() {
                    return 0 as xmlNodePtr;
                }
                let ref mut fresh234 = (*q).doc;
                *fresh234 = doc;
                let ref mut fresh235 = (*q).parent;
                *fresh235 = parent;
                let ref mut fresh236 = (*doc).intSubset;
                *fresh236 = q as xmlDtdPtr;
                xmlAddChild(parent, q);
            } else {
                q = (*doc).intSubset as xmlNodePtr;
                xmlAddChild(parent, q);
            }
        } else {
            q = xmlStaticCopyNode(node, doc, parent, 1 as libc::c_int);
        }
        if q.is_null() {
            return 0 as xmlNodePtr;
        }
        if ret.is_null() {
            let ref mut fresh237 = (*q).prev;
            *fresh237 = 0 as *mut _xmlNode;
            p = q;
            ret = p;
        } else if p != q {
            let ref mut fresh238 = (*p).next;
            *fresh238 = q;
            let ref mut fresh239 = (*q).prev;
            *fresh239 = p;
            p = q;
        }
        node = (*node).next;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyNode(
    mut node: xmlNodePtr,
    mut extended: libc::c_int,
) -> xmlNodePtr {
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    ret = xmlStaticCopyNode(node, 0 as xmlDocPtr, 0 as xmlNodePtr, extended);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDocCopyNode(
    mut node: xmlNodePtr,
    mut doc: xmlDocPtr,
    mut extended: libc::c_int,
) -> xmlNodePtr {
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    ret = xmlStaticCopyNode(node, doc, 0 as xmlNodePtr, extended);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDocCopyNodeList(
    mut doc: xmlDocPtr,
    mut node: xmlNodePtr,
) -> xmlNodePtr {
    let mut ret: xmlNodePtr = xmlStaticCopyNodeList(node, doc, 0 as xmlNodePtr);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyNodeList(mut node: xmlNodePtr) -> xmlNodePtr {
    let mut ret: xmlNodePtr = xmlStaticCopyNodeList(
        node,
        0 as xmlDocPtr,
        0 as xmlNodePtr,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyDtd(mut dtd: xmlDtdPtr) -> xmlDtdPtr {
    let mut ret: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut p: xmlNodePtr = 0 as xmlNodePtr;
    let mut q: xmlNodePtr = 0 as *mut xmlNode;
    if dtd.is_null() {
        return 0 as xmlDtdPtr;
    }
    ret = xmlNewDtd(0 as xmlDocPtr, (*dtd).name, (*dtd).ExternalID, (*dtd).SystemID);
    if ret.is_null() {
        return 0 as xmlDtdPtr;
    }
    if !((*dtd).entities).is_null() {
        let ref mut fresh240 = (*ret).entities;
        *fresh240 = xmlCopyEntitiesTable((*dtd).entities as xmlEntitiesTablePtr)
            as *mut libc::c_void;
    }
    if !((*dtd).notations).is_null() {
        let ref mut fresh241 = (*ret).notations;
        *fresh241 = xmlCopyNotationTable((*dtd).notations as xmlNotationTablePtr)
            as *mut libc::c_void;
    }
    if !((*dtd).elements).is_null() {
        let ref mut fresh242 = (*ret).elements;
        *fresh242 = xmlCopyElementTable((*dtd).elements as xmlElementTablePtr)
            as *mut libc::c_void;
    }
    if !((*dtd).attributes).is_null() {
        let ref mut fresh243 = (*ret).attributes;
        *fresh243 = xmlCopyAttributeTable((*dtd).attributes as xmlAttributeTablePtr)
            as *mut libc::c_void;
    }
    if !((*dtd).pentities).is_null() {
        let ref mut fresh244 = (*ret).pentities;
        *fresh244 = xmlCopyEntitiesTable((*dtd).pentities as xmlEntitiesTablePtr)
            as *mut libc::c_void;
    }
    cur = (*dtd).children;
    while !cur.is_null() {
        q = 0 as xmlNodePtr;
        if (*cur).type_0 as libc::c_uint
            == XML_ENTITY_DECL as libc::c_int as libc::c_uint
        {
            let mut tmp: xmlEntityPtr = cur as xmlEntityPtr;
            match (*tmp).etype as libc::c_uint {
                1 | 2 | 3 => {
                    q = xmlGetEntityFromDtd(ret as *const xmlDtd, (*tmp).name)
                        as xmlNodePtr;
                }
                4 | 5 => {
                    q = xmlGetParameterEntityFromDtd(ret as *const xmlDtd, (*tmp).name)
                        as xmlNodePtr;
                }
                6 | _ => {}
            }
        } else if (*cur).type_0 as libc::c_uint
                == XML_ELEMENT_DECL as libc::c_int as libc::c_uint
            {
            let mut tmp_0: xmlElementPtr = cur as xmlElementPtr;
            q = xmlGetDtdQElementDesc(ret, (*tmp_0).name, (*tmp_0).prefix) as xmlNodePtr;
        } else if (*cur).type_0 as libc::c_uint
                == XML_ATTRIBUTE_DECL as libc::c_int as libc::c_uint
            {
            let mut tmp_1: xmlAttributePtr = cur as xmlAttributePtr;
            q = xmlGetDtdQAttrDesc(ret, (*tmp_1).elem, (*tmp_1).name, (*tmp_1).prefix)
                as xmlNodePtr;
        } else if (*cur).type_0 as libc::c_uint
                == XML_COMMENT_NODE as libc::c_int as libc::c_uint
            {
            q = xmlCopyNode(cur, 0 as libc::c_int);
        }
        if q.is_null() {
            cur = (*cur).next;
        } else {
            if p.is_null() {
                let ref mut fresh245 = (*ret).children;
                *fresh245 = q;
            } else {
                let ref mut fresh246 = (*p).next;
                *fresh246 = q;
            }
            let ref mut fresh247 = (*q).prev;
            *fresh247 = p;
            let ref mut fresh248 = (*q).parent;
            *fresh248 = ret as xmlNodePtr;
            let ref mut fresh249 = (*q).next;
            *fresh249 = 0 as *mut _xmlNode;
            let ref mut fresh250 = (*ret).last;
            *fresh250 = q;
            p = q;
            cur = (*cur).next;
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyDoc(
    mut doc: xmlDocPtr,
    mut recursive: libc::c_int,
) -> xmlDocPtr {
    let mut ret: xmlDocPtr = 0 as *mut xmlDoc;
    if doc.is_null() {
        return 0 as xmlDocPtr;
    }
    ret = xmlNewDoc((*doc).version);
    if ret.is_null() {
        return 0 as xmlDocPtr;
    }
    (*ret).type_0 = (*doc).type_0;
    if !((*doc).name).is_null() {
        let ref mut fresh251 = (*ret).name;
        *fresh251 = xmlMemStrdup.expect("non-null function pointer")((*doc).name);
    }
    if !((*doc).encoding).is_null() {
        let ref mut fresh252 = (*ret).encoding;
        *fresh252 = xmlStrdup((*doc).encoding);
    }
    if !((*doc).URL).is_null() {
        let ref mut fresh253 = (*ret).URL;
        *fresh253 = xmlStrdup((*doc).URL);
    }
    (*ret).charset = (*doc).charset;
    (*ret).compression = (*doc).compression;
    (*ret).standalone = (*doc).standalone;
    if recursive == 0 {
        return ret;
    }
    let ref mut fresh254 = (*ret).last;
    *fresh254 = 0 as *mut _xmlNode;
    let ref mut fresh255 = (*ret).children;
    *fresh255 = 0 as *mut _xmlNode;
    if !((*doc).intSubset).is_null() {
        let ref mut fresh256 = (*ret).intSubset;
        *fresh256 = xmlCopyDtd((*doc).intSubset);
        if ((*ret).intSubset).is_null() {
            xmlFreeDoc(ret);
            return 0 as xmlDocPtr;
        }
        xmlSetTreeDoc((*ret).intSubset as xmlNodePtr, ret);
        let ref mut fresh257 = (*(*ret).intSubset).parent;
        *fresh257 = ret;
    }
    if !((*doc).oldNs).is_null() {
        let ref mut fresh258 = (*ret).oldNs;
        *fresh258 = xmlCopyNamespaceList((*doc).oldNs);
    }
    if !((*doc).children).is_null() {
        let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
        let ref mut fresh259 = (*ret).children;
        *fresh259 = xmlStaticCopyNodeList((*doc).children, ret, ret as xmlNodePtr);
        let ref mut fresh260 = (*ret).last;
        *fresh260 = 0 as *mut _xmlNode;
        tmp = (*ret).children;
        while !tmp.is_null() {
            if ((*tmp).next).is_null() {
                let ref mut fresh261 = (*ret).last;
                *fresh261 = tmp;
            }
            tmp = (*tmp).next;
        }
    }
    return ret;
}
unsafe extern "C" fn xmlGetLineNoInternal(
    mut node: *const xmlNode,
    mut depth: libc::c_int,
) -> libc::c_long {
    let mut result: libc::c_long = -(1 as libc::c_int) as libc::c_long;
    if depth >= 5 as libc::c_int {
        return -(1 as libc::c_int) as libc::c_long;
    }
    if node.is_null() {
        return result;
    }
    if (*node).type_0 as libc::c_uint == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        || (*node).type_0 as libc::c_uint == XML_TEXT_NODE as libc::c_int as libc::c_uint
        || (*node).type_0 as libc::c_uint
            == XML_COMMENT_NODE as libc::c_int as libc::c_uint
        || (*node).type_0 as libc::c_uint == XML_PI_NODE as libc::c_int as libc::c_uint
    {
        if (*node).line as libc::c_int == 65535 as libc::c_int {
            if (*node).type_0 as libc::c_uint
                == XML_TEXT_NODE as libc::c_int as libc::c_uint
                && !((*node).psvi).is_null()
            {
                result = (*node).psvi as ptrdiff_t;
            } else if (*node).type_0 as libc::c_uint
                    == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                    && !((*node).children).is_null()
                {
                result = xmlGetLineNoInternal(
                    (*node).children,
                    depth + 1 as libc::c_int,
                );
            } else if !((*node).next).is_null() {
                result = xmlGetLineNoInternal((*node).next, depth + 1 as libc::c_int);
            } else if !((*node).prev).is_null() {
                result = xmlGetLineNoInternal((*node).prev, depth + 1 as libc::c_int);
            }
        }
        if result == -(1 as libc::c_int) as libc::c_long
            || result == 65535 as libc::c_int as libc::c_long
        {
            result = (*node).line as libc::c_long;
        }
    } else if !((*node).prev).is_null()
            && ((*(*node).prev).type_0 as libc::c_uint
                == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                || (*(*node).prev).type_0 as libc::c_uint
                    == XML_TEXT_NODE as libc::c_int as libc::c_uint
                || (*(*node).prev).type_0 as libc::c_uint
                    == XML_COMMENT_NODE as libc::c_int as libc::c_uint
                || (*(*node).prev).type_0 as libc::c_uint
                    == XML_PI_NODE as libc::c_int as libc::c_uint)
        {
        result = xmlGetLineNoInternal((*node).prev, depth + 1 as libc::c_int);
    } else if !((*node).parent).is_null()
            && (*(*node).parent).type_0 as libc::c_uint
                == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
        result = xmlGetLineNoInternal((*node).parent, depth + 1 as libc::c_int);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetLineNo(mut node: *const xmlNode) -> libc::c_long {
    return xmlGetLineNoInternal(node, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetNodePath(mut node: *const xmlNode) -> *mut xmlChar {
    let mut cur: *const xmlNode = 0 as *const xmlNode;
    let mut tmp: *const xmlNode = 0 as *const xmlNode;
    let mut next: *const xmlNode = 0 as *const xmlNode;
    let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
    let mut temp: *mut xmlChar = 0 as *mut xmlChar;
    let mut buf_len: size_t = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut sep: *const libc::c_char = 0 as *const libc::c_char;
    let mut name: *const libc::c_char = 0 as *const libc::c_char;
    let mut nametemp: [libc::c_char; 100] = [0; 100];
    let mut occur: libc::c_int = 0 as libc::c_int;
    let mut generic: libc::c_int = 0;
    if node.is_null()
        || (*node).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as *mut xmlChar;
    }
    buf_len = 500 as libc::c_int as size_t;
    buffer = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(buf_len.wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong))
        as *mut xmlChar;
    if buffer.is_null() {
        xmlTreeErrMemory(b"getting node path\0" as *const u8 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    buf = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(buf_len.wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong))
        as *mut xmlChar;
    if buf.is_null() {
        xmlTreeErrMemory(b"getting node path\0" as *const u8 as *const libc::c_char);
        xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void);
        return 0 as *mut xmlChar;
    }
    *buffer.offset(0 as libc::c_int as isize) = 0 as libc::c_int as xmlChar;
    cur = node;
    loop {
        name = b"\0" as *const u8 as *const libc::c_char;
        sep = b"?\0" as *const u8 as *const libc::c_char;
        occur = 0 as libc::c_int;
        if (*cur).type_0 as libc::c_uint
            == XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
            || (*cur).type_0 as libc::c_uint
                == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
        {
            if *buffer.offset(0 as libc::c_int as isize) as libc::c_int == '/' as i32 {
                break;
            }
            sep = b"/\0" as *const u8 as *const libc::c_char;
            next = 0 as *const xmlNode;
        } else if (*cur).type_0 as libc::c_uint
                == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
            {
            generic = 0 as libc::c_int;
            sep = b"/\0" as *const u8 as *const libc::c_char;
            name = (*cur).name as *const libc::c_char;
            if !((*cur).ns).is_null() {
                if !((*(*cur).ns).prefix).is_null() {
                    snprintf(
                        nametemp.as_mut_ptr(),
                        (::std::mem::size_of::<[libc::c_char; 100]>() as libc::c_ulong)
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                        b"%s:%s\0" as *const u8 as *const libc::c_char,
                        (*(*cur).ns).prefix as *mut libc::c_char,
                        (*cur).name as *mut libc::c_char,
                    );
                    nametemp[(::std::mem::size_of::<[libc::c_char; 100]>()
                        as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                        as usize] = 0 as libc::c_int as libc::c_char;
                    name = nametemp.as_mut_ptr();
                } else {
                    generic = 1 as libc::c_int;
                    name = b"*\0" as *const u8 as *const libc::c_char;
                }
            }
            next = (*cur).parent;
            tmp = (*cur).prev;
            while !tmp.is_null() {
                if (*tmp).type_0 as libc::c_uint
                    == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                    && (generic != 0
                        || xmlStrEqual((*cur).name, (*tmp).name) != 0
                            && ((*tmp).ns == (*cur).ns
                                || !((*tmp).ns).is_null() && !((*cur).ns).is_null()
                                    && xmlStrEqual((*(*cur).ns).prefix, (*(*tmp).ns).prefix)
                                        != 0))
                {
                    occur += 1;
                }
                tmp = (*tmp).prev;
            }
            if occur == 0 as libc::c_int {
                tmp = (*cur).next;
                while !tmp.is_null() && occur == 0 as libc::c_int {
                    if (*tmp).type_0 as libc::c_uint
                        == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                        && (generic != 0
                            || xmlStrEqual((*cur).name, (*tmp).name) != 0
                                && ((*tmp).ns == (*cur).ns
                                    || !((*tmp).ns).is_null() && !((*cur).ns).is_null()
                                        && xmlStrEqual((*(*cur).ns).prefix, (*(*tmp).ns).prefix)
                                            != 0))
                    {
                        occur += 1;
                    }
                    tmp = (*tmp).next;
                }
                if occur != 0 as libc::c_int {
                    occur = 1 as libc::c_int;
                }
            } else {
                occur += 1;
            }
        } else if (*cur).type_0 as libc::c_uint
                == XML_COMMENT_NODE as libc::c_int as libc::c_uint
            {
            sep = b"/\0" as *const u8 as *const libc::c_char;
            name = b"comment()\0" as *const u8 as *const libc::c_char;
            next = (*cur).parent;
            tmp = (*cur).prev;
            while !tmp.is_null() {
                if (*tmp).type_0 as libc::c_uint
                    == XML_COMMENT_NODE as libc::c_int as libc::c_uint
                {
                    occur += 1;
                }
                tmp = (*tmp).prev;
            }
            if occur == 0 as libc::c_int {
                tmp = (*cur).next;
                while !tmp.is_null() && occur == 0 as libc::c_int {
                    if (*tmp).type_0 as libc::c_uint
                        == XML_COMMENT_NODE as libc::c_int as libc::c_uint
                    {
                        occur += 1;
                    }
                    tmp = (*tmp).next;
                }
                if occur != 0 as libc::c_int {
                    occur = 1 as libc::c_int;
                }
            } else {
                occur += 1;
            }
        } else if (*cur).type_0 as libc::c_uint
                == XML_TEXT_NODE as libc::c_int as libc::c_uint
                || (*cur).type_0 as libc::c_uint
                    == XML_CDATA_SECTION_NODE as libc::c_int as libc::c_uint
            {
            sep = b"/\0" as *const u8 as *const libc::c_char;
            name = b"text()\0" as *const u8 as *const libc::c_char;
            next = (*cur).parent;
            tmp = (*cur).prev;
            while !tmp.is_null() {
                if (*tmp).type_0 as libc::c_uint
                    == XML_TEXT_NODE as libc::c_int as libc::c_uint
                    || (*tmp).type_0 as libc::c_uint
                        == XML_CDATA_SECTION_NODE as libc::c_int as libc::c_uint
                {
                    occur += 1;
                }
                tmp = (*tmp).prev;
            }
            if occur == 0 as libc::c_int {
                tmp = (*cur).next;
                while !tmp.is_null() {
                    if (*tmp).type_0 as libc::c_uint
                        == XML_TEXT_NODE as libc::c_int as libc::c_uint
                        || (*tmp).type_0 as libc::c_uint
                            == XML_CDATA_SECTION_NODE as libc::c_int as libc::c_uint
                    {
                        occur = 1 as libc::c_int;
                        break;
                    } else {
                        tmp = (*tmp).next;
                    }
                }
            } else {
                occur += 1;
            }
        } else if (*cur).type_0 as libc::c_uint
                == XML_PI_NODE as libc::c_int as libc::c_uint
            {
            sep = b"/\0" as *const u8 as *const libc::c_char;
            snprintf(
                nametemp.as_mut_ptr(),
                (::std::mem::size_of::<[libc::c_char; 100]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                b"processing-instruction('%s')\0" as *const u8 as *const libc::c_char,
                (*cur).name as *mut libc::c_char,
            );
            nametemp[(::std::mem::size_of::<[libc::c_char; 100]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                as usize] = 0 as libc::c_int as libc::c_char;
            name = nametemp.as_mut_ptr();
            next = (*cur).parent;
            tmp = (*cur).prev;
            while !tmp.is_null() {
                if (*tmp).type_0 as libc::c_uint
                    == XML_PI_NODE as libc::c_int as libc::c_uint
                    && xmlStrEqual((*cur).name, (*tmp).name) != 0
                {
                    occur += 1;
                }
                tmp = (*tmp).prev;
            }
            if occur == 0 as libc::c_int {
                tmp = (*cur).next;
                while !tmp.is_null() && occur == 0 as libc::c_int {
                    if (*tmp).type_0 as libc::c_uint
                        == XML_PI_NODE as libc::c_int as libc::c_uint
                        && xmlStrEqual((*cur).name, (*tmp).name) != 0
                    {
                        occur += 1;
                    }
                    tmp = (*tmp).next;
                }
                if occur != 0 as libc::c_int {
                    occur = 1 as libc::c_int;
                }
            } else {
                occur += 1;
            }
        } else if (*cur).type_0 as libc::c_uint
                == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
            {
            sep = b"/@\0" as *const u8 as *const libc::c_char;
            name = (*(cur as xmlAttrPtr)).name as *const libc::c_char;
            if !((*cur).ns).is_null() {
                if !((*(*cur).ns).prefix).is_null() {
                    snprintf(
                        nametemp.as_mut_ptr(),
                        (::std::mem::size_of::<[libc::c_char; 100]>() as libc::c_ulong)
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                        b"%s:%s\0" as *const u8 as *const libc::c_char,
                        (*(*cur).ns).prefix as *mut libc::c_char,
                        (*cur).name as *mut libc::c_char,
                    );
                } else {
                    snprintf(
                        nametemp.as_mut_ptr(),
                        (::std::mem::size_of::<[libc::c_char; 100]>() as libc::c_ulong)
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                        b"%s\0" as *const u8 as *const libc::c_char,
                        (*cur).name as *mut libc::c_char,
                    );
                }
                nametemp[(::std::mem::size_of::<[libc::c_char; 100]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    as usize] = 0 as libc::c_int as libc::c_char;
                name = nametemp.as_mut_ptr();
            }
            next = (*(cur as xmlAttrPtr)).parent;
        } else {
            xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
            xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void);
            return 0 as *mut xmlChar;
        }
        if (xmlStrlen(buffer) as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<[libc::c_char; 100]>() as libc::c_ulong)
            .wrapping_add(20 as libc::c_int as libc::c_ulong) > buf_len
        {
            buf_len = (2 as libc::c_int as libc::c_ulong)
                .wrapping_mul(buf_len)
                .wrapping_add(xmlStrlen(buffer) as libc::c_ulong)
                .wrapping_add(
                    ::std::mem::size_of::<[libc::c_char; 100]>() as libc::c_ulong,
                )
                .wrapping_add(20 as libc::c_int as libc::c_ulong);
            temp = xmlRealloc
                .expect(
                    "non-null function pointer",
                )(buffer as *mut libc::c_void, buf_len) as *mut xmlChar;
            if temp.is_null() {
                xmlTreeErrMemory(
                    b"getting node path\0" as *const u8 as *const libc::c_char,
                );
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void);
                return 0 as *mut xmlChar;
            }
            buffer = temp;
            temp = xmlRealloc
                .expect("non-null function pointer")(buf as *mut libc::c_void, buf_len)
                as *mut xmlChar;
            if temp.is_null() {
                xmlTreeErrMemory(
                    b"getting node path\0" as *const u8 as *const libc::c_char,
                );
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void);
                return 0 as *mut xmlChar;
            }
            buf = temp;
        }
        if occur == 0 as libc::c_int {
            snprintf(
                buf as *mut libc::c_char,
                buf_len,
                b"%s%s%s\0" as *const u8 as *const libc::c_char,
                sep,
                name,
                buffer as *mut libc::c_char,
            );
        } else {
            snprintf(
                buf as *mut libc::c_char,
                buf_len,
                b"%s%s[%d]%s\0" as *const u8 as *const libc::c_char,
                sep,
                name,
                occur,
                buffer as *mut libc::c_char,
            );
        }
        snprintf(
            buffer as *mut libc::c_char,
            buf_len,
            b"%s\0" as *const u8 as *const libc::c_char,
            buf as *mut libc::c_char,
        );
        cur = next;
        if cur.is_null() {
            break;
        }
    }
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return buffer;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDocGetRootElement(mut doc: *const xmlDoc) -> xmlNodePtr {
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    if doc.is_null() {
        return 0 as xmlNodePtr;
    }
    ret = (*doc).children;
    while !ret.is_null() {
        if (*ret).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            return ret;
        }
        ret = (*ret).next;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDocSetRootElement(
    mut doc: xmlDocPtr,
    mut root: xmlNodePtr,
) -> xmlNodePtr {
    let mut old: xmlNodePtr = 0 as xmlNodePtr;
    if doc.is_null() {
        return 0 as xmlNodePtr;
    }
    if root.is_null()
        || (*root).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNodePtr;
    }
    xmlUnlinkNode(root);
    xmlSetTreeDoc(root, doc);
    let ref mut fresh262 = (*root).parent;
    *fresh262 = doc as xmlNodePtr;
    old = (*doc).children;
    while !old.is_null() {
        if (*old).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            break;
        }
        old = (*old).next;
    }
    if old.is_null() {
        if ((*doc).children).is_null() {
            let ref mut fresh263 = (*doc).children;
            *fresh263 = root;
            let ref mut fresh264 = (*doc).last;
            *fresh264 = root;
        } else {
            xmlAddSibling((*doc).children, root);
        }
    } else {
        xmlReplaceNode(old, root);
    }
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeSetLang(mut cur: xmlNodePtr, mut lang: *const xmlChar) {
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    if cur.is_null() {
        return;
    }
    match (*cur).type_0 as libc::c_uint {
        3 | 4 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 7 | 5 | 6 | 18 | 19
        | 20 => return,
        1 | 2 | _ => {}
    }
    ns = xmlSearchNsByHref(
        (*cur).doc,
        cur,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
            as *const xmlChar,
    );
    if ns.is_null() {
        return;
    }
    xmlSetNsProp(
        cur,
        ns,
        b"lang\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        lang,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeGetLang(mut cur: *const xmlNode) -> *mut xmlChar {
    let mut lang: *mut xmlChar = 0 as *mut xmlChar;
    if cur.is_null()
        || (*cur).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as *mut xmlChar;
    }
    while !cur.is_null() {
        lang = xmlGetNsProp(
            cur,
            b"lang\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
                as *const xmlChar,
        );
        if !lang.is_null() {
            return lang;
        }
        cur = (*cur).parent;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeSetSpacePreserve(
    mut cur: xmlNodePtr,
    mut val: libc::c_int,
) {
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    if cur.is_null() {
        return;
    }
    match (*cur).type_0 as libc::c_uint {
        3 | 4 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 7 | 5 | 6 | 18 | 19
        | 20 => return,
        1 | 2 | _ => {}
    }
    ns = xmlSearchNsByHref(
        (*cur).doc,
        cur,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
            as *const xmlChar,
    );
    if ns.is_null() {
        return;
    }
    match val {
        0 => {
            xmlSetNsProp(
                cur,
                ns,
                b"space\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                b"default\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
        }
        1 => {
            xmlSetNsProp(
                cur,
                ns,
                b"space\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                b"preserve\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
        }
        _ => {}
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeGetSpacePreserve(
    mut cur: *const xmlNode,
) -> libc::c_int {
    let mut space: *mut xmlChar = 0 as *mut xmlChar;
    if cur.is_null()
        || (*cur).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    while !cur.is_null() {
        space = xmlGetNsProp(
            cur,
            b"space\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
                as *const xmlChar,
        );
        if !space.is_null() {
            if xmlStrEqual(
                space,
                b"preserve\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            {
                xmlFree.expect("non-null function pointer")(space as *mut libc::c_void);
                return 1 as libc::c_int;
            }
            if xmlStrEqual(
                space,
                b"default\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            {
                xmlFree.expect("non-null function pointer")(space as *mut libc::c_void);
                return 0 as libc::c_int;
            }
            xmlFree.expect("non-null function pointer")(space as *mut libc::c_void);
        }
        cur = (*cur).parent;
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeSetName(mut cur: xmlNodePtr, mut name: *const xmlChar) {
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut dict: xmlDictPtr = 0 as *mut xmlDict;
    let mut freeme: *const xmlChar = 0 as *const xmlChar;
    if cur.is_null() {
        return;
    }
    if name.is_null() {
        return;
    }
    match (*cur).type_0 as libc::c_uint {
        3 | 4 | 8 | 10 | 11 | 12 | 13 | 18 | 19 | 20 => return,
        1 | 2 | 7 | 5 | 6 | 14 | 9 | 15 | 16 | 17 | _ => {}
    }
    doc = (*cur).doc;
    if !doc.is_null() {
        dict = (*doc).dict;
    } else {
        dict = 0 as xmlDictPtr;
    }
    if !dict.is_null() {
        if !((*cur).name).is_null() && xmlDictOwns(dict, (*cur).name) == 0 {
            freeme = (*cur).name;
        }
        let ref mut fresh265 = (*cur).name;
        *fresh265 = xmlDictLookup(dict, name, -(1 as libc::c_int));
    } else {
        if !((*cur).name).is_null() {
            freeme = (*cur).name;
        }
        let ref mut fresh266 = (*cur).name;
        *fresh266 = xmlStrdup(name);
    }
    if !freeme.is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )(freeme as *mut xmlChar as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeSetBase(mut cur: xmlNodePtr, mut uri: *const xmlChar) {
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut fixed: *mut xmlChar = 0 as *mut xmlChar;
    if cur.is_null() {
        return;
    }
    match (*cur).type_0 as libc::c_uint {
        3 | 4 | 8 | 10 | 11 | 12 | 14 | 15 | 16 | 17 | 7 | 5 | 6 | 18 | 19 | 20 => return,
        9 | 13 => {
            let mut doc: xmlDocPtr = cur as xmlDocPtr;
            if !((*doc).URL).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*doc).URL as *mut xmlChar as *mut libc::c_void);
            }
            if uri.is_null() {
                let ref mut fresh267 = (*doc).URL;
                *fresh267 = 0 as *const xmlChar;
            } else {
                let ref mut fresh268 = (*doc).URL;
                *fresh268 = xmlPathToURI(uri);
            }
            return;
        }
        1 | 2 | _ => {}
    }
    ns = xmlSearchNsByHref(
        (*cur).doc,
        cur,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
            as *const xmlChar,
    );
    if ns.is_null() {
        return;
    }
    fixed = xmlPathToURI(uri);
    if !fixed.is_null() {
        xmlSetNsProp(
            cur,
            ns,
            b"base\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            fixed,
        );
        xmlFree.expect("non-null function pointer")(fixed as *mut libc::c_void);
    } else {
        xmlSetNsProp(
            cur,
            ns,
            b"base\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            uri,
        );
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeGetBase(
    mut doc: *const xmlDoc,
    mut cur: *const xmlNode,
) -> *mut xmlChar {
    let mut oldbase: *mut xmlChar = 0 as *mut xmlChar;
    let mut base: *mut xmlChar = 0 as *mut xmlChar;
    let mut newbase: *mut xmlChar = 0 as *mut xmlChar;
    if cur.is_null() && doc.is_null() {
        return 0 as *mut xmlChar;
    }
    if !cur.is_null()
        && (*cur).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as *mut xmlChar;
    }
    if doc.is_null() {
        doc = (*cur).doc;
    }
    if !doc.is_null()
        && (*doc).type_0 as libc::c_uint
            == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
    {
        cur = (*doc).children;
        while !cur.is_null() && !((*cur).name).is_null() {
            if (*cur).type_0 as libc::c_uint
                != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
            {
                cur = (*cur).next;
            } else if xmlStrcasecmp(
                    (*cur).name,
                    b"html\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) == 0
                {
                cur = (*cur).children;
            } else if xmlStrcasecmp(
                    (*cur).name,
                    b"head\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) == 0
                {
                cur = (*cur).children;
            } else {
                if xmlStrcasecmp(
                    (*cur).name,
                    b"base\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) == 0
                {
                    return xmlGetProp(
                        cur,
                        b"href\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    );
                }
                cur = (*cur).next;
            }
        }
        return 0 as *mut xmlChar;
    }
    while !cur.is_null() {
        if (*cur).type_0 as libc::c_uint
            == XML_ENTITY_DECL as libc::c_int as libc::c_uint
        {
            let mut ent: xmlEntityPtr = cur as xmlEntityPtr;
            return xmlStrdup((*ent).URI);
        }
        if (*cur).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            base = xmlGetNsProp(
                cur,
                b"base\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                    as *const libc::c_char as *const xmlChar,
            );
            if !base.is_null() {
                if !oldbase.is_null() {
                    newbase = xmlBuildURI(oldbase, base);
                    if !newbase.is_null() {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(oldbase as *mut libc::c_void);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(base as *mut libc::c_void);
                        oldbase = newbase;
                    } else {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(oldbase as *mut libc::c_void);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(base as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                } else {
                    oldbase = base;
                }
                if xmlStrncmp(
                    oldbase,
                    b"http://\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    7 as libc::c_int,
                ) == 0
                    || xmlStrncmp(
                        oldbase,
                        b"ftp://\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                        6 as libc::c_int,
                    ) == 0
                    || xmlStrncmp(
                        oldbase,
                        b"urn:\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                        4 as libc::c_int,
                    ) == 0
                {
                    return oldbase;
                }
            }
        }
        cur = (*cur).parent;
    }
    if !doc.is_null() && !((*doc).URL).is_null() {
        if oldbase.is_null() {
            return xmlStrdup((*doc).URL);
        }
        newbase = xmlBuildURI(oldbase, (*doc).URL);
        xmlFree.expect("non-null function pointer")(oldbase as *mut libc::c_void);
        return newbase;
    }
    return oldbase;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeBufGetContent(
    mut buffer: xmlBufferPtr,
    mut cur: *const xmlNode,
) -> libc::c_int {
    let mut buf: xmlBufPtr = 0 as *mut xmlBuf;
    let mut ret: libc::c_int = 0;
    if cur.is_null() || buffer.is_null() {
        return -(1 as libc::c_int);
    }
    buf = xmlBufFromBuffer(buffer);
    ret = xmlBufGetNodeContent(buf, cur);
    buffer = xmlBufBackToBuffer(buf);
    if ret < 0 as libc::c_int || buffer.is_null() {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufGetNodeContent(
    mut buf: xmlBufPtr,
    mut cur: *const xmlNode,
) -> libc::c_int {
    if cur.is_null() || buf.is_null() {
        return -(1 as libc::c_int);
    }
    match (*cur).type_0 as libc::c_uint {
        4 | 3 => {
            xmlBufCat(buf, (*cur).content);
        }
        11 | 1 => {
            let mut tmp: *const xmlNode = cur;
            while !tmp.is_null() {
                match (*tmp).type_0 as libc::c_uint {
                    4 | 3 => {
                        if !((*tmp).content).is_null() {
                            xmlBufCat(buf, (*tmp).content);
                        }
                    }
                    5 => {
                        xmlBufGetNodeContent(buf, tmp);
                    }
                    _ => {}
                }
                if !((*tmp).children).is_null() {
                    if (*(*tmp).children).type_0 as libc::c_uint
                        != XML_ENTITY_DECL as libc::c_int as libc::c_uint
                    {
                        tmp = (*tmp).children;
                        continue;
                    }
                }
                if tmp == cur {
                    break;
                }
                if !((*tmp).next).is_null() {
                    tmp = (*tmp).next;
                } else {
                    loop {
                        tmp = (*tmp).parent;
                        if tmp.is_null() {
                            break;
                        }
                        if tmp == cur {
                            tmp = 0 as *const xmlNode;
                            break;
                        } else if !((*tmp).next).is_null() {
                            tmp = (*tmp).next;
                            break;
                        } else if tmp.is_null() {
                            break;
                        }
                    }
                }
            }
        }
        2 => {
            let mut attr: xmlAttrPtr = cur as xmlAttrPtr;
            let mut tmp_0: xmlNodePtr = (*attr).children;
            while !tmp_0.is_null() {
                if (*tmp_0).type_0 as libc::c_uint
                    == XML_TEXT_NODE as libc::c_int as libc::c_uint
                {
                    xmlBufCat(buf, (*tmp_0).content);
                } else {
                    xmlBufGetNodeContent(buf, tmp_0 as *const xmlNode);
                }
                tmp_0 = (*tmp_0).next;
            }
        }
        8 | 7 => {
            xmlBufCat(buf, (*cur).content);
        }
        5 => {
            let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
            let mut tmp_1: xmlNodePtr = 0 as *mut xmlNode;
            ent = xmlGetDocEntity((*cur).doc, (*cur).name);
            if ent.is_null() {
                return -(1 as libc::c_int);
            }
            tmp_1 = (*ent).children;
            while !tmp_1.is_null() {
                xmlBufGetNodeContent(buf, tmp_1 as *const xmlNode);
                tmp_1 = (*tmp_1).next;
            }
        }
        9 | 13 => {
            cur = (*cur).children;
            while !cur.is_null() {
                if (*cur).type_0 as libc::c_uint
                    == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                    || (*cur).type_0 as libc::c_uint
                        == XML_TEXT_NODE as libc::c_int as libc::c_uint
                    || (*cur).type_0 as libc::c_uint
                        == XML_CDATA_SECTION_NODE as libc::c_int as libc::c_uint
                {
                    xmlBufGetNodeContent(buf, cur);
                }
                cur = (*cur).next;
            }
        }
        18 => {
            xmlBufCat(buf, (*(cur as xmlNsPtr)).href);
        }
        6 | 10 | 12 | 14 | 19 | 20 | 15 | 16 | 17 | _ => {}
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeGetContent(mut cur: *const xmlNode) -> *mut xmlChar {
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    match (*cur).type_0 as libc::c_uint {
        11 | 1 => {
            let mut buf: xmlBufPtr = 0 as *mut xmlBuf;
            let mut ret: *mut xmlChar = 0 as *mut xmlChar;
            buf = xmlBufCreateSize(64 as libc::c_int as size_t);
            if buf.is_null() {
                return 0 as *mut xmlChar;
            }
            xmlBufSetAllocationScheme(buf, XML_BUFFER_ALLOC_DOUBLEIT);
            xmlBufGetNodeContent(buf, cur);
            ret = xmlBufDetach(buf);
            xmlBufFree(buf);
            return ret;
        }
        2 => return xmlGetPropNodeValueInternal(cur as xmlAttrPtr as *const xmlAttr),
        8 | 7 => {
            if !((*cur).content).is_null() {
                return xmlStrdup((*cur).content);
            }
            return 0 as *mut xmlChar;
        }
        5 => {
            let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
            let mut buf_0: xmlBufPtr = 0 as *mut xmlBuf;
            let mut ret_0: *mut xmlChar = 0 as *mut xmlChar;
            ent = xmlGetDocEntity((*cur).doc, (*cur).name);
            if ent.is_null() {
                return 0 as *mut xmlChar;
            }
            buf_0 = xmlBufCreate();
            if buf_0.is_null() {
                return 0 as *mut xmlChar;
            }
            xmlBufSetAllocationScheme(buf_0, XML_BUFFER_ALLOC_DOUBLEIT);
            xmlBufGetNodeContent(buf_0, cur);
            ret_0 = xmlBufDetach(buf_0);
            xmlBufFree(buf_0);
            return ret_0;
        }
        6 | 10 | 12 | 14 | 19 | 20 => return 0 as *mut xmlChar,
        9 | 13 => {
            let mut buf_1: xmlBufPtr = 0 as *mut xmlBuf;
            let mut ret_1: *mut xmlChar = 0 as *mut xmlChar;
            buf_1 = xmlBufCreate();
            if buf_1.is_null() {
                return 0 as *mut xmlChar;
            }
            xmlBufSetAllocationScheme(buf_1, XML_BUFFER_ALLOC_DOUBLEIT);
            xmlBufGetNodeContent(buf_1, cur as xmlNodePtr as *const xmlNode);
            ret_1 = xmlBufDetach(buf_1);
            xmlBufFree(buf_1);
            return ret_1;
        }
        18 => {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            tmp = xmlStrdup((*(cur as xmlNsPtr)).href);
            return tmp;
        }
        15 => return 0 as *mut xmlChar,
        16 => return 0 as *mut xmlChar,
        17 => return 0 as *mut xmlChar,
        4 | 3 => {
            if !((*cur).content).is_null() {
                return xmlStrdup((*cur).content);
            }
            return 0 as *mut xmlChar;
        }
        _ => {}
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeSetContent(
    mut cur: xmlNodePtr,
    mut content: *const xmlChar,
) {
    if cur.is_null() {
        return;
    }
    match (*cur).type_0 as libc::c_uint {
        11 | 1 | 2 => {
            if !((*cur).children).is_null() {
                xmlFreeNodeList((*cur).children);
            }
            let ref mut fresh269 = (*cur).children;
            *fresh269 = xmlStringGetNodeList((*cur).doc, content);
            if !cur.is_null() {
                let mut ulccur: xmlNodePtr = (*cur).children;
                if ulccur.is_null() {
                    let ref mut fresh270 = (*cur).last;
                    *fresh270 = 0 as *mut _xmlNode;
                } else {
                    while !((*ulccur).next).is_null() {
                        let ref mut fresh271 = (*ulccur).parent;
                        *fresh271 = cur;
                        ulccur = (*ulccur).next;
                    }
                    let ref mut fresh272 = (*ulccur).parent;
                    *fresh272 = cur;
                    let ref mut fresh273 = (*cur).last;
                    *fresh273 = ulccur;
                }
            }
        }
        3 | 4 | 5 | 6 | 7 | 8 => {
            if !((*cur).content).is_null()
                && (*cur).content
                    != &mut (*cur).properties as *mut *mut _xmlAttr as *mut xmlChar
            {
                if !(!((*cur).doc).is_null() && !((*(*cur).doc).dict).is_null()
                    && xmlDictOwns((*(*cur).doc).dict, (*cur).content) != 0)
                {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )((*cur).content as *mut libc::c_void);
                }
            }
            if !((*cur).children).is_null() {
                xmlFreeNodeList((*cur).children);
            }
            let ref mut fresh274 = (*cur).children;
            *fresh274 = 0 as *mut _xmlNode;
            let ref mut fresh275 = (*cur).last;
            *fresh275 = *fresh274;
            if !content.is_null() {
                let ref mut fresh276 = (*cur).content;
                *fresh276 = xmlStrdup(content);
            } else {
                let ref mut fresh277 = (*cur).content;
                *fresh277 = 0 as *mut xmlChar;
            }
            let ref mut fresh278 = (*cur).properties;
            *fresh278 = 0 as *mut _xmlAttr;
        }
        15 => {}
        17 => {}
        9 | 13 | 10 | 19 | 20 | 12 | 14 | 18 | 16 | _ => {}
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeSetContentLen(
    mut cur: xmlNodePtr,
    mut content: *const xmlChar,
    mut len: libc::c_int,
) {
    if cur.is_null() {
        return;
    }
    match (*cur).type_0 as libc::c_uint {
        11 | 1 | 2 => {
            if !((*cur).children).is_null() {
                xmlFreeNodeList((*cur).children);
            }
            let ref mut fresh279 = (*cur).children;
            *fresh279 = xmlStringLenGetNodeList((*cur).doc, content, len);
            if !cur.is_null() {
                let mut ulccur: xmlNodePtr = (*cur).children;
                if ulccur.is_null() {
                    let ref mut fresh280 = (*cur).last;
                    *fresh280 = 0 as *mut _xmlNode;
                } else {
                    while !((*ulccur).next).is_null() {
                        let ref mut fresh281 = (*ulccur).parent;
                        *fresh281 = cur;
                        ulccur = (*ulccur).next;
                    }
                    let ref mut fresh282 = (*ulccur).parent;
                    *fresh282 = cur;
                    let ref mut fresh283 = (*cur).last;
                    *fresh283 = ulccur;
                }
            }
        }
        3 | 4 | 5 | 6 | 7 | 8 | 12 => {
            if !((*cur).content).is_null()
                && (*cur).content
                    != &mut (*cur).properties as *mut *mut _xmlAttr as *mut xmlChar
            {
                if !(!((*cur).doc).is_null() && !((*(*cur).doc).dict).is_null()
                    && xmlDictOwns((*(*cur).doc).dict, (*cur).content) != 0)
                {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )((*cur).content as *mut libc::c_void);
                }
            }
            if !((*cur).children).is_null() {
                xmlFreeNodeList((*cur).children);
            }
            let ref mut fresh284 = (*cur).last;
            *fresh284 = 0 as *mut _xmlNode;
            let ref mut fresh285 = (*cur).children;
            *fresh285 = *fresh284;
            if !content.is_null() {
                let ref mut fresh286 = (*cur).content;
                *fresh286 = xmlStrndup(content, len);
            } else {
                let ref mut fresh287 = (*cur).content;
                *fresh287 = 0 as *mut xmlChar;
            }
            let ref mut fresh288 = (*cur).properties;
            *fresh288 = 0 as *mut _xmlAttr;
        }
        15 => {}
        17 => {}
        9 | 14 | 13 | 10 | 18 | 19 | 20 | 16 | _ => {}
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeAddContentLen(
    mut cur: xmlNodePtr,
    mut content: *const xmlChar,
    mut len: libc::c_int,
) {
    if cur.is_null() {
        return;
    }
    if len <= 0 as libc::c_int {
        return;
    }
    match (*cur).type_0 as libc::c_uint {
        11 | 1 => {
            let mut last: xmlNodePtr = 0 as *mut xmlNode;
            let mut newNode: xmlNodePtr = 0 as *mut xmlNode;
            let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
            last = (*cur).last;
            newNode = xmlNewDocTextLen((*cur).doc, content, len);
            if !newNode.is_null() {
                tmp = xmlAddChild(cur, newNode);
                if tmp != newNode {
                    return;
                }
                if !last.is_null() && (*last).next == newNode {
                    xmlTextMerge(last, newNode);
                }
            }
        }
        3 | 4 | 5 | 6 | 7 | 8 | 12 => {
            if !content.is_null() {
                if (*cur).content
                    == &mut (*cur).properties as *mut *mut _xmlAttr as *mut xmlChar
                    || !((*cur).doc).is_null() && !((*(*cur).doc).dict).is_null()
                        && xmlDictOwns((*(*cur).doc).dict, (*cur).content) != 0
                {
                    let ref mut fresh289 = (*cur).content;
                    *fresh289 = xmlStrncatNew((*cur).content, content, len);
                    let ref mut fresh290 = (*cur).properties;
                    *fresh290 = 0 as *mut _xmlAttr;
                } else {
                    let ref mut fresh291 = (*cur).content;
                    *fresh291 = xmlStrncat((*cur).content, content, len);
                }
            }
        }
        2 | 9 | 14 | 13 | 10 | 18 | 19 | 20 | 15 | 16 | 17 | _ => {}
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeAddContent(
    mut cur: xmlNodePtr,
    mut content: *const xmlChar,
) {
    let mut len: libc::c_int = 0;
    if cur.is_null() {
        return;
    }
    if content.is_null() {
        return;
    }
    len = xmlStrlen(content);
    xmlNodeAddContentLen(cur, content, len);
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextMerge(
    mut first: xmlNodePtr,
    mut second: xmlNodePtr,
) -> xmlNodePtr {
    if first.is_null() {
        return second;
    }
    if second.is_null() {
        return first;
    }
    if (*first).type_0 as libc::c_uint != XML_TEXT_NODE as libc::c_int as libc::c_uint {
        return first;
    }
    if (*second).type_0 as libc::c_uint != XML_TEXT_NODE as libc::c_int as libc::c_uint {
        return first;
    }
    if (*second).name != (*first).name {
        return first;
    }
    xmlNodeAddContent(first, (*second).content);
    xmlUnlinkNode(second);
    xmlFreeNode(second);
    return first;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetNsList(
    mut doc: *const xmlDoc,
    mut node: *const xmlNode,
) -> *mut xmlNsPtr {
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    let mut ret: *mut xmlNsPtr = 0 as *mut xmlNsPtr;
    let mut nbns: libc::c_int = 0 as libc::c_int;
    let mut maxns: libc::c_int = 10 as libc::c_int;
    let mut i: libc::c_int = 0;
    if node.is_null()
        || (*node).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as *mut xmlNsPtr;
    }
    while !node.is_null() {
        if (*node).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            cur = (*node).nsDef;
            while !cur.is_null() {
                if ret.is_null() {
                    ret = xmlMalloc
                        .expect(
                            "non-null function pointer",
                        )(
                        ((maxns + 1 as libc::c_int) as libc::c_ulong)
                            .wrapping_mul(
                                ::std::mem::size_of::<xmlNsPtr>() as libc::c_ulong,
                            ),
                    ) as *mut xmlNsPtr;
                    if ret.is_null() {
                        xmlTreeErrMemory(
                            b"getting namespace list\0" as *const u8
                                as *const libc::c_char,
                        );
                        return 0 as *mut xmlNsPtr;
                    }
                    let ref mut fresh292 = *ret.offset(nbns as isize);
                    *fresh292 = 0 as xmlNsPtr;
                }
                i = 0 as libc::c_int;
                while i < nbns {
                    if (*cur).prefix == (**ret.offset(i as isize)).prefix
                        || xmlStrEqual((*cur).prefix, (**ret.offset(i as isize)).prefix)
                            != 0
                    {
                        break;
                    }
                    i += 1;
                }
                if i >= nbns {
                    if nbns >= maxns {
                        maxns *= 2 as libc::c_int;
                        ret = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(
                            ret as *mut libc::c_void,
                            ((maxns + 1 as libc::c_int) as libc::c_ulong)
                                .wrapping_mul(
                                    ::std::mem::size_of::<xmlNsPtr>() as libc::c_ulong,
                                ),
                        ) as *mut xmlNsPtr;
                        if ret.is_null() {
                            xmlTreeErrMemory(
                                b"getting namespace list\0" as *const u8
                                    as *const libc::c_char,
                            );
                            return 0 as *mut xmlNsPtr;
                        }
                    }
                    let fresh293 = nbns;
                    nbns = nbns + 1;
                    let ref mut fresh294 = *ret.offset(fresh293 as isize);
                    *fresh294 = cur;
                    let ref mut fresh295 = *ret.offset(nbns as isize);
                    *fresh295 = 0 as xmlNsPtr;
                }
                cur = (*cur).next;
            }
        }
        node = (*node).parent;
    }
    return ret;
}
unsafe extern "C" fn xmlTreeEnsureXMLDecl(mut doc: xmlDocPtr) -> xmlNsPtr {
    if doc.is_null() {
        return 0 as xmlNsPtr;
    }
    if !((*doc).oldNs).is_null() {
        return (*doc).oldNs;
    }
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    ns = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNs>() as libc::c_ulong) as xmlNsPtr;
    if ns.is_null() {
        xmlTreeErrMemory(
            b"allocating the XML namespace\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlNsPtr;
    }
    memset(
        ns as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNs>() as libc::c_ulong,
    );
    (*ns).type_0 = XML_NAMESPACE_DECL;
    let ref mut fresh296 = (*ns).href;
    *fresh296 = xmlStrdup(
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
            as *const xmlChar,
    );
    let ref mut fresh297 = (*ns).prefix;
    *fresh297 = xmlStrdup(
        b"xml\0" as *const u8 as *const libc::c_char as *const xmlChar,
    );
    let ref mut fresh298 = (*doc).oldNs;
    *fresh298 = ns;
    return ns;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSearchNs(
    mut doc: xmlDocPtr,
    mut node: xmlNodePtr,
    mut nameSpace: *const xmlChar,
) -> xmlNsPtr {
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    let mut orig: *const xmlNode = node as *const xmlNode;
    if node.is_null()
        || (*node).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNsPtr;
    }
    if !nameSpace.is_null()
        && xmlStrEqual(
            nameSpace,
            b"xml\0" as *const u8 as *const libc::c_char as *const xmlChar,
        ) != 0
    {
        if doc.is_null()
            && (*node).type_0 as libc::c_uint
                == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            cur = xmlMalloc
                .expect(
                    "non-null function pointer",
                )(::std::mem::size_of::<xmlNs>() as libc::c_ulong) as xmlNsPtr;
            if cur.is_null() {
                xmlTreeErrMemory(
                    b"searching namespace\0" as *const u8 as *const libc::c_char,
                );
                return 0 as xmlNsPtr;
            }
            memset(
                cur as *mut libc::c_void,
                0 as libc::c_int,
                ::std::mem::size_of::<xmlNs>() as libc::c_ulong,
            );
            (*cur).type_0 = XML_NAMESPACE_DECL;
            let ref mut fresh299 = (*cur).href;
            *fresh299 = xmlStrdup(
                b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                    as *const libc::c_char as *const xmlChar,
            );
            let ref mut fresh300 = (*cur).prefix;
            *fresh300 = xmlStrdup(
                b"xml\0" as *const u8 as *const libc::c_char as *const xmlChar,
            );
            let ref mut fresh301 = (*cur).next;
            *fresh301 = (*node).nsDef;
            let ref mut fresh302 = (*node).nsDef;
            *fresh302 = cur;
            return cur;
        }
        if doc.is_null() {
            doc = (*node).doc;
            if doc.is_null() {
                return 0 as xmlNsPtr;
            }
        }
        if ((*doc).oldNs).is_null() {
            return xmlTreeEnsureXMLDecl(doc)
        } else {
            return (*doc).oldNs
        }
    }
    while !node.is_null() {
        if (*node).type_0 as libc::c_uint
            == XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
            || (*node).type_0 as libc::c_uint
                == XML_ENTITY_NODE as libc::c_int as libc::c_uint
            || (*node).type_0 as libc::c_uint
                == XML_ENTITY_DECL as libc::c_int as libc::c_uint
        {
            return 0 as xmlNsPtr;
        }
        if (*node).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            cur = (*node).nsDef;
            while !cur.is_null() {
                if ((*cur).prefix).is_null() && nameSpace.is_null()
                    && !((*cur).href).is_null()
                {
                    return cur;
                }
                if !((*cur).prefix).is_null() && !nameSpace.is_null()
                    && !((*cur).href).is_null()
                    && xmlStrEqual((*cur).prefix, nameSpace) != 0
                {
                    return cur;
                }
                cur = (*cur).next;
            }
            if orig != node as *const xmlNode {
                cur = (*node).ns;
                if !cur.is_null() {
                    if ((*cur).prefix).is_null() && nameSpace.is_null()
                        && !((*cur).href).is_null()
                    {
                        return cur;
                    }
                    if !((*cur).prefix).is_null() && !nameSpace.is_null()
                        && !((*cur).href).is_null()
                        && xmlStrEqual((*cur).prefix, nameSpace) != 0
                    {
                        return cur;
                    }
                }
            }
        }
        node = (*node).parent;
    }
    return 0 as xmlNsPtr;
}
unsafe extern "C" fn xmlNsInScope(
    mut doc: xmlDocPtr,
    mut node: xmlNodePtr,
    mut ancestor: xmlNodePtr,
    mut prefix: *const xmlChar,
) -> libc::c_int {
    let mut tst: xmlNsPtr = 0 as *mut xmlNs;
    while !node.is_null() && node != ancestor {
        if (*node).type_0 as libc::c_uint
            == XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
            || (*node).type_0 as libc::c_uint
                == XML_ENTITY_NODE as libc::c_int as libc::c_uint
            || (*node).type_0 as libc::c_uint
                == XML_ENTITY_DECL as libc::c_int as libc::c_uint
        {
            return -(1 as libc::c_int);
        }
        if (*node).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            tst = (*node).nsDef;
            while !tst.is_null() {
                if ((*tst).prefix).is_null() && prefix.is_null() {
                    return 0 as libc::c_int;
                }
                if !((*tst).prefix).is_null() && !prefix.is_null()
                    && xmlStrEqual((*tst).prefix, prefix) != 0
                {
                    return 0 as libc::c_int;
                }
                tst = (*tst).next;
            }
        }
        node = (*node).parent;
    }
    if node != ancestor {
        return -(1 as libc::c_int);
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSearchNsByHref(
    mut doc: xmlDocPtr,
    mut node: xmlNodePtr,
    mut href: *const xmlChar,
) -> xmlNsPtr {
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    let mut orig: xmlNodePtr = node;
    let mut is_attr: libc::c_int = 0;
    if node.is_null()
        || (*node).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint || href.is_null()
    {
        return 0 as xmlNsPtr;
    }
    if xmlStrEqual(
        href,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
            as *const xmlChar,
    ) != 0
    {
        if doc.is_null()
            && (*node).type_0 as libc::c_uint
                == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            cur = xmlMalloc
                .expect(
                    "non-null function pointer",
                )(::std::mem::size_of::<xmlNs>() as libc::c_ulong) as xmlNsPtr;
            if cur.is_null() {
                xmlTreeErrMemory(
                    b"searching namespace\0" as *const u8 as *const libc::c_char,
                );
                return 0 as xmlNsPtr;
            }
            memset(
                cur as *mut libc::c_void,
                0 as libc::c_int,
                ::std::mem::size_of::<xmlNs>() as libc::c_ulong,
            );
            (*cur).type_0 = XML_NAMESPACE_DECL;
            let ref mut fresh303 = (*cur).href;
            *fresh303 = xmlStrdup(
                b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                    as *const libc::c_char as *const xmlChar,
            );
            let ref mut fresh304 = (*cur).prefix;
            *fresh304 = xmlStrdup(
                b"xml\0" as *const u8 as *const libc::c_char as *const xmlChar,
            );
            let ref mut fresh305 = (*cur).next;
            *fresh305 = (*node).nsDef;
            let ref mut fresh306 = (*node).nsDef;
            *fresh306 = cur;
            return cur;
        }
        if doc.is_null() {
            doc = (*node).doc;
            if doc.is_null() {
                return 0 as xmlNsPtr;
            }
        }
        if ((*doc).oldNs).is_null() {
            return xmlTreeEnsureXMLDecl(doc)
        } else {
            return (*doc).oldNs
        }
    }
    is_attr = ((*node).type_0 as libc::c_uint
        == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint) as libc::c_int;
    while !node.is_null() {
        if (*node).type_0 as libc::c_uint
            == XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
            || (*node).type_0 as libc::c_uint
                == XML_ENTITY_NODE as libc::c_int as libc::c_uint
            || (*node).type_0 as libc::c_uint
                == XML_ENTITY_DECL as libc::c_int as libc::c_uint
        {
            return 0 as xmlNsPtr;
        }
        if (*node).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            cur = (*node).nsDef;
            while !cur.is_null() {
                if !((*cur).href).is_null() && !href.is_null()
                    && xmlStrEqual((*cur).href, href) != 0
                {
                    if (is_attr == 0 || !((*cur).prefix).is_null())
                        && xmlNsInScope(doc, orig, node, (*cur).prefix)
                            == 1 as libc::c_int
                    {
                        return cur;
                    }
                }
                cur = (*cur).next;
            }
            if orig != node {
                cur = (*node).ns;
                if !cur.is_null() {
                    if !((*cur).href).is_null() && !href.is_null()
                        && xmlStrEqual((*cur).href, href) != 0
                    {
                        if (is_attr == 0 || !((*cur).prefix).is_null())
                            && xmlNsInScope(doc, orig, node, (*cur).prefix)
                                == 1 as libc::c_int
                        {
                            return cur;
                        }
                    }
                }
            }
        }
        node = (*node).parent;
    }
    return 0 as xmlNsPtr;
}
unsafe extern "C" fn xmlNewReconciledNs(
    mut doc: xmlDocPtr,
    mut tree: xmlNodePtr,
    mut ns: xmlNsPtr,
) -> xmlNsPtr {
    let mut def: xmlNsPtr = 0 as *mut xmlNs;
    let mut prefix: [xmlChar; 50] = [0; 50];
    let mut counter: libc::c_int = 1 as libc::c_int;
    if tree.is_null()
        || (*tree).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        return 0 as xmlNsPtr;
    }
    if ns.is_null()
        || (*ns).type_0 as libc::c_uint
            != XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 0 as xmlNsPtr;
    }
    def = xmlSearchNsByHref(doc, tree, (*ns).href);
    if !def.is_null() {
        return def;
    }
    if ((*ns).prefix).is_null() {
        snprintf(
            prefix.as_mut_ptr() as *mut libc::c_char,
            ::std::mem::size_of::<[xmlChar; 50]>() as libc::c_ulong,
            b"default\0" as *const u8 as *const libc::c_char,
        );
    } else {
        snprintf(
            prefix.as_mut_ptr() as *mut libc::c_char,
            ::std::mem::size_of::<[xmlChar; 50]>() as libc::c_ulong,
            b"%.20s\0" as *const u8 as *const libc::c_char,
            (*ns).prefix as *mut libc::c_char,
        );
    }
    def = xmlSearchNs(doc, tree, prefix.as_mut_ptr());
    while !def.is_null() {
        if counter > 1000 as libc::c_int {
            return 0 as xmlNsPtr;
        }
        if ((*ns).prefix).is_null() {
            let fresh307 = counter;
            counter = counter + 1;
            snprintf(
                prefix.as_mut_ptr() as *mut libc::c_char,
                ::std::mem::size_of::<[xmlChar; 50]>() as libc::c_ulong,
                b"default%d\0" as *const u8 as *const libc::c_char,
                fresh307,
            );
        } else {
            let fresh308 = counter;
            counter = counter + 1;
            snprintf(
                prefix.as_mut_ptr() as *mut libc::c_char,
                ::std::mem::size_of::<[xmlChar; 50]>() as libc::c_ulong,
                b"%.20s%d\0" as *const u8 as *const libc::c_char,
                (*ns).prefix as *mut libc::c_char,
                fresh308,
            );
        }
        def = xmlSearchNs(doc, tree, prefix.as_mut_ptr());
    }
    def = xmlNewNs(tree, (*ns).href, prefix.as_mut_ptr());
    return def;
}
#[no_mangle]
pub unsafe extern "C" fn xmlReconciliateNs(
    mut doc: xmlDocPtr,
    mut tree: xmlNodePtr,
) -> libc::c_int {
    let mut oldNs: *mut xmlNsPtr = 0 as *mut xmlNsPtr;
    let mut newNs: *mut xmlNsPtr = 0 as *mut xmlNsPtr;
    let mut sizeCache: libc::c_int = 0 as libc::c_int;
    let mut nbCache: libc::c_int = 0 as libc::c_int;
    let mut n: xmlNsPtr = 0 as *mut xmlNs;
    let mut node: xmlNodePtr = tree;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    if node.is_null()
        || (*node).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    if doc.is_null()
        || (*doc).type_0 as libc::c_uint
            != XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    if (*node).doc != doc {
        return -(1 as libc::c_int);
    }
    while !node.is_null() {
        if !((*node).ns).is_null() {
            if sizeCache == 0 as libc::c_int {
                sizeCache = 10 as libc::c_int;
                oldNs = xmlMalloc
                    .expect(
                        "non-null function pointer",
                    )(
                    (sizeCache as libc::c_ulong)
                        .wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as libc::c_ulong),
                ) as *mut xmlNsPtr;
                if oldNs.is_null() {
                    xmlTreeErrMemory(
                        b"fixing namespaces\0" as *const u8 as *const libc::c_char,
                    );
                    return -(1 as libc::c_int);
                }
                newNs = xmlMalloc
                    .expect(
                        "non-null function pointer",
                    )(
                    (sizeCache as libc::c_ulong)
                        .wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as libc::c_ulong),
                ) as *mut xmlNsPtr;
                if newNs.is_null() {
                    xmlTreeErrMemory(
                        b"fixing namespaces\0" as *const u8 as *const libc::c_char,
                    );
                    xmlFree
                        .expect("non-null function pointer")(oldNs as *mut libc::c_void);
                    return -(1 as libc::c_int);
                }
            }
            i = 0 as libc::c_int;
            while i < nbCache {
                if *oldNs.offset(i as isize) == (*node).ns {
                    let ref mut fresh309 = (*node).ns;
                    *fresh309 = *newNs.offset(i as isize);
                    break;
                } else {
                    i += 1;
                }
            }
            if i == nbCache {
                n = xmlNewReconciledNs(doc, tree, (*node).ns);
                if !n.is_null() {
                    if sizeCache <= nbCache {
                        sizeCache *= 2 as libc::c_int;
                        oldNs = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(
                            oldNs as *mut libc::c_void,
                            (sizeCache as libc::c_ulong)
                                .wrapping_mul(
                                    ::std::mem::size_of::<xmlNsPtr>() as libc::c_ulong,
                                ),
                        ) as *mut xmlNsPtr;
                        if oldNs.is_null() {
                            xmlTreeErrMemory(
                                b"fixing namespaces\0" as *const u8 as *const libc::c_char,
                            );
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(newNs as *mut libc::c_void);
                            return -(1 as libc::c_int);
                        }
                        newNs = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(
                            newNs as *mut libc::c_void,
                            (sizeCache as libc::c_ulong)
                                .wrapping_mul(
                                    ::std::mem::size_of::<xmlNsPtr>() as libc::c_ulong,
                                ),
                        ) as *mut xmlNsPtr;
                        if newNs.is_null() {
                            xmlTreeErrMemory(
                                b"fixing namespaces\0" as *const u8 as *const libc::c_char,
                            );
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(oldNs as *mut libc::c_void);
                            return -(1 as libc::c_int);
                        }
                    }
                    let ref mut fresh310 = *newNs.offset(nbCache as isize);
                    *fresh310 = n;
                    let fresh311 = nbCache;
                    nbCache = nbCache + 1;
                    let ref mut fresh312 = *oldNs.offset(fresh311 as isize);
                    *fresh312 = (*node).ns;
                    let ref mut fresh313 = (*node).ns;
                    *fresh313 = n;
                }
            }
        }
        if (*node).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            attr = (*node).properties;
            while !attr.is_null() {
                if !((*attr).ns).is_null() {
                    if sizeCache == 0 as libc::c_int {
                        sizeCache = 10 as libc::c_int;
                        oldNs = xmlMalloc
                            .expect(
                                "non-null function pointer",
                            )(
                            (sizeCache as libc::c_ulong)
                                .wrapping_mul(
                                    ::std::mem::size_of::<xmlNsPtr>() as libc::c_ulong,
                                ),
                        ) as *mut xmlNsPtr;
                        if oldNs.is_null() {
                            xmlTreeErrMemory(
                                b"fixing namespaces\0" as *const u8 as *const libc::c_char,
                            );
                            return -(1 as libc::c_int);
                        }
                        newNs = xmlMalloc
                            .expect(
                                "non-null function pointer",
                            )(
                            (sizeCache as libc::c_ulong)
                                .wrapping_mul(
                                    ::std::mem::size_of::<xmlNsPtr>() as libc::c_ulong,
                                ),
                        ) as *mut xmlNsPtr;
                        if newNs.is_null() {
                            xmlTreeErrMemory(
                                b"fixing namespaces\0" as *const u8 as *const libc::c_char,
                            );
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(oldNs as *mut libc::c_void);
                            return -(1 as libc::c_int);
                        }
                    }
                    i = 0 as libc::c_int;
                    while i < nbCache {
                        if *oldNs.offset(i as isize) == (*attr).ns {
                            let ref mut fresh314 = (*attr).ns;
                            *fresh314 = *newNs.offset(i as isize);
                            break;
                        } else {
                            i += 1;
                        }
                    }
                    if i == nbCache {
                        n = xmlNewReconciledNs(doc, tree, (*attr).ns);
                        if !n.is_null() {
                            if sizeCache <= nbCache {
                                sizeCache *= 2 as libc::c_int;
                                oldNs = xmlRealloc
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    oldNs as *mut libc::c_void,
                                    (sizeCache as libc::c_ulong)
                                        .wrapping_mul(
                                            ::std::mem::size_of::<xmlNsPtr>() as libc::c_ulong,
                                        ),
                                ) as *mut xmlNsPtr;
                                if oldNs.is_null() {
                                    xmlTreeErrMemory(
                                        b"fixing namespaces\0" as *const u8 as *const libc::c_char,
                                    );
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(newNs as *mut libc::c_void);
                                    return -(1 as libc::c_int);
                                }
                                newNs = xmlRealloc
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    newNs as *mut libc::c_void,
                                    (sizeCache as libc::c_ulong)
                                        .wrapping_mul(
                                            ::std::mem::size_of::<xmlNsPtr>() as libc::c_ulong,
                                        ),
                                ) as *mut xmlNsPtr;
                                if newNs.is_null() {
                                    xmlTreeErrMemory(
                                        b"fixing namespaces\0" as *const u8 as *const libc::c_char,
                                    );
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(oldNs as *mut libc::c_void);
                                    return -(1 as libc::c_int);
                                }
                            }
                            let ref mut fresh315 = *newNs.offset(nbCache as isize);
                            *fresh315 = n;
                            let fresh316 = nbCache;
                            nbCache = nbCache + 1;
                            let ref mut fresh317 = *oldNs.offset(fresh316 as isize);
                            *fresh317 = (*attr).ns;
                            let ref mut fresh318 = (*attr).ns;
                            *fresh318 = n;
                        }
                    }
                }
                attr = (*attr).next;
            }
        }
        if !((*node).children).is_null()
            && (*node).type_0 as libc::c_uint
                != XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
        {
            node = (*node).children;
        } else if node != tree && !((*node).next).is_null() {
            node = (*node).next;
        } else {
            if !(node != tree) {
                break;
            }
            while node != tree {
                if !((*node).parent).is_null() {
                    node = (*node).parent;
                }
                if node != tree && !((*node).next).is_null() {
                    node = (*node).next;
                    break;
                } else {
                    if !((*node).parent).is_null() {
                        continue;
                    }
                    node = 0 as xmlNodePtr;
                    break;
                }
            }
            if node == tree {
                node = 0 as xmlNodePtr;
            }
        }
    }
    if !oldNs.is_null() {
        xmlFree.expect("non-null function pointer")(oldNs as *mut libc::c_void);
    }
    if !newNs.is_null() {
        xmlFree.expect("non-null function pointer")(newNs as *mut libc::c_void);
    }
    return ret;
}
unsafe extern "C" fn xmlGetPropNodeInternal(
    mut node: *const xmlNode,
    mut name: *const xmlChar,
    mut nsName: *const xmlChar,
    mut useDTD: libc::c_int,
) -> xmlAttrPtr {
    let mut prop: xmlAttrPtr = 0 as *mut xmlAttr;
    if node.is_null()
        || (*node).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint || name.is_null()
    {
        return 0 as xmlAttrPtr;
    }
    if !((*node).properties).is_null() {
        prop = (*node).properties;
        if nsName.is_null() {
            loop {
                if ((*prop).ns).is_null() && xmlStrEqual((*prop).name, name) != 0 {
                    return prop;
                }
                prop = (*prop).next;
                if prop.is_null() {
                    break;
                }
            }
        } else {
            loop {
                if !((*prop).ns).is_null() && xmlStrEqual((*prop).name, name) != 0
                    && ((*(*prop).ns).href == nsName
                        || xmlStrEqual((*(*prop).ns).href, nsName) != 0)
                {
                    return prop;
                }
                prop = (*prop).next;
                if prop.is_null() {
                    break;
                }
            }
        }
    }
    if useDTD == 0 {
        return 0 as xmlAttrPtr;
    }
    if !((*node).doc).is_null() && !((*(*node).doc).intSubset).is_null() {
        let mut doc: xmlDocPtr = (*node).doc;
        let mut attrDecl: xmlAttributePtr = 0 as xmlAttributePtr;
        let mut elemQName: *mut xmlChar = 0 as *mut xmlChar;
        let mut tmpstr: *mut xmlChar = 0 as *mut xmlChar;
        if !((*node).ns).is_null() && !((*(*node).ns).prefix).is_null() {
            tmpstr = xmlStrdup((*(*node).ns).prefix);
            tmpstr = xmlStrcat(
                tmpstr,
                b":\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
            tmpstr = xmlStrcat(tmpstr, (*node).name);
            if tmpstr.is_null() {
                return 0 as xmlAttrPtr;
            }
            elemQName = tmpstr;
        } else {
            elemQName = (*node).name as *mut xmlChar;
        }
        if nsName.is_null() {
            attrDecl = xmlGetDtdQAttrDesc(
                (*doc).intSubset,
                elemQName,
                name,
                0 as *const xmlChar,
            );
            if attrDecl.is_null() && !((*doc).extSubset).is_null() {
                attrDecl = xmlGetDtdQAttrDesc(
                    (*doc).extSubset,
                    elemQName,
                    name,
                    0 as *const xmlChar,
                );
            }
        } else if xmlStrEqual(
                nsName,
                b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                    as *const libc::c_char as *const xmlChar,
            ) != 0
            {
            attrDecl = xmlGetDtdQAttrDesc(
                (*doc).intSubset,
                elemQName,
                name,
                b"xml\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
            if attrDecl.is_null() && !((*doc).extSubset).is_null() {
                attrDecl = xmlGetDtdQAttrDesc(
                    (*doc).extSubset,
                    elemQName,
                    name,
                    b"xml\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                );
            }
        } else {
            let mut nsList: *mut xmlNsPtr = 0 as *mut xmlNsPtr;
            let mut cur: *mut xmlNsPtr = 0 as *mut xmlNsPtr;
            nsList = xmlGetNsList((*node).doc, node);
            if nsList.is_null() {
                if !tmpstr.is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(tmpstr as *mut libc::c_void);
                }
                return 0 as xmlAttrPtr;
            }
            cur = nsList;
            while !(*cur).is_null() {
                if xmlStrEqual((**cur).href, nsName) != 0 {
                    attrDecl = xmlGetDtdQAttrDesc(
                        (*doc).intSubset,
                        elemQName,
                        name,
                        (**cur).prefix,
                    );
                    if !attrDecl.is_null() {
                        break;
                    }
                    if !((*doc).extSubset).is_null() {
                        attrDecl = xmlGetDtdQAttrDesc(
                            (*doc).extSubset,
                            elemQName,
                            name,
                            (**cur).prefix,
                        );
                        if !attrDecl.is_null() {
                            break;
                        }
                    }
                }
                cur = cur.offset(1);
            }
            xmlFree.expect("non-null function pointer")(nsList as *mut libc::c_void);
        }
        if !tmpstr.is_null() {
            xmlFree.expect("non-null function pointer")(tmpstr as *mut libc::c_void);
        }
        if !attrDecl.is_null() && !((*attrDecl).defaultValue).is_null() {
            return attrDecl as xmlAttrPtr;
        }
    }
    return 0 as xmlAttrPtr;
}
unsafe extern "C" fn xmlGetPropNodeValueInternal(
    mut prop: *const xmlAttr,
) -> *mut xmlChar {
    if prop.is_null() {
        return 0 as *mut xmlChar;
    }
    if (*prop).type_0 as libc::c_uint
        == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
    {
        if !((*prop).children).is_null() {
            if ((*(*prop).children).next).is_null()
                && ((*(*prop).children).type_0 as libc::c_uint
                    == XML_TEXT_NODE as libc::c_int as libc::c_uint
                    || (*(*prop).children).type_0 as libc::c_uint
                        == XML_CDATA_SECTION_NODE as libc::c_int as libc::c_uint)
            {
                return xmlStrdup((*(*prop).children).content)
            } else {
                let mut ret: *mut xmlChar = 0 as *mut xmlChar;
                ret = xmlNodeListGetString(
                    (*prop).doc,
                    (*prop).children,
                    1 as libc::c_int,
                );
                if !ret.is_null() {
                    return ret;
                }
            }
        }
        return xmlStrdup(b"\0" as *const u8 as *const libc::c_char as *mut xmlChar);
    } else {
        if (*prop).type_0 as libc::c_uint
            == XML_ATTRIBUTE_DECL as libc::c_int as libc::c_uint
        {
            return xmlStrdup((*(prop as xmlAttributePtr)).defaultValue);
        }
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlHasProp(
    mut node: *const xmlNode,
    mut name: *const xmlChar,
) -> xmlAttrPtr {
    let mut prop: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    if node.is_null()
        || (*node).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint || name.is_null()
    {
        return 0 as xmlAttrPtr;
    }
    prop = (*node).properties;
    while !prop.is_null() {
        if xmlStrEqual((*prop).name, name) != 0 {
            return prop;
        }
        prop = (*prop).next;
    }
    if xmlCheckDTD == 0 {
        return 0 as xmlAttrPtr;
    }
    doc = (*node).doc;
    if !doc.is_null() {
        let mut attrDecl: xmlAttributePtr = 0 as *mut xmlAttribute;
        if !((*doc).intSubset).is_null() {
            attrDecl = xmlGetDtdAttrDesc((*doc).intSubset, (*node).name, name);
            if attrDecl.is_null() && !((*doc).extSubset).is_null() {
                attrDecl = xmlGetDtdAttrDesc((*doc).extSubset, (*node).name, name);
            }
            if !attrDecl.is_null() && !((*attrDecl).defaultValue).is_null() {
                return attrDecl as xmlAttrPtr;
            }
        }
    }
    return 0 as xmlAttrPtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlHasNsProp(
    mut node: *const xmlNode,
    mut name: *const xmlChar,
    mut nameSpace: *const xmlChar,
) -> xmlAttrPtr {
    return xmlGetPropNodeInternal(node, name, nameSpace, xmlCheckDTD);
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetProp(
    mut node: *const xmlNode,
    mut name: *const xmlChar,
) -> *mut xmlChar {
    let mut prop: xmlAttrPtr = 0 as *mut xmlAttr;
    prop = xmlHasProp(node, name);
    if prop.is_null() {
        return 0 as *mut xmlChar;
    }
    return xmlGetPropNodeValueInternal(prop as *const xmlAttr);
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetNoNsProp(
    mut node: *const xmlNode,
    mut name: *const xmlChar,
) -> *mut xmlChar {
    let mut prop: xmlAttrPtr = 0 as *mut xmlAttr;
    prop = xmlGetPropNodeInternal(node, name, 0 as *const xmlChar, xmlCheckDTD);
    if prop.is_null() {
        return 0 as *mut xmlChar;
    }
    return xmlGetPropNodeValueInternal(prop as *const xmlAttr);
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetNsProp(
    mut node: *const xmlNode,
    mut name: *const xmlChar,
    mut nameSpace: *const xmlChar,
) -> *mut xmlChar {
    let mut prop: xmlAttrPtr = 0 as *mut xmlAttr;
    prop = xmlGetPropNodeInternal(node, name, nameSpace, xmlCheckDTD);
    if prop.is_null() {
        return 0 as *mut xmlChar;
    }
    return xmlGetPropNodeValueInternal(prop as *const xmlAttr);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUnsetProp(
    mut node: xmlNodePtr,
    mut name: *const xmlChar,
) -> libc::c_int {
    let mut prop: xmlAttrPtr = 0 as *mut xmlAttr;
    prop = xmlGetPropNodeInternal(
        node as *const xmlNode,
        name,
        0 as *const xmlChar,
        0 as libc::c_int,
    );
    if prop.is_null() {
        return -(1 as libc::c_int);
    }
    xmlUnlinkNode(prop as xmlNodePtr);
    xmlFreeProp(prop);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUnsetNsProp(
    mut node: xmlNodePtr,
    mut ns: xmlNsPtr,
    mut name: *const xmlChar,
) -> libc::c_int {
    let mut prop: xmlAttrPtr = 0 as *mut xmlAttr;
    prop = xmlGetPropNodeInternal(
        node as *const xmlNode,
        name,
        if !ns.is_null() { (*ns).href } else { 0 as *const xmlChar },
        0 as libc::c_int,
    );
    if prop.is_null() {
        return -(1 as libc::c_int);
    }
    xmlUnlinkNode(prop as xmlNodePtr);
    xmlFreeProp(prop);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetProp(
    mut node: xmlNodePtr,
    mut name: *const xmlChar,
    mut value: *const xmlChar,
) -> xmlAttrPtr {
    let mut len: libc::c_int = 0;
    let mut nqname: *const xmlChar = 0 as *const xmlChar;
    if node.is_null() || name.is_null()
        || (*node).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        return 0 as xmlAttrPtr;
    }
    nqname = xmlSplitQName3(name, &mut len);
    if !nqname.is_null() {
        let mut ns: xmlNsPtr = 0 as *mut xmlNs;
        let mut prefix: *mut xmlChar = xmlStrndup(name, len);
        ns = xmlSearchNs((*node).doc, node, prefix);
        if !prefix.is_null() {
            xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void);
        }
        if !ns.is_null() {
            return xmlSetNsProp(node, ns, nqname, value);
        }
    }
    return xmlSetNsProp(node, 0 as xmlNsPtr, name, value);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetNsProp(
    mut node: xmlNodePtr,
    mut ns: xmlNsPtr,
    mut name: *const xmlChar,
    mut value: *const xmlChar,
) -> xmlAttrPtr {
    let mut prop: xmlAttrPtr = 0 as *mut xmlAttr;
    if !ns.is_null() && ((*ns).href).is_null() {
        return 0 as xmlAttrPtr;
    }
    prop = xmlGetPropNodeInternal(
        node as *const xmlNode,
        name,
        if !ns.is_null() { (*ns).href } else { 0 as *const xmlChar },
        0 as libc::c_int,
    );
    if !prop.is_null() {
        if (*prop).atype as libc::c_uint
            == XML_ATTRIBUTE_ID as libc::c_int as libc::c_uint
        {
            xmlRemoveID((*node).doc, prop);
            (*prop).atype = XML_ATTRIBUTE_ID;
        }
        if !((*prop).children).is_null() {
            xmlFreeNodeList((*prop).children);
        }
        let ref mut fresh319 = (*prop).children;
        *fresh319 = 0 as *mut _xmlNode;
        let ref mut fresh320 = (*prop).last;
        *fresh320 = 0 as *mut _xmlNode;
        let ref mut fresh321 = (*prop).ns;
        *fresh321 = ns;
        if !value.is_null() {
            let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
            let ref mut fresh322 = (*prop).children;
            *fresh322 = xmlNewDocText((*node).doc, value);
            let ref mut fresh323 = (*prop).last;
            *fresh323 = 0 as *mut _xmlNode;
            tmp = (*prop).children;
            while !tmp.is_null() {
                let ref mut fresh324 = (*tmp).parent;
                *fresh324 = prop as xmlNodePtr;
                if ((*tmp).next).is_null() {
                    let ref mut fresh325 = (*prop).last;
                    *fresh325 = tmp;
                }
                tmp = (*tmp).next;
            }
        }
        if (*prop).atype as libc::c_uint
            == XML_ATTRIBUTE_ID as libc::c_int as libc::c_uint
        {
            xmlAddID(0 as xmlValidCtxtPtr, (*node).doc, value, prop);
        }
        return prop;
    }
    return xmlNewPropInternal(node, ns, name, value, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNodeIsText(mut node: *const xmlNode) -> libc::c_int {
    if node.is_null() {
        return 0 as libc::c_int;
    }
    if (*node).type_0 as libc::c_uint == XML_TEXT_NODE as libc::c_int as libc::c_uint {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsBlankNode(mut node: *const xmlNode) -> libc::c_int {
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    if node.is_null() {
        return 0 as libc::c_int;
    }
    if (*node).type_0 as libc::c_uint != XML_TEXT_NODE as libc::c_int as libc::c_uint
        && (*node).type_0 as libc::c_uint
            != XML_CDATA_SECTION_NODE as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    if ((*node).content).is_null() {
        return 1 as libc::c_int;
    }
    cur = (*node).content;
    while *cur as libc::c_int != 0 as libc::c_int {
        if !(*cur as libc::c_int == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= *cur as libc::c_int
                && *cur as libc::c_int <= 0xa as libc::c_int
            || *cur as libc::c_int == 0xd as libc::c_int)
        {
            return 0 as libc::c_int;
        }
        cur = cur.offset(1);
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextConcat(
    mut node: xmlNodePtr,
    mut content: *const xmlChar,
    mut len: libc::c_int,
) -> libc::c_int {
    if node.is_null() {
        return -(1 as libc::c_int);
    }
    if (*node).type_0 as libc::c_uint != XML_TEXT_NODE as libc::c_int as libc::c_uint
        && (*node).type_0 as libc::c_uint
            != XML_CDATA_SECTION_NODE as libc::c_int as libc::c_uint
        && (*node).type_0 as libc::c_uint
            != XML_COMMENT_NODE as libc::c_int as libc::c_uint
        && (*node).type_0 as libc::c_uint != XML_PI_NODE as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    if (*node).content == &mut (*node).properties as *mut *mut _xmlAttr as *mut xmlChar
        || !((*node).doc).is_null() && !((*(*node).doc).dict).is_null()
            && xmlDictOwns((*(*node).doc).dict, (*node).content) != 0
    {
        let ref mut fresh326 = (*node).content;
        *fresh326 = xmlStrncatNew((*node).content, content, len);
    } else {
        let ref mut fresh327 = (*node).content;
        *fresh327 = xmlStrncat((*node).content, content, len);
    }
    let ref mut fresh328 = (*node).properties;
    *fresh328 = 0 as *mut _xmlAttr;
    if ((*node).content).is_null() {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferCreate() -> xmlBufferPtr {
    let mut ret: xmlBufferPtr = 0 as *mut xmlBuffer;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlBuffer>() as libc::c_ulong) as xmlBufferPtr;
    if ret.is_null() {
        xmlTreeErrMemory(b"creating buffer\0" as *const u8 as *const libc::c_char);
        return 0 as xmlBufferPtr;
    }
    (*ret).use_0 = 0 as libc::c_int as libc::c_uint;
    (*ret).size = *__xmlDefaultBufferSize() as libc::c_uint;
    (*ret).alloc = *__xmlBufferAllocScheme();
    let ref mut fresh329 = (*ret).content;
    *fresh329 = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        ((*ret).size as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if ((*ret).content).is_null() {
        xmlTreeErrMemory(b"creating buffer\0" as *const u8 as *const libc::c_char);
        xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
        return 0 as xmlBufferPtr;
    }
    *((*ret).content).offset(0 as libc::c_int as isize) = 0 as libc::c_int as xmlChar;
    let ref mut fresh330 = (*ret).contentIO;
    *fresh330 = 0 as *mut xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferCreateSize(mut size: size_t) -> xmlBufferPtr {
    let mut ret: xmlBufferPtr = 0 as *mut xmlBuffer;
    if size
        >= (2147483647 as libc::c_int as libc::c_uint)
            .wrapping_mul(2 as libc::c_uint)
            .wrapping_add(1 as libc::c_uint) as libc::c_ulong
    {
        return 0 as xmlBufferPtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlBuffer>() as libc::c_ulong) as xmlBufferPtr;
    if ret.is_null() {
        xmlTreeErrMemory(b"creating buffer\0" as *const u8 as *const libc::c_char);
        return 0 as xmlBufferPtr;
    }
    (*ret).use_0 = 0 as libc::c_int as libc::c_uint;
    (*ret).alloc = *__xmlBufferAllocScheme();
    (*ret)
        .size = (if size != 0 {
        size.wrapping_add(1 as libc::c_int as libc::c_ulong)
    } else {
        0 as libc::c_int as libc::c_ulong
    }) as libc::c_uint;
    if (*ret).size != 0 {
        let ref mut fresh331 = (*ret).content;
        *fresh331 = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )(
            ((*ret).size as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
        ) as *mut xmlChar;
        if ((*ret).content).is_null() {
            xmlTreeErrMemory(b"creating buffer\0" as *const u8 as *const libc::c_char);
            xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
            return 0 as xmlBufferPtr;
        }
        *((*ret).content)
            .offset(0 as libc::c_int as isize) = 0 as libc::c_int as xmlChar;
    } else {
        let ref mut fresh332 = (*ret).content;
        *fresh332 = 0 as *mut xmlChar;
    }
    let ref mut fresh333 = (*ret).contentIO;
    *fresh333 = 0 as *mut xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferDetach(mut buf: xmlBufferPtr) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if buf.is_null() {
        return 0 as *mut xmlChar;
    }
    if (*buf).alloc as libc::c_uint
        == XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
    {
        return 0 as *mut xmlChar;
    }
    ret = (*buf).content;
    let ref mut fresh334 = (*buf).content;
    *fresh334 = 0 as *mut xmlChar;
    (*buf).size = 0 as libc::c_int as libc::c_uint;
    (*buf).use_0 = 0 as libc::c_int as libc::c_uint;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferCreateStatic(
    mut mem: *mut libc::c_void,
    mut size: size_t,
) -> xmlBufferPtr {
    let mut ret: xmlBufferPtr = 0 as *mut xmlBuffer;
    if mem.is_null() || size == 0 as libc::c_int as libc::c_ulong {
        return 0 as xmlBufferPtr;
    }
    if size
        > (2147483647 as libc::c_int as libc::c_uint)
            .wrapping_mul(2 as libc::c_uint)
            .wrapping_add(1 as libc::c_uint) as libc::c_ulong
    {
        return 0 as xmlBufferPtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlBuffer>() as libc::c_ulong) as xmlBufferPtr;
    if ret.is_null() {
        xmlTreeErrMemory(b"creating buffer\0" as *const u8 as *const libc::c_char);
        return 0 as xmlBufferPtr;
    }
    (*ret).use_0 = size as libc::c_uint;
    (*ret).size = size as libc::c_uint;
    (*ret).alloc = XML_BUFFER_ALLOC_IMMUTABLE;
    let ref mut fresh335 = (*ret).content;
    *fresh335 = mem as *mut xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferSetAllocationScheme(
    mut buf: xmlBufferPtr,
    mut scheme: xmlBufferAllocationScheme,
) {
    if buf.is_null() {
        return;
    }
    if (*buf).alloc as libc::c_uint
        == XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
        || (*buf).alloc as libc::c_uint
            == XML_BUFFER_ALLOC_IO as libc::c_int as libc::c_uint
    {
        return;
    }
    if scheme as libc::c_uint == XML_BUFFER_ALLOC_DOUBLEIT as libc::c_int as libc::c_uint
        || scheme as libc::c_uint
            == XML_BUFFER_ALLOC_EXACT as libc::c_int as libc::c_uint
        || scheme as libc::c_uint
            == XML_BUFFER_ALLOC_HYBRID as libc::c_int as libc::c_uint
        || scheme as libc::c_uint
            == XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
    {
        (*buf).alloc = scheme;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferFree(mut buf: xmlBufferPtr) {
    if buf.is_null() {
        return;
    }
    if (*buf).alloc as libc::c_uint == XML_BUFFER_ALLOC_IO as libc::c_int as libc::c_uint
        && !((*buf).contentIO).is_null()
    {
        xmlFree
            .expect("non-null function pointer")((*buf).contentIO as *mut libc::c_void);
    } else if !((*buf).content).is_null()
            && (*buf).alloc as libc::c_uint
                != XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
        {
        xmlFree.expect("non-null function pointer")((*buf).content as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferEmpty(mut buf: xmlBufferPtr) {
    if buf.is_null() {
        return;
    }
    if ((*buf).content).is_null() {
        return;
    }
    (*buf).use_0 = 0 as libc::c_int as libc::c_uint;
    if (*buf).alloc as libc::c_uint
        == XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
    {
        let ref mut fresh336 = (*buf).content;
        *fresh336 = b"\0" as *const u8 as *const libc::c_char as *mut xmlChar;
    } else if (*buf).alloc as libc::c_uint
            == XML_BUFFER_ALLOC_IO as libc::c_int as libc::c_uint
            && !((*buf).contentIO).is_null()
        {
        let mut start_buf: size_t = ((*buf).content).offset_from((*buf).contentIO)
            as libc::c_long as size_t;
        let ref mut fresh337 = (*buf).size;
        *fresh337 = (*fresh337 as libc::c_ulong).wrapping_add(start_buf) as libc::c_uint
            as libc::c_uint;
        let ref mut fresh338 = (*buf).content;
        *fresh338 = (*buf).contentIO;
        *((*buf).content)
            .offset(0 as libc::c_int as isize) = 0 as libc::c_int as xmlChar;
    } else {
        *((*buf).content)
            .offset(0 as libc::c_int as isize) = 0 as libc::c_int as xmlChar;
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferShrink(
    mut buf: xmlBufferPtr,
    mut len: libc::c_uint,
) -> libc::c_int {
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    if len == 0 as libc::c_int as libc::c_uint {
        return 0 as libc::c_int;
    }
    if len > (*buf).use_0 {
        return -(1 as libc::c_int);
    }
    let ref mut fresh339 = (*buf).use_0;
    *fresh339 = (*fresh339).wrapping_sub(len);
    if (*buf).alloc as libc::c_uint
        == XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
        || (*buf).alloc as libc::c_uint
            == XML_BUFFER_ALLOC_IO as libc::c_int as libc::c_uint
            && !((*buf).contentIO).is_null()
    {
        let ref mut fresh340 = (*buf).content;
        *fresh340 = (*fresh340).offset(len as isize);
        let ref mut fresh341 = (*buf).size;
        *fresh341 = (*fresh341).wrapping_sub(len);
        if (*buf).alloc as libc::c_uint
            == XML_BUFFER_ALLOC_IO as libc::c_int as libc::c_uint
            && !((*buf).contentIO).is_null()
        {
            let mut start_buf: size_t = ((*buf).content).offset_from((*buf).contentIO)
                as libc::c_long as size_t;
            if start_buf >= (*buf).size as libc::c_ulong {
                memmove(
                    (*buf).contentIO as *mut libc::c_void,
                    &mut *((*buf).content).offset(0 as libc::c_int as isize)
                        as *mut xmlChar as *const libc::c_void,
                    (*buf).use_0 as libc::c_ulong,
                );
                let ref mut fresh342 = (*buf).content;
                *fresh342 = (*buf).contentIO;
                *((*buf).content)
                    .offset((*buf).use_0 as isize) = 0 as libc::c_int as xmlChar;
                let ref mut fresh343 = (*buf).size;
                *fresh343 = (*fresh343 as libc::c_ulong).wrapping_add(start_buf)
                    as libc::c_uint as libc::c_uint;
            }
        }
    } else {
        memmove(
            (*buf).content as *mut libc::c_void,
            &mut *((*buf).content).offset(len as isize) as *mut xmlChar
                as *const libc::c_void,
            (*buf).use_0 as libc::c_ulong,
        );
        *((*buf).content).offset((*buf).use_0 as isize) = 0 as libc::c_int as xmlChar;
    }
    return len as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferGrow(
    mut buf: xmlBufferPtr,
    mut len: libc::c_uint,
) -> libc::c_int {
    let mut size: libc::c_uint = 0;
    let mut newbuf: *mut xmlChar = 0 as *mut xmlChar;
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    if (*buf).alloc as libc::c_uint
        == XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    if len < ((*buf).size).wrapping_sub((*buf).use_0) {
        return 0 as libc::c_int;
    }
    if len
        >= (2147483647 as libc::c_int as libc::c_uint)
            .wrapping_mul(2 as libc::c_uint)
            .wrapping_add(1 as libc::c_uint)
            .wrapping_sub((*buf).use_0)
    {
        xmlTreeErrMemory(
            b"growing buffer past UINT_MAX\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if (*buf).size as libc::c_ulong > len as size_t {
        size = if (*buf).size
            > (2147483647 as libc::c_int as libc::c_uint)
                .wrapping_mul(2 as libc::c_uint)
                .wrapping_add(1 as libc::c_uint)
                .wrapping_div(2 as libc::c_int as libc::c_uint)
        {
            (2147483647 as libc::c_int as libc::c_uint)
                .wrapping_mul(2 as libc::c_uint)
                .wrapping_add(1 as libc::c_uint)
        } else {
            ((*buf).size).wrapping_mul(2 as libc::c_int as libc::c_uint)
        };
    } else {
        size = ((*buf).use_0).wrapping_add(len);
        size = if size
            > (2147483647 as libc::c_int as libc::c_uint)
                .wrapping_mul(2 as libc::c_uint)
                .wrapping_add(1 as libc::c_uint)
                .wrapping_sub(100 as libc::c_int as libc::c_uint)
        {
            (2147483647 as libc::c_int as libc::c_uint)
                .wrapping_mul(2 as libc::c_uint)
                .wrapping_add(1 as libc::c_uint)
        } else {
            size.wrapping_add(100 as libc::c_int as libc::c_uint)
        };
    }
    if (*buf).alloc as libc::c_uint == XML_BUFFER_ALLOC_IO as libc::c_int as libc::c_uint
        && !((*buf).contentIO).is_null()
    {
        let mut start_buf: size_t = ((*buf).content).offset_from((*buf).contentIO)
            as libc::c_long as size_t;
        newbuf = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*buf).contentIO as *mut libc::c_void,
            start_buf.wrapping_add(size as libc::c_ulong),
        ) as *mut xmlChar;
        if newbuf.is_null() {
            xmlTreeErrMemory(b"growing buffer\0" as *const u8 as *const libc::c_char);
            return -(1 as libc::c_int);
        }
        let ref mut fresh344 = (*buf).contentIO;
        *fresh344 = newbuf;
        let ref mut fresh345 = (*buf).content;
        *fresh345 = newbuf.offset(start_buf as isize);
    } else {
        newbuf = xmlRealloc
            .expect(
                "non-null function pointer",
            )((*buf).content as *mut libc::c_void, size as size_t) as *mut xmlChar;
        if newbuf.is_null() {
            xmlTreeErrMemory(b"growing buffer\0" as *const u8 as *const libc::c_char);
            return -(1 as libc::c_int);
        }
        let ref mut fresh346 = (*buf).content;
        *fresh346 = newbuf;
    }
    (*buf).size = size;
    return ((*buf).size)
        .wrapping_sub((*buf).use_0)
        .wrapping_sub(1 as libc::c_int as libc::c_uint) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferDump(
    mut file: *mut FILE,
    mut buf: xmlBufferPtr,
) -> libc::c_int {
    let mut ret: size_t = 0;
    if buf.is_null() {
        return 0 as libc::c_int;
    }
    if ((*buf).content).is_null() {
        return 0 as libc::c_int;
    }
    if file.is_null() {
        file = stdout;
    }
    ret = fwrite(
        (*buf).content as *const libc::c_void,
        ::std::mem::size_of::<xmlChar>() as libc::c_ulong,
        (*buf).use_0 as libc::c_ulong,
        file,
    );
    return if ret > 2147483647 as libc::c_int as libc::c_ulong {
        2147483647 as libc::c_int
    } else {
        ret as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferContent(mut buf: *const xmlBuffer) -> *const xmlChar {
    if buf.is_null() {
        return 0 as *const xmlChar;
    }
    return (*buf).content;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferLength(mut buf: *const xmlBuffer) -> libc::c_int {
    if buf.is_null() {
        return 0 as libc::c_int;
    }
    return (*buf).use_0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferResize(
    mut buf: xmlBufferPtr,
    mut size: libc::c_uint,
) -> libc::c_int {
    let mut newSize: libc::c_uint = 0;
    let mut rebuf: *mut xmlChar = 0 as *mut xmlChar;
    let mut start_buf: size_t = 0;
    if buf.is_null() {
        return 0 as libc::c_int;
    }
    if (*buf).alloc as libc::c_uint
        == XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    if size < (*buf).size {
        return 1 as libc::c_int;
    }
    if size
        > (2147483647 as libc::c_int as libc::c_uint)
            .wrapping_mul(2 as libc::c_uint)
            .wrapping_add(1 as libc::c_uint)
            .wrapping_sub(10 as libc::c_int as libc::c_uint)
    {
        xmlTreeErrMemory(
            b"growing buffer past UINT_MAX\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    match (*buf).alloc as libc::c_uint {
        3 | 0 => {
            if (*buf).size == 0 as libc::c_int as libc::c_uint {
                newSize = if size
                    > (2147483647 as libc::c_int as libc::c_uint)
                        .wrapping_mul(2 as libc::c_uint)
                        .wrapping_add(1 as libc::c_uint)
                        .wrapping_sub(10 as libc::c_int as libc::c_uint)
                {
                    (2147483647 as libc::c_int as libc::c_uint)
                        .wrapping_mul(2 as libc::c_uint)
                        .wrapping_add(1 as libc::c_uint)
                } else {
                    size.wrapping_add(10 as libc::c_int as libc::c_uint)
                };
            } else {
                newSize = (*buf).size;
            }
            while size > newSize {
                if newSize
                    > (2147483647 as libc::c_int as libc::c_uint)
                        .wrapping_mul(2 as libc::c_uint)
                        .wrapping_add(1 as libc::c_uint)
                        .wrapping_div(2 as libc::c_int as libc::c_uint)
                {
                    xmlTreeErrMemory(
                        b"growing buffer\0" as *const u8 as *const libc::c_char,
                    );
                    return 0 as libc::c_int;
                }
                newSize = newSize.wrapping_mul(2 as libc::c_int as libc::c_uint);
            }
        }
        1 => {
            newSize = if size
                > (2147483647 as libc::c_int as libc::c_uint)
                    .wrapping_mul(2 as libc::c_uint)
                    .wrapping_add(1 as libc::c_uint)
                    .wrapping_sub(10 as libc::c_int as libc::c_uint)
            {
                (2147483647 as libc::c_int as libc::c_uint)
                    .wrapping_mul(2 as libc::c_uint)
                    .wrapping_add(1 as libc::c_uint)
            } else {
                size.wrapping_add(10 as libc::c_int as libc::c_uint)
            };
        }
        4 => {
            if (*buf).use_0 < 4096 as libc::c_int as libc::c_uint {
                newSize = size;
            } else {
                newSize = (*buf).size;
                while size > newSize {
                    if newSize
                        > (2147483647 as libc::c_int as libc::c_uint)
                            .wrapping_mul(2 as libc::c_uint)
                            .wrapping_add(1 as libc::c_uint)
                            .wrapping_div(2 as libc::c_int as libc::c_uint)
                    {
                        xmlTreeErrMemory(
                            b"growing buffer\0" as *const u8 as *const libc::c_char,
                        );
                        return 0 as libc::c_int;
                    }
                    newSize = newSize.wrapping_mul(2 as libc::c_int as libc::c_uint);
                }
            }
        }
        _ => {
            newSize = if size
                > (2147483647 as libc::c_int as libc::c_uint)
                    .wrapping_mul(2 as libc::c_uint)
                    .wrapping_add(1 as libc::c_uint)
                    .wrapping_sub(10 as libc::c_int as libc::c_uint)
            {
                (2147483647 as libc::c_int as libc::c_uint)
                    .wrapping_mul(2 as libc::c_uint)
                    .wrapping_add(1 as libc::c_uint)
            } else {
                size.wrapping_add(10 as libc::c_int as libc::c_uint)
            };
        }
    }
    if (*buf).alloc as libc::c_uint == XML_BUFFER_ALLOC_IO as libc::c_int as libc::c_uint
        && !((*buf).contentIO).is_null()
    {
        start_buf = ((*buf).content).offset_from((*buf).contentIO) as libc::c_long
            as size_t;
        if start_buf > newSize as libc::c_ulong {
            memmove(
                (*buf).contentIO as *mut libc::c_void,
                (*buf).content as *const libc::c_void,
                (*buf).use_0 as libc::c_ulong,
            );
            let ref mut fresh347 = (*buf).content;
            *fresh347 = (*buf).contentIO;
            *((*buf).content)
                .offset((*buf).use_0 as isize) = 0 as libc::c_int as xmlChar;
            let ref mut fresh348 = (*buf).size;
            *fresh348 = (*fresh348 as libc::c_ulong).wrapping_add(start_buf)
                as libc::c_uint as libc::c_uint;
        } else {
            rebuf = xmlRealloc
                .expect(
                    "non-null function pointer",
                )(
                (*buf).contentIO as *mut libc::c_void,
                start_buf.wrapping_add(newSize as libc::c_ulong),
            ) as *mut xmlChar;
            if rebuf.is_null() {
                xmlTreeErrMemory(
                    b"growing buffer\0" as *const u8 as *const libc::c_char,
                );
                return 0 as libc::c_int;
            }
            let ref mut fresh349 = (*buf).contentIO;
            *fresh349 = rebuf;
            let ref mut fresh350 = (*buf).content;
            *fresh350 = rebuf.offset(start_buf as isize);
        }
    } else {
        if ((*buf).content).is_null() {
            rebuf = xmlMallocAtomic
                .expect("non-null function pointer")(newSize as size_t) as *mut xmlChar;
            (*buf).use_0 = 0 as libc::c_int as libc::c_uint;
            *rebuf.offset((*buf).use_0 as isize) = 0 as libc::c_int as xmlChar;
        } else if ((*buf).size).wrapping_sub((*buf).use_0)
                < 100 as libc::c_int as libc::c_uint
            {
            rebuf = xmlRealloc
                .expect(
                    "non-null function pointer",
                )((*buf).content as *mut libc::c_void, newSize as size_t)
                as *mut xmlChar;
        } else {
            rebuf = xmlMallocAtomic
                .expect("non-null function pointer")(newSize as size_t) as *mut xmlChar;
            if !rebuf.is_null() {
                memcpy(
                    rebuf as *mut libc::c_void,
                    (*buf).content as *const libc::c_void,
                    (*buf).use_0 as libc::c_ulong,
                );
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*buf).content as *mut libc::c_void);
                *rebuf.offset((*buf).use_0 as isize) = 0 as libc::c_int as xmlChar;
            }
        }
        if rebuf.is_null() {
            xmlTreeErrMemory(b"growing buffer\0" as *const u8 as *const libc::c_char);
            return 0 as libc::c_int;
        }
        let ref mut fresh351 = (*buf).content;
        *fresh351 = rebuf;
    }
    (*buf).size = newSize;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferAdd(
    mut buf: xmlBufferPtr,
    mut str: *const xmlChar,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut needSize: libc::c_uint = 0;
    if str.is_null() || buf.is_null() {
        return -(1 as libc::c_int);
    }
    if (*buf).alloc as libc::c_uint
        == XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    if len < -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    if len == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if len < 0 as libc::c_int {
        len = xmlStrlen(str);
    }
    if len < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if len == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if len as libc::c_uint >= ((*buf).size).wrapping_sub((*buf).use_0) {
        if len as libc::c_uint
            >= (2147483647 as libc::c_int as libc::c_uint)
                .wrapping_mul(2 as libc::c_uint)
                .wrapping_add(1 as libc::c_uint)
                .wrapping_sub((*buf).use_0)
        {
            xmlTreeErrMemory(
                b"growing buffer past UINT_MAX\0" as *const u8 as *const libc::c_char,
            );
            return XML_ERR_NO_MEMORY as libc::c_int;
        }
        needSize = ((*buf).use_0)
            .wrapping_add(len as libc::c_uint)
            .wrapping_add(1 as libc::c_int as libc::c_uint);
        if xmlBufferResize(buf, needSize) == 0 {
            xmlTreeErrMemory(b"growing buffer\0" as *const u8 as *const libc::c_char);
            return XML_ERR_NO_MEMORY as libc::c_int;
        }
    }
    memmove(
        &mut *((*buf).content).offset((*buf).use_0 as isize) as *mut xmlChar
            as *mut libc::c_void,
        str as *const libc::c_void,
        (len as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    );
    let ref mut fresh352 = (*buf).use_0;
    *fresh352 = (*fresh352).wrapping_add(len as libc::c_uint);
    *((*buf).content).offset((*buf).use_0 as isize) = 0 as libc::c_int as xmlChar;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferAddHead(
    mut buf: xmlBufferPtr,
    mut str: *const xmlChar,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut needSize: libc::c_uint = 0;
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    if (*buf).alloc as libc::c_uint
        == XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    if str.is_null() {
        return -(1 as libc::c_int);
    }
    if len < -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    if len == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if len < 0 as libc::c_int {
        len = xmlStrlen(str);
    }
    if len <= 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if (*buf).alloc as libc::c_uint == XML_BUFFER_ALLOC_IO as libc::c_int as libc::c_uint
        && !((*buf).contentIO).is_null()
    {
        let mut start_buf: size_t = ((*buf).content).offset_from((*buf).contentIO)
            as libc::c_long as size_t;
        if start_buf > len as libc::c_uint as libc::c_ulong {
            let ref mut fresh353 = (*buf).content;
            *fresh353 = (*fresh353).offset(-(len as isize));
            memmove(
                &mut *((*buf).content).offset(0 as libc::c_int as isize) as *mut xmlChar
                    as *mut libc::c_void,
                str as *const libc::c_void,
                len as libc::c_ulong,
            );
            let ref mut fresh354 = (*buf).use_0;
            *fresh354 = (*fresh354).wrapping_add(len as libc::c_uint);
            let ref mut fresh355 = (*buf).size;
            *fresh355 = (*fresh355).wrapping_add(len as libc::c_uint);
            *((*buf).content)
                .offset((*buf).use_0 as isize) = 0 as libc::c_int as xmlChar;
            return 0 as libc::c_int;
        }
    }
    if len as libc::c_uint >= ((*buf).size).wrapping_sub((*buf).use_0) {
        if len as libc::c_uint
            >= (2147483647 as libc::c_int as libc::c_uint)
                .wrapping_mul(2 as libc::c_uint)
                .wrapping_add(1 as libc::c_uint)
                .wrapping_sub((*buf).use_0)
        {
            xmlTreeErrMemory(
                b"growing buffer past UINT_MAX\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        needSize = ((*buf).use_0)
            .wrapping_add(len as libc::c_uint)
            .wrapping_add(1 as libc::c_int as libc::c_uint);
        if xmlBufferResize(buf, needSize) == 0 {
            xmlTreeErrMemory(b"growing buffer\0" as *const u8 as *const libc::c_char);
            return XML_ERR_NO_MEMORY as libc::c_int;
        }
    }
    memmove(
        &mut *((*buf).content).offset(len as isize) as *mut xmlChar as *mut libc::c_void,
        &mut *((*buf).content).offset(0 as libc::c_int as isize) as *mut xmlChar
            as *const libc::c_void,
        (*buf).use_0 as libc::c_ulong,
    );
    memmove(
        &mut *((*buf).content).offset(0 as libc::c_int as isize) as *mut xmlChar
            as *mut libc::c_void,
        str as *const libc::c_void,
        len as libc::c_ulong,
    );
    let ref mut fresh356 = (*buf).use_0;
    *fresh356 = (*fresh356).wrapping_add(len as libc::c_uint);
    *((*buf).content).offset((*buf).use_0 as isize) = 0 as libc::c_int as xmlChar;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferCat(
    mut buf: xmlBufferPtr,
    mut str: *const xmlChar,
) -> libc::c_int {
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    if (*buf).alloc as libc::c_uint
        == XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    if str.is_null() {
        return -(1 as libc::c_int);
    }
    return xmlBufferAdd(buf, str, -(1 as libc::c_int));
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferCCat(
    mut buf: xmlBufferPtr,
    mut str: *const libc::c_char,
) -> libc::c_int {
    return xmlBufferCat(buf, str as *const xmlChar);
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferWriteCHAR(
    mut buf: xmlBufferPtr,
    mut string: *const xmlChar,
) {
    if buf.is_null() {
        return;
    }
    if (*buf).alloc as libc::c_uint
        == XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
    {
        return;
    }
    xmlBufferCat(buf, string);
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferWriteChar(
    mut buf: xmlBufferPtr,
    mut string: *const libc::c_char,
) {
    if buf.is_null() {
        return;
    }
    if (*buf).alloc as libc::c_uint
        == XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
    {
        return;
    }
    xmlBufferCCat(buf, string);
}
#[no_mangle]
pub unsafe extern "C" fn xmlBufferWriteQuotedString(
    mut buf: xmlBufferPtr,
    mut string: *const xmlChar,
) {
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut base: *const xmlChar = 0 as *const xmlChar;
    if buf.is_null() {
        return;
    }
    if (*buf).alloc as libc::c_uint
        == XML_BUFFER_ALLOC_IMMUTABLE as libc::c_int as libc::c_uint
    {
        return;
    }
    if !(xmlStrchr(string, '"' as i32 as xmlChar)).is_null() {
        if !(xmlStrchr(string, '\'' as i32 as xmlChar)).is_null() {
            xmlBufferCCat(buf, b"\"\0" as *const u8 as *const libc::c_char);
            cur = string;
            base = cur;
            while *cur as libc::c_int != 0 as libc::c_int {
                if *cur as libc::c_int == '"' as i32 {
                    if base != cur {
                        xmlBufferAdd(
                            buf,
                            base,
                            cur.offset_from(base) as libc::c_long as libc::c_int,
                        );
                    }
                    xmlBufferAdd(
                        buf,
                        b"&quot;\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                        6 as libc::c_int,
                    );
                    cur = cur.offset(1);
                    base = cur;
                } else {
                    cur = cur.offset(1);
                }
            }
            if base != cur {
                xmlBufferAdd(
                    buf,
                    base,
                    cur.offset_from(base) as libc::c_long as libc::c_int,
                );
            }
            xmlBufferCCat(buf, b"\"\0" as *const u8 as *const libc::c_char);
        } else {
            xmlBufferCCat(buf, b"'\0" as *const u8 as *const libc::c_char);
            xmlBufferCat(buf, string);
            xmlBufferCCat(buf, b"'\0" as *const u8 as *const libc::c_char);
        }
    } else {
        xmlBufferCCat(buf, b"\"\0" as *const u8 as *const libc::c_char);
        xmlBufferCat(buf, string);
        xmlBufferCCat(buf, b"\"\0" as *const u8 as *const libc::c_char);
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetDocCompressMode(mut doc: *const xmlDoc) -> libc::c_int {
    if doc.is_null() {
        return -(1 as libc::c_int);
    }
    return (*doc).compression;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetDocCompressMode(
    mut doc: xmlDocPtr,
    mut mode: libc::c_int,
) {
    if doc.is_null() {
        return;
    }
    if mode < 0 as libc::c_int {
        (*doc).compression = 0 as libc::c_int;
    } else if mode > 9 as libc::c_int {
        (*doc).compression = 9 as libc::c_int;
    } else {
        (*doc).compression = mode;
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetCompressMode() -> libc::c_int {
    return xmlCompressMode;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetCompressMode(mut mode: libc::c_int) {
    if mode < 0 as libc::c_int {
        xmlCompressMode = 0 as libc::c_int;
    } else if mode > 9 as libc::c_int {
        xmlCompressMode = 9 as libc::c_int;
    } else {
        xmlCompressMode = mode;
    };
}
unsafe extern "C" fn xmlDOMWrapNsMapFree(mut nsmap: xmlNsMapPtr) {
    let mut cur: xmlNsMapItemPtr = 0 as *mut xmlNsMapItem;
    let mut tmp: xmlNsMapItemPtr = 0 as *mut xmlNsMapItem;
    if nsmap.is_null() {
        return;
    }
    cur = (*nsmap).pool;
    while !cur.is_null() {
        tmp = cur;
        cur = (*cur).next;
        xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void);
    }
    cur = (*nsmap).first;
    while !cur.is_null() {
        tmp = cur;
        cur = (*cur).next;
        xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(nsmap as *mut libc::c_void);
}
unsafe extern "C" fn xmlDOMWrapNsMapAddItem(
    mut nsmap: *mut xmlNsMapPtr,
    mut position: libc::c_int,
    mut oldNs: xmlNsPtr,
    mut newNs: xmlNsPtr,
    mut depth: libc::c_int,
) -> xmlNsMapItemPtr {
    let mut ret: xmlNsMapItemPtr = 0 as *mut xmlNsMapItem;
    let mut map: xmlNsMapPtr = 0 as *mut xmlNsMap;
    if nsmap.is_null() {
        return 0 as xmlNsMapItemPtr;
    }
    if position != -(1 as libc::c_int) && position != 0 as libc::c_int {
        return 0 as xmlNsMapItemPtr;
    }
    map = *nsmap;
    if map.is_null() {
        map = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlNsMap>() as libc::c_ulong) as xmlNsMapPtr;
        if map.is_null() {
            xmlTreeErrMemory(
                b"allocating namespace map\0" as *const u8 as *const libc::c_char,
            );
            return 0 as xmlNsMapItemPtr;
        }
        memset(
            map as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<xmlNsMap>() as libc::c_ulong,
        );
        *nsmap = map;
    }
    if !((*map).pool).is_null() {
        ret = (*map).pool;
        let ref mut fresh357 = (*map).pool;
        *fresh357 = (*ret).next;
        memset(
            ret as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<xmlNsMapItem>() as libc::c_ulong,
        );
    } else {
        ret = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlNsMapItem>() as libc::c_ulong) as xmlNsMapItemPtr;
        if ret.is_null() {
            xmlTreeErrMemory(
                b"allocating namespace map item\0" as *const u8 as *const libc::c_char,
            );
            return 0 as xmlNsMapItemPtr;
        }
        memset(
            ret as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<xmlNsMapItem>() as libc::c_ulong,
        );
    }
    if ((*map).first).is_null() {
        let ref mut fresh358 = (*map).first;
        *fresh358 = ret;
        let ref mut fresh359 = (*map).last;
        *fresh359 = ret;
    } else if position == -(1 as libc::c_int) {
        let ref mut fresh360 = (*ret).prev;
        *fresh360 = (*map).last;
        let ref mut fresh361 = (*(*map).last).next;
        *fresh361 = ret;
        let ref mut fresh362 = (*map).last;
        *fresh362 = ret;
    } else if position == 0 as libc::c_int {
        let ref mut fresh363 = (*(*map).first).prev;
        *fresh363 = ret;
        let ref mut fresh364 = (*ret).next;
        *fresh364 = (*map).first;
        let ref mut fresh365 = (*map).first;
        *fresh365 = ret;
    }
    let ref mut fresh366 = (*ret).oldNs;
    *fresh366 = oldNs;
    let ref mut fresh367 = (*ret).newNs;
    *fresh367 = newNs;
    (*ret).shadowDepth = -(1 as libc::c_int);
    (*ret).depth = depth;
    return ret;
}
unsafe extern "C" fn xmlDOMWrapStoreNs(
    mut doc: xmlDocPtr,
    mut nsName: *const xmlChar,
    mut prefix: *const xmlChar,
) -> xmlNsPtr {
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    if doc.is_null() {
        return 0 as xmlNsPtr;
    }
    ns = xmlTreeEnsureXMLDecl(doc);
    if ns.is_null() {
        return 0 as xmlNsPtr;
    }
    if !((*ns).next).is_null() {
        ns = (*ns).next;
        while !ns.is_null() {
            if ((*ns).prefix == prefix || xmlStrEqual((*ns).prefix, prefix) != 0)
                && xmlStrEqual((*ns).href, nsName) != 0
            {
                return ns;
            }
            if ((*ns).next).is_null() {
                break;
            }
            ns = (*ns).next;
        }
    }
    if !ns.is_null() {
        let ref mut fresh368 = (*ns).next;
        *fresh368 = xmlNewNs(0 as xmlNodePtr, nsName, prefix);
        return (*ns).next;
    }
    return 0 as xmlNsPtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDOMWrapNewCtxt() -> xmlDOMWrapCtxtPtr {
    let mut ret: xmlDOMWrapCtxtPtr = 0 as *mut xmlDOMWrapCtxt;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlDOMWrapCtxt>() as libc::c_ulong) as xmlDOMWrapCtxtPtr;
    if ret.is_null() {
        xmlTreeErrMemory(
            b"allocating DOM-wrapper context\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlDOMWrapCtxtPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlDOMWrapCtxt>() as libc::c_ulong,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDOMWrapFreeCtxt(mut ctxt: xmlDOMWrapCtxtPtr) {
    if ctxt.is_null() {
        return;
    }
    if !((*ctxt).namespaceMap).is_null() {
        xmlDOMWrapNsMapFree((*ctxt).namespaceMap as xmlNsMapPtr);
    }
    xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void);
}
unsafe extern "C" fn xmlTreeNSListLookupByPrefix(
    mut nsList: xmlNsPtr,
    mut prefix: *const xmlChar,
) -> xmlNsPtr {
    if nsList.is_null() {
        return 0 as xmlNsPtr;
    }
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    ns = nsList;
    loop {
        if prefix == (*ns).prefix || xmlStrEqual(prefix, (*ns).prefix) != 0 {
            return ns;
        }
        ns = (*ns).next;
        if ns.is_null() {
            break;
        }
    }
    return 0 as xmlNsPtr;
}
unsafe extern "C" fn xmlDOMWrapNSNormGatherInScopeNs(
    mut map: *mut xmlNsMapPtr,
    mut node: xmlNodePtr,
) -> libc::c_int {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut mi: xmlNsMapItemPtr = 0 as *mut xmlNsMapItem;
    let mut shadowed: libc::c_int = 0;
    if map.is_null() || !(*map).is_null() {
        return -(1 as libc::c_int);
    }
    if node.is_null()
        || (*node).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    cur = node;
    while !cur.is_null() && cur != (*cur).doc as xmlNodePtr {
        if (*cur).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            if !((*cur).nsDef).is_null() {
                ns = (*cur).nsDef;
                loop {
                    shadowed = 0 as libc::c_int;
                    if !(*map).is_null() && !((**map).first).is_null() {
                        mi = (**map).first;
                        while !mi.is_null() {
                            if (*ns).prefix == (*(*mi).newNs).prefix
                                || xmlStrEqual((*ns).prefix, (*(*mi).newNs).prefix) != 0
                            {
                                shadowed = 1 as libc::c_int;
                                break;
                            } else {
                                mi = (*mi).next;
                            }
                        }
                    }
                    mi = xmlDOMWrapNsMapAddItem(
                        map,
                        0 as libc::c_int,
                        0 as xmlNsPtr,
                        ns,
                        -(1 as libc::c_int),
                    );
                    if mi.is_null() {
                        return -(1 as libc::c_int);
                    }
                    if shadowed != 0 {
                        (*mi).shadowDepth = 0 as libc::c_int;
                    }
                    ns = (*ns).next;
                    if ns.is_null() {
                        break;
                    }
                }
            }
        }
        cur = (*cur).parent;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlDOMWrapNSNormAddNsMapItem2(
    mut list: *mut *mut xmlNsPtr,
    mut size: *mut libc::c_int,
    mut number: *mut libc::c_int,
    mut oldNs: xmlNsPtr,
    mut newNs: xmlNsPtr,
) -> libc::c_int {
    if (*list).is_null() {
        *list = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            (6 as libc::c_int as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as libc::c_ulong),
        ) as *mut xmlNsPtr;
        if (*list).is_null() {
            xmlTreeErrMemory(b"alloc ns map item\0" as *const u8 as *const libc::c_char);
            return -(1 as libc::c_int);
        }
        *size = 3 as libc::c_int;
        *number = 0 as libc::c_int;
    } else if *number >= *size {
        *size *= 2 as libc::c_int;
        *list = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            *list as *mut libc::c_void,
            ((*size * 2 as libc::c_int) as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as libc::c_ulong),
        ) as *mut xmlNsPtr;
        if (*list).is_null() {
            xmlTreeErrMemory(
                b"realloc ns map item\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
    }
    let ref mut fresh369 = *(*list).offset((2 as libc::c_int * *number) as isize);
    *fresh369 = oldNs;
    let ref mut fresh370 = *(*list)
        .offset((2 as libc::c_int * *number + 1 as libc::c_int) as isize);
    *fresh370 = newNs;
    *number += 1;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDOMWrapRemoveNode(
    mut ctxt: xmlDOMWrapCtxtPtr,
    mut doc: xmlDocPtr,
    mut node: xmlNodePtr,
    mut options: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut list: *mut xmlNsPtr = 0 as *mut xmlNsPtr;
    let mut sizeList: libc::c_int = 0;
    let mut nbList: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    if node.is_null() || doc.is_null() || (*node).doc != doc {
        return -(1 as libc::c_int);
    }
    if ((*node).parent).is_null() {
        return 0 as libc::c_int;
    }
    match (*node).type_0 as libc::c_uint {
        3 | 4 | 5 | 7 | 8 => {
            xmlUnlinkNode(node);
            return 0 as libc::c_int;
        }
        1 | 2 => {}
        _ => return 1 as libc::c_int,
    }
    xmlUnlinkNode(node);
    's_67: loop {
        match (*node).type_0 as libc::c_uint {
            1 => {
                if ctxt.is_null() && !((*node).nsDef).is_null() {
                    ns = (*node).nsDef;
                    loop {
                        if xmlDOMWrapNSNormAddNsMapItem2(
                            &mut list,
                            &mut sizeList,
                            &mut nbList,
                            ns,
                            ns,
                        ) == -(1 as libc::c_int)
                        {
                            current_block = 1967415137939254181;
                            break 's_67;
                        }
                        ns = (*ns).next;
                        if ns.is_null() {
                            break;
                        }
                    }
                    current_block = 2762306430282308233;
                } else {
                    current_block = 2762306430282308233;
                }
            }
            2 => {
                current_block = 2762306430282308233;
            }
            _ => {
                current_block = 17781479925825957363;
            }
        }
        match current_block {
            2762306430282308233 => {
                if !((*node).ns).is_null() {
                    if !list.is_null() {
                        i = 0 as libc::c_int;
                        j = 0 as libc::c_int;
                        loop {
                            if !(i < nbList) {
                                current_block = 3437258052017859086;
                                break;
                            }
                            if (*node).ns == *list.offset(j as isize) {
                                j += 1;
                                let ref mut fresh371 = (*node).ns;
                                *fresh371 = *list.offset(j as isize);
                                current_block = 7143145737794049375;
                                break;
                            } else {
                                i += 1;
                                j += 2 as libc::c_int;
                            }
                        }
                    } else {
                        current_block = 3437258052017859086;
                    }
                    match current_block {
                        7143145737794049375 => {}
                        _ => {
                            ns = 0 as xmlNsPtr;
                            if ctxt.is_null() {
                                ns = xmlDOMWrapStoreNs(
                                    doc,
                                    (*(*node).ns).href,
                                    (*(*node).ns).prefix,
                                );
                                if ns.is_null() {
                                    current_block = 1967415137939254181;
                                    break;
                                }
                            }
                            if !ns.is_null() {
                                if xmlDOMWrapNSNormAddNsMapItem2(
                                    &mut list,
                                    &mut sizeList,
                                    &mut nbList,
                                    (*node).ns,
                                    ns,
                                ) == -(1 as libc::c_int)
                                {
                                    current_block = 1967415137939254181;
                                    break;
                                }
                            }
                            let ref mut fresh372 = (*node).ns;
                            *fresh372 = ns;
                            current_block = 3123434771885419771;
                        }
                    }
                } else {
                    current_block = 3123434771885419771;
                }
                match current_block {
                    3123434771885419771 => {
                        if (*node).type_0 as libc::c_uint
                            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                            && !((*node).properties).is_null()
                        {
                            node = (*node).properties as xmlNodePtr;
                            current_block = 2979737022853876585;
                        } else {
                            current_block = 7143145737794049375;
                        }
                    }
                    _ => {}
                }
                match current_block {
                    2979737022853876585 => {}
                    _ => {
                        if (*node).type_0 as libc::c_uint
                            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                            && !((*node).children).is_null()
                        {
                            node = (*node).children;
                            current_block = 2979737022853876585;
                        } else {
                            current_block = 17781479925825957363;
                        }
                    }
                }
            }
            _ => {}
        }
        loop {
            match current_block {
                2979737022853876585 => {
                    if !node.is_null() {
                        break;
                    } else {
                        current_block = 10095721787123848864;
                        break 's_67;
                    }
                }
                _ => {
                    if node.is_null() {
                        current_block = 10095721787123848864;
                        break 's_67;
                    }
                    if !((*node).next).is_null() {
                        node = (*node).next;
                        current_block = 2979737022853876585;
                    } else {
                        node = (*node).parent;
                        current_block = 17781479925825957363;
                    }
                }
            }
        }
    }
    match current_block {
        1967415137939254181 => {
            if !list.is_null() {
                xmlFree.expect("non-null function pointer")(list as *mut libc::c_void);
            }
            return -(1 as libc::c_int);
        }
        _ => {
            if !list.is_null() {
                xmlFree.expect("non-null function pointer")(list as *mut libc::c_void);
            }
            return 0 as libc::c_int;
        }
    };
}
unsafe extern "C" fn xmlSearchNsByNamespaceStrict(
    mut doc: xmlDocPtr,
    mut node: xmlNodePtr,
    mut nsName: *const xmlChar,
    mut retNs: *mut xmlNsPtr,
    mut prefixed: libc::c_int,
) -> libc::c_int {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut prev: xmlNodePtr = 0 as xmlNodePtr;
    let mut out: xmlNodePtr = 0 as xmlNodePtr;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut prevns: xmlNsPtr = 0 as *mut xmlNs;
    if doc.is_null() || nsName.is_null() || retNs.is_null() {
        return -(1 as libc::c_int);
    }
    if node.is_null()
        || (*node).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    *retNs = 0 as xmlNsPtr;
    if xmlStrEqual(
        nsName,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
            as *const xmlChar,
    ) != 0
    {
        *retNs = xmlTreeEnsureXMLDecl(doc);
        if (*retNs).is_null() {
            return -(1 as libc::c_int);
        }
        return 1 as libc::c_int;
    }
    cur = node;
    loop {
        if (*cur).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            if !((*cur).nsDef).is_null() {
                let mut current_block_20: u64;
                ns = (*cur).nsDef;
                while !ns.is_null() {
                    if !(prefixed != 0 && ((*ns).prefix).is_null()) {
                        if !prev.is_null() {
                            prevns = (*prev).nsDef;
                            while !((*prevns).prefix == (*ns).prefix
                                || !((*prevns).prefix).is_null()
                                    && !((*ns).prefix).is_null()
                                    && xmlStrEqual((*prevns).prefix, (*ns).prefix) != 0)
                            {
                                prevns = (*prevns).next;
                                if prevns.is_null() {
                                    break;
                                }
                            }
                            if !prevns.is_null() {
                                current_block_20 = 12349973810996921269;
                            } else {
                                current_block_20 = 2719512138335094285;
                            }
                        } else {
                            current_block_20 = 2719512138335094285;
                        }
                        match current_block_20 {
                            12349973810996921269 => {}
                            _ => {
                                if nsName == (*ns).href
                                    || xmlStrEqual(nsName, (*ns).href) != 0
                                {
                                    if !out.is_null() {
                                        let mut ret: libc::c_int = 0;
                                        ret = xmlNsInScope(doc, node, prev, (*ns).prefix);
                                        if ret < 0 as libc::c_int {
                                            return -(1 as libc::c_int);
                                        }
                                        if ret == 0 {
                                            current_block_20 = 12349973810996921269;
                                        } else {
                                            current_block_20 = 17281240262373992796;
                                        }
                                    } else {
                                        current_block_20 = 17281240262373992796;
                                    }
                                    match current_block_20 {
                                        12349973810996921269 => {}
                                        _ => {
                                            *retNs = ns;
                                            return 1 as libc::c_int;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    ns = (*ns).next;
                }
                out = prev;
                prev = cur;
            }
        } else if (*cur).type_0 as libc::c_uint
                == XML_ENTITY_NODE as libc::c_int as libc::c_uint
                || (*cur).type_0 as libc::c_uint
                    == XML_ENTITY_DECL as libc::c_int as libc::c_uint
            {
            return 0 as libc::c_int
        }
        cur = (*cur).parent;
        if !(!cur.is_null() && (*cur).doc != cur as xmlDocPtr) {
            break;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlSearchNsByPrefixStrict(
    mut doc: xmlDocPtr,
    mut node: xmlNodePtr,
    mut prefix: *const xmlChar,
    mut retNs: *mut xmlNsPtr,
) -> libc::c_int {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    if doc.is_null() || node.is_null()
        || (*node).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    if !retNs.is_null() {
        *retNs = 0 as xmlNsPtr;
    }
    if !prefix.is_null()
        && *prefix.offset(0 as libc::c_int as isize) as libc::c_int == 'x' as i32
        && *prefix.offset(1 as libc::c_int as isize) as libc::c_int == 'm' as i32
        && *prefix.offset(2 as libc::c_int as isize) as libc::c_int == 'l' as i32
        && *prefix.offset(3 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
    {
        if !retNs.is_null() {
            *retNs = xmlTreeEnsureXMLDecl(doc);
            if (*retNs).is_null() {
                return -(1 as libc::c_int);
            }
        }
        return 1 as libc::c_int;
    }
    cur = node;
    loop {
        if (*cur).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            if !((*cur).nsDef).is_null() {
                ns = (*cur).nsDef;
                loop {
                    if prefix == (*ns).prefix || xmlStrEqual(prefix, (*ns).prefix) != 0 {
                        if ((*ns).href).is_null() {
                            return 0 as libc::c_int;
                        }
                        if !retNs.is_null() {
                            *retNs = ns;
                        }
                        return 1 as libc::c_int;
                    }
                    ns = (*ns).next;
                    if ns.is_null() {
                        break;
                    }
                }
            }
        } else if (*cur).type_0 as libc::c_uint
                == XML_ENTITY_NODE as libc::c_int as libc::c_uint
                || (*cur).type_0 as libc::c_uint
                    == XML_ENTITY_DECL as libc::c_int as libc::c_uint
            {
            return 0 as libc::c_int
        }
        cur = (*cur).parent;
        if !(!cur.is_null() && (*cur).doc != cur as xmlDocPtr) {
            break;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlDOMWrapNSNormDeclareNsForced(
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
    mut nsName: *const xmlChar,
    mut prefix: *const xmlChar,
    mut checkShadow: libc::c_int,
) -> xmlNsPtr {
    let mut current_block: u64;
    let mut ret: xmlNsPtr = 0 as *mut xmlNs;
    let mut buf: [libc::c_char; 50] = [0; 50];
    let mut pref: *const xmlChar = 0 as *const xmlChar;
    let mut counter: libc::c_int = 0 as libc::c_int;
    if doc.is_null() || elem.is_null()
        || (*elem).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        return 0 as xmlNsPtr;
    }
    pref = prefix;
    loop {
        if !(!((*elem).nsDef).is_null()
            && !(xmlTreeNSListLookupByPrefix((*elem).nsDef, pref)).is_null())
        {
            if checkShadow != 0 && !((*elem).parent).is_null()
                && (*(*elem).parent).doc as xmlNodePtr != (*elem).parent
            {
                if xmlSearchNsByPrefixStrict(
                    doc,
                    (*elem).parent,
                    pref,
                    0 as *mut xmlNsPtr,
                ) == 1 as libc::c_int
                {
                    current_block = 15495627227377452971;
                } else {
                    current_block = 1394248824506584008;
                }
            } else {
                current_block = 1394248824506584008;
            }
            match current_block {
                15495627227377452971 => {}
                _ => {
                    ret = xmlNewNs(0 as xmlNodePtr, nsName, pref);
                    if ret.is_null() {
                        return 0 as xmlNsPtr;
                    }
                    if ((*elem).nsDef).is_null() {
                        let ref mut fresh373 = (*elem).nsDef;
                        *fresh373 = ret;
                    } else {
                        let mut ns2: xmlNsPtr = (*elem).nsDef;
                        while !((*ns2).next).is_null() {
                            ns2 = (*ns2).next;
                        }
                        let ref mut fresh374 = (*ns2).next;
                        *fresh374 = ret;
                    }
                    return ret;
                }
            }
        }
        counter += 1;
        if counter > 1000 as libc::c_int {
            return 0 as xmlNsPtr;
        }
        if prefix.is_null() {
            snprintf(
                buf.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 50]>() as libc::c_ulong,
                b"ns_%d\0" as *const u8 as *const libc::c_char,
                counter,
            );
        } else {
            snprintf(
                buf.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 50]>() as libc::c_ulong,
                b"%.30s_%d\0" as *const u8 as *const libc::c_char,
                prefix as *mut libc::c_char,
                counter,
            );
        }
        pref = buf.as_mut_ptr() as *mut xmlChar;
    };
}
unsafe extern "C" fn xmlDOMWrapNSNormAcquireNormalizedNs(
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
    mut ns: xmlNsPtr,
    mut retNs: *mut xmlNsPtr,
    mut nsMap: *mut xmlNsMapPtr,
    mut depth: libc::c_int,
    mut ancestorsOnly: libc::c_int,
    mut prefixed: libc::c_int,
) -> libc::c_int {
    let mut mi: xmlNsMapItemPtr = 0 as *mut xmlNsMapItem;
    if doc.is_null() || ns.is_null() || retNs.is_null() || nsMap.is_null() {
        return -(1 as libc::c_int);
    }
    *retNs = 0 as xmlNsPtr;
    if !((*ns).prefix).is_null()
        && *((*ns).prefix).offset(0 as libc::c_int as isize) as libc::c_int == 'x' as i32
        && *((*ns).prefix).offset(1 as libc::c_int as isize) as libc::c_int == 'm' as i32
        && *((*ns).prefix).offset(2 as libc::c_int as isize) as libc::c_int == 'l' as i32
        && *((*ns).prefix).offset(3 as libc::c_int as isize) as libc::c_int
            == 0 as libc::c_int
    {
        *retNs = xmlTreeEnsureXMLDecl(doc);
        if (*retNs).is_null() {
            return -(1 as libc::c_int);
        }
        return 0 as libc::c_int;
    }
    if !(*nsMap).is_null() && !((**nsMap).first).is_null()
        && !(ancestorsOnly != 0 && elem.is_null())
    {
        mi = (**nsMap).first;
        while !mi.is_null() {
            if (*mi).depth >= -(1 as libc::c_int)
                && (ancestorsOnly == 0 || (*mi).depth == -(1 as libc::c_int))
                && (*mi).shadowDepth == -(1 as libc::c_int)
                && (!((*(*mi).newNs).href).is_null()
                    && *((*(*mi).newNs).href).offset(0 as libc::c_int as isize)
                        as libc::c_int != 0 as libc::c_int)
                && (prefixed == 0 || !((*(*mi).newNs).prefix).is_null())
                && ((*(*mi).newNs).href == (*ns).href
                    || xmlStrEqual((*(*mi).newNs).href, (*ns).href) != 0)
            {
                let ref mut fresh375 = (*mi).oldNs;
                *fresh375 = ns;
                *retNs = (*mi).newNs;
                return 0 as libc::c_int;
            }
            mi = (*mi).next;
        }
    }
    if elem.is_null() {
        let mut tmpns: xmlNsPtr = 0 as *mut xmlNs;
        tmpns = xmlDOMWrapStoreNs(doc, (*ns).href, (*ns).prefix);
        if tmpns.is_null() {
            return -(1 as libc::c_int);
        }
        if (xmlDOMWrapNsMapAddItem(
            nsMap,
            -(1 as libc::c_int),
            ns,
            tmpns,
            -(3 as libc::c_int),
        ))
            .is_null()
        {
            xmlFreeNs(tmpns);
            return -(1 as libc::c_int);
        }
        *retNs = tmpns;
    } else {
        let mut tmpns_0: xmlNsPtr = 0 as *mut xmlNs;
        tmpns_0 = xmlDOMWrapNSNormDeclareNsForced(
            doc,
            elem,
            (*ns).href,
            (*ns).prefix,
            0 as libc::c_int,
        );
        if tmpns_0.is_null() {
            return -(1 as libc::c_int);
        }
        if !(*nsMap).is_null() {
            mi = (**nsMap).first;
            while !mi.is_null() {
                if (*mi).depth < depth && (*mi).shadowDepth == -(1 as libc::c_int)
                    && ((*ns).prefix == (*(*mi).newNs).prefix
                        || xmlStrEqual((*ns).prefix, (*(*mi).newNs).prefix) != 0)
                {
                    (*mi).shadowDepth = depth;
                    break;
                } else {
                    mi = (*mi).next;
                }
            }
        }
        if (xmlDOMWrapNsMapAddItem(nsMap, -(1 as libc::c_int), ns, tmpns_0, depth))
            .is_null()
        {
            xmlFreeNs(tmpns_0);
            return -(1 as libc::c_int);
        }
        *retNs = tmpns_0;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDOMWrapReconcileNamespaces(
    mut ctxt: xmlDOMWrapCtxtPtr,
    mut elem: xmlNodePtr,
    mut options: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut depth: libc::c_int = -(1 as libc::c_int);
    let mut adoptns: libc::c_int = 0 as libc::c_int;
    let mut parnsdone: libc::c_int = 0 as libc::c_int;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut prevns: xmlNsPtr = 0 as *mut xmlNs;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut curElem: xmlNodePtr = 0 as xmlNodePtr;
    let mut nsMap: xmlNsMapPtr = 0 as xmlNsMapPtr;
    let mut mi: xmlNsMapItemPtr = 0 as *mut xmlNsMapItem;
    let mut ancestorsOnly: libc::c_int = 0 as libc::c_int;
    let mut optRemoveRedundantNS: libc::c_int = if options as xmlDOMReconcileNSOptions
        as libc::c_uint & XML_DOM_RECONNS_REMOVEREDUND as libc::c_int as libc::c_uint
        != 0
    {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    };
    let mut listRedund: *mut xmlNsPtr = 0 as *mut xmlNsPtr;
    let mut sizeRedund: libc::c_int = 0 as libc::c_int;
    let mut nbRedund: libc::c_int = 0 as libc::c_int;
    let mut ret: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    if elem.is_null() || ((*elem).doc).is_null()
        || (*elem).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    doc = (*elem).doc;
    cur = elem;
    's_51: loop {
        match (*cur).type_0 as libc::c_uint {
            1 => {
                adoptns = 1 as libc::c_int;
                curElem = cur;
                depth += 1;
                if !((*cur).nsDef).is_null() {
                    prevns = 0 as xmlNsPtr;
                    ns = (*cur).nsDef;
                    while !ns.is_null() {
                        if parnsdone == 0 {
                            if !((*elem).parent).is_null()
                                && (*(*elem).parent).doc as xmlNodePtr != (*elem).parent
                            {
                                if xmlDOMWrapNSNormGatherInScopeNs(
                                    &mut nsMap,
                                    (*elem).parent,
                                ) == -(1 as libc::c_int)
                                {
                                    current_block = 3912784260007845398;
                                    break 's_51;
                                }
                            }
                            parnsdone = 1 as libc::c_int;
                        }
                        if optRemoveRedundantNS != 0
                            && (!nsMap.is_null() && !((*nsMap).first).is_null())
                        {
                            mi = (*nsMap).first;
                            loop {
                                if mi.is_null() {
                                    current_block = 652864300344834934;
                                    break;
                                }
                                if (*mi).depth >= -(1 as libc::c_int)
                                    && (*mi).shadowDepth == -(1 as libc::c_int)
                                    && ((*ns).prefix == (*(*mi).newNs).prefix
                                        || xmlStrEqual((*ns).prefix, (*(*mi).newNs).prefix) != 0)
                                    && ((*ns).href == (*(*mi).newNs).href
                                        || xmlStrEqual((*ns).href, (*(*mi).newNs).href) != 0)
                                {
                                    if xmlDOMWrapNSNormAddNsMapItem2(
                                        &mut listRedund,
                                        &mut sizeRedund,
                                        &mut nbRedund,
                                        ns,
                                        (*mi).newNs,
                                    ) == -(1 as libc::c_int)
                                    {
                                        current_block = 3912784260007845398;
                                        break 's_51;
                                    }
                                    if !prevns.is_null() {
                                        let ref mut fresh376 = (*prevns).next;
                                        *fresh376 = (*ns).next;
                                    } else {
                                        let ref mut fresh377 = (*cur).nsDef;
                                        *fresh377 = (*ns).next;
                                    }
                                    current_block = 18339261097437597264;
                                    break;
                                } else {
                                    mi = (*mi).next;
                                }
                            }
                        } else {
                            current_block = 652864300344834934;
                        }
                        match current_block {
                            652864300344834934 => {
                                if !((*cur).ns).is_null() && adoptns != 0 && (*cur).ns == ns
                                {
                                    adoptns = 0 as libc::c_int;
                                }
                                if !nsMap.is_null() && !((*nsMap).first).is_null() {
                                    mi = (*nsMap).first;
                                    while !mi.is_null() {
                                        if (*mi).depth >= -(1 as libc::c_int)
                                            && (*mi).shadowDepth == -(1 as libc::c_int)
                                            && ((*ns).prefix == (*(*mi).newNs).prefix
                                                || xmlStrEqual((*ns).prefix, (*(*mi).newNs).prefix) != 0)
                                        {
                                            (*mi).shadowDepth = depth;
                                        }
                                        mi = (*mi).next;
                                    }
                                }
                                if (xmlDOMWrapNsMapAddItem(
                                    &mut nsMap,
                                    -(1 as libc::c_int),
                                    ns,
                                    ns,
                                    depth,
                                ))
                                    .is_null()
                                {
                                    current_block = 3912784260007845398;
                                    break 's_51;
                                }
                                prevns = ns;
                            }
                            _ => {}
                        }
                        ns = (*ns).next;
                    }
                }
                if adoptns == 0 {
                    current_block = 11129218233486035409;
                } else {
                    current_block = 14349190553367373684;
                }
            }
            2 => {
                current_block = 14349190553367373684;
            }
            _ => {
                current_block = 15166383349133654314;
            }
        }
        match current_block {
            14349190553367373684 => {
                if ((*cur).ns).is_null() {
                    current_block = 11129218233486035409;
                } else {
                    if parnsdone == 0 {
                        if !((*elem).parent).is_null()
                            && (*(*elem).parent).doc as xmlNodePtr != (*elem).parent
                        {
                            if xmlDOMWrapNSNormGatherInScopeNs(
                                &mut nsMap,
                                (*elem).parent,
                            ) == -(1 as libc::c_int)
                            {
                                current_block = 3912784260007845398;
                                break;
                            }
                        }
                        parnsdone = 1 as libc::c_int;
                    }
                    if !listRedund.is_null() {
                        i = 0 as libc::c_int;
                        j = 0 as libc::c_int;
                        while i < nbRedund {
                            if (*cur).ns == *listRedund.offset(j as isize) {
                                j += 1;
                                let ref mut fresh378 = (*cur).ns;
                                *fresh378 = *listRedund.offset(j as isize);
                                break;
                            } else {
                                i += 1;
                                j += 2 as libc::c_int;
                            }
                        }
                    }
                    if !nsMap.is_null() && !((*nsMap).first).is_null() {
                        mi = (*nsMap).first;
                        loop {
                            if mi.is_null() {
                                current_block = 7189308829251266000;
                                break;
                            }
                            if (*mi).shadowDepth == -(1 as libc::c_int)
                                && (*cur).ns == (*mi).oldNs
                            {
                                let ref mut fresh379 = (*cur).ns;
                                *fresh379 = (*mi).newNs;
                                current_block = 11129218233486035409;
                                break;
                            } else {
                                mi = (*mi).next;
                            }
                        }
                    } else {
                        current_block = 7189308829251266000;
                    }
                    match current_block {
                        11129218233486035409 => {}
                        _ => {
                            if xmlDOMWrapNSNormAcquireNormalizedNs(
                                doc,
                                curElem,
                                (*cur).ns,
                                &mut ns,
                                &mut nsMap,
                                depth,
                                ancestorsOnly,
                                (if (*cur).type_0 as libc::c_uint
                                    == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
                                {
                                    1 as libc::c_int
                                } else {
                                    0 as libc::c_int
                                }),
                            ) == -(1 as libc::c_int)
                            {
                                current_block = 3912784260007845398;
                                break;
                            }
                            let ref mut fresh380 = (*cur).ns;
                            *fresh380 = ns;
                            current_block = 11129218233486035409;
                        }
                    }
                }
            }
            _ => {}
        }
        match current_block {
            11129218233486035409 => {
                if (*cur).type_0 as libc::c_uint
                    == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                    && !((*cur).properties).is_null()
                {
                    cur = (*cur).properties as xmlNodePtr;
                    current_block = 1394248824506584008;
                } else {
                    current_block = 456721507831113532;
                }
            }
            _ => {}
        }
        loop {
            match current_block {
                1394248824506584008 => {
                    if !cur.is_null() {
                        break;
                    } else {
                        current_block = 7739940392431776979;
                        break 's_51;
                    }
                }
                15166383349133654314 => {
                    if cur == elem {
                        current_block = 7739940392431776979;
                        break 's_51;
                    }
                    if (*cur).type_0 as libc::c_uint
                        == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                    {
                        if !nsMap.is_null() && !((*nsMap).first).is_null() {
                            while !((*nsMap).last).is_null()
                                && (*(*nsMap).last).depth >= depth
                            {
                                mi = (*nsMap).last;
                                let ref mut fresh381 = (*nsMap).last;
                                *fresh381 = (*mi).prev;
                                if ((*nsMap).last).is_null() {
                                    let ref mut fresh382 = (*nsMap).first;
                                    *fresh382 = 0 as xmlNsMapItemPtr;
                                } else {
                                    let ref mut fresh383 = (*(*nsMap).last).next;
                                    *fresh383 = 0 as xmlNsMapItemPtr;
                                }
                                let ref mut fresh384 = (*mi).next;
                                *fresh384 = (*nsMap).pool;
                                let ref mut fresh385 = (*nsMap).pool;
                                *fresh385 = mi;
                            }
                            mi = (*nsMap).first;
                            while !mi.is_null() {
                                if (*mi).shadowDepth >= depth {
                                    (*mi).shadowDepth = -(1 as libc::c_int);
                                }
                                mi = (*mi).next;
                            }
                        }
                        depth -= 1;
                    }
                    if !((*cur).next).is_null() {
                        cur = (*cur).next;
                        current_block = 1394248824506584008;
                    } else if (*cur).type_0 as libc::c_uint
                            == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
                        {
                        cur = (*cur).parent;
                        current_block = 456721507831113532;
                    } else {
                        cur = (*cur).parent;
                        current_block = 15166383349133654314;
                    }
                }
                _ => {
                    if !((*cur).type_0 as libc::c_uint
                        == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                        && !((*cur).children).is_null())
                    {
                        current_block = 15166383349133654314;
                        continue;
                    }
                    cur = (*cur).children;
                    current_block = 1394248824506584008;
                }
            }
        }
    }
    match current_block {
        3912784260007845398 => {
            ret = -(1 as libc::c_int);
        }
        _ => {
            ret = 0 as libc::c_int;
        }
    }
    if !listRedund.is_null() {
        i = 0 as libc::c_int;
        j = 0 as libc::c_int;
        while i < nbRedund {
            xmlFreeNs(*listRedund.offset(j as isize));
            i += 1;
            j += 2 as libc::c_int;
        }
        xmlFree.expect("non-null function pointer")(listRedund as *mut libc::c_void);
    }
    if !nsMap.is_null() {
        xmlDOMWrapNsMapFree(nsMap);
    }
    return ret;
}
unsafe extern "C" fn xmlDOMWrapAdoptBranch(
    mut ctxt: xmlDOMWrapCtxtPtr,
    mut sourceDoc: xmlDocPtr,
    mut node: xmlNodePtr,
    mut destDoc: xmlDocPtr,
    mut destParent: xmlNodePtr,
    mut options: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut curElem: xmlNodePtr = 0 as xmlNodePtr;
    let mut nsMap: xmlNsMapPtr = 0 as xmlNsMapPtr;
    let mut mi: xmlNsMapItemPtr = 0 as *mut xmlNsMapItem;
    let mut ns: xmlNsPtr = 0 as xmlNsPtr;
    let mut depth: libc::c_int = -(1 as libc::c_int);
    let mut adoptStr: libc::c_int = 1 as libc::c_int;
    let mut parnsdone: libc::c_int = 0;
    let mut ancestorsOnly: libc::c_int = 0 as libc::c_int;
    if !sourceDoc.is_null() && (*sourceDoc).dict == (*destDoc).dict {
        adoptStr = 0 as libc::c_int;
    } else {
        adoptStr = 1 as libc::c_int;
    }
    if !ctxt.is_null() {
        nsMap = (*ctxt).namespaceMap as xmlNsMapPtr;
    }
    if destParent.is_null() || !ctxt.is_null() && ((*ctxt).getNsForNodeFunc).is_some() {
        parnsdone = 1 as libc::c_int;
    } else {
        parnsdone = 0 as libc::c_int;
    }
    cur = node;
    if !cur.is_null()
        && (*cur).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        current_block = 11057361962272637943;
    } else {
        current_block = 17860125682698302841;
    }
    'c_44681: loop {
        match current_block {
            11057361962272637943 => {
                ret = -(1 as libc::c_int);
                break;
            }
            _ => {
                if cur.is_null() {
                    break;
                }
                if (*cur).doc != sourceDoc {
                    if ((*cur).next).is_null() {
                        current_block = 16447908953907659923;
                    } else {
                        loop {
                            cur = (*cur).next;
                            if (*cur).type_0 as libc::c_uint
                                == XML_XINCLUDE_END as libc::c_int as libc::c_uint
                                || (*cur).doc == (*node).doc
                            {
                                break;
                            }
                            if ((*cur).next).is_null() {
                                break;
                            }
                        }
                        if (*cur).doc != (*node).doc {
                            current_block = 16447908953907659923;
                        } else {
                            current_block = 11298138898191919651;
                        }
                    }
                } else {
                    current_block = 11298138898191919651;
                }
                match current_block {
                    11298138898191919651 => {
                        let ref mut fresh386 = (*cur).doc;
                        *fresh386 = destDoc;
                        match (*cur).type_0 as libc::c_uint {
                            19 | 20 => return -(1 as libc::c_int),
                            1 => {
                                curElem = cur;
                                depth += 1;
                                if !((*cur).nsDef).is_null()
                                    && (ctxt.is_null() || ((*ctxt).getNsForNodeFunc).is_none())
                                {
                                    if parnsdone == 0 {
                                        if xmlDOMWrapNSNormGatherInScopeNs(&mut nsMap, destParent)
                                            == -(1 as libc::c_int)
                                        {
                                            current_block = 11057361962272637943;
                                            continue;
                                        }
                                        parnsdone = 1 as libc::c_int;
                                    }
                                    ns = (*cur).nsDef;
                                    while !ns.is_null() {
                                        if !nsMap.is_null() && !((*nsMap).first).is_null() {
                                            mi = (*nsMap).first;
                                            while !mi.is_null() {
                                                if (*mi).depth >= -(1 as libc::c_int)
                                                    && (*mi).shadowDepth == -(1 as libc::c_int)
                                                    && ((*ns).prefix == (*(*mi).newNs).prefix
                                                        || xmlStrEqual((*ns).prefix, (*(*mi).newNs).prefix) != 0)
                                                {
                                                    (*mi).shadowDepth = depth;
                                                }
                                                mi = (*mi).next;
                                            }
                                        }
                                        if (xmlDOMWrapNsMapAddItem(
                                            &mut nsMap,
                                            -(1 as libc::c_int),
                                            ns,
                                            ns,
                                            depth,
                                        ))
                                            .is_null()
                                        {
                                            current_block = 11057361962272637943;
                                            continue 'c_44681;
                                        }
                                        ns = (*ns).next;
                                    }
                                }
                                current_block = 14835353632257566941;
                            }
                            2 => {
                                current_block = 14835353632257566941;
                            }
                            3 | 4 => {
                                if adoptStr != 0 && !((*cur).content).is_null()
                                    && !sourceDoc.is_null() && !((*sourceDoc).dict).is_null()
                                    && xmlDictOwns((*sourceDoc).dict, (*cur).content) != 0
                                {
                                    if !((*destDoc).dict).is_null() {
                                        let ref mut fresh394 = (*cur).content;
                                        *fresh394 = xmlDictLookup(
                                            (*destDoc).dict,
                                            (*cur).content,
                                            -(1 as libc::c_int),
                                        ) as *mut xmlChar;
                                    } else {
                                        let ref mut fresh395 = (*cur).content;
                                        *fresh395 = xmlStrdup((*cur).content);
                                    }
                                }
                                current_block = 16447908953907659923;
                            }
                            5 => {
                                let ref mut fresh396 = (*cur).content;
                                *fresh396 = 0 as *mut xmlChar;
                                let ref mut fresh397 = (*cur).children;
                                *fresh397 = 0 as *mut _xmlNode;
                                let ref mut fresh398 = (*cur).last;
                                *fresh398 = 0 as *mut _xmlNode;
                                if !((*destDoc).intSubset).is_null()
                                    || !((*destDoc).extSubset).is_null()
                                {
                                    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
                                    ent = xmlGetDocEntity(
                                        destDoc as *const xmlDoc,
                                        (*cur).name,
                                    );
                                    if !ent.is_null() {
                                        let ref mut fresh399 = (*cur).content;
                                        *fresh399 = (*ent).content;
                                        let ref mut fresh400 = (*cur).children;
                                        *fresh400 = ent as xmlNodePtr;
                                        let ref mut fresh401 = (*cur).last;
                                        *fresh401 = ent as xmlNodePtr;
                                    }
                                }
                                current_block = 16447908953907659923;
                            }
                            7 => {
                                if adoptStr != 0 && !((*cur).name).is_null() {
                                    if !((*destDoc).dict).is_null() {
                                        let mut old_0: *const xmlChar = (*cur).name;
                                        let ref mut fresh402 = (*cur).name;
                                        *fresh402 = xmlDictLookup(
                                            (*destDoc).dict,
                                            (*cur).name,
                                            -(1 as libc::c_int),
                                        );
                                        if sourceDoc.is_null() || ((*sourceDoc).dict).is_null()
                                            || xmlDictOwns((*sourceDoc).dict, old_0) == 0
                                        {
                                            xmlFree
                                                .expect(
                                                    "non-null function pointer",
                                                )(old_0 as *mut libc::c_char as *mut libc::c_void);
                                        }
                                    } else if !sourceDoc.is_null()
                                            && !((*sourceDoc).dict).is_null()
                                            && xmlDictOwns((*sourceDoc).dict, (*cur).name) != 0
                                        {
                                        let ref mut fresh403 = (*cur).name;
                                        *fresh403 = xmlStrdup((*cur).name);
                                    }
                                }
                                if adoptStr != 0 && !((*cur).content).is_null()
                                    && !sourceDoc.is_null() && !((*sourceDoc).dict).is_null()
                                    && xmlDictOwns((*sourceDoc).dict, (*cur).content) != 0
                                {
                                    if !((*destDoc).dict).is_null() {
                                        let ref mut fresh404 = (*cur).content;
                                        *fresh404 = xmlDictLookup(
                                            (*destDoc).dict,
                                            (*cur).content,
                                            -(1 as libc::c_int),
                                        ) as *mut xmlChar;
                                    } else {
                                        let ref mut fresh405 = (*cur).content;
                                        *fresh405 = xmlStrdup((*cur).content);
                                    }
                                }
                                current_block = 11162283542402356847;
                            }
                            8 => {
                                current_block = 11162283542402356847;
                            }
                            _ => {
                                current_block = 11057361962272637943;
                                continue;
                            }
                        }
                        match current_block {
                            16447908953907659923 => {}
                            _ => {
                                match current_block {
                                    14835353632257566941 => {
                                        if !((*cur).ns).is_null() {
                                            if parnsdone == 0 {
                                                if xmlDOMWrapNSNormGatherInScopeNs(&mut nsMap, destParent)
                                                    == -(1 as libc::c_int)
                                                {
                                                    current_block = 11057361962272637943;
                                                    continue;
                                                }
                                                parnsdone = 1 as libc::c_int;
                                            }
                                            if !nsMap.is_null() && !((*nsMap).first).is_null() {
                                                mi = (*nsMap).first;
                                                loop {
                                                    if mi.is_null() {
                                                        current_block = 2520131295878969859;
                                                        break;
                                                    }
                                                    if (*mi).shadowDepth == -(1 as libc::c_int)
                                                        && (*cur).ns == (*mi).oldNs
                                                    {
                                                        let ref mut fresh387 = (*cur).ns;
                                                        *fresh387 = (*mi).newNs;
                                                        current_block = 4936991246711566589;
                                                        break;
                                                    } else {
                                                        mi = (*mi).next;
                                                    }
                                                }
                                            } else {
                                                current_block = 2520131295878969859;
                                            }
                                            match current_block {
                                                4936991246711566589 => {}
                                                _ => {
                                                    if !ctxt.is_null() && ((*ctxt).getNsForNodeFunc).is_some() {
                                                        ns = ((*ctxt).getNsForNodeFunc)
                                                            .expect(
                                                                "non-null function pointer",
                                                            )(ctxt, cur, (*(*cur).ns).href, (*(*cur).ns).prefix);
                                                        if (xmlDOMWrapNsMapAddItem(
                                                            &mut nsMap,
                                                            -(1 as libc::c_int),
                                                            (*cur).ns,
                                                            ns,
                                                            -(4 as libc::c_int),
                                                        ))
                                                            .is_null()
                                                        {
                                                            current_block = 11057361962272637943;
                                                            continue;
                                                        }
                                                        let ref mut fresh388 = (*cur).ns;
                                                        *fresh388 = ns;
                                                    } else {
                                                        if xmlDOMWrapNSNormAcquireNormalizedNs(
                                                            destDoc,
                                                            (if !destParent.is_null() {
                                                                curElem
                                                            } else {
                                                                0 as xmlNodePtr
                                                            }),
                                                            (*cur).ns,
                                                            &mut ns,
                                                            &mut nsMap,
                                                            depth,
                                                            ancestorsOnly,
                                                            (if (*cur).type_0 as libc::c_uint
                                                                == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
                                                            {
                                                                1 as libc::c_int
                                                            } else {
                                                                0 as libc::c_int
                                                            }),
                                                        ) == -(1 as libc::c_int)
                                                        {
                                                            current_block = 11057361962272637943;
                                                            continue;
                                                        }
                                                        let ref mut fresh389 = (*cur).ns;
                                                        *fresh389 = ns;
                                                    }
                                                }
                                            }
                                        }
                                        if adoptStr != 0 && !((*cur).name).is_null() {
                                            if !((*destDoc).dict).is_null() {
                                                let mut old: *const xmlChar = (*cur).name;
                                                let ref mut fresh390 = (*cur).name;
                                                *fresh390 = xmlDictLookup(
                                                    (*destDoc).dict,
                                                    (*cur).name,
                                                    -(1 as libc::c_int),
                                                );
                                                if sourceDoc.is_null() || ((*sourceDoc).dict).is_null()
                                                    || xmlDictOwns((*sourceDoc).dict, old) == 0
                                                {
                                                    xmlFree
                                                        .expect(
                                                            "non-null function pointer",
                                                        )(old as *mut libc::c_char as *mut libc::c_void);
                                                }
                                            } else if !sourceDoc.is_null()
                                                    && !((*sourceDoc).dict).is_null()
                                                    && xmlDictOwns((*sourceDoc).dict, (*cur).name) != 0
                                                {
                                                let ref mut fresh391 = (*cur).name;
                                                *fresh391 = xmlStrdup((*cur).name);
                                            }
                                        }
                                        if (*cur).type_0 as libc::c_uint
                                            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                                        {
                                            let ref mut fresh392 = (*cur).psvi;
                                            *fresh392 = 0 as *mut libc::c_void;
                                            (*cur).line = 0 as libc::c_int as libc::c_ushort;
                                            (*cur).extra = 0 as libc::c_int as libc::c_ushort;
                                            if !((*cur).properties).is_null() {
                                                cur = (*cur).properties as xmlNodePtr;
                                                current_block = 17860125682698302841;
                                                continue;
                                            }
                                        } else {
                                            if !sourceDoc.is_null()
                                                && (*(cur as xmlAttrPtr)).atype as libc::c_uint
                                                    == XML_ATTRIBUTE_ID as libc::c_int as libc::c_uint
                                            {
                                                xmlRemoveID(sourceDoc, cur as xmlAttrPtr);
                                            }
                                            (*(cur as xmlAttrPtr)).atype = 0 as xmlAttributeType;
                                            let ref mut fresh393 = (*(cur as xmlAttrPtr)).psvi;
                                            *fresh393 = 0 as *mut libc::c_void;
                                        }
                                    }
                                    _ => {}
                                }
                                if !((*cur).children).is_null() {
                                    cur = (*cur).children;
                                    current_block = 17860125682698302841;
                                    continue;
                                }
                            }
                        }
                    }
                    _ => {}
                }
                loop {
                    if cur == node {
                        break 'c_44681;
                    }
                    if (*cur).type_0 as libc::c_uint
                        == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                        || (*cur).type_0 as libc::c_uint
                            == XML_XINCLUDE_START as libc::c_int as libc::c_uint
                        || (*cur).type_0 as libc::c_uint
                            == XML_XINCLUDE_END as libc::c_int as libc::c_uint
                    {
                        if !nsMap.is_null() && !((*nsMap).first).is_null() {
                            while !((*nsMap).last).is_null()
                                && (*(*nsMap).last).depth >= depth
                            {
                                mi = (*nsMap).last;
                                let ref mut fresh406 = (*nsMap).last;
                                *fresh406 = (*mi).prev;
                                if ((*nsMap).last).is_null() {
                                    let ref mut fresh407 = (*nsMap).first;
                                    *fresh407 = 0 as xmlNsMapItemPtr;
                                } else {
                                    let ref mut fresh408 = (*(*nsMap).last).next;
                                    *fresh408 = 0 as xmlNsMapItemPtr;
                                }
                                let ref mut fresh409 = (*mi).next;
                                *fresh409 = (*nsMap).pool;
                                let ref mut fresh410 = (*nsMap).pool;
                                *fresh410 = mi;
                            }
                            mi = (*nsMap).first;
                            while !mi.is_null() {
                                if (*mi).shadowDepth >= depth {
                                    (*mi).shadowDepth = -(1 as libc::c_int);
                                }
                                mi = (*mi).next;
                            }
                        }
                        depth -= 1;
                    }
                    if !((*cur).next).is_null() {
                        cur = (*cur).next;
                        current_block = 17860125682698302841;
                        break;
                    } else if (*cur).type_0 as libc::c_uint
                            == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
                            && !((*(*cur).parent).children).is_null()
                        {
                        cur = (*(*cur).parent).children;
                        current_block = 17860125682698302841;
                        break;
                    } else {
                        cur = (*cur).parent;
                    }
                }
            }
        }
    }
    if !nsMap.is_null() {
        if !ctxt.is_null() && (*ctxt).namespaceMap == nsMap as *mut libc::c_void {
            if !((*nsMap).first).is_null() {
                if !((*nsMap).pool).is_null() {
                    let ref mut fresh411 = (*(*nsMap).last).next;
                    *fresh411 = (*nsMap).pool;
                }
                let ref mut fresh412 = (*nsMap).pool;
                *fresh412 = (*nsMap).first;
                let ref mut fresh413 = (*nsMap).first;
                *fresh413 = 0 as xmlNsMapItemPtr;
            }
        } else {
            xmlDOMWrapNsMapFree(nsMap);
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDOMWrapCloneNode(
    mut ctxt: xmlDOMWrapCtxtPtr,
    mut sourceDoc: xmlDocPtr,
    mut node: xmlNodePtr,
    mut resNode: *mut xmlNodePtr,
    mut destDoc: xmlDocPtr,
    mut destParent: xmlNodePtr,
    mut deep: libc::c_int,
    mut options: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut curElem: xmlNodePtr = 0 as xmlNodePtr;
    let mut nsMap: xmlNsMapPtr = 0 as xmlNsMapPtr;
    let mut mi: xmlNsMapItemPtr = 0 as *mut xmlNsMapItem;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut depth: libc::c_int = -(1 as libc::c_int);
    let mut parnsdone: libc::c_int = 0 as libc::c_int;
    let mut ancestorsOnly: libc::c_int = 0 as libc::c_int;
    let mut resultClone: xmlNodePtr = 0 as xmlNodePtr;
    let mut clone: xmlNodePtr = 0 as xmlNodePtr;
    let mut parentClone: xmlNodePtr = 0 as xmlNodePtr;
    let mut prevClone: xmlNodePtr = 0 as xmlNodePtr;
    let mut cloneNs: xmlNsPtr = 0 as xmlNsPtr;
    let mut cloneNsDefSlot: *mut xmlNsPtr = 0 as *mut xmlNsPtr;
    let mut dict: xmlDictPtr = 0 as *mut xmlDict;
    if node.is_null() || resNode.is_null() || destDoc.is_null() {
        return -(1 as libc::c_int);
    }
    if (*node).type_0 as libc::c_uint != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        return 1 as libc::c_int;
    }
    if !((*node).doc).is_null() && !sourceDoc.is_null() && (*node).doc != sourceDoc {
        return -(1 as libc::c_int);
    }
    if sourceDoc.is_null() {
        sourceDoc = (*node).doc;
    }
    if sourceDoc.is_null() {
        return -(1 as libc::c_int);
    }
    dict = (*destDoc).dict;
    if !ctxt.is_null() {
        nsMap = (*ctxt).namespaceMap as xmlNsMapPtr;
    }
    *resNode = 0 as xmlNodePtr;
    cur = node;
    if !cur.is_null()
        && (*cur).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    's_109: loop {
        if cur.is_null() {
            current_block = 11128556818017063193;
            break;
        }
        if (*cur).doc != sourceDoc {
            current_block = 9881238597775047924;
            break;
        } else {
            match (*cur).type_0 as libc::c_uint {
                19 | 20 => {
                    current_block = 9881238597775047924;
                    break;
                }
                1 | 3 | 4 | 8 | 7 | 11 | 5 | 6 => {
                    clone = xmlMalloc
                        .expect(
                            "non-null function pointer",
                        )(::std::mem::size_of::<xmlNode>() as libc::c_ulong)
                        as xmlNodePtr;
                    if clone.is_null() {
                        xmlTreeErrMemory(
                            b"xmlDOMWrapCloneNode(): allocating a node\0" as *const u8
                                as *const libc::c_char,
                        );
                        current_block = 9881238597775047924;
                        break;
                    } else {
                        memset(
                            clone as *mut libc::c_void,
                            0 as libc::c_int,
                            ::std::mem::size_of::<xmlNode>() as libc::c_ulong,
                        );
                        if !resultClone.is_null() {
                            let ref mut fresh414 = (*clone).parent;
                            *fresh414 = parentClone;
                            if !prevClone.is_null() {
                                let ref mut fresh415 = (*prevClone).next;
                                *fresh415 = clone;
                                let ref mut fresh416 = (*clone).prev;
                                *fresh416 = prevClone;
                            } else {
                                let ref mut fresh417 = (*parentClone).children;
                                *fresh417 = clone;
                            }
                        } else {
                            resultClone = clone;
                        }
                    }
                }
                2 => {
                    clone = xmlMalloc
                        .expect(
                            "non-null function pointer",
                        )(::std::mem::size_of::<xmlAttr>() as libc::c_ulong)
                        as xmlNodePtr;
                    if clone.is_null() {
                        xmlTreeErrMemory(
                            b"xmlDOMWrapCloneNode(): allocating an attr-node\0"
                                as *const u8 as *const libc::c_char,
                        );
                        current_block = 9881238597775047924;
                        break;
                    } else {
                        memset(
                            clone as *mut libc::c_void,
                            0 as libc::c_int,
                            ::std::mem::size_of::<xmlAttr>() as libc::c_ulong,
                        );
                        if !resultClone.is_null() {
                            let ref mut fresh418 = (*clone).parent;
                            *fresh418 = parentClone;
                            if !prevClone.is_null() {
                                let ref mut fresh419 = (*prevClone).next;
                                *fresh419 = clone;
                                let ref mut fresh420 = (*clone).prev;
                                *fresh420 = prevClone;
                            } else {
                                let ref mut fresh421 = (*parentClone).properties;
                                *fresh421 = clone as xmlAttrPtr;
                            }
                        } else {
                            resultClone = clone;
                        }
                    }
                }
                _ => {
                    current_block = 9881238597775047924;
                    break;
                }
            }
            (*clone).type_0 = (*cur).type_0;
            let ref mut fresh422 = (*clone).doc;
            *fresh422 = destDoc;
            if (*cur).name == xmlStringText.as_ptr() {
                let ref mut fresh423 = (*clone).name;
                *fresh423 = xmlStringText.as_ptr();
            } else if (*cur).name == xmlStringTextNoenc.as_ptr() {
                let ref mut fresh424 = (*clone).name;
                *fresh424 = xmlStringTextNoenc.as_ptr();
            } else if (*cur).name == xmlStringComment.as_ptr() {
                let ref mut fresh425 = (*clone).name;
                *fresh425 = xmlStringComment.as_ptr();
            } else if !((*cur).name).is_null() {
                if !((*cur).name).is_null() {
                    if !dict.is_null() {
                        if xmlDictOwns(dict, (*cur).name) != 0 {
                            let ref mut fresh426 = (*clone).name;
                            *fresh426 = (*cur).name;
                        } else {
                            let ref mut fresh427 = (*clone).name;
                            *fresh427 = xmlDictLookup(
                                dict,
                                (*cur).name,
                                -(1 as libc::c_int),
                            );
                        }
                    } else {
                        let ref mut fresh428 = (*clone).name;
                        *fresh428 = xmlStrdup((*cur).name) as *const xmlChar;
                    }
                }
            }
            match (*cur).type_0 as libc::c_uint {
                19 | 20 => return -(1 as libc::c_int),
                1 => {
                    curElem = cur;
                    depth += 1;
                    if !((*cur).nsDef).is_null() {
                        if parnsdone == 0 {
                            if !destParent.is_null() && ctxt.is_null() {
                                if xmlDOMWrapNSNormGatherInScopeNs(&mut nsMap, destParent)
                                    == -(1 as libc::c_int)
                                {
                                    current_block = 9881238597775047924;
                                    break;
                                }
                            }
                            parnsdone = 1 as libc::c_int;
                        }
                        cloneNsDefSlot = &mut (*clone).nsDef;
                        ns = (*cur).nsDef;
                        while !ns.is_null() {
                            cloneNs = xmlMalloc
                                .expect(
                                    "non-null function pointer",
                                )(::std::mem::size_of::<xmlNs>() as libc::c_ulong)
                                as xmlNsPtr;
                            if cloneNs.is_null() {
                                xmlTreeErrMemory(
                                    b"xmlDOMWrapCloneNode(): allocating namespace\0"
                                        as *const u8 as *const libc::c_char,
                                );
                                return -(1 as libc::c_int);
                            }
                            memset(
                                cloneNs as *mut libc::c_void,
                                0 as libc::c_int,
                                ::std::mem::size_of::<xmlNs>() as libc::c_ulong,
                            );
                            (*cloneNs).type_0 = XML_NAMESPACE_DECL;
                            if !((*ns).href).is_null() {
                                let ref mut fresh429 = (*cloneNs).href;
                                *fresh429 = xmlStrdup((*ns).href);
                            }
                            if !((*ns).prefix).is_null() {
                                let ref mut fresh430 = (*cloneNs).prefix;
                                *fresh430 = xmlStrdup((*ns).prefix);
                            }
                            *cloneNsDefSlot = cloneNs;
                            cloneNsDefSlot = &mut (*cloneNs).next;
                            if ctxt.is_null() || ((*ctxt).getNsForNodeFunc).is_none() {
                                if !nsMap.is_null() && !((*nsMap).first).is_null() {
                                    mi = (*nsMap).first;
                                    while !mi.is_null() {
                                        if (*mi).depth >= -(1 as libc::c_int)
                                            && (*mi).shadowDepth == -(1 as libc::c_int)
                                            && ((*ns).prefix == (*(*mi).newNs).prefix
                                                || xmlStrEqual((*ns).prefix, (*(*mi).newNs).prefix) != 0)
                                        {
                                            (*mi).shadowDepth = depth;
                                        }
                                        mi = (*mi).next;
                                    }
                                }
                                if (xmlDOMWrapNsMapAddItem(
                                    &mut nsMap,
                                    -(1 as libc::c_int),
                                    ns,
                                    cloneNs,
                                    depth,
                                ))
                                    .is_null()
                                {
                                    current_block = 9881238597775047924;
                                    break 's_109;
                                }
                            }
                            ns = (*ns).next;
                        }
                    }
                    current_block = 2544535129495155983;
                }
                2 => {
                    current_block = 2544535129495155983;
                }
                3 | 4 => {
                    if !((*cur).content).is_null() {
                        if !dict.is_null() {
                            if xmlDictOwns(dict, (*cur).content as *const xmlChar) != 0 {
                                let ref mut fresh431 = (*clone).content;
                                *fresh431 = (*cur).content;
                            } else {
                                let ref mut fresh432 = (*clone).content;
                                *fresh432 = xmlDictLookup(
                                    dict,
                                    (*cur).content as *const xmlChar,
                                    -(1 as libc::c_int),
                                ) as *mut xmlChar;
                            }
                        } else {
                            let ref mut fresh433 = (*clone).content;
                            *fresh433 = xmlStrdup((*cur).content as *const xmlChar);
                        }
                    }
                    current_block = 17418631935567976705;
                }
                6 => {
                    current_block = 17418631935567976705;
                }
                5 => {
                    if sourceDoc != destDoc {
                        if !((*destDoc).intSubset).is_null()
                            || !((*destDoc).extSubset).is_null()
                        {
                            let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
                            ent = xmlGetDocEntity(destDoc as *const xmlDoc, (*cur).name);
                            if !ent.is_null() {
                                let ref mut fresh434 = (*clone).content;
                                *fresh434 = (*ent).content;
                                let ref mut fresh435 = (*clone).children;
                                *fresh435 = ent as xmlNodePtr;
                                let ref mut fresh436 = (*clone).last;
                                *fresh436 = ent as xmlNodePtr;
                            }
                        }
                    } else {
                        let ref mut fresh437 = (*clone).content;
                        *fresh437 = (*cur).content;
                        let ref mut fresh438 = (*clone).children;
                        *fresh438 = (*cur).children;
                        let ref mut fresh439 = (*clone).last;
                        *fresh439 = (*cur).last;
                    }
                    current_block = 17418631935567976705;
                }
                7 => {
                    if !((*cur).content).is_null() {
                        if !dict.is_null() {
                            if xmlDictOwns(dict, (*cur).content as *const xmlChar) != 0 {
                                let ref mut fresh440 = (*clone).content;
                                *fresh440 = (*cur).content;
                            } else {
                                let ref mut fresh441 = (*clone).content;
                                *fresh441 = xmlDictLookup(
                                    dict,
                                    (*cur).content as *const xmlChar,
                                    -(1 as libc::c_int),
                                ) as *mut xmlChar;
                            }
                        } else {
                            let ref mut fresh442 = (*clone).content;
                            *fresh442 = xmlStrdup((*cur).content as *const xmlChar);
                        }
                    }
                    current_block = 17418631935567976705;
                }
                8 => {
                    if !((*cur).content).is_null() {
                        if !dict.is_null() {
                            if xmlDictOwns(dict, (*cur).content as *const xmlChar) != 0 {
                                let ref mut fresh443 = (*clone).content;
                                *fresh443 = (*cur).content;
                            } else {
                                let ref mut fresh444 = (*clone).content;
                                *fresh444 = xmlDictLookup(
                                    dict,
                                    (*cur).content as *const xmlChar,
                                    -(1 as libc::c_int),
                                ) as *mut xmlChar;
                            }
                        } else {
                            let ref mut fresh445 = (*clone).content;
                            *fresh445 = xmlStrdup((*cur).content as *const xmlChar);
                        }
                    }
                    current_block = 17418631935567976705;
                }
                _ => {
                    current_block = 9881238597775047924;
                    break;
                }
            }
            match current_block {
                2544535129495155983 => {
                    if !((*cur).ns).is_null() {
                        if parnsdone == 0 {
                            if !destParent.is_null() && ctxt.is_null() {
                                if xmlDOMWrapNSNormGatherInScopeNs(&mut nsMap, destParent)
                                    == -(1 as libc::c_int)
                                {
                                    current_block = 9881238597775047924;
                                    break;
                                }
                            }
                            parnsdone = 1 as libc::c_int;
                        }
                        if !nsMap.is_null() && !((*nsMap).first).is_null() {
                            mi = (*nsMap).first;
                            loop {
                                if mi.is_null() {
                                    current_block = 9657096306311191688;
                                    break;
                                }
                                if (*mi).shadowDepth == -(1 as libc::c_int)
                                    && (*cur).ns == (*mi).oldNs
                                {
                                    let ref mut fresh446 = (*clone).ns;
                                    *fresh446 = (*mi).newNs;
                                    current_block = 2484559367671746789;
                                    break;
                                } else {
                                    mi = (*mi).next;
                                }
                            }
                        } else {
                            current_block = 9657096306311191688;
                        }
                        match current_block {
                            2484559367671746789 => {}
                            _ => {
                                if !ctxt.is_null() && ((*ctxt).getNsForNodeFunc).is_some() {
                                    ns = ((*ctxt).getNsForNodeFunc)
                                        .expect(
                                            "non-null function pointer",
                                        )(ctxt, cur, (*(*cur).ns).href, (*(*cur).ns).prefix);
                                    if (xmlDOMWrapNsMapAddItem(
                                        &mut nsMap,
                                        -(1 as libc::c_int),
                                        (*cur).ns,
                                        ns,
                                        -(4 as libc::c_int),
                                    ))
                                        .is_null()
                                    {
                                        current_block = 9881238597775047924;
                                        break;
                                    }
                                    let ref mut fresh447 = (*clone).ns;
                                    *fresh447 = ns;
                                } else {
                                    if xmlDOMWrapNSNormAcquireNormalizedNs(
                                        destDoc,
                                        (if !destParent.is_null() {
                                            curElem
                                        } else {
                                            0 as xmlNodePtr
                                        }),
                                        (*cur).ns,
                                        &mut ns,
                                        &mut nsMap,
                                        depth,
                                        ancestorsOnly,
                                        (if (*cur).type_0 as libc::c_uint
                                            == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
                                        {
                                            1 as libc::c_int
                                        } else {
                                            0 as libc::c_int
                                        }),
                                    ) == -(1 as libc::c_int)
                                    {
                                        current_block = 9881238597775047924;
                                        break;
                                    }
                                    let ref mut fresh448 = (*clone).ns;
                                    *fresh448 = ns;
                                }
                            }
                        }
                    }
                    if (*clone).type_0 as libc::c_uint
                        == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
                        && !((*clone).parent).is_null()
                    {
                        if xmlIsID(destDoc, (*clone).parent, clone as xmlAttrPtr) != 0 {
                            let mut idVal: *mut xmlChar = 0 as *mut xmlChar;
                            idVal = xmlNodeListGetString(
                                (*cur).doc,
                                (*cur).children,
                                1 as libc::c_int,
                            );
                            if !idVal.is_null() {
                                if (xmlAddID(
                                    0 as xmlValidCtxtPtr,
                                    destDoc,
                                    idVal,
                                    cur as xmlAttrPtr,
                                ))
                                    .is_null()
                                {
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(idVal as *mut libc::c_void);
                                    current_block = 9881238597775047924;
                                    break;
                                } else {
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(idVal as *mut libc::c_void);
                                }
                            }
                        }
                    }
                    if (*cur).type_0 as libc::c_uint
                        == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                        && !((*cur).properties).is_null()
                    {
                        prevClone = 0 as xmlNodePtr;
                        parentClone = clone;
                        cur = (*cur).properties as xmlNodePtr;
                        continue;
                    } else {
                        current_block = 16134469364361965152;
                    }
                }
                _ => {}
            }
            loop {
                match current_block {
                    17418631935567976705 => {
                        if cur == node {
                            current_block = 11128556818017063193;
                            break 's_109;
                        }
                        if (*cur).type_0 as libc::c_uint
                            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                            || (*cur).type_0 as libc::c_uint
                                == XML_XINCLUDE_START as libc::c_int as libc::c_uint
                            || (*cur).type_0 as libc::c_uint
                                == XML_XINCLUDE_END as libc::c_int as libc::c_uint
                        {
                            if !nsMap.is_null() && !((*nsMap).first).is_null() {
                                while !((*nsMap).last).is_null()
                                    && (*(*nsMap).last).depth >= depth
                                {
                                    mi = (*nsMap).last;
                                    let ref mut fresh449 = (*nsMap).last;
                                    *fresh449 = (*mi).prev;
                                    if ((*nsMap).last).is_null() {
                                        let ref mut fresh450 = (*nsMap).first;
                                        *fresh450 = 0 as xmlNsMapItemPtr;
                                    } else {
                                        let ref mut fresh451 = (*(*nsMap).last).next;
                                        *fresh451 = 0 as xmlNsMapItemPtr;
                                    }
                                    let ref mut fresh452 = (*mi).next;
                                    *fresh452 = (*nsMap).pool;
                                    let ref mut fresh453 = (*nsMap).pool;
                                    *fresh453 = mi;
                                }
                                mi = (*nsMap).first;
                                while !mi.is_null() {
                                    if (*mi).shadowDepth >= depth {
                                        (*mi).shadowDepth = -(1 as libc::c_int);
                                    }
                                    mi = (*mi).next;
                                }
                            }
                            depth -= 1;
                        }
                        if !((*cur).next).is_null() {
                            prevClone = clone;
                            cur = (*cur).next;
                            break;
                        } else if (*cur).type_0 as libc::c_uint
                                != XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
                            {
                            if !((*clone).parent).is_null() {
                                let ref mut fresh454 = (*(*clone).parent).last;
                                *fresh454 = clone;
                            }
                            clone = (*clone).parent;
                            if !clone.is_null() {
                                parentClone = (*clone).parent;
                            }
                            cur = (*cur).parent;
                            current_block = 17418631935567976705;
                        } else {
                            clone = (*clone).parent;
                            parentClone = (*clone).parent;
                            cur = (*cur).parent;
                            current_block = 16134469364361965152;
                        }
                    }
                    _ => {
                        if ((*cur).children).is_null() {
                            current_block = 17418631935567976705;
                            continue;
                        }
                        if !(deep != 0
                            || (*cur).type_0 as libc::c_uint
                                == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint)
                        {
                            current_block = 17418631935567976705;
                            continue;
                        }
                        prevClone = 0 as xmlNodePtr;
                        parentClone = clone;
                        cur = (*cur).children;
                        break;
                    }
                }
            }
        }
    }
    match current_block {
        9881238597775047924 => {
            ret = -(1 as libc::c_int);
        }
        _ => {}
    }
    if !nsMap.is_null() {
        if !ctxt.is_null() && (*ctxt).namespaceMap == nsMap as *mut libc::c_void {
            if !((*nsMap).first).is_null() {
                if !((*nsMap).pool).is_null() {
                    let ref mut fresh455 = (*(*nsMap).last).next;
                    *fresh455 = (*nsMap).pool;
                }
                let ref mut fresh456 = (*nsMap).pool;
                *fresh456 = (*nsMap).first;
                let ref mut fresh457 = (*nsMap).first;
                *fresh457 = 0 as xmlNsMapItemPtr;
            }
        } else {
            xmlDOMWrapNsMapFree(nsMap);
        }
    }
    *resNode = resultClone;
    return ret;
}
unsafe extern "C" fn xmlDOMWrapAdoptAttr(
    mut ctxt: xmlDOMWrapCtxtPtr,
    mut sourceDoc: xmlDocPtr,
    mut attr: xmlAttrPtr,
    mut destDoc: xmlDocPtr,
    mut destParent: xmlNodePtr,
    mut options: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut adoptStr: libc::c_int = 1 as libc::c_int;
    if attr.is_null() || destDoc.is_null() {
        return -(1 as libc::c_int);
    }
    let ref mut fresh458 = (*attr).doc;
    *fresh458 = destDoc;
    if !((*attr).ns).is_null() {
        let mut ns: xmlNsPtr = 0 as xmlNsPtr;
        !ctxt.is_null();
        if !((*(*attr).ns).prefix).is_null()
            && *((*(*attr).ns).prefix).offset(0 as libc::c_int as isize) as libc::c_int
                == 'x' as i32
            && *((*(*attr).ns).prefix).offset(1 as libc::c_int as isize) as libc::c_int
                == 'm' as i32
            && *((*(*attr).ns).prefix).offset(2 as libc::c_int as isize) as libc::c_int
                == 'l' as i32
            && *((*(*attr).ns).prefix).offset(3 as libc::c_int as isize) as libc::c_int
                == 0 as libc::c_int
        {
            ns = xmlTreeEnsureXMLDecl(destDoc);
            current_block = 5143058163439228106;
        } else if destParent.is_null() {
            ns = xmlDOMWrapStoreNs(destDoc, (*(*attr).ns).href, (*(*attr).ns).prefix);
            current_block = 5143058163439228106;
        } else if xmlSearchNsByNamespaceStrict(
                destDoc,
                destParent,
                (*(*attr).ns).href,
                &mut ns,
                1 as libc::c_int,
            ) == -(1 as libc::c_int)
            {
            current_block = 10866158498708961612;
        } else {
            if ns.is_null() {
                ns = xmlDOMWrapNSNormDeclareNsForced(
                    destDoc,
                    destParent,
                    (*(*attr).ns).href,
                    (*(*attr).ns).prefix,
                    1 as libc::c_int,
                );
            }
            current_block = 5143058163439228106;
        }
        match current_block {
            10866158498708961612 => {}
            _ => {
                if ns.is_null() {
                    current_block = 10866158498708961612;
                } else {
                    let ref mut fresh459 = (*attr).ns;
                    *fresh459 = ns;
                    current_block = 12124785117276362961;
                }
            }
        }
    } else {
        current_block = 12124785117276362961;
    }
    match current_block {
        12124785117276362961 => {
            if adoptStr != 0 && !((*attr).name).is_null() {
                if !((*destDoc).dict).is_null() {
                    let mut old: *const xmlChar = (*attr).name;
                    let ref mut fresh460 = (*attr).name;
                    *fresh460 = xmlDictLookup(
                        (*destDoc).dict,
                        (*attr).name,
                        -(1 as libc::c_int),
                    );
                    if sourceDoc.is_null() || ((*sourceDoc).dict).is_null()
                        || xmlDictOwns((*sourceDoc).dict, old) == 0
                    {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(old as *mut libc::c_char as *mut libc::c_void);
                    }
                } else if !sourceDoc.is_null() && !((*sourceDoc).dict).is_null()
                        && xmlDictOwns((*sourceDoc).dict, (*attr).name) != 0
                    {
                    let ref mut fresh461 = (*attr).name;
                    *fresh461 = xmlStrdup((*attr).name);
                }
            }
            (*attr).atype = 0 as xmlAttributeType;
            let ref mut fresh462 = (*attr).psvi;
            *fresh462 = 0 as *mut libc::c_void;
            if ((*attr).children).is_null() {
                return 0 as libc::c_int;
            }
            cur = (*attr).children;
            if !(!cur.is_null()
                && (*cur).type_0 as libc::c_uint
                    == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint)
            {
                's_181: while !cur.is_null() {
                    let ref mut fresh463 = (*cur).doc;
                    *fresh463 = destDoc;
                    match (*cur).type_0 as libc::c_uint {
                        3 | 4 => {
                            if adoptStr != 0 && !((*cur).content).is_null()
                                && !sourceDoc.is_null() && !((*sourceDoc).dict).is_null()
                                && xmlDictOwns((*sourceDoc).dict, (*cur).content) != 0
                            {
                                if !((*destDoc).dict).is_null() {
                                    let ref mut fresh464 = (*cur).content;
                                    *fresh464 = xmlDictLookup(
                                        (*destDoc).dict,
                                        (*cur).content,
                                        -(1 as libc::c_int),
                                    ) as *mut xmlChar;
                                } else {
                                    let ref mut fresh465 = (*cur).content;
                                    *fresh465 = xmlStrdup((*cur).content);
                                }
                            }
                        }
                        5 => {
                            let ref mut fresh466 = (*cur).content;
                            *fresh466 = 0 as *mut xmlChar;
                            let ref mut fresh467 = (*cur).children;
                            *fresh467 = 0 as *mut _xmlNode;
                            let ref mut fresh468 = (*cur).last;
                            *fresh468 = 0 as *mut _xmlNode;
                            if !((*destDoc).intSubset).is_null()
                                || !((*destDoc).extSubset).is_null()
                            {
                                let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
                                ent = xmlGetDocEntity(
                                    destDoc as *const xmlDoc,
                                    (*cur).name,
                                );
                                if !ent.is_null() {
                                    let ref mut fresh469 = (*cur).content;
                                    *fresh469 = (*ent).content;
                                    let ref mut fresh470 = (*cur).children;
                                    *fresh470 = ent as xmlNodePtr;
                                    let ref mut fresh471 = (*cur).last;
                                    *fresh471 = ent as xmlNodePtr;
                                }
                            }
                        }
                        _ => {}
                    }
                    if !((*cur).children).is_null() {
                        cur = (*cur).children;
                    } else {
                        loop {
                            if cur == attr as xmlNodePtr {
                                break 's_181;
                            }
                            if !((*cur).next).is_null() {
                                break;
                            }
                            cur = (*cur).parent;
                        }
                        cur = (*cur).next;
                    }
                }
                return 0 as libc::c_int;
            }
        }
        _ => {}
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDOMWrapAdoptNode(
    mut ctxt: xmlDOMWrapCtxtPtr,
    mut sourceDoc: xmlDocPtr,
    mut node: xmlNodePtr,
    mut destDoc: xmlDocPtr,
    mut destParent: xmlNodePtr,
    mut options: libc::c_int,
) -> libc::c_int {
    if node.is_null()
        || (*node).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint || destDoc.is_null()
        || !destParent.is_null() && (*destParent).doc != destDoc
    {
        return -(1 as libc::c_int);
    }
    if !((*node).doc).is_null() && !sourceDoc.is_null() && (*node).doc != sourceDoc {
        return -(1 as libc::c_int);
    }
    if sourceDoc.is_null() {
        sourceDoc = (*node).doc;
    }
    if sourceDoc == destDoc {
        return -(1 as libc::c_int);
    }
    match (*node).type_0 as libc::c_uint {
        1 | 2 | 3 | 4 | 5 | 7 | 8 => {}
        11 => return 2 as libc::c_int,
        _ => return 1 as libc::c_int,
    }
    if !((*node).parent).is_null() && destParent != (*node).parent {
        xmlUnlinkNode(node);
    }
    if (*node).type_0 as libc::c_uint == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        return xmlDOMWrapAdoptBranch(ctxt, sourceDoc, node, destDoc, destParent, options)
    } else {
        if (*node).type_0 as libc::c_uint
            == XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
        {
            return xmlDOMWrapAdoptAttr(
                ctxt,
                sourceDoc,
                node as xmlAttrPtr,
                destDoc,
                destParent,
                options,
            )
        } else {
            let mut cur: xmlNodePtr = node;
            let mut adoptStr: libc::c_int = 1 as libc::c_int;
            let ref mut fresh472 = (*cur).doc;
            *fresh472 = destDoc;
            if !sourceDoc.is_null() && (*sourceDoc).dict == (*destDoc).dict {
                adoptStr = 0 as libc::c_int;
            }
            match (*node).type_0 as libc::c_uint {
                3 | 4 => {
                    if adoptStr != 0 && !((*node).content).is_null()
                        && !sourceDoc.is_null() && !((*sourceDoc).dict).is_null()
                        && xmlDictOwns((*sourceDoc).dict, (*cur).content) != 0
                    {
                        if !((*destDoc).dict).is_null() {
                            let ref mut fresh473 = (*cur).content;
                            *fresh473 = xmlDictLookup(
                                (*destDoc).dict,
                                (*cur).content,
                                -(1 as libc::c_int),
                            ) as *mut xmlChar;
                        } else {
                            let ref mut fresh474 = (*cur).content;
                            *fresh474 = xmlStrdup((*cur).content);
                        }
                    }
                }
                5 => {
                    let ref mut fresh475 = (*node).content;
                    *fresh475 = 0 as *mut xmlChar;
                    let ref mut fresh476 = (*node).children;
                    *fresh476 = 0 as *mut _xmlNode;
                    let ref mut fresh477 = (*node).last;
                    *fresh477 = 0 as *mut _xmlNode;
                    if !((*destDoc).intSubset).is_null()
                        || !((*destDoc).extSubset).is_null()
                    {
                        let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
                        ent = xmlGetDocEntity(destDoc as *const xmlDoc, (*node).name);
                        if !ent.is_null() {
                            let ref mut fresh478 = (*node).content;
                            *fresh478 = (*ent).content;
                            let ref mut fresh479 = (*node).children;
                            *fresh479 = ent as xmlNodePtr;
                            let ref mut fresh480 = (*node).last;
                            *fresh480 = ent as xmlNodePtr;
                        }
                    }
                    if adoptStr != 0 && !((*node).name).is_null() {
                        if !((*destDoc).dict).is_null() {
                            let mut old: *const xmlChar = (*node).name;
                            let ref mut fresh481 = (*node).name;
                            *fresh481 = xmlDictLookup(
                                (*destDoc).dict,
                                (*node).name,
                                -(1 as libc::c_int),
                            );
                            if sourceDoc.is_null() || ((*sourceDoc).dict).is_null()
                                || xmlDictOwns((*sourceDoc).dict, old) == 0
                            {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(old as *mut libc::c_char as *mut libc::c_void);
                            }
                        } else if !sourceDoc.is_null() && !((*sourceDoc).dict).is_null()
                                && xmlDictOwns((*sourceDoc).dict, (*node).name) != 0
                            {
                            let ref mut fresh482 = (*node).name;
                            *fresh482 = xmlStrdup((*node).name);
                        }
                    }
                }
                7 => {
                    if adoptStr != 0 && !((*node).name).is_null() {
                        if !((*destDoc).dict).is_null() {
                            let mut old_0: *const xmlChar = (*node).name;
                            let ref mut fresh483 = (*node).name;
                            *fresh483 = xmlDictLookup(
                                (*destDoc).dict,
                                (*node).name,
                                -(1 as libc::c_int),
                            );
                            if sourceDoc.is_null() || ((*sourceDoc).dict).is_null()
                                || xmlDictOwns((*sourceDoc).dict, old_0) == 0
                            {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(old_0 as *mut libc::c_char as *mut libc::c_void);
                            }
                        } else if !sourceDoc.is_null() && !((*sourceDoc).dict).is_null()
                                && xmlDictOwns((*sourceDoc).dict, (*node).name) != 0
                            {
                            let ref mut fresh484 = (*node).name;
                            *fresh484 = xmlStrdup((*node).name);
                        }
                    }
                    if adoptStr != 0 && !((*node).content).is_null()
                        && !sourceDoc.is_null() && !((*sourceDoc).dict).is_null()
                        && xmlDictOwns((*sourceDoc).dict, (*cur).content) != 0
                    {
                        if !((*destDoc).dict).is_null() {
                            let ref mut fresh485 = (*cur).content;
                            *fresh485 = xmlDictLookup(
                                (*destDoc).dict,
                                (*cur).content,
                                -(1 as libc::c_int),
                            ) as *mut xmlChar;
                        } else {
                            let ref mut fresh486 = (*cur).content;
                            *fresh486 = xmlStrdup((*cur).content);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    return 0 as libc::c_int;
}
