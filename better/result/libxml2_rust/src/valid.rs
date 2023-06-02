use :: libc;
extern "C" {
    pub type _xmlLink;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn strcat(_: *mut i8, _: *const i8) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strlen(_: *const i8) -> u64;
    fn xmlDictLookup(
        dict: *mut crate::src::xpointer::_xmlDict,
        name: *const u8,
        len: i32,
    ) -> *const u8;
    fn xmlDictOwns(dict: *mut crate::src::xpointer::_xmlDict, str: *const u8) -> i32;
    fn xmlHashCreateDict(
        size: i32,
        dict: *mut crate::src::xpointer::_xmlDict,
    ) -> *mut crate::src::xmlsave::_xmlHashTable;
    fn xmlHashFree(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        f: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>,
    );
    fn xmlHashAddEntry(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
        userdata: *mut core::ffi::c_void,
    ) -> i32;
    fn xmlHashUpdateEntry(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
        userdata: *mut core::ffi::c_void,
        f: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>,
    ) -> i32;
    fn xmlHashAddEntry2(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
        name2: *const u8,
        userdata: *mut core::ffi::c_void,
    ) -> i32;
    fn xmlHashAddEntry3(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
        name2: *const u8,
        name3: *const u8,
        userdata: *mut core::ffi::c_void,
    ) -> i32;
    fn xmlHashRemoveEntry(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
        f: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>,
    ) -> i32;
    fn xmlHashRemoveEntry2(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
        name2: *const u8,
        f: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>,
    ) -> i32;
    fn xmlHashLookup(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
    ) -> *mut core::ffi::c_void;
    fn xmlHashLookup2(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
        name2: *const u8,
    ) -> *mut core::ffi::c_void;
    fn xmlHashLookup3(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
        name2: *const u8,
        name3: *const u8,
    ) -> *mut core::ffi::c_void;
    fn xmlHashCopy(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        f: Option<
            unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> *mut core::ffi::c_void,
        >,
    ) -> *mut crate::src::xmlsave::_xmlHashTable;
    fn xmlHashScan(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        f: Option<
            unsafe extern "C" fn(
                _: *mut core::ffi::c_void,
                _: *mut core::ffi::c_void,
                _: *const u8,
            ) -> (),
        >,
        data: *mut core::ffi::c_void,
    );
    fn xmlHashScan3(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
        name2: *const u8,
        name3: *const u8,
        f: Option<
            unsafe extern "C" fn(
                _: *mut core::ffi::c_void,
                _: *mut core::ffi::c_void,
                _: *const u8,
            ) -> (),
        >,
        data: *mut core::ffi::c_void,
    );
    fn __xmlRaiseError(
        schannel: Option<
            unsafe extern "C" fn(
                _: *mut core::ffi::c_void,
                _: *mut crate::src::threads::_xmlError,
            ) -> (),
        >,
        channel: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
        data: *mut core::ffi::c_void,
        ctx: *mut core::ffi::c_void,
        node: *mut core::ffi::c_void,
        domain: i32,
        code: i32,
        level: u32,
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
    fn xmlListCreate(
        deallocator: Option<unsafe extern "C" fn(_: *mut crate::src::valid::_xmlLink) -> ()>,
        compare: Option<
            unsafe extern "C" fn(_: *const core::ffi::c_void, _: *const core::ffi::c_void) -> i32,
        >,
    ) -> *mut crate::src::xmlwriter::_xmlList;
    fn xmlListDelete(l: *mut crate::src::xmlwriter::_xmlList);
    fn xmlListAppend(l: *mut crate::src::xmlwriter::_xmlList, data: *mut core::ffi::c_void) -> i32;
    fn xmlListRemoveFirst(
        l: *mut crate::src::xmlwriter::_xmlList,
        data: *mut core::ffi::c_void,
    ) -> i32;
    fn xmlListEmpty(l: *mut crate::src::xmlwriter::_xmlList) -> i32;
    fn xmlListWalk(
        l: *mut crate::src::xmlwriter::_xmlList,
        walker: Option<
            unsafe extern "C" fn(_: *const core::ffi::c_void, _: *mut core::ffi::c_void) -> i32,
        >,
        user: *mut core::ffi::c_void,
    );
    fn xmlLinkGetData(lk: *mut crate::src::valid::_xmlLink) -> *mut core::ffi::c_void;
    static mut xmlFree: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
    static mut xmlMalloc: Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
    fn xmlGetDocEntity(
        doc: *const crate::src::threads::_xmlDoc,
        name: *const u8,
    ) -> *mut crate::src::threads::_xmlEntity;
    static mut xmlRealloc:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void>;
    fn xmlParseDTD(ExternalID: *const u8, SystemID: *const u8)
        -> *mut crate::src::threads::_xmlDtd;
    static xmlIsCombiningGroup: crate::src::tree::_xmlChRangeGroup;
    fn xmlStringCurrentChar(
        ctxt: *mut crate::src::tree::_xmlParserCtxt,
        cur: *const u8,
        len: *mut i32,
    ) -> i32;
    fn xmlCharInRange(val: u32, group: *const crate::src::tree::_xmlChRangeGroup) -> i32;
    static xmlIsBaseCharGroup: crate::src::tree::_xmlChRangeGroup;
    static xmlIsExtenderGroup: crate::src::tree::_xmlChRangeGroup;
    static xmlIsDigitGroup: crate::src::tree::_xmlChRangeGroup;
}
pub use crate::src::tree::xmlBufferWriteCHAR;
pub use crate::src::tree::xmlBufferWriteChar;
pub use crate::src::tree::xmlBufferWriteQuotedString;
pub use crate::src::tree::xmlBuildQName;
pub use crate::src::tree::xmlDocGetRootElement;
pub use crate::src::tree::xmlFreeNode;
pub use crate::src::tree::xmlGetLineNo;
pub use crate::src::tree::xmlIsBlankNode;
pub use crate::src::tree::xmlNewDocNode;
pub use crate::src::tree::xmlNodeListGetString;
pub use crate::src::tree::xmlSplitQName2;
pub use crate::src::tree::xmlSplitQName3;
pub use crate::src::tree::xmlUnlinkNode;
pub use crate::src::uri::xmlBuildURI;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::xmlregexp::_xmlRegExecCtxt;
pub use crate::src::xmlregexp::_xmlRegexp;
pub use crate::src::xmlregexp::xmlAutomataCompile;
pub use crate::src::xmlregexp::xmlAutomataGetInitState;
pub use crate::src::xmlregexp::xmlAutomataNewEpsilon;
pub use crate::src::xmlregexp::xmlAutomataNewState;
pub use crate::src::xmlregexp::xmlAutomataNewTransition;
pub use crate::src::xmlregexp::xmlAutomataSetFinalState;
pub use crate::src::xmlregexp::xmlFreeAutomata;
pub use crate::src::xmlregexp::xmlNewAutomata;
pub use crate::src::xmlregexp::xmlRegExecPushString;
pub use crate::src::xmlregexp::xmlRegFreeExecCtxt;
pub use crate::src::xmlregexp::xmlRegFreeRegexp;
pub use crate::src::xmlregexp::xmlRegNewExecCtxt;
pub use crate::src::xmlregexp::xmlRegexpIsDeterminist;
pub use crate::src::xmlsave::_xmlHashTable;
pub use crate::src::xmlstring::_xmlBuf;
pub use crate::src::xmlstring::_xmlStartTag;
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrlen;
pub use crate::src::xmlstring::xmlStrncmp;
pub use crate::src::xmlstring::xmlStrndup;
pub use crate::src::xmlwriter::_xmlList;
pub use crate::src::xpointer::_xmlDict;
pub type xmlChar = u8;
pub type size_t = u64;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
pub type xmlReallocFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void>;
pub type _xmlParserInputBuffer = crate::src::threads::_xmlParserInputBuffer;
pub type xmlBufPtr = *mut crate::src::xmlstring::_xmlBuf;
pub type xmlBuf = crate::src::xmlstring::_xmlBuf;
pub type xmlCharEncodingHandlerPtr = *mut crate::src::threads::_xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = crate::src::threads::_xmlCharEncodingHandler;
pub type _xmlCharEncodingHandler = crate::src::threads::_xmlCharEncodingHandler;
pub type iconv_t = *mut core::ffi::c_void;
pub type xmlCharEncodingOutputFunc =
    Option<unsafe extern "C" fn(_: *mut u8, _: *mut i32, _: *const u8, _: *mut i32) -> i32>;
pub type xmlCharEncodingInputFunc =
    Option<unsafe extern "C" fn(_: *mut u8, _: *mut i32, _: *const u8, _: *mut i32) -> i32>;
pub type xmlInputCloseCallback = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type xmlInputReadCallback =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut i8, _: i32) -> i32>;
pub type xmlParserInputBuffer = crate::src::threads::_xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = *mut crate::src::threads::_xmlParserInputBuffer;
pub type _xmlParserInput = crate::src::threads::_xmlParserInput;
pub type xmlParserInputDeallocate = Option<unsafe extern "C" fn(_: *mut u8) -> ()>;
pub type xmlParserInput = crate::src::threads::_xmlParserInput;
pub type xmlParserInputPtr = *mut crate::src::threads::_xmlParserInput;
pub type _xmlParserCtxt = crate::src::tree::_xmlParserCtxt;
pub type xmlParserNodeInfo = crate::src::tree::_xmlParserNodeInfo;
pub type _xmlParserNodeInfo = crate::src::tree::_xmlParserNodeInfo;
pub type _xmlNode = crate::src::threads::_xmlNode;
pub type xmlNs = crate::src::threads::_xmlNs;
pub type _xmlNs = crate::src::threads::_xmlNs;
pub type _xmlDoc = crate::src::threads::_xmlDoc;
pub type _xmlDtd = crate::src::threads::_xmlDtd;
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
pub type xmlNsType = u32;
pub type _xmlAttr = crate::src::threads::_xmlAttr;
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
pub type xmlError = crate::src::threads::_xmlError;
pub type _xmlError = crate::src::threads::_xmlError;
pub type xmlErrorLevel = u32;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlAttrPtr = *mut crate::src::threads::_xmlAttr;
pub type xmlAttr = crate::src::threads::_xmlAttr;
pub type xmlNodePtr = *mut crate::src::threads::_xmlNode;
pub type xmlNode = crate::src::threads::_xmlNode;
pub type xmlHashTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlHashTable = crate::src::xmlsave::_xmlHashTable;
pub type xmlStartTag = crate::src::xmlstring::_xmlStartTag;
pub type xmlDictPtr = *mut crate::src::xpointer::_xmlDict;
pub type xmlDict = crate::src::xpointer::_xmlDict;
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
pub type xmlValidCtxt = crate::src::tree::_xmlValidCtxt;
pub type _xmlValidCtxt = crate::src::tree::_xmlValidCtxt;
pub type xmlAutomataStatePtr = *mut crate::src::xmlregexp::_xmlAutomataState;
pub type xmlAutomataState = crate::src::xmlregexp::_xmlAutomataState;
pub type xmlAutomataPtr = *mut crate::src::xmlregexp::_xmlAutomata;
pub type xmlAutomata = crate::src::xmlregexp::_xmlAutomata;
pub type xmlValidState = crate::src::valid::_xmlValidState;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlValidState {
    pub elemDecl: *mut crate::src::tree::_xmlElement,
    pub node: *mut crate::src::threads::_xmlNode,
    pub exec: *mut crate::src::xmlregexp::_xmlRegExecCtxt,
}
impl _xmlValidState {
    pub const fn new() -> Self {
        _xmlValidState {
            elemDecl: (0 as *mut crate::src::tree::_xmlElement),
            node: (0 as *mut crate::src::threads::_xmlNode),
            exec: (0 as *mut crate::src::xmlregexp::_xmlRegExecCtxt),
        }
    }
}
impl std::default::Default for _xmlValidState {
    fn default() -> Self {
        _xmlValidState::new()
    }
}
pub type xmlRegExecCtxtPtr = *mut crate::src::xmlregexp::_xmlRegExecCtxt;
pub type xmlRegExecCtxt = crate::src::xmlregexp::_xmlRegExecCtxt;
pub type xmlElementPtr = *mut crate::src::tree::_xmlElement;
pub type xmlElement = crate::src::tree::_xmlElement;
pub type _xmlElement = crate::src::tree::_xmlElement;
pub type xmlRegexpPtr = *mut crate::src::xmlregexp::_xmlRegexp;
pub type xmlRegexp = crate::src::xmlregexp::_xmlRegexp;
pub type xmlAttributePtr = *mut crate::src::tree::_xmlAttribute;
pub type xmlAttribute = crate::src::tree::_xmlAttribute;
pub type _xmlAttribute = crate::src::tree::_xmlAttribute;
pub type xmlEnumerationPtr = *mut crate::src::threads::_xmlEnumeration;
pub type xmlEnumeration = crate::src::threads::_xmlEnumeration;
pub type _xmlEnumeration = crate::src::threads::_xmlEnumeration;
pub type xmlAttributeDefault = u32;
pub const XML_ATTRIBUTE_FIXED: xmlAttributeDefault = 4;
pub const XML_ATTRIBUTE_IMPLIED: xmlAttributeDefault = 3;
pub const XML_ATTRIBUTE_REQUIRED: xmlAttributeDefault = 2;
pub const XML_ATTRIBUTE_NONE: xmlAttributeDefault = 1;
pub type xmlElementContentPtr = *mut crate::src::threads::_xmlElementContent;
pub type xmlElementContent = crate::src::threads::_xmlElementContent;
pub type _xmlElementContent = crate::src::threads::_xmlElementContent;
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
pub type xmlElementTypeVal = u32;
pub const XML_ELEMENT_TYPE_ELEMENT: xmlElementTypeVal = 4;
pub const XML_ELEMENT_TYPE_MIXED: xmlElementTypeVal = 3;
pub const XML_ELEMENT_TYPE_ANY: xmlElementTypeVal = 2;
pub const XML_ELEMENT_TYPE_EMPTY: xmlElementTypeVal = 1;
pub const XML_ELEMENT_TYPE_UNDEFINED: xmlElementTypeVal = 0;
pub type xmlDocPtr = *mut crate::src::threads::_xmlDoc;
pub type xmlDoc = crate::src::threads::_xmlDoc;
pub type xmlValidityWarningFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type xmlValidityErrorFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type xmlParserNodeInfoSeq = crate::src::tree::_xmlParserNodeInfoSeq;
pub type _xmlParserNodeInfoSeq = crate::src::tree::_xmlParserNodeInfoSeq;
pub type _xmlSAXHandler = crate::src::tree::_xmlSAXHandler;
pub type xmlStructuredErrorFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut crate::src::threads::_xmlError) -> (),
>;
pub type xmlErrorPtr = *mut crate::src::threads::_xmlError;
pub type endElementNsSAX2Func = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type startElementNsSAX2Func = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
        _: *const u8,
        _: i32,
        _: *mut *const u8,
        _: i32,
        _: i32,
        _: *mut *const u8,
    ) -> (),
>;
pub type externalSubsetSAXFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type cdataBlockSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>;
pub type getParameterEntitySAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
    ) -> *mut crate::src::threads::_xmlEntity,
>;
pub type xmlEntityPtr = *mut crate::src::threads::_xmlEntity;
pub type xmlEntity = crate::src::threads::_xmlEntity;
pub type _xmlEntity = crate::src::threads::_xmlEntity;
pub type xmlEntityType = u32;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type errorSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type warningSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type commentSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>;
pub type processingInstructionSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8) -> ()>;
pub type ignorableWhitespaceSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>;
pub type charactersSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>;
pub type referenceSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>;
pub type endElementSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>;
pub type startElementSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *mut *const u8) -> ()>;
pub type endDocumentSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type startDocumentSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type setDocumentLocatorSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *mut crate::src::threads::_xmlSAXLocator,
    ) -> (),
>;
pub type xmlSAXLocatorPtr = *mut crate::src::threads::_xmlSAXLocator;
pub type xmlSAXLocator = crate::src::threads::_xmlSAXLocator;
pub type _xmlSAXLocator = crate::src::threads::_xmlSAXLocator;
pub type unparsedEntityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
        _: *const u8,
        _: *const u8,
    ) -> (),
>;
pub type elementDeclSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: i32,
        _: *mut crate::src::threads::_xmlElementContent,
    ) -> (),
>;
pub type attributeDeclSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
        _: i32,
        _: i32,
        _: *const u8,
        _: *mut crate::src::threads::_xmlEnumeration,
    ) -> (),
>;
pub type notationDeclSAXFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type entityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: i32,
        _: *const u8,
        _: *const u8,
        _: *mut u8,
    ) -> (),
>;
pub type getEntitySAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
    ) -> *mut crate::src::threads::_xmlEntity,
>;
pub type resolveEntitySAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
    ) -> *mut crate::src::threads::_xmlParserInput,
>;
pub type hasExternalSubsetSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type hasInternalSubsetSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type isStandaloneSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type internalSubsetSAXFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type xmlParserCtxt = crate::src::tree::_xmlParserCtxt;
pub type xmlParserCtxtPtr = *mut crate::src::tree::_xmlParserCtxt;
pub type xmlBufferAllocationScheme = u32;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
pub type _xmlBuffer = crate::src::tree::_xmlBuffer;
pub type xmlBuffer = crate::src::tree::_xmlBuffer;
pub type xmlBufferPtr = *mut crate::src::tree::_xmlBuffer;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNotation {
    pub name: *const u8,
    pub PublicID: *const u8,
    pub SystemID: *const u8,
}
impl _xmlNotation {
    pub const fn new() -> Self {
        _xmlNotation {
            name: (0 as *const u8),
            PublicID: (0 as *const u8),
            SystemID: (0 as *const u8),
        }
    }
}
impl std::default::Default for _xmlNotation {
    fn default() -> Self {
        _xmlNotation::new()
    }
}
pub type xmlNotation = crate::src::valid::_xmlNotation;
pub type xmlNotationPtr = *mut crate::src::valid::_xmlNotation;
pub type xmlRegExecCallbacks = Option<
    unsafe extern "C" fn(
        _: *mut crate::src::xmlregexp::_xmlRegExecCtxt,
        _: *const u8,
        _: *mut core::ffi::c_void,
        _: *mut core::ffi::c_void,
    ) -> (),
>;
pub type xmlNsPtr = *mut crate::src::threads::_xmlNs;
pub type xmlDtd = crate::src::threads::_xmlDtd;
pub type xmlDtdPtr = *mut crate::src::threads::_xmlDtd;
pub type _xmlID<'a> = crate::src::tree::_xmlID<'a>;
pub type xmlID<'a> = crate::src::tree::_xmlID<'a>;
pub type xmlIDPtr<'a> = *mut crate::src::tree::_xmlID<'a>;
#[repr(C)]
pub struct _xmlRef<'a> {
    pub next: Option<&'a mut crate::src::valid::_xmlRef<'a>>,
    pub value: *const u8,
    pub attr: *mut crate::src::threads::_xmlAttr,
    pub name: *const u8,
    pub lineno: i32,
}
impl<'a> _xmlRef<'a> {
    pub const fn new() -> Self {
        _xmlRef {
            next: None,
            value: (0 as *const u8),
            attr: (0 as *mut crate::src::threads::_xmlAttr),
            name: (0 as *const u8),
            lineno: 0,
        }
    }
}
impl<'a> std::default::Default for _xmlRef<'a> {
    fn default() -> Self {
        _xmlRef::new()
    }
}
pub type xmlRef<'a> = crate::src::valid::_xmlRef<'a>;
pub type xmlRefPtr<'a> = *mut crate::src::valid::_xmlRef<'a>;
pub type C2RustUnnamed = u32;
pub const XML_DOC_HTML: C2RustUnnamed = 128;
pub const XML_DOC_INTERNAL: C2RustUnnamed = 64;
pub const XML_DOC_USERBUILT: C2RustUnnamed = 32;
pub const XML_DOC_XINCLUDE: C2RustUnnamed = 16;
pub const XML_DOC_DTDVALID: C2RustUnnamed = 8;
pub const XML_DOC_OLD10: C2RustUnnamed = 4;
pub const XML_DOC_NSVALID: C2RustUnnamed = 2;
pub const XML_DOC_WELLFORMED: C2RustUnnamed = 1;
pub type xmlHashDeallocator =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>;
pub type xmlHashCopier =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> *mut core::ffi::c_void>;
pub type xmlHashScanner = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut core::ffi::c_void, _: *const u8) -> (),
>;
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
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type xmlLink = crate::src::valid::_xmlLink;
pub type xmlLinkPtr = *mut crate::src::valid::_xmlLink;
pub type xmlList = crate::src::xmlwriter::_xmlList;
pub type xmlListPtr = *mut crate::src::xmlwriter::_xmlList;
pub type xmlListDeallocator =
    Option<unsafe extern "C" fn(_: *mut crate::src::valid::_xmlLink) -> ()>;
pub type xmlListDataCompare =
    Option<unsafe extern "C" fn(_: *const core::ffi::c_void, _: *const core::ffi::c_void) -> i32>;
pub type xmlListWalker =
    Option<unsafe extern "C" fn(_: *const core::ffi::c_void, _: *mut core::ffi::c_void) -> i32>;
pub type xmlValidStatePtr = *mut crate::src::valid::_xmlValidState;
pub type xmlValidCtxtPtr = *mut crate::src::tree::_xmlValidCtxt;
pub type xmlNotationTable = crate::src::xmlsave::_xmlHashTable;
pub type xmlNotationTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlElementTable = crate::src::xmlsave::_xmlHashTable;
pub type xmlElementTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlAttributeTable = crate::src::xmlsave::_xmlHashTable;
pub type xmlAttributeTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlIDTable = crate::src::xmlsave::_xmlHashTable;
pub type xmlIDTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlRefTable = crate::src::xmlsave::_xmlHashTable;
pub type xmlRefTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlChRangeGroup = crate::src::tree::_xmlChRangeGroup;
pub type _xmlChRangeGroup = crate::src::tree::_xmlChRangeGroup;
pub type xmlChLRange = crate::src::tree::_xmlChLRange;
pub type _xmlChLRange = crate::src::tree::_xmlChLRange;
pub type xmlChSRange = crate::src::tree::_xmlChSRange;
pub type _xmlChSRange = crate::src::tree::_xmlChSRange;
pub type xmlRemoveMemo = crate::src::valid::xmlRemoveMemo_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlRemoveMemo_t {
    pub l: *mut crate::src::xmlwriter::_xmlList,
    pub ap: *mut crate::src::threads::_xmlAttr,
}
impl xmlRemoveMemo_t {
    pub const fn new() -> Self {
        xmlRemoveMemo_t {
            l: (0 as *mut crate::src::xmlwriter::_xmlList),
            ap: (0 as *mut crate::src::threads::_xmlAttr),
        }
    }
}
impl std::default::Default for xmlRemoveMemo_t {
    fn default() -> Self {
        xmlRemoveMemo_t::new()
    }
}
pub type xmlRemoveMemoPtr = *mut crate::src::valid::xmlRemoveMemo_t;
pub type xmlValidateMemo = crate::src::valid::xmlValidateMemo_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlValidateMemo_t {
    pub ctxt: *mut crate::src::tree::_xmlValidCtxt,
    pub name: *const u8,
}
impl xmlValidateMemo_t {
    pub const fn new() -> Self {
        xmlValidateMemo_t {
            ctxt: (0 as *mut crate::src::tree::_xmlValidCtxt),
            name: (0 as *const u8),
        }
    }
}
impl std::default::Default for xmlValidateMemo_t {
    fn default() -> Self {
        xmlValidateMemo_t::new()
    }
}
pub type xmlValidateMemoPtr = *mut crate::src::valid::xmlValidateMemo_t;
pub type xmlEntitiesTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlEntitiesTable = crate::src::xmlsave::_xmlHashTable;
extern "C" fn xmlVErrMemory(mut ctxt: *mut crate::src::tree::_xmlValidCtxt, mut extra: *const i8) {
    let mut channel: Option<
        unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> (),
    > = None;
    let mut pctxt: *mut crate::src::tree::_xmlParserCtxt = 0 as xmlParserCtxtPtr;
    let mut data: *mut core::ffi::c_void = 0 as *mut libc::c_void;
    if !ctxt.is_null() {
        channel = unsafe { (*ctxt).error };
        data = unsafe { (*ctxt).userData };
        if (unsafe { (*ctxt).flags }) & (1 as u32) << 1 as i32 != 0 {
            let mut delta: i64 =
                (unsafe { (ctxt as *mut i8).offset_from((*ctxt).userData as *mut i8) }) as i64;
            if delta > 0 as i32 as i64 && delta < 250 as i32 as i64 {
                pctxt = (unsafe { (*ctxt).userData }) as xmlParserCtxtPtr;
            }
        }
    }
    if !extra.is_null() {
        (unsafe {
            __xmlRaiseError(
                None,
                channel,
                data,
                pctxt as *mut libc::c_void,
                0 as *mut libc::c_void,
                XML_FROM_VALID as i32,
                XML_ERR_NO_MEMORY as i32,
                XML_ERR_FATAL,
                0 as *const i8,
                0 as i32,
                extra,
                0 as *const i8,
                0 as *const i8,
                0 as i32,
                0 as i32,
                b"Memory allocation failed : %s\n\0" as *const u8 as *const i8,
                extra,
            )
        });
    } else {
        (unsafe {
            __xmlRaiseError(
                None,
                channel,
                data,
                pctxt as *mut libc::c_void,
                0 as *mut libc::c_void,
                XML_FROM_VALID as i32,
                XML_ERR_NO_MEMORY as i32,
                XML_ERR_FATAL,
                0 as *const i8,
                0 as i32,
                0 as *const i8,
                0 as *const i8,
                0 as *const i8,
                0 as i32,
                0 as i32,
                b"Memory allocation failed\n\0" as *const u8 as *const i8,
            )
        });
    };
}
extern "C" fn xmlErrValid(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut error: u32,
    mut msg: *const i8,
    mut extra: *const i8,
) {
    let mut channel: Option<
        unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> (),
    > = None;
    let mut pctxt: *mut crate::src::tree::_xmlParserCtxt = 0 as xmlParserCtxtPtr;
    let mut data: *mut core::ffi::c_void = 0 as *mut libc::c_void;
    if !ctxt.is_null() {
        channel = unsafe { (*ctxt).error };
        data = unsafe { (*ctxt).userData };
        if (unsafe { (*ctxt).flags }) & (1 as u32) << 1 as i32 != 0 {
            let mut delta: i64 =
                (unsafe { (ctxt as *mut i8).offset_from((*ctxt).userData as *mut i8) }) as i64;
            if delta > 0 as i32 as i64 && delta < 250 as i32 as i64 {
                pctxt = (unsafe { (*ctxt).userData }) as xmlParserCtxtPtr;
            }
        }
    }
    if !extra.is_null() {
        (unsafe {
            __xmlRaiseError(
                None,
                channel,
                data,
                pctxt as *mut libc::c_void,
                0 as *mut libc::c_void,
                XML_FROM_VALID as i32,
                error as i32,
                XML_ERR_ERROR,
                0 as *const i8,
                0 as i32,
                extra,
                0 as *const i8,
                0 as *const i8,
                0 as i32,
                0 as i32,
                msg,
                extra,
            )
        });
    } else {
        (unsafe {
            __xmlRaiseError(
                None,
                channel,
                data,
                pctxt as *mut libc::c_void,
                0 as *mut libc::c_void,
                XML_FROM_VALID as i32,
                error as i32,
                XML_ERR_ERROR,
                0 as *const i8,
                0 as i32,
                0 as *const i8,
                0 as *const i8,
                0 as *const i8,
                0 as i32,
                0 as i32,
                b"%s\0" as *const u8 as *const i8,
                msg,
            )
        });
    };
}
extern "C" fn xmlErrValidNode(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut node: *mut crate::src::threads::_xmlNode,
    mut error: u32,
    mut msg: *const i8,
    mut str1: *const u8,
    mut str2: *const u8,
    mut str3: *const u8,
) {
    let mut schannel: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *mut crate::src::threads::_xmlError,
        ) -> (),
    > = None;
    let mut channel: Option<
        unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> (),
    > = None;
    let mut pctxt: *mut crate::src::tree::_xmlParserCtxt = 0 as xmlParserCtxtPtr;
    let mut data: *mut core::ffi::c_void = 0 as *mut libc::c_void;
    if !ctxt.is_null() {
        channel = unsafe { (*ctxt).error };
        data = unsafe { (*ctxt).userData };
        if (unsafe { (*ctxt).flags }) & (1 as u32) << 1 as i32 != 0 {
            let mut delta: i64 =
                (unsafe { (ctxt as *mut i8).offset_from((*ctxt).userData as *mut i8) }) as i64;
            if delta > 0 as i32 as i64 && delta < 250 as i32 as i64 {
                pctxt = (unsafe { (*ctxt).userData }) as xmlParserCtxtPtr;
            }
        }
    }
    (unsafe {
        __xmlRaiseError(
            schannel,
            channel,
            data,
            pctxt as *mut libc::c_void,
            node as *mut libc::c_void,
            XML_FROM_VALID as i32,
            error as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            str1 as *const i8,
            str2 as *const i8,
            str3 as *const i8,
            0 as i32,
            0 as i32,
            msg,
            str1,
            str2,
            str3,
        )
    });
}
extern "C" fn xmlErrValidNodeNr(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut node: *mut crate::src::threads::_xmlNode,
    mut error: u32,
    mut msg: *const i8,
    mut str1: *const u8,
    mut int2: i32,
    mut str3: *const u8,
) {
    let mut schannel: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *mut crate::src::threads::_xmlError,
        ) -> (),
    > = None;
    let mut channel: Option<
        unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> (),
    > = None;
    let mut pctxt: *mut crate::src::tree::_xmlParserCtxt = 0 as xmlParserCtxtPtr;
    let mut data: *mut core::ffi::c_void = 0 as *mut libc::c_void;
    if !ctxt.is_null() {
        channel = unsafe { (*ctxt).error };
        data = unsafe { (*ctxt).userData };
        if (unsafe { (*ctxt).flags }) & (1 as u32) << 1 as i32 != 0 {
            let mut delta: i64 =
                (unsafe { (ctxt as *mut i8).offset_from((*ctxt).userData as *mut i8) }) as i64;
            if delta > 0 as i32 as i64 && delta < 250 as i32 as i64 {
                pctxt = (unsafe { (*ctxt).userData }) as xmlParserCtxtPtr;
            }
        }
    }
    (unsafe {
        __xmlRaiseError(
            schannel,
            channel,
            data,
            pctxt as *mut libc::c_void,
            node as *mut libc::c_void,
            XML_FROM_VALID as i32,
            error as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            str1 as *const i8,
            str3 as *const i8,
            0 as *const i8,
            int2,
            0 as i32,
            msg,
            str1,
            int2,
            str3,
        )
    });
}
extern "C" fn xmlErrValidWarning(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut node: *mut crate::src::threads::_xmlNode,
    mut error: u32,
    mut msg: *const i8,
    mut str1: *const u8,
    mut str2: *const u8,
    mut str3: *const u8,
) {
    let mut schannel: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *mut crate::src::threads::_xmlError,
        ) -> (),
    > = None;
    let mut channel: Option<
        unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> (),
    > = None;
    let mut pctxt: *mut crate::src::tree::_xmlParserCtxt = 0 as xmlParserCtxtPtr;
    let mut data: *mut core::ffi::c_void = 0 as *mut libc::c_void;
    if !ctxt.is_null() {
        channel = unsafe { (*ctxt).warning };
        data = unsafe { (*ctxt).userData };
        if (unsafe { (*ctxt).flags }) & (1 as u32) << 1 as i32 != 0 {
            let mut delta: i64 =
                (unsafe { (ctxt as *mut i8).offset_from((*ctxt).userData as *mut i8) }) as i64;
            if delta > 0 as i32 as i64 && delta < 250 as i32 as i64 {
                pctxt = (unsafe { (*ctxt).userData }) as xmlParserCtxtPtr;
            }
        }
    }
    (unsafe {
        __xmlRaiseError(
            schannel,
            channel,
            data,
            pctxt as *mut libc::c_void,
            node as *mut libc::c_void,
            XML_FROM_VALID as i32,
            error as i32,
            XML_ERR_WARNING,
            0 as *const i8,
            0 as i32,
            str1 as *const i8,
            str2 as *const i8,
            str3 as *const i8,
            0 as i32,
            0 as i32,
            msg,
            str1,
            str2,
            str3,
        )
    });
}
extern "C" fn vstateVPush(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut elemDecl: *mut crate::src::tree::_xmlElement,
    mut node: *mut crate::src::threads::_xmlNode,
) -> i32 {
    if (unsafe { (*ctxt).vstateMax }) == 0 as i32 || (unsafe { (*ctxt).vstateTab }).is_null() {
        (unsafe { (*ctxt).vstateMax = 10 as i32 });
        let fresh0 = unsafe { &mut ((*ctxt).vstateTab) };
        *fresh0 = (unsafe {
            xmlMalloc.expect("non-null function pointer")(
                ((*ctxt).vstateMax as u64)
                    .wrapping_mul(::std::mem::size_of::<xmlValidState>() as u64),
            )
        }) as *mut xmlValidState;
        if (unsafe { (*ctxt).vstateTab }).is_null() {
            xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const i8);
            return -(1 as i32);
        }
    }
    if (unsafe { (*ctxt).vstateNr }) >= (unsafe { (*ctxt).vstateMax }) {
        let mut tmp: *mut crate::src::valid::_xmlValidState = 0 as *mut xmlValidState;
        tmp = (unsafe {
            xmlRealloc.expect("non-null function pointer")(
                (*ctxt).vstateTab as *mut libc::c_void,
                ((2 as i32 * (*ctxt).vstateMax) as u64)
                    .wrapping_mul(::std::mem::size_of::<xmlValidState>() as u64),
            )
        }) as *mut xmlValidState;
        if tmp.is_null() {
            xmlVErrMemory(ctxt, b"realloc failed\0" as *const u8 as *const i8);
            return -(1 as i32);
        }
        (unsafe { (*ctxt).vstateMax *= 2 as i32 });
        let fresh1 = unsafe { &mut ((*ctxt).vstateTab) };
        *fresh1 = tmp;
    }
    let fresh2 = unsafe { &mut ((*ctxt).vstate) };
    *fresh2 = (unsafe { &mut *((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize) })
        as *mut xmlValidState;
    let fresh3 =
        unsafe { &mut ((*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).elemDecl) };
    *fresh3 = elemDecl;
    let fresh4 = unsafe { &mut ((*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).node) };
    *fresh4 = node;
    if !elemDecl.is_null()
        && (unsafe { (*elemDecl).etype }) as u32 == XML_ELEMENT_TYPE_ELEMENT as i32 as u32
    {
        if (unsafe { (*elemDecl).contModel }).is_null() {
            xmlValidBuildContentModel(ctxt, elemDecl);
        }
        if !(unsafe { (*elemDecl).contModel }).is_null() {
            let fresh5 =
                unsafe { &mut ((*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).exec) };
            *fresh5 = xmlRegNewExecCtxt(
                unsafe { (*elemDecl).contModel },
                None,
                0 as *mut libc::c_void,
            );
        } else {
            let fresh6 =
                unsafe { &mut ((*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).exec) };
            *fresh6 = 0 as xmlRegExecCtxtPtr;
            xmlErrValidNode(
                ctxt,
                elemDecl as xmlNodePtr,
                XML_ERR_INTERNAL_ERROR,
                b"Failed to build content model regexp for %s\n\0" as *const u8 as *const i8,
                unsafe { (*node).name },
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
    }
    let fresh7 = unsafe { &mut ((*ctxt).vstateNr) };
    let mut fresh8 = *fresh7;
    *fresh7 = *fresh7 + 1;
    return fresh8;
}
extern "C" fn vstateVPop(mut ctxt: *mut crate::src::tree::_xmlValidCtxt) -> i32 {
    let mut elemDecl: *mut crate::src::tree::_xmlElement = 0 as *mut xmlElement;
    if (unsafe { (*ctxt).vstateNr }) < 1 as i32 {
        return -(1 as i32);
    }
    let fresh9 = unsafe { &mut ((*ctxt).vstateNr) };
    *fresh9 -= 1;
    elemDecl = unsafe { (*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).elemDecl };
    let fresh10 =
        unsafe { &mut ((*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).elemDecl) };
    *fresh10 = 0 as xmlElementPtr;
    let fresh11 = unsafe { &mut ((*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).node) };
    *fresh11 = 0 as xmlNodePtr;
    if !elemDecl.is_null()
        && (unsafe { (*elemDecl).etype }) as u32 == XML_ELEMENT_TYPE_ELEMENT as i32 as u32
    {
        xmlRegFreeExecCtxt(
            unsafe { (*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).exec },
        );
    }
    let fresh12 = unsafe { &mut ((*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).exec) };
    *fresh12 = 0 as xmlRegExecCtxtPtr;
    if (unsafe { (*ctxt).vstateNr }) >= 1 as i32 {
        let fresh13 = unsafe { &mut ((*ctxt).vstate) };
        *fresh13 =
            (unsafe { &mut *((*ctxt).vstateTab).offset(((*ctxt).vstateNr - 1 as i32) as isize) })
                as *mut xmlValidState;
    } else {
        let fresh14 = unsafe { &mut ((*ctxt).vstate) };
        *fresh14 = 0 as *mut xmlValidState;
    }
    return unsafe { (*ctxt).vstateNr };
}
extern "C" fn nodeVPush(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut value: *mut crate::src::threads::_xmlNode,
) -> i32 {
    if (unsafe { (*ctxt).nodeMax }) <= 0 as i32 {
        (unsafe { (*ctxt).nodeMax = 4 as i32 });
        let fresh15 = unsafe { &mut ((*ctxt).nodeTab) };
        *fresh15 = (unsafe {
            xmlMalloc.expect("non-null function pointer")(
                ((*ctxt).nodeMax as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
            )
        }) as *mut xmlNodePtr;
        if (unsafe { (*ctxt).nodeTab }).is_null() {
            xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const i8);
            (unsafe { (*ctxt).nodeMax = 0 as i32 });
            return 0 as i32;
        }
    }
    if (unsafe { (*ctxt).nodeNr }) >= (unsafe { (*ctxt).nodeMax }) {
        let mut tmp: *mut *mut crate::src::threads::_xmlNode = 0 as *mut xmlNodePtr;
        tmp = (unsafe {
            xmlRealloc.expect("non-null function pointer")(
                (*ctxt).nodeTab as *mut libc::c_void,
                (((*ctxt).nodeMax * 2 as i32) as u64)
                    .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
            )
        }) as *mut xmlNodePtr;
        if tmp.is_null() {
            xmlVErrMemory(ctxt, b"realloc failed\0" as *const u8 as *const i8);
            return 0 as i32;
        }
        (unsafe { (*ctxt).nodeMax *= 2 as i32 });
        let fresh16 = unsafe { &mut ((*ctxt).nodeTab) };
        *fresh16 = tmp;
    }
    let fresh17 = unsafe { &mut (*((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize)) };
    *fresh17 = value;
    let fresh18 = unsafe { &mut ((*ctxt).node) };
    *fresh18 = value;
    let fresh19 = unsafe { &mut ((*ctxt).nodeNr) };
    let mut fresh20 = *fresh19;
    *fresh19 = *fresh19 + 1;
    return fresh20;
}
extern "C" fn nodeVPop(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
) -> *mut crate::src::threads::_xmlNode {
    let mut ret: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if (unsafe { (*ctxt).nodeNr }) <= 0 as i32 {
        return 0 as xmlNodePtr;
    }
    let fresh21 = unsafe { &mut ((*ctxt).nodeNr) };
    *fresh21 -= 1;
    if (unsafe { (*ctxt).nodeNr }) > 0 as i32 {
        let fresh22 = unsafe { &mut ((*ctxt).node) };
        *fresh22 = unsafe { *((*ctxt).nodeTab).offset(((*ctxt).nodeNr - 1 as i32) as isize) };
    } else {
        let fresh23 = unsafe { &mut ((*ctxt).node) };
        *fresh23 = 0 as xmlNodePtr;
    }
    ret = unsafe { *((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize) };
    let fresh24 = unsafe { &mut (*((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize)) };
    *fresh24 = 0 as xmlNodePtr;
    return ret;
}
extern "C" fn xmlValidBuildAContentModel(
    mut content: *mut crate::src::threads::_xmlElementContent,
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut name: *const u8,
) -> i32 {
    if content.is_null() {
        xmlErrValidNode(
            ctxt,
            0 as xmlNodePtr,
            XML_ERR_INTERNAL_ERROR,
            b"Found NULL content in content model of %s\n\0" as *const u8 as *const i8,
            name,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as i32;
    }
    match (unsafe { (*content).type_0 }) as u32 {
        1 => {
            xmlErrValidNode(
                ctxt,
                0 as xmlNodePtr,
                XML_ERR_INTERNAL_ERROR,
                b"Found PCDATA in content model of %s\n\0" as *const u8 as *const i8,
                name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as i32;
        }
        2 => {
            let mut oldstate: *mut crate::src::xmlregexp::_xmlAutomataState =
                unsafe { (*ctxt).state };
            let mut fn_0: [u8; 50] = [0; 50];
            let mut fullname: *mut u8 = 0 as *mut xmlChar;
            fullname = xmlBuildQName(
                unsafe { (*content).name },
                unsafe { (*content).prefix },
                fn_0.as_mut_ptr(),
                50 as i32,
            );
            if fullname.is_null() {
                xmlVErrMemory(ctxt, b"Building content model\0" as *const u8 as *const i8);
                return 0 as i32;
            }
            match (unsafe { (*content).ocur }) as u32 {
                1 => {
                    let fresh25 = unsafe { &mut ((*ctxt).state) };
                    *fresh25 = xmlAutomataNewTransition(
                        unsafe { (*ctxt).am },
                        unsafe { (*ctxt).state },
                        0 as xmlAutomataStatePtr,
                        fullname,
                        0 as *mut libc::c_void,
                    );
                }
                2 => {
                    let fresh26 = unsafe { &mut ((*ctxt).state) };
                    *fresh26 = xmlAutomataNewTransition(
                        unsafe { (*ctxt).am },
                        unsafe { (*ctxt).state },
                        0 as xmlAutomataStatePtr,
                        fullname,
                        0 as *mut libc::c_void,
                    );
                    xmlAutomataNewEpsilon(
                        unsafe { (*ctxt).am },
                        oldstate,
                        unsafe { (*ctxt).state },
                    );
                }
                4 => {
                    let fresh27 = unsafe { &mut ((*ctxt).state) };
                    *fresh27 = xmlAutomataNewTransition(
                        unsafe { (*ctxt).am },
                        unsafe { (*ctxt).state },
                        0 as xmlAutomataStatePtr,
                        fullname,
                        0 as *mut libc::c_void,
                    );
                    xmlAutomataNewTransition(
                        unsafe { (*ctxt).am },
                        unsafe { (*ctxt).state },
                        unsafe { (*ctxt).state },
                        fullname,
                        0 as *mut libc::c_void,
                    );
                }
                3 => {
                    let fresh28 = unsafe { &mut ((*ctxt).state) };
                    *fresh28 = xmlAutomataNewEpsilon(
                        unsafe { (*ctxt).am },
                        unsafe { (*ctxt).state },
                        0 as xmlAutomataStatePtr,
                    );
                    xmlAutomataNewTransition(
                        unsafe { (*ctxt).am },
                        unsafe { (*ctxt).state },
                        unsafe { (*ctxt).state },
                        fullname,
                        0 as *mut libc::c_void,
                    );
                }
                _ => {}
            }
            if fullname != fn_0.as_mut_ptr()
                && fullname != (unsafe { (*content).name }) as *mut xmlChar
            {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(fullname as *mut libc::c_void)
                });
            }
        }
        3 => {
            let mut oldstate_0: *mut crate::src::xmlregexp::_xmlAutomataState =
                0 as *mut xmlAutomataState;
            let mut oldend: *mut crate::src::xmlregexp::_xmlAutomataState =
                0 as *mut xmlAutomataState;
            let mut ocur: u32 = 0 as xmlElementContentOccur;
            oldstate_0 = unsafe { (*ctxt).state };
            ocur = unsafe { (*content).ocur };
            if ocur as u32 != XML_ELEMENT_CONTENT_ONCE as i32 as u32 {
                let fresh29 = unsafe { &mut ((*ctxt).state) };
                *fresh29 = xmlAutomataNewEpsilon(
                    unsafe { (*ctxt).am },
                    oldstate_0,
                    0 as xmlAutomataStatePtr,
                );
                oldstate_0 = unsafe { (*ctxt).state };
            }
            loop {
                xmlValidBuildAContentModel(unsafe { (*content).c1 }, ctxt, name);
                content = unsafe { (*content).c2 };
                if !((unsafe { (*content).type_0 }) as u32 == XML_ELEMENT_CONTENT_SEQ as i32 as u32
                    && (unsafe { (*content).ocur }) as u32
                        == XML_ELEMENT_CONTENT_ONCE as i32 as u32)
                {
                    break;
                }
            }
            xmlValidBuildAContentModel(content, ctxt, name);
            oldend = unsafe { (*ctxt).state };
            let fresh30 = unsafe { &mut ((*ctxt).state) };
            *fresh30 =
                xmlAutomataNewEpsilon(unsafe { (*ctxt).am }, oldend, 0 as xmlAutomataStatePtr);
            match ocur as u32 {
                2 => {
                    xmlAutomataNewEpsilon(
                        unsafe { (*ctxt).am },
                        oldstate_0,
                        unsafe { (*ctxt).state },
                    );
                }
                3 => {
                    xmlAutomataNewEpsilon(
                        unsafe { (*ctxt).am },
                        oldstate_0,
                        unsafe { (*ctxt).state },
                    );
                    xmlAutomataNewEpsilon(unsafe { (*ctxt).am }, oldend, oldstate_0);
                }
                4 => {
                    xmlAutomataNewEpsilon(unsafe { (*ctxt).am }, oldend, oldstate_0);
                }
                1 | _ => {}
            }
        }
        4 => {
            let mut oldstate_1: *mut crate::src::xmlregexp::_xmlAutomataState =
                0 as *mut xmlAutomataState;
            let mut oldend_0: *mut crate::src::xmlregexp::_xmlAutomataState =
                0 as *mut xmlAutomataState;
            let mut ocur_0: u32 = 0 as xmlElementContentOccur;
            ocur_0 = unsafe { (*content).ocur };
            if ocur_0 as u32 == XML_ELEMENT_CONTENT_PLUS as i32 as u32
                || ocur_0 as u32 == XML_ELEMENT_CONTENT_MULT as i32 as u32
            {
                let fresh31 = unsafe { &mut ((*ctxt).state) };
                *fresh31 = xmlAutomataNewEpsilon(
                    unsafe { (*ctxt).am },
                    unsafe { (*ctxt).state },
                    0 as xmlAutomataStatePtr,
                );
            }
            oldstate_1 = unsafe { (*ctxt).state };
            oldend_0 = xmlAutomataNewState(unsafe { (*ctxt).am });
            loop {
                let fresh32 = unsafe { &mut ((*ctxt).state) };
                *fresh32 = oldstate_1;
                xmlValidBuildAContentModel(unsafe { (*content).c1 }, ctxt, name);
                xmlAutomataNewEpsilon(
                    unsafe { (*ctxt).am },
                    unsafe { (*ctxt).state },
                    oldend_0,
                );
                content = unsafe { (*content).c2 };
                if !((unsafe { (*content).type_0 }) as u32 == XML_ELEMENT_CONTENT_OR as i32 as u32
                    && (unsafe { (*content).ocur }) as u32
                        == XML_ELEMENT_CONTENT_ONCE as i32 as u32)
                {
                    break;
                }
            }
            let fresh33 = unsafe { &mut ((*ctxt).state) };
            *fresh33 = oldstate_1;
            xmlValidBuildAContentModel(content, ctxt, name);
            xmlAutomataNewEpsilon(
                unsafe { (*ctxt).am },
                unsafe { (*ctxt).state },
                oldend_0,
            );
            let fresh34 = unsafe { &mut ((*ctxt).state) };
            *fresh34 =
                xmlAutomataNewEpsilon(unsafe { (*ctxt).am }, oldend_0, 0 as xmlAutomataStatePtr);
            match ocur_0 as u32 {
                2 => {
                    xmlAutomataNewEpsilon(
                        unsafe { (*ctxt).am },
                        oldstate_1,
                        unsafe { (*ctxt).state },
                    );
                }
                3 => {
                    xmlAutomataNewEpsilon(
                        unsafe { (*ctxt).am },
                        oldstate_1,
                        unsafe { (*ctxt).state },
                    );
                    xmlAutomataNewEpsilon(unsafe { (*ctxt).am }, oldend_0, oldstate_1);
                }
                4 => {
                    xmlAutomataNewEpsilon(unsafe { (*ctxt).am }, oldend_0, oldstate_1);
                }
                1 | _ => {}
            }
        }
        _ => {
            xmlErrValid(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"ContentModel broken for element %s\n\0" as *const u8 as *const i8,
                name as *const i8,
            );
            return 0 as i32;
        }
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlValidBuildContentModel(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut elem: *mut crate::src::tree::_xmlElement,
) -> i32 {
    if ctxt.is_null() || elem.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*elem).type_0 }) as u32 != XML_ELEMENT_DECL as i32 as u32 {
        return 0 as i32;
    }
    if (unsafe { (*elem).etype }) as u32 != XML_ELEMENT_TYPE_ELEMENT as i32 as u32 {
        return 1 as i32;
    }
    if !(unsafe { (*elem).contModel }).is_null() {
        if xmlRegexpIsDeterminist(unsafe { (*elem).contModel }) == 0 {
            (unsafe { (*ctxt).valid = 0 as i32 });
            return 0 as i32;
        }
        return 1 as i32;
    }
    let fresh35 = unsafe { &mut ((*ctxt).am) };
    *fresh35 = xmlNewAutomata();
    if (unsafe { (*ctxt).am }).is_null() {
        xmlErrValidNode(
            ctxt,
            elem as xmlNodePtr,
            XML_ERR_INTERNAL_ERROR,
            b"Cannot create automata for element %s\n\0" as *const u8 as *const i8,
            unsafe { (*elem).name },
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as i32;
    }
    let fresh36 = unsafe { &mut ((*ctxt).state) };
    *fresh36 = xmlAutomataGetInitState(unsafe { (*ctxt).am });
    xmlValidBuildAContentModel(
        unsafe { (*elem).content },
        ctxt,
        unsafe { (*elem).name },
    );
    xmlAutomataSetFinalState(unsafe { (*ctxt).am }, unsafe { (*ctxt).state });
    let fresh37 = unsafe { &mut ((*elem).contModel) };
    *fresh37 = xmlAutomataCompile(unsafe { (*ctxt).am });
    if xmlRegexpIsDeterminist(unsafe { (*elem).contModel }) != 1 as i32 {
        let mut expr: [i8; 5000] = [0; 5000];
        expr[0 as i32 as usize] = 0 as i32 as i8;
        xmlSnprintfElementContent(
            expr.as_mut_ptr(),
            5000 as i32,
            unsafe { (*elem).content },
            1 as i32,
        );
        xmlErrValidNode(
            ctxt,
            elem as xmlNodePtr,
            XML_DTD_CONTENT_NOT_DETERMINIST,
            b"Content model of %s is not determinist: %s\n\0" as *const u8 as *const i8,
            unsafe { (*elem).name },
            expr.as_mut_ptr() as *mut xmlChar,
            0 as *const xmlChar,
        );
        (unsafe { (*ctxt).valid = 0 as i32 });
        let fresh38 = unsafe { &mut ((*ctxt).state) };
        *fresh38 = 0 as xmlAutomataStatePtr;
        xmlFreeAutomata(unsafe { (*ctxt).am });
        let fresh39 = unsafe { &mut ((*ctxt).am) };
        *fresh39 = 0 as xmlAutomataPtr;
        return 0 as i32;
    }
    let fresh40 = unsafe { &mut ((*ctxt).state) };
    *fresh40 = 0 as xmlAutomataStatePtr;
    xmlFreeAutomata(unsafe { (*ctxt).am });
    let fresh41 = unsafe { &mut ((*ctxt).am) };
    *fresh41 = 0 as xmlAutomataPtr;
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlNewValidCtxt() -> *mut crate::src::tree::_xmlValidCtxt {
    let mut ret: *mut crate::src::tree::_xmlValidCtxt = 0 as *mut xmlValidCtxt;
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlValidCtxt>() as u64)
    }) as xmlValidCtxtPtr;
    if ret.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const i8,
        );
        return 0 as xmlValidCtxtPtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlValidCtxt>() as u64,
        )
    });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlFreeValidCtxt(mut cur: *mut crate::src::tree::_xmlValidCtxt) {
    if !(unsafe { (*cur).vstateTab }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*cur).vstateTab as *mut libc::c_void)
        });
    }
    if !(unsafe { (*cur).nodeTab }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*cur).nodeTab as *mut libc::c_void)
        });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlNewDocElementContent<'a1>(
    mut doc: Option<&'a1 mut crate::src::threads::_xmlDoc>,
    mut name: *const u8,
    mut type_0: u32,
) -> *mut crate::src::threads::_xmlElementContent {
    let mut ret: *mut crate::src::threads::_xmlElementContent = 0 as *mut xmlElementContent;
    let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as xmlDictPtr;
    if !borrow(&doc).is_none() {
        dict = (*(borrow_mut(&mut doc)).unwrap()).dict;
    }
    match type_0 as u32 {
        2 => {
            if name.is_null() {
                xmlErrValid(
                    0 as xmlValidCtxtPtr,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlNewElementContent : name == NULL !\n\0" as *const u8 as *const i8,
                    0 as *const i8,
                );
            }
        }
        1 | 3 | 4 => {
            if !name.is_null() {
                xmlErrValid(
                    0 as xmlValidCtxtPtr,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlNewElementContent : name != NULL !\n\0" as *const u8 as *const i8,
                    0 as *const i8,
                );
            }
        }
        _ => {
            xmlErrValid(
                0 as xmlValidCtxtPtr,
                XML_ERR_INTERNAL_ERROR,
                b"Internal: ELEMENT content corrupted invalid type\n\0" as *const u8 as *const i8,
                0 as *const i8,
            );
            return 0 as xmlElementContentPtr;
        }
    }
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlElementContent>() as u64
        )
    }) as xmlElementContentPtr;
    if ret.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const i8,
        );
        return 0 as xmlElementContentPtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlElementContent>() as u64,
        )
    });
    (unsafe { (*ret).type_0 = type_0 });
    (unsafe { (*ret).ocur = XML_ELEMENT_CONTENT_ONCE });
    if !name.is_null() {
        let mut l: i32 = 0;
        let mut tmp: *const u8 = 0 as *const xmlChar;
        tmp = xmlSplitQName3(name, Some(&mut l));
        if tmp.is_null() {
            if dict.is_null() {
                let fresh42 = unsafe { &mut ((*ret).name) };
                *fresh42 = xmlStrdup(name);
            } else {
                let fresh43 = unsafe { &mut ((*ret).name) };
                *fresh43 = unsafe { xmlDictLookup(dict, name, -(1 as i32)) };
            }
        } else if dict.is_null() {
            let fresh44 = unsafe { &mut ((*ret).prefix) };
            *fresh44 = xmlStrndup(name, l);
            let fresh45 = unsafe { &mut ((*ret).name) };
            *fresh45 = xmlStrdup(tmp);
        } else {
            let fresh46 = unsafe { &mut ((*ret).prefix) };
            *fresh46 = unsafe { xmlDictLookup(dict, name, l) };
            let fresh47 = unsafe { &mut ((*ret).name) };
            *fresh47 = unsafe { xmlDictLookup(dict, tmp, -(1 as i32)) };
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlNewElementContent(
    mut name: *const u8,
    mut type_0: u32,
) -> *mut crate::src::threads::_xmlElementContent {
    return xmlNewDocElementContent(
        Option::<&'_ mut crate::src::threads::_xmlDoc>::None,
        name,
        type_0,
    );
}
#[no_mangle]
pub extern "C" fn xmlCopyDocElementContent(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut cur: *mut crate::src::threads::_xmlElementContent,
) -> *mut crate::src::threads::_xmlElementContent {
    let mut ret: *mut crate::src::threads::_xmlElementContent = 0 as xmlElementContentPtr;
    let mut prev: *mut crate::src::threads::_xmlElementContent = 0 as xmlElementContentPtr;
    let mut tmp: *mut crate::src::threads::_xmlElementContent = 0 as *mut xmlElementContent;
    let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as xmlDictPtr;
    if cur.is_null() {
        return 0 as xmlElementContentPtr;
    }
    if !doc.is_null() {
        dict = unsafe { (*doc).dict };
    }
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlElementContent>() as u64
        )
    }) as xmlElementContentPtr;
    if ret.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const i8,
        );
        return 0 as xmlElementContentPtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlElementContent>() as u64,
        )
    });
    (unsafe { (*ret).type_0 = (*cur).type_0 });
    (unsafe { (*ret).ocur = (*cur).ocur });
    if !(unsafe { (*cur).name }).is_null() {
        if !dict.is_null() {
            let fresh48 = unsafe { &mut ((*ret).name) };
            *fresh48 = unsafe { xmlDictLookup(dict, (*cur).name, -(1 as i32)) };
        } else {
            let fresh49 = unsafe { &mut ((*ret).name) };
            *fresh49 = xmlStrdup(unsafe { (*cur).name });
        }
    }
    if !(unsafe { (*cur).prefix }).is_null() {
        if !dict.is_null() {
            let fresh50 = unsafe { &mut ((*ret).prefix) };
            *fresh50 = unsafe { xmlDictLookup(dict, (*cur).prefix, -(1 as i32)) };
        } else {
            let fresh51 = unsafe { &mut ((*ret).prefix) };
            *fresh51 = xmlStrdup(unsafe { (*cur).prefix });
        }
    }
    if !(unsafe { (*cur).c1 }).is_null() {
        let fresh52 = unsafe { &mut ((*ret).c1) };
        *fresh52 = xmlCopyDocElementContent(doc, unsafe { (*cur).c1 });
    }
    if !(unsafe { (*ret).c1 }).is_null() {
        let fresh53 = unsafe { &mut ((*(*ret).c1).parent) };
        *fresh53 = ret;
    }
    if !(unsafe { (*cur).c2 }).is_null() {
        prev = ret;
        cur = unsafe { (*cur).c2 };
        while !cur.is_null() {
            tmp = (unsafe {
                xmlMalloc.expect("non-null function pointer")(
                    ::std::mem::size_of::<xmlElementContent>() as u64,
                )
            }) as xmlElementContentPtr;
            if tmp.is_null() {
                xmlVErrMemory(
                    0 as xmlValidCtxtPtr,
                    b"malloc failed\0" as *const u8 as *const i8,
                );
                return ret;
            }
            (unsafe {
                memset(
                    tmp as *mut libc::c_void,
                    0 as i32,
                    ::std::mem::size_of::<xmlElementContent>() as u64,
                )
            });
            (unsafe { (*tmp).type_0 = (*cur).type_0 });
            (unsafe { (*tmp).ocur = (*cur).ocur });
            let fresh54 = unsafe { &mut ((*prev).c2) };
            *fresh54 = tmp;
            let fresh55 = unsafe { &mut ((*tmp).parent) };
            *fresh55 = prev;
            if !(unsafe { (*cur).name }).is_null() {
                if !dict.is_null() {
                    let fresh56 = unsafe { &mut ((*tmp).name) };
                    *fresh56 = unsafe { xmlDictLookup(dict, (*cur).name, -(1 as i32)) };
                } else {
                    let fresh57 = unsafe { &mut ((*tmp).name) };
                    *fresh57 = xmlStrdup(unsafe { (*cur).name });
                }
            }
            if !(unsafe { (*cur).prefix }).is_null() {
                if !dict.is_null() {
                    let fresh58 = unsafe { &mut ((*tmp).prefix) };
                    *fresh58 = unsafe { xmlDictLookup(dict, (*cur).prefix, -(1 as i32)) };
                } else {
                    let fresh59 = unsafe { &mut ((*tmp).prefix) };
                    *fresh59 = xmlStrdup(unsafe { (*cur).prefix });
                }
            }
            if !(unsafe { (*cur).c1 }).is_null() {
                let fresh60 = unsafe { &mut ((*tmp).c1) };
                *fresh60 = xmlCopyDocElementContent(doc, unsafe { (*cur).c1 });
            }
            if !(unsafe { (*tmp).c1 }).is_null() {
                let fresh61 = unsafe { &mut ((*(*tmp).c1).parent) };
                *fresh61 = ret;
            }
            prev = tmp;
            cur = unsafe { (*cur).c2 };
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCopyElementContent(
    mut cur: *mut crate::src::threads::_xmlElementContent,
) -> *mut crate::src::threads::_xmlElementContent {
    return xmlCopyDocElementContent(0 as xmlDocPtr, cur);
}
#[no_mangle]
pub extern "C" fn xmlFreeDocElementContent(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut cur: *mut crate::src::threads::_xmlElementContent,
) {
    let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as xmlDictPtr;
    let mut depth: u64 = 0 as i32 as size_t;
    if cur.is_null() {
        return;
    }
    if !doc.is_null() {
        dict = unsafe { (*doc).dict };
    }
    loop {
        let mut parent: *mut crate::src::threads::_xmlElementContent = 0 as *mut xmlElementContent;
        while !(unsafe { (*cur).c1 }).is_null() || !(unsafe { (*cur).c2 }).is_null() {
            cur = if !(unsafe { (*cur).c1 }).is_null() {
                unsafe { (*cur).c1 }
            } else {
                unsafe { (*cur).c2 }
            };
            depth = (depth as u64).wrapping_add(1 as i32 as u64) as size_t as size_t;
        }
        match (unsafe { (*cur).type_0 }) as u32 {
            1 | 2 | 3 | 4 => {}
            _ => {
                xmlErrValid(
                    0 as xmlValidCtxtPtr,
                    XML_ERR_INTERNAL_ERROR,
                    b"Internal: ELEMENT content corrupted invalid type\n\0" as *const u8
                        as *const i8,
                    0 as *const i8,
                );
                return;
            }
        }
        if !dict.is_null() {
            if !(unsafe { (*cur).name }).is_null()
                && (unsafe { xmlDictOwns(dict, (*cur).name) }) == 0
            {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(
                        (*cur).name as *mut xmlChar as *mut libc::c_void,
                    )
                });
            }
            if !(unsafe { (*cur).prefix }).is_null()
                && (unsafe { xmlDictOwns(dict, (*cur).prefix) }) == 0
            {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(
                        (*cur).prefix as *mut xmlChar as *mut libc::c_void,
                    )
                });
            }
        } else {
            if !(unsafe { (*cur).name }).is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(
                        (*cur).name as *mut xmlChar as *mut libc::c_void,
                    )
                });
            }
            if !(unsafe { (*cur).prefix }).is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(
                        (*cur).prefix as *mut xmlChar as *mut libc::c_void,
                    )
                });
            }
        }
        parent = unsafe { (*cur).parent };
        if depth == 0 as i32 as u64 || parent.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
            break;
        } else {
            if cur == (unsafe { (*parent).c1 }) {
                let fresh62 = unsafe { &mut ((*parent).c1) };
                *fresh62 = 0 as *mut _xmlElementContent;
            } else {
                let fresh63 = unsafe { &mut ((*parent).c2) };
                *fresh63 = 0 as *mut _xmlElementContent;
            }
            (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
            if !(unsafe { (*parent).c2 }).is_null() {
                cur = unsafe { (*parent).c2 };
            } else {
                depth = (depth as u64).wrapping_sub(1 as i32 as u64) as size_t as size_t;
                cur = parent;
            }
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlFreeElementContent(mut cur: *mut crate::src::threads::_xmlElementContent) {
    xmlFreeDocElementContent(0 as xmlDocPtr, cur);
}
extern "C" fn xmlDumpElementOccur(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut cur: *mut crate::src::threads::_xmlElementContent,
) {
    match (unsafe { (*cur).ocur }) as u32 {
        2 => {
            xmlBufferWriteChar(buf, b"?\0" as *const u8 as *const i8);
        }
        3 => {
            xmlBufferWriteChar(buf, b"*\0" as *const u8 as *const i8);
        }
        4 => {
            xmlBufferWriteChar(buf, b"+\0" as *const u8 as *const i8);
        }
        1 | _ => {}
    };
}
extern "C" fn xmlDumpElementContent(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut content: *mut crate::src::threads::_xmlElementContent,
) {
    let mut cur: *mut crate::src::threads::_xmlElementContent = 0 as *mut xmlElementContent;
    if content.is_null() {
        return;
    }
    xmlBufferWriteChar(buf, b"(\0" as *const u8 as *const i8);
    cur = content;
    let mut current_block_27: u64;
    loop {
        if cur.is_null() {
            return;
        }
        match (unsafe { (*cur).type_0 }) as u32 {
            1 => {
                xmlBufferWriteChar(buf, b"#PCDATA\0" as *const u8 as *const i8);
                current_block_27 = 12124785117276362961;
            }
            2 => {
                if !(unsafe { (*cur).prefix }).is_null() {
                    xmlBufferWriteCHAR(buf, unsafe { (*cur).prefix });
                    xmlBufferWriteChar(buf, b":\0" as *const u8 as *const i8);
                }
                xmlBufferWriteCHAR(buf, unsafe { (*cur).name });
                current_block_27 = 12124785117276362961;
            }
            3 | 4 => {
                if cur != content
                    && !(unsafe { (*cur).parent }).is_null()
                    && ((unsafe { (*cur).type_0 }) as u32
                        != (unsafe { (*(*cur).parent).type_0 }) as u32
                        || (unsafe { (*cur).ocur }) as u32
                            != XML_ELEMENT_CONTENT_ONCE as i32 as u32)
                {
                    xmlBufferWriteChar(buf, b"(\0" as *const u8 as *const i8);
                }
                cur = unsafe { (*cur).c1 };
                current_block_27 = 17179679302217393232;
            }
            _ => {
                xmlErrValid(
                    0 as xmlValidCtxtPtr,
                    XML_ERR_INTERNAL_ERROR,
                    b"Internal: ELEMENT cur corrupted invalid type\n\0" as *const u8 as *const i8,
                    0 as *const i8,
                );
                current_block_27 = 12124785117276362961;
            }
        }
        match current_block_27 {
            12124785117276362961 => {
                while cur != content {
                    let mut parent: *mut crate::src::threads::_xmlElementContent =
                        unsafe { (*cur).parent };
                    if parent.is_null() {
                        return;
                    }
                    if ((unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_CONTENT_OR as i32 as u32
                        || (unsafe { (*cur).type_0 }) as u32
                            == XML_ELEMENT_CONTENT_SEQ as i32 as u32)
                        && ((unsafe { (*cur).type_0 }) as u32
                            != (unsafe { (*parent).type_0 }) as u32
                            || (unsafe { (*cur).ocur }) as u32
                                != XML_ELEMENT_CONTENT_ONCE as i32 as u32)
                    {
                        xmlBufferWriteChar(buf, b")\0" as *const u8 as *const i8);
                    }
                    xmlDumpElementOccur(buf, cur);
                    if cur == (unsafe { (*parent).c1 }) {
                        if (unsafe { (*parent).type_0 }) as u32
                            == XML_ELEMENT_CONTENT_SEQ as i32 as u32
                        {
                            xmlBufferWriteChar(buf, b" , \0" as *const u8 as *const i8);
                        } else if (unsafe { (*parent).type_0 }) as u32
                            == XML_ELEMENT_CONTENT_OR as i32 as u32
                        {
                            xmlBufferWriteChar(buf, b" | \0" as *const u8 as *const i8);
                        }
                        cur = unsafe { (*parent).c2 };
                        break;
                    } else {
                        cur = parent;
                    }
                }
            }
            _ => {}
        }
        if !(cur != content) {
            break;
        }
    }
    xmlBufferWriteChar(buf, b")\0" as *const u8 as *const i8);
    xmlDumpElementOccur(buf, content);
}
#[no_mangle]
pub extern "C" fn xmlSprintfElementContent<'a1, 'a2>(
    mut _buf: Option<&'a1 mut i8>,
    mut _content: Option<&'a2 mut crate::src::threads::_xmlElementContent>,
    mut _englob: i32,
) {
}
#[no_mangle]
pub extern "C" fn xmlSnprintfElementContent(
    mut buf: *mut i8,
    mut size: i32,
    mut content: *mut crate::src::threads::_xmlElementContent,
    mut englob: i32,
) {
    let mut len: i32 = 0;
    if content.is_null() {
        return;
    }
    len = (unsafe { strlen(buf) }) as i32;
    if size - len < 50 as i32 {
        if size - len > 4 as i32
            && (unsafe { *buf.offset((len - 1 as i32) as isize) }) as i32 != '.' as i32
        {
            (unsafe { strcat(buf, b" ...\0" as *const u8 as *const i8) });
        }
        return;
    }
    if englob != 0 {
        (unsafe { strcat(buf, b"(\0" as *const u8 as *const i8) });
    }
    match (unsafe { (*content).type_0 }) as u32 {
        1 => {
            (unsafe { strcat(buf, b"#PCDATA\0" as *const u8 as *const i8) });
        }
        2 => {
            let mut qnameLen: i32 = xmlStrlen(unsafe { (*content).name });
            if !(unsafe { (*content).prefix }).is_null() {
                qnameLen += xmlStrlen(unsafe { (*content).prefix }) + 1 as i32;
            }
            if size - len < qnameLen + 10 as i32 {
                (unsafe { strcat(buf, b" ...\0" as *const u8 as *const i8) });
                return;
            }
            if !(unsafe { (*content).prefix }).is_null() {
                (unsafe { strcat(buf, (*content).prefix as *mut i8) });
                (unsafe { strcat(buf, b":\0" as *const u8 as *const i8) });
            }
            if !(unsafe { (*content).name }).is_null() {
                (unsafe { strcat(buf, (*content).name as *mut i8) });
            }
        }
        3 => {
            if (unsafe { (*(*content).c1).type_0 }) as u32 == XML_ELEMENT_CONTENT_OR as i32 as u32
                || (unsafe { (*(*content).c1).type_0 }) as u32
                    == XML_ELEMENT_CONTENT_SEQ as i32 as u32
            {
                xmlSnprintfElementContent(buf, size, unsafe { (*content).c1 }, 1 as i32);
            } else {
                xmlSnprintfElementContent(buf, size, unsafe { (*content).c1 }, 0 as i32);
            }
            len = (unsafe { strlen(buf) }) as i32;
            if size - len < 50 as i32 {
                if size - len > 4 as i32
                    && (unsafe { *buf.offset((len - 1 as i32) as isize) }) as i32 != '.' as i32
                {
                    (unsafe { strcat(buf, b" ...\0" as *const u8 as *const i8) });
                }
                return;
            }
            (unsafe { strcat(buf, b" , \0" as *const u8 as *const i8) });
            if ((unsafe { (*(*content).c2).type_0 }) as u32 == XML_ELEMENT_CONTENT_OR as i32 as u32
                || (unsafe { (*(*content).c2).ocur }) as u32
                    != XML_ELEMENT_CONTENT_ONCE as i32 as u32)
                && (unsafe { (*(*content).c2).type_0 }) as u32
                    != XML_ELEMENT_CONTENT_ELEMENT as i32 as u32
            {
                xmlSnprintfElementContent(buf, size, unsafe { (*content).c2 }, 1 as i32);
            } else {
                xmlSnprintfElementContent(buf, size, unsafe { (*content).c2 }, 0 as i32);
            }
        }
        4 => {
            if (unsafe { (*(*content).c1).type_0 }) as u32 == XML_ELEMENT_CONTENT_OR as i32 as u32
                || (unsafe { (*(*content).c1).type_0 }) as u32
                    == XML_ELEMENT_CONTENT_SEQ as i32 as u32
            {
                xmlSnprintfElementContent(buf, size, unsafe { (*content).c1 }, 1 as i32);
            } else {
                xmlSnprintfElementContent(buf, size, unsafe { (*content).c1 }, 0 as i32);
            }
            len = (unsafe { strlen(buf) }) as i32;
            if size - len < 50 as i32 {
                if size - len > 4 as i32
                    && (unsafe { *buf.offset((len - 1 as i32) as isize) }) as i32 != '.' as i32
                {
                    (unsafe { strcat(buf, b" ...\0" as *const u8 as *const i8) });
                }
                return;
            }
            (unsafe { strcat(buf, b" | \0" as *const u8 as *const i8) });
            if ((unsafe { (*(*content).c2).type_0 }) as u32
                == XML_ELEMENT_CONTENT_SEQ as i32 as u32
                || (unsafe { (*(*content).c2).ocur }) as u32
                    != XML_ELEMENT_CONTENT_ONCE as i32 as u32)
                && (unsafe { (*(*content).c2).type_0 }) as u32
                    != XML_ELEMENT_CONTENT_ELEMENT as i32 as u32
            {
                xmlSnprintfElementContent(buf, size, unsafe { (*content).c2 }, 1 as i32);
            } else {
                xmlSnprintfElementContent(buf, size, unsafe { (*content).c2 }, 0 as i32);
            }
        }
        _ => {}
    }
    if (size as u64).wrapping_sub(unsafe { strlen(buf) }) <= 2 as i32 as u64 {
        return;
    }
    if englob != 0 {
        (unsafe { strcat(buf, b")\0" as *const u8 as *const i8) });
    }
    match (unsafe { (*content).ocur }) as u32 {
        2 => {
            (unsafe { strcat(buf, b"?\0" as *const u8 as *const i8) });
        }
        3 => {
            (unsafe { strcat(buf, b"*\0" as *const u8 as *const i8) });
        }
        4 => {
            (unsafe { strcat(buf, b"+\0" as *const u8 as *const i8) });
        }
        1 | _ => {}
    };
}
extern "C" fn xmlFreeElement(mut elem: *mut crate::src::tree::_xmlElement) {
    if elem.is_null() {
        return;
    }
    xmlUnlinkNode(elem as xmlNodePtr);
    xmlFreeDocElementContent(unsafe { (*elem).doc }, unsafe { (*elem).content });
    if !(unsafe { (*elem).name }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*elem).name as *mut xmlChar as *mut libc::c_void,
            )
        });
    }
    if !(unsafe { (*elem).prefix }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*elem).prefix as *mut xmlChar as *mut libc::c_void,
            )
        });
    }
    if !(unsafe { (*elem).contModel }).is_null() {
        xmlRegFreeRegexp(unsafe { (*elem).contModel });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(elem as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlAddElementDecl(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut dtd: *mut crate::src::threads::_xmlDtd,
    mut name: *const u8,
    mut type_0: u32,
    mut content: *mut crate::src::threads::_xmlElementContent,
) -> *mut crate::src::tree::_xmlElement {
    let mut ret: *mut crate::src::tree::_xmlElement = 0 as *mut xmlElement;
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlElementTable;
    let mut oldAttributes: *mut crate::src::tree::_xmlAttribute = 0 as xmlAttributePtr;
    let mut ns: *mut u8 = 0 as *mut xmlChar;
    let mut uqname: *mut u8 = 0 as *mut xmlChar;
    if dtd.is_null() {
        return 0 as xmlElementPtr;
    }
    if name.is_null() {
        return 0 as xmlElementPtr;
    }
    match type_0 as u32 {
        1 => {
            if !content.is_null() {
                xmlErrValid(
                    ctxt,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlAddElementDecl: content != NULL for EMPTY\n\0" as *const u8 as *const i8,
                    0 as *const i8,
                );
                return 0 as xmlElementPtr;
            }
        }
        2 => {
            if !content.is_null() {
                xmlErrValid(
                    ctxt,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlAddElementDecl: content != NULL for ANY\n\0" as *const u8 as *const i8,
                    0 as *const i8,
                );
                return 0 as xmlElementPtr;
            }
        }
        3 => {
            if content.is_null() {
                xmlErrValid(
                    ctxt,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlAddElementDecl: content == NULL for MIXED\n\0" as *const u8 as *const i8,
                    0 as *const i8,
                );
                return 0 as xmlElementPtr;
            }
        }
        4 => {
            if content.is_null() {
                xmlErrValid(
                    ctxt,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlAddElementDecl: content == NULL for ELEMENT\n\0" as *const u8 as *const i8,
                    0 as *const i8,
                );
                return 0 as xmlElementPtr;
            }
        }
        _ => {
            xmlErrValid(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"Internal: ELEMENT decl corrupted invalid type\n\0" as *const u8 as *const i8,
                0 as *const i8,
            );
            return 0 as xmlElementPtr;
        }
    }
    uqname = xmlSplitQName2(name, Some(&mut ns));
    if !uqname.is_null() {
        name = uqname;
    }
    table = (unsafe { (*dtd).elements }) as xmlElementTablePtr;
    if table.is_null() {
        let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as xmlDictPtr;
        if !(unsafe { (*dtd).doc }).is_null() {
            dict = unsafe { (*(*dtd).doc).dict };
        }
        table = unsafe { xmlHashCreateDict(0 as i32, dict) };
        let fresh64 = unsafe { &mut ((*dtd).elements) };
        *fresh64 = table as *mut libc::c_void;
    }
    if table.is_null() {
        xmlVErrMemory(
            ctxt,
            b"xmlAddElementDecl: Table creation failed!\n\0" as *const u8 as *const i8,
        );
        if !uqname.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void) });
        }
        if !ns.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void) });
        }
        return 0 as xmlElementPtr;
    }
    if !(unsafe { (*dtd).doc }).is_null() && !(unsafe { (*(*dtd).doc).intSubset }).is_null() {
        ret = (unsafe {
            xmlHashLookup2(
                (*(*(*dtd).doc).intSubset).elements as xmlHashTablePtr,
                name,
                ns,
            )
        }) as xmlElementPtr;
        if !ret.is_null()
            && (unsafe { (*ret).etype }) as u32 == XML_ELEMENT_TYPE_UNDEFINED as i32 as u32
        {
            oldAttributes = unsafe { (*ret).attributes };
            let fresh65 = unsafe { &mut ((*ret).attributes) };
            *fresh65 = 0 as xmlAttributePtr;
            (unsafe {
                xmlHashRemoveEntry2(
                    (*(*(*dtd).doc).intSubset).elements as xmlHashTablePtr,
                    name,
                    ns,
                    None,
                )
            });
            xmlFreeElement(ret);
        }
    }
    ret = (unsafe { xmlHashLookup2(table, name, ns) }) as xmlElementPtr;
    if !ret.is_null() {
        if (unsafe { (*ret).etype }) as u32 != XML_ELEMENT_TYPE_UNDEFINED as i32 as u32 {
            xmlErrValidNode(
                ctxt,
                dtd as xmlNodePtr,
                XML_DTD_ELEM_REDEFINED,
                b"Redefinition of element %s\n\0" as *const u8 as *const i8,
                name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            if !uqname.is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void)
                });
            }
            if !ns.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void) });
            }
            return 0 as xmlElementPtr;
        }
        if !ns.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void) });
            ns = 0 as *mut xmlChar;
        }
    } else {
        ret = (unsafe {
            xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlElement>() as u64)
        }) as xmlElementPtr;
        if ret.is_null() {
            xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const i8);
            if !uqname.is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void)
                });
            }
            if !ns.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void) });
            }
            return 0 as xmlElementPtr;
        }
        (unsafe {
            memset(
                ret as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<xmlElement>() as u64,
            )
        });
        (unsafe { (*ret).type_0 = XML_ELEMENT_DECL });
        let fresh66 = unsafe { &mut ((*ret).name) };
        *fresh66 = xmlStrdup(name);
        if (unsafe { (*ret).name }).is_null() {
            xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const i8);
            if !uqname.is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void)
                });
            }
            if !ns.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void) });
            }
            (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
            return 0 as xmlElementPtr;
        }
        let fresh67 = unsafe { &mut ((*ret).prefix) };
        *fresh67 = ns;
        if (unsafe { xmlHashAddEntry2(table, name, ns, ret as *mut libc::c_void) }) != 0 {
            xmlErrValidNode(
                ctxt,
                dtd as xmlNodePtr,
                XML_DTD_ELEM_REDEFINED,
                b"Redefinition of element %s\n\0" as *const u8 as *const i8,
                name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            xmlFreeElement(ret);
            if !uqname.is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void)
                });
            }
            return 0 as xmlElementPtr;
        }
        let fresh68 = unsafe { &mut ((*ret).attributes) };
        *fresh68 = oldAttributes;
    }
    (unsafe { (*ret).etype = type_0 });
    if !ctxt.is_null() && (unsafe { (*ctxt).flags }) & (1 as u32) << 1 as i32 != 0 {
        let fresh69 = unsafe { &mut ((*ret).content) };
        *fresh69 = content;
        if !content.is_null() {
            let fresh70 = unsafe { &mut ((*content).parent) };
            *fresh70 = 1 as i32 as xmlElementContentPtr;
        }
    } else {
        let fresh71 = unsafe { &mut ((*ret).content) };
        *fresh71 = xmlCopyDocElementContent(unsafe { (*dtd).doc }, content);
    }
    let fresh72 = unsafe { &mut ((*ret).parent) };
    *fresh72 = dtd;
    let fresh73 = unsafe { &mut ((*ret).doc) };
    *fresh73 = unsafe { (*dtd).doc };
    if (unsafe { (*dtd).last }).is_null() {
        let fresh74 = unsafe { &mut ((*dtd).last) };
        *fresh74 = ret as xmlNodePtr;
        let fresh75 = unsafe { &mut ((*dtd).children) };
        *fresh75 = *fresh74;
    } else {
        let fresh76 = unsafe { &mut ((*(*dtd).last).next) };
        *fresh76 = ret as xmlNodePtr;
        let fresh77 = unsafe { &mut ((*ret).prev) };
        *fresh77 = unsafe { (*dtd).last };
        let fresh78 = unsafe { &mut ((*dtd).last) };
        *fresh78 = ret as xmlNodePtr;
    }
    if !uqname.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void) });
    }
    return ret;
}
extern "C" fn xmlFreeElementTableEntry(mut elem: *mut core::ffi::c_void, mut _name: *const u8) {
    xmlFreeElement(elem as xmlElementPtr);
}
#[no_mangle]
pub extern "C" fn xmlFreeElementTable(mut table: *mut crate::src::xmlsave::_xmlHashTable) {
    (unsafe { xmlHashFree(table, Some(xmlFreeElementTableEntry)) });
}
extern "C" fn xmlCopyElement(
    mut payload: *mut core::ffi::c_void,
    mut _name: *const u8,
) -> *mut core::ffi::c_void {
    let mut elem: *mut crate::src::tree::_xmlElement = payload as xmlElementPtr;
    let mut cur: *mut crate::src::tree::_xmlElement = 0 as *mut xmlElement;
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlElement>() as u64)
    }) as xmlElementPtr;
    if cur.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const i8,
        );
        return 0 as *mut libc::c_void;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlElement>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_ELEMENT_DECL });
    (unsafe { (*cur).etype = (*elem).etype });
    if !(unsafe { (*elem).name }).is_null() {
        let fresh79 = unsafe { &mut ((*cur).name) };
        *fresh79 = xmlStrdup(unsafe { (*elem).name });
    } else {
        let fresh80 = unsafe { &mut ((*cur).name) };
        *fresh80 = 0 as *const xmlChar;
    }
    if !(unsafe { (*elem).prefix }).is_null() {
        let fresh81 = unsafe { &mut ((*cur).prefix) };
        *fresh81 = xmlStrdup(unsafe { (*elem).prefix });
    } else {
        let fresh82 = unsafe { &mut ((*cur).prefix) };
        *fresh82 = 0 as *const xmlChar;
    }
    let fresh83 = unsafe { &mut ((*cur).content) };
    *fresh83 = xmlCopyElementContent(unsafe { (*elem).content });
    let fresh84 = unsafe { &mut ((*cur).attributes) };
    *fresh84 = 0 as xmlAttributePtr;
    return cur as *mut libc::c_void;
}
#[no_mangle]
pub extern "C" fn xmlCopyElementTable(
    mut table: *mut crate::src::xmlsave::_xmlHashTable,
) -> *mut crate::src::xmlsave::_xmlHashTable {
    return (unsafe { xmlHashCopy(table, Some(xmlCopyElement)) }) as xmlElementTablePtr;
}
#[no_mangle]
pub extern "C" fn xmlDumpElementDecl(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut elem: *mut crate::src::tree::_xmlElement,
) {
    if buf.is_null() || elem.is_null() {
        return;
    }
    match (unsafe { (*elem).etype }) as u32 {
        1 => {
            xmlBufferWriteChar(buf, b"<!ELEMENT \0" as *const u8 as *const i8);
            if !(unsafe { (*elem).prefix }).is_null() {
                xmlBufferWriteCHAR(buf, unsafe { (*elem).prefix });
                xmlBufferWriteChar(buf, b":\0" as *const u8 as *const i8);
            }
            xmlBufferWriteCHAR(buf, unsafe { (*elem).name });
            xmlBufferWriteChar(buf, b" EMPTY>\n\0" as *const u8 as *const i8);
        }
        2 => {
            xmlBufferWriteChar(buf, b"<!ELEMENT \0" as *const u8 as *const i8);
            if !(unsafe { (*elem).prefix }).is_null() {
                xmlBufferWriteCHAR(buf, unsafe { (*elem).prefix });
                xmlBufferWriteChar(buf, b":\0" as *const u8 as *const i8);
            }
            xmlBufferWriteCHAR(buf, unsafe { (*elem).name });
            xmlBufferWriteChar(buf, b" ANY>\n\0" as *const u8 as *const i8);
        }
        3 => {
            xmlBufferWriteChar(buf, b"<!ELEMENT \0" as *const u8 as *const i8);
            if !(unsafe { (*elem).prefix }).is_null() {
                xmlBufferWriteCHAR(buf, unsafe { (*elem).prefix });
                xmlBufferWriteChar(buf, b":\0" as *const u8 as *const i8);
            }
            xmlBufferWriteCHAR(buf, unsafe { (*elem).name });
            xmlBufferWriteChar(buf, b" \0" as *const u8 as *const i8);
            xmlDumpElementContent(buf, unsafe { (*elem).content });
            xmlBufferWriteChar(buf, b">\n\0" as *const u8 as *const i8);
        }
        4 => {
            xmlBufferWriteChar(buf, b"<!ELEMENT \0" as *const u8 as *const i8);
            if !(unsafe { (*elem).prefix }).is_null() {
                xmlBufferWriteCHAR(buf, unsafe { (*elem).prefix });
                xmlBufferWriteChar(buf, b":\0" as *const u8 as *const i8);
            }
            xmlBufferWriteCHAR(buf, unsafe { (*elem).name });
            xmlBufferWriteChar(buf, b" \0" as *const u8 as *const i8);
            xmlDumpElementContent(buf, unsafe { (*elem).content });
            xmlBufferWriteChar(buf, b">\n\0" as *const u8 as *const i8);
        }
        _ => {
            xmlErrValid(
                0 as xmlValidCtxtPtr,
                XML_ERR_INTERNAL_ERROR,
                b"Internal: ELEMENT struct corrupted invalid type\n\0" as *const u8 as *const i8,
                0 as *const i8,
            );
        }
    };
}
extern "C" fn xmlDumpElementDeclScan(
    mut elem: *mut core::ffi::c_void,
    mut buf: *mut core::ffi::c_void,
    mut _name: *const u8,
) {
    xmlDumpElementDecl(buf as xmlBufferPtr, elem as xmlElementPtr);
}
#[no_mangle]
pub extern "C" fn xmlDumpElementTable(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut table: *mut crate::src::xmlsave::_xmlHashTable,
) {
    if buf.is_null() || table.is_null() {
        return;
    }
    (unsafe {
        xmlHashScan(
            table,
            Some(xmlDumpElementDeclScan),
            buf as *mut libc::c_void,
        )
    });
}
#[no_mangle]
pub extern "C" fn xmlCreateEnumeration(
    mut name: *const u8,
) -> *mut crate::src::threads::_xmlEnumeration {
    let mut ret: *mut crate::src::threads::_xmlEnumeration = 0 as *mut xmlEnumeration;
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlEnumeration>() as u64)
    }) as xmlEnumerationPtr;
    if ret.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const i8,
        );
        return 0 as xmlEnumerationPtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlEnumeration>() as u64,
        )
    });
    if !name.is_null() {
        let fresh85 = unsafe { &mut ((*ret).name) };
        *fresh85 = xmlStrdup(name);
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlFreeEnumeration(mut cur: *mut crate::src::threads::_xmlEnumeration) {
    if cur.is_null() {
        return;
    }
    if !(unsafe { (*cur).next }).is_null() {
        xmlFreeEnumeration(unsafe { (*cur).next });
    }
    if !(unsafe { (*cur).name }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*cur).name as *mut xmlChar as *mut libc::c_void,
            )
        });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlCopyEnumeration(
    mut cur: *mut crate::src::threads::_xmlEnumeration,
) -> *mut crate::src::threads::_xmlEnumeration {
    let mut ret: *mut crate::src::threads::_xmlEnumeration = 0 as *mut xmlEnumeration;
    if cur.is_null() {
        return 0 as xmlEnumerationPtr;
    }
    ret = xmlCreateEnumeration((unsafe { (*cur).name }) as *mut xmlChar);
    if ret.is_null() {
        return 0 as xmlEnumerationPtr;
    }
    if !(unsafe { (*cur).next }).is_null() {
        let fresh86 = unsafe { &mut ((*ret).next) };
        *fresh86 = xmlCopyEnumeration(unsafe { (*cur).next });
    } else {
        let fresh87 = unsafe { &mut ((*ret).next) };
        *fresh87 = 0 as *mut _xmlEnumeration;
    }
    return ret;
}
extern "C" fn xmlDumpEnumeration(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut cur: *mut crate::src::threads::_xmlEnumeration,
) {
    if buf.is_null() || cur.is_null() {
        return;
    }
    xmlBufferWriteCHAR(buf, unsafe { (*cur).name });
    if (unsafe { (*cur).next }).is_null() {
        xmlBufferWriteChar(buf, b")\0" as *const u8 as *const i8);
    } else {
        xmlBufferWriteChar(buf, b" | \0" as *const u8 as *const i8);
        xmlDumpEnumeration(buf, unsafe { (*cur).next });
    };
}
extern "C" fn xmlScanIDAttributeDecl(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut elem: *mut crate::src::tree::_xmlElement,
    mut err: i32,
) -> i32 {
    let mut cur: *mut crate::src::tree::_xmlAttribute = 0 as *mut xmlAttribute;
    let mut ret: i32 = 0 as i32;
    if elem.is_null() {
        return 0 as i32;
    }
    cur = unsafe { (*elem).attributes };
    while !cur.is_null() {
        if (unsafe { (*cur).atype }) as u32 == XML_ATTRIBUTE_ID as i32 as u32 {
            ret += 1;
            if ret > 1 as i32 && err != 0 {
                xmlErrValidNode(
                    ctxt,
                    elem as xmlNodePtr,
                    XML_DTD_MULTIPLE_ID,
                    b"Element %s has too many ID attributes defined : %s\n\0" as *const u8
                        as *const i8,
                    unsafe { (*elem).name },
                    unsafe { (*cur).name },
                    0 as *const xmlChar,
                );
            }
        }
        cur = unsafe { (*cur).nexth };
    }
    return ret;
}
extern "C" fn xmlFreeAttribute(mut attr: *mut crate::src::tree::_xmlAttribute) {
    let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as *mut xmlDict;
    if attr.is_null() {
        return;
    }
    if !(unsafe { (*attr).doc }).is_null() {
        dict = unsafe { (*(*attr).doc).dict };
    } else {
        dict = 0 as xmlDictPtr;
    }
    xmlUnlinkNode(attr as xmlNodePtr);
    if !(unsafe { (*attr).tree }).is_null() {
        xmlFreeEnumeration(unsafe { (*attr).tree });
    }
    if !dict.is_null() {
        if !(unsafe { (*attr).elem }).is_null()
            && (unsafe { xmlDictOwns(dict, (*attr).elem) }) == 0
        {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*attr).elem as *mut xmlChar as *mut libc::c_void,
                )
            });
        }
        if !(unsafe { (*attr).name }).is_null()
            && (unsafe { xmlDictOwns(dict, (*attr).name) }) == 0
        {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*attr).name as *mut xmlChar as *mut libc::c_void,
                )
            });
        }
        if !(unsafe { (*attr).prefix }).is_null()
            && (unsafe { xmlDictOwns(dict, (*attr).prefix) }) == 0
        {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*attr).prefix as *mut xmlChar as *mut libc::c_void,
                )
            });
        }
        if !(unsafe { (*attr).defaultValue }).is_null()
            && (unsafe { xmlDictOwns(dict, (*attr).defaultValue) }) == 0
        {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*attr).defaultValue as *mut xmlChar as *mut libc::c_void,
                )
            });
        }
    } else {
        if !(unsafe { (*attr).elem }).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*attr).elem as *mut xmlChar as *mut libc::c_void,
                )
            });
        }
        if !(unsafe { (*attr).name }).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*attr).name as *mut xmlChar as *mut libc::c_void,
                )
            });
        }
        if !(unsafe { (*attr).defaultValue }).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*attr).defaultValue as *mut xmlChar as *mut libc::c_void,
                )
            });
        }
        if !(unsafe { (*attr).prefix }).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*attr).prefix as *mut xmlChar as *mut libc::c_void,
                )
            });
        }
    }
    (unsafe { xmlFree.expect("non-null function pointer")(attr as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlAddAttributeDecl(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut dtd: *mut crate::src::threads::_xmlDtd,
    mut elem: *const u8,
    mut name: *const u8,
    mut ns: *const u8,
    mut type_0: u32,
    mut def: u32,
    mut defaultValue: *const u8,
    mut tree: *mut crate::src::threads::_xmlEnumeration,
) -> *mut crate::src::tree::_xmlAttribute {
    let mut ret: *mut crate::src::tree::_xmlAttribute = 0 as *mut xmlAttribute;
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlAttributeTable;
    let mut elemDef: *mut crate::src::tree::_xmlElement = 0 as *mut xmlElement;
    let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as xmlDictPtr;
    if dtd.is_null() {
        xmlFreeEnumeration(tree);
        return 0 as xmlAttributePtr;
    }
    if name.is_null() {
        xmlFreeEnumeration(tree);
        return 0 as xmlAttributePtr;
    }
    if elem.is_null() {
        xmlFreeEnumeration(tree);
        return 0 as xmlAttributePtr;
    }
    if !(unsafe { (*dtd).doc }).is_null() {
        dict = unsafe { (*(*dtd).doc).dict };
    }
    match type_0 as u32 {
        1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 => {}
        _ => {
            xmlErrValid(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"Internal: ATTRIBUTE struct corrupted invalid type\n\0" as *const u8 as *const i8,
                0 as *const i8,
            );
            xmlFreeEnumeration(tree);
            return 0 as xmlAttributePtr;
        }
    }
    if !defaultValue.is_null()
        && xmlValidateAttributeValueInternal(unsafe { (*dtd).doc }, type_0, defaultValue) == 0
    {
        xmlErrValidNode(
            ctxt,
            dtd as xmlNodePtr,
            XML_DTD_ATTRIBUTE_DEFAULT,
            b"Attribute %s of %s: invalid default value\n\0" as *const u8 as *const i8,
            elem,
            name,
            defaultValue,
        );
        defaultValue = 0 as *const xmlChar;
        if !ctxt.is_null() {
            (unsafe { (*ctxt).valid = 0 as i32 });
        }
    }
    if !(unsafe { (*dtd).doc }).is_null()
        && (unsafe { (*(*dtd).doc).extSubset }) == dtd
        && !(unsafe { (*(*dtd).doc).intSubset }).is_null()
        && !(unsafe { (*(*(*dtd).doc).intSubset).attributes }).is_null()
    {
        ret = (unsafe {
            xmlHashLookup3(
                (*(*(*dtd).doc).intSubset).attributes as xmlHashTablePtr,
                name,
                ns,
                elem,
            )
        }) as xmlAttributePtr;
        if !ret.is_null() {
            xmlFreeEnumeration(tree);
            return 0 as xmlAttributePtr;
        }
    }
    table = (unsafe { (*dtd).attributes }) as xmlAttributeTablePtr;
    if table.is_null() {
        table = unsafe { xmlHashCreateDict(0 as i32, dict) };
        let fresh88 = unsafe { &mut ((*dtd).attributes) };
        *fresh88 = table as *mut libc::c_void;
    }
    if table.is_null() {
        xmlVErrMemory(
            ctxt,
            b"xmlAddAttributeDecl: Table creation failed!\n\0" as *const u8 as *const i8,
        );
        xmlFreeEnumeration(tree);
        return 0 as xmlAttributePtr;
    }
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlAttribute>() as u64)
    }) as xmlAttributePtr;
    if ret.is_null() {
        xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const i8);
        xmlFreeEnumeration(tree);
        return 0 as xmlAttributePtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlAttribute>() as u64,
        )
    });
    (unsafe { (*ret).type_0 = XML_ATTRIBUTE_DECL });
    (unsafe { (*ret).atype = type_0 });
    let fresh89 = unsafe { &mut ((*ret).doc) };
    *fresh89 = unsafe { (*dtd).doc };
    if !dict.is_null() {
        let fresh90 = unsafe { &mut ((*ret).name) };
        *fresh90 = unsafe { xmlDictLookup(dict, name, -(1 as i32)) };
        let fresh91 = unsafe { &mut ((*ret).prefix) };
        *fresh91 = unsafe { xmlDictLookup(dict, ns, -(1 as i32)) };
        let fresh92 = unsafe { &mut ((*ret).elem) };
        *fresh92 = unsafe { xmlDictLookup(dict, elem, -(1 as i32)) };
    } else {
        let fresh93 = unsafe { &mut ((*ret).name) };
        *fresh93 = xmlStrdup(name);
        let fresh94 = unsafe { &mut ((*ret).prefix) };
        *fresh94 = xmlStrdup(ns);
        let fresh95 = unsafe { &mut ((*ret).elem) };
        *fresh95 = xmlStrdup(elem);
    }
    (unsafe { (*ret).def = def });
    let fresh96 = unsafe { &mut ((*ret).tree) };
    *fresh96 = tree;
    if !defaultValue.is_null() {
        if !dict.is_null() {
            let fresh97 = unsafe { &mut ((*ret).defaultValue) };
            *fresh97 = unsafe { xmlDictLookup(dict, defaultValue, -(1 as i32)) };
        } else {
            let fresh98 = unsafe { &mut ((*ret).defaultValue) };
            *fresh98 = xmlStrdup(defaultValue);
        }
    }
    if (unsafe {
        xmlHashAddEntry3(
            table,
            (*ret).name,
            (*ret).prefix,
            (*ret).elem,
            ret as *mut libc::c_void,
        )
    }) < 0 as i32
    {
        xmlErrValidWarning(
            ctxt,
            dtd as xmlNodePtr,
            XML_DTD_ATTRIBUTE_REDEFINED,
            b"Attribute %s of element %s: already defined\n\0" as *const u8 as *const i8,
            name,
            elem,
            0 as *const xmlChar,
        );
        xmlFreeAttribute(ret);
        return 0 as xmlAttributePtr;
    }
    elemDef = xmlGetDtdElementDesc2(dtd, elem, 1 as i32);
    if !elemDef.is_null() {
        if type_0 as u32 == XML_ATTRIBUTE_ID as i32 as u32
            && xmlScanIDAttributeDecl(0 as xmlValidCtxtPtr, elemDef, 1 as i32) != 0 as i32
        {
            xmlErrValidNode(
                ctxt,
                dtd as xmlNodePtr,
                XML_DTD_MULTIPLE_ID,
                b"Element %s has too may ID attributes defined : %s\n\0" as *const u8 as *const i8,
                elem,
                name,
                0 as *const xmlChar,
            );
            if !ctxt.is_null() {
                (unsafe { (*ctxt).valid = 0 as i32 });
            }
        }
        if xmlStrEqual(
            unsafe { (*ret).name },
            b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
            || !(unsafe { (*ret).prefix }).is_null()
                && xmlStrEqual(
                    unsafe { (*ret).prefix },
                    b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
        {
            let fresh99 = unsafe { &mut ((*ret).nexth) };
            *fresh99 = unsafe { (*elemDef).attributes };
            let fresh100 = unsafe { &mut ((*elemDef).attributes) };
            *fresh100 = ret;
        } else {
            let mut tmp: *mut crate::src::tree::_xmlAttribute = unsafe { (*elemDef).attributes };
            while !tmp.is_null()
                && (xmlStrEqual(
                    unsafe { (*tmp).name },
                    b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
                    || !(unsafe { (*ret).prefix }).is_null()
                        && xmlStrEqual(
                            unsafe { (*ret).prefix },
                            b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                        ) != 0)
            {
                if (unsafe { (*tmp).nexth }).is_null() {
                    break;
                }
                tmp = unsafe { (*tmp).nexth };
            }
            if !tmp.is_null() {
                let fresh101 = unsafe { &mut ((*ret).nexth) };
                *fresh101 = unsafe { (*tmp).nexth };
                let fresh102 = unsafe { &mut ((*tmp).nexth) };
                *fresh102 = ret;
            } else {
                let fresh103 = unsafe { &mut ((*ret).nexth) };
                *fresh103 = unsafe { (*elemDef).attributes };
                let fresh104 = unsafe { &mut ((*elemDef).attributes) };
                *fresh104 = ret;
            }
        }
    }
    let fresh105 = unsafe { &mut ((*ret).parent) };
    *fresh105 = dtd;
    if (unsafe { (*dtd).last }).is_null() {
        let fresh106 = unsafe { &mut ((*dtd).last) };
        *fresh106 = ret as xmlNodePtr;
        let fresh107 = unsafe { &mut ((*dtd).children) };
        *fresh107 = *fresh106;
    } else {
        let fresh108 = unsafe { &mut ((*(*dtd).last).next) };
        *fresh108 = ret as xmlNodePtr;
        let fresh109 = unsafe { &mut ((*ret).prev) };
        *fresh109 = unsafe { (*dtd).last };
        let fresh110 = unsafe { &mut ((*dtd).last) };
        *fresh110 = ret as xmlNodePtr;
    }
    return ret;
}
extern "C" fn xmlFreeAttributeTableEntry(mut attr: *mut core::ffi::c_void, mut _name: *const u8) {
    xmlFreeAttribute(attr as xmlAttributePtr);
}
#[no_mangle]
pub extern "C" fn xmlFreeAttributeTable(mut table: *mut crate::src::xmlsave::_xmlHashTable) {
    (unsafe { xmlHashFree(table, Some(xmlFreeAttributeTableEntry)) });
}
extern "C" fn xmlCopyAttribute(
    mut payload: *mut core::ffi::c_void,
    mut _name: *const u8,
) -> *mut core::ffi::c_void {
    let mut attr: *mut crate::src::tree::_xmlAttribute = payload as xmlAttributePtr;
    let mut cur: *mut crate::src::tree::_xmlAttribute = 0 as *mut xmlAttribute;
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlAttribute>() as u64)
    }) as xmlAttributePtr;
    if cur.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const i8,
        );
        return 0 as *mut libc::c_void;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlAttribute>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_ATTRIBUTE_DECL });
    (unsafe { (*cur).atype = (*attr).atype });
    (unsafe { (*cur).def = (*attr).def });
    let fresh111 = unsafe { &mut ((*cur).tree) };
    *fresh111 = xmlCopyEnumeration(unsafe { (*attr).tree });
    if !(unsafe { (*attr).elem }).is_null() {
        let fresh112 = unsafe { &mut ((*cur).elem) };
        *fresh112 = xmlStrdup(unsafe { (*attr).elem });
    }
    if !(unsafe { (*attr).name }).is_null() {
        let fresh113 = unsafe { &mut ((*cur).name) };
        *fresh113 = xmlStrdup(unsafe { (*attr).name });
    }
    if !(unsafe { (*attr).prefix }).is_null() {
        let fresh114 = unsafe { &mut ((*cur).prefix) };
        *fresh114 = xmlStrdup(unsafe { (*attr).prefix });
    }
    if !(unsafe { (*attr).defaultValue }).is_null() {
        let fresh115 = unsafe { &mut ((*cur).defaultValue) };
        *fresh115 = xmlStrdup(unsafe { (*attr).defaultValue });
    }
    return cur as *mut libc::c_void;
}
#[no_mangle]
pub extern "C" fn xmlCopyAttributeTable(
    mut table: *mut crate::src::xmlsave::_xmlHashTable,
) -> *mut crate::src::xmlsave::_xmlHashTable {
    return (unsafe { xmlHashCopy(table, Some(xmlCopyAttribute)) }) as xmlAttributeTablePtr;
}
#[no_mangle]
pub extern "C" fn xmlDumpAttributeDecl(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut attr: *mut crate::src::tree::_xmlAttribute,
) {
    if buf.is_null() || attr.is_null() {
        return;
    }
    xmlBufferWriteChar(buf, b"<!ATTLIST \0" as *const u8 as *const i8);
    xmlBufferWriteCHAR(buf, unsafe { (*attr).elem });
    xmlBufferWriteChar(buf, b" \0" as *const u8 as *const i8);
    if !(unsafe { (*attr).prefix }).is_null() {
        xmlBufferWriteCHAR(buf, unsafe { (*attr).prefix });
        xmlBufferWriteChar(buf, b":\0" as *const u8 as *const i8);
    }
    xmlBufferWriteCHAR(buf, unsafe { (*attr).name });
    match (unsafe { (*attr).atype }) as u32 {
        1 => {
            xmlBufferWriteChar(buf, b" CDATA\0" as *const u8 as *const i8);
        }
        2 => {
            xmlBufferWriteChar(buf, b" ID\0" as *const u8 as *const i8);
        }
        3 => {
            xmlBufferWriteChar(buf, b" IDREF\0" as *const u8 as *const i8);
        }
        4 => {
            xmlBufferWriteChar(buf, b" IDREFS\0" as *const u8 as *const i8);
        }
        5 => {
            xmlBufferWriteChar(buf, b" ENTITY\0" as *const u8 as *const i8);
        }
        6 => {
            xmlBufferWriteChar(buf, b" ENTITIES\0" as *const u8 as *const i8);
        }
        7 => {
            xmlBufferWriteChar(buf, b" NMTOKEN\0" as *const u8 as *const i8);
        }
        8 => {
            xmlBufferWriteChar(buf, b" NMTOKENS\0" as *const u8 as *const i8);
        }
        9 => {
            xmlBufferWriteChar(buf, b" (\0" as *const u8 as *const i8);
            xmlDumpEnumeration(buf, unsafe { (*attr).tree });
        }
        10 => {
            xmlBufferWriteChar(buf, b" NOTATION (\0" as *const u8 as *const i8);
            xmlDumpEnumeration(buf, unsafe { (*attr).tree });
        }
        _ => {
            xmlErrValid(
                0 as xmlValidCtxtPtr,
                XML_ERR_INTERNAL_ERROR,
                b"Internal: ATTRIBUTE struct corrupted invalid type\n\0" as *const u8 as *const i8,
                0 as *const i8,
            );
        }
    }
    match (unsafe { (*attr).def }) as u32 {
        1 => {}
        2 => {
            xmlBufferWriteChar(buf, b" #REQUIRED\0" as *const u8 as *const i8);
        }
        3 => {
            xmlBufferWriteChar(buf, b" #IMPLIED\0" as *const u8 as *const i8);
        }
        4 => {
            xmlBufferWriteChar(buf, b" #FIXED\0" as *const u8 as *const i8);
        }
        _ => {
            xmlErrValid(
                0 as xmlValidCtxtPtr,
                XML_ERR_INTERNAL_ERROR,
                b"Internal: ATTRIBUTE struct corrupted invalid def\n\0" as *const u8 as *const i8,
                0 as *const i8,
            );
        }
    }
    if !(unsafe { (*attr).defaultValue }).is_null() {
        xmlBufferWriteChar(buf, b" \0" as *const u8 as *const i8);
        xmlBufferWriteQuotedString(buf, unsafe { (*attr).defaultValue });
    }
    xmlBufferWriteChar(buf, b">\n\0" as *const u8 as *const i8);
}
extern "C" fn xmlDumpAttributeDeclScan(
    mut attr: *mut core::ffi::c_void,
    mut buf: *mut core::ffi::c_void,
    mut _name: *const u8,
) {
    xmlDumpAttributeDecl(buf as xmlBufferPtr, attr as xmlAttributePtr);
}
#[no_mangle]
pub extern "C" fn xmlDumpAttributeTable(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut table: *mut crate::src::xmlsave::_xmlHashTable,
) {
    if buf.is_null() || table.is_null() {
        return;
    }
    (unsafe {
        xmlHashScan(
            table,
            Some(xmlDumpAttributeDeclScan),
            buf as *mut libc::c_void,
        )
    });
}
extern "C" fn xmlFreeNotation(mut nota: *mut crate::src::valid::_xmlNotation) {
    if nota.is_null() {
        return;
    }
    if !(unsafe { (*nota).name }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*nota).name as *mut xmlChar as *mut libc::c_void,
            )
        });
    }
    if !(unsafe { (*nota).PublicID }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*nota).PublicID as *mut xmlChar as *mut libc::c_void,
            )
        });
    }
    if !(unsafe { (*nota).SystemID }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*nota).SystemID as *mut xmlChar as *mut libc::c_void,
            )
        });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(nota as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlAddNotationDecl<'a1>(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut dtd: Option<&'a1 mut crate::src::threads::_xmlDtd>,
    mut name: *const u8,
    mut PublicID: *const u8,
    mut SystemID: *const u8,
) -> *mut crate::src::valid::_xmlNotation {
    let mut ret: *mut crate::src::valid::_xmlNotation = 0 as *mut xmlNotation;
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlNotationTable;
    if borrow(&dtd).is_none() {
        return 0 as xmlNotationPtr;
    }
    if name.is_null() {
        return 0 as xmlNotationPtr;
    }
    if PublicID.is_null() && SystemID.is_null() {
        return 0 as xmlNotationPtr;
    }
    table = (*(borrow_mut(&mut dtd)).unwrap()).notations as xmlNotationTablePtr;
    if table.is_null() {
        let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as xmlDictPtr;
        if !((*(borrow_mut(&mut dtd)).unwrap()).doc).is_null() {
            dict = unsafe { (*(*(borrow_mut(&mut dtd)).unwrap()).doc).dict };
        }
        table = unsafe { xmlHashCreateDict(0 as i32, dict) };
        let fresh116 = &mut ((*(borrow_mut(&mut dtd)).unwrap()).notations);
        *fresh116 = table as *mut libc::c_void;
    }
    if table.is_null() {
        xmlVErrMemory(
            ctxt,
            b"xmlAddNotationDecl: Table creation failed!\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlNotationPtr;
    }
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNotation>() as u64)
    }) as xmlNotationPtr;
    if ret.is_null() {
        xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const i8);
        return 0 as xmlNotationPtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNotation>() as u64,
        )
    });
    let fresh117 = unsafe { &mut ((*ret).name) };
    *fresh117 = xmlStrdup(name);
    if !SystemID.is_null() {
        let fresh118 = unsafe { &mut ((*ret).SystemID) };
        *fresh118 = xmlStrdup(SystemID);
    }
    if !PublicID.is_null() {
        let fresh119 = unsafe { &mut ((*ret).PublicID) };
        *fresh119 = xmlStrdup(PublicID);
    }
    if (unsafe { xmlHashAddEntry(table, name, ret as *mut libc::c_void) }) != 0 {
        xmlErrValid(
            0 as xmlValidCtxtPtr,
            XML_DTD_NOTATION_REDEFINED,
            b"xmlAddNotationDecl: %s already defined\n\0" as *const u8 as *const i8,
            name as *const i8,
        );
        xmlFreeNotation(ret);
        return 0 as xmlNotationPtr;
    }
    return ret;
}
extern "C" fn xmlFreeNotationTableEntry(mut nota: *mut core::ffi::c_void, mut _name: *const u8) {
    xmlFreeNotation(nota as xmlNotationPtr);
}
#[no_mangle]
pub extern "C" fn xmlFreeNotationTable(mut table: *mut crate::src::xmlsave::_xmlHashTable) {
    (unsafe { xmlHashFree(table, Some(xmlFreeNotationTableEntry)) });
}
extern "C" fn xmlCopyNotation(
    mut payload: *mut core::ffi::c_void,
    mut _name: *const u8,
) -> *mut core::ffi::c_void {
    let mut nota: *mut crate::src::valid::_xmlNotation = payload as xmlNotationPtr;
    let mut cur: *mut crate::src::valid::_xmlNotation = 0 as *mut xmlNotation;
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNotation>() as u64)
    }) as xmlNotationPtr;
    if cur.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const i8,
        );
        return 0 as *mut libc::c_void;
    }
    if !(unsafe { (*nota).name }).is_null() {
        let fresh120 = unsafe { &mut ((*cur).name) };
        *fresh120 = xmlStrdup(unsafe { (*nota).name });
    } else {
        let fresh121 = unsafe { &mut ((*cur).name) };
        *fresh121 = 0 as *const xmlChar;
    }
    if !(unsafe { (*nota).PublicID }).is_null() {
        let fresh122 = unsafe { &mut ((*cur).PublicID) };
        *fresh122 = xmlStrdup(unsafe { (*nota).PublicID });
    } else {
        let fresh123 = unsafe { &mut ((*cur).PublicID) };
        *fresh123 = 0 as *const xmlChar;
    }
    if !(unsafe { (*nota).SystemID }).is_null() {
        let fresh124 = unsafe { &mut ((*cur).SystemID) };
        *fresh124 = xmlStrdup(unsafe { (*nota).SystemID });
    } else {
        let fresh125 = unsafe { &mut ((*cur).SystemID) };
        *fresh125 = 0 as *const xmlChar;
    }
    return cur as *mut libc::c_void;
}
#[no_mangle]
pub extern "C" fn xmlCopyNotationTable(
    mut table: *mut crate::src::xmlsave::_xmlHashTable,
) -> *mut crate::src::xmlsave::_xmlHashTable {
    return (unsafe { xmlHashCopy(table, Some(xmlCopyNotation)) }) as xmlNotationTablePtr;
}
#[no_mangle]
pub extern "C" fn xmlDumpNotationDecl(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut nota: *mut crate::src::valid::_xmlNotation,
) {
    if buf.is_null() || nota.is_null() {
        return;
    }
    xmlBufferWriteChar(buf, b"<!NOTATION \0" as *const u8 as *const i8);
    xmlBufferWriteCHAR(buf, unsafe { (*nota).name });
    if !(unsafe { (*nota).PublicID }).is_null() {
        xmlBufferWriteChar(buf, b" PUBLIC \0" as *const u8 as *const i8);
        xmlBufferWriteQuotedString(buf, unsafe { (*nota).PublicID });
        if !(unsafe { (*nota).SystemID }).is_null() {
            xmlBufferWriteChar(buf, b" \0" as *const u8 as *const i8);
            xmlBufferWriteQuotedString(buf, unsafe { (*nota).SystemID });
        }
    } else {
        xmlBufferWriteChar(buf, b" SYSTEM \0" as *const u8 as *const i8);
        xmlBufferWriteQuotedString(buf, unsafe { (*nota).SystemID });
    }
    xmlBufferWriteChar(buf, b" >\n\0" as *const u8 as *const i8);
}
extern "C" fn xmlDumpNotationDeclScan(
    mut nota: *mut core::ffi::c_void,
    mut buf: *mut core::ffi::c_void,
    mut _name: *const u8,
) {
    xmlDumpNotationDecl(buf as xmlBufferPtr, nota as xmlNotationPtr);
}
#[no_mangle]
pub extern "C" fn xmlDumpNotationTable(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut table: *mut crate::src::xmlsave::_xmlHashTable,
) {
    if buf.is_null() || table.is_null() {
        return;
    }
    (unsafe {
        xmlHashScan(
            table,
            Some(xmlDumpNotationDeclScan),
            buf as *mut libc::c_void,
        )
    });
}
extern "C" fn xmlValidNormalizeString(mut str: *mut u8) {
    let mut dst: *mut u8 = 0 as *mut xmlChar;
    let mut src: *const u8 = 0 as *const xmlChar;
    if str.is_null() {
        return;
    }
    src = str;
    dst = str;
    while (unsafe { *src }) as i32 == 0x20 as i32 {
        src = unsafe { src.offset(1) };
    }
    while (unsafe { *src }) as i32 != 0 as i32 {
        if (unsafe { *src }) as i32 == 0x20 as i32 {
            while (unsafe { *src }) as i32 == 0x20 as i32 {
                src = unsafe { src.offset(1) };
            }
            if (unsafe { *src }) as i32 != 0 as i32 {
                let mut fresh126 = dst;
                dst = unsafe { dst.offset(1) };
                (unsafe { *fresh126 = 0x20 as i32 as xmlChar });
            }
        } else {
            let mut fresh127 = src;
            src = unsafe { src.offset(1) };
            let mut fresh128 = dst;
            dst = unsafe { dst.offset(1) };
            (unsafe { *fresh128 = *fresh127 });
        }
    }
    (unsafe { *dst = 0 as i32 as xmlChar });
}
extern "C" fn xmlIsStreaming(mut ctxt: *mut crate::src::tree::_xmlValidCtxt) -> i32 {
    let mut pctxt: *mut crate::src::tree::_xmlParserCtxt =
        0 as *mut crate::src::tree::_xmlParserCtxt;
    if ctxt.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*ctxt).flags }) & (1 as u32) << 1 as i32 == 0 as i32 as u32 {
        return 0 as i32;
    }
    pctxt = (unsafe { (*ctxt).userData }) as xmlParserCtxtPtr;
    return ((unsafe { (*pctxt).parseMode }) as u32 == XML_PARSE_READER as i32 as u32) as i32;
}
extern "C" fn xmlFreeID<'a1>(mut id: *mut crate::src::tree::_xmlID<'a1>) {
    let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as xmlDictPtr;
    if id.is_null() {
        return;
    }
    if !(unsafe { (*id).doc }).is_null() {
        dict = unsafe { (*(*id).doc).dict };
    }
    if !(unsafe { (*id).value }).is_null() {
        if !(unsafe { (*id).value }).is_null()
            && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*id).value) }) == 0 as i32)
        {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*id).value as *mut i8 as *mut libc::c_void,
                )
            });
        }
    }
    if !(unsafe { (*id).name }).is_null() {
        if !(unsafe { (*id).name }).is_null()
            && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*id).name) }) == 0 as i32)
        {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*id).name as *mut i8 as *mut libc::c_void,
                )
            });
        }
    }
    (unsafe { xmlFree.expect("non-null function pointer")(id as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlAddID<'a1>(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut value: *const u8,
    mut attr: *mut crate::src::threads::_xmlAttr,
) -> *mut crate::src::tree::_xmlID<'a1> {
    let mut ret: *mut crate::src::tree::_xmlID<'_> = 0 as *mut xmlID;
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlIDTable;
    if doc.is_null() {
        return 0 as xmlIDPtr;
    }
    if value.is_null() || (unsafe { *value.offset(0 as i32 as isize) }) as i32 == 0 as i32 {
        return 0 as xmlIDPtr;
    }
    if attr.is_null() {
        return 0 as xmlIDPtr;
    }
    table = (unsafe { (*doc).ids }) as xmlIDTablePtr;
    if table.is_null() {
        table = unsafe { xmlHashCreateDict(0 as i32, (*doc).dict) };
        let fresh129 = unsafe { &mut ((*doc).ids) };
        *fresh129 = table as *mut libc::c_void;
    }
    if table.is_null() {
        xmlVErrMemory(
            ctxt,
            b"xmlAddID: Table creation failed!\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlIDPtr;
    }
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlID>() as u64)
    }) as xmlIDPtr;
    if ret.is_null() {
        xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const i8);
        return 0 as xmlIDPtr;
    }
    let fresh130 = unsafe { &mut ((*ret).value) };
    *fresh130 = xmlStrdup(value);
    let fresh131 = unsafe { &mut ((*ret).doc) };
    *fresh131 = doc;
    if xmlIsStreaming(ctxt) != 0 {
        if !(unsafe { (*doc).dict }).is_null() {
            let fresh132 = unsafe { &mut ((*ret).name) };
            *fresh132 = unsafe { xmlDictLookup((*doc).dict, (*attr).name, -(1 as i32)) };
        } else {
            let fresh133 = unsafe { &mut ((*ret).name) };
            *fresh133 = xmlStrdup(unsafe { (*attr).name });
        }
        let fresh134 = unsafe { &mut ((*ret).attr) };
        *fresh134 = 0 as xmlAttrPtr;
    } else {
        let fresh135 = unsafe { &mut ((*ret).attr) };
        *fresh135 = attr;
        let fresh136 = unsafe { &mut ((*ret).name) };
        *fresh136 = 0 as *const xmlChar;
    }
    (unsafe { (*ret).lineno = xmlGetLineNo((*attr).parent) as i32 });
    if (unsafe { xmlHashAddEntry(table, value, ret as *mut libc::c_void) }) < 0 as i32 {
        if !ctxt.is_null() {
            xmlErrValidNode(
                ctxt,
                unsafe { (*attr).parent },
                XML_DTD_ID_REDEFINED,
                b"ID %s already defined\n\0" as *const u8 as *const i8,
                value,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        xmlFreeID(ret);
        return 0 as xmlIDPtr;
    }
    if !attr.is_null() {
        (unsafe { (*attr).atype = XML_ATTRIBUTE_ID });
    }
    return ret;
}
extern "C" fn xmlFreeIDTableEntry(mut id: *mut core::ffi::c_void, mut _name: *const u8) {
    xmlFreeID(id as xmlIDPtr);
}
#[no_mangle]
pub extern "C" fn xmlFreeIDTable(mut table: *mut crate::src::xmlsave::_xmlHashTable) {
    (unsafe { xmlHashFree(table, Some(xmlFreeIDTableEntry)) });
}
#[no_mangle]
pub extern "C" fn xmlIsID(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut elem: *mut crate::src::threads::_xmlNode,
    mut attr: *mut crate::src::threads::_xmlAttr,
) -> i32 {
    if attr.is_null() || (unsafe { (*attr).name }).is_null() {
        return 0 as i32;
    }
    if !(unsafe { (*attr).ns }).is_null()
        && !(unsafe { (*(*attr).ns).prefix }).is_null()
        && (unsafe { strcmp((*attr).name as *mut i8, b"id\0" as *const u8 as *const i8) }) == 0
        && (unsafe {
            strcmp(
                (*(*attr).ns).prefix as *mut i8,
                b"xml\0" as *const u8 as *const i8,
            )
        }) == 0
    {
        return 1 as i32;
    }
    if doc.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*doc).intSubset }).is_null()
        && (unsafe { (*doc).extSubset }).is_null()
        && (unsafe { (*doc).type_0 }) as u32 != XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        return 0 as i32;
    } else {
        if (unsafe { (*doc).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32 {
            if xmlStrEqual(
                b"id\0" as *const u8 as *const i8 as *mut xmlChar,
                unsafe { (*attr).name },
            ) != 0
                || xmlStrEqual(
                    b"name\0" as *const u8 as *const i8 as *mut xmlChar,
                    unsafe { (*attr).name },
                ) != 0
                    && (elem.is_null()
                        || xmlStrEqual(
                            unsafe { (*elem).name },
                            b"a\0" as *const u8 as *const i8 as *mut xmlChar,
                        ) != 0)
            {
                return 1 as i32;
            }
            return 0 as i32;
        } else {
            if elem.is_null() {
                return 0 as i32;
            } else {
                let mut attrDecl: *mut crate::src::tree::_xmlAttribute = 0 as xmlAttributePtr;
                let mut felem: [u8; 50] = [0; 50];
                let mut fattr: [u8; 50] = [0; 50];
                let mut fullelemname: *mut u8 = 0 as *mut xmlChar;
                let mut fullattrname: *mut u8 = 0 as *mut xmlChar;
                fullelemname = if !(unsafe { (*elem).ns }).is_null()
                    && !(unsafe { (*(*elem).ns).prefix }).is_null()
                {
                    xmlBuildQName(
                        unsafe { (*elem).name },
                        unsafe { (*(*elem).ns).prefix },
                        felem.as_mut_ptr(),
                        50 as i32,
                    )
                } else {
                    (unsafe { (*elem).name }) as *mut xmlChar
                };
                fullattrname = if !(unsafe { (*attr).ns }).is_null()
                    && !(unsafe { (*(*attr).ns).prefix }).is_null()
                {
                    xmlBuildQName(
                        unsafe { (*attr).name },
                        unsafe { (*(*attr).ns).prefix },
                        fattr.as_mut_ptr(),
                        50 as i32,
                    )
                } else {
                    (unsafe { (*attr).name }) as *mut xmlChar
                };
                if !fullelemname.is_null() && !fullattrname.is_null() {
                    attrDecl = xmlGetDtdAttrDesc(
                        unsafe { (*doc).intSubset },
                        fullelemname,
                        fullattrname,
                    );
                    if attrDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                        attrDecl = xmlGetDtdAttrDesc(
                            unsafe { (*doc).extSubset },
                            fullelemname,
                            fullattrname,
                        );
                    }
                }
                if fullattrname != fattr.as_mut_ptr()
                    && fullattrname != (unsafe { (*attr).name }) as *mut xmlChar
                {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(
                            fullattrname as *mut libc::c_void,
                        )
                    });
                }
                if fullelemname != felem.as_mut_ptr()
                    && fullelemname != (unsafe { (*elem).name }) as *mut xmlChar
                {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(
                            fullelemname as *mut libc::c_void,
                        )
                    });
                }
                if !attrDecl.is_null()
                    && (unsafe { (*attrDecl).atype }) as u32 == XML_ATTRIBUTE_ID as i32 as u32
                {
                    return 1 as i32;
                }
            }
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlRemoveID(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut attr: *mut crate::src::threads::_xmlAttr,
) -> i32 {
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlIDTable;
    let mut id: *mut crate::src::tree::_xmlID<'_> = 0 as *mut crate::src::tree::_xmlID<'_>;
    let mut ID: *mut u8 = 0 as *mut xmlChar;
    if doc.is_null() {
        return -(1 as i32);
    }
    if attr.is_null() {
        return -(1 as i32);
    }
    table = (unsafe { (*doc).ids }) as xmlIDTablePtr;
    if table.is_null() {
        return -(1 as i32);
    }
    ID = xmlNodeListGetString(doc, unsafe { (*attr).children }, 1 as i32);
    if ID.is_null() {
        return -(1 as i32);
    }
    xmlValidNormalizeString(ID);
    id = (unsafe { xmlHashLookup(table, ID) }) as xmlIDPtr;
    if id.is_null() || (unsafe { (*id).attr }) != attr {
        (unsafe { xmlFree.expect("non-null function pointer")(ID as *mut libc::c_void) });
        return -(1 as i32);
    }
    (unsafe { xmlHashRemoveEntry(table, ID, Some(xmlFreeIDTableEntry)) });
    (unsafe { xmlFree.expect("non-null function pointer")(ID as *mut libc::c_void) });
    (unsafe { (*attr).atype = 0 as xmlAttributeType });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlGetID(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut ID: *const u8,
) -> *mut crate::src::threads::_xmlAttr {
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlIDTable;
    let mut id: *mut crate::src::tree::_xmlID<'_> = 0 as *mut crate::src::tree::_xmlID<'_>;
    if doc.is_null() {
        return 0 as xmlAttrPtr;
    }
    if ID.is_null() {
        return 0 as xmlAttrPtr;
    }
    table = (unsafe { (*doc).ids }) as xmlIDTablePtr;
    if table.is_null() {
        return 0 as xmlAttrPtr;
    }
    id = (unsafe { xmlHashLookup(table, ID) }) as xmlIDPtr;
    if id.is_null() {
        return 0 as xmlAttrPtr;
    }
    if (unsafe { (*id).attr }).is_null() {
        return doc as xmlAttrPtr;
    }
    return unsafe { (*id).attr };
}
extern "C" fn xmlFreeRef(mut lk: *mut crate::src::valid::_xmlLink) {
    let mut ref_0: *mut crate::src::valid::_xmlRef<'_> =
        (unsafe { xmlLinkGetData(lk) }) as xmlRefPtr;
    if ref_0.is_null() {
        return;
    }
    if !(unsafe { (*ref_0).value }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*ref_0).value as *mut xmlChar as *mut libc::c_void,
            )
        });
    }
    if !(unsafe { (*ref_0).name }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*ref_0).name as *mut xmlChar as *mut libc::c_void,
            )
        });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(ref_0 as *mut libc::c_void) });
}
extern "C" fn xmlFreeRefTableEntry(mut payload: *mut core::ffi::c_void, mut _name: *const u8) {
    let mut list_ref: *mut crate::src::xmlwriter::_xmlList = payload as xmlListPtr;
    if list_ref.is_null() {
        return;
    }
    (unsafe { xmlListDelete(list_ref) });
}
extern "C" fn xmlWalkRemoveRef(
    mut data: *const core::ffi::c_void,
    mut user: *mut core::ffi::c_void,
) -> i32 {
    let mut attr0: *mut crate::src::threads::_xmlAttr = unsafe { (*(data as xmlRefPtr)).attr };
    let mut attr1: *mut crate::src::threads::_xmlAttr =
        unsafe { (*(user as xmlRemoveMemoPtr)).ap };
    let mut ref_list: *mut crate::src::xmlwriter::_xmlList =
        unsafe { (*(user as xmlRemoveMemoPtr)).l };
    if attr0 == attr1 {
        (unsafe { xmlListRemoveFirst(ref_list, data as *mut libc::c_void) });
        return 0 as i32;
    }
    return 1 as i32;
}
extern "C" fn xmlDummyCompare(
    mut _data0: *const core::ffi::c_void,
    mut _data1: *const core::ffi::c_void,
) -> i32 {
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlAddRef<'a1>(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut value: *const u8,
    mut attr: *mut crate::src::threads::_xmlAttr,
) -> *mut crate::src::valid::_xmlRef<'a1> {
    let mut current_block: u64;
    let mut ret: *mut crate::src::valid::_xmlRef<'_> = 0 as *mut xmlRef;
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlRefTable;
    let mut ref_list: *mut crate::src::xmlwriter::_xmlList = 0 as *mut xmlList;
    if doc.is_null() {
        return 0 as xmlRefPtr;
    }
    if value.is_null() {
        return 0 as xmlRefPtr;
    }
    if attr.is_null() {
        return 0 as xmlRefPtr;
    }
    table = (unsafe { (*doc).refs }) as xmlRefTablePtr;
    if table.is_null() {
        table = unsafe { xmlHashCreateDict(0 as i32, (*doc).dict) };
        let fresh137 = unsafe { &mut ((*doc).refs) };
        *fresh137 = table as *mut libc::c_void;
    }
    if table.is_null() {
        xmlVErrMemory(
            ctxt,
            b"xmlAddRef: Table creation failed!\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlRefPtr;
    }
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlRef>() as u64)
    }) as xmlRefPtr;
    if ret.is_null() {
        xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const i8);
        return 0 as xmlRefPtr;
    }
    let fresh138 = unsafe { &mut ((*ret).value) };
    *fresh138 = xmlStrdup(value);
    if xmlIsStreaming(ctxt) != 0 {
        let fresh139 = unsafe { &mut ((*ret).name) };
        *fresh139 = xmlStrdup(unsafe { (*attr).name });
        let fresh140 = unsafe { &mut ((*ret).attr) };
        *fresh140 = 0 as xmlAttrPtr;
    } else {
        let fresh141 = unsafe { &mut ((*ret).name) };
        *fresh141 = 0 as *const xmlChar;
        let fresh142 = unsafe { &mut ((*ret).attr) };
        *fresh142 = attr;
    }
    (unsafe { (*ret).lineno = xmlGetLineNo((*attr).parent) as i32 });
    ref_list = (unsafe { xmlHashLookup(table, value) }) as xmlListPtr;
    if ref_list.is_null() {
        ref_list = unsafe { xmlListCreate(Some(xmlFreeRef), Some(xmlDummyCompare)) };
        if ref_list.is_null() {
            xmlErrValid(
                0 as xmlValidCtxtPtr,
                XML_ERR_INTERNAL_ERROR,
                b"xmlAddRef: Reference list creation failed!\n\0" as *const u8 as *const i8,
                0 as *const i8,
            );
            current_block = 11302113584356292201;
        } else if (unsafe { xmlHashAddEntry(table, value, ref_list as *mut libc::c_void) })
            < 0 as i32
        {
            (unsafe { xmlListDelete(ref_list) });
            xmlErrValid(
                0 as xmlValidCtxtPtr,
                XML_ERR_INTERNAL_ERROR,
                b"xmlAddRef: Reference list insertion failed!\n\0" as *const u8 as *const i8,
                0 as *const i8,
            );
            current_block = 11302113584356292201;
        } else {
            current_block = 7333393191927787629;
        }
    } else {
        current_block = 7333393191927787629;
    }
    match current_block {
        7333393191927787629 => {
            if (unsafe { xmlListAppend(ref_list, ret as *mut libc::c_void) }) != 0 as i32 {
                xmlErrValid(
                    0 as xmlValidCtxtPtr,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlAddRef: Reference list insertion failed!\n\0" as *const u8 as *const i8,
                    0 as *const i8,
                );
            } else {
                return ret;
            }
        }
        _ => {}
    }
    if !ret.is_null() {
        if !(unsafe { (*ret).value }).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*ret).value as *mut i8 as *mut libc::c_void,
                )
            });
        }
        if !(unsafe { (*ret).name }).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*ret).name as *mut i8 as *mut libc::c_void,
                )
            });
        }
        (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
    }
    return 0 as xmlRefPtr;
}
#[no_mangle]
pub extern "C" fn xmlFreeRefTable(mut table: *mut crate::src::xmlsave::_xmlHashTable) {
    (unsafe { xmlHashFree(table, Some(xmlFreeRefTableEntry)) });
}
#[no_mangle]
pub extern "C" fn xmlIsRef<'a1, 'a2>(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut elem: Option<&'a1 mut crate::src::threads::_xmlNode>,
    mut attr: Option<&'a2 mut crate::src::threads::_xmlAttr>,
) -> i32 {
    if borrow(&attr).is_none() {
        return 0 as i32;
    }
    if doc.is_null() {
        doc = (*(borrow_mut(&mut attr)).unwrap()).doc;
        if doc.is_null() {
            return 0 as i32;
        }
    }
    if (unsafe { (*doc).intSubset }).is_null() && (unsafe { (*doc).extSubset }).is_null() {
        return 0 as i32;
    } else {
        if (unsafe { (*doc).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32 {
            return 0 as i32;
        } else {
            let mut attrDecl: *mut crate::src::tree::_xmlAttribute = 0 as *mut xmlAttribute;
            if borrow(&elem).is_none() {
                return 0 as i32;
            }
            attrDecl = xmlGetDtdAttrDesc(
                unsafe { (*doc).intSubset },
                (*(borrow(&elem)).unwrap()).name,
                (*(borrow(&attr)).unwrap()).name,
            );
            if attrDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                attrDecl = xmlGetDtdAttrDesc(
                    unsafe { (*doc).extSubset },
                    (*(borrow(&elem)).unwrap()).name,
                    (*(borrow(&attr)).unwrap()).name,
                );
            }
            if !attrDecl.is_null()
                && ((unsafe { (*attrDecl).atype }) as u32 == XML_ATTRIBUTE_IDREF as i32 as u32
                    || (unsafe { (*attrDecl).atype }) as u32 == XML_ATTRIBUTE_IDREFS as i32 as u32)
            {
                return 1 as i32;
            }
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlRemoveRef(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut attr: *mut crate::src::threads::_xmlAttr,
) -> i32 {
    let mut ref_list: *mut crate::src::xmlwriter::_xmlList = 0 as *mut xmlList;
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlRefTable;
    let mut ID: *mut u8 = 0 as *mut xmlChar;
    let mut target: crate::src::valid::xmlRemoveMemo_t = xmlRemoveMemo {
        l: 0 as *mut xmlList,
        ap: 0 as *mut xmlAttr,
    };
    if doc.is_null() {
        return -(1 as i32);
    }
    if attr.is_null() {
        return -(1 as i32);
    }
    table = (unsafe { (*doc).refs }) as xmlRefTablePtr;
    if table.is_null() {
        return -(1 as i32);
    }
    ID = xmlNodeListGetString(doc, unsafe { (*attr).children }, 1 as i32);
    if ID.is_null() {
        return -(1 as i32);
    }
    ref_list = (unsafe { xmlHashLookup(table, ID) }) as xmlListPtr;
    if ref_list.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(ID as *mut libc::c_void) });
        return -(1 as i32);
    }
    target.l = ref_list;
    target.ap = attr;
    (unsafe {
        xmlListWalk(
            ref_list,
            Some(xmlWalkRemoveRef),
            &mut target as *mut xmlRemoveMemo as *mut libc::c_void,
        )
    });
    if (unsafe { xmlListEmpty(ref_list) }) != 0 {
        (unsafe {
            xmlHashUpdateEntry(
                table,
                ID,
                0 as *mut libc::c_void,
                Some(xmlFreeRefTableEntry),
            )
        });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(ID as *mut libc::c_void) });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlGetRefs<'a1>(
    mut doc: Option<&'a1 mut crate::src::threads::_xmlDoc>,
    mut ID: *const u8,
) -> *mut crate::src::xmlwriter::_xmlList {
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlRefTable;
    if borrow(&doc).is_none() {
        return 0 as *mut crate::src::xmlwriter::_xmlList;
    }
    if ID.is_null() {
        return 0 as *mut crate::src::xmlwriter::_xmlList;
    }
    table = (*(borrow_mut(&mut doc)).unwrap()).refs as xmlRefTablePtr;
    if table.is_null() {
        return 0 as *mut crate::src::xmlwriter::_xmlList;
    }
    return (unsafe { xmlHashLookup(table, ID) }) as xmlListPtr;
}
#[no_mangle]
pub extern "C" fn xmlGetDtdElementDesc(
    mut dtd: *mut crate::src::threads::_xmlDtd,
    mut name: *const u8,
) -> *mut crate::src::tree::_xmlElement {
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlElementTable;
    let mut cur: *mut crate::src::tree::_xmlElement = 0 as *mut xmlElement;
    let mut uqname: *mut u8 = 0 as *mut xmlChar;
    let mut prefix: *mut u8 = 0 as *mut xmlChar;
    if dtd.is_null() || name.is_null() {
        return 0 as xmlElementPtr;
    }
    if (unsafe { (*dtd).elements }).is_null() {
        return 0 as xmlElementPtr;
    }
    table = (unsafe { (*dtd).elements }) as xmlElementTablePtr;
    uqname = xmlSplitQName2(name, Some(&mut prefix));
    if !uqname.is_null() {
        name = uqname;
    }
    cur = (unsafe { xmlHashLookup2(table, name, prefix) }) as xmlElementPtr;
    if !prefix.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
    }
    if !uqname.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void) });
    }
    return cur;
}
extern "C" fn xmlGetDtdElementDesc2(
    mut dtd: *mut crate::src::threads::_xmlDtd,
    mut name: *const u8,
    mut create: i32,
) -> *mut crate::src::tree::_xmlElement {
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlElementTable;
    let mut cur: *mut crate::src::tree::_xmlElement = 0 as *mut xmlElement;
    let mut uqname: *mut u8 = 0 as *mut xmlChar;
    let mut prefix: *mut u8 = 0 as *mut xmlChar;
    if dtd.is_null() {
        return 0 as xmlElementPtr;
    }
    if (unsafe { (*dtd).elements }).is_null() {
        let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as xmlDictPtr;
        if !(unsafe { (*dtd).doc }).is_null() {
            dict = unsafe { (*(*dtd).doc).dict };
        }
        if create == 0 {
            return 0 as xmlElementPtr;
        }
        table = (unsafe { (*dtd).elements }) as xmlElementTablePtr;
        if table.is_null() {
            table = unsafe { xmlHashCreateDict(0 as i32, dict) };
            let fresh143 = unsafe { &mut ((*dtd).elements) };
            *fresh143 = table as *mut libc::c_void;
        }
        if table.is_null() {
            xmlVErrMemory(
                0 as xmlValidCtxtPtr,
                b"element table allocation failed\0" as *const u8 as *const i8,
            );
            return 0 as xmlElementPtr;
        }
    }
    table = (unsafe { (*dtd).elements }) as xmlElementTablePtr;
    uqname = xmlSplitQName2(name, Some(&mut prefix));
    if !uqname.is_null() {
        name = uqname;
    }
    cur = (unsafe { xmlHashLookup2(table, name, prefix) }) as xmlElementPtr;
    if cur.is_null() && create != 0 {
        cur = (unsafe {
            xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlElement>() as u64)
        }) as xmlElementPtr;
        if cur.is_null() {
            xmlVErrMemory(
                0 as xmlValidCtxtPtr,
                b"malloc failed\0" as *const u8 as *const i8,
            );
            return 0 as xmlElementPtr;
        }
        (unsafe {
            memset(
                cur as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<xmlElement>() as u64,
            )
        });
        (unsafe { (*cur).type_0 = XML_ELEMENT_DECL });
        let fresh144 = unsafe { &mut ((*cur).name) };
        *fresh144 = xmlStrdup(name);
        let fresh145 = unsafe { &mut ((*cur).prefix) };
        *fresh145 = xmlStrdup(prefix);
        (unsafe { (*cur).etype = XML_ELEMENT_TYPE_UNDEFINED });
        (unsafe { xmlHashAddEntry2(table, name, prefix, cur as *mut libc::c_void) });
    }
    if !prefix.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
    }
    if !uqname.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void) });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlGetDtdQElementDesc(
    mut dtd: *mut crate::src::threads::_xmlDtd,
    mut name: *const u8,
    mut prefix: *const u8,
) -> *mut crate::src::tree::_xmlElement {
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlElementTable;
    if dtd.is_null() {
        return 0 as xmlElementPtr;
    }
    if (unsafe { (*dtd).elements }).is_null() {
        return 0 as xmlElementPtr;
    }
    table = (unsafe { (*dtd).elements }) as xmlElementTablePtr;
    return (unsafe { xmlHashLookup2(table, name, prefix) }) as xmlElementPtr;
}
#[no_mangle]
pub extern "C" fn xmlGetDtdAttrDesc(
    mut dtd: *mut crate::src::threads::_xmlDtd,
    mut elem: *const u8,
    mut name: *const u8,
) -> *mut crate::src::tree::_xmlAttribute {
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlAttributeTable;
    let mut cur: *mut crate::src::tree::_xmlAttribute = 0 as *mut xmlAttribute;
    let mut uqname: *mut u8 = 0 as *mut xmlChar;
    let mut prefix: *mut u8 = 0 as *mut xmlChar;
    if dtd.is_null() {
        return 0 as xmlAttributePtr;
    }
    if (unsafe { (*dtd).attributes }).is_null() {
        return 0 as xmlAttributePtr;
    }
    table = (unsafe { (*dtd).attributes }) as xmlAttributeTablePtr;
    if table.is_null() {
        return 0 as xmlAttributePtr;
    }
    uqname = xmlSplitQName2(name, Some(&mut prefix));
    if !uqname.is_null() {
        cur = (unsafe { xmlHashLookup3(table, uqname, prefix, elem) }) as xmlAttributePtr;
        if !prefix.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
        }
        if !uqname.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void) });
        }
    } else {
        cur =
            (unsafe { xmlHashLookup3(table, name, 0 as *const xmlChar, elem) }) as xmlAttributePtr;
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlGetDtdQAttrDesc(
    mut dtd: *mut crate::src::threads::_xmlDtd,
    mut elem: *const u8,
    mut name: *const u8,
    mut prefix: *const u8,
) -> *mut crate::src::tree::_xmlAttribute {
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlAttributeTable;
    if dtd.is_null() {
        return 0 as xmlAttributePtr;
    }
    if (unsafe { (*dtd).attributes }).is_null() {
        return 0 as xmlAttributePtr;
    }
    table = (unsafe { (*dtd).attributes }) as xmlAttributeTablePtr;
    return (unsafe { xmlHashLookup3(table, name, prefix, elem) }) as xmlAttributePtr;
}
#[no_mangle]
pub extern "C" fn xmlGetDtdNotationDesc(
    mut dtd: *mut crate::src::threads::_xmlDtd,
    mut name: *const u8,
) -> *mut crate::src::valid::_xmlNotation {
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlNotationTable;
    if dtd.is_null() {
        return 0 as *mut crate::src::valid::_xmlNotation;
    }
    if (unsafe { (*dtd).notations }).is_null() {
        return 0 as *mut crate::src::valid::_xmlNotation;
    }
    table = (unsafe { (*dtd).notations }) as xmlNotationTablePtr;
    return (unsafe { xmlHashLookup(table, name) }) as xmlNotationPtr;
}
#[no_mangle]
pub extern "C" fn xmlValidateNotationUse(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut notationName: *const u8,
) -> i32 {
    let mut notaDecl: *mut crate::src::valid::_xmlNotation =
        0 as *mut crate::src::valid::_xmlNotation;
    if doc.is_null() || (unsafe { (*doc).intSubset }).is_null() || notationName.is_null() {
        return -(1 as i32);
    }
    notaDecl = xmlGetDtdNotationDesc(unsafe { (*doc).intSubset }, notationName);
    if notaDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
        notaDecl = xmlGetDtdNotationDesc(unsafe { (*doc).extSubset }, notationName);
    }
    if notaDecl.is_null() && !ctxt.is_null() {
        xmlErrValidNode(
            ctxt,
            doc as xmlNodePtr,
            XML_DTD_UNKNOWN_NOTATION,
            b"NOTATION %s is not declared\n\0" as *const u8 as *const i8,
            notationName,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as i32;
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlIsMixedElement<'a1>(
    mut doc: Option<&'a1 mut crate::src::threads::_xmlDoc>,
    mut name: *const u8,
) -> i32 {
    let mut elemDecl: *mut crate::src::tree::_xmlElement = 0 as *mut xmlElement;
    if borrow(&doc).is_none() || ((*(borrow_mut(&mut doc)).unwrap()).intSubset).is_null() {
        return -(1 as i32);
    }
    elemDecl = xmlGetDtdElementDesc((*(borrow_mut(&mut doc)).unwrap()).intSubset, name);
    if elemDecl.is_null() && !((*(borrow_mut(&mut doc)).unwrap()).extSubset).is_null() {
        elemDecl = xmlGetDtdElementDesc((*(borrow_mut(&mut doc)).unwrap()).extSubset, name);
    }
    if elemDecl.is_null() {
        return -(1 as i32);
    }
    match (unsafe { (*elemDecl).etype }) as u32 {
        0 => return -(1 as i32),
        4 => return 0 as i32,
        1 | 2 | 3 => return 1 as i32,
        _ => {}
    }
    return 1 as i32;
}
extern "C" fn xmlIsDocNameStartChar(mut doc: *mut crate::src::threads::_xmlDoc, mut c: i32) -> i32 {
    if doc.is_null() || (unsafe { (*doc).properties }) & XML_DOC_OLD10 as i32 == 0 as i32 {
        if c >= 'a' as i32 && c <= 'z' as i32
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
            || c >= 0x10000 as i32 && c <= 0xeffff as i32
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
extern "C" fn xmlIsDocNameChar(mut doc: *mut crate::src::threads::_xmlDoc, mut c: i32) -> i32 {
    if doc.is_null() || (unsafe { (*doc).properties }) & XML_DOC_OLD10 as i32 == 0 as i32 {
        if c >= 'a' as i32 && c <= 'z' as i32
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
            || c >= 0x10000 as i32 && c <= 0xeffff as i32
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
extern "C" fn xmlValidateNameValueInternal(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut value: *const u8,
) -> i32 {
    let mut cur: *const u8 = 0 as *const xmlChar;
    let mut val: i32 = 0;
    let mut len: i32 = 0;
    if value.is_null() {
        return 0 as i32;
    }
    cur = value;
    val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
    cur = unsafe { cur.offset(len as isize) };
    if xmlIsDocNameStartChar(doc, val) == 0 {
        return 0 as i32;
    }
    val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
    cur = unsafe { cur.offset(len as isize) };
    while xmlIsDocNameChar(doc, val) != 0 {
        val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
        cur = unsafe { cur.offset(len as isize) };
    }
    if val != 0 as i32 {
        return 0 as i32;
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlValidateNameValue(mut value: *const u8) -> i32 {
    return xmlValidateNameValueInternal(0 as xmlDocPtr, value);
}
extern "C" fn xmlValidateNamesValueInternal(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut value: *const u8,
) -> i32 {
    let mut cur: *const u8 = 0 as *const xmlChar;
    let mut val: i32 = 0;
    let mut len: i32 = 0;
    if value.is_null() {
        return 0 as i32;
    }
    cur = value;
    val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
    cur = unsafe { cur.offset(len as isize) };
    if xmlIsDocNameStartChar(doc, val) == 0 {
        return 0 as i32;
    }
    val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
    cur = unsafe { cur.offset(len as isize) };
    while xmlIsDocNameChar(doc, val) != 0 {
        val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
        cur = unsafe { cur.offset(len as isize) };
    }
    while val == 0x20 as i32 {
        while val == 0x20 as i32 {
            val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
            cur = unsafe { cur.offset(len as isize) };
        }
        if xmlIsDocNameStartChar(doc, val) == 0 {
            return 0 as i32;
        }
        val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
        cur = unsafe { cur.offset(len as isize) };
        while xmlIsDocNameChar(doc, val) != 0 {
            val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
            cur = unsafe { cur.offset(len as isize) };
        }
    }
    if val != 0 as i32 {
        return 0 as i32;
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlValidateNamesValue(mut value: *const u8) -> i32 {
    return xmlValidateNamesValueInternal(0 as xmlDocPtr, value);
}
extern "C" fn xmlValidateNmtokenValueInternal(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut value: *const u8,
) -> i32 {
    let mut cur: *const u8 = 0 as *const xmlChar;
    let mut val: i32 = 0;
    let mut len: i32 = 0;
    if value.is_null() {
        return 0 as i32;
    }
    cur = value;
    val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
    cur = unsafe { cur.offset(len as isize) };
    if xmlIsDocNameChar(doc, val) == 0 {
        return 0 as i32;
    }
    val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
    cur = unsafe { cur.offset(len as isize) };
    while xmlIsDocNameChar(doc, val) != 0 {
        val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
        cur = unsafe { cur.offset(len as isize) };
    }
    if val != 0 as i32 {
        return 0 as i32;
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlValidateNmtokenValue(mut value: *const u8) -> i32 {
    return xmlValidateNmtokenValueInternal(0 as xmlDocPtr, value);
}
extern "C" fn xmlValidateNmtokensValueInternal(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut value: *const u8,
) -> i32 {
    let mut cur: *const u8 = 0 as *const xmlChar;
    let mut val: i32 = 0;
    let mut len: i32 = 0;
    if value.is_null() {
        return 0 as i32;
    }
    cur = value;
    val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
    cur = unsafe { cur.offset(len as isize) };
    while if val < 0x100 as i32 {
        (val == 0x20 as i32 || 0x9 as i32 <= val && val <= 0xa as i32 || val == 0xd as i32) as i32
    } else {
        0 as i32
    } != 0
    {
        val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
        cur = unsafe { cur.offset(len as isize) };
    }
    if xmlIsDocNameChar(doc, val) == 0 {
        return 0 as i32;
    }
    while xmlIsDocNameChar(doc, val) != 0 {
        val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
        cur = unsafe { cur.offset(len as isize) };
    }
    while val == 0x20 as i32 {
        while val == 0x20 as i32 {
            val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
            cur = unsafe { cur.offset(len as isize) };
        }
        if val == 0 as i32 {
            return 1 as i32;
        }
        if xmlIsDocNameChar(doc, val) == 0 {
            return 0 as i32;
        }
        val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
        cur = unsafe { cur.offset(len as isize) };
        while xmlIsDocNameChar(doc, val) != 0 {
            val = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len) };
            cur = unsafe { cur.offset(len as isize) };
        }
    }
    if val != 0 as i32 {
        return 0 as i32;
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlValidateNmtokensValue(mut value: *const u8) -> i32 {
    return xmlValidateNmtokensValueInternal(0 as xmlDocPtr, value);
}
#[no_mangle]
pub extern "C" fn xmlValidateNotationDecl<'a1, 'a2, 'a3>(
    mut _ctxt: Option<&'a1 mut crate::src::tree::_xmlValidCtxt>,
    mut _doc: Option<&'a2 mut crate::src::threads::_xmlDoc>,
    mut _nota: Option<&'a3 mut crate::src::valid::_xmlNotation>,
) -> i32 {
    let mut ret: i32 = 1 as i32;
    return ret;
}
extern "C" fn xmlValidateAttributeValueInternal(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut type_0: u32,
    mut value: *const u8,
) -> i32 {
    match type_0 as u32 {
        6 | 4 => return xmlValidateNamesValueInternal(doc, value),
        5 | 3 | 2 | 10 => return xmlValidateNameValueInternal(doc, value),
        8 | 9 => return xmlValidateNmtokensValueInternal(doc, value),
        7 => return xmlValidateNmtokenValueInternal(doc, value),
        1 | _ => {}
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlValidateAttributeValue(mut type_0: u32, mut value: *const u8) -> i32 {
    return xmlValidateAttributeValueInternal(0 as xmlDocPtr, type_0, value);
}
extern "C" fn xmlValidateAttributeValue2(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut name: *const u8,
    mut type_0: u32,
    mut value: *const u8,
) -> i32 {
    let mut ret: i32 = 1 as i32;
    match type_0 as u32 {
        5 => {
            let mut ent: *mut crate::src::threads::_xmlEntity =
                0 as *mut crate::src::threads::_xmlEntity;
            ent = unsafe { xmlGetDocEntity(doc as *const xmlDoc, value) };
            if ent.is_null() && (unsafe { (*doc).standalone }) == 1 as i32 {
                (unsafe { (*doc).standalone = 0 as i32 });
                ent = unsafe { xmlGetDocEntity(doc as *const xmlDoc, value) };
            }
            if ent.is_null() {
                xmlErrValidNode(
                    ctxt,
                    doc as xmlNodePtr,
                    XML_DTD_UNKNOWN_ENTITY,
                    b"ENTITY attribute %s reference an unknown entity \"%s\"\n\0" as *const u8
                        as *const i8,
                    name,
                    value,
                    0 as *const xmlChar,
                );
                ret = 0 as i32;
            } else if (unsafe { (*ent).etype }) as u32
                != XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as i32 as u32
            {
                xmlErrValidNode(
                    ctxt,
                    doc as xmlNodePtr,
                    XML_DTD_ENTITY_TYPE,
                    b"ENTITY attribute %s reference an entity \"%s\" of wrong type\n\0" as *const u8
                        as *const i8,
                    name,
                    value,
                    0 as *const xmlChar,
                );
                ret = 0 as i32;
            }
        }
        6 => {
            let mut dup: *mut u8 = 0 as *mut xmlChar;
            let mut nam: *mut u8 = 0 as *mut xmlChar;
            let mut cur: *mut u8 = 0 as *mut xmlChar;
            let mut save: u8 = 0;
            let mut ent_0: *mut crate::src::threads::_xmlEntity =
                0 as *mut crate::src::threads::_xmlEntity;
            dup = xmlStrdup(value);
            if dup.is_null() {
                return 0 as i32;
            }
            cur = dup;
            while (unsafe { *cur }) as i32 != 0 as i32 {
                nam = cur;
                while (unsafe { *cur }) as i32 != 0 as i32
                    && !((unsafe { *cur }) as i32 == 0x20 as i32
                        || 0x9 as i32 <= (unsafe { *cur }) as i32
                            && (unsafe { *cur }) as i32 <= 0xa as i32
                        || (unsafe { *cur }) as i32 == 0xd as i32)
                {
                    cur = unsafe { cur.offset(1) };
                }
                save = unsafe { *cur };
                (unsafe { *cur = 0 as i32 as xmlChar });
                ent_0 = unsafe { xmlGetDocEntity(doc as *const xmlDoc, nam) };
                if ent_0.is_null() {
                    xmlErrValidNode(
                        ctxt,
                        doc as xmlNodePtr,
                        XML_DTD_UNKNOWN_ENTITY,
                        b"ENTITIES attribute %s reference an unknown entity \"%s\"\n\0" as *const u8
                            as *const i8,
                        name,
                        nam,
                        0 as *const xmlChar,
                    );
                    ret = 0 as i32;
                } else if (unsafe { (*ent_0).etype }) as u32
                    != XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as i32 as u32
                {
                    xmlErrValidNode(
                        ctxt,
                        doc as xmlNodePtr,
                        XML_DTD_ENTITY_TYPE,
                        b"ENTITIES attribute %s reference an entity \"%s\" of wrong type\n\0"
                            as *const u8 as *const i8,
                        name,
                        nam,
                        0 as *const xmlChar,
                    );
                    ret = 0 as i32;
                }
                if save as i32 == 0 as i32 {
                    break;
                }
                (unsafe { *cur = save });
                while (unsafe { *cur }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *cur }) as i32
                        && (unsafe { *cur }) as i32 <= 0xa as i32
                    || (unsafe { *cur }) as i32 == 0xd as i32
                {
                    cur = unsafe { cur.offset(1) };
                }
            }
            (unsafe { xmlFree.expect("non-null function pointer")(dup as *mut libc::c_void) });
        }
        10 => {
            let mut nota: *mut crate::src::valid::_xmlNotation =
                0 as *mut crate::src::valid::_xmlNotation;
            nota = xmlGetDtdNotationDesc(unsafe { (*doc).intSubset }, value);
            if nota.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                nota = xmlGetDtdNotationDesc(unsafe { (*doc).extSubset }, value);
            }
            if nota.is_null() {
                xmlErrValidNode(
                    ctxt,
                    doc as xmlNodePtr,
                    XML_DTD_UNKNOWN_NOTATION,
                    b"NOTATION attribute %s reference an unknown notation \"%s\"\n\0" as *const u8
                        as *const i8,
                    name,
                    value,
                    0 as *const xmlChar,
                );
                ret = 0 as i32;
            }
        }
        4 | 3 | 2 | 8 | 9 | 7 | 1 | _ => {}
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlValidCtxtNormalizeAttributeValue<'a1>(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: Option<&'a1 mut crate::src::threads::_xmlDoc>,
    mut elem: *mut crate::src::threads::_xmlNode,
    mut name: *const u8,
    mut value: *const u8,
) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    let mut attrDecl: *mut crate::src::tree::_xmlAttribute = 0 as xmlAttributePtr;
    let mut extsubset: i32 = 0 as i32;
    if borrow(&doc).is_none() {
        return 0 as *mut xmlChar;
    }
    if elem.is_null() {
        return 0 as *mut xmlChar;
    }
    if name.is_null() {
        return 0 as *mut xmlChar;
    }
    if value.is_null() {
        return 0 as *mut xmlChar;
    }
    if !(unsafe { (*elem).ns }).is_null() && !(unsafe { (*(*elem).ns).prefix }).is_null() {
        let mut fn_0: [u8; 50] = [0; 50];
        let mut fullname: *mut u8 = 0 as *mut xmlChar;
        fullname = xmlBuildQName(
            unsafe { (*elem).name },
            unsafe { (*(*elem).ns).prefix },
            fn_0.as_mut_ptr(),
            50 as i32,
        );
        if fullname.is_null() {
            return 0 as *mut xmlChar;
        }
        attrDecl = xmlGetDtdAttrDesc((*(borrow_mut(&mut doc)).unwrap()).intSubset, fullname, name);
        if attrDecl.is_null() && !((*(borrow_mut(&mut doc)).unwrap()).extSubset).is_null() {
            attrDecl =
                xmlGetDtdAttrDesc((*(borrow_mut(&mut doc)).unwrap()).extSubset, fullname, name);
            if !attrDecl.is_null() {
                extsubset = 1 as i32;
            }
        }
        if fullname != fn_0.as_mut_ptr() && fullname != (unsafe { (*elem).name }) as *mut xmlChar {
            (unsafe { xmlFree.expect("non-null function pointer")(fullname as *mut libc::c_void) });
        }
    }
    if attrDecl.is_null() && !((*(borrow_mut(&mut doc)).unwrap()).intSubset).is_null() {
        attrDecl = xmlGetDtdAttrDesc(
            (*(borrow_mut(&mut doc)).unwrap()).intSubset,
            unsafe { (*elem).name },
            name,
        );
    }
    if attrDecl.is_null() && !((*(borrow_mut(&mut doc)).unwrap()).extSubset).is_null() {
        attrDecl = xmlGetDtdAttrDesc(
            (*(borrow_mut(&mut doc)).unwrap()).extSubset,
            unsafe { (*elem).name },
            name,
        );
        if !attrDecl.is_null() {
            extsubset = 1 as i32;
        }
    }
    if attrDecl.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { (*attrDecl).atype }) as u32 == XML_ATTRIBUTE_CDATA as i32 as u32 {
        return 0 as *mut xmlChar;
    }
    ret = xmlStrdup(value);
    if ret.is_null() {
        return 0 as *mut xmlChar;
    }
    xmlValidNormalizeString(ret);
    if (*(borrow(&doc)).unwrap()).standalone != 0
        && extsubset == 1 as i32
        && xmlStrEqual(value, ret) == 0
    {
        xmlErrValidNode (ctxt , elem , XML_DTD_NOT_STANDALONE , b"standalone: %s on %s value had to be normalized based on external subset declaration\n\0" as * const u8 as * const i8 , name , unsafe { (* elem) . name } , 0 as * const xmlChar ,) ;
        (unsafe { (*ctxt).valid = 0 as i32 });
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlValidNormalizeAttributeValue<'a1, 'a2>(
    mut doc: Option<&'a1 mut crate::src::threads::_xmlDoc>,
    mut elem: Option<&'a2 mut crate::src::threads::_xmlNode>,
    mut name: *const u8,
    mut value: *const u8,
) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    let mut attrDecl: *mut crate::src::tree::_xmlAttribute = 0 as xmlAttributePtr;
    if borrow(&doc).is_none() {
        return 0 as *mut xmlChar;
    }
    if borrow(&elem).is_none() {
        return 0 as *mut xmlChar;
    }
    if name.is_null() {
        return 0 as *mut xmlChar;
    }
    if value.is_null() {
        return 0 as *mut xmlChar;
    }
    if !((*(borrow(&elem)).unwrap()).ns).is_null()
        && !(unsafe { (*(*(borrow(&elem)).unwrap()).ns).prefix }).is_null()
    {
        let mut fn_0: [u8; 50] = [0; 50];
        let mut fullname: *mut u8 = 0 as *mut xmlChar;
        fullname = xmlBuildQName(
            (*(borrow(&elem)).unwrap()).name,
            unsafe { (*(*(borrow(&elem)).unwrap()).ns).prefix },
            fn_0.as_mut_ptr(),
            50 as i32,
        );
        if fullname.is_null() {
            return 0 as *mut xmlChar;
        }
        if fullname != fn_0.as_mut_ptr()
            && fullname != (*(borrow_mut(&mut elem)).unwrap()).name as *mut xmlChar
        {
            (unsafe { xmlFree.expect("non-null function pointer")(fullname as *mut libc::c_void) });
        }
    }
    attrDecl = xmlGetDtdAttrDesc(
        (*(borrow_mut(&mut doc)).unwrap()).intSubset,
        (*(borrow(&elem)).unwrap()).name,
        name,
    );
    if attrDecl.is_null() && !((*(borrow_mut(&mut doc)).unwrap()).extSubset).is_null() {
        attrDecl = xmlGetDtdAttrDesc(
            (*(borrow_mut(&mut doc)).unwrap()).extSubset,
            (*(borrow(&elem)).unwrap()).name,
            name,
        );
    }
    if attrDecl.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { (*attrDecl).atype }) as u32 == XML_ATTRIBUTE_CDATA as i32 as u32 {
        return 0 as *mut xmlChar;
    }
    ret = xmlStrdup(value);
    if ret.is_null() {
        return 0 as *mut xmlChar;
    }
    xmlValidNormalizeString(ret);
    return ret;
}
extern "C" fn xmlValidateAttributeIdCallback(
    mut payload: *mut core::ffi::c_void,
    mut data: *mut core::ffi::c_void,
    mut _name: *const u8,
) {
    let mut attr: *mut crate::src::tree::_xmlAttribute = payload as xmlAttributePtr;
    let mut count: *mut i32 = data as *mut i32;
    if (unsafe { (*attr).atype }) as u32 == XML_ATTRIBUTE_ID as i32 as u32 {
        (unsafe { *count += 1 });
    }
}
#[no_mangle]
pub extern "C" fn xmlValidateAttributeDecl(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut attr: *mut crate::src::tree::_xmlAttribute,
) -> i32 {
    let mut ret: i32 = 1 as i32;
    let mut val: i32 = 0;
    if doc.is_null() {
        return 0 as i32;
    } else {
        if (unsafe { (*doc).intSubset }).is_null() && (unsafe { (*doc).extSubset }).is_null() {
            return 0 as i32;
        }
    }
    if attr.is_null() {
        return 1 as i32;
    }
    if !(unsafe { (*attr).defaultValue }).is_null() {
        val = xmlValidateAttributeValueInternal(
            doc,
            unsafe { (*attr).atype },
            unsafe { (*attr).defaultValue },
        );
        if val == 0 as i32 {
            xmlErrValidNode(
                ctxt,
                attr as xmlNodePtr,
                XML_DTD_ATTRIBUTE_DEFAULT,
                b"Syntax of default value for attribute %s of %s is not valid\n\0" as *const u8
                    as *const i8,
                unsafe { (*attr).name },
                unsafe { (*attr).elem },
                0 as *const xmlChar,
            );
        }
        ret &= val;
    }
    if (unsafe { (*attr).atype }) as u32 == XML_ATTRIBUTE_ID as i32 as u32
        && (unsafe { (*attr).def }) as u32 != XML_ATTRIBUTE_IMPLIED as i32 as u32
        && (unsafe { (*attr).def }) as u32 != XML_ATTRIBUTE_REQUIRED as i32 as u32
    {
        xmlErrValidNode(
            ctxt,
            attr as xmlNodePtr,
            XML_DTD_ID_FIXED,
            b"ID attribute %s of %s is not valid must be #IMPLIED or #REQUIRED\n\0" as *const u8
                as *const i8,
            unsafe { (*attr).name },
            unsafe { (*attr).elem },
            0 as *const xmlChar,
        );
        ret = 0 as i32;
    }
    if (unsafe { (*attr).atype }) as u32 == XML_ATTRIBUTE_ID as i32 as u32 {
        let mut nbId: i32 = 0;
        let mut elem: *mut crate::src::tree::_xmlElement =
            xmlGetDtdElementDesc(unsafe { (*doc).intSubset }, unsafe { (*attr).elem });
        if !elem.is_null() {
            nbId = xmlScanIDAttributeDecl(0 as xmlValidCtxtPtr, elem, 0 as i32);
        } else {
            let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlAttributeTable;
            nbId = 0 as i32;
            if !(unsafe { (*doc).intSubset }).is_null() {
                table = (unsafe { (*(*doc).intSubset).attributes }) as xmlAttributeTablePtr;
                (unsafe {
                    xmlHashScan3(
                        table,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                        (*attr).elem,
                        Some(xmlValidateAttributeIdCallback),
                        &mut nbId as *mut i32 as *mut libc::c_void,
                    )
                });
            }
        }
        if nbId > 1 as i32 {
            xmlErrValidNodeNr(
                ctxt,
                attr as xmlNodePtr,
                XML_DTD_ID_SUBSET,
                b"Element %s has %d ID attribute defined in the internal subset : %s\n\0"
                    as *const u8 as *const i8,
                unsafe { (*attr).elem },
                nbId,
                unsafe { (*attr).name },
            );
        } else if !(unsafe { (*doc).extSubset }).is_null() {
            let mut extId: i32 = 0 as i32;
            elem = xmlGetDtdElementDesc(unsafe { (*doc).extSubset }, unsafe { (*attr).elem });
            if !elem.is_null() {
                extId = xmlScanIDAttributeDecl(0 as xmlValidCtxtPtr, elem, 0 as i32);
            }
            if extId > 1 as i32 {
                xmlErrValidNodeNr(
                    ctxt,
                    attr as xmlNodePtr,
                    XML_DTD_ID_SUBSET,
                    b"Element %s has %d ID attribute defined in the external subset : %s\n\0"
                        as *const u8 as *const i8,
                    unsafe { (*attr).elem },
                    extId,
                    unsafe { (*attr).name },
                );
            } else if extId + nbId > 1 as i32 {
                xmlErrValidNode (ctxt , attr as xmlNodePtr , XML_DTD_ID_SUBSET , b"Element %s has ID attributes defined in the internal and external subset : %s\n\0" as * const u8 as * const i8 , unsafe { (* attr) . elem } , unsafe { (* attr) . name } , 0 as * const xmlChar ,) ;
            }
        }
    }
    if !(unsafe { (*attr).defaultValue }).is_null() && !(unsafe { (*attr).tree }).is_null() {
        let mut tree: *mut crate::src::threads::_xmlEnumeration = unsafe { (*attr).tree };
        while !tree.is_null() {
            if xmlStrEqual(unsafe { (*tree).name }, unsafe { (*attr).defaultValue }) != 0 {
                break;
            }
            tree = unsafe { (*tree).next };
        }
        if tree.is_null() {
            xmlErrValidNode(
                ctxt,
                attr as xmlNodePtr,
                XML_DTD_ATTRIBUTE_VALUE,
                b"Default value \"%s\" for attribute %s of %s is not among the enumerated set\n\0"
                    as *const u8 as *const i8,
                unsafe { (*attr).defaultValue },
                unsafe { (*attr).name },
                unsafe { (*attr).elem },
            );
            ret = 0 as i32;
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlValidateElementDecl<'a1>(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: Option<&'a1 mut crate::src::threads::_xmlDoc>,
    mut elem: *mut crate::src::tree::_xmlElement,
) -> i32 {
    let mut ret: i32 = 1 as i32;
    let mut tst: *mut crate::src::tree::_xmlElement = 0 as *mut xmlElement;
    if borrow(&doc).is_none() {
        return 0 as i32;
    } else {
        if ((*(borrow_mut(&mut doc)).unwrap()).intSubset).is_null()
            && ((*(borrow_mut(&mut doc)).unwrap()).extSubset).is_null()
        {
            return 0 as i32;
        }
    }
    if elem.is_null() {
        return 1 as i32;
    }
    if (unsafe { (*elem).etype }) as u32 == XML_ELEMENT_TYPE_MIXED as i32 as u32 {
        let mut cur: *mut crate::src::threads::_xmlElementContent = 0 as *mut xmlElementContent;
        let mut next: *mut crate::src::threads::_xmlElementContent = 0 as *mut xmlElementContent;
        let mut name: *const u8 = 0 as *const xmlChar;
        cur = unsafe { (*elem).content };
        while !cur.is_null() {
            if (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_CONTENT_OR as i32 as u32 {
                break;
            }
            if (unsafe { (*cur).c1 }).is_null() {
                break;
            }
            if (unsafe { (*(*cur).c1).type_0 }) as u32 == XML_ELEMENT_CONTENT_ELEMENT as i32 as u32
            {
                name = unsafe { (*(*cur).c1).name };
                next = unsafe { (*cur).c2 };
                while !next.is_null() {
                    if (unsafe { (*next).type_0 }) as u32
                        == XML_ELEMENT_CONTENT_ELEMENT as i32 as u32
                    {
                        if xmlStrEqual(unsafe { (*next).name }, name) != 0
                            && xmlStrEqual(
                                unsafe { (*next).prefix },
                                unsafe { (*(*cur).c1).prefix },
                            ) != 0
                        {
                            if (unsafe { (*(*cur).c1).prefix }).is_null() {
                                xmlErrValidNode(
                                    ctxt,
                                    elem as xmlNodePtr,
                                    XML_DTD_CONTENT_ERROR,
                                    b"Definition of %s has duplicate references of %s\n\0"
                                        as *const u8
                                        as *const i8,
                                    unsafe { (*elem).name },
                                    name,
                                    0 as *const xmlChar,
                                );
                            } else {
                                xmlErrValidNode(
                                    ctxt,
                                    elem as xmlNodePtr,
                                    XML_DTD_CONTENT_ERROR,
                                    b"Definition of %s has duplicate references of %s:%s\n\0"
                                        as *const u8
                                        as *const i8,
                                    unsafe { (*elem).name },
                                    unsafe { (*(*cur).c1).prefix },
                                    name,
                                );
                            }
                            ret = 0 as i32;
                        }
                        break;
                    } else {
                        if (unsafe { (*next).c1 }).is_null() {
                            break;
                        }
                        if (unsafe { (*(*next).c1).type_0 }) as u32
                            != XML_ELEMENT_CONTENT_ELEMENT as i32 as u32
                        {
                            break;
                        }
                        if xmlStrEqual(unsafe { (*(*next).c1).name }, name) != 0
                            && xmlStrEqual(
                                unsafe { (*(*next).c1).prefix },
                                unsafe { (*(*cur).c1).prefix },
                            ) != 0
                        {
                            if (unsafe { (*(*cur).c1).prefix }).is_null() {
                                xmlErrValidNode(
                                    ctxt,
                                    elem as xmlNodePtr,
                                    XML_DTD_CONTENT_ERROR,
                                    b"Definition of %s has duplicate references to %s\n\0"
                                        as *const u8
                                        as *const i8,
                                    unsafe { (*elem).name },
                                    name,
                                    0 as *const xmlChar,
                                );
                            } else {
                                xmlErrValidNode(
                                    ctxt,
                                    elem as xmlNodePtr,
                                    XML_DTD_CONTENT_ERROR,
                                    b"Definition of %s has duplicate references to %s:%s\n\0"
                                        as *const u8
                                        as *const i8,
                                    unsafe { (*elem).name },
                                    unsafe { (*(*cur).c1).prefix },
                                    name,
                                );
                            }
                            ret = 0 as i32;
                        }
                        next = unsafe { (*next).c2 };
                    }
                }
            }
            cur = unsafe { (*cur).c2 };
        }
    }
    tst = xmlGetDtdElementDesc(
        (*(borrow_mut(&mut doc)).unwrap()).intSubset,
        unsafe { (*elem).name },
    );
    if !tst.is_null()
        && tst != elem
        && ((unsafe { (*tst).prefix }) == (unsafe { (*elem).prefix })
            || xmlStrEqual(unsafe { (*tst).prefix }, unsafe { (*elem).prefix }) != 0)
        && (unsafe { (*tst).etype }) as u32 != XML_ELEMENT_TYPE_UNDEFINED as i32 as u32
    {
        xmlErrValidNode(
            ctxt,
            elem as xmlNodePtr,
            XML_DTD_ELEM_REDEFINED,
            b"Redefinition of element %s\n\0" as *const u8 as *const i8,
            unsafe { (*elem).name },
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        ret = 0 as i32;
    }
    tst = xmlGetDtdElementDesc(
        (*(borrow_mut(&mut doc)).unwrap()).extSubset,
        unsafe { (*elem).name },
    );
    if !tst.is_null()
        && tst != elem
        && ((unsafe { (*tst).prefix }) == (unsafe { (*elem).prefix })
            || xmlStrEqual(unsafe { (*tst).prefix }, unsafe { (*elem).prefix }) != 0)
        && (unsafe { (*tst).etype }) as u32 != XML_ELEMENT_TYPE_UNDEFINED as i32 as u32
    {
        xmlErrValidNode(
            ctxt,
            elem as xmlNodePtr,
            XML_DTD_ELEM_REDEFINED,
            b"Redefinition of element %s\n\0" as *const u8 as *const i8,
            unsafe { (*elem).name },
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        ret = 0 as i32;
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlValidateOneAttribute(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut elem: *mut crate::src::threads::_xmlNode,
    mut attr: *mut crate::src::threads::_xmlAttr,
    mut value: *const u8,
) -> i32 {
    let mut attrDecl: *mut crate::src::tree::_xmlAttribute = 0 as xmlAttributePtr;
    let mut val: i32 = 0;
    let mut ret: i32 = 1 as i32;
    if doc.is_null() {
        return 0 as i32;
    } else {
        if (unsafe { (*doc).intSubset }).is_null() && (unsafe { (*doc).extSubset }).is_null() {
            return 0 as i32;
        }
    }
    if elem.is_null() || (unsafe { (*elem).name }).is_null() {
        return 0 as i32;
    }
    if attr.is_null() || (unsafe { (*attr).name }).is_null() {
        return 0 as i32;
    }
    if !(unsafe { (*elem).ns }).is_null() && !(unsafe { (*(*elem).ns).prefix }).is_null() {
        let mut fn_0: [u8; 50] = [0; 50];
        let mut fullname: *mut u8 = 0 as *mut xmlChar;
        fullname = xmlBuildQName(
            unsafe { (*elem).name },
            unsafe { (*(*elem).ns).prefix },
            fn_0.as_mut_ptr(),
            50 as i32,
        );
        if fullname.is_null() {
            return 0 as i32;
        }
        if !(unsafe { (*attr).ns }).is_null() {
            attrDecl = xmlGetDtdQAttrDesc(
                unsafe { (*doc).intSubset },
                fullname,
                unsafe { (*attr).name },
                unsafe { (*(*attr).ns).prefix },
            );
            if attrDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                attrDecl = xmlGetDtdQAttrDesc(
                    unsafe { (*doc).extSubset },
                    fullname,
                    unsafe { (*attr).name },
                    unsafe { (*(*attr).ns).prefix },
                );
            }
        } else {
            attrDecl = xmlGetDtdAttrDesc(
                unsafe { (*doc).intSubset },
                fullname,
                unsafe { (*attr).name },
            );
            if attrDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                attrDecl = xmlGetDtdAttrDesc(
                    unsafe { (*doc).extSubset },
                    fullname,
                    unsafe { (*attr).name },
                );
            }
        }
        if fullname != fn_0.as_mut_ptr() && fullname != (unsafe { (*elem).name }) as *mut xmlChar {
            (unsafe { xmlFree.expect("non-null function pointer")(fullname as *mut libc::c_void) });
        }
    }
    if attrDecl.is_null() {
        if !(unsafe { (*attr).ns }).is_null() {
            attrDecl = xmlGetDtdQAttrDesc(
                unsafe { (*doc).intSubset },
                unsafe { (*elem).name },
                unsafe { (*attr).name },
                unsafe { (*(*attr).ns).prefix },
            );
            if attrDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                attrDecl = xmlGetDtdQAttrDesc(
                    unsafe { (*doc).extSubset },
                    unsafe { (*elem).name },
                    unsafe { (*attr).name },
                    unsafe { (*(*attr).ns).prefix },
                );
            }
        } else {
            attrDecl = xmlGetDtdAttrDesc(
                unsafe { (*doc).intSubset },
                unsafe { (*elem).name },
                unsafe { (*attr).name },
            );
            if attrDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                attrDecl = xmlGetDtdAttrDesc(
                    unsafe { (*doc).extSubset },
                    unsafe { (*elem).name },
                    unsafe { (*attr).name },
                );
            }
        }
    }
    if attrDecl.is_null() {
        xmlErrValidNode(
            ctxt,
            elem,
            XML_DTD_UNKNOWN_ATTRIBUTE,
            b"No declaration for attribute %s of element %s\n\0" as *const u8 as *const i8,
            unsafe { (*attr).name },
            unsafe { (*elem).name },
            0 as *const xmlChar,
        );
        return 0 as i32;
    }
    (unsafe { (*attr).atype = (*attrDecl).atype });
    val = xmlValidateAttributeValueInternal(doc, unsafe { (*attrDecl).atype }, value);
    if val == 0 as i32 {
        xmlErrValidNode(
            ctxt,
            elem,
            XML_DTD_ATTRIBUTE_VALUE,
            b"Syntax of value for attribute %s of %s is not valid\n\0" as *const u8 as *const i8,
            unsafe { (*attr).name },
            unsafe { (*elem).name },
            0 as *const xmlChar,
        );
        ret = 0 as i32;
    }
    if (unsafe { (*attrDecl).def }) as u32 == XML_ATTRIBUTE_FIXED as i32 as u32 {
        if xmlStrEqual(value, unsafe { (*attrDecl).defaultValue }) == 0 {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_ATTRIBUTE_DEFAULT,
                b"Value for attribute %s of %s is different from default \"%s\"\n\0" as *const u8
                    as *const i8,
                unsafe { (*attr).name },
                unsafe { (*elem).name },
                unsafe { (*attrDecl).defaultValue },
            );
            ret = 0 as i32;
        }
    }
    if (unsafe { (*attrDecl).atype }) as u32 == XML_ATTRIBUTE_ID as i32 as u32 {
        if (xmlAddID(ctxt, doc, value, attr)).is_null() {
            ret = 0 as i32;
        }
    }
    if (unsafe { (*attrDecl).atype }) as u32 == XML_ATTRIBUTE_IDREF as i32 as u32
        || (unsafe { (*attrDecl).atype }) as u32 == XML_ATTRIBUTE_IDREFS as i32 as u32
    {
        if (xmlAddRef(ctxt, doc, value, attr)).is_null() {
            ret = 0 as i32;
        }
    }
    if (unsafe { (*attrDecl).atype }) as u32 == XML_ATTRIBUTE_NOTATION as i32 as u32 {
        let mut tree: *mut crate::src::threads::_xmlEnumeration = unsafe { (*attrDecl).tree };
        let mut nota: *mut crate::src::valid::_xmlNotation =
            0 as *mut crate::src::valid::_xmlNotation;
        nota = xmlGetDtdNotationDesc(unsafe { (*doc).intSubset }, value);
        if nota.is_null() {
            nota = xmlGetDtdNotationDesc(unsafe { (*doc).extSubset }, value);
        }
        if nota.is_null() {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_UNKNOWN_NOTATION,
                b"Value \"%s\" for attribute %s of %s is not a declared Notation\n\0" as *const u8
                    as *const i8,
                value,
                unsafe { (*attr).name },
                unsafe { (*elem).name },
            );
            ret = 0 as i32;
        }
        while !tree.is_null() {
            if xmlStrEqual(unsafe { (*tree).name }, value) != 0 {
                break;
            }
            tree = unsafe { (*tree).next };
        }
        if tree.is_null() {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_NOTATION_VALUE,
                b"Value \"%s\" for attribute %s of %s is not among the enumerated notations\n\0"
                    as *const u8 as *const i8,
                value,
                unsafe { (*attr).name },
                unsafe { (*elem).name },
            );
            ret = 0 as i32;
        }
    }
    if (unsafe { (*attrDecl).atype }) as u32 == XML_ATTRIBUTE_ENUMERATION as i32 as u32 {
        let mut tree_0: *mut crate::src::threads::_xmlEnumeration = unsafe { (*attrDecl).tree };
        while !tree_0.is_null() {
            if xmlStrEqual(unsafe { (*tree_0).name }, value) != 0 {
                break;
            }
            tree_0 = unsafe { (*tree_0).next };
        }
        if tree_0.is_null() {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_ATTRIBUTE_VALUE,
                b"Value \"%s\" for attribute %s of %s is not among the enumerated set\n\0"
                    as *const u8 as *const i8,
                value,
                unsafe { (*attr).name },
                unsafe { (*elem).name },
            );
            ret = 0 as i32;
        }
    }
    if (unsafe { (*attrDecl).def }) as u32 == XML_ATTRIBUTE_FIXED as i32 as u32
        && xmlStrEqual(unsafe { (*attrDecl).defaultValue }, value) == 0
    {
        xmlErrValidNode(
            ctxt,
            elem,
            XML_DTD_ATTRIBUTE_VALUE,
            b"Value for attribute %s of %s must be \"%s\"\n\0" as *const u8 as *const i8,
            unsafe { (*attr).name },
            unsafe { (*elem).name },
            unsafe { (*attrDecl).defaultValue },
        );
        ret = 0 as i32;
    }
    ret &= xmlValidateAttributeValue2(
        ctxt,
        doc,
        unsafe { (*attr).name },
        unsafe { (*attrDecl).atype },
        value,
    );
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlValidateOneNamespace(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut elem: *mut crate::src::threads::_xmlNode,
    mut prefix: *const u8,
    mut ns: *mut crate::src::threads::_xmlNs,
    mut value: *const u8,
) -> i32 {
    let mut attrDecl: *mut crate::src::tree::_xmlAttribute = 0 as xmlAttributePtr;
    let mut val: i32 = 0;
    let mut ret: i32 = 1 as i32;
    if doc.is_null() {
        return 0 as i32;
    } else {
        if (unsafe { (*doc).intSubset }).is_null() && (unsafe { (*doc).extSubset }).is_null() {
            return 0 as i32;
        }
    }
    if elem.is_null() || (unsafe { (*elem).name }).is_null() {
        return 0 as i32;
    }
    if ns.is_null() || (unsafe { (*ns).href }).is_null() {
        return 0 as i32;
    }
    if !prefix.is_null() {
        let mut fn_0: [u8; 50] = [0; 50];
        let mut fullname: *mut u8 = 0 as *mut xmlChar;
        fullname = xmlBuildQName(
            unsafe { (*elem).name },
            prefix,
            fn_0.as_mut_ptr(),
            50 as i32,
        );
        if fullname.is_null() {
            xmlVErrMemory(ctxt, b"Validating namespace\0" as *const u8 as *const i8);
            return 0 as i32;
        }
        if !(unsafe { (*ns).prefix }).is_null() {
            attrDecl = xmlGetDtdQAttrDesc(
                unsafe { (*doc).intSubset },
                fullname,
                unsafe { (*ns).prefix },
                b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
            );
            if attrDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                attrDecl = xmlGetDtdQAttrDesc(
                    unsafe { (*doc).extSubset },
                    fullname,
                    unsafe { (*ns).prefix },
                    b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                );
            }
        } else {
            attrDecl = xmlGetDtdAttrDesc(
                unsafe { (*doc).intSubset },
                fullname,
                b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
            );
            if attrDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                attrDecl = xmlGetDtdAttrDesc(
                    unsafe { (*doc).extSubset },
                    fullname,
                    b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                );
            }
        }
        if fullname != fn_0.as_mut_ptr() && fullname != (unsafe { (*elem).name }) as *mut xmlChar {
            (unsafe { xmlFree.expect("non-null function pointer")(fullname as *mut libc::c_void) });
        }
    }
    if attrDecl.is_null() {
        if !(unsafe { (*ns).prefix }).is_null() {
            attrDecl = xmlGetDtdQAttrDesc(
                unsafe { (*doc).intSubset },
                unsafe { (*elem).name },
                unsafe { (*ns).prefix },
                b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
            );
            if attrDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                attrDecl = xmlGetDtdQAttrDesc(
                    unsafe { (*doc).extSubset },
                    unsafe { (*elem).name },
                    unsafe { (*ns).prefix },
                    b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                );
            }
        } else {
            attrDecl = xmlGetDtdAttrDesc(
                unsafe { (*doc).intSubset },
                unsafe { (*elem).name },
                b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
            );
            if attrDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                attrDecl = xmlGetDtdAttrDesc(
                    unsafe { (*doc).extSubset },
                    unsafe { (*elem).name },
                    b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                );
            }
        }
    }
    if attrDecl.is_null() {
        if !(unsafe { (*ns).prefix }).is_null() {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_UNKNOWN_ATTRIBUTE,
                b"No declaration for attribute xmlns:%s of element %s\n\0" as *const u8
                    as *const i8,
                unsafe { (*ns).prefix },
                unsafe { (*elem).name },
                0 as *const xmlChar,
            );
        } else {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_UNKNOWN_ATTRIBUTE,
                b"No declaration for attribute xmlns of element %s\n\0" as *const u8 as *const i8,
                unsafe { (*elem).name },
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        return 0 as i32;
    }
    val = xmlValidateAttributeValueInternal(doc, unsafe { (*attrDecl).atype }, value);
    if val == 0 as i32 {
        if !(unsafe { (*ns).prefix }).is_null() {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_INVALID_DEFAULT,
                b"Syntax of value for attribute xmlns:%s of %s is not valid\n\0" as *const u8
                    as *const i8,
                unsafe { (*ns).prefix },
                unsafe { (*elem).name },
                0 as *const xmlChar,
            );
        } else {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_INVALID_DEFAULT,
                b"Syntax of value for attribute xmlns of %s is not valid\n\0" as *const u8
                    as *const i8,
                unsafe { (*elem).name },
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        ret = 0 as i32;
    }
    if (unsafe { (*attrDecl).def }) as u32 == XML_ATTRIBUTE_FIXED as i32 as u32 {
        if xmlStrEqual(value, unsafe { (*attrDecl).defaultValue }) == 0 {
            if !(unsafe { (*ns).prefix }).is_null() {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_ATTRIBUTE_DEFAULT,
                    b"Value for attribute xmlns:%s of %s is different from default \"%s\"\n\0"
                        as *const u8 as *const i8,
                    unsafe { (*ns).prefix },
                    unsafe { (*elem).name },
                    unsafe { (*attrDecl).defaultValue },
                );
            } else {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_ATTRIBUTE_DEFAULT,
                    b"Value for attribute xmlns of %s is different from default \"%s\"\n\0"
                        as *const u8 as *const i8,
                    unsafe { (*elem).name },
                    unsafe { (*attrDecl).defaultValue },
                    0 as *const xmlChar,
                );
            }
            ret = 0 as i32;
        }
    }
    if (unsafe { (*attrDecl).atype }) as u32 == XML_ATTRIBUTE_NOTATION as i32 as u32 {
        let mut tree: *mut crate::src::threads::_xmlEnumeration = unsafe { (*attrDecl).tree };
        let mut nota: *mut crate::src::valid::_xmlNotation =
            0 as *mut crate::src::valid::_xmlNotation;
        nota = xmlGetDtdNotationDesc(unsafe { (*doc).intSubset }, value);
        if nota.is_null() {
            nota = xmlGetDtdNotationDesc(unsafe { (*doc).extSubset }, value);
        }
        if nota.is_null() {
            if !(unsafe { (*ns).prefix }).is_null() {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_UNKNOWN_NOTATION,
                    b"Value \"%s\" for attribute xmlns:%s of %s is not a declared Notation\n\0"
                        as *const u8 as *const i8,
                    value,
                    unsafe { (*ns).prefix },
                    unsafe { (*elem).name },
                );
            } else {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_UNKNOWN_NOTATION,
                    b"Value \"%s\" for attribute xmlns of %s is not a declared Notation\n\0"
                        as *const u8 as *const i8,
                    value,
                    unsafe { (*elem).name },
                    0 as *const xmlChar,
                );
            }
            ret = 0 as i32;
        }
        while !tree.is_null() {
            if xmlStrEqual(unsafe { (*tree).name }, value) != 0 {
                break;
            }
            tree = unsafe { (*tree).next };
        }
        if tree.is_null() {
            if !(unsafe { (*ns).prefix }).is_null() {
                xmlErrValidNode (ctxt , elem , XML_DTD_NOTATION_VALUE , b"Value \"%s\" for attribute xmlns:%s of %s is not among the enumerated notations\n\0" as * const u8 as * const i8 , value , unsafe { (* ns) . prefix } , unsafe { (* elem) . name } ,) ;
            } else {
                xmlErrValidNode (ctxt , elem , XML_DTD_NOTATION_VALUE , b"Value \"%s\" for attribute xmlns of %s is not among the enumerated notations\n\0" as * const u8 as * const i8 , value , unsafe { (* elem) . name } , 0 as * const xmlChar ,) ;
            }
            ret = 0 as i32;
        }
    }
    if (unsafe { (*attrDecl).atype }) as u32 == XML_ATTRIBUTE_ENUMERATION as i32 as u32 {
        let mut tree_0: *mut crate::src::threads::_xmlEnumeration = unsafe { (*attrDecl).tree };
        while !tree_0.is_null() {
            if xmlStrEqual(unsafe { (*tree_0).name }, value) != 0 {
                break;
            }
            tree_0 = unsafe { (*tree_0).next };
        }
        if tree_0.is_null() {
            if !(unsafe { (*ns).prefix }).is_null() {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_ATTRIBUTE_VALUE,
                    b"Value \"%s\" for attribute xmlns:%s of %s is not among the enumerated set\n\0"
                        as *const u8 as *const i8,
                    value,
                    unsafe { (*ns).prefix },
                    unsafe { (*elem).name },
                );
            } else {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_ATTRIBUTE_VALUE,
                    b"Value \"%s\" for attribute xmlns of %s is not among the enumerated set\n\0"
                        as *const u8 as *const i8,
                    value,
                    unsafe { (*elem).name },
                    0 as *const xmlChar,
                );
            }
            ret = 0 as i32;
        }
    }
    if (unsafe { (*attrDecl).def }) as u32 == XML_ATTRIBUTE_FIXED as i32 as u32
        && xmlStrEqual(unsafe { (*attrDecl).defaultValue }, value) == 0
    {
        if !(unsafe { (*ns).prefix }).is_null() {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_ELEM_NAMESPACE,
                b"Value for attribute xmlns:%s of %s must be \"%s\"\n\0" as *const u8 as *const i8,
                unsafe { (*ns).prefix },
                unsafe { (*elem).name },
                unsafe { (*attrDecl).defaultValue },
            );
        } else {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_ELEM_NAMESPACE,
                b"Value for attribute xmlns of %s must be \"%s\"\n\0" as *const u8 as *const i8,
                unsafe { (*elem).name },
                unsafe { (*attrDecl).defaultValue },
                0 as *const xmlChar,
            );
        }
        ret = 0 as i32;
    }
    if !(unsafe { (*ns).prefix }).is_null() {
        ret &= xmlValidateAttributeValue2(
            ctxt,
            doc,
            unsafe { (*ns).prefix },
            unsafe { (*attrDecl).atype },
            value,
        );
    } else {
        ret &= xmlValidateAttributeValue2(
            ctxt,
            doc,
            b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
            unsafe { (*attrDecl).atype },
            value,
        );
    }
    return ret;
}
extern "C" fn xmlSnprintfElements(
    mut buf: *mut i8,
    mut size: i32,
    mut node: *mut crate::src::threads::_xmlNode,
    mut glob: i32,
) {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut len: i32 = 0;
    if node.is_null() {
        return;
    }
    if glob != 0 {
        (unsafe { strcat(buf, b"(\0" as *const u8 as *const i8) });
    }
    cur = node;
    while !cur.is_null() {
        len = (unsafe { strlen(buf) }) as i32;
        if size - len < 50 as i32 {
            if size - len > 4 as i32
                && (unsafe { *buf.offset((len - 1 as i32) as isize) }) as i32 != '.' as i32
            {
                (unsafe { strcat(buf, b" ...\0" as *const u8 as *const i8) });
            }
            return;
        }
        let mut current_block_33: u64;
        match (unsafe { (*cur).type_0 }) as u32 {
            1 => {
                if !(unsafe { (*cur).ns }).is_null()
                    && !(unsafe { (*(*cur).ns).prefix }).is_null()
                {
                    if size - len < xmlStrlen(unsafe { (*(*cur).ns).prefix }) + 10 as i32 {
                        if size - len > 4 as i32
                            && (unsafe { *buf.offset((len - 1 as i32) as isize) }) as i32
                                != '.' as i32
                        {
                            (unsafe { strcat(buf, b" ...\0" as *const u8 as *const i8) });
                        }
                        return;
                    }
                    (unsafe { strcat(buf, (*(*cur).ns).prefix as *mut i8) });
                    (unsafe { strcat(buf, b":\0" as *const u8 as *const i8) });
                }
                if size - len < xmlStrlen(unsafe { (*cur).name }) + 10 as i32 {
                    if size - len > 4 as i32
                        && (unsafe { *buf.offset((len - 1 as i32) as isize) }) as i32 != '.' as i32
                    {
                        (unsafe { strcat(buf, b" ...\0" as *const u8 as *const i8) });
                    }
                    return;
                }
                (unsafe { strcat(buf, (*cur).name as *mut i8) });
                if !(unsafe { (*cur).next }).is_null() {
                    (unsafe { strcat(buf, b" \0" as *const u8 as *const i8) });
                }
                current_block_33 = 572715077006366937;
            }
            3 => {
                if xmlIsBlankNode(cur as *const xmlNode) != 0 {
                    current_block_33 = 572715077006366937;
                } else {
                    current_block_33 = 17094473893460782832;
                }
            }
            4 | 5 => {
                current_block_33 = 17094473893460782832;
            }
            2 | 9 | 13 | 10 | 11 | 12 | 18 => {
                (unsafe { strcat(buf, b"???\0" as *const u8 as *const i8) });
                if !(unsafe { (*cur).next }).is_null() {
                    (unsafe { strcat(buf, b" \0" as *const u8 as *const i8) });
                }
                current_block_33 = 572715077006366937;
            }
            6 | 7 | 14 | 8 | 15 | 16 | 17 | 19 | 20 | _ => {
                current_block_33 = 572715077006366937;
            }
        }
        match current_block_33 {
            17094473893460782832 => {
                (unsafe { strcat(buf, b"CDATA\0" as *const u8 as *const i8) });
                if !(unsafe { (*cur).next }).is_null() {
                    (unsafe { strcat(buf, b" \0" as *const u8 as *const i8) });
                }
            }
            _ => {}
        }
        cur = unsafe { (*cur).next };
    }
    if glob != 0 {
        (unsafe { strcat(buf, b")\0" as *const u8 as *const i8) });
    }
}
extern "C" fn xmlValidateElementContent(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut child: *mut crate::src::threads::_xmlNode,
    mut elemDecl: *mut crate::src::tree::_xmlElement,
    mut warn: i32,
    mut parent: *mut crate::src::threads::_xmlNode,
) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 1 as i32;
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut cont: *mut crate::src::threads::_xmlElementContent = 0 as *mut xmlElementContent;
    let mut name: *const u8 = 0 as *const xmlChar;
    if elemDecl.is_null() || parent.is_null() || ctxt.is_null() {
        return -(1 as i32);
    }
    cont = unsafe { (*elemDecl).content };
    name = unsafe { (*elemDecl).name };
    if (unsafe { (*elemDecl).contModel }).is_null() {
        ret = xmlValidBuildContentModel(ctxt, elemDecl);
    }
    if (unsafe { (*elemDecl).contModel }).is_null() {
        return -(1 as i32);
    } else {
        let mut exec: *mut crate::src::xmlregexp::_xmlRegExecCtxt = 0 as *mut xmlRegExecCtxt;
        if xmlRegexpIsDeterminist(unsafe { (*elemDecl).contModel }) == 0 {
            return -(1 as i32);
        }
        (unsafe { (*ctxt).nodeMax = 0 as i32 });
        (unsafe { (*ctxt).nodeNr = 0 as i32 });
        let fresh146 = unsafe { &mut ((*ctxt).nodeTab) };
        *fresh146 = 0 as *mut xmlNodePtr;
        exec = xmlRegNewExecCtxt(
            unsafe { (*elemDecl).contModel },
            None,
            0 as *mut libc::c_void,
        );
        if !exec.is_null() {
            cur = child;
            loop {
                if cur.is_null() {
                    current_block = 1345366029464561491;
                    break;
                }
                match (unsafe { (*cur).type_0 }) as u32 {
                    5 => {
                        if !(unsafe { (*cur).children }).is_null()
                            && !(unsafe { (*(*cur).children).children }).is_null()
                        {
                            nodeVPush(ctxt, cur);
                            cur = unsafe { (*(*cur).children).children };
                            continue;
                        }
                    }
                    3 => {
                        if !(xmlIsBlankNode(cur as *const xmlNode) != 0) {
                            ret = 0 as i32;
                            current_block = 9694673564057544886;
                            break;
                        }
                    }
                    4 => {
                        ret = 0 as i32;
                        current_block = 9694673564057544886;
                        break;
                    }
                    1 => {
                        if !(unsafe { (*cur).ns }).is_null()
                            && !(unsafe { (*(*cur).ns).prefix }).is_null()
                        {
                            let mut fn_0: [u8; 50] = [0; 50];
                            let mut fullname: *mut u8 = 0 as *mut xmlChar;
                            fullname = xmlBuildQName(
                                unsafe { (*cur).name },
                                unsafe { (*(*cur).ns).prefix },
                                fn_0.as_mut_ptr(),
                                50 as i32,
                            );
                            if fullname.is_null() {
                                ret = -(1 as i32);
                                current_block = 9694673564057544886;
                                break;
                            } else {
                                ret = xmlRegExecPushString(exec, fullname, 0 as *mut libc::c_void);
                                if fullname != fn_0.as_mut_ptr()
                                    && fullname != (unsafe { (*cur).name }) as *mut xmlChar
                                {
                                    (unsafe {
                                        xmlFree.expect("non-null function pointer")(
                                            fullname as *mut libc::c_void,
                                        )
                                    });
                                }
                            }
                        } else {
                            ret = xmlRegExecPushString(
                                exec,
                                unsafe { (*cur).name },
                                0 as *mut libc::c_void,
                            );
                        }
                    }
                    _ => {}
                }
                cur = unsafe { (*cur).next };
                while cur.is_null() {
                    cur = nodeVPop(ctxt);
                    if cur.is_null() {
                        break;
                    }
                    cur = unsafe { (*cur).next };
                }
            }
            match current_block {
                1345366029464561491 => {
                    ret = xmlRegExecPushString(exec, 0 as *const xmlChar, 0 as *mut libc::c_void);
                }
                _ => {}
            }
            xmlRegFreeExecCtxt(exec);
        }
        if warn != 0 && (ret != 1 as i32 && ret != -(3 as i32)) {
            if !ctxt.is_null() {
                let mut expr: [i8; 5000] = [0; 5000];
                let mut list: [i8; 5000] = [0; 5000];
                expr[0 as i32 as usize] = 0 as i32 as i8;
                xmlSnprintfElementContent(
                    unsafe { &mut *expr.as_mut_ptr().offset(0 as i32 as isize) },
                    5000 as i32,
                    cont,
                    1 as i32,
                );
                list[0 as i32 as usize] = 0 as i32 as i8;
                xmlSnprintfElements(
                    unsafe { &mut *list.as_mut_ptr().offset(0 as i32 as isize) },
                    5000 as i32,
                    child,
                    1 as i32,
                );
                if !name.is_null() {
                    xmlErrValidNode(
                        ctxt,
                        parent,
                        XML_DTD_CONTENT_MODEL,
                        b"Element %s content does not follow the DTD, expecting %s, got %s\n\0"
                            as *const u8 as *const i8,
                        name,
                        expr.as_mut_ptr() as *mut xmlChar,
                        list.as_mut_ptr() as *mut xmlChar,
                    );
                } else {
                    xmlErrValidNode(
                        ctxt,
                        parent,
                        XML_DTD_CONTENT_MODEL,
                        b"Element content does not follow the DTD, expecting %s, got %s\n\0"
                            as *const u8 as *const i8,
                        expr.as_mut_ptr() as *mut xmlChar,
                        list.as_mut_ptr() as *mut xmlChar,
                        0 as *const xmlChar,
                    );
                }
            } else if !name.is_null() {
                xmlErrValidNode(
                    ctxt,
                    parent,
                    XML_DTD_CONTENT_MODEL,
                    b"Element %s content does not follow the DTD\n\0" as *const u8 as *const i8,
                    name,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
            } else {
                xmlErrValidNode(
                    ctxt,
                    parent,
                    XML_DTD_CONTENT_MODEL,
                    b"Element content does not follow the DTD\n\0" as *const u8 as *const i8,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
            }
            ret = 0 as i32;
        }
        if ret == -(3 as i32) {
            ret = 1 as i32;
        }
        (unsafe { (*ctxt).nodeMax = 0 as i32 });
        (unsafe { (*ctxt).nodeNr = 0 as i32 });
        if !(unsafe { (*ctxt).nodeTab }).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")((*ctxt).nodeTab as *mut libc::c_void)
            });
            let fresh147 = unsafe { &mut ((*ctxt).nodeTab) };
            *fresh147 = 0 as *mut xmlNodePtr;
        }
        return ret;
    };
}
extern "C" fn xmlValidateOneCdataElement(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut elem: *mut crate::src::threads::_xmlNode,
) -> i32 {
    let mut ret: i32 = 1 as i32;
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut child: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if ctxt.is_null()
        || doc.is_null()
        || elem.is_null()
        || (unsafe { (*elem).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
    {
        return 0 as i32;
    }
    child = unsafe { (*elem).children };
    cur = child;
    while !cur.is_null() {
        match (unsafe { (*cur).type_0 }) as u32 {
            5 => {
                if !(unsafe { (*cur).children }).is_null()
                    && !(unsafe { (*(*cur).children).children }).is_null()
                {
                    nodeVPush(ctxt, cur);
                    cur = unsafe { (*(*cur).children).children };
                    continue;
                }
            }
            8 | 7 | 3 | 4 => {}
            _ => {
                ret = 0 as i32;
                break;
            }
        }
        cur = unsafe { (*cur).next };
        while cur.is_null() {
            cur = nodeVPop(ctxt);
            if cur.is_null() {
                break;
            }
            cur = unsafe { (*cur).next };
        }
    }
    (unsafe { (*ctxt).nodeMax = 0 as i32 });
    (unsafe { (*ctxt).nodeNr = 0 as i32 });
    if !(unsafe { (*ctxt).nodeTab }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*ctxt).nodeTab as *mut libc::c_void)
        });
        let fresh148 = unsafe { &mut ((*ctxt).nodeTab) };
        *fresh148 = 0 as *mut xmlNodePtr;
    }
    return ret;
}
extern "C" fn xmlValidateCheckMixed(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut cont: *mut crate::src::threads::_xmlElementContent,
    mut qname: *const u8,
) -> i32 {
    let mut name: *const u8 = 0 as *const xmlChar;
    let mut plen: i32 = 0;
    name = xmlSplitQName3(qname, Some(&mut plen));
    if name.is_null() {
        while !cont.is_null() {
            if (unsafe { (*cont).type_0 }) as u32 == XML_ELEMENT_CONTENT_ELEMENT as i32 as u32 {
                if (unsafe { (*cont).prefix }).is_null()
                    && xmlStrEqual(unsafe { (*cont).name }, qname) != 0
                {
                    return 1 as i32;
                }
            } else if (unsafe { (*cont).type_0 }) as u32 == XML_ELEMENT_CONTENT_OR as i32 as u32
                && !(unsafe { (*cont).c1 }).is_null()
                && (unsafe { (*(*cont).c1).type_0 }) as u32
                    == XML_ELEMENT_CONTENT_ELEMENT as i32 as u32
            {
                if (unsafe { (*(*cont).c1).prefix }).is_null()
                    && xmlStrEqual(unsafe { (*(*cont).c1).name }, qname) != 0
                {
                    return 1 as i32;
                }
            } else if (unsafe { (*cont).type_0 }) as u32 != XML_ELEMENT_CONTENT_OR as i32 as u32
                || (unsafe { (*cont).c1 }).is_null()
                || (unsafe { (*(*cont).c1).type_0 }) as u32
                    != XML_ELEMENT_CONTENT_PCDATA as i32 as u32
            {
                xmlErrValid(
                    0 as xmlValidCtxtPtr,
                    XML_DTD_MIXED_CORRUPT,
                    b"Internal: MIXED struct corrupted\n\0" as *const u8 as *const i8,
                    0 as *const i8,
                );
                break;
            }
            cont = unsafe { (*cont).c2 };
        }
    } else {
        while !cont.is_null() {
            if (unsafe { (*cont).type_0 }) as u32 == XML_ELEMENT_CONTENT_ELEMENT as i32 as u32 {
                if !(unsafe { (*cont).prefix }).is_null()
                    && xmlStrncmp(unsafe { (*cont).prefix }, qname, plen) == 0 as i32
                    && xmlStrEqual(unsafe { (*cont).name }, name) != 0
                {
                    return 1 as i32;
                }
            } else if (unsafe { (*cont).type_0 }) as u32 == XML_ELEMENT_CONTENT_OR as i32 as u32
                && !(unsafe { (*cont).c1 }).is_null()
                && (unsafe { (*(*cont).c1).type_0 }) as u32
                    == XML_ELEMENT_CONTENT_ELEMENT as i32 as u32
            {
                if !(unsafe { (*(*cont).c1).prefix }).is_null()
                    && xmlStrncmp(unsafe { (*(*cont).c1).prefix }, qname, plen) == 0 as i32
                    && xmlStrEqual(unsafe { (*(*cont).c1).name }, name) != 0
                {
                    return 1 as i32;
                }
            } else if (unsafe { (*cont).type_0 }) as u32 != XML_ELEMENT_CONTENT_OR as i32 as u32
                || (unsafe { (*cont).c1 }).is_null()
                || (unsafe { (*(*cont).c1).type_0 }) as u32
                    != XML_ELEMENT_CONTENT_PCDATA as i32 as u32
            {
                xmlErrValid(
                    ctxt,
                    XML_DTD_MIXED_CORRUPT,
                    b"Internal: MIXED struct corrupted\n\0" as *const u8 as *const i8,
                    0 as *const i8,
                );
                break;
            }
            cont = unsafe { (*cont).c2 };
        }
    }
    return 0 as i32;
}
extern "C" fn xmlValidGetElemDecl<'a1>(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut elem: *mut crate::src::threads::_xmlNode,
    mut extsubset: Option<&'a1 mut i32>,
) -> *mut crate::src::tree::_xmlElement {
    let mut elemDecl: *mut crate::src::tree::_xmlElement = 0 as xmlElementPtr;
    let mut prefix: *const u8 = 0 as *const xmlChar;
    if ctxt.is_null() || doc.is_null() || elem.is_null() || (unsafe { (*elem).name }).is_null() {
        return 0 as xmlElementPtr;
    }
    if !borrow(&extsubset).is_none() {
        *(borrow_mut(&mut extsubset)).unwrap() = 0 as i32;
    }
    if !(unsafe { (*elem).ns }).is_null() && !(unsafe { (*(*elem).ns).prefix }).is_null() {
        prefix = unsafe { (*(*elem).ns).prefix };
    }
    if !prefix.is_null() {
        elemDecl = xmlGetDtdQElementDesc(
            unsafe { (*doc).intSubset },
            unsafe { (*elem).name },
            prefix,
        );
        if elemDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
            elemDecl = xmlGetDtdQElementDesc(
                unsafe { (*doc).extSubset },
                unsafe { (*elem).name },
                prefix,
            );
            if !elemDecl.is_null() && !borrow(&extsubset).is_none() {
                *(borrow_mut(&mut extsubset)).unwrap() = 1 as i32;
            }
        }
    }
    if elemDecl.is_null() {
        elemDecl = xmlGetDtdElementDesc(unsafe { (*doc).intSubset }, unsafe { (*elem).name });
        if elemDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
            elemDecl =
                xmlGetDtdElementDesc(unsafe { (*doc).extSubset }, unsafe { (*elem).name });
            if !elemDecl.is_null() && !borrow(&extsubset).is_none() {
                *(borrow_mut(&mut extsubset)).unwrap() = 1 as i32;
            }
        }
    }
    if elemDecl.is_null() {
        xmlErrValidNode(
            ctxt,
            elem,
            XML_DTD_UNKNOWN_ELEM,
            b"No declaration for element %s\n\0" as *const u8 as *const i8,
            unsafe { (*elem).name },
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    }
    return elemDecl;
}
#[no_mangle]
pub extern "C" fn xmlValidatePushElement(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut elem: *mut crate::src::threads::_xmlNode,
    mut qname: *const u8,
) -> i32 {
    let mut ret: i32 = 1 as i32;
    let mut eDecl: *mut crate::src::tree::_xmlElement = 0 as *mut xmlElement;
    let mut extsubset: i32 = 0 as i32;
    if ctxt.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*ctxt).vstateNr }) > 0 as i32 && !(unsafe { (*ctxt).vstate }).is_null() {
        let mut state: *mut crate::src::valid::_xmlValidState = unsafe { (*ctxt).vstate };
        let mut elemDecl: *mut crate::src::tree::_xmlElement = 0 as *mut xmlElement;
        if !(unsafe { (*state).elemDecl }).is_null() {
            elemDecl = unsafe { (*state).elemDecl };
            match (unsafe { (*elemDecl).etype }) as u32 {
                0 => {
                    ret = 0 as i32;
                }
                1 => {
                    xmlErrValidNode(
                        ctxt,
                        unsafe { (*state).node },
                        XML_DTD_NOT_EMPTY,
                        b"Element %s was declared EMPTY this one has content\n\0" as *const u8
                            as *const i8,
                        unsafe { (*(*state).node).name },
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    ret = 0 as i32;
                }
                3 => {
                    if !(unsafe { (*elemDecl).content }).is_null()
                        && (unsafe { (*(*elemDecl).content).type_0 }) as u32
                            == XML_ELEMENT_CONTENT_PCDATA as i32 as u32
                    {
                        xmlErrValidNode(
                            ctxt,
                            unsafe { (*state).node },
                            XML_DTD_NOT_PCDATA,
                            b"Element %s was declared #PCDATA but contains non text nodes\n\0"
                                as *const u8 as *const i8,
                            unsafe { (*(*state).node).name },
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                        ret = 0 as i32;
                    } else {
                        ret = xmlValidateCheckMixed(ctxt, unsafe { (*elemDecl).content }, qname);
                        if ret != 1 as i32 {
                            xmlErrValidNode(
                                ctxt,
                                unsafe { (*state).node },
                                XML_DTD_INVALID_CHILD,
                                b"Element %s is not declared in %s list of possible children\n\0"
                                    as *const u8 as *const i8,
                                qname,
                                unsafe { (*(*state).node).name },
                                0 as *const xmlChar,
                            );
                        }
                    }
                }
                4 => {
                    if !(unsafe { (*state).exec }).is_null() {
                        ret = xmlRegExecPushString(
                            unsafe { (*state).exec },
                            qname,
                            0 as *mut libc::c_void,
                        );
                        if ret < 0 as i32 {
                            xmlErrValidNode(
                                ctxt,
                                unsafe { (*state).node },
                                XML_DTD_CONTENT_MODEL,
                                b"Element %s content does not follow the DTD, Misplaced %s\n\0"
                                    as *const u8 as *const i8,
                                unsafe { (*(*state).node).name },
                                qname,
                                0 as *const xmlChar,
                            );
                            ret = 0 as i32;
                        } else {
                            ret = 1 as i32;
                        }
                    }
                }
                2 | _ => {}
            }
        }
    }
    eDecl = xmlValidGetElemDecl(ctxt, doc, elem, Some(&mut extsubset));
    vstateVPush(ctxt, eDecl, elem);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlValidatePushCData(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut data: *const u8,
    mut len: i32,
) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 1 as i32;
    if ctxt.is_null() {
        return 0 as i32;
    }
    if len <= 0 as i32 {
        return ret;
    }
    if (unsafe { (*ctxt).vstateNr }) > 0 as i32 && !(unsafe { (*ctxt).vstate }).is_null() {
        let mut state: *mut crate::src::valid::_xmlValidState = unsafe { (*ctxt).vstate };
        let mut elemDecl: *mut crate::src::tree::_xmlElement = 0 as *mut xmlElement;
        if !(unsafe { (*state).elemDecl }).is_null() {
            elemDecl = unsafe { (*state).elemDecl };
            match (unsafe { (*elemDecl).etype }) as u32 {
                0 => {
                    current_block = 8999518187244832834;
                    match current_block {
                        8999518187244832834 => {
                            ret = 0 as i32;
                        }
                        10599921512955367680 => {
                            let mut i: i32 = 0;
                            i = 0 as i32;
                            while i < len {
                                if !((unsafe { *data.offset(i as isize) }) as i32 == 0x20 as i32
                                    || 0x9 as i32 <= (unsafe { *data.offset(i as isize) }) as i32
                                        && (unsafe { *data.offset(i as isize) }) as i32
                                            <= 0xa as i32
                                    || (unsafe { *data.offset(i as isize) }) as i32 == 0xd as i32)
                                {
                                    xmlErrValidNode (ctxt , unsafe { (* state) . node } , XML_DTD_CONTENT_MODEL , b"Element %s content does not follow the DTD, Text not allowed\n\0" as * const u8 as * const i8 , unsafe { (* (* state) . node) . name } , 0 as * const xmlChar , 0 as * const xmlChar ,) ;
                                    ret = 0 as i32;
                                    break;
                                } else {
                                    i += 1;
                                }
                            }
                        }
                        _ => {
                            xmlErrValidNode(
                                ctxt,
                                unsafe { (*state).node },
                                XML_DTD_NOT_EMPTY,
                                b"Element %s was declared EMPTY this one has content\n\0"
                                    as *const u8 as *const i8,
                                unsafe { (*(*state).node).name },
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                            );
                            ret = 0 as i32;
                        }
                    }
                }
                1 => {
                    current_block = 11090157271596910899;
                    match current_block {
                        8999518187244832834 => {
                            ret = 0 as i32;
                        }
                        10599921512955367680 => {
                            let mut i: i32 = 0;
                            i = 0 as i32;
                            while i < len {
                                if !((unsafe { *data.offset(i as isize) }) as i32 == 0x20 as i32
                                    || 0x9 as i32 <= (unsafe { *data.offset(i as isize) }) as i32
                                        && (unsafe { *data.offset(i as isize) }) as i32
                                            <= 0xa as i32
                                    || (unsafe { *data.offset(i as isize) }) as i32 == 0xd as i32)
                                {
                                    xmlErrValidNode (ctxt , unsafe { (* state) . node } , XML_DTD_CONTENT_MODEL , b"Element %s content does not follow the DTD, Text not allowed\n\0" as * const u8 as * const i8 , unsafe { (* (* state) . node) . name } , 0 as * const xmlChar , 0 as * const xmlChar ,) ;
                                    ret = 0 as i32;
                                    break;
                                } else {
                                    i += 1;
                                }
                            }
                        }
                        _ => {
                            xmlErrValidNode(
                                ctxt,
                                unsafe { (*state).node },
                                XML_DTD_NOT_EMPTY,
                                b"Element %s was declared EMPTY this one has content\n\0"
                                    as *const u8 as *const i8,
                                unsafe { (*(*state).node).name },
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                            );
                            ret = 0 as i32;
                        }
                    }
                }
                4 => {
                    current_block = 10599921512955367680;
                    match current_block {
                        8999518187244832834 => {
                            ret = 0 as i32;
                        }
                        10599921512955367680 => {
                            let mut i: i32 = 0;
                            i = 0 as i32;
                            while i < len {
                                if !((unsafe { *data.offset(i as isize) }) as i32 == 0x20 as i32
                                    || 0x9 as i32 <= (unsafe { *data.offset(i as isize) }) as i32
                                        && (unsafe { *data.offset(i as isize) }) as i32
                                            <= 0xa as i32
                                    || (unsafe { *data.offset(i as isize) }) as i32 == 0xd as i32)
                                {
                                    xmlErrValidNode (ctxt , unsafe { (* state) . node } , XML_DTD_CONTENT_MODEL , b"Element %s content does not follow the DTD, Text not allowed\n\0" as * const u8 as * const i8 , unsafe { (* (* state) . node) . name } , 0 as * const xmlChar , 0 as * const xmlChar ,) ;
                                    ret = 0 as i32;
                                    break;
                                } else {
                                    i += 1;
                                }
                            }
                        }
                        _ => {
                            xmlErrValidNode(
                                ctxt,
                                unsafe { (*state).node },
                                XML_DTD_NOT_EMPTY,
                                b"Element %s was declared EMPTY this one has content\n\0"
                                    as *const u8 as *const i8,
                                unsafe { (*(*state).node).name },
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                            );
                            ret = 0 as i32;
                        }
                    }
                }
                2 | 3 | _ => {}
            }
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlValidatePopElement(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut _doc: *mut crate::src::threads::_xmlDoc,
    mut _elem: *mut crate::src::threads::_xmlNode,
    mut _qname: *const u8,
) -> i32 {
    let mut ret: i32 = 1 as i32;
    if ctxt.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*ctxt).vstateNr }) > 0 as i32 && !(unsafe { (*ctxt).vstate }).is_null() {
        let mut state: *mut crate::src::valid::_xmlValidState = unsafe { (*ctxt).vstate };
        let mut elemDecl: *mut crate::src::tree::_xmlElement = 0 as *mut xmlElement;
        if !(unsafe { (*state).elemDecl }).is_null() {
            elemDecl = unsafe { (*state).elemDecl };
            if (unsafe { (*elemDecl).etype }) as u32 == XML_ELEMENT_TYPE_ELEMENT as i32 as u32 {
                if !(unsafe { (*state).exec }).is_null() {
                    ret = xmlRegExecPushString(
                        unsafe { (*state).exec },
                        0 as *const xmlChar,
                        0 as *mut libc::c_void,
                    );
                    if ret == 0 as i32 {
                        xmlErrValidNode(
                            ctxt,
                            unsafe { (*state).node },
                            XML_DTD_CONTENT_MODEL,
                            b"Element %s content does not follow the DTD, Expecting more child\n\0"
                                as *const u8 as *const i8,
                            unsafe { (*(*state).node).name },
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                    } else {
                        ret = 1 as i32;
                    }
                }
            }
        }
        vstateVPop(ctxt);
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlValidateOneElement(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut elem: *mut crate::src::threads::_xmlNode,
) -> i32 {
    let mut current_block: u64;
    let mut elemDecl: *mut crate::src::tree::_xmlElement = 0 as xmlElementPtr;
    let mut cont: *mut crate::src::threads::_xmlElementContent = 0 as *mut xmlElementContent;
    let mut attr: *mut crate::src::tree::_xmlAttribute = 0 as *mut xmlAttribute;
    let mut child: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut ret: i32 = 1 as i32;
    let mut tmp: i32 = 0;
    let mut name: *const u8 = 0 as *const xmlChar;
    let mut extsubset: i32 = 0 as i32;
    if doc.is_null() {
        return 0 as i32;
    } else {
        if (unsafe { (*doc).intSubset }).is_null() && (unsafe { (*doc).extSubset }).is_null() {
            return 0 as i32;
        }
    }
    if elem.is_null() {
        return 0 as i32;
    }
    match (unsafe { (*elem).type_0 }) as u32 {
        2 => {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_ERR_INTERNAL_ERROR,
                b"Attribute element not expected\n\0" as *const u8 as *const i8,
                0 as *const xmlChar,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as i32;
        }
        3 => {
            if !(unsafe { (*elem).children }).is_null() {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_ERR_INTERNAL_ERROR,
                    b"Text element has children !\n\0" as *const u8 as *const i8,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                return 0 as i32;
            }
            if !(unsafe { (*elem).ns }).is_null() {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_ERR_INTERNAL_ERROR,
                    b"Text element has namespace !\n\0" as *const u8 as *const i8,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                return 0 as i32;
            }
            if (unsafe { (*elem).content }).is_null() {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_ERR_INTERNAL_ERROR,
                    b"Text element has no content !\n\0" as *const u8 as *const i8,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                return 0 as i32;
            }
            return 1 as i32;
        }
        19 | 20 => return 1 as i32,
        4 | 5 | 7 | 8 => return 1 as i32,
        6 => {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_ERR_INTERNAL_ERROR,
                b"Entity element not expected\n\0" as *const u8 as *const i8,
                0 as *const xmlChar,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as i32;
        }
        12 => {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_ERR_INTERNAL_ERROR,
                b"Notation element not expected\n\0" as *const u8 as *const i8,
                0 as *const xmlChar,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as i32;
        }
        9 | 10 | 11 => {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_ERR_INTERNAL_ERROR,
                b"Document element not expected\n\0" as *const u8 as *const i8,
                0 as *const xmlChar,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as i32;
        }
        13 => {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_ERR_INTERNAL_ERROR,
                b"HTML Document not expected\n\0" as *const u8 as *const i8,
                0 as *const xmlChar,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as i32;
        }
        1 => {}
        _ => {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_ERR_INTERNAL_ERROR,
                b"unknown element type\n\0" as *const u8 as *const i8,
                0 as *const xmlChar,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as i32;
        }
    }
    elemDecl = xmlValidGetElemDecl(ctxt, doc, elem, Some(&mut extsubset));
    if elemDecl.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*ctxt).vstateNr }) == 0 as i32 {
        match (unsafe { (*elemDecl).etype }) as u32 {
            0 => {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_UNKNOWN_ELEM,
                    b"No declaration for element %s\n\0" as *const u8 as *const i8,
                    unsafe { (*elem).name },
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                return 0 as i32;
            }
            1 => {
                if !(unsafe { (*elem).children }).is_null() {
                    xmlErrValidNode(
                        ctxt,
                        elem,
                        XML_DTD_NOT_EMPTY,
                        b"Element %s was declared EMPTY this one has content\n\0" as *const u8
                            as *const i8,
                        unsafe { (*elem).name },
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    ret = 0 as i32;
                }
            }
            3 => {
                if !(unsafe { (*elemDecl).content }).is_null()
                    && (unsafe { (*(*elemDecl).content).type_0 }) as u32
                        == XML_ELEMENT_CONTENT_PCDATA as i32 as u32
                {
                    ret = xmlValidateOneCdataElement(ctxt, doc, elem);
                    if ret == 0 {
                        xmlErrValidNode(
                            ctxt,
                            elem,
                            XML_DTD_NOT_PCDATA,
                            b"Element %s was declared #PCDATA but contains non text nodes\n\0"
                                as *const u8 as *const i8,
                            unsafe { (*elem).name },
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                    }
                } else {
                    child = unsafe { (*elem).children };
                    while !child.is_null() {
                        let mut current_block_66: u64;
                        if (unsafe { (*child).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                            name = unsafe { (*child).name };
                            if !(unsafe { (*child).ns }).is_null()
                                && !(unsafe { (*(*child).ns).prefix }).is_null()
                            {
                                let mut fn_0: [u8; 50] = [0; 50];
                                let mut fullname: *mut u8 = 0 as *mut xmlChar;
                                fullname = xmlBuildQName(
                                    unsafe { (*child).name },
                                    unsafe { (*(*child).ns).prefix },
                                    fn_0.as_mut_ptr(),
                                    50 as i32,
                                );
                                if fullname.is_null() {
                                    return 0 as i32;
                                }
                                cont = unsafe { (*elemDecl).content };
                                while !cont.is_null() {
                                    if (unsafe { (*cont).type_0 }) as u32
                                        == XML_ELEMENT_CONTENT_ELEMENT as i32 as u32
                                    {
                                        if xmlStrEqual(unsafe { (*cont).name }, fullname) != 0 {
                                            break;
                                        }
                                    } else if (unsafe { (*cont).type_0 }) as u32
                                        == XML_ELEMENT_CONTENT_OR as i32 as u32
                                        && !(unsafe { (*cont).c1 }).is_null()
                                        && (unsafe { (*(*cont).c1).type_0 }) as u32
                                            == XML_ELEMENT_CONTENT_ELEMENT as i32 as u32
                                    {
                                        if xmlStrEqual(unsafe { (*(*cont).c1).name }, fullname)
                                            != 0
                                        {
                                            break;
                                        }
                                    } else if (unsafe { (*cont).type_0 }) as u32
                                        != XML_ELEMENT_CONTENT_OR as i32 as u32
                                        || (unsafe { (*cont).c1 }).is_null()
                                        || (unsafe { (*(*cont).c1).type_0 }) as u32
                                            != XML_ELEMENT_CONTENT_PCDATA as i32 as u32
                                    {
                                        xmlErrValid(
                                            0 as xmlValidCtxtPtr,
                                            XML_DTD_MIXED_CORRUPT,
                                            b"Internal: MIXED struct corrupted\n\0" as *const u8
                                                as *const i8,
                                            0 as *const i8,
                                        );
                                        break;
                                    }
                                    cont = unsafe { (*cont).c2 };
                                }
                                if fullname != fn_0.as_mut_ptr()
                                    && fullname != (unsafe { (*child).name }) as *mut xmlChar
                                {
                                    (unsafe {
                                        xmlFree.expect("non-null function pointer")(
                                            fullname as *mut libc::c_void,
                                        )
                                    });
                                }
                                if !cont.is_null() {
                                    current_block_66 = 3489511572693469903;
                                } else {
                                    current_block_66 = 17020603795727957434;
                                }
                            } else {
                                current_block_66 = 17020603795727957434;
                            }
                            match current_block_66 {
                                3489511572693469903 => {}
                                _ => {
                                    cont = unsafe { (*elemDecl).content };
                                    while !cont.is_null() {
                                        if (unsafe { (*cont).type_0 }) as u32
                                            == XML_ELEMENT_CONTENT_ELEMENT as i32 as u32
                                        {
                                            if xmlStrEqual(unsafe { (*cont).name }, name) != 0 {
                                                break;
                                            }
                                        } else if (unsafe { (*cont).type_0 }) as u32
                                            == XML_ELEMENT_CONTENT_OR as i32 as u32
                                            && !(unsafe { (*cont).c1 }).is_null()
                                            && (unsafe { (*(*cont).c1).type_0 }) as u32
                                                == XML_ELEMENT_CONTENT_ELEMENT as i32 as u32
                                        {
                                            if xmlStrEqual(unsafe { (*(*cont).c1).name }, name)
                                                != 0
                                            {
                                                break;
                                            }
                                        } else if (unsafe { (*cont).type_0 }) as u32
                                            != XML_ELEMENT_CONTENT_OR as i32 as u32
                                            || (unsafe { (*cont).c1 }).is_null()
                                            || (unsafe { (*(*cont).c1).type_0 }) as u32
                                                != XML_ELEMENT_CONTENT_PCDATA as i32 as u32
                                        {
                                            xmlErrValid(
                                                ctxt,
                                                XML_DTD_MIXED_CORRUPT,
                                                b"Internal: MIXED struct corrupted\n\0" as *const u8
                                                    as *const i8,
                                                0 as *const i8,
                                            );
                                            break;
                                        }
                                        cont = unsafe { (*cont).c2 };
                                    }
                                    if cont.is_null() {
                                        xmlErrValidNode (ctxt , elem , XML_DTD_INVALID_CHILD , b"Element %s is not declared in %s list of possible children\n\0" as * const u8 as * const i8 , name , unsafe { (* elem) . name } , 0 as * const xmlChar ,) ;
                                        ret = 0 as i32;
                                    }
                                }
                            }
                        }
                        child = unsafe { (*child).next };
                    }
                }
            }
            4 => {
                if (unsafe { (*doc).standalone }) == 1 as i32 && extsubset == 1 as i32 {
                    child = unsafe { (*elem).children };
                    while !child.is_null() {
                        if (unsafe { (*child).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32 {
                            let mut content: *const u8 = unsafe { (*child).content };
                            while (unsafe { *content }) as i32 == 0x20 as i32
                                || 0x9 as i32 <= (unsafe { *content }) as i32
                                    && (unsafe { *content }) as i32 <= 0xa as i32
                                || (unsafe { *content }) as i32 == 0xd as i32
                            {
                                content = unsafe { content.offset(1) };
                            }
                            if (unsafe { *content }) as i32 == 0 as i32 {
                                xmlErrValidNode (ctxt , elem , XML_DTD_STANDALONE_WHITE_SPACE , b"standalone: %s declared in the external subset contains white spaces nodes\n\0" as * const u8 as * const i8 , unsafe { (* elem) . name } , 0 as * const xmlChar , 0 as * const xmlChar ,) ;
                                ret = 0 as i32;
                                break;
                            }
                        }
                        child = unsafe { (*child).next };
                    }
                }
                child = unsafe { (*elem).children };
                cont = unsafe { (*elemDecl).content };
                tmp = xmlValidateElementContent(ctxt, child, elemDecl, 1 as i32, elem);
                if tmp <= 0 as i32 {
                    ret = tmp;
                }
            }
            2 | _ => {}
        }
    }
    attr = unsafe { (*elemDecl).attributes };
    while !attr.is_null() {
        if (unsafe { (*attr).def }) as u32 == XML_ATTRIBUTE_REQUIRED as i32 as u32 {
            let mut qualified: i32 = -(1 as i32);
            if (unsafe { (*attr).prefix }).is_null()
                && xmlStrEqual(
                    unsafe { (*attr).name },
                    b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
            {
                let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
                ns = unsafe { (*elem).nsDef };
                loop {
                    if ns.is_null() {
                        current_block = 14184516523743666873;
                        break;
                    }
                    if (unsafe { (*ns).prefix }).is_null() {
                        current_block = 10877472729522060806;
                        break;
                    }
                    ns = unsafe { (*ns).next };
                }
            } else if xmlStrEqual(
                unsafe { (*attr).prefix },
                b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                let mut ns_0: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
                ns_0 = unsafe { (*elem).nsDef };
                loop {
                    if ns_0.is_null() {
                        current_block = 14184516523743666873;
                        break;
                    }
                    if xmlStrEqual(unsafe { (*attr).name }, unsafe { (*ns_0).prefix }) != 0 {
                        current_block = 10877472729522060806;
                        break;
                    }
                    ns_0 = unsafe { (*ns_0).next };
                }
            } else {
                let mut attrib: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
                attrib = unsafe { (*elem).properties };
                loop {
                    if attrib.is_null() {
                        current_block = 14184516523743666873;
                        break;
                    }
                    if xmlStrEqual(unsafe { (*attrib).name }, unsafe { (*attr).name }) != 0 {
                        if (unsafe { (*attr).prefix }).is_null() {
                            current_block = 10877472729522060806;
                            break;
                        }
                        let mut nameSpace: *mut crate::src::threads::_xmlNs =
                            unsafe { (*attrib).ns };
                        if nameSpace.is_null() {
                            nameSpace = unsafe { (*elem).ns };
                        }
                        if nameSpace.is_null() {
                            if qualified < 0 as i32 {
                                qualified = 0 as i32;
                            }
                        } else {
                            if !(xmlStrEqual(
                                unsafe { (*nameSpace).prefix },
                                unsafe { (*attr).prefix },
                            ) == 0)
                            {
                                current_block = 10877472729522060806;
                                break;
                            }
                            if qualified < 1 as i32 {
                                qualified = 1 as i32;
                            }
                        }
                    }
                    attrib = unsafe { (*attrib).next };
                }
            }
            match current_block {
                10877472729522060806 => {}
                _ => {
                    if qualified == -(1 as i32) {
                        if (unsafe { (*attr).prefix }).is_null() {
                            xmlErrValidNode(
                                ctxt,
                                elem,
                                XML_DTD_MISSING_ATTRIBUTE,
                                b"Element %s does not carry attribute %s\n\0" as *const u8
                                    as *const i8,
                                unsafe { (*elem).name },
                                unsafe { (*attr).name },
                                0 as *const xmlChar,
                            );
                            ret = 0 as i32;
                        } else {
                            xmlErrValidNode(
                                ctxt,
                                elem,
                                XML_DTD_MISSING_ATTRIBUTE,
                                b"Element %s does not carry attribute %s:%s\n\0" as *const u8
                                    as *const i8,
                                unsafe { (*elem).name },
                                unsafe { (*attr).prefix },
                                unsafe { (*attr).name },
                            );
                            ret = 0 as i32;
                        }
                    } else if qualified == 0 as i32 {
                        xmlErrValidWarning(
                            ctxt,
                            elem,
                            XML_DTD_NO_PREFIX,
                            b"Element %s required attribute %s:%s has no prefix\n\0" as *const u8
                                as *const i8,
                            unsafe { (*elem).name },
                            unsafe { (*attr).prefix },
                            unsafe { (*attr).name },
                        );
                    } else if qualified == 1 as i32 {
                        xmlErrValidWarning(
                            ctxt,
                            elem,
                            XML_DTD_DIFFERENT_PREFIX,
                            b"Element %s required attribute %s:%s has different prefix\n\0"
                                as *const u8 as *const i8,
                            unsafe { (*elem).name },
                            unsafe { (*attr).prefix },
                            unsafe { (*attr).name },
                        );
                    }
                }
            }
        } else if (unsafe { (*attr).def }) as u32 == XML_ATTRIBUTE_FIXED as i32 as u32 {
            if (unsafe { (*attr).prefix }).is_null()
                && xmlStrEqual(
                    unsafe { (*attr).name },
                    b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
                ) != 0
            {
                let mut ns_1: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
                ns_1 = unsafe { (*elem).nsDef };
                while !ns_1.is_null() {
                    if (unsafe { (*ns_1).prefix }).is_null() {
                        if xmlStrEqual(unsafe { (*attr).defaultValue }, unsafe { (*ns_1).href })
                            == 0
                        {
                            xmlErrValidNode (ctxt , elem , XML_DTD_ELEM_DEFAULT_NAMESPACE , b"Element %s namespace name for default namespace does not match the DTD\n\0" as * const u8 as * const i8 , unsafe { (* elem) . name } , 0 as * const xmlChar , 0 as * const xmlChar ,) ;
                            ret = 0 as i32;
                        }
                        break;
                    } else {
                        ns_1 = unsafe { (*ns_1).next };
                    }
                }
            } else if xmlStrEqual(
                unsafe { (*attr).prefix },
                b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                let mut ns_2: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
                ns_2 = unsafe { (*elem).nsDef };
                while !ns_2.is_null() {
                    if xmlStrEqual(unsafe { (*attr).name }, unsafe { (*ns_2).prefix }) != 0 {
                        if xmlStrEqual(unsafe { (*attr).defaultValue }, unsafe { (*ns_2).href })
                            == 0
                        {
                            xmlErrValidNode(
                                ctxt,
                                elem,
                                XML_DTD_ELEM_NAMESPACE,
                                b"Element %s namespace name for %s does not match the DTD\n\0"
                                    as *const u8 as *const i8,
                                unsafe { (*elem).name },
                                unsafe { (*ns_2).prefix },
                                0 as *const xmlChar,
                            );
                            ret = 0 as i32;
                        }
                        break;
                    } else {
                        ns_2 = unsafe { (*ns_2).next };
                    }
                }
            }
        }
        attr = unsafe { (*attr).nexth };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlValidateRoot(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
) -> i32 {
    let mut current_block: u64;
    let mut root: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut ret: i32 = 0;
    if doc.is_null() {
        return 0 as i32;
    }
    root = xmlDocGetRootElement(doc as *const xmlDoc);
    if root.is_null() || (unsafe { (*root).name }).is_null() {
        xmlErrValid(
            ctxt,
            XML_DTD_NO_ROOT,
            b"no root element\n\0" as *const u8 as *const i8,
            0 as *const i8,
        );
        return 0 as i32;
    }
    if !(unsafe { (*doc).intSubset }).is_null()
        && !(unsafe { (*(*doc).intSubset).name }).is_null()
    {
        if xmlStrEqual(
            unsafe { (*(*doc).intSubset).name },
            unsafe { (*root).name },
        ) == 0
        {
            if !(unsafe { (*root).ns }).is_null()
                && !(unsafe { (*(*root).ns).prefix }).is_null()
            {
                let mut fn_0: [u8; 50] = [0; 50];
                let mut fullname: *mut u8 = 0 as *mut xmlChar;
                fullname = xmlBuildQName(
                    unsafe { (*root).name },
                    unsafe { (*(*root).ns).prefix },
                    fn_0.as_mut_ptr(),
                    50 as i32,
                );
                if fullname.is_null() {
                    xmlVErrMemory(ctxt, 0 as *const i8);
                    return 0 as i32;
                }
                ret = xmlStrEqual(unsafe { (*(*doc).intSubset).name }, fullname);
                if fullname != fn_0.as_mut_ptr()
                    && fullname != (unsafe { (*root).name }) as *mut xmlChar
                {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(fullname as *mut libc::c_void)
                    });
                }
                if ret == 1 as i32 {
                    current_block = 7579103798491188749;
                } else {
                    current_block = 6057473163062296781;
                }
            } else {
                current_block = 6057473163062296781;
            }
            match current_block {
                7579103798491188749 => {}
                _ => {
                    if !(xmlStrEqual(
                        unsafe { (*(*doc).intSubset).name },
                        b"HTML\0" as *const u8 as *const i8 as *mut xmlChar,
                    ) != 0
                        && xmlStrEqual(
                            unsafe { (*root).name },
                            b"html\0" as *const u8 as *const i8 as *mut xmlChar,
                        ) != 0)
                    {
                        xmlErrValidNode(
                            ctxt,
                            root,
                            XML_DTD_ROOT_NAME,
                            b"root and DTD name do not match '%s' and '%s'\n\0" as *const u8
                                as *const i8,
                            unsafe { (*root).name },
                            unsafe { (*(*doc).intSubset).name },
                            0 as *const xmlChar,
                        );
                        return 0 as i32;
                    }
                }
            }
        }
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlValidateElement(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut elem: *mut crate::src::threads::_xmlNode,
) -> i32 {
    let mut child: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut attr: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    let mut value: *const u8 = 0 as *const xmlChar;
    let mut ret: i32 = 1 as i32;
    if elem.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*elem).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32
        || (unsafe { (*elem).type_0 }) as u32 == XML_XINCLUDE_END as i32 as u32
        || (unsafe { (*elem).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
    {
        return 1 as i32;
    }
    if doc.is_null() {
        return 0 as i32;
    } else {
        if (unsafe { (*doc).intSubset }).is_null() && (unsafe { (*doc).extSubset }).is_null() {
            return 0 as i32;
        }
    }
    if (unsafe { (*elem).type_0 }) as u32 == XML_ENTITY_REF_NODE as i32 as u32 {
        return 1 as i32;
    }
    ret &= xmlValidateOneElement(ctxt, doc, elem);
    if (unsafe { (*elem).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
        attr = unsafe { (*elem).properties };
        while !attr.is_null() {
            value = xmlNodeListGetString(doc, unsafe { (*attr).children }, 0 as i32);
            ret &= xmlValidateOneAttribute(ctxt, doc, elem, attr, value);
            if !value.is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(
                        value as *mut i8 as *mut libc::c_void,
                    )
                });
            }
            attr = unsafe { (*attr).next };
        }
        ns = unsafe { (*elem).nsDef };
        while !ns.is_null() {
            if (unsafe { (*elem).ns }).is_null() {
                ret &= xmlValidateOneNamespace(
                    ctxt,
                    doc,
                    elem,
                    0 as *const xmlChar,
                    ns,
                    unsafe { (*ns).href },
                );
            } else {
                ret &= xmlValidateOneNamespace(
                    ctxt,
                    doc,
                    elem,
                    unsafe { (*(*elem).ns).prefix },
                    ns,
                    unsafe { (*ns).href },
                );
            }
            ns = unsafe { (*ns).next };
        }
    }
    child = unsafe { (*elem).children };
    while !child.is_null() {
        ret &= xmlValidateElement(ctxt, doc, child);
        child = unsafe { (*child).next };
    }
    return ret;
}
extern "C" fn xmlValidateRef<'a1>(
    mut ref_0: *mut crate::src::valid::_xmlRef<'a1>,
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut name: *const u8,
) {
    let mut id: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    let mut attr: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    if ref_0.is_null() {
        return;
    }
    if (unsafe { (*ref_0).attr }).is_null() && (unsafe { (*ref_0).name }).is_null() {
        return;
    }
    attr = unsafe { (*ref_0).attr };
    if attr.is_null() {
        let mut dup: *mut u8 = 0 as *mut xmlChar;
        let mut str: *mut u8 = 0 as *mut xmlChar;
        let mut cur: *mut u8 = 0 as *mut xmlChar;
        let mut save: u8 = 0;
        dup = xmlStrdup(name);
        if dup.is_null() {
            (unsafe { (*ctxt).valid = 0 as i32 });
            return;
        }
        cur = dup;
        while (unsafe { *cur }) as i32 != 0 as i32 {
            str = cur;
            while (unsafe { *cur }) as i32 != 0 as i32
                && !((unsafe { *cur }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *cur }) as i32
                        && (unsafe { *cur }) as i32 <= 0xa as i32
                    || (unsafe { *cur }) as i32 == 0xd as i32)
            {
                cur = unsafe { cur.offset(1) };
            }
            save = unsafe { *cur };
            (unsafe { *cur = 0 as i32 as xmlChar });
            id = xmlGetID(unsafe { (*ctxt).doc }, str);
            if id.is_null() {
                xmlErrValidNodeNr(
                    ctxt,
                    0 as xmlNodePtr,
                    XML_DTD_UNKNOWN_ID,
                    b"attribute %s line %d references an unknown ID \"%s\"\n\0" as *const u8
                        as *const i8,
                    unsafe { (*ref_0).name },
                    unsafe { (*ref_0).lineno },
                    str,
                );
                (unsafe { (*ctxt).valid = 0 as i32 });
            }
            if save as i32 == 0 as i32 {
                break;
            }
            (unsafe { *cur = save });
            while (unsafe { *cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
                || (unsafe { *cur }) as i32 == 0xd as i32
            {
                cur = unsafe { cur.offset(1) };
            }
        }
        (unsafe { xmlFree.expect("non-null function pointer")(dup as *mut libc::c_void) });
    } else if (unsafe { (*attr).atype }) as u32 == XML_ATTRIBUTE_IDREF as i32 as u32 {
        id = xmlGetID(unsafe { (*ctxt).doc }, name);
        if id.is_null() {
            xmlErrValidNode(
                ctxt,
                unsafe { (*attr).parent },
                XML_DTD_UNKNOWN_ID,
                b"IDREF attribute %s references an unknown ID \"%s\"\n\0" as *const u8 as *const i8,
                unsafe { (*attr).name },
                name,
                0 as *const xmlChar,
            );
            (unsafe { (*ctxt).valid = 0 as i32 });
        }
    } else if (unsafe { (*attr).atype }) as u32 == XML_ATTRIBUTE_IDREFS as i32 as u32 {
        let mut dup_0: *mut u8 = 0 as *mut xmlChar;
        let mut str_0: *mut u8 = 0 as *mut xmlChar;
        let mut cur_0: *mut u8 = 0 as *mut xmlChar;
        let mut save_0: u8 = 0;
        dup_0 = xmlStrdup(name);
        if dup_0.is_null() {
            xmlVErrMemory(ctxt, b"IDREFS split\0" as *const u8 as *const i8);
            (unsafe { (*ctxt).valid = 0 as i32 });
            return;
        }
        cur_0 = dup_0;
        while (unsafe { *cur_0 }) as i32 != 0 as i32 {
            str_0 = cur_0;
            while (unsafe { *cur_0 }) as i32 != 0 as i32
                && !((unsafe { *cur_0 }) as i32 == 0x20 as i32
                    || 0x9 as i32 <= (unsafe { *cur_0 }) as i32
                        && (unsafe { *cur_0 }) as i32 <= 0xa as i32
                    || (unsafe { *cur_0 }) as i32 == 0xd as i32)
            {
                cur_0 = unsafe { cur_0.offset(1) };
            }
            save_0 = unsafe { *cur_0 };
            (unsafe { *cur_0 = 0 as i32 as xmlChar });
            id = xmlGetID(unsafe { (*ctxt).doc }, str_0);
            if id.is_null() {
                xmlErrValidNode(
                    ctxt,
                    unsafe { (*attr).parent },
                    XML_DTD_UNKNOWN_ID,
                    b"IDREFS attribute %s references an unknown ID \"%s\"\n\0" as *const u8
                        as *const i8,
                    unsafe { (*attr).name },
                    str_0,
                    0 as *const xmlChar,
                );
                (unsafe { (*ctxt).valid = 0 as i32 });
            }
            if save_0 as i32 == 0 as i32 {
                break;
            }
            (unsafe { *cur_0 = save_0 });
            while (unsafe { *cur_0 }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *cur_0 }) as i32
                    && (unsafe { *cur_0 }) as i32 <= 0xa as i32
                || (unsafe { *cur_0 }) as i32 == 0xd as i32
            {
                cur_0 = unsafe { cur_0.offset(1) };
            }
        }
        (unsafe { xmlFree.expect("non-null function pointer")(dup_0 as *mut libc::c_void) });
    }
}
extern "C" fn xmlWalkValidateList(
    mut data: *const core::ffi::c_void,
    mut user: *mut core::ffi::c_void,
) -> i32 {
    let mut memo: *mut crate::src::valid::xmlValidateMemo_t = user as xmlValidateMemoPtr;
    xmlValidateRef(
        data as xmlRefPtr,
        unsafe { (*memo).ctxt },
        unsafe { (*memo).name },
    );
    return 1 as i32;
}
extern "C" fn xmlValidateCheckRefCallback(
    mut payload: *mut core::ffi::c_void,
    mut data: *mut core::ffi::c_void,
    mut name: *const u8,
) {
    let mut ref_list: *mut crate::src::xmlwriter::_xmlList = payload as xmlListPtr;
    let mut ctxt: *mut crate::src::tree::_xmlValidCtxt = data as xmlValidCtxtPtr;
    let mut memo: crate::src::valid::xmlValidateMemo_t = xmlValidateMemo {
        ctxt: 0 as *mut xmlValidCtxt,
        name: 0 as *const xmlChar,
    };
    if ref_list.is_null() {
        return;
    }
    memo.ctxt = ctxt;
    memo.name = name;
    (unsafe {
        xmlListWalk(
            ref_list,
            Some(xmlWalkValidateList),
            &mut memo as *mut xmlValidateMemo as *mut libc::c_void,
        )
    });
}
#[no_mangle]
pub extern "C" fn xmlValidateDocumentFinal(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
) -> i32 {
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlRefTable;
    let mut save: u32 = 0;
    if ctxt.is_null() {
        return 0 as i32;
    }
    if doc.is_null() {
        xmlErrValid(
            ctxt,
            XML_DTD_NO_DOC,
            b"xmlValidateDocumentFinal: doc == NULL\n\0" as *const u8 as *const i8,
            0 as *const i8,
        );
        return 0 as i32;
    }
    save = unsafe { (*ctxt).flags };
    (unsafe { (*ctxt).flags &= !((1 as u32) << 1 as i32) });
    table = (unsafe { (*doc).refs }) as xmlRefTablePtr;
    let fresh149 = unsafe { &mut ((*ctxt).doc) };
    *fresh149 = doc;
    (unsafe { (*ctxt).valid = 1 as i32 });
    (unsafe {
        xmlHashScan(
            table,
            Some(xmlValidateCheckRefCallback),
            ctxt as *mut libc::c_void,
        )
    });
    (unsafe { (*ctxt).flags = save });
    return unsafe { (*ctxt).valid };
}
#[no_mangle]
pub extern "C" fn xmlValidateDtd(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut dtd: *mut crate::src::threads::_xmlDtd,
) -> i32 {
    let mut ret: i32 = 0;
    let mut oldExt: *mut crate::src::threads::_xmlDtd = 0 as *mut xmlDtd;
    let mut oldInt: *mut crate::src::threads::_xmlDtd = 0 as *mut xmlDtd;
    let mut root: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if dtd.is_null() {
        return 0 as i32;
    }
    if doc.is_null() {
        return 0 as i32;
    }
    oldExt = unsafe { (*doc).extSubset };
    oldInt = unsafe { (*doc).intSubset };
    let fresh150 = unsafe { &mut ((*doc).extSubset) };
    *fresh150 = dtd;
    let fresh151 = unsafe { &mut ((*doc).intSubset) };
    *fresh151 = 0 as *mut _xmlDtd;
    ret = xmlValidateRoot(ctxt, doc);
    if ret == 0 as i32 {
        let fresh152 = unsafe { &mut ((*doc).extSubset) };
        *fresh152 = oldExt;
        let fresh153 = unsafe { &mut ((*doc).intSubset) };
        *fresh153 = oldInt;
        return ret;
    }
    if !(unsafe { (*doc).ids }).is_null() {
        xmlFreeIDTable((unsafe { (*doc).ids }) as xmlIDTablePtr);
        let fresh154 = unsafe { &mut ((*doc).ids) };
        *fresh154 = 0 as *mut libc::c_void;
    }
    if !(unsafe { (*doc).refs }).is_null() {
        xmlFreeRefTable((unsafe { (*doc).refs }) as xmlRefTablePtr);
        let fresh155 = unsafe { &mut ((*doc).refs) };
        *fresh155 = 0 as *mut libc::c_void;
    }
    root = xmlDocGetRootElement(doc as *const xmlDoc);
    ret = xmlValidateElement(ctxt, doc, root);
    ret &= xmlValidateDocumentFinal(ctxt, doc);
    let fresh156 = unsafe { &mut ((*doc).extSubset) };
    *fresh156 = oldExt;
    let fresh157 = unsafe { &mut ((*doc).intSubset) };
    *fresh157 = oldInt;
    return ret;
}
extern "C" fn xmlValidateNotationCallback(
    mut payload: *mut core::ffi::c_void,
    mut data: *mut core::ffi::c_void,
    mut _name: *const u8,
) {
    let mut cur: *mut crate::src::threads::_xmlEntity = payload as xmlEntityPtr;
    let mut ctxt: *mut crate::src::tree::_xmlValidCtxt = data as xmlValidCtxtPtr;
    if cur.is_null() {
        return;
    }
    if (unsafe { (*cur).etype }) as u32 == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as i32 as u32 {
        let mut notation: *mut u8 = unsafe { (*cur).content };
        if !notation.is_null() {
            let mut ret: i32 = 0;
            ret = xmlValidateNotationUse(ctxt, unsafe { (*cur).doc }, notation);
            if ret != 1 as i32 {
                (unsafe { (*ctxt).valid = 0 as i32 });
            }
        }
    }
}
extern "C" fn xmlValidateAttributeCallback(
    mut payload: *mut core::ffi::c_void,
    mut data: *mut core::ffi::c_void,
    mut _name: *const u8,
) {
    let mut cur: *mut crate::src::tree::_xmlAttribute = payload as xmlAttributePtr;
    let mut ctxt: *mut crate::src::tree::_xmlValidCtxt = data as xmlValidCtxtPtr;
    let mut ret: i32 = 0;
    let mut doc: *mut crate::src::threads::_xmlDoc = 0 as *mut xmlDoc;
    let mut elem: *mut crate::src::tree::_xmlElement = 0 as xmlElementPtr;
    if cur.is_null() {
        return;
    }
    match (unsafe { (*cur).atype }) as u32 {
        5 | 6 | 10 => {
            if !(unsafe { (*cur).defaultValue }).is_null() {
                ret = xmlValidateAttributeValue2(
                    ctxt,
                    unsafe { (*ctxt).doc },
                    unsafe { (*cur).name },
                    unsafe { (*cur).atype },
                    unsafe { (*cur).defaultValue },
                );
                if ret == 0 as i32 && (unsafe { (*ctxt).valid }) == 1 as i32 {
                    (unsafe { (*ctxt).valid = 0 as i32 });
                }
            }
            if !(unsafe { (*cur).tree }).is_null() {
                let mut tree: *mut crate::src::threads::_xmlEnumeration = unsafe { (*cur).tree };
                while !tree.is_null() {
                    ret = xmlValidateAttributeValue2(
                        ctxt,
                        unsafe { (*ctxt).doc },
                        unsafe { (*cur).name },
                        unsafe { (*cur).atype },
                        unsafe { (*tree).name },
                    );
                    if ret == 0 as i32 && (unsafe { (*ctxt).valid }) == 1 as i32 {
                        (unsafe { (*ctxt).valid = 0 as i32 });
                    }
                    tree = unsafe { (*tree).next };
                }
            }
        }
        1 | 2 | 3 | 4 | 7 | 8 | 9 | _ => {}
    }
    if (unsafe { (*cur).atype }) as u32 == XML_ATTRIBUTE_NOTATION as i32 as u32 {
        doc = unsafe { (*cur).doc };
        if (unsafe { (*cur).elem }).is_null() {
            xmlErrValid(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"xmlValidateAttributeCallback(%s): internal error\n\0" as *const u8 as *const i8,
                (unsafe { (*cur).name }) as *const i8,
            );
            return;
        }
        if !doc.is_null() {
            elem = xmlGetDtdElementDesc(unsafe { (*doc).intSubset }, unsafe { (*cur).elem });
        }
        if elem.is_null() && !doc.is_null() {
            elem = xmlGetDtdElementDesc(unsafe { (*doc).extSubset }, unsafe { (*cur).elem });
        }
        if elem.is_null()
            && !(unsafe { (*cur).parent }).is_null()
            && (unsafe { (*(*cur).parent).type_0 }) as u32 == XML_DTD_NODE as i32 as u32
        {
            elem = xmlGetDtdElementDesc(
                (unsafe { (*cur).parent }) as xmlDtdPtr,
                unsafe { (*cur).elem },
            );
        }
        if elem.is_null() {
            xmlErrValidNode(
                ctxt,
                0 as xmlNodePtr,
                XML_DTD_UNKNOWN_ELEM,
                b"attribute %s: could not find decl for element %s\n\0" as *const u8 as *const i8,
                unsafe { (*cur).name },
                unsafe { (*cur).elem },
                0 as *const xmlChar,
            );
            return;
        }
        if (unsafe { (*elem).etype }) as u32 == XML_ELEMENT_TYPE_EMPTY as i32 as u32 {
            xmlErrValidNode(
                ctxt,
                0 as xmlNodePtr,
                XML_DTD_EMPTY_NOTATION,
                b"NOTATION attribute %s declared for EMPTY element %s\n\0" as *const u8
                    as *const i8,
                unsafe { (*cur).name },
                unsafe { (*cur).elem },
                0 as *const xmlChar,
            );
            (unsafe { (*ctxt).valid = 0 as i32 });
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlValidateDtdFinal(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
) -> i32 {
    let mut dtd: *mut crate::src::threads::_xmlDtd = 0 as *mut xmlDtd;
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlAttributeTable;
    let mut entities: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlEntitiesTable;
    if doc.is_null() || ctxt.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*doc).intSubset }).is_null() && (unsafe { (*doc).extSubset }).is_null() {
        return 0 as i32;
    }
    let fresh158 = unsafe { &mut ((*ctxt).doc) };
    *fresh158 = doc;
    (unsafe { (*ctxt).valid = 1 as i32 });
    dtd = unsafe { (*doc).intSubset };
    if !dtd.is_null() && !(unsafe { (*dtd).attributes }).is_null() {
        table = (unsafe { (*dtd).attributes }) as xmlAttributeTablePtr;
        (unsafe {
            xmlHashScan(
                table,
                Some(xmlValidateAttributeCallback),
                ctxt as *mut libc::c_void,
            )
        });
    }
    if !dtd.is_null() && !(unsafe { (*dtd).entities }).is_null() {
        entities = (unsafe { (*dtd).entities }) as xmlEntitiesTablePtr;
        (unsafe {
            xmlHashScan(
                entities,
                Some(xmlValidateNotationCallback),
                ctxt as *mut libc::c_void,
            )
        });
    }
    dtd = unsafe { (*doc).extSubset };
    if !dtd.is_null() && !(unsafe { (*dtd).attributes }).is_null() {
        table = (unsafe { (*dtd).attributes }) as xmlAttributeTablePtr;
        (unsafe {
            xmlHashScan(
                table,
                Some(xmlValidateAttributeCallback),
                ctxt as *mut libc::c_void,
            )
        });
    }
    if !dtd.is_null() && !(unsafe { (*dtd).entities }).is_null() {
        entities = (unsafe { (*dtd).entities }) as xmlEntitiesTablePtr;
        (unsafe {
            xmlHashScan(
                entities,
                Some(xmlValidateNotationCallback),
                ctxt as *mut libc::c_void,
            )
        });
    }
    return unsafe { (*ctxt).valid };
}
#[no_mangle]
pub extern "C" fn xmlValidateDocument(
    mut ctxt: *mut crate::src::tree::_xmlValidCtxt,
    mut doc: *mut crate::src::threads::_xmlDoc,
) -> i32 {
    let mut ret: i32 = 0;
    let mut root: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if doc.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*doc).intSubset }).is_null() && (unsafe { (*doc).extSubset }).is_null() {
        xmlErrValid(
            ctxt,
            XML_DTD_NO_DTD,
            b"no DTD found!\n\0" as *const u8 as *const i8,
            0 as *const i8,
        );
        return 0 as i32;
    }
    if !(unsafe { (*doc).intSubset }).is_null()
        && (!(unsafe { (*(*doc).intSubset).SystemID }).is_null()
            || !(unsafe { (*(*doc).intSubset).ExternalID }).is_null())
        && (unsafe { (*doc).extSubset }).is_null()
    {
        let mut sysID: *mut u8 = 0 as *mut xmlChar;
        if !(unsafe { (*(*doc).intSubset).SystemID }).is_null() {
            sysID = xmlBuildURI(
                unsafe { (*(*doc).intSubset).SystemID },
                unsafe { (*doc).URL },
            );
            if sysID.is_null() {
                xmlErrValid(
                    ctxt,
                    XML_DTD_LOAD_ERROR,
                    b"Could not build URI for external subset \"%s\"\n\0" as *const u8 as *const i8,
                    (unsafe { (*(*doc).intSubset).SystemID }) as *const i8,
                );
                return 0 as i32;
            }
        } else {
            sysID = 0 as *mut xmlChar;
        }
        let fresh159 = unsafe { &mut ((*doc).extSubset) };
        *fresh159 =
            unsafe { xmlParseDTD((*(*doc).intSubset).ExternalID, sysID as *const xmlChar) };
        if !sysID.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(sysID as *mut libc::c_void) });
        }
        if (unsafe { (*doc).extSubset }).is_null() {
            if !(unsafe { (*(*doc).intSubset).SystemID }).is_null() {
                xmlErrValid(
                    ctxt,
                    XML_DTD_LOAD_ERROR,
                    b"Could not load the external subset \"%s\"\n\0" as *const u8 as *const i8,
                    (unsafe { (*(*doc).intSubset).SystemID }) as *const i8,
                );
            } else {
                xmlErrValid(
                    ctxt,
                    XML_DTD_LOAD_ERROR,
                    b"Could not load the external subset \"%s\"\n\0" as *const u8 as *const i8,
                    (unsafe { (*(*doc).intSubset).ExternalID }) as *const i8,
                );
            }
            return 0 as i32;
        }
    }
    if !(unsafe { (*doc).ids }).is_null() {
        xmlFreeIDTable((unsafe { (*doc).ids }) as xmlIDTablePtr);
        let fresh160 = unsafe { &mut ((*doc).ids) };
        *fresh160 = 0 as *mut libc::c_void;
    }
    if !(unsafe { (*doc).refs }).is_null() {
        xmlFreeRefTable((unsafe { (*doc).refs }) as xmlRefTablePtr);
        let fresh161 = unsafe { &mut ((*doc).refs) };
        *fresh161 = 0 as *mut libc::c_void;
    }
    ret = xmlValidateDtdFinal(ctxt, doc);
    if xmlValidateRoot(ctxt, doc) == 0 {
        return 0 as i32;
    }
    root = xmlDocGetRootElement(doc as *const xmlDoc);
    ret &= xmlValidateElement(ctxt, doc, root);
    ret &= xmlValidateDocumentFinal(ctxt, doc);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlValidGetPotentialChildren<'a1, 'a2>(
    mut ctree: *mut crate::src::threads::_xmlElementContent,
    mut names: Option<crate::__laertes_array::CustomSlice<'a1, *const u8, &'a1 mut [*const u8]>>,
    mut len: Option<&'a2 mut i32>,
    mut max: i32,
) -> i32 {
    let mut i: i32 = 0;
    if ctree.is_null() || crate::__laertes_array::borrow(&names).is_none() || borrow(&len).is_none()
    {
        return -(1 as i32);
    }
    if *(borrow(&len)).unwrap() >= max {
        return *(borrow(&len)).unwrap();
    }
    match (unsafe { (*ctree).type_0 }) as u32 {
        1 => {
            i = 0 as i32;
            while i < *(borrow(&len)).unwrap() {
                if xmlStrEqual(
                    b"#PCDATA\0" as *const u8 as *const i8 as *mut xmlChar,
                    *crate::__laertes_array::Get::<&_>::get_offset(
                        crate::__laertes_array::borrow(&names).as_ref().unwrap(),
                        i as isize,
                    ),
                ) != 0
                {
                    return *(borrow(&len)).unwrap();
                }
                i += 1;
            }
            let mut fresh162 = *(borrow_mut(&mut len)).unwrap();
            *(borrow_mut(&mut len)).unwrap() = *(borrow(&len)).unwrap() + 1;
            let fresh163 = &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                names.as_mut().unwrap(),
                fresh162 as isize,
            ));
            *fresh163 = b"#PCDATA\0" as *const u8 as *const i8 as *mut xmlChar;
        }
        2 => {
            i = 0 as i32;
            while i < *(borrow(&len)).unwrap() {
                if xmlStrEqual(
                    unsafe { (*ctree).name },
                    *crate::__laertes_array::Get::<&_>::get_offset(
                        crate::__laertes_array::borrow(&names).as_ref().unwrap(),
                        i as isize,
                    ),
                ) != 0
                {
                    return *(borrow(&len)).unwrap();
                }
                i += 1;
            }
            let mut fresh164 = *(borrow_mut(&mut len)).unwrap();
            *(borrow_mut(&mut len)).unwrap() = *(borrow(&len)).unwrap() + 1;
            let fresh165 = &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                names.as_mut().unwrap(),
                fresh164 as isize,
            ));
            *fresh165 = unsafe { (*ctree).name };
        }
        3 => {
            xmlValidGetPotentialChildren(
                unsafe { (*ctree).c1 },
                crate::__laertes_array::borrow_mut(&mut names),
                borrow_mut(&mut len),
                max,
            );
            xmlValidGetPotentialChildren(
                unsafe { (*ctree).c2 },
                crate::__laertes_array::borrow_mut(&mut names),
                borrow_mut(&mut len),
                max,
            );
        }
        4 => {
            xmlValidGetPotentialChildren(
                unsafe { (*ctree).c1 },
                crate::__laertes_array::borrow_mut(&mut names),
                borrow_mut(&mut len),
                max,
            );
            xmlValidGetPotentialChildren(
                unsafe { (*ctree).c2 },
                crate::__laertes_array::borrow_mut(&mut names),
                borrow_mut(&mut len),
                max,
            );
        }
        _ => {}
    }
    return *(borrow(&len)).unwrap();
}
unsafe extern "C" fn xmlNoValidityErr(
    mut _ctx: *mut core::ffi::c_void,
    mut _msg: *const i8,
    mut _args: ...
) {
}
#[no_mangle]
pub extern "C" fn xmlValidGetValidElements<'a1>(
    mut prev: *mut crate::src::threads::_xmlNode,
    mut next: *mut crate::src::threads::_xmlNode,
    mut names: Option<crate::__laertes_array::CustomSlice<'a1, *const u8, &'a1 mut [*const u8]>>,
    mut max: i32,
) -> i32 {
    let mut vctxt: crate::src::tree::_xmlValidCtxt = xmlValidCtxt {
        userData: 0 as *mut libc::c_void,
        error: None,
        warning: None,
        node: 0 as *mut xmlNode,
        nodeNr: 0,
        nodeMax: 0,
        nodeTab: 0 as *mut xmlNodePtr,
        flags: 0,
        doc: 0 as *mut xmlDoc,
        valid: 0,
        vstate: 0 as *mut xmlValidState,
        vstateNr: 0,
        vstateMax: 0,
        vstateTab: 0 as *mut xmlValidState,
        am: 0 as *mut xmlAutomata,
        state: 0 as *mut xmlAutomataState,
    };
    let mut nb_valid_elements: i32 = 0 as i32;
    let mut elements: Option<
        crate::__laertes_array::CustomSlice<'static, *const u8, [*const u8; 256]>,
    > = Some(crate::__laertes_array::CustomSlice::new([
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
        0 as *const xmlChar,
    ]));
    let mut nb_elements: i32 = 0 as i32;
    let mut i: i32 = 0;
    let mut name: *const u8 = 0 as *const xmlChar;
    let mut ref_node: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut parent: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut test_node: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut prev_next: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut next_prev: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut parent_childs: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut parent_last: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut element_desc: *mut crate::src::tree::_xmlElement = 0 as *mut xmlElement;
    if prev.is_null() && next.is_null() {
        return -(1 as i32);
    }
    if crate::__laertes_array::borrow(&names).is_none() {
        return -(1 as i32);
    }
    if max <= 0 as i32 {
        return -(1 as i32);
    }
    (unsafe {
        memset(
            &mut vctxt as *mut xmlValidCtxt as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlValidCtxt>() as u64,
        )
    });
    vctxt.error = Some(xmlNoValidityErr);
    nb_valid_elements = 0 as i32;
    ref_node = if !prev.is_null() { prev } else { next };
    parent = unsafe { (*ref_node).parent };
    element_desc = xmlGetDtdElementDesc(
        unsafe { (*(*parent).doc).intSubset },
        unsafe { (*parent).name },
    );
    if element_desc.is_null() && !(unsafe { (*(*parent).doc).extSubset }).is_null() {
        element_desc = xmlGetDtdElementDesc(
            unsafe { (*(*parent).doc).extSubset },
            unsafe { (*parent).name },
        );
    }
    if element_desc.is_null() {
        return -(1 as i32);
    }
    prev_next = if !prev.is_null() {
        unsafe { (*prev).next }
    } else {
        0 as *mut _xmlNode
    };
    next_prev = if !next.is_null() {
        unsafe { (*next).prev }
    } else {
        0 as *mut _xmlNode
    };
    parent_childs = unsafe { (*parent).children };
    parent_last = unsafe { (*parent).last };
    test_node = xmlNewDocNode(
        unsafe { (*ref_node).doc },
        0 as xmlNsPtr,
        b"<!dummy?>\0" as *const u8 as *const i8 as *mut xmlChar,
        0 as *const xmlChar,
    );
    if test_node.is_null() {
        return -(1 as i32);
    }
    let fresh166 = unsafe { &mut ((*test_node).parent) };
    *fresh166 = parent;
    let fresh167 = unsafe { &mut ((*test_node).prev) };
    *fresh167 = prev;
    let fresh168 = unsafe { &mut ((*test_node).next) };
    *fresh168 = next;
    name = unsafe { (*test_node).name };
    if !prev.is_null() {
        let fresh169 = unsafe { &mut ((*prev).next) };
        *fresh169 = test_node;
    } else {
        let fresh170 = unsafe { &mut ((*parent).children) };
        *fresh170 = test_node;
    }
    if !next.is_null() {
        let fresh171 = unsafe { &mut ((*next).prev) };
        *fresh171 = test_node;
    } else {
        let fresh172 = unsafe { &mut ((*parent).last) };
        *fresh172 = test_node;
    }
    nb_elements = xmlValidGetPotentialChildren(
        unsafe { (*element_desc).content },
        Some(crate::__laertes_array::SliceMut::slice_add_mut(
            elements.as_mut().unwrap(),
            0,
        )),
        Some(&mut nb_elements),
        256 as i32,
    );
    i = 0 as i32;
    while i < nb_elements {
        let fresh173 = unsafe { &mut ((*test_node).name) };
        *fresh173 = *crate::__laertes_array::Get::<&_>::get_add(
            (elements).as_ref().unwrap(),
            i as usize,
        );
        if xmlValidateOneElement(&mut vctxt, unsafe { (*parent).doc }, parent) != 0 {
            let mut j: i32 = 0;
            j = 0 as i32;
            while j < nb_valid_elements {
                if xmlStrEqual(
                    *crate::__laertes_array::Get::<&_>::get_add(
                        (elements).as_ref().unwrap(),
                        i as usize,
                    ),
                    *crate::__laertes_array::Get::<&_>::get_offset(
                        crate::__laertes_array::borrow(&names).as_ref().unwrap(),
                        j as isize,
                    ),
                ) != 0
                {
                    break;
                }
                j += 1;
            }
            let mut fresh174 = nb_valid_elements;
            nb_valid_elements = nb_valid_elements + 1;
            let fresh175 = &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                names.as_mut().unwrap(),
                fresh174 as isize,
            ));
            *fresh175 = *crate::__laertes_array::Get::<&_>::get_add(
                (elements).as_ref().unwrap(),
                i as usize,
            );
            if nb_valid_elements >= max {
                break;
            }
        }
        i += 1;
    }
    if !prev.is_null() {
        let fresh176 = unsafe { &mut ((*prev).next) };
        *fresh176 = prev_next;
    }
    if !next.is_null() {
        let fresh177 = unsafe { &mut ((*next).prev) };
        *fresh177 = next_prev;
    }
    let fresh178 = unsafe { &mut ((*parent).children) };
    *fresh178 = parent_childs;
    let fresh179 = unsafe { &mut ((*parent).last) };
    *fresh179 = parent_last;
    let fresh180 = unsafe { &mut ((*test_node).name) };
    *fresh180 = name;
    xmlFreeNode(test_node);
    return nb_valid_elements;
}
use crate::laertes_rt::*;
