use :: libc;
extern "C" {
    pub type _xmlList;
    fn vsnprintf(_: *mut i8, _: u64, _: *const i8, _: core::ffi::VaList) -> i32;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
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
    fn xmlListSearch(
        l: *mut crate::src::xmlwriter::_xmlList,
        data: *mut core::ffi::c_void,
    ) -> *mut core::ffi::c_void;
    fn xmlListEmpty(l: *mut crate::src::xmlwriter::_xmlList) -> i32;
    fn xmlListFront(l: *mut crate::src::xmlwriter::_xmlList) -> *mut crate::src::valid::_xmlLink;
    fn xmlListSize(l: *mut crate::src::xmlwriter::_xmlList) -> i32;
    fn xmlListPopFront(l: *mut crate::src::xmlwriter::_xmlList);
    fn xmlListPushFront(
        l: *mut crate::src::xmlwriter::_xmlList,
        data: *mut core::ffi::c_void,
    ) -> i32;
    fn xmlLinkGetData(lk: *mut crate::src::valid::_xmlLink) -> *mut core::ffi::c_void;
    fn xmlEncodeSpecialChars(doc: *const crate::src::threads::_xmlDoc, input: *const u8)
        -> *mut u8;
    fn xmlFindCharEncodingHandler(
        name: *const i8,
    ) -> *mut crate::src::threads::_xmlCharEncodingHandler;
    fn xmlFreeParserCtxt(ctxt: *mut crate::src::tree::_xmlParserCtxt);
    fn xmlCreatePushParserCtxt(
        sax: *mut crate::src::tree::_xmlSAXHandler,
        user_data: *mut core::ffi::c_void,
        chunk: *const i8,
        size: i32,
        filename: *const i8,
    ) -> *mut crate::src::tree::_xmlParserCtxt;
    fn xmlParseChunk(
        ctxt: *mut crate::src::tree::_xmlParserCtxt,
        chunk: *const i8,
        size: i32,
        terminate: i32,
    ) -> i32;
    fn xmlSAX2StartElement(ctx: *mut core::ffi::c_void, fullname: *const u8, atts: *mut *const u8);
    fn xmlSAX2EndElement(ctx: *mut core::ffi::c_void, name: *const u8);
    fn xmlSAX2InitDefaultSAXHandler(hdlr: *mut crate::src::tree::_xmlSAXHandler, warning: i32);
    static mut xmlMalloc: Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
    static mut xmlFree: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
    fn htmlNewDocNoDtD(URI: *const u8, ExternalID: *const u8) -> *mut crate::src::threads::_xmlDoc;
    fn xmlBufCreateSize(size: u64) -> *mut crate::src::xmlstring::_xmlBuf;
    fn xmlCharEncOutput(output: *mut crate::src::threads::_xmlOutputBuffer, init: i32) -> i32;
}
pub use crate::src::tree::xmlFreeDoc;
pub use crate::src::tree::xmlNewDoc;
pub use crate::src::tree::xmlSetDocCompressMode;
pub use crate::src::uri::xmlCanonicPath;
pub use crate::src::valid::_xmlLink;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmlIO::xmlOutputBufferClose;
pub use crate::src::xmlIO::xmlOutputBufferCreateBuffer;
pub use crate::src::xmlIO::xmlOutputBufferCreateFilename;
pub use crate::src::xmlIO::xmlOutputBufferCreateIO;
pub use crate::src::xmlIO::xmlOutputBufferFlush;
pub use crate::src::xmlIO::xmlOutputBufferWrite;
pub use crate::src::xmlIO::xmlOutputBufferWriteString;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::xmlsave::_xmlHashTable;
pub use crate::src::xmlsave::xmlBufAttrSerializeTxtContent;
pub use crate::src::xmlstring::_xmlBuf;
pub use crate::src::xmlstring::_xmlStartTag;
pub use crate::src::xmlstring::xmlStrcasecmp;
pub use crate::src::xmlstring::xmlStrcat;
pub use crate::src::xmlstring::xmlStrcmp;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrlen;
pub use crate::src::xpointer::_xmlDict;
pub type __builtin_va_list = [crate::src::xmllint::__va_list_tag; 1];
pub type __va_list_tag = crate::src::xmllint::__va_list_tag;
pub type va_list = [crate::src::xmllint::__va_list_tag; 1];
pub type xmlChar = u8;
pub type size_t = u64;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
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
pub type _xmlOutputBuffer = crate::src::threads::_xmlOutputBuffer;
pub type xmlOutputCloseCallback = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type xmlOutputWriteCallback =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, _: i32) -> i32>;
pub type xmlOutputBuffer = crate::src::threads::_xmlOutputBuffer;
pub type xmlOutputBufferPtr = *mut crate::src::threads::_xmlOutputBuffer;
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
pub type xmlEnumerationPtr = *mut crate::src::threads::_xmlEnumeration;
pub type xmlEnumeration = crate::src::threads::_xmlEnumeration;
pub type _xmlEnumeration = crate::src::threads::_xmlEnumeration;
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
pub type xmlSAXHandler = crate::src::tree::_xmlSAXHandler;
pub type xmlSAXHandlerPtr = *mut crate::src::tree::_xmlSAXHandler;
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
pub type htmlDocPtr = *mut crate::src::threads::_xmlDoc;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlTextWriter {
    pub out: *mut crate::src::threads::_xmlOutputBuffer,
    pub nodes: *mut crate::src::xmlwriter::_xmlList,
    pub nsstack: *mut crate::src::xmlwriter::_xmlList,
    pub level: i32,
    pub indent: i32,
    pub doindent: i32,
    pub ichar: *mut u8,
    pub qchar: i8,
    pub ctxt: *mut crate::src::tree::_xmlParserCtxt,
    pub no_doc_free: i32,
    pub doc: *mut crate::src::threads::_xmlDoc,
}
impl _xmlTextWriter {
    pub const fn new() -> Self {
        _xmlTextWriter {
            out: (0 as *mut crate::src::threads::_xmlOutputBuffer),
            nodes: (0 as *mut crate::src::xmlwriter::_xmlList),
            nsstack: (0 as *mut crate::src::xmlwriter::_xmlList),
            level: 0,
            indent: 0,
            doindent: 0,
            ichar: (0 as *mut u8),
            qchar: 0,
            ctxt: (0 as *mut crate::src::tree::_xmlParserCtxt),
            no_doc_free: 0,
            doc: (0 as *mut crate::src::threads::_xmlDoc),
        }
    }
}
impl std::default::Default for _xmlTextWriter {
    fn default() -> Self {
        _xmlTextWriter::new()
    }
}
pub type xmlTextWriter = crate::src::xmlwriter::_xmlTextWriter;
pub type xmlTextWriterPtr = *mut crate::src::xmlwriter::_xmlTextWriter;
pub type xmlTextWriterNsStackEntry = crate::src::xmlwriter::_xmlTextWriterNsStackEntry;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlTextWriterNsStackEntry {
    pub prefix: *mut u8,
    pub uri: *mut u8,
    pub elem: *mut crate::src::valid::_xmlLink,
}
impl _xmlTextWriterNsStackEntry {
    pub const fn new() -> Self {
        _xmlTextWriterNsStackEntry {
            prefix: (0 as *mut u8),
            uri: (0 as *mut u8),
            elem: (0 as *mut crate::src::valid::_xmlLink),
        }
    }
}
impl std::default::Default for _xmlTextWriterNsStackEntry {
    fn default() -> Self {
        _xmlTextWriterNsStackEntry::new()
    }
}
pub type xmlTextWriterStackEntry = crate::src::xmlwriter::_xmlTextWriterStackEntry;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlTextWriterStackEntry {
    pub name: *mut u8,
    pub state: u32,
}
impl _xmlTextWriterStackEntry {
    pub const fn new() -> Self {
        _xmlTextWriterStackEntry {
            name: (0 as *mut u8),
            state: 0,
        }
    }
}
impl std::default::Default for _xmlTextWriterStackEntry {
    fn default() -> Self {
        _xmlTextWriterStackEntry::new()
    }
}
pub type xmlTextWriterState = u32;
pub const XML_TEXTWRITER_COMMENT: xmlTextWriterState = 16;
pub const XML_TEXTWRITER_DTD_PENT: xmlTextWriterState = 15;
pub const XML_TEXTWRITER_DTD_ENTY_TEXT: xmlTextWriterState = 14;
pub const XML_TEXTWRITER_DTD_ENTY: xmlTextWriterState = 13;
pub const XML_TEXTWRITER_DTD_ATTL_TEXT: xmlTextWriterState = 12;
pub const XML_TEXTWRITER_DTD_ATTL: xmlTextWriterState = 11;
pub const XML_TEXTWRITER_DTD_ELEM_TEXT: xmlTextWriterState = 10;
pub const XML_TEXTWRITER_DTD_ELEM: xmlTextWriterState = 9;
pub const XML_TEXTWRITER_DTD_TEXT: xmlTextWriterState = 8;
pub const XML_TEXTWRITER_DTD: xmlTextWriterState = 7;
pub const XML_TEXTWRITER_CDATA: xmlTextWriterState = 6;
pub const XML_TEXTWRITER_PI_TEXT: xmlTextWriterState = 5;
pub const XML_TEXTWRITER_PI: xmlTextWriterState = 4;
pub const XML_TEXTWRITER_TEXT: xmlTextWriterState = 3;
pub const XML_TEXTWRITER_ATTRIBUTE: xmlTextWriterState = 2;
pub const XML_TEXTWRITER_NAME: xmlTextWriterState = 1;
pub const XML_TEXTWRITER_NONE: xmlTextWriterState = 0;
extern "C" fn xmlWriterErrMsg<'a1>(
    mut ctxt: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut error: u32,
    mut msg: *const i8,
) {
    if !borrow(&ctxt).is_none() {
        (unsafe {
            __xmlRaiseError(
                None,
                None,
                0 as *mut libc::c_void,
                (*(borrow_mut(&mut ctxt)).unwrap()).ctxt as *mut libc::c_void,
                0 as *mut libc::c_void,
                XML_FROM_WRITER as i32,
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
            )
        });
    } else {
        (unsafe {
            __xmlRaiseError(
                None,
                None,
                0 as *mut libc::c_void,
                0 as *mut libc::c_void,
                0 as *mut libc::c_void,
                XML_FROM_WRITER as i32,
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
            )
        });
    };
}
extern "C" fn xmlWriterErrMsgInt<'a1>(
    mut ctxt: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut error: u32,
    mut msg: *const i8,
    mut val: i32,
) {
    if !borrow(&ctxt).is_none() {
        (unsafe {
            __xmlRaiseError(
                None,
                None,
                0 as *mut libc::c_void,
                (*(borrow_mut(&mut ctxt)).unwrap()).ctxt as *mut libc::c_void,
                0 as *mut libc::c_void,
                XML_FROM_WRITER as i32,
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
            )
        });
    } else {
        (unsafe {
            __xmlRaiseError(
                None,
                None,
                0 as *mut libc::c_void,
                0 as *mut libc::c_void,
                0 as *mut libc::c_void,
                XML_FROM_WRITER as i32,
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
            )
        });
    };
}
#[no_mangle]
pub extern "C" fn xmlNewTextWriter(
    mut out: *mut crate::src::threads::_xmlOutputBuffer,
) -> *mut crate::src::xmlwriter::_xmlTextWriter {
    let mut ret: *mut crate::src::xmlwriter::_xmlTextWriter = 0 as *mut xmlTextWriter;
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlTextWriter>() as u64)
    }) as xmlTextWriterPtr;
    if ret.is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriter : out of memory!\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlTextWriterPtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlTextWriter>() as u64,
        )
    });
    let fresh0 = unsafe { &mut ((*ret).nodes) };
    *fresh0 = unsafe {
        xmlListCreate(
            Some(xmlFreeTextWriterStackEntry),
            Some(xmlCmpTextWriterStackEntry),
        )
    };
    if (unsafe { (*ret).nodes }).is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriter : out of memory!\n\0" as *const u8 as *const i8,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
        return 0 as xmlTextWriterPtr;
    }
    let fresh1 = unsafe { &mut ((*ret).nsstack) };
    *fresh1 = unsafe {
        xmlListCreate(
            Some(xmlFreeTextWriterNsStackEntry),
            Some(xmlCmpTextWriterNsStackEntry),
        )
    };
    if (unsafe { (*ret).nsstack }).is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriter : out of memory!\n\0" as *const u8 as *const i8,
        );
        (unsafe { xmlListDelete((*ret).nodes) });
        (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
        return 0 as xmlTextWriterPtr;
    }
    let fresh2 = unsafe { &mut ((*ret).out) };
    *fresh2 = out;
    let fresh3 = unsafe { &mut ((*ret).ichar) };
    *fresh3 = xmlStrdup(b" \0" as *const u8 as *const i8 as *mut xmlChar);
    (unsafe { (*ret).qchar = '"' as i32 as i8 });
    if (unsafe { (*ret).ichar }).is_null() {
        (unsafe { xmlListDelete((*ret).nodes) });
        (unsafe { xmlListDelete((*ret).nsstack) });
        (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriter : out of memory!\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlTextWriterPtr;
    }
    let fresh4 = unsafe { &mut ((*ret).doc) };
    *fresh4 = xmlNewDoc(0 as *const xmlChar);
    (unsafe { (*ret).no_doc_free = 0 as i32 });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlNewTextWriterFilename(
    mut uri: *const i8,
    mut compression: i32,
) -> *mut crate::src::xmlwriter::_xmlTextWriter {
    let mut ret: *mut crate::src::xmlwriter::_xmlTextWriter = 0 as *mut xmlTextWriter;
    let mut out: *mut crate::src::threads::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    out = xmlOutputBufferCreateFilename(uri, 0 as xmlCharEncodingHandlerPtr, compression);
    if out.is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_IO_EIO,
            b"xmlNewTextWriterFilename : cannot open uri\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlTextWriterPtr;
    }
    ret = xmlNewTextWriter(out);
    if ret.is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriterFilename : out of memory!\n\0" as *const u8 as *const i8,
        );
        xmlOutputBufferClose(out);
        return 0 as xmlTextWriterPtr;
    }
    (unsafe { (*ret).indent = 0 as i32 });
    (unsafe { (*ret).doindent = 0 as i32 });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlNewTextWriterMemory(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut _compression: i32,
) -> *mut crate::src::xmlwriter::_xmlTextWriter {
    let mut ret: *mut crate::src::xmlwriter::_xmlTextWriter = 0 as *mut xmlTextWriter;
    let mut out: *mut crate::src::threads::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    out = xmlOutputBufferCreateBuffer(buf, 0 as xmlCharEncodingHandlerPtr);
    if out.is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriterMemory : out of memory!\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlTextWriterPtr;
    }
    ret = xmlNewTextWriter(out);
    if ret.is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriterMemory : out of memory!\n\0" as *const u8 as *const i8,
        );
        xmlOutputBufferClose(out);
        return 0 as xmlTextWriterPtr;
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlNewTextWriterPushParser(
    mut ctxt: *mut crate::src::tree::_xmlParserCtxt,
    mut _compression: i32,
) -> *mut crate::src::xmlwriter::_xmlTextWriter {
    let mut ret: *mut crate::src::xmlwriter::_xmlTextWriter = 0 as *mut xmlTextWriter;
    let mut out: *mut crate::src::threads::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    if ctxt.is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterPushParser : invalid context!\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlTextWriterPtr;
    }
    out = xmlOutputBufferCreateIO(
        Some(xmlTextWriterWriteDocCallback),
        Some(xmlTextWriterCloseDocCallback),
        ctxt as *mut libc::c_void,
        0 as xmlCharEncodingHandlerPtr,
    );
    if out.is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterPushParser : error at xmlOutputBufferCreateIO!\n\0" as *const u8
                as *const i8,
        );
        return 0 as xmlTextWriterPtr;
    }
    ret = xmlNewTextWriter(out);
    if ret.is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterPushParser : error at xmlNewTextWriter!\n\0" as *const u8
                as *const i8,
        );
        xmlOutputBufferClose(out);
        return 0 as xmlTextWriterPtr;
    }
    let fresh5 = unsafe { &mut ((*ret).ctxt) };
    *fresh5 = ctxt;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlNewTextWriterDoc<'a1>(
    mut doc: Option<&'a1 mut *mut crate::src::threads::_xmlDoc>,
    mut compression: i32,
) -> *mut crate::src::xmlwriter::_xmlTextWriter {
    let mut ret: *mut crate::src::xmlwriter::_xmlTextWriter = 0 as *mut xmlTextWriter;
    let mut saxHandler: crate::src::tree::_xmlSAXHandler = xmlSAXHandler {
        internalSubset: None,
        isStandalone: None,
        hasInternalSubset: None,
        hasExternalSubset: None,
        resolveEntity: None,
        getEntity: None,
        entityDecl: None,
        notationDecl: None,
        attributeDecl: None,
        elementDecl: None,
        unparsedEntityDecl: None,
        setDocumentLocator: None,
        startDocument: None,
        endDocument: None,
        startElement: None,
        endElement: None,
        reference: None,
        characters: None,
        ignorableWhitespace: None,
        processingInstruction: None,
        comment: None,
        warning: None,
        error: None,
        fatalError: None,
        getParameterEntity: None,
        cdataBlock: None,
        externalSubset: None,
        initialized: 0,
        _private: 0 as *mut libc::c_void,
        startElementNs: None,
        endElementNs: None,
        serror: None,
    };
    let mut ctxt: *mut crate::src::tree::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    (unsafe {
        memset(
            &mut saxHandler as *mut xmlSAXHandler as *mut libc::c_void,
            '\u{0}' as i32,
            ::std::mem::size_of::<xmlSAXHandler>() as u64,
        )
    });
    (unsafe { xmlSAX2InitDefaultSAXHandler(&mut saxHandler, 1 as i32) });
    saxHandler.startDocument = Some(xmlTextWriterStartDocumentCallback);
    saxHandler.startElement = Some(xmlSAX2StartElement);
    saxHandler.endElement = Some(xmlSAX2EndElement);
    ctxt = unsafe {
        xmlCreatePushParserCtxt(
            &mut saxHandler,
            0 as *mut libc::c_void,
            0 as *const i8,
            0 as i32,
            0 as *const i8,
        )
    };
    if ctxt.is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterDoc : error at xmlCreatePushParserCtxt!\n\0" as *const u8
                as *const i8,
        );
        return 0 as xmlTextWriterPtr;
    }
    (unsafe { (*ctxt).dictNames = 0 as i32 });
    let fresh6 = unsafe { &mut ((*ctxt).myDoc) };
    *fresh6 = xmlNewDoc(b"1.0\0" as *const u8 as *const i8 as *mut xmlChar);
    if (unsafe { (*ctxt).myDoc }).is_null() {
        (unsafe { xmlFreeParserCtxt(ctxt) });
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterDoc : error at xmlNewDoc!\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlTextWriterPtr;
    }
    ret = xmlNewTextWriterPushParser(ctxt, compression);
    if ret.is_null() {
        xmlFreeDoc(unsafe { (*ctxt).myDoc });
        (unsafe { xmlFreeParserCtxt(ctxt) });
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterDoc : error at xmlNewTextWriterPushParser!\n\0" as *const u8
                as *const i8,
        );
        return 0 as xmlTextWriterPtr;
    }
    xmlSetDocCompressMode(unsafe { (*ctxt).myDoc }, compression);
    if !borrow(&doc).is_none() {
        *(borrow_mut(&mut doc)).unwrap() = unsafe { (*ctxt).myDoc };
        (unsafe { (*ret).no_doc_free = 1 as i32 });
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlNewTextWriterTree(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut node: *mut crate::src::threads::_xmlNode,
    mut compression: i32,
) -> *mut crate::src::xmlwriter::_xmlTextWriter {
    let mut ret: *mut crate::src::xmlwriter::_xmlTextWriter = 0 as *mut xmlTextWriter;
    let mut saxHandler: crate::src::tree::_xmlSAXHandler = xmlSAXHandler {
        internalSubset: None,
        isStandalone: None,
        hasInternalSubset: None,
        hasExternalSubset: None,
        resolveEntity: None,
        getEntity: None,
        entityDecl: None,
        notationDecl: None,
        attributeDecl: None,
        elementDecl: None,
        unparsedEntityDecl: None,
        setDocumentLocator: None,
        startDocument: None,
        endDocument: None,
        startElement: None,
        endElement: None,
        reference: None,
        characters: None,
        ignorableWhitespace: None,
        processingInstruction: None,
        comment: None,
        warning: None,
        error: None,
        fatalError: None,
        getParameterEntity: None,
        cdataBlock: None,
        externalSubset: None,
        initialized: 0,
        _private: 0 as *mut libc::c_void,
        startElementNs: None,
        endElementNs: None,
        serror: None,
    };
    let mut ctxt: *mut crate::src::tree::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
    if doc.is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterTree : invalid document tree!\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlTextWriterPtr;
    }
    (unsafe {
        memset(
            &mut saxHandler as *mut xmlSAXHandler as *mut libc::c_void,
            '\u{0}' as i32,
            ::std::mem::size_of::<xmlSAXHandler>() as u64,
        )
    });
    (unsafe { xmlSAX2InitDefaultSAXHandler(&mut saxHandler, 1 as i32) });
    saxHandler.startDocument = Some(xmlTextWriterStartDocumentCallback);
    saxHandler.startElement = Some(xmlSAX2StartElement);
    saxHandler.endElement = Some(xmlSAX2EndElement);
    ctxt = unsafe {
        xmlCreatePushParserCtxt(
            &mut saxHandler,
            0 as *mut libc::c_void,
            0 as *const i8,
            0 as i32,
            0 as *const i8,
        )
    };
    if ctxt.is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterDoc : error at xmlCreatePushParserCtxt!\n\0" as *const u8
                as *const i8,
        );
        return 0 as xmlTextWriterPtr;
    }
    (unsafe { (*ctxt).dictNames = 0 as i32 });
    ret = xmlNewTextWriterPushParser(ctxt, compression);
    if ret.is_null() {
        (unsafe { xmlFreeParserCtxt(ctxt) });
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterDoc : error at xmlNewTextWriterPushParser!\n\0" as *const u8
                as *const i8,
        );
        return 0 as xmlTextWriterPtr;
    }
    let fresh7 = unsafe { &mut ((*ctxt).myDoc) };
    *fresh7 = doc;
    let fresh8 = unsafe { &mut ((*ctxt).node) };
    *fresh8 = node;
    (unsafe { (*ret).no_doc_free = 1 as i32 });
    xmlSetDocCompressMode(doc, compression);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlFreeTextWriter(mut writer: *mut crate::src::xmlwriter::_xmlTextWriter) {
    if writer.is_null() {
        return;
    }
    if !(unsafe { (*writer).out }).is_null() {
        xmlOutputBufferClose(unsafe { (*writer).out });
    }
    if !(unsafe { (*writer).nodes }).is_null() {
        (unsafe { xmlListDelete((*writer).nodes) });
    }
    if !(unsafe { (*writer).nsstack }).is_null() {
        (unsafe { xmlListDelete((*writer).nsstack) });
    }
    if !(unsafe { (*writer).ctxt }).is_null() {
        if !(unsafe { (*(*writer).ctxt).myDoc }).is_null()
            && (unsafe { (*writer).no_doc_free }) == 0 as i32
        {
            xmlFreeDoc(unsafe { (*(*writer).ctxt).myDoc });
            let fresh9 = unsafe { &mut ((*(*writer).ctxt).myDoc) };
            *fresh9 = 0 as xmlDocPtr;
        }
        (unsafe { xmlFreeParserCtxt((*writer).ctxt) });
    }
    if !(unsafe { (*writer).doc }).is_null() {
        xmlFreeDoc(unsafe { (*writer).doc });
    }
    if !(unsafe { (*writer).ichar }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*writer).ichar as *mut libc::c_void)
        });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(writer as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlTextWriterStartDocument<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut version: *const i8,
    mut encoding: *const i8,
    mut standalone: *const i8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut encoder: *mut crate::src::threads::_xmlCharEncodingHandler =
        0 as *mut xmlCharEncodingHandler;
    if borrow(&writer).is_none() || ((*(borrow_mut(&mut writer)).unwrap()).out).is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterStartDocument : invalid writer!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if !lk.is_null() && !(unsafe { xmlLinkGetData(lk) }).is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterStartDocument : not allowed in this context!\n\0" as *const u8
                as *const i8,
        );
        return -(1 as i32);
    }
    encoder = 0 as xmlCharEncodingHandlerPtr;
    if !encoding.is_null() {
        encoder = unsafe { xmlFindCharEncodingHandler(encoding) };
        if encoder.is_null() {
            xmlWriterErrMsg(
                borrow_mut(&mut writer),
                XML_ERR_UNSUPPORTED_ENCODING,
                b"xmlTextWriterStartDocument : unsupported encoding\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
    }
    let fresh10 = unsafe { &mut ((*(*(borrow_mut(&mut writer)).unwrap()).out).encoder) };
    *fresh10 = encoder;
    if !encoder.is_null() {
        if (unsafe { (*(*(borrow_mut(&mut writer)).unwrap()).out).conv }).is_null() {
            let fresh11 = unsafe { &mut ((*(*(borrow_mut(&mut writer)).unwrap()).out).conv) };
            *fresh11 = unsafe { xmlBufCreateSize(4000 as i32 as size_t) };
        }
        (unsafe { xmlCharEncOutput((*(borrow_mut(&mut writer)).unwrap()).out, 1 as i32) });
        if !((*(borrow_mut(&mut writer)).unwrap()).doc).is_null()
            && (unsafe { (*(*(borrow_mut(&mut writer)).unwrap()).doc).encoding }).is_null()
        {
            let fresh12 = unsafe { &mut ((*(*(borrow_mut(&mut writer)).unwrap()).doc).encoding) };
            *fresh12 = xmlStrdup(
                (unsafe { (*(*(*(borrow(&writer)).unwrap()).out).encoder).name }) as *mut xmlChar,
            );
        }
    } else {
        let fresh13 = unsafe { &mut ((*(*(borrow_mut(&mut writer)).unwrap()).out).conv) };
        *fresh13 = 0 as xmlBufPtr;
    }
    sum = 0 as i32;
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b"<?xml version=\0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlOutputBufferWrite(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        1 as i32,
        &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    if !version.is_null() {
        count = xmlOutputBufferWriteString((*(borrow_mut(&mut writer)).unwrap()).out, version);
    } else {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b"1.0\0" as *const u8 as *const i8,
        );
    }
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlOutputBufferWrite(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        1 as i32,
        &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    if !(unsafe { (*(*(borrow_mut(&mut writer)).unwrap()).out).encoder }).is_null() {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b" encoding=\0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            unsafe { (*(*(*(borrow(&writer)).unwrap()).out).encoder).name },
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    if !standalone.is_null() {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b" standalone=\0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWriteString((*(borrow_mut(&mut writer)).unwrap()).out, standalone);
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b"?>\n\0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterEndDocument<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterEndDocument : invalid writer!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    sum = 0 as i32;
    loop {
        lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
        if lk.is_null() {
            break;
        }
        p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
        if p.is_null() {
            break;
        }
        match (unsafe { (*p).state }) as u32 {
            1 | 2 | 3 => {
                count = xmlTextWriterEndElement(borrow_mut(&mut writer));
                if count < 0 as i32 {
                    return -(1 as i32);
                }
                sum += count;
            }
            4 | 5 => {
                count = xmlTextWriterEndPI(borrow_mut(&mut writer));
                if count < 0 as i32 {
                    return -(1 as i32);
                }
                sum += count;
            }
            6 => {
                count = xmlTextWriterEndCDATA(borrow_mut(&mut writer));
                if count < 0 as i32 {
                    return -(1 as i32);
                }
                sum += count;
            }
            7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 => {
                count = xmlTextWriterEndDTD(borrow_mut(&mut writer));
                if count < 0 as i32 {
                    return -(1 as i32);
                }
                sum += count;
            }
            16 => {
                count = xmlTextWriterEndComment(borrow_mut(&mut writer));
                if count < 0 as i32 {
                    return -(1 as i32);
                }
                sum += count;
            }
            _ => {}
        }
    }
    if (*(borrow(&writer)).unwrap()).indent == 0 {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b"\n\0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    sum += xmlTextWriterFlush(borrow_mut(&mut writer));
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterStartComment<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterStartComment : invalid writer!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if !lk.is_null() {
        p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            match (unsafe { (*p).state }) as u32 {
                3 | 0 => {}
                1 => {
                    count = xmlTextWriterOutputNSDecl(borrow_mut(&mut writer));
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                    count = xmlOutputBufferWriteString(
                        (*(borrow_mut(&mut writer)).unwrap()).out,
                        b">\0" as *const u8 as *const i8,
                    );
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                    if (*(borrow(&writer)).unwrap()).indent != 0 {
                        count = xmlOutputBufferWriteString(
                            (*(borrow_mut(&mut writer)).unwrap()).out,
                            b"\n\0" as *const u8 as *const i8,
                        );
                        if count < 0 as i32 {
                            return -(1 as i32);
                        }
                        sum += count;
                    }
                    (unsafe { (*p).state = XML_TEXTWRITER_TEXT });
                }
                _ => return -(1 as i32),
            }
        }
    }
    p = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlTextWriterStackEntry>() as u64,
        )
    }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartElement : out of memory!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    let fresh14 = unsafe { &mut ((*p).name) };
    *fresh14 = 0 as *mut xmlChar;
    (unsafe { (*p).state = XML_TEXTWRITER_COMMENT });
    (unsafe {
        xmlListPushFront(
            (*(borrow_mut(&mut writer)).unwrap()).nodes,
            p as *mut libc::c_void,
        )
    });
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        count = xmlTextWriterWriteIndent(borrow_mut(&mut writer));
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b"<!--\0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterEndComment<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterEndComment : invalid writer!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterEndComment : not allowed in this context!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    match (unsafe { (*p).state }) as u32 {
        16 => {
            count = xmlOutputBufferWriteString(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                b"-->\0" as *const u8 as *const i8,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
        _ => return -(1 as i32),
    }
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b"\n\0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    (unsafe { xmlListPopFront((*(borrow_mut(&mut writer)).unwrap()).nodes) });
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatComment<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut rc: i32 = 0;
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatComment(borrow_mut(&mut writer), format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteVFormatComment<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> i32 {
    let mut rc: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterWriteVFormatComment : invalid writer!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as i32);
    }
    rc = xmlTextWriterWriteComment(borrow_mut(&mut writer), buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteComment<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut content: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    sum = 0 as i32;
    count = xmlTextWriterStartComment(borrow_mut(&mut writer));
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterWriteString(borrow_mut(&mut writer), content);
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterEndComment(borrow_mut(&mut writer));
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterStartElement<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut xmlTextWriterStackEntry;
    if borrow(&writer).is_none() || name.is_null() || (unsafe { *name }) as i32 == '\u{0}' as i32 {
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if !lk.is_null() {
        p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            let mut current_block_20: u64;
            match (unsafe { (*p).state }) as u32 {
                4 | 5 => return -(1 as i32),
                2 => {
                    count = xmlTextWriterEndAttribute(borrow_mut(&mut writer));
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                    current_block_20 = 11617129861404113245;
                }
                1 => {
                    current_block_20 = 11617129861404113245;
                }
                0 | _ => {
                    current_block_20 = 17478428563724192186;
                }
            }
            match current_block_20 {
                11617129861404113245 => {
                    count = xmlTextWriterOutputNSDecl(borrow_mut(&mut writer));
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                    count = xmlOutputBufferWriteString(
                        (*(borrow_mut(&mut writer)).unwrap()).out,
                        b">\0" as *const u8 as *const i8,
                    );
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                    if (*(borrow(&writer)).unwrap()).indent != 0 {
                        count = xmlOutputBufferWriteString(
                            (*(borrow_mut(&mut writer)).unwrap()).out,
                            b"\n\0" as *const u8 as *const i8,
                        );
                    }
                    (unsafe { (*p).state = XML_TEXTWRITER_TEXT });
                }
                _ => {}
            }
        }
    }
    p = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlTextWriterStackEntry>() as u64,
        )
    }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartElement : out of memory!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    let fresh15 = unsafe { &mut ((*p).name) };
    *fresh15 = xmlStrdup(name);
    if (unsafe { (*p).name }).is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartElement : out of memory!\n\0" as *const u8 as *const i8,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(p as *mut libc::c_void) });
        return -(1 as i32);
    }
    (unsafe { (*p).state = XML_TEXTWRITER_NAME });
    (unsafe {
        xmlListPushFront(
            (*(borrow_mut(&mut writer)).unwrap()).nodes,
            p as *mut libc::c_void,
        )
    });
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        count = xmlTextWriterWriteIndent(borrow_mut(&mut writer));
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b"<\0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        (unsafe { (*p).name }) as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterStartElementNS<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut prefix: *const u8,
    mut name: *const u8,
    mut namespaceURI: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() || name.is_null() || (unsafe { *name }) as i32 == '\u{0}' as i32 {
        return -(1 as i32);
    }
    buf = 0 as *mut xmlChar;
    if !prefix.is_null() {
        buf = xmlStrdup(prefix);
        buf = xmlStrcat(buf, b":\0" as *const u8 as *const i8 as *mut xmlChar);
    }
    buf = xmlStrcat(buf, name);
    sum = 0 as i32;
    count = xmlTextWriterStartElement(borrow_mut(&mut writer), buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    if !namespaceURI.is_null() {
        let mut p: *mut crate::src::xmlwriter::_xmlTextWriterNsStackEntry = (unsafe {
            xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<
                xmlTextWriterNsStackEntry,
            >() as u64)
        })
            as *mut xmlTextWriterNsStackEntry;
        if p.is_null() {
            xmlWriterErrMsg(
                borrow_mut(&mut writer),
                XML_ERR_NO_MEMORY,
                b"xmlTextWriterStartElementNS : out of memory!\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        buf = xmlStrdup(b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar);
        if !prefix.is_null() {
            buf = xmlStrcat(buf, b":\0" as *const u8 as *const i8 as *mut xmlChar);
            buf = xmlStrcat(buf, prefix);
        }
        let fresh16 = unsafe { &mut ((*p).prefix) };
        *fresh16 = buf;
        let fresh17 = unsafe { &mut ((*p).uri) };
        *fresh17 = xmlStrdup(namespaceURI);
        if (unsafe { (*p).uri }).is_null() {
            xmlWriterErrMsg(
                borrow_mut(&mut writer),
                XML_ERR_NO_MEMORY,
                b"xmlTextWriterStartElementNS : out of memory!\n\0" as *const u8 as *const i8,
            );
            (unsafe { xmlFree.expect("non-null function pointer")(p as *mut libc::c_void) });
            return -(1 as i32);
        }
        let fresh18 = unsafe { &mut ((*p).elem) };
        *fresh18 = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
        (unsafe {
            xmlListPushFront(
                (*(borrow_mut(&mut writer)).unwrap()).nsstack,
                p as *mut libc::c_void,
            )
        });
    }
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterEndElement<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        (unsafe { xmlListDelete((*(borrow_mut(&mut writer)).unwrap()).nsstack) });
        let fresh19 = &mut ((*(borrow_mut(&mut writer)).unwrap()).nsstack);
        *fresh19 = 0 as xmlListPtr;
        return -(1 as i32);
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        (unsafe { xmlListDelete((*(borrow_mut(&mut writer)).unwrap()).nsstack) });
        let fresh20 = &mut ((*(borrow_mut(&mut writer)).unwrap()).nsstack);
        *fresh20 = 0 as xmlListPtr;
        return -(1 as i32);
    }
    sum = 0 as i32;
    let mut current_block_50: u64;
    match (unsafe { (*p).state }) as u32 {
        2 => {
            count = xmlTextWriterEndAttribute(borrow_mut(&mut writer));
            if count < 0 as i32 {
                (unsafe { xmlListDelete((*(borrow_mut(&mut writer)).unwrap()).nsstack) });
                let fresh21 = &mut ((*(borrow_mut(&mut writer)).unwrap()).nsstack);
                *fresh21 = 0 as xmlListPtr;
                return -(1 as i32);
            }
            sum += count;
            current_block_50 = 9733961473582153922;
        }
        1 => {
            current_block_50 = 9733961473582153922;
        }
        3 => {
            if (*(borrow(&writer)).unwrap()).indent != 0
                && (*(borrow(&writer)).unwrap()).doindent != 0
            {
                count = xmlTextWriterWriteIndent(borrow_mut(&mut writer));
                sum += count;
                (*(borrow_mut(&mut writer)).unwrap()).doindent = 1 as i32;
            } else {
                (*(borrow_mut(&mut writer)).unwrap()).doindent = 1 as i32;
            }
            count = xmlOutputBufferWriteString(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                b"</\0" as *const u8 as *const i8,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
            count = xmlOutputBufferWriteString(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                (unsafe { (*p).name }) as *const i8,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
            count = xmlOutputBufferWriteString(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                b">\0" as *const u8 as *const i8,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
            current_block_50 = 3160140712158701372;
        }
        _ => return -(1 as i32),
    }
    match current_block_50 {
        9733961473582153922 => {
            count = xmlTextWriterOutputNSDecl(borrow_mut(&mut writer));
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
            if (*(borrow(&writer)).unwrap()).indent != 0 {
                (*(borrow_mut(&mut writer)).unwrap()).doindent = 1 as i32;
            }
            count = xmlOutputBufferWriteString(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                b"/>\0" as *const u8 as *const i8,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
        _ => {}
    }
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b"\n\0" as *const u8 as *const i8,
        );
        sum += count;
    }
    (unsafe { xmlListPopFront((*(borrow_mut(&mut writer)).unwrap()).nodes) });
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterFullEndElement<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        return -(1 as i32);
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    let mut current_block_41: u64;
    match (unsafe { (*p).state }) as u32 {
        2 => {
            count = xmlTextWriterEndAttribute(borrow_mut(&mut writer));
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
            current_block_41 = 16476552305145445901;
        }
        1 => {
            current_block_41 = 16476552305145445901;
        }
        3 => {
            current_block_41 = 16982823512181177793;
        }
        _ => return -(1 as i32),
    }
    match current_block_41 {
        16476552305145445901 => {
            count = xmlTextWriterOutputNSDecl(borrow_mut(&mut writer));
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
            count = xmlOutputBufferWriteString(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                b">\0" as *const u8 as *const i8,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
            if (*(borrow(&writer)).unwrap()).indent != 0 {
                (*(borrow_mut(&mut writer)).unwrap()).doindent = 0 as i32;
            }
        }
        _ => {}
    }
    if (*(borrow(&writer)).unwrap()).indent != 0 && (*(borrow(&writer)).unwrap()).doindent != 0 {
        count = xmlTextWriterWriteIndent(borrow_mut(&mut writer));
        sum += count;
        (*(borrow_mut(&mut writer)).unwrap()).doindent = 1 as i32;
    } else {
        (*(borrow_mut(&mut writer)).unwrap()).doindent = 1 as i32;
    }
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b"</\0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        (unsafe { (*p).name }) as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b">\0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b"\n\0" as *const u8 as *const i8,
        );
        sum += count;
    }
    (unsafe { xmlListPopFront((*(borrow_mut(&mut writer)).unwrap()).nodes) });
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatRaw<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut rc: i32 = 0;
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatRaw(borrow_mut(&mut writer), format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteVFormatRaw<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> i32 {
    let mut rc: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as i32);
    }
    rc = xmlTextWriterWriteRaw(borrow_mut(&mut writer), buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteRawLen<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut content: *const u8,
    mut len: i32,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterWriteRawLen : invalid writer!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    if content.is_null() || len < 0 as i32 {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterWriteRawLen : invalid content!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if !lk.is_null() {
        p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
        count = xmlTextWriterHandleStateDependencies(borrow_mut(&mut writer), p);
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        (*(borrow_mut(&mut writer)).unwrap()).doindent = 0 as i32;
    }
    if !content.is_null() {
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            len,
            content as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteRaw<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut content: *const u8,
) -> i32 {
    return xmlTextWriterWriteRawLen(borrow_mut(&mut writer), content, xmlStrlen(content));
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatString<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut rc: i32 = 0;
    let mut ap: core::ffi::VaListImpl;
    if borrow(&writer).is_none() || format.is_null() {
        return -(1 as i32);
    }
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatString(borrow_mut(&mut writer), format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteVFormatString<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> i32 {
    let mut rc: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() || format.is_null() {
        return -(1 as i32);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as i32);
    }
    rc = xmlTextWriterWriteString(borrow_mut(&mut writer), buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteString<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut content: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() || content.is_null() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    buf = content as *mut xmlChar;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if !lk.is_null() {
        p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            match (unsafe { (*p).state }) as u32 {
                1 | 3 => {
                    buf = unsafe { xmlEncodeSpecialChars(0 as *const xmlDoc, content) };
                }
                2 => {
                    buf = 0 as *mut xmlChar;
                    xmlBufAttrSerializeTxtContent(
                        unsafe { (*(*(borrow_mut(&mut writer)).unwrap()).out).buffer },
                        (*(borrow_mut(&mut writer)).unwrap()).doc,
                        0 as xmlAttrPtr,
                        content,
                    );
                }
                _ => {}
            }
        }
    }
    if !buf.is_null() {
        count = xmlTextWriterWriteRaw(borrow_mut(&mut writer), buf);
        if buf != content as *mut xmlChar {
            (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
        }
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    return sum;
}
extern "C" fn xmlOutputBufferWriteBase64(
    mut out: *mut crate::src::threads::_xmlOutputBuffer,
    mut len: i32,
    mut data: *const u8,
) -> i32 {
    static mut dtable: [u8; 64] = [
        'A' as i32 as u8,
        'B' as i32 as u8,
        'C' as i32 as u8,
        'D' as i32 as u8,
        'E' as i32 as u8,
        'F' as i32 as u8,
        'G' as i32 as u8,
        'H' as i32 as u8,
        'I' as i32 as u8,
        'J' as i32 as u8,
        'K' as i32 as u8,
        'L' as i32 as u8,
        'M' as i32 as u8,
        'N' as i32 as u8,
        'O' as i32 as u8,
        'P' as i32 as u8,
        'Q' as i32 as u8,
        'R' as i32 as u8,
        'S' as i32 as u8,
        'T' as i32 as u8,
        'U' as i32 as u8,
        'V' as i32 as u8,
        'W' as i32 as u8,
        'X' as i32 as u8,
        'Y' as i32 as u8,
        'Z' as i32 as u8,
        'a' as i32 as u8,
        'b' as i32 as u8,
        'c' as i32 as u8,
        'd' as i32 as u8,
        'e' as i32 as u8,
        'f' as i32 as u8,
        'g' as i32 as u8,
        'h' as i32 as u8,
        'i' as i32 as u8,
        'j' as i32 as u8,
        'k' as i32 as u8,
        'l' as i32 as u8,
        'm' as i32 as u8,
        'n' as i32 as u8,
        'o' as i32 as u8,
        'p' as i32 as u8,
        'q' as i32 as u8,
        'r' as i32 as u8,
        's' as i32 as u8,
        't' as i32 as u8,
        'u' as i32 as u8,
        'v' as i32 as u8,
        'w' as i32 as u8,
        'x' as i32 as u8,
        'y' as i32 as u8,
        'z' as i32 as u8,
        '0' as i32 as u8,
        '1' as i32 as u8,
        '2' as i32 as u8,
        '3' as i32 as u8,
        '4' as i32 as u8,
        '5' as i32 as u8,
        '6' as i32 as u8,
        '7' as i32 as u8,
        '8' as i32 as u8,
        '9' as i32 as u8,
        '+' as i32 as u8,
        '/' as i32 as u8,
    ];
    let mut i: i32 = 0;
    let mut linelen: i32 = 0;
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    if out.is_null() || len < 0 as i32 || data.is_null() {
        return -(1 as i32);
    }
    linelen = 0 as i32;
    sum = 0 as i32;
    i = 0 as i32;
    loop {
        let mut igroup: [u8; 3] = [0; 3];
        let mut ogroup: [u8; 4] = [0; 4];
        let mut c: i32 = 0;
        let mut n: i32 = 0;
        igroup[2 as i32 as usize] = 0 as i32 as u8;
        igroup[1 as i32 as usize] = igroup[2 as i32 as usize];
        igroup[0 as i32 as usize] = igroup[1 as i32 as usize];
        n = 0 as i32;
        while n < 3 as i32 && i < len {
            c = (unsafe { *data.offset(i as isize) }) as i32;
            igroup[n as usize] = c as u8;
            n += 1;
            i += 1;
        }
        if n > 0 as i32 {
            ogroup[0 as i32 as usize] =
                unsafe { dtable[(igroup[0 as i32 as usize] as i32 >> 2 as i32) as usize] };
            ogroup[1 as i32 as usize] = unsafe {
                dtable[((igroup[0 as i32 as usize] as i32 & 3 as i32) << 4 as i32
                    | igroup[1 as i32 as usize] as i32 >> 4 as i32) as usize]
            };
            ogroup[2 as i32 as usize] = unsafe {
                dtable[((igroup[1 as i32 as usize] as i32 & 0xf as i32) << 2 as i32
                    | igroup[2 as i32 as usize] as i32 >> 6 as i32) as usize]
            };
            ogroup[3 as i32 as usize] =
                unsafe { dtable[(igroup[2 as i32 as usize] as i32 & 0x3f as i32) as usize] };
            if n < 3 as i32 {
                ogroup[3 as i32 as usize] = '=' as i32 as u8;
                if n < 2 as i32 {
                    ogroup[2 as i32 as usize] = '=' as i32 as u8;
                }
            }
            if linelen >= 72 as i32 {
                count = xmlOutputBufferWrite(out, 2 as i32, b"\r\n\0" as *const u8 as *const i8);
                if count == -(1 as i32) {
                    return -(1 as i32);
                }
                sum += count;
                linelen = 0 as i32;
            }
            count = xmlOutputBufferWrite(out, 4 as i32, ogroup.as_mut_ptr() as *const i8);
            if count == -(1 as i32) {
                return -(1 as i32);
            }
            sum += count;
            linelen += 4 as i32;
        }
        if i >= len {
            break;
        }
    }
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteBase64<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut data: *const i8,
    mut start: i32,
    mut len: i32,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() || data.is_null() || start < 0 as i32 || len < 0 as i32 {
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if !lk.is_null() {
        p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            count = xmlTextWriterHandleStateDependencies(borrow_mut(&mut writer), p);
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
    }
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        (*(borrow_mut(&mut writer)).unwrap()).doindent = 0 as i32;
    }
    count = xmlOutputBufferWriteBase64(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        len,
        unsafe { (data as *mut u8).offset(start as isize) },
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
extern "C" fn xmlOutputBufferWriteBinHex(
    mut out: *mut crate::src::threads::_xmlOutputBuffer,
    mut len: i32,
    mut data: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    static mut hex: [i8; 16] = [
        '0' as i32 as i8,
        '1' as i32 as i8,
        '2' as i32 as i8,
        '3' as i32 as i8,
        '4' as i32 as i8,
        '5' as i32 as i8,
        '6' as i32 as i8,
        '7' as i32 as i8,
        '8' as i32 as i8,
        '9' as i32 as i8,
        'A' as i32 as i8,
        'B' as i32 as i8,
        'C' as i32 as i8,
        'D' as i32 as i8,
        'E' as i32 as i8,
        'F' as i32 as i8,
    ];
    let mut i: i32 = 0;
    if out.is_null() || data.is_null() || len < 0 as i32 {
        return -(1 as i32);
    }
    sum = 0 as i32;
    i = 0 as i32;
    while i < len {
        count = xmlOutputBufferWrite(
            out,
            1 as i32,
            (unsafe {
                &*hex
                    .as_ptr()
                    .offset((*data.offset(i as isize) as i32 >> 4 as i32) as isize)
            }) as *const i8,
        );
        if count == -(1 as i32) {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            out,
            1 as i32,
            (unsafe {
                &*hex
                    .as_ptr()
                    .offset((*data.offset(i as isize) as i32 & 0xf as i32) as isize)
            }) as *const i8,
        );
        if count == -(1 as i32) {
            return -(1 as i32);
        }
        sum += count;
        i += 1;
    }
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteBinHex<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut data: *const i8,
    mut start: i32,
    mut len: i32,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() || data.is_null() || start < 0 as i32 || len < 0 as i32 {
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if !lk.is_null() {
        p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            count = xmlTextWriterHandleStateDependencies(borrow_mut(&mut writer), p);
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
    }
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        (*(borrow_mut(&mut writer)).unwrap()).doindent = 0 as i32;
    }
    count = xmlOutputBufferWriteBinHex(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        len,
        unsafe { (data as *mut u8).offset(start as isize) },
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterStartAttribute<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() || name.is_null() || (unsafe { *name }) as i32 == '\u{0}' as i32 {
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        return -(1 as i32);
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as i32);
    }
    match (unsafe { (*p).state }) as u32 {
        2 => {
            count = xmlTextWriterEndAttribute(borrow_mut(&mut writer));
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
        1 => {}
        _ => return -(1 as i32),
    }
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b" \0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count =
        xmlOutputBufferWriteString((*(borrow_mut(&mut writer)).unwrap()).out, name as *const i8);
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b"=\0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlOutputBufferWrite(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        1 as i32,
        &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    (unsafe { (*p).state = XML_TEXTWRITER_ATTRIBUTE });
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterStartAttributeNS<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut prefix: *const u8,
    mut name: *const u8,
    mut namespaceURI: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterNsStackEntry =
        0 as *mut xmlTextWriterNsStackEntry;
    if borrow(&writer).is_none() || name.is_null() || (unsafe { *name }) as i32 == '\u{0}' as i32 {
        return -(1 as i32);
    }
    if !namespaceURI.is_null() {
        let mut nsentry: crate::src::xmlwriter::_xmlTextWriterNsStackEntry =
            xmlTextWriterNsStackEntry {
                prefix: 0 as *mut xmlChar,
                uri: 0 as *mut xmlChar,
                elem: 0 as *mut xmlLink,
            };
        let mut curns: *mut crate::src::xmlwriter::_xmlTextWriterNsStackEntry =
            0 as *mut crate::src::xmlwriter::_xmlTextWriterNsStackEntry;
        buf = xmlStrdup(b"xmlns\0" as *const u8 as *const i8 as *mut xmlChar);
        if !prefix.is_null() {
            buf = xmlStrcat(buf, b":\0" as *const u8 as *const i8 as *mut xmlChar);
            buf = xmlStrcat(buf, prefix);
        }
        nsentry.prefix = buf;
        nsentry.uri = namespaceURI as *mut xmlChar;
        nsentry.elem = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
        curns = (unsafe {
            xmlListSearch(
                (*(borrow_mut(&mut writer)).unwrap()).nsstack,
                &mut nsentry as *mut xmlTextWriterNsStackEntry as *mut libc::c_void,
            )
        }) as *mut xmlTextWriterNsStackEntry;
        if !curns.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
            if xmlStrcmp(unsafe { (*curns).uri }, namespaceURI) == 0 as i32 {
                buf = 0 as *mut xmlChar;
            } else {
                return -(1 as i32);
            }
        }
        if !buf.is_null() {
            p = (unsafe {
                xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<
                    xmlTextWriterNsStackEntry,
                >() as u64)
            }) as *mut xmlTextWriterNsStackEntry;
            if p.is_null() {
                xmlWriterErrMsg(
                    borrow_mut(&mut writer),
                    XML_ERR_NO_MEMORY,
                    b"xmlTextWriterStartAttributeNS : out of memory!\n\0" as *const u8 as *const i8,
                );
                return -(1 as i32);
            }
            let fresh22 = unsafe { &mut ((*p).prefix) };
            *fresh22 = buf;
            let fresh23 = unsafe { &mut ((*p).uri) };
            *fresh23 = xmlStrdup(namespaceURI);
            if (unsafe { (*p).uri }).is_null() {
                xmlWriterErrMsg(
                    borrow_mut(&mut writer),
                    XML_ERR_NO_MEMORY,
                    b"xmlTextWriterStartAttributeNS : out of memory!\n\0" as *const u8 as *const i8,
                );
                (unsafe { xmlFree.expect("non-null function pointer")(p as *mut libc::c_void) });
                return -(1 as i32);
            }
            let fresh24 = unsafe { &mut ((*p).elem) };
            *fresh24 = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
            (unsafe {
                xmlListPushFront(
                    (*(borrow_mut(&mut writer)).unwrap()).nsstack,
                    p as *mut libc::c_void,
                )
            });
        }
    }
    buf = 0 as *mut xmlChar;
    if !prefix.is_null() {
        buf = xmlStrdup(prefix);
        buf = xmlStrcat(buf, b":\0" as *const u8 as *const i8 as *mut xmlChar);
    }
    buf = xmlStrcat(buf, name);
    sum = 0 as i32;
    count = xmlTextWriterStartAttribute(borrow_mut(&mut writer), buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterEndAttribute<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        return -(1 as i32);
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    match (unsafe { (*p).state }) as u32 {
        2 => {
            (unsafe { (*p).state = XML_TEXTWRITER_NAME });
            count = xmlOutputBufferWrite(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                1 as i32,
                &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
        _ => return -(1 as i32),
    }
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatAttribute<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut rc: i32 = 0;
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatAttribute(borrow_mut(&mut writer), name, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteVFormatAttribute<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> i32 {
    let mut rc: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as i32);
    }
    rc = xmlTextWriterWriteAttribute(borrow_mut(&mut writer), name, buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteAttribute<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut content: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    sum = 0 as i32;
    count = xmlTextWriterStartAttribute(borrow_mut(&mut writer), name);
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterWriteString(borrow_mut(&mut writer), content);
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterEndAttribute(borrow_mut(&mut writer));
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatAttributeNS<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut prefix: *const u8,
    mut name: *const u8,
    mut namespaceURI: *const u8,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut rc: i32 = 0;
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatAttributeNS(
        borrow_mut(&mut writer),
        prefix,
        name,
        namespaceURI,
        format,
        ap.as_va_list(),
    );
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteVFormatAttributeNS<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut prefix: *const u8,
    mut name: *const u8,
    mut namespaceURI: *const u8,
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> i32 {
    let mut rc: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as i32);
    }
    rc = xmlTextWriterWriteAttributeNS(borrow_mut(&mut writer), prefix, name, namespaceURI, buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteAttributeNS<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut prefix: *const u8,
    mut name: *const u8,
    mut namespaceURI: *const u8,
    mut content: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    if borrow(&writer).is_none() || name.is_null() || (unsafe { *name }) as i32 == '\u{0}' as i32 {
        return -(1 as i32);
    }
    sum = 0 as i32;
    count = xmlTextWriterStartAttributeNS(borrow_mut(&mut writer), prefix, name, namespaceURI);
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterWriteString(borrow_mut(&mut writer), content);
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterEndAttribute(borrow_mut(&mut writer));
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatElement<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut rc: i32 = 0;
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatElement(borrow_mut(&mut writer), name, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteVFormatElement<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> i32 {
    let mut rc: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as i32);
    }
    rc = xmlTextWriterWriteElement(borrow_mut(&mut writer), name, buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteElement<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut content: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    sum = 0 as i32;
    count = xmlTextWriterStartElement(borrow_mut(&mut writer), name);
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    if !content.is_null() {
        count = xmlTextWriterWriteString(borrow_mut(&mut writer), content);
        if count == -(1 as i32) {
            return -(1 as i32);
        }
        sum += count;
    }
    count = xmlTextWriterEndElement(borrow_mut(&mut writer));
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatElementNS<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut prefix: *const u8,
    mut name: *const u8,
    mut namespaceURI: *const u8,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut rc: i32 = 0;
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatElementNS(
        borrow_mut(&mut writer),
        prefix,
        name,
        namespaceURI,
        format,
        ap.as_va_list(),
    );
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteVFormatElementNS<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut prefix: *const u8,
    mut name: *const u8,
    mut namespaceURI: *const u8,
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> i32 {
    let mut rc: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as i32);
    }
    rc = xmlTextWriterWriteElementNS(borrow_mut(&mut writer), prefix, name, namespaceURI, buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteElementNS<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut prefix: *const u8,
    mut name: *const u8,
    mut namespaceURI: *const u8,
    mut content: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    if borrow(&writer).is_none() || name.is_null() || (unsafe { *name }) as i32 == '\u{0}' as i32 {
        return -(1 as i32);
    }
    sum = 0 as i32;
    count = xmlTextWriterStartElementNS(borrow_mut(&mut writer), prefix, name, namespaceURI);
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterWriteString(borrow_mut(&mut writer), content);
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterEndElement(borrow_mut(&mut writer));
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterStartPI<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut target: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut xmlTextWriterStackEntry;
    if borrow(&writer).is_none()
        || target.is_null()
        || (unsafe { *target }) as i32 == '\u{0}' as i32
    {
        return -(1 as i32);
    }
    if xmlStrcasecmp(target, b"xml\0" as *const u8 as *const i8 as *const xmlChar) == 0 as i32 {
        xmlWriterErrMsg (borrow_mut (& mut writer) , XML_ERR_INTERNAL_ERROR , b"xmlTextWriterStartPI : target name [Xx][Mm][Ll] is reserved for xml standardization!\n\0" as * const u8 as * const i8 ,) ;
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if !lk.is_null() {
        p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            let mut current_block_24: u64;
            match (unsafe { (*p).state }) as u32 {
                2 => {
                    count = xmlTextWriterEndAttribute(borrow_mut(&mut writer));
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                    current_block_24 = 51576440349808026;
                }
                1 => {
                    current_block_24 = 51576440349808026;
                }
                0 | 3 | 7 => {
                    current_block_24 = 13550086250199790493;
                }
                4 | 5 => {
                    xmlWriterErrMsg(
                        borrow_mut(&mut writer),
                        XML_ERR_INTERNAL_ERROR,
                        b"xmlTextWriterStartPI : nested PI!\n\0" as *const u8 as *const i8,
                    );
                    return -(1 as i32);
                }
                _ => return -(1 as i32),
            }
            match current_block_24 {
                51576440349808026 => {
                    count = xmlTextWriterOutputNSDecl(borrow_mut(&mut writer));
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                    count = xmlOutputBufferWriteString(
                        (*(borrow_mut(&mut writer)).unwrap()).out,
                        b">\0" as *const u8 as *const i8,
                    );
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                    (unsafe { (*p).state = XML_TEXTWRITER_TEXT });
                }
                _ => {}
            }
        }
    }
    p = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlTextWriterStackEntry>() as u64,
        )
    }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartPI : out of memory!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    let fresh25 = unsafe { &mut ((*p).name) };
    *fresh25 = xmlStrdup(target);
    if (unsafe { (*p).name }).is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartPI : out of memory!\n\0" as *const u8 as *const i8,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(p as *mut libc::c_void) });
        return -(1 as i32);
    }
    (unsafe { (*p).state = XML_TEXTWRITER_PI });
    (unsafe {
        xmlListPushFront(
            (*(borrow_mut(&mut writer)).unwrap()).nodes,
            p as *mut libc::c_void,
        )
    });
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b"<?\0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        (unsafe { (*p).name }) as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterEndPI<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        return 0 as i32;
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return 0 as i32;
    }
    sum = 0 as i32;
    match (unsafe { (*p).state }) as u32 {
        4 | 5 => {
            count = xmlOutputBufferWriteString(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                b"?>\0" as *const u8 as *const i8,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
        _ => return -(1 as i32),
    }
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b"\n\0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    (unsafe { xmlListPopFront((*(borrow_mut(&mut writer)).unwrap()).nodes) });
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatPI<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut target: *const u8,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut rc: i32 = 0;
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatPI(borrow_mut(&mut writer), target, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteVFormatPI<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut target: *const u8,
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> i32 {
    let mut rc: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as i32);
    }
    rc = xmlTextWriterWritePI(borrow_mut(&mut writer), target, buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWritePI<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut target: *const u8,
    mut content: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    sum = 0 as i32;
    count = xmlTextWriterStartPI(borrow_mut(&mut writer), target);
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    if !content.is_null() {
        count = xmlTextWriterWriteString(borrow_mut(&mut writer), content);
        if count == -(1 as i32) {
            return -(1 as i32);
        }
        sum += count;
    }
    count = xmlTextWriterEndPI(borrow_mut(&mut writer));
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterStartCDATA<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if !lk.is_null() {
        p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            let mut current_block_20: u64;
            match (unsafe { (*p).state }) as u32 {
                0 | 3 | 4 | 5 => {
                    current_block_20 = 13472856163611868459;
                }
                2 => {
                    count = xmlTextWriterEndAttribute(borrow_mut(&mut writer));
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                    current_block_20 = 1628216707406609217;
                }
                1 => {
                    current_block_20 = 1628216707406609217;
                }
                6 => {
                    xmlWriterErrMsg(
                        borrow_mut(&mut writer),
                        XML_ERR_INTERNAL_ERROR,
                        b"xmlTextWriterStartCDATA : CDATA not allowed in this context!\n\0"
                            as *const u8 as *const i8,
                    );
                    return -(1 as i32);
                }
                _ => return -(1 as i32),
            }
            match current_block_20 {
                1628216707406609217 => {
                    count = xmlTextWriterOutputNSDecl(borrow_mut(&mut writer));
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                    count = xmlOutputBufferWriteString(
                        (*(borrow_mut(&mut writer)).unwrap()).out,
                        b">\0" as *const u8 as *const i8,
                    );
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                    (unsafe { (*p).state = XML_TEXTWRITER_TEXT });
                }
                _ => {}
            }
        }
    }
    p = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlTextWriterStackEntry>() as u64,
        )
    }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartCDATA : out of memory!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    let fresh26 = unsafe { &mut ((*p).name) };
    *fresh26 = 0 as *mut xmlChar;
    (unsafe { (*p).state = XML_TEXTWRITER_CDATA });
    (unsafe {
        xmlListPushFront(
            (*(borrow_mut(&mut writer)).unwrap()).nodes,
            p as *mut libc::c_void,
        )
    });
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b"<![CDATA[\0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterEndCDATA<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        return -(1 as i32);
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    match (unsafe { (*p).state }) as u32 {
        6 => {
            count = xmlOutputBufferWriteString(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                b"]]>\0" as *const u8 as *const i8,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
        _ => return -(1 as i32),
    }
    (unsafe { xmlListPopFront((*(borrow_mut(&mut writer)).unwrap()).nodes) });
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatCDATA<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut rc: i32 = 0;
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatCDATA(borrow_mut(&mut writer), format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteVFormatCDATA<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> i32 {
    let mut rc: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as i32);
    }
    rc = xmlTextWriterWriteCDATA(borrow_mut(&mut writer), buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteCDATA<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut content: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    sum = 0 as i32;
    count = xmlTextWriterStartCDATA(borrow_mut(&mut writer));
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    if !content.is_null() {
        count = xmlTextWriterWriteString(borrow_mut(&mut writer), content);
        if count == -(1 as i32) {
            return -(1 as i32);
        }
        sum += count;
    }
    count = xmlTextWriterEndCDATA(borrow_mut(&mut writer));
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterStartDTD<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut pubid: *const u8,
    mut sysid: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut xmlTextWriterStackEntry;
    if borrow(&writer).is_none() || name.is_null() || (unsafe { *name }) as i32 == '\u{0}' as i32 {
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if !lk.is_null() && !(unsafe { xmlLinkGetData(lk) }).is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterStartDTD : DTD allowed only in prolog!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    p = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlTextWriterStackEntry>() as u64,
        )
    }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTD : out of memory!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    let fresh27 = unsafe { &mut ((*p).name) };
    *fresh27 = xmlStrdup(name);
    if (unsafe { (*p).name }).is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTD : out of memory!\n\0" as *const u8 as *const i8,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(p as *mut libc::c_void) });
        return -(1 as i32);
    }
    (unsafe { (*p).state = XML_TEXTWRITER_DTD });
    (unsafe {
        xmlListPushFront(
            (*(borrow_mut(&mut writer)).unwrap()).nodes,
            p as *mut libc::c_void,
        )
    });
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b"<!DOCTYPE \0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count =
        xmlOutputBufferWriteString((*(borrow_mut(&mut writer)).unwrap()).out, name as *const i8);
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    if !pubid.is_null() {
        if sysid.is_null() {
            xmlWriterErrMsg(
                borrow_mut(&mut writer),
                XML_ERR_INTERNAL_ERROR,
                b"xmlTextWriterStartDTD : system identifier needed!\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        if (*(borrow(&writer)).unwrap()).indent != 0 {
            count = xmlOutputBufferWrite(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                1 as i32,
                b"\n\0" as *const u8 as *const i8,
            );
        } else {
            count = xmlOutputBufferWrite(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                1 as i32,
                b" \0" as *const u8 as *const i8,
            );
        }
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b"PUBLIC \0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            pubid as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    if !sysid.is_null() {
        if pubid.is_null() {
            if (*(borrow(&writer)).unwrap()).indent != 0 {
                count = xmlOutputBufferWrite(
                    (*(borrow_mut(&mut writer)).unwrap()).out,
                    1 as i32,
                    b"\n\0" as *const u8 as *const i8,
                );
            } else {
                count = xmlOutputBufferWrite(
                    (*(borrow_mut(&mut writer)).unwrap()).out,
                    1 as i32,
                    b" \0" as *const u8 as *const i8,
                );
            }
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
            count = xmlOutputBufferWriteString(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                b"SYSTEM \0" as *const u8 as *const i8,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        } else {
            if (*(borrow(&writer)).unwrap()).indent != 0 {
                count = xmlOutputBufferWriteString(
                    (*(borrow_mut(&mut writer)).unwrap()).out,
                    b"\n       \0" as *const u8 as *const i8,
                );
            } else {
                count = xmlOutputBufferWrite(
                    (*(borrow_mut(&mut writer)).unwrap()).out,
                    1 as i32,
                    b" \0" as *const u8 as *const i8,
                );
            }
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            sysid as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterEndDTD<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut loop_0: i32 = 0;
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    loop_0 = 1 as i32;
    let mut current_block_25: u64;
    while loop_0 != 0 {
        lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
        if lk.is_null() {
            break;
        }
        p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
        if p.is_null() {
            break;
        }
        match (unsafe { (*p).state }) as u32 {
            8 => {
                count = xmlOutputBufferWriteString(
                    (*(borrow_mut(&mut writer)).unwrap()).out,
                    b"]\0" as *const u8 as *const i8,
                );
                if count < 0 as i32 {
                    return -(1 as i32);
                }
                sum += count;
                current_block_25 = 1862023469299908377;
            }
            7 => {
                current_block_25 = 1862023469299908377;
            }
            9 | 10 => {
                count = xmlTextWriterEndDTDElement(borrow_mut(&mut writer));
                current_block_25 = 17500079516916021833;
            }
            11 | 12 => {
                count = xmlTextWriterEndDTDAttlist(borrow_mut(&mut writer));
                current_block_25 = 17500079516916021833;
            }
            13 | 15 | 14 => {
                count = xmlTextWriterEndDTDEntity(borrow_mut(&mut writer));
                current_block_25 = 17500079516916021833;
            }
            16 => {
                count = xmlTextWriterEndComment(borrow_mut(&mut writer));
                current_block_25 = 17500079516916021833;
            }
            _ => {
                loop_0 = 0 as i32;
                continue;
            }
        }
        match current_block_25 {
            1862023469299908377 => {
                count = xmlOutputBufferWriteString(
                    (*(borrow_mut(&mut writer)).unwrap()).out,
                    b">\0" as *const u8 as *const i8,
                );
                if (*(borrow(&writer)).unwrap()).indent != 0 {
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                    count = xmlOutputBufferWriteString(
                        (*(borrow_mut(&mut writer)).unwrap()).out,
                        b"\n\0" as *const u8 as *const i8,
                    );
                }
                (unsafe { xmlListPopFront((*(borrow_mut(&mut writer)).unwrap()).nodes) });
            }
            _ => {}
        }
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatDTD<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut pubid: *const u8,
    mut sysid: *const u8,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut rc: i32 = 0;
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatDTD(
        borrow_mut(&mut writer),
        name,
        pubid,
        sysid,
        format,
        ap.as_va_list(),
    );
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteVFormatDTD<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut pubid: *const u8,
    mut sysid: *const u8,
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> i32 {
    let mut rc: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as i32);
    }
    rc = xmlTextWriterWriteDTD(borrow_mut(&mut writer), name, pubid, sysid, buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteDTD<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut pubid: *const u8,
    mut sysid: *const u8,
    mut subset: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    sum = 0 as i32;
    count = xmlTextWriterStartDTD(borrow_mut(&mut writer), name, pubid, sysid);
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    if !subset.is_null() {
        count = xmlTextWriterWriteString(borrow_mut(&mut writer), subset);
        if count == -(1 as i32) {
            return -(1 as i32);
        }
        sum += count;
    }
    count = xmlTextWriterEndDTD(borrow_mut(&mut writer));
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterStartDTDElement<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut xmlTextWriterStackEntry;
    if borrow(&writer).is_none() || name.is_null() || (unsafe { *name }) as i32 == '\u{0}' as i32 {
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        return -(1 as i32);
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if !p.is_null() {
        match (unsafe { (*p).state }) as u32 {
            7 => {
                count = xmlOutputBufferWriteString(
                    (*(borrow_mut(&mut writer)).unwrap()).out,
                    b" [\0" as *const u8 as *const i8,
                );
                if count < 0 as i32 {
                    return -(1 as i32);
                }
                sum += count;
                if (*(borrow(&writer)).unwrap()).indent != 0 {
                    count = xmlOutputBufferWriteString(
                        (*(borrow_mut(&mut writer)).unwrap()).out,
                        b"\n\0" as *const u8 as *const i8,
                    );
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                }
                (unsafe { (*p).state = XML_TEXTWRITER_DTD_TEXT });
            }
            8 | 0 => {}
            _ => return -(1 as i32),
        }
    }
    p = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlTextWriterStackEntry>() as u64,
        )
    }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTDElement : out of memory!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    let fresh28 = unsafe { &mut ((*p).name) };
    *fresh28 = xmlStrdup(name);
    if (unsafe { (*p).name }).is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTDElement : out of memory!\n\0" as *const u8 as *const i8,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(p as *mut libc::c_void) });
        return -(1 as i32);
    }
    (unsafe { (*p).state = XML_TEXTWRITER_DTD_ELEM });
    (unsafe {
        xmlListPushFront(
            (*(borrow_mut(&mut writer)).unwrap()).nodes,
            p as *mut libc::c_void,
        )
    });
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        count = xmlTextWriterWriteIndent(borrow_mut(&mut writer));
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b"<!ELEMENT \0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count =
        xmlOutputBufferWriteString((*(borrow_mut(&mut writer)).unwrap()).out, name as *const i8);
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterEndDTDElement<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        return -(1 as i32);
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as i32);
    }
    match (unsafe { (*p).state }) as u32 {
        9 | 10 => {
            count = xmlOutputBufferWriteString(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                b">\0" as *const u8 as *const i8,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
        _ => return -(1 as i32),
    }
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b"\n\0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    (unsafe { xmlListPopFront((*(borrow_mut(&mut writer)).unwrap()).nodes) });
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatDTDElement<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut rc: i32 = 0;
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    rc =
        xmlTextWriterWriteVFormatDTDElement(borrow_mut(&mut writer), name, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteVFormatDTDElement<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> i32 {
    let mut rc: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as i32);
    }
    rc = xmlTextWriterWriteDTDElement(borrow_mut(&mut writer), name, buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteDTDElement<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut content: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    if content.is_null() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    count = xmlTextWriterStartDTDElement(borrow_mut(&mut writer), name);
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterWriteString(borrow_mut(&mut writer), content);
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterEndDTDElement(borrow_mut(&mut writer));
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterStartDTDAttlist<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut xmlTextWriterStackEntry;
    if borrow(&writer).is_none() || name.is_null() || (unsafe { *name }) as i32 == '\u{0}' as i32 {
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        return -(1 as i32);
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if !p.is_null() {
        match (unsafe { (*p).state }) as u32 {
            7 => {
                count = xmlOutputBufferWriteString(
                    (*(borrow_mut(&mut writer)).unwrap()).out,
                    b" [\0" as *const u8 as *const i8,
                );
                if count < 0 as i32 {
                    return -(1 as i32);
                }
                sum += count;
                if (*(borrow(&writer)).unwrap()).indent != 0 {
                    count = xmlOutputBufferWriteString(
                        (*(borrow_mut(&mut writer)).unwrap()).out,
                        b"\n\0" as *const u8 as *const i8,
                    );
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                }
                (unsafe { (*p).state = XML_TEXTWRITER_DTD_TEXT });
            }
            8 | 0 => {}
            _ => return -(1 as i32),
        }
    }
    p = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlTextWriterStackEntry>() as u64,
        )
    }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTDAttlist : out of memory!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    let fresh29 = unsafe { &mut ((*p).name) };
    *fresh29 = xmlStrdup(name);
    if (unsafe { (*p).name }).is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTDAttlist : out of memory!\n\0" as *const u8 as *const i8,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(p as *mut libc::c_void) });
        return -(1 as i32);
    }
    (unsafe { (*p).state = XML_TEXTWRITER_DTD_ATTL });
    (unsafe {
        xmlListPushFront(
            (*(borrow_mut(&mut writer)).unwrap()).nodes,
            p as *mut libc::c_void,
        )
    });
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        count = xmlTextWriterWriteIndent(borrow_mut(&mut writer));
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b"<!ATTLIST \0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count =
        xmlOutputBufferWriteString((*(borrow_mut(&mut writer)).unwrap()).out, name as *const i8);
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterEndDTDAttlist<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        return -(1 as i32);
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as i32);
    }
    match (unsafe { (*p).state }) as u32 {
        11 | 12 => {
            count = xmlOutputBufferWriteString(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                b">\0" as *const u8 as *const i8,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
        _ => return -(1 as i32),
    }
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b"\n\0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    (unsafe { xmlListPopFront((*(borrow_mut(&mut writer)).unwrap()).nodes) });
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatDTDAttlist<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut rc: i32 = 0;
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    rc =
        xmlTextWriterWriteVFormatDTDAttlist(borrow_mut(&mut writer), name, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteVFormatDTDAttlist<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> i32 {
    let mut rc: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as i32);
    }
    rc = xmlTextWriterWriteDTDAttlist(borrow_mut(&mut writer), name, buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteDTDAttlist<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut content: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    if content.is_null() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    count = xmlTextWriterStartDTDAttlist(borrow_mut(&mut writer), name);
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterWriteString(borrow_mut(&mut writer), content);
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterEndDTDAttlist(borrow_mut(&mut writer));
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterStartDTDEntity<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut pe: i32,
    mut name: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut xmlTextWriterStackEntry;
    if borrow(&writer).is_none() || name.is_null() || (unsafe { *name }) as i32 == '\u{0}' as i32 {
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if !lk.is_null() {
        p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            match (unsafe { (*p).state }) as u32 {
                7 => {
                    count = xmlOutputBufferWriteString(
                        (*(borrow_mut(&mut writer)).unwrap()).out,
                        b" [\0" as *const u8 as *const i8,
                    );
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                    if (*(borrow(&writer)).unwrap()).indent != 0 {
                        count = xmlOutputBufferWriteString(
                            (*(borrow_mut(&mut writer)).unwrap()).out,
                            b"\n\0" as *const u8 as *const i8,
                        );
                        if count < 0 as i32 {
                            return -(1 as i32);
                        }
                        sum += count;
                    }
                    (unsafe { (*p).state = XML_TEXTWRITER_DTD_TEXT });
                }
                8 | 0 => {}
                _ => return -(1 as i32),
            }
        }
    }
    p = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlTextWriterStackEntry>() as u64,
        )
    }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTDElement : out of memory!\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    let fresh30 = unsafe { &mut ((*p).name) };
    *fresh30 = xmlStrdup(name);
    if (unsafe { (*p).name }).is_null() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTDElement : out of memory!\n\0" as *const u8 as *const i8,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(p as *mut libc::c_void) });
        return -(1 as i32);
    }
    if pe != 0 as i32 {
        (unsafe { (*p).state = XML_TEXTWRITER_DTD_PENT });
    } else {
        (unsafe { (*p).state = XML_TEXTWRITER_DTD_ENTY });
    }
    (unsafe {
        xmlListPushFront(
            (*(borrow_mut(&mut writer)).unwrap()).nodes,
            p as *mut libc::c_void,
        )
    });
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        count = xmlTextWriterWriteIndent(borrow_mut(&mut writer));
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b"<!ENTITY \0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    if pe != 0 as i32 {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b"% \0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    count =
        xmlOutputBufferWriteString((*(borrow_mut(&mut writer)).unwrap()).out, name as *const i8);
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterEndDTDEntity<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        return -(1 as i32);
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as i32);
    }
    match (unsafe { (*p).state }) as u32 {
        14 => {
            count = xmlOutputBufferWrite(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                1 as i32,
                &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
        13 | 15 => {}
        _ => return -(1 as i32),
    }
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b">\0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b"\n\0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    (unsafe { xmlListPopFront((*(borrow_mut(&mut writer)).unwrap()).nodes) });
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatDTDInternalEntity<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut pe: i32,
    mut name: *const u8,
    mut format: *const i8,
    mut args: ...
) -> i32 {
    let mut rc: i32 = 0;
    let mut ap: core::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatDTDInternalEntity(
        borrow_mut(&mut writer),
        pe,
        name,
        format,
        ap.as_va_list(),
    );
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteVFormatDTDInternalEntity<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut pe: i32,
    mut name: *const u8,
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> i32 {
    let mut rc: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as i32);
    }
    rc = xmlTextWriterWriteDTDInternalEntity(borrow_mut(&mut writer), pe, name, buf);
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return rc;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteDTDEntity<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut pe: i32,
    mut name: *const u8,
    mut pubid: *const u8,
    mut sysid: *const u8,
    mut ndataid: *const u8,
    mut content: *const u8,
) -> i32 {
    if content.is_null() && pubid.is_null() && sysid.is_null() {
        return -(1 as i32);
    }
    if pe != 0 as i32 && !ndataid.is_null() {
        return -(1 as i32);
    }
    if pubid.is_null() && sysid.is_null() {
        return xmlTextWriterWriteDTDInternalEntity(borrow_mut(&mut writer), pe, name, content);
    }
    return xmlTextWriterWriteDTDExternalEntity(
        borrow_mut(&mut writer),
        pe,
        name,
        pubid,
        sysid,
        ndataid,
    );
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteDTDInternalEntity<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut pe: i32,
    mut name: *const u8,
    mut content: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    if name.is_null() || (unsafe { *name }) as i32 == '\u{0}' as i32 || content.is_null() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    count = xmlTextWriterStartDTDEntity(borrow_mut(&mut writer), pe, name);
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterWriteString(borrow_mut(&mut writer), content);
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterEndDTDEntity(borrow_mut(&mut writer));
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteDTDExternalEntity<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut pe: i32,
    mut name: *const u8,
    mut pubid: *const u8,
    mut sysid: *const u8,
    mut ndataid: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    if pubid.is_null() && sysid.is_null() {
        return -(1 as i32);
    }
    if pe != 0 as i32 && !ndataid.is_null() {
        return -(1 as i32);
    }
    sum = 0 as i32;
    count = xmlTextWriterStartDTDEntity(borrow_mut(&mut writer), pe, name);
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    count =
        xmlTextWriterWriteDTDExternalEntityContents(borrow_mut(&mut writer), pubid, sysid, ndataid);
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count = xmlTextWriterEndDTDEntity(borrow_mut(&mut writer));
    if count == -(1 as i32) {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteDTDExternalEntityContents<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut pubid: *const u8,
    mut sysid: *const u8,
    mut ndataid: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() {
        xmlWriterErrMsg(
            borrow_mut(&mut writer),
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterWriteDTDExternalEntityContents: xmlTextWriterPtr invalid!\n\0"
                as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        xmlWriterErrMsg (borrow_mut (& mut writer) , XML_ERR_INTERNAL_ERROR , b"xmlTextWriterWriteDTDExternalEntityContents: you must call xmlTextWriterStartDTDEntity before the call to this function!\n\0" as * const u8 as * const i8 ,) ;
        return -(1 as i32);
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as i32);
    }
    match (unsafe { (*p).state }) as u32 {
        13 => {}
        15 => {
            if !ndataid.is_null() {
                xmlWriterErrMsg (borrow_mut (& mut writer) , XML_ERR_INTERNAL_ERROR , b"xmlTextWriterWriteDTDExternalEntityContents: notation not allowed with parameter entities!\n\0" as * const u8 as * const i8 ,) ;
                return -(1 as i32);
            }
        }
        _ => {
            xmlWriterErrMsg (borrow_mut (& mut writer) , XML_ERR_INTERNAL_ERROR , b"xmlTextWriterWriteDTDExternalEntityContents: you must call xmlTextWriterStartDTDEntity before the call to this function!\n\0" as * const u8 as * const i8 ,) ;
            return -(1 as i32);
        }
    }
    if !pubid.is_null() {
        if sysid.is_null() {
            xmlWriterErrMsg(
                borrow_mut(&mut writer),
                XML_ERR_INTERNAL_ERROR,
                b"xmlTextWriterWriteDTDExternalEntityContents: system identifier needed!\n\0"
                    as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b" PUBLIC \0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            pubid as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    if !sysid.is_null() {
        if pubid.is_null() {
            count = xmlOutputBufferWriteString(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                b" SYSTEM\0" as *const u8 as *const i8,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b" \0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            sysid as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    if !ndataid.is_null() {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b" NDATA \0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            ndataid as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterWriteDTDNotation<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut name: *const u8,
    mut pubid: *const u8,
    mut sysid: *const u8,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if borrow(&writer).is_none() || name.is_null() || (unsafe { *name }) as i32 == '\u{0}' as i32 {
        return -(1 as i32);
    }
    sum = 0 as i32;
    lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lk.is_null() {
        return -(1 as i32);
    }
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if !p.is_null() {
        match (unsafe { (*p).state }) as u32 {
            7 => {
                count = xmlOutputBufferWriteString(
                    (*(borrow_mut(&mut writer)).unwrap()).out,
                    b" [\0" as *const u8 as *const i8,
                );
                if count < 0 as i32 {
                    return -(1 as i32);
                }
                sum += count;
                if (*(borrow(&writer)).unwrap()).indent != 0 {
                    count = xmlOutputBufferWriteString(
                        (*(borrow_mut(&mut writer)).unwrap()).out,
                        b"\n\0" as *const u8 as *const i8,
                    );
                    if count < 0 as i32 {
                        return -(1 as i32);
                    }
                    sum += count;
                }
                (unsafe { (*p).state = XML_TEXTWRITER_DTD_TEXT });
            }
            8 => {}
            _ => return -(1 as i32),
        }
    }
    if (*(borrow(&writer)).unwrap()).indent != 0 {
        count = xmlTextWriterWriteIndent(borrow_mut(&mut writer));
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b"<!NOTATION \0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    count =
        xmlOutputBufferWriteString((*(borrow_mut(&mut writer)).unwrap()).out, name as *const i8);
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    if !pubid.is_null() {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b" PUBLIC \0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            pubid as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    if !sysid.is_null() {
        if pubid.is_null() {
            count = xmlOutputBufferWriteString(
                (*(borrow_mut(&mut writer)).unwrap()).out,
                b" SYSTEM\0" as *const u8 as *const i8,
            );
            if count < 0 as i32 {
                return -(1 as i32);
            }
            sum += count;
        }
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            b" \0" as *const u8 as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            sysid as *const i8,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            1 as i32,
            &mut (*(borrow_mut(&mut writer)).unwrap()).qchar,
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*(borrow_mut(&mut writer)).unwrap()).out,
        b">\0" as *const u8 as *const i8,
    );
    if count < 0 as i32 {
        return -(1 as i32);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterFlush<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut count: i32 = 0;
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    if ((*(borrow_mut(&mut writer)).unwrap()).out).is_null() {
        count = 0 as i32;
    } else {
        count = xmlOutputBufferFlush((*(borrow_mut(&mut writer)).unwrap()).out);
    }
    return count;
}
extern "C" fn xmlFreeTextWriterStackEntry(mut lk: *mut crate::src::valid::_xmlLink) {
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut xmlTextWriterStackEntry;
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return;
    }
    if !(unsafe { (*p).name }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*p).name as *mut libc::c_void) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(p as *mut libc::c_void) });
}
extern "C" fn xmlCmpTextWriterStackEntry(
    mut data0: *const core::ffi::c_void,
    mut data1: *const core::ffi::c_void,
) -> i32 {
    let mut p0: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    let mut p1: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterStackEntry;
    if data0 == data1 {
        return 0 as i32;
    }
    if data0.is_null() {
        return -(1 as i32);
    }
    if data1.is_null() {
        return 1 as i32;
    }
    p0 = data0 as *mut xmlTextWriterStackEntry;
    p1 = data1 as *mut xmlTextWriterStackEntry;
    return xmlStrcmp(unsafe { (*p0).name }, unsafe { (*p1).name });
}
extern "C" fn xmlTextWriterOutputNSDecl<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut lk: *mut crate::src::valid::_xmlLink = 0 as *mut xmlLink;
    let mut np: *mut crate::src::xmlwriter::_xmlTextWriterNsStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterNsStackEntry;
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    sum = 0 as i32;
    while (unsafe { xmlListEmpty((*(borrow_mut(&mut writer)).unwrap()).nsstack) }) == 0 {
        let mut namespaceURI: *mut u8 = 0 as *mut xmlChar;
        let mut prefix: *mut u8 = 0 as *mut xmlChar;
        lk = unsafe { xmlListFront((*(borrow_mut(&mut writer)).unwrap()).nsstack) };
        np = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterNsStackEntry;
        if !np.is_null() {
            namespaceURI = xmlStrdup(unsafe { (*np).uri });
            prefix = xmlStrdup(unsafe { (*np).prefix });
        }
        (unsafe { xmlListPopFront((*(borrow_mut(&mut writer)).unwrap()).nsstack) });
        if !np.is_null() {
            count = xmlTextWriterWriteAttribute(borrow_mut(&mut writer), prefix, namespaceURI);
            (unsafe {
                xmlFree.expect("non-null function pointer")(namespaceURI as *mut libc::c_void)
            });
            (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
            if count < 0 as i32 {
                (unsafe { xmlListDelete((*(borrow_mut(&mut writer)).unwrap()).nsstack) });
                let fresh31 = &mut ((*(borrow_mut(&mut writer)).unwrap()).nsstack);
                *fresh31 = 0 as xmlListPtr;
                return -(1 as i32);
            }
            sum += count;
        }
    }
    return sum;
}
extern "C" fn xmlFreeTextWriterNsStackEntry(mut lk: *mut crate::src::valid::_xmlLink) {
    let mut p: *mut crate::src::xmlwriter::_xmlTextWriterNsStackEntry =
        0 as *mut xmlTextWriterNsStackEntry;
    p = (unsafe { xmlLinkGetData(lk) }) as *mut xmlTextWriterNsStackEntry;
    if p.is_null() {
        return;
    }
    if !(unsafe { (*p).prefix }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*p).prefix as *mut libc::c_void) });
    }
    if !(unsafe { (*p).uri }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*p).uri as *mut libc::c_void) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(p as *mut libc::c_void) });
}
extern "C" fn xmlCmpTextWriterNsStackEntry(
    mut data0: *const core::ffi::c_void,
    mut data1: *const core::ffi::c_void,
) -> i32 {
    let mut p0: *mut crate::src::xmlwriter::_xmlTextWriterNsStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterNsStackEntry;
    let mut p1: *mut crate::src::xmlwriter::_xmlTextWriterNsStackEntry =
        0 as *mut crate::src::xmlwriter::_xmlTextWriterNsStackEntry;
    let mut rc: i32 = 0;
    if data0 == data1 {
        return 0 as i32;
    }
    if data0.is_null() {
        return -(1 as i32);
    }
    if data1.is_null() {
        return 1 as i32;
    }
    p0 = data0 as *mut xmlTextWriterNsStackEntry;
    p1 = data1 as *mut xmlTextWriterNsStackEntry;
    rc = xmlStrcmp(unsafe { (*p0).prefix }, unsafe { (*p1).prefix });
    if rc != 0 as i32 || (unsafe { (*p0).elem }) != (unsafe { (*p1).elem }) {
        rc = -(1 as i32);
    }
    return rc;
}
extern "C" fn xmlTextWriterWriteDocCallback(
    mut context: *mut core::ffi::c_void,
    mut str: *const i8,
    mut len: i32,
) -> i32 {
    let mut ctxt: *mut crate::src::tree::_xmlParserCtxt = context as xmlParserCtxtPtr;
    let mut rc: i32 = 0;
    rc = unsafe { xmlParseChunk(ctxt, str, len, 0 as i32) };
    if rc != 0 as i32 {
        xmlWriterErrMsgInt(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterWriteDocCallback : XML error %d !\n\0" as *const u8 as *const i8,
            rc,
        );
        return -(1 as i32);
    }
    return len;
}
extern "C" fn xmlTextWriterCloseDocCallback(mut context: *mut core::ffi::c_void) -> i32 {
    let mut ctxt: *mut crate::src::tree::_xmlParserCtxt = context as xmlParserCtxtPtr;
    let mut rc: i32 = 0;
    rc = unsafe { xmlParseChunk(ctxt, 0 as *const i8, 0 as i32, 1 as i32) };
    if rc != 0 as i32 {
        xmlWriterErrMsgInt(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterCloseDocCallback : XML error %d !\n\0" as *const u8 as *const i8,
            rc,
        );
        return -(1 as i32);
    }
    return 0 as i32;
}
extern "C" fn xmlTextWriterVSprintf(
    mut format: *const i8,
    mut argptr: core::ffi::VaList,
) -> *mut u8 {
    let mut size: i32 = 0;
    let mut count: i32 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    let mut locarg: core::ffi::VaListImpl;
    size = 8192 as i32;
    buf =
        (unsafe { xmlMalloc.expect("non-null function pointer")(size as size_t) }) as *mut xmlChar;
    if buf.is_null() {
        xmlWriterErrMsg(
            Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterVSprintf : out of memory!\n\0" as *const u8 as *const i8,
        );
        return 0 as *mut xmlChar;
    }
    locarg = argptr.clone();
    loop {
        count = unsafe { vsnprintf(buf as *mut i8, size as u64, format, locarg.as_va_list()) };
        if !(count < 0 as i32 || count == size - 1 as i32 || count == size || count > size) {
            break;
        }
        (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
        size += 8192 as i32;
        buf = (unsafe { xmlMalloc.expect("non-null function pointer")(size as size_t) })
            as *mut xmlChar;
        if buf.is_null() {
            xmlWriterErrMsg(
                Option::<&'_ mut crate::src::xmlwriter::_xmlTextWriter>::None,
                XML_ERR_NO_MEMORY,
                b"xmlTextWriterVSprintf : out of memory!\n\0" as *const u8 as *const i8,
            );
            return 0 as *mut xmlChar;
        }
        locarg = argptr.clone();
    }
    return buf;
}
extern "C" fn xmlTextWriterStartDocumentCallback(mut ctx: *mut core::ffi::c_void) {
    let mut ctxt: *mut crate::src::tree::_xmlParserCtxt = ctx as xmlParserCtxtPtr;
    let mut doc: *mut crate::src::threads::_xmlDoc = 0 as *mut xmlDoc;
    if (unsafe { (*ctxt).html }) != 0 {
        if (unsafe { (*ctxt).myDoc }).is_null() {
            let fresh32 = unsafe { &mut ((*ctxt).myDoc) };
            *fresh32 = unsafe { htmlNewDocNoDtD(0 as *const xmlChar, 0 as *const xmlChar) };
        }
        if (unsafe { (*ctxt).myDoc }).is_null() {
            if !(unsafe { (*ctxt).sax }).is_null()
                && (unsafe { ((*(*ctxt).sax).error).is_some() })
            {
                (unsafe {
                    ((*(*ctxt).sax).error).expect("non-null function pointer")(
                        (*ctxt).userData,
                        b"SAX.startDocument(): out of memory\n\0" as *const u8 as *const i8,
                    )
                });
            }
            (unsafe { (*ctxt).errNo = XML_ERR_NO_MEMORY as i32 });
            (unsafe { (*ctxt).instate = XML_PARSER_EOF });
            (unsafe { (*ctxt).disableSAX = 1 as i32 });
            return;
        }
    } else {
        doc = unsafe { (*ctxt).myDoc };
        if doc.is_null() {
            let fresh33 = unsafe { &mut ((*ctxt).myDoc) };
            *fresh33 = xmlNewDoc(unsafe { (*ctxt).version });
            doc = *fresh33;
        }
        if !doc.is_null() {
            if (unsafe { (*doc).children }).is_null() {
                if !(unsafe { (*ctxt).encoding }).is_null() {
                    let fresh34 = unsafe { &mut ((*doc).encoding) };
                    *fresh34 = xmlStrdup(unsafe { (*ctxt).encoding });
                } else {
                    let fresh35 = unsafe { &mut ((*doc).encoding) };
                    *fresh35 = 0 as *const xmlChar;
                }
                (unsafe { (*doc).standalone = (*ctxt).standalone });
            }
        } else {
            if !(unsafe { (*ctxt).sax }).is_null()
                && (unsafe { ((*(*ctxt).sax).error).is_some() })
            {
                (unsafe {
                    ((*(*ctxt).sax).error).expect("non-null function pointer")(
                        (*ctxt).userData,
                        b"SAX.startDocument(): out of memory\n\0" as *const u8 as *const i8,
                    )
                });
            }
            (unsafe { (*ctxt).errNo = XML_ERR_NO_MEMORY as i32 });
            (unsafe { (*ctxt).instate = XML_PARSER_EOF });
            (unsafe { (*ctxt).disableSAX = 1 as i32 });
            return;
        }
    }
    if !(unsafe { (*ctxt).myDoc }).is_null()
        && (unsafe { (*(*ctxt).myDoc).URL }).is_null()
        && !(unsafe { (*ctxt).input }).is_null()
        && !(unsafe { (*(*ctxt).input).filename }).is_null()
    {
        let fresh36 = unsafe { &mut ((*(*ctxt).myDoc).URL) };
        *fresh36 = xmlCanonicPath((unsafe { (*(*ctxt).input).filename }) as *const xmlChar);
        if (unsafe { (*(*ctxt).myDoc).URL }).is_null() {
            let fresh37 = unsafe { &mut ((*(*ctxt).myDoc).URL) };
            *fresh37 = xmlStrdup((unsafe { (*(*ctxt).input).filename }) as *const xmlChar);
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlTextWriterSetIndent<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut indent: i32,
) -> i32 {
    if borrow(&writer).is_none() || indent < 0 as i32 {
        return -(1 as i32);
    }
    (*(borrow_mut(&mut writer)).unwrap()).indent = indent;
    (*(borrow_mut(&mut writer)).unwrap()).doindent = 1 as i32;
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextWriterSetIndentString<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut str: *const u8,
) -> i32 {
    if borrow(&writer).is_none() || str.is_null() {
        return -(1 as i32);
    }
    if !((*(borrow_mut(&mut writer)).unwrap()).ichar).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*(borrow_mut(&mut writer)).unwrap()).ichar as *mut libc::c_void,
            )
        });
    }
    let fresh38 = &mut ((*(borrow_mut(&mut writer)).unwrap()).ichar);
    *fresh38 = xmlStrdup(str);
    if ((*(borrow_mut(&mut writer)).unwrap()).ichar).is_null() {
        return -(1 as i32);
    } else {
        return 0 as i32;
    };
}
#[no_mangle]
pub extern "C" fn xmlTextWriterSetQuoteChar<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut quotechar: u8,
) -> i32 {
    if borrow(&writer).is_none()
        || quotechar as i32 != '\'' as i32 && quotechar as i32 != '"' as i32
    {
        return -(1 as i32);
    }
    (*(borrow_mut(&mut writer)).unwrap()).qchar = quotechar as i8;
    return 0 as i32;
}
extern "C" fn xmlTextWriterWriteIndent<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
) -> i32 {
    let mut lksize: i32 = 0;
    let mut i: i32 = 0;
    let mut ret: i32 = 0;
    lksize = unsafe { xmlListSize((*(borrow_mut(&mut writer)).unwrap()).nodes) };
    if lksize < 1 as i32 {
        return -(1 as i32);
    }
    i = 0 as i32;
    while i < lksize - 1 as i32 {
        ret = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            (*(borrow(&writer)).unwrap()).ichar as *const i8,
        );
        if ret == -(1 as i32) {
            return -(1 as i32);
        }
        i += 1;
    }
    return lksize - 1 as i32;
}
extern "C" fn xmlTextWriterHandleStateDependencies<'a1>(
    mut writer: Option<&'a1 mut crate::src::xmlwriter::_xmlTextWriter>,
    mut p: *mut crate::src::xmlwriter::_xmlTextWriterStackEntry,
) -> i32 {
    let mut count: i32 = 0;
    let mut sum: i32 = 0;
    let mut extra: [i8; 3] = [0; 3];
    if borrow(&writer).is_none() {
        return -(1 as i32);
    }
    if p.is_null() {
        return 0 as i32;
    }
    sum = 0 as i32;
    extra[2 as i32 as usize] = '\u{0}' as i32 as i8;
    extra[1 as i32 as usize] = extra[2 as i32 as usize];
    extra[0 as i32 as usize] = extra[1 as i32 as usize];
    if !p.is_null() {
        sum = 0 as i32;
        match (unsafe { (*p).state }) as u32 {
            1 => {
                count = xmlTextWriterOutputNSDecl(borrow_mut(&mut writer));
                if count < 0 as i32 {
                    return -(1 as i32);
                }
                sum += count;
                extra[0 as i32 as usize] = '>' as i32 as i8;
                (unsafe { (*p).state = XML_TEXTWRITER_TEXT });
            }
            4 => {
                extra[0 as i32 as usize] = ' ' as i32 as i8;
                (unsafe { (*p).state = XML_TEXTWRITER_PI_TEXT });
            }
            7 => {
                extra[0 as i32 as usize] = ' ' as i32 as i8;
                extra[1 as i32 as usize] = '[' as i32 as i8;
                (unsafe { (*p).state = XML_TEXTWRITER_DTD_TEXT });
            }
            9 => {
                extra[0 as i32 as usize] = ' ' as i32 as i8;
                (unsafe { (*p).state = XML_TEXTWRITER_DTD_ELEM_TEXT });
            }
            11 => {
                extra[0 as i32 as usize] = ' ' as i32 as i8;
                (unsafe { (*p).state = XML_TEXTWRITER_DTD_ATTL_TEXT });
            }
            13 | 15 => {
                extra[0 as i32 as usize] = ' ' as i32 as i8;
                extra[1 as i32 as usize] = (*(borrow_mut(&mut writer)).unwrap()).qchar;
                (unsafe { (*p).state = XML_TEXTWRITER_DTD_ENTY_TEXT });
            }
            _ => {}
        }
    }
    if (unsafe { *extra.as_mut_ptr() }) as i32 != '\u{0}' as i32 {
        count = xmlOutputBufferWriteString(
            (*(borrow_mut(&mut writer)).unwrap()).out,
            extra.as_mut_ptr(),
        );
        if count < 0 as i32 {
            return -(1 as i32);
        }
        sum += count;
    }
    return sum;
}
use crate::laertes_rt::*;
