use ::libc;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    static mut stderr: *mut FILE;
    
    
    
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    fn snprintf(
        _: *mut i8,
        _: u64,
        _: *const i8,
        _: ...
    ) -> i32;
    fn memset(
        _: *mut libc::c_void,
        _: i32,
        _: u64,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::SAX2::xmlSAX2IgnorableWhitespace;
pub use crate::src::SAX2::xmlSAXVersion;
pub use crate::src::buf::xmlBufContent;
pub use crate::src::buf::xmlBufCreate;
pub use crate::src::buf::xmlBufEnd;
pub use crate::src::buf::xmlBufIsEmpty;
pub use crate::src::buf::xmlBufResetInput;
pub use crate::src::buf::xmlBufShrink;
pub use crate::src::buf::xmlBufUse;
pub use crate::src::catalog::xmlCatalogFreeLocal;
pub use crate::src::chvalid::xmlCharInRange;
pub use crate::src::dict::xmlDictCreate;
pub use crate::src::dict::xmlDictFree;
pub use crate::src::dict::xmlDictSetLimit;
pub use crate::src::encoding::xmlCharEncCloseFunc;
pub use crate::src::encoding::xmlCharEncFirstLineInput;
pub use crate::src::encoding::xmlCharEncInput;
pub use crate::src::encoding::xmlGetCharEncodingHandler;
pub use crate::src::encoding::xmlGetCharEncodingName;
pub use crate::src::error::__xmlRaiseError;
pub use crate::src::error::xmlParserValidityError;
pub use crate::src::error::xmlParserValidityWarning;
pub use crate::src::globals::__xmlDefaultSAXHandler;
pub use crate::src::globals::__xmlDoValidityCheckingDefaultValue;
pub use crate::src::globals::__xmlGenericError;
pub use crate::src::globals::__xmlGenericErrorContext;
pub use crate::src::globals::__xmlGetWarningsDefaultValue;
pub use crate::src::globals::__xmlIndentTreeOutput;
pub use crate::src::globals::__xmlKeepBlanksDefaultValue;
pub use crate::src::globals::__xmlLineNumbersDefaultValue;
pub use crate::src::globals::__xmlLoadExtDtdDefaultValue;
pub use crate::src::globals::__xmlParserDebugEntities;
pub use crate::src::globals::__xmlPedanticParserDefaultValue;
pub use crate::src::globals::__xmlSubstituteEntitiesDefaultValue;
pub use crate::src::hash::xmlHashDefaultDeallocator;
pub use crate::src::hash::xmlHashFree;
pub use crate::src::parser::inputPop;
pub use crate::src::parser::xmlCtxtReset;
pub use crate::src::parser::xmlInitParser;
pub use crate::src::parser::xmlStopParser;
pub use crate::src::uri::xmlCanonicPath;
pub use crate::src::xmlIO::__xmlLoaderErr;
pub use crate::src::xmlIO::xmlCheckHTTPInput;
pub use crate::src::xmlIO::xmlFreeParserInputBuffer;
pub use crate::src::xmlIO::xmlLoadExternalEntity;
pub use crate::src::xmlIO::xmlParserGetDirectory;
pub use crate::src::xmlIO::xmlParserInputBufferCreateFilename;
pub use crate::src::xmlIO::xmlParserInputBufferGrow;
pub use crate::src::xmlIO::xmlParserInputBufferRead;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrlen;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::parser::_xmlStartTag;
pub use crate::src::HTMLtree::_IO_codecvt;
pub use crate::src::buf::_IO_marker;
pub use crate::src::chvalid::xmlIsBaseCharGroup;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub use crate::src::globals::xmlRealloc;
pub use crate::src::python::types::_IO_wide_data;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub type xmlGenericErrorFunc = crate::src::HTMLparser::xmlGenericErrorFunc;
pub type FILE = crate::src::HTMLtree::FILE;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::HTMLtree::_IO_FILE;
pub type size_t = crate::src::HTMLparser::size_t;
pub type __off64_t = crate::src::HTMLtree::__off64_t;
pub type _IO_lock_t = crate::src::HTMLtree::_IO_lock_t;
pub type __off_t = crate::src::HTMLtree::__off_t;
pub type xmlChar = crate::src::HTMLparser::xmlChar;
pub type xmlFreeFunc = crate::src::HTMLparser::xmlFreeFunc;
pub type xmlMallocFunc = crate::src::HTMLparser::xmlMallocFunc;
pub type xmlReallocFunc = crate::src::HTMLparser::xmlReallocFunc;
// #[derive(Copy, Clone)]

pub type _xmlParserInputBuffer = crate::src::HTMLparser::_xmlParserInputBuffer;
pub type xmlBufPtr = crate::src::HTMLparser::xmlBufPtr;
pub type xmlBuf = crate::src::HTMLparser::xmlBuf;
pub type xmlCharEncodingHandlerPtr = crate::src::HTMLparser::xmlCharEncodingHandlerPtr;
pub type xmlCharEncodingHandler = crate::src::HTMLparser::xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub type _xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type iconv_t = crate::src::HTMLparser::iconv_t;
pub type xmlCharEncodingOutputFunc = crate::src::HTMLparser::xmlCharEncodingOutputFunc;
pub type xmlCharEncodingInputFunc = crate::src::HTMLparser::xmlCharEncodingInputFunc;
pub type xmlInputCloseCallback = crate::src::HTMLparser::xmlInputCloseCallback;
pub type xmlInputReadCallback = crate::src::HTMLparser::xmlInputReadCallback;
pub type xmlParserInputBuffer = crate::src::HTMLparser::xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = crate::src::HTMLparser::xmlParserInputBufferPtr;
// #[derive(Copy, Clone)]

pub type _xmlParserInput = crate::src::HTMLparser::_xmlParserInput;
pub type xmlParserInputDeallocate = crate::src::HTMLparser::xmlParserInputDeallocate;
pub type xmlParserInput = crate::src::HTMLparser::xmlParserInput;
pub type xmlParserInputPtr = crate::src::HTMLparser::xmlParserInputPtr;
// #[derive(Copy, Clone)]

pub type _xmlParserCtxt = crate::src::HTMLparser::_xmlParserCtxt;
pub type xmlParserNodeInfo = crate::src::HTMLparser::xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub type _xmlParserNodeInfo = crate::src::HTMLparser::_xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub type _xmlNode = crate::src::HTMLparser::_xmlNode;
pub type xmlNs = crate::src::HTMLparser::xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlNs = crate::src::HTMLparser::_xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlDoc = crate::src::HTMLparser::_xmlDoc;
// #[derive(Copy, Clone)]

pub type _xmlDtd = crate::src::HTMLparser::_xmlDtd;
pub type xmlElementType = crate::src::HTMLparser::xmlElementType;
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
pub type xmlNsType = crate::src::HTMLparser::xmlNsType;
// #[derive(Copy, Clone)]

pub type _xmlAttr = crate::src::HTMLparser::_xmlAttr;
pub type xmlAttributeType = crate::src::HTMLparser::xmlAttributeType;
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
pub type xmlParserMode = crate::src::HTMLparser::xmlParserMode;
pub const XML_PARSE_READER: xmlParserMode = 5;
pub const XML_PARSE_PUSH_SAX: xmlParserMode = 4;
pub const XML_PARSE_PUSH_DOM: xmlParserMode = 3;
pub const XML_PARSE_SAX: xmlParserMode = 2;
pub const XML_PARSE_DOM: xmlParserMode = 1;
pub const XML_PARSE_UNKNOWN: xmlParserMode = 0;
pub type xmlError = crate::src::HTMLparser::xmlError;
// #[derive(Copy, Clone)]

pub type _xmlError = crate::src::HTMLparser::_xmlError;
pub type xmlErrorLevel = crate::src::HTMLparser::xmlErrorLevel;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlAttrPtr = crate::src::HTMLparser::xmlAttrPtr;
pub type xmlAttr = crate::src::HTMLparser::xmlAttr;
pub type xmlNodePtr = crate::src::HTMLparser::xmlNodePtr;
pub type xmlNode = crate::src::HTMLparser::xmlNode;
pub type xmlHashTablePtr = crate::src::HTMLparser::xmlHashTablePtr;
pub type xmlHashTable = crate::src::HTMLparser::xmlHashTable;
pub type xmlStartTag = crate::src::HTMLparser::xmlStartTag;
pub type xmlDictPtr = crate::src::HTMLparser::xmlDictPtr;
pub type xmlDict = crate::src::HTMLparser::xmlDict;
pub type xmlParserInputState = crate::src::HTMLparser::xmlParserInputState;
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
pub type xmlValidCtxt = crate::src::HTMLparser::xmlValidCtxt;
// #[derive(Copy, Clone)]

pub type _xmlValidCtxt = crate::src::HTMLparser::_xmlValidCtxt;
pub type xmlAutomataStatePtr = crate::src::HTMLparser::xmlAutomataStatePtr;
pub type xmlAutomataState = crate::src::HTMLparser::xmlAutomataState;
pub type xmlAutomataPtr = crate::src::HTMLparser::xmlAutomataPtr;
pub type xmlAutomata = crate::src::HTMLparser::xmlAutomata;
pub type xmlValidState = crate::src::HTMLparser::xmlValidState;
pub type xmlDocPtr = crate::src::HTMLparser::xmlDocPtr;
pub type xmlDoc = crate::src::HTMLparser::xmlDoc;
pub type xmlValidityWarningFunc = crate::src::HTMLparser::xmlValidityWarningFunc;
pub type xmlValidityErrorFunc = crate::src::HTMLparser::xmlValidityErrorFunc;
pub type xmlParserNodeInfoSeq = crate::src::HTMLparser::xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub type _xmlParserNodeInfoSeq = crate::src::HTMLparser::_xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub type _xmlSAXHandler = crate::src::HTMLparser::_xmlSAXHandler;
pub type xmlStructuredErrorFunc = crate::src::HTMLparser::xmlStructuredErrorFunc;
pub type xmlErrorPtr = crate::src::HTMLparser::xmlErrorPtr;
pub type endElementNsSAX2Func = crate::src::HTMLparser::endElementNsSAX2Func;
pub type startElementNsSAX2Func = crate::src::HTMLparser::startElementNsSAX2Func;
pub type externalSubsetSAXFunc = crate::src::HTMLparser::externalSubsetSAXFunc;
pub type cdataBlockSAXFunc = crate::src::HTMLparser::cdataBlockSAXFunc;
pub type getParameterEntitySAXFunc = crate::src::HTMLparser::getParameterEntitySAXFunc;
pub type xmlEntityPtr = crate::src::HTMLparser::xmlEntityPtr;
pub type xmlEntity = crate::src::HTMLparser::xmlEntity;
// #[derive(Copy, Clone)]

pub type _xmlEntity = crate::src::HTMLparser::_xmlEntity;
pub type xmlEntityType = crate::src::HTMLparser::xmlEntityType;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = crate::src::HTMLparser::fatalErrorSAXFunc;
pub type errorSAXFunc = crate::src::HTMLparser::errorSAXFunc;
pub type warningSAXFunc = crate::src::HTMLparser::warningSAXFunc;
pub type commentSAXFunc = crate::src::HTMLparser::commentSAXFunc;
pub type processingInstructionSAXFunc = crate::src::HTMLparser::processingInstructionSAXFunc;
pub type ignorableWhitespaceSAXFunc = crate::src::HTMLparser::ignorableWhitespaceSAXFunc;
pub type charactersSAXFunc = crate::src::HTMLparser::charactersSAXFunc;
pub type referenceSAXFunc = crate::src::HTMLparser::referenceSAXFunc;
pub type endElementSAXFunc = crate::src::HTMLparser::endElementSAXFunc;
pub type startElementSAXFunc = crate::src::HTMLparser::startElementSAXFunc;
pub type endDocumentSAXFunc = crate::src::HTMLparser::endDocumentSAXFunc;
pub type startDocumentSAXFunc = crate::src::HTMLparser::startDocumentSAXFunc;
pub type setDocumentLocatorSAXFunc = crate::src::HTMLparser::setDocumentLocatorSAXFunc;
pub type xmlSAXLocatorPtr = crate::src::HTMLparser::xmlSAXLocatorPtr;
pub type xmlSAXLocator = crate::src::HTMLparser::xmlSAXLocator;
// #[derive(Copy, Clone)]

pub type _xmlSAXLocator = crate::src::HTMLparser::_xmlSAXLocator;
pub type unparsedEntityDeclSAXFunc = crate::src::HTMLparser::unparsedEntityDeclSAXFunc;
pub type elementDeclSAXFunc = crate::src::HTMLparser::elementDeclSAXFunc;
pub type xmlElementContentPtr = crate::src::HTMLparser::xmlElementContentPtr;
pub type xmlElementContent = crate::src::HTMLparser::xmlElementContent;
// #[derive(Copy, Clone)]

pub type _xmlElementContent = crate::src::HTMLparser::_xmlElementContent;
pub type xmlElementContentOccur = crate::src::HTMLparser::xmlElementContentOccur;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub type xmlElementContentType = crate::src::HTMLparser::xmlElementContentType;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub type attributeDeclSAXFunc = crate::src::HTMLparser::attributeDeclSAXFunc;
pub type xmlEnumerationPtr = crate::src::HTMLparser::xmlEnumerationPtr;
pub type xmlEnumeration = crate::src::HTMLparser::xmlEnumeration;
// #[derive(Copy, Clone)]

pub type _xmlEnumeration = crate::src::HTMLparser::_xmlEnumeration;
pub type notationDeclSAXFunc = crate::src::HTMLparser::notationDeclSAXFunc;
pub type entityDeclSAXFunc = crate::src::HTMLparser::entityDeclSAXFunc;
pub type getEntitySAXFunc = crate::src::HTMLparser::getEntitySAXFunc;
pub type resolveEntitySAXFunc = crate::src::HTMLparser::resolveEntitySAXFunc;
pub type hasExternalSubsetSAXFunc = crate::src::HTMLparser::hasExternalSubsetSAXFunc;
pub type hasInternalSubsetSAXFunc = crate::src::HTMLparser::hasInternalSubsetSAXFunc;
pub type isStandaloneSAXFunc = crate::src::HTMLparser::isStandaloneSAXFunc;
pub type internalSubsetSAXFunc = crate::src::HTMLparser::internalSubsetSAXFunc;
pub type xmlParserCtxt = crate::src::HTMLparser::xmlParserCtxt;
pub type xmlParserCtxtPtr = crate::src::HTMLparser::xmlParserCtxtPtr;
pub type xmlSAXHandler = crate::src::HTMLparser::xmlSAXHandler;
pub type xmlSAXHandlerPtr = crate::src::HTMLparser::xmlSAXHandlerPtr;
pub type xmlHashDeallocator = crate::src::HTMLparser::xmlHashDeallocator;
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
pub type xmlParserErrors = crate::src::HTMLparser::xmlParserErrors;
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
pub type xmlParserNodeInfoPtr = crate::src::HTMLparser::xmlParserNodeInfoPtr;
pub type xmlParserNodeInfoSeqPtr = crate::src::HTMLparser::xmlParserNodeInfoSeqPtr;
// #[derive(Copy, Clone)]

pub type _xmlSAXHandlerV1 = crate::src::HTMLparser::_xmlSAXHandlerV1;
pub type xmlSAXHandlerV1 = crate::src::HTMLparser::xmlSAXHandlerV1;
pub type xmlCharEncoding = crate::src::HTMLparser::xmlCharEncoding;
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
pub const XML_PARSE_NOENT: C2RustUnnamed_0 = 2;
pub const XML_PARSE_DTDVALID: C2RustUnnamed_0 = 16;
pub const XML_PARSE_NOBLANKS: C2RustUnnamed_0 = 256;
pub const XML_PARSE_PEDANTIC: C2RustUnnamed_0 = 128;
pub const XML_PARSE_DTDLOAD: C2RustUnnamed_0 = 4;
pub type C2RustUnnamed_0 = u32;
pub const XML_PARSE_BIG_LINES: C2RustUnnamed_0 = 4194304;
pub const XML_PARSE_IGNORE_ENC: C2RustUnnamed_0 = 2097152;
pub const XML_PARSE_OLDSAX: C2RustUnnamed_0 = 1048576;
pub const XML_PARSE_HUGE: C2RustUnnamed_0 = 524288;
pub const XML_PARSE_NOBASEFIX: C2RustUnnamed_0 = 262144;
pub const XML_PARSE_OLD10: C2RustUnnamed_0 = 131072;
pub const XML_PARSE_COMPACT: C2RustUnnamed_0 = 65536;
pub const XML_PARSE_NOXINCNODE: C2RustUnnamed_0 = 32768;
pub const XML_PARSE_NOCDATA: C2RustUnnamed_0 = 16384;
pub const XML_PARSE_NSCLEAN: C2RustUnnamed_0 = 8192;
pub const XML_PARSE_NODICT: C2RustUnnamed_0 = 4096;
pub const XML_PARSE_NONET: C2RustUnnamed_0 = 2048;
pub const XML_PARSE_XINCLUDE: C2RustUnnamed_0 = 1024;
pub const XML_PARSE_SAX1: C2RustUnnamed_0 = 512;
pub const XML_PARSE_NOWARNING: C2RustUnnamed_0 = 64;
pub const XML_PARSE_NOERROR: C2RustUnnamed_0 = 32;
pub const XML_PARSE_DTDATTR: C2RustUnnamed_0 = 8;
pub const XML_PARSE_RECOVER: C2RustUnnamed_0 = 1;
// #[derive(Copy, Clone)]

pub type _xmlChSRange = crate::src::HTMLparser::_xmlChSRange;
pub type xmlChSRange = crate::src::HTMLparser::xmlChSRange;
// #[derive(Copy, Clone)]

pub type _xmlChLRange = crate::src::HTMLparser::_xmlChLRange;
pub type xmlChLRange = crate::src::HTMLparser::xmlChLRange;
// #[derive(Copy, Clone)]

pub type _xmlChRangeGroup = crate::src::HTMLparser::_xmlChRangeGroup;
pub type xmlChRangeGroup = crate::src::HTMLparser::xmlChRangeGroup;
#[no_mangle]
pub unsafe extern "C" fn xmlCheckVersion(mut version: i32) {
    let mut myversion: i32 = 21000 as i32;
    xmlInitParser();
    if myversion / 10000 as i32 != version / 10000 as i32 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Fatal: program compiled against libxml %d using libxml %d\n\0" as *const u8
                as *const i8,
            version / 10000 as i32,
            myversion / 10000 as i32,
        );
        fprintf(
            stderr,
            b"Fatal: program compiled against libxml %d using libxml %d\n\0" as *const u8
                as *const i8,
            version / 10000 as i32,
            myversion / 10000 as i32,
        );
    }
    if (myversion / 100 as i32) < version / 100 as i32 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Warning: program compiled against libxml %d using older %d\n\0"
                as *const u8 as *const i8,
            version / 100 as i32,
            myversion / 100 as i32,
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlErrMemory(
    mut ctxt: xmlParserCtxtPtr,
    mut extra: *const i8,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = XML_ERR_NO_MEMORY as i32;
        (*ctxt).instate = XML_PARSER_EOF;
        (*ctxt).disableSAX = 1 as i32;
    }
    if !extra.is_null() {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as i32,
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
        );
    } else {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as i32,
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
        );
    };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlErrEncoding(
    mut ctxt: xmlParserCtxtPtr,
    mut xmlerr: xmlParserErrors,
    mut msg: *const i8,
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = xmlerr as i32;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_PARSER as i32,
        xmlerr as i32,
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
    );
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as i32;
        if (*ctxt).recovery == 0 as i32 {
            (*ctxt).disableSAX = 1 as i32;
        }
    }
}
unsafe extern "C" fn xmlErrInternal(
    mut ctxt: xmlParserCtxtPtr,
    mut msg: *const i8,
    mut str: *const xmlChar,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = XML_ERR_INTERNAL_ERROR as i32;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_PARSER as i32,
        XML_ERR_INTERNAL_ERROR as i32,
        XML_ERR_FATAL,
        0 as *const i8,
        0 as i32,
        str as *const i8,
        0 as *const i8,
        0 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        str,
    );
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as i32;
        if (*ctxt).recovery == 0 as i32 {
            (*ctxt).disableSAX = 1 as i32;
        }
    }
}
unsafe extern "C" fn xmlErrEncodingInt(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const i8,
    mut val: i32,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as i32;
    }
    __xmlRaiseError(
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
    );
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as i32;
        if (*ctxt).recovery == 0 as i32 {
            (*ctxt).disableSAX = 1 as i32;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsLetter(mut c: i32) -> i32 {
    return ((if c < 0x100 as i32 {
        (0x41 as i32 <= c && c <= 0x5a as i32
            || 0x61 as i32 <= c && c <= 0x7a as i32
            || 0xc0 as i32 <= c && c <= 0xd6 as i32
            || 0xd8 as i32 <= c && c <= 0xf6 as i32
            || 0xf8 as i32 <= c) as i32
    } else {
        xmlCharInRange(c as u32, &xmlIsBaseCharGroup)
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32)
                as i32
        }) != 0) as i32;
}
#[no_mangle]
pub extern "C" fn xmlParserInputRead(
    mut in_0: xmlParserInputPtr,
    mut len: i32,
) -> i32 {
    return -(1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserInputGrow(
    mut in_0: xmlParserInputPtr,
    mut len: i32,
) -> i32 {
    let mut ret: i32 = 0;
    let mut indx: size_t = 0;
    if in_0.is_null() || len < 0 as i32 {
        return -(1 as i32);
    }
    if ((*in_0).buf).is_null() {
        return -(1 as i32);
    }
    if ((*in_0).base).is_null() {
        return -(1 as i32);
    }
    if ((*in_0).cur).is_null() {
        return -(1 as i32);
    }
    if ((*(*in_0).buf).buffer).is_null() {
        return -(1 as i32);
    }
    indx = ((*in_0).cur).offset_from((*in_0).base) as i64 as size_t;
    if xmlBufUse((*(*in_0).buf).buffer)
        > (indx as u32).wrapping_add(250 as i32 as u32)
            as u64
    {
        return 0 as i32;
    }
    if ((*(*in_0).buf).readcallback).is_some() {
        ret = xmlParserInputBufferGrow((*in_0).buf, len);
    } else {
        return 0 as i32
    }
    let fresh0 = &mut ((*in_0).base);
    *fresh0 = xmlBufContent((*(*in_0).buf).buffer as *const xmlBuf);
    let fresh1 = &mut ((*in_0).cur);
    *fresh1 = ((*in_0).base).offset(indx as isize);
    let fresh2 = &mut ((*in_0).end);
    *fresh2 = xmlBufEnd((*(*in_0).buf).buffer);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserInputShrink(mut in_0: xmlParserInputPtr) {
    let mut used: size_t = 0;
    let mut ret: size_t = 0;
    if in_0.is_null() {
        return;
    }
    if ((*in_0).buf).is_null() {
        return;
    }
    if ((*in_0).base).is_null() {
        return;
    }
    if ((*in_0).cur).is_null() {
        return;
    }
    if ((*(*in_0).buf).buffer).is_null() {
        return;
    }
    used = ((*in_0).cur).offset_from((*in_0).base) as i64 as size_t;
    if used > 250 as i32 as u64 {
        ret = xmlBufShrink(
            (*(*in_0).buf).buffer,
            used.wrapping_sub(80 as i32 as u64),
        );
        if ret > 0 as i32 as u64 {
            used = (used as u64).wrapping_sub(ret) as size_t as size_t;
            let fresh3 = &mut ((*in_0).consumed);
            *fresh3 = (*fresh3).wrapping_add(ret);
        }
    }
    if xmlBufUse((*(*in_0).buf).buffer) <= 250 as i32 as u64 {
        xmlParserInputBufferRead((*in_0).buf, 2 as i32 * 250 as i32);
    }
    let fresh4 = &mut ((*in_0).base);
    *fresh4 = xmlBufContent((*(*in_0).buf).buffer as *const xmlBuf);
    let fresh5 = &mut ((*in_0).cur);
    *fresh5 = ((*in_0).base).offset(used as isize);
    let fresh6 = &mut ((*in_0).end);
    *fresh6 = xmlBufEnd((*(*in_0).buf).buffer);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNextChar(mut ctxt: xmlParserCtxtPtr) {
    let mut current_block: u64;
    if ctxt.is_null() || (*ctxt).instate as i32 == XML_PARSER_EOF as i32
        || ((*ctxt).input).is_null()
    {
        return;
    }
    if !((*(*ctxt).input).cur <= (*(*ctxt).input).end) {
        xmlErrInternal(
            ctxt,
            b"Parser input data memory error\n\0" as *const u8 as *const i8,
            0 as *const xmlChar,
        );
        (*ctxt).errNo = XML_ERR_INTERNAL_ERROR as i32;
        xmlStopParser(ctxt);
        return;
    }
    if *(*(*ctxt).input).cur as i32 == 0 as i32
        && xmlParserInputGrow((*ctxt).input, 250 as i32) <= 0 as i32
    {
        return;
    }
    if (*ctxt).charset == XML_CHAR_ENCODING_UTF8 as i32 {
        let mut cur: *const u8 = 0 as *const u8;
        let mut c: u8 = 0;
        if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
            let fresh7 = &mut ((*(*ctxt).input).line);
            *fresh7 += 1;
            (*(*ctxt).input).col = 1 as i32;
        } else {
            let fresh8 = &mut ((*(*ctxt).input).col);
            *fresh8 += 1;
        }
        cur = (*(*ctxt).input).cur;
        c = *cur;
        if c as i32 & 0x80 as i32 != 0 {
            if c as i32 == 0xc0 as i32 {
                current_block = 6366546706204172389;
            } else {
                if *cur.offset(1 as i32 as isize) as i32
                    == 0 as i32
                {
                    xmlParserInputGrow((*ctxt).input, 250 as i32);
                    cur = (*(*ctxt).input).cur;
                }
                if *cur.offset(1 as i32 as isize) as i32
                    & 0xc0 as i32 != 0x80 as i32
                {
                    current_block = 6366546706204172389;
                } else if c as i32 & 0xe0 as i32 == 0xe0 as i32 {
                    let mut val: u32 = 0;
                    if *cur.offset(2 as i32 as isize) as i32
                        == 0 as i32
                    {
                        xmlParserInputGrow((*ctxt).input, 250 as i32);
                        cur = (*(*ctxt).input).cur;
                    }
                    if *cur.offset(2 as i32 as isize) as i32
                        & 0xc0 as i32 != 0x80 as i32
                    {
                        current_block = 6366546706204172389;
                    } else {
                        if c as i32 & 0xf0 as i32 == 0xf0 as i32
                        {
                            if *cur.offset(3 as i32 as isize) as i32
                                == 0 as i32
                            {
                                xmlParserInputGrow((*ctxt).input, 250 as i32);
                                cur = (*(*ctxt).input).cur;
                            }
                            if c as i32 & 0xf8 as i32
                                != 0xf0 as i32
                                || *cur.offset(3 as i32 as isize) as i32
                                    & 0xc0 as i32 != 0x80 as i32
                            {
                                current_block = 6366546706204172389;
                            } else {
                                let fresh9 = &mut ((*(*ctxt).input).cur);
                                *fresh9 = (*fresh9).offset(4 as i32 as isize);
                                val = ((*cur.offset(0 as i32 as isize)
                                    as i32 & 0x7 as i32) << 18 as i32)
                                    as u32;
                                val
                                    |= ((*cur.offset(1 as i32 as isize) as i32
                                        & 0x3f as i32) << 12 as i32)
                                        as u32;
                                val
                                    |= ((*cur.offset(2 as i32 as isize) as i32
                                        & 0x3f as i32) << 6 as i32) as u32;
                                val
                                    |= (*cur.offset(3 as i32 as isize) as i32
                                        & 0x3f as i32) as u32;
                                current_block = 15004371738079956865;
                            }
                        } else {
                            let fresh10 = &mut ((*(*ctxt).input).cur);
                            *fresh10 = (*fresh10).offset(3 as i32 as isize);
                            val = ((*cur.offset(0 as i32 as isize) as i32
                                & 0xf as i32) << 12 as i32) as u32;
                            val
                                |= ((*cur.offset(1 as i32 as isize) as i32
                                    & 0x3f as i32) << 6 as i32) as u32;
                            val
                                |= (*cur.offset(2 as i32 as isize) as i32
                                    & 0x3f as i32) as u32;
                            current_block = 15004371738079956865;
                        }
                        match current_block {
                            6366546706204172389 => {}
                            _ => {
                                if val > 0xd7ff as i32 as u32
                                    && val < 0xe000 as i32 as u32
                                    || val > 0xfffd as i32 as u32
                                        && val < 0x10000 as i32 as u32
                                    || val >= 0x110000 as i32 as u32
                                {
                                    xmlErrEncodingInt(
                                        ctxt,
                                        XML_ERR_INVALID_CHAR,
                                        b"Char 0x%X out of allowed range\n\0" as *const u8
                                            as *const i8,
                                        val as i32,
                                    );
                                }
                                current_block = 6072622540298447352;
                            }
                        }
                    }
                } else {
                    let fresh11 = &mut ((*(*ctxt).input).cur);
                    *fresh11 = (*fresh11).offset(2 as i32 as isize);
                    current_block = 6072622540298447352;
                }
            }
            match current_block {
                6072622540298447352 => {}
                _ => {
                    if ctxt.is_null() || ((*ctxt).input).is_null()
                        || (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as i64) < 4 as i32 as i64
                    {
                        __xmlErrEncoding(
                            ctxt,
                            XML_ERR_INVALID_CHAR,
                            b"Input is not proper UTF-8, indicate encoding !\n\0"
                                as *const u8 as *const i8,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                    } else {
                        let mut buffer: [i8; 150] = [0; 150];
                        snprintf(
                            buffer.as_mut_ptr(),
                            149 as i32 as u64,
                            b"Bytes: 0x%02X 0x%02X 0x%02X 0x%02X\n\0" as *const u8
                                as *const i8,
                            *((*(*ctxt).input).cur).offset(0 as i32 as isize)
                                as i32,
                            *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                                as i32,
                            *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                                as i32,
                            *((*(*ctxt).input).cur).offset(3 as i32 as isize)
                                as i32,
                        );
                        __xmlErrEncoding(
                            ctxt,
                            XML_ERR_INVALID_CHAR,
                            b"Input is not proper UTF-8, indicate encoding !\n%s\0"
                                as *const u8 as *const i8,
                            buffer.as_mut_ptr() as *mut xmlChar,
                            0 as *const xmlChar,
                        );
                    }
                    (*ctxt).charset = XML_CHAR_ENCODING_8859_1 as i32;
                    let fresh16 = &mut ((*(*ctxt).input).cur);
                    *fresh16 = (*fresh16).offset(1);
                    return;
                }
            }
        } else {
            let fresh12 = &mut ((*(*ctxt).input).cur);
            *fresh12 = (*fresh12).offset(1);
        }
    } else {
        if *(*(*ctxt).input).cur as i32 == '\n' as i32 {
            let fresh13 = &mut ((*(*ctxt).input).line);
            *fresh13 += 1;
            (*(*ctxt).input).col = 1 as i32;
        } else {
            let fresh14 = &mut ((*(*ctxt).input).col);
            *fresh14 += 1;
        }
        let fresh15 = &mut ((*(*ctxt).input).cur);
        *fresh15 = (*fresh15).offset(1);
    }
    if *(*(*ctxt).input).cur as i32 == 0 as i32 {
        xmlParserInputGrow((*ctxt).input, 250 as i32);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlCurrentChar(
    mut ctxt: xmlParserCtxtPtr,
    mut len: *mut i32,
) -> i32 {
    let mut current_block: u64;
    if ctxt.is_null() || len.is_null() || ((*ctxt).input).is_null() {
        return 0 as i32;
    }
    if (*ctxt).instate as i32 == XML_PARSER_EOF as i32 {
        return 0 as i32;
    }
    if *(*(*ctxt).input).cur as i32 >= 0x20 as i32
        && *(*(*ctxt).input).cur as i32 <= 0x7f as i32
    {
        *len = 1 as i32;
        return *(*(*ctxt).input).cur as i32;
    }
    if (*ctxt).charset == XML_CHAR_ENCODING_UTF8 as i32 {
        let mut cur: *const u8 = (*(*ctxt).input).cur;
        let mut c: u8 = 0;
        let mut val: u32 = 0;
        c = *cur;
        if c as i32 & 0x80 as i32 != 0 {
            if !(c as i32 & 0x40 as i32 == 0 as i32
                || c as i32 == 0xc0 as i32)
            {
                if *cur.offset(1 as i32 as isize) as i32
                    == 0 as i32
                {
                    xmlParserInputGrow((*ctxt).input, 250 as i32);
                    cur = (*(*ctxt).input).cur;
                }
                if !(*cur.offset(1 as i32 as isize) as i32
                    & 0xc0 as i32 != 0x80 as i32)
                {
                    if c as i32 & 0xe0 as i32 == 0xe0 as i32 {
                        if *cur.offset(2 as i32 as isize) as i32
                            == 0 as i32
                        {
                            xmlParserInputGrow((*ctxt).input, 250 as i32);
                            cur = (*(*ctxt).input).cur;
                        }
                        if *cur.offset(2 as i32 as isize) as i32
                            & 0xc0 as i32 != 0x80 as i32
                        {
                            current_block = 2938061015511697447;
                        } else if c as i32 & 0xf0 as i32
                                == 0xf0 as i32
                            {
                            if *cur.offset(3 as i32 as isize) as i32
                                == 0 as i32
                            {
                                xmlParserInputGrow((*ctxt).input, 250 as i32);
                                cur = (*(*ctxt).input).cur;
                            }
                            if c as i32 & 0xf8 as i32
                                != 0xf0 as i32
                                || *cur.offset(3 as i32 as isize) as i32
                                    & 0xc0 as i32 != 0x80 as i32
                            {
                                current_block = 2938061015511697447;
                            } else {
                                *len = 4 as i32;
                                val = ((*cur.offset(0 as i32 as isize)
                                    as i32 & 0x7 as i32) << 18 as i32)
                                    as u32;
                                val
                                    |= ((*cur.offset(1 as i32 as isize) as i32
                                        & 0x3f as i32) << 12 as i32)
                                        as u32;
                                val
                                    |= ((*cur.offset(2 as i32 as isize) as i32
                                        & 0x3f as i32) << 6 as i32) as u32;
                                val
                                    |= (*cur.offset(3 as i32 as isize) as i32
                                        & 0x3f as i32) as u32;
                                if val < 0x10000 as i32 as u32 {
                                    current_block = 2938061015511697447;
                                } else {
                                    current_block = 3938820862080741272;
                                }
                            }
                        } else {
                            *len = 3 as i32;
                            val = ((*cur.offset(0 as i32 as isize) as i32
                                & 0xf as i32) << 12 as i32) as u32;
                            val
                                |= ((*cur.offset(1 as i32 as isize) as i32
                                    & 0x3f as i32) << 6 as i32) as u32;
                            val
                                |= (*cur.offset(2 as i32 as isize) as i32
                                    & 0x3f as i32) as u32;
                            if val < 0x800 as i32 as u32 {
                                current_block = 2938061015511697447;
                            } else {
                                current_block = 3938820862080741272;
                            }
                        }
                    } else {
                        *len = 2 as i32;
                        val = ((*cur.offset(0 as i32 as isize) as i32
                            & 0x1f as i32) << 6 as i32) as u32;
                        val
                            |= (*cur.offset(1 as i32 as isize) as i32
                                & 0x3f as i32) as u32;
                        if val < 0x80 as i32 as u32 {
                            current_block = 2938061015511697447;
                        } else {
                            current_block = 3938820862080741272;
                        }
                    }
                    match current_block {
                        2938061015511697447 => {}
                        _ => {
                            if if val < 0x100 as i32 as u32 {
                                (0x9 as i32 as u32 <= val
                                    && val <= 0xa as i32 as u32
                                    || val == 0xd as i32 as u32
                                    || 0x20 as i32 as u32 <= val)
                                    as i32
                            } else {
                                (0x100 as i32 as u32 <= val
                                    && val <= 0xd7ff as i32 as u32
                                    || 0xe000 as i32 as u32 <= val
                                        && val <= 0xfffd as i32 as u32
                                    || 0x10000 as i32 as u32 <= val
                                        && val <= 0x10ffff as i32 as u32)
                                    as i32
                            } == 0
                            {
                                xmlErrEncodingInt(
                                    ctxt,
                                    XML_ERR_INVALID_CHAR,
                                    b"Char 0x%X out of allowed range\n\0" as *const u8
                                        as *const i8,
                                    val as i32,
                                );
                            }
                            return val as i32;
                        }
                    }
                }
            }
            if (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as i64)
                < 4 as i32 as i64
            {
                *len = 0 as i32;
                return 0 as i32;
            }
            let mut buffer: [i8; 150] = [0; 150];
            snprintf(
                &mut *buffer.as_mut_ptr().offset(0 as i32 as isize)
                    as *mut i8,
                149 as i32 as u64,
                b"Bytes: 0x%02X 0x%02X 0x%02X 0x%02X\n\0" as *const u8
                    as *const i8,
                *((*(*ctxt).input).cur).offset(0 as i32 as isize) as i32,
                *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32,
                *((*(*ctxt).input).cur).offset(2 as i32 as isize) as i32,
                *((*(*ctxt).input).cur).offset(3 as i32 as isize) as i32,
            );
            __xmlErrEncoding(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"Input is not proper UTF-8, indicate encoding !\n%s\0" as *const u8
                    as *const i8,
                buffer.as_mut_ptr() as *mut xmlChar,
                0 as *const xmlChar,
            );
            (*ctxt).charset = XML_CHAR_ENCODING_8859_1 as i32;
            *len = 1 as i32;
            return *(*(*ctxt).input).cur as i32;
        } else {
            *len = 1 as i32;
            if *(*(*ctxt).input).cur as i32 == 0 as i32 {
                xmlParserInputGrow((*ctxt).input, 250 as i32);
            }
            if *(*(*ctxt).input).cur as i32 == 0 as i32
                && (*(*ctxt).input).end > (*(*ctxt).input).cur
            {
                xmlErrEncodingInt(
                    ctxt,
                    XML_ERR_INVALID_CHAR,
                    b"Char 0x0 out of allowed range\n\0" as *const u8
                        as *const i8,
                    0 as i32,
                );
            }
            if *(*(*ctxt).input).cur as i32 == 0xd as i32 {
                if *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == 0xa as i32
                {
                    let fresh17 = &mut ((*(*ctxt).input).cur);
                    *fresh17 = (*fresh17).offset(1);
                }
                return 0xa as i32;
            }
            return *(*(*ctxt).input).cur as i32;
        }
    } else {
        *len = 1 as i32;
        if *(*(*ctxt).input).cur as i32 == 0xd as i32 {
            if *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32
                == 0xa as i32
            {
                let fresh18 = &mut ((*(*ctxt).input).cur);
                *fresh18 = (*fresh18).offset(1);
            }
            return 0xa as i32;
        }
        return *(*(*ctxt).input).cur as i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlStringCurrentChar(
    mut ctxt: xmlParserCtxtPtr,
    mut cur: *const xmlChar,
    mut len: *mut i32,
) -> i32 {
    let mut current_block: u64;
    if len.is_null() || cur.is_null() {
        return 0 as i32;
    }
    if ctxt.is_null() || (*ctxt).charset == XML_CHAR_ENCODING_UTF8 as i32 {
        let mut c: u8 = 0;
        let mut val: u32 = 0;
        c = *cur;
        if c as i32 & 0x80 as i32 != 0 {
            if !(*cur.offset(1 as i32 as isize) as i32
                & 0xc0 as i32 != 0x80 as i32)
            {
                if c as i32 & 0xe0 as i32 == 0xe0 as i32 {
                    if *cur.offset(2 as i32 as isize) as i32
                        & 0xc0 as i32 != 0x80 as i32
                    {
                        current_block = 15758567910763114451;
                    } else if c as i32 & 0xf0 as i32
                            == 0xf0 as i32
                        {
                        if c as i32 & 0xf8 as i32 != 0xf0 as i32
                            || *cur.offset(3 as i32 as isize) as i32
                                & 0xc0 as i32 != 0x80 as i32
                        {
                            current_block = 15758567910763114451;
                        } else {
                            *len = 4 as i32;
                            val = ((*cur.offset(0 as i32 as isize) as i32
                                & 0x7 as i32) << 18 as i32) as u32;
                            val
                                |= ((*cur.offset(1 as i32 as isize) as i32
                                    & 0x3f as i32) << 12 as i32)
                                    as u32;
                            val
                                |= ((*cur.offset(2 as i32 as isize) as i32
                                    & 0x3f as i32) << 6 as i32) as u32;
                            val
                                |= (*cur.offset(3 as i32 as isize) as i32
                                    & 0x3f as i32) as u32;
                            current_block = 11298138898191919651;
                        }
                    } else {
                        *len = 3 as i32;
                        val = ((*cur.offset(0 as i32 as isize) as i32
                            & 0xf as i32) << 12 as i32) as u32;
                        val
                            |= ((*cur.offset(1 as i32 as isize) as i32
                                & 0x3f as i32) << 6 as i32) as u32;
                        val
                            |= (*cur.offset(2 as i32 as isize) as i32
                                & 0x3f as i32) as u32;
                        current_block = 11298138898191919651;
                    }
                } else {
                    *len = 2 as i32;
                    val = ((*cur.offset(0 as i32 as isize) as i32
                        & 0x1f as i32) << 6 as i32) as u32;
                    val
                        |= (*cur.offset(1 as i32 as isize) as i32
                            & 0x3f as i32) as u32;
                    current_block = 11298138898191919651;
                }
                match current_block {
                    15758567910763114451 => {}
                    _ => {
                        if if val < 0x100 as i32 as u32 {
                            (0x9 as i32 as u32 <= val
                                && val <= 0xa as i32 as u32
                                || val == 0xd as i32 as u32
                                || 0x20 as i32 as u32 <= val)
                                as i32
                        } else {
                            (0x100 as i32 as u32 <= val
                                && val <= 0xd7ff as i32 as u32
                                || 0xe000 as i32 as u32 <= val
                                    && val <= 0xfffd as i32 as u32
                                || 0x10000 as i32 as u32 <= val
                                    && val <= 0x10ffff as i32 as u32)
                                as i32
                        } == 0
                        {
                            xmlErrEncodingInt(
                                ctxt,
                                XML_ERR_INVALID_CHAR,
                                b"Char 0x%X out of allowed range\n\0" as *const u8
                                    as *const i8,
                                val as i32,
                            );
                        }
                        return val as i32;
                    }
                }
            }
            if ctxt.is_null() || ((*ctxt).input).is_null()
                || (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as i64) < 4 as i32 as i64
            {
                *len = 0 as i32;
                return 0 as i32;
            }
            let mut buffer: [i8; 150] = [0; 150];
            snprintf(
                buffer.as_mut_ptr(),
                149 as i32 as u64,
                b"Bytes: 0x%02X 0x%02X 0x%02X 0x%02X\n\0" as *const u8
                    as *const i8,
                *((*(*ctxt).input).cur).offset(0 as i32 as isize) as i32,
                *((*(*ctxt).input).cur).offset(1 as i32 as isize) as i32,
                *((*(*ctxt).input).cur).offset(2 as i32 as isize) as i32,
                *((*(*ctxt).input).cur).offset(3 as i32 as isize) as i32,
            );
            __xmlErrEncoding(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"Input is not proper UTF-8, indicate encoding !\n%s\0" as *const u8
                    as *const i8,
                buffer.as_mut_ptr() as *mut xmlChar,
                0 as *const xmlChar,
            );
            *len = 1 as i32;
            return *cur as i32;
        } else {
            *len = 1 as i32;
            return *cur as i32;
        }
    } else {
        *len = 1 as i32;
        return *cur as i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyCharMultiByte(
    mut out: *mut xmlChar,
    mut val: i32,
) -> i32 {
    if out.is_null() {
        return 0 as i32;
    }
    if val >= 0x80 as i32 {
        let mut savedout: *mut xmlChar = out;
        let mut bits: i32 = 0;
        if val < 0x800 as i32 {
            let fresh19 = out;
            out = out.offset(1);
            *fresh19 = (val >> 6 as i32 | 0xc0 as i32) as xmlChar;
            bits = 0 as i32;
        } else if val < 0x10000 as i32 {
            let fresh20 = out;
            out = out.offset(1);
            *fresh20 = (val >> 12 as i32 | 0xe0 as i32) as xmlChar;
            bits = 6 as i32;
        } else if val < 0x110000 as i32 {
            let fresh21 = out;
            out = out.offset(1);
            *fresh21 = (val >> 18 as i32 | 0xf0 as i32) as xmlChar;
            bits = 12 as i32;
        } else {
            xmlErrEncodingInt(
                0 as xmlParserCtxtPtr,
                XML_ERR_INVALID_CHAR,
                b"Internal error, xmlCopyCharMultiByte 0x%X out of bound\n\0"
                    as *const u8 as *const i8,
                val,
            );
            return 0 as i32;
        }
        while bits >= 0 as i32 {
            let fresh22 = out;
            out = out.offset(1);
            *fresh22 = (val >> bits & 0x3f as i32 | 0x80 as i32)
                as xmlChar;
            bits -= 6 as i32;
        }
        return out.offset_from(savedout) as i64 as i32;
    }
    *out = val as xmlChar;
    return 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyChar(
    mut len: i32,
    mut out: *mut xmlChar,
    mut val: i32,
) -> i32 {
    if out.is_null() {
        return 0 as i32;
    }
    if val >= 0x80 as i32 {
        return xmlCopyCharMultiByte(out, val);
    }
    *out = val as xmlChar;
    return 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSwitchEncoding(
    mut ctxt: xmlParserCtxtPtr,
    mut enc: xmlCharEncoding,
) -> i32 {
    let mut handler: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
    let mut len: i32 = -(1 as i32);
    let mut ret: i32 = 0;
    if ctxt.is_null() {
        return -(1 as i32);
    }
    match enc as i32 {
        -1 => {
            __xmlErrEncoding(
                ctxt,
                XML_ERR_UNKNOWN_ENCODING,
                b"encoding unknown\n\0" as *const u8 as *const i8,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return -(1 as i32);
        }
        0 => {
            (*ctxt).charset = XML_CHAR_ENCODING_UTF8 as i32;
            return 0 as i32;
        }
        1 => {
            (*ctxt).charset = XML_CHAR_ENCODING_UTF8 as i32;
            if !((*ctxt).input).is_null()
                && *((*(*ctxt).input).cur).offset(0 as i32 as isize)
                    as i32 == 0xef as i32
                && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == 0xbb as i32
                && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                    as i32 == 0xbf as i32
            {
                let fresh23 = &mut ((*(*ctxt).input).cur);
                *fresh23 = (*fresh23).offset(3 as i32 as isize);
            }
            return 0 as i32;
        }
        2 | 3 => {
            if !((*ctxt).input).is_null() && !((*(*ctxt).input).cur).is_null()
                && *((*(*ctxt).input).cur).offset(0 as i32 as isize)
                    as i32 == 0xef as i32
                && *((*(*ctxt).input).cur).offset(1 as i32 as isize)
                    as i32 == 0xbb as i32
                && *((*(*ctxt).input).cur).offset(2 as i32 as isize)
                    as i32 == 0xbf as i32
            {
                let fresh24 = &mut ((*(*ctxt).input).cur);
                *fresh24 = (*fresh24).offset(3 as i32 as isize);
            }
            len = 90 as i32;
        }
        9 => {
            len = 90 as i32;
        }
        5 | 4 | 7 | 8 => {
            len = 180 as i32;
        }
        6 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 22 | 19 | 20 | 21 => {
            len = 45 as i32;
        }
        _ => {}
    }
    handler = xmlGetCharEncodingHandler(enc);
    if handler.is_null() {
        match enc as i32 {
            22 => {
                (*ctxt).charset = XML_CHAR_ENCODING_UTF8 as i32;
                return 0 as i32;
            }
            10 => {
                if (*ctxt).inputNr == 1 as i32 && ((*ctxt).encoding).is_null()
                    && !((*ctxt).input).is_null()
                    && !((*(*ctxt).input).encoding).is_null()
                {
                    let fresh25 = &mut ((*ctxt).encoding);
                    *fresh25 = xmlStrdup((*(*ctxt).input).encoding);
                }
                (*ctxt).charset = enc as i32;
                return 0 as i32;
            }
            _ => {
                __xmlErrEncoding(
                    ctxt,
                    XML_ERR_UNSUPPORTED_ENCODING,
                    b"encoding not supported: %s\n\0" as *const u8
                        as *const i8,
                    xmlGetCharEncodingName(enc) as *mut xmlChar,
                    0 as *const xmlChar,
                );
                xmlStopParser(ctxt);
                return -(1 as i32);
            }
        }
    }
    ret = xmlSwitchInputEncodingInt(ctxt, (*ctxt).input, handler, len);
    if ret < 0 as i32 || (*ctxt).errNo == XML_I18N_CONV_FAILED as i32 {
        xmlStopParser(ctxt);
        (*ctxt).errNo = XML_I18N_CONV_FAILED as i32;
    }
    return ret;
}
unsafe extern "C" fn xmlSwitchInputEncodingInt(
    mut ctxt: xmlParserCtxtPtr,
    mut input: xmlParserInputPtr,
    mut handler: xmlCharEncodingHandlerPtr,
    mut len: i32,
) -> i32 {
    let mut nbchars: i32 = 0;
    if handler.is_null() {
        return -(1 as i32);
    }
    if input.is_null() {
        return -(1 as i32);
    }
    if !((*input).buf).is_null() {
        (*ctxt).charset = XML_CHAR_ENCODING_UTF8 as i32;
        if !((*(*input).buf).encoder).is_null() {
            if (*(*input).buf).encoder == handler {
                return 0 as i32;
            }
            xmlCharEncCloseFunc((*(*input).buf).encoder);
            let fresh26 = &mut ((*(*input).buf).encoder);
            *fresh26 = handler;
            return 0 as i32;
        }
        let fresh27 = &mut ((*(*input).buf).encoder);
        *fresh27 = handler;
        if xmlBufIsEmpty((*(*input).buf).buffer) == 0 as i32 {
            let mut processed: i32 = 0;
            let mut use_0: u32 = 0;
            if !((*handler).name).is_null()
                && (strcmp(
                    (*handler).name,
                    b"UTF-16LE\0" as *const u8 as *const i8,
                ) == 0
                    || strcmp(
                        (*handler).name,
                        b"UTF-16\0" as *const u8 as *const i8,
                    ) == 0)
                && *((*input).cur).offset(0 as i32 as isize) as i32
                    == 0xff as i32
                && *((*input).cur).offset(1 as i32 as isize) as i32
                    == 0xfe as i32
            {
                let fresh28 = &mut ((*input).cur);
                *fresh28 = (*fresh28).offset(2 as i32 as isize);
            }
            if !((*handler).name).is_null()
                && strcmp(
                    (*handler).name,
                    b"UTF-16BE\0" as *const u8 as *const i8,
                ) == 0
                && *((*input).cur).offset(0 as i32 as isize) as i32
                    == 0xfe as i32
                && *((*input).cur).offset(1 as i32 as isize) as i32
                    == 0xff as i32
            {
                let fresh29 = &mut ((*input).cur);
                *fresh29 = (*fresh29).offset(2 as i32 as isize);
            }
            if !((*handler).name).is_null()
                && strcmp(
                    (*handler).name,
                    b"UTF-8\0" as *const u8 as *const i8,
                ) == 0
                && *((*input).cur).offset(0 as i32 as isize) as i32
                    == 0xef as i32
                && *((*input).cur).offset(1 as i32 as isize) as i32
                    == 0xbb as i32
                && *((*input).cur).offset(2 as i32 as isize) as i32
                    == 0xbf as i32
            {
                let fresh30 = &mut ((*input).cur);
                *fresh30 = (*fresh30).offset(3 as i32 as isize);
            }
            processed = ((*input).cur).offset_from((*input).base) as i64
                as i32;
            xmlBufShrink((*(*input).buf).buffer, processed as size_t);
            let fresh31 = &mut ((*(*input).buf).raw);
            *fresh31 = (*(*input).buf).buffer;
            let fresh32 = &mut ((*(*input).buf).buffer);
            *fresh32 = xmlBufCreate();
            (*(*input).buf).rawconsumed = processed as u64;
            use_0 = xmlBufUse((*(*input).buf).raw) as u32;
            if (*ctxt).html != 0 {
                nbchars = xmlCharEncInput((*input).buf, 1 as i32);
            } else {
                nbchars = xmlCharEncFirstLineInput((*input).buf, len);
            }
            xmlBufResetInput((*(*input).buf).buffer, input);
            if nbchars < 0 as i32 {
                xmlErrInternal(
                    ctxt,
                    b"switching encoding: encoder error\n\0" as *const u8
                        as *const i8,
                    0 as *const xmlChar,
                );
                return -(1 as i32);
            }
            let fresh33 = &mut ((*(*input).buf).rawconsumed);
            *fresh33 = (*fresh33)
                .wrapping_add(
                    (use_0 as u64).wrapping_sub(xmlBufUse((*(*input).buf).raw)),
                );
        }
        return 0 as i32;
    } else {
        xmlErrInternal(
            ctxt,
            b"static memory buffer doesn't support encoding\n\0" as *const u8
                as *const i8,
            0 as *const xmlChar,
        );
        xmlCharEncCloseFunc(handler);
        return -(1 as i32);
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlSwitchInputEncoding(
    mut ctxt: xmlParserCtxtPtr,
    mut input: xmlParserInputPtr,
    mut handler: xmlCharEncodingHandlerPtr,
) -> i32 {
    return xmlSwitchInputEncodingInt(ctxt, input, handler, -(1 as i32));
}
#[no_mangle]
pub unsafe extern "C" fn xmlSwitchToEncoding(
    mut ctxt: xmlParserCtxtPtr,
    mut handler: xmlCharEncodingHandlerPtr,
) -> i32 {
    if ctxt.is_null() {
        return -(1 as i32);
    }
    return xmlSwitchInputEncodingInt(ctxt, (*ctxt).input, handler, -(1 as i32));
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeInputStream(mut input: xmlParserInputPtr) {
    if input.is_null() {
        return;
    }
    if !((*input).filename).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*input).filename as *mut i8 as *mut libc::c_void);
    }
    if !((*input).directory).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*input).directory as *mut i8 as *mut libc::c_void);
    }
    if !((*input).encoding).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*input).encoding as *mut i8 as *mut libc::c_void);
    }
    if !((*input).version).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*input).version as *mut i8 as *mut libc::c_void);
    }
    if ((*input).free).is_some() && !((*input).base).is_null() {
        ((*input).free)
            .expect("non-null function pointer")((*input).base as *mut xmlChar);
    }
    if !((*input).buf).is_null() {
        xmlFreeParserInputBuffer((*input).buf);
    }
    xmlFree.expect("non-null function pointer")(input as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewInputStream(
    mut ctxt: xmlParserCtxtPtr,
) -> xmlParserInputPtr {
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    input = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlParserInput>() as u64) as xmlParserInputPtr;
    if input.is_null() {
        xmlErrMemory(
            ctxt,
            b"couldn't allocate a new input stream\n\0" as *const u8
                as *const i8,
        );
        return 0 as xmlParserInputPtr;
    }
    memset(
        input as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlParserInput>() as u64,
    );
    (*input).line = 1 as i32;
    (*input).col = 1 as i32;
    (*input).standalone = -(1 as i32);
    if !ctxt.is_null() {
        let fresh34 = &mut ((*ctxt).input_id);
        let fresh35 = *fresh34;
        *fresh34 = *fresh34 + 1;
        (*input).id = fresh35;
    }
    return input;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewIOInputStream(
    mut ctxt: xmlParserCtxtPtr,
    mut input: xmlParserInputBufferPtr,
    mut enc: xmlCharEncoding,
) -> xmlParserInputPtr {
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if input.is_null() {
        return 0 as xmlParserInputPtr;
    }
    if *__xmlParserDebugEntities() != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"new input from I/O\n\0" as *const u8 as *const i8,
        );
    }
    inputStream = xmlNewInputStream(ctxt);
    if inputStream.is_null() {
        return 0 as xmlParserInputPtr;
    }
    let fresh36 = &mut ((*inputStream).filename);
    *fresh36 = 0 as *const i8;
    let fresh37 = &mut ((*inputStream).buf);
    *fresh37 = input;
    xmlBufResetInput((*(*inputStream).buf).buffer, inputStream);
    if enc as i32 != XML_CHAR_ENCODING_NONE as i32 {
        xmlSwitchEncoding(ctxt, enc);
    }
    return inputStream;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewEntityInputStream(
    mut ctxt: xmlParserCtxtPtr,
    mut entity: xmlEntityPtr,
) -> xmlParserInputPtr {
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if entity.is_null() {
        xmlErrInternal(
            ctxt,
            b"xmlNewEntityInputStream entity = NULL\n\0" as *const u8
                as *const i8,
            0 as *const xmlChar,
        );
        return 0 as xmlParserInputPtr;
    }
    if *__xmlParserDebugEntities() != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"new input from entity: %s\n\0" as *const u8 as *const i8,
            (*entity).name,
        );
    }
    if ((*entity).content).is_null() {
        match (*entity).etype as u32 {
            3 => {
                xmlErrInternal(
                    ctxt,
                    b"Cannot parse entity %s\n\0" as *const u8 as *const i8,
                    (*entity).name,
                );
            }
            2 | 5 => {
                return xmlLoadExternalEntity(
                    (*entity).URI as *mut i8,
                    (*entity).ExternalID as *mut i8,
                    ctxt,
                );
            }
            1 => {
                xmlErrInternal(
                    ctxt,
                    b"Internal entity %s without content !\n\0" as *const u8
                        as *const i8,
                    (*entity).name,
                );
            }
            4 => {
                xmlErrInternal(
                    ctxt,
                    b"Internal parameter entity %s without content !\n\0" as *const u8
                        as *const i8,
                    (*entity).name,
                );
            }
            6 => {
                xmlErrInternal(
                    ctxt,
                    b"Predefined entity %s without content !\n\0" as *const u8
                        as *const i8,
                    (*entity).name,
                );
            }
            _ => {}
        }
        return 0 as xmlParserInputPtr;
    }
    input = xmlNewInputStream(ctxt);
    if input.is_null() {
        return 0 as xmlParserInputPtr;
    }
    if !((*entity).URI).is_null() {
        let fresh38 = &mut ((*input).filename);
        *fresh38 = xmlStrdup((*entity).URI as *mut xmlChar) as *mut i8;
    }
    let fresh39 = &mut ((*input).base);
    *fresh39 = (*entity).content;
    if (*entity).length == 0 as i32 {
        (*entity).length = xmlStrlen((*entity).content);
    }
    let fresh40 = &mut ((*input).cur);
    *fresh40 = (*entity).content;
    (*input).length = (*entity).length;
    let fresh41 = &mut ((*input).end);
    *fresh41 = &mut *((*entity).content).offset((*input).length as isize)
        as *mut xmlChar;
    return input;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewStringInputStream(
    mut ctxt: xmlParserCtxtPtr,
    mut buffer: *const xmlChar,
) -> xmlParserInputPtr {
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if buffer.is_null() {
        xmlErrInternal(
            ctxt,
            b"xmlNewStringInputStream string = NULL\n\0" as *const u8
                as *const i8,
            0 as *const xmlChar,
        );
        return 0 as xmlParserInputPtr;
    }
    if *__xmlParserDebugEntities() != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"new fixed input: %.30s\n\0" as *const u8 as *const i8,
            buffer,
        );
    }
    input = xmlNewInputStream(ctxt);
    if input.is_null() {
        xmlErrMemory(
            ctxt,
            b"couldn't allocate a new input stream\n\0" as *const u8
                as *const i8,
        );
        return 0 as xmlParserInputPtr;
    }
    let fresh42 = &mut ((*input).base);
    *fresh42 = buffer;
    let fresh43 = &mut ((*input).cur);
    *fresh43 = buffer;
    (*input).length = xmlStrlen(buffer);
    let fresh44 = &mut ((*input).end);
    *fresh44 = &*buffer.offset((*input).length as isize) as *const xmlChar;
    return input;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewInputFromFile(
    mut ctxt: xmlParserCtxtPtr,
    mut filename: *const i8,
) -> xmlParserInputPtr {
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut directory: *mut i8 = 0 as *mut i8;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    if *__xmlParserDebugEntities() != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"new input from file: %s\n\0" as *const u8 as *const i8,
            filename,
        );
    }
    if ctxt.is_null() {
        return 0 as xmlParserInputPtr;
    }
    buf = xmlParserInputBufferCreateFilename(filename, XML_CHAR_ENCODING_NONE);
    if buf.is_null() {
        if filename.is_null() {
            __xmlLoaderErr(
                ctxt as *mut libc::c_void,
                b"failed to load external entity: NULL filename \n\0" as *const u8
                    as *const i8,
                0 as *const i8,
            );
        } else {
            __xmlLoaderErr(
                ctxt as *mut libc::c_void,
                b"failed to load external entity \"%s\"\n\0" as *const u8
                    as *const i8,
                filename,
            );
        }
        return 0 as xmlParserInputPtr;
    }
    inputStream = xmlNewInputStream(ctxt);
    if inputStream.is_null() {
        xmlFreeParserInputBuffer(buf);
        return 0 as xmlParserInputPtr;
    }
    let fresh45 = &mut ((*inputStream).buf);
    *fresh45 = buf;
    inputStream = xmlCheckHTTPInput(ctxt, inputStream);
    if inputStream.is_null() {
        return 0 as xmlParserInputPtr;
    }
    if ((*inputStream).filename).is_null() {
        URI = xmlStrdup(filename as *mut xmlChar);
    } else {
        URI = xmlStrdup((*inputStream).filename as *mut xmlChar);
    }
    directory = xmlParserGetDirectory(URI as *const i8);
    if !((*inputStream).filename).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*inputStream).filename as *mut i8 as *mut libc::c_void);
    }
    let fresh46 = &mut ((*inputStream).filename);
    *fresh46 = xmlCanonicPath(URI as *const xmlChar) as *mut i8;
    if !URI.is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )(URI as *mut i8 as *mut libc::c_void);
    }
    let fresh47 = &mut ((*inputStream).directory);
    *fresh47 = directory;
    xmlBufResetInput((*(*inputStream).buf).buffer, inputStream);
    if ((*ctxt).directory).is_null() && !directory.is_null() {
        let fresh48 = &mut ((*ctxt).directory);
        *fresh48 = xmlStrdup(directory as *const xmlChar) as *mut i8;
    }
    return inputStream;
}
#[no_mangle]
pub unsafe extern "C" fn xmlInitParserCtxt(mut ctxt: xmlParserCtxtPtr) -> i32 {
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ctxt.is_null() {
        xmlErrInternal(
            0 as xmlParserCtxtPtr,
            b"Got NULL parser context\n\0" as *const u8 as *const i8,
            0 as *const xmlChar,
        );
        return -(1 as i32);
    }
    xmlInitParser();
    if ((*ctxt).dict).is_null() {
        let fresh49 = &mut ((*ctxt).dict);
        *fresh49 = xmlDictCreate();
    }
    if ((*ctxt).dict).is_null() {
        xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"cannot initialize parser context\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    xmlDictSetLimit((*ctxt).dict, 10000000 as i32 as size_t);
    if ((*ctxt).sax).is_null() {
        let fresh50 = &mut ((*ctxt).sax);
        *fresh50 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlSAXHandler>() as u64)
            as *mut xmlSAXHandler;
    }
    if ((*ctxt).sax).is_null() {
        xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"cannot initialize parser context\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    } else {
        xmlSAXVersion((*ctxt).sax, 2 as i32);
    }
    (*ctxt).maxatts = 0 as i32;
    let fresh51 = &mut ((*ctxt).atts);
    *fresh51 = 0 as *mut *const xmlChar;
    if ((*ctxt).inputTab).is_null() {
        let fresh52 = &mut ((*ctxt).inputTab);
        *fresh52 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            (5 as i32 as u64)
                .wrapping_mul(
                    ::std::mem::size_of::<xmlParserInputPtr>() as u64,
                ),
        ) as *mut xmlParserInputPtr;
        (*ctxt).inputMax = 5 as i32;
    }
    if ((*ctxt).inputTab).is_null() {
        xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"cannot initialize parser context\n\0" as *const u8 as *const i8,
        );
        (*ctxt).inputNr = 0 as i32;
        (*ctxt).inputMax = 0 as i32;
        let fresh53 = &mut ((*ctxt).input);
        *fresh53 = 0 as xmlParserInputPtr;
        return -(1 as i32);
    }
    loop {
        input = inputPop(ctxt);
        if input.is_null() {
            break;
        }
        xmlFreeInputStream(input);
    }
    (*ctxt).inputNr = 0 as i32;
    let fresh54 = &mut ((*ctxt).input);
    *fresh54 = 0 as xmlParserInputPtr;
    let fresh55 = &mut ((*ctxt).version);
    *fresh55 = 0 as *const xmlChar;
    let fresh56 = &mut ((*ctxt).encoding);
    *fresh56 = 0 as *const xmlChar;
    (*ctxt).standalone = -(1 as i32);
    (*ctxt).hasExternalSubset = 0 as i32;
    (*ctxt).hasPErefs = 0 as i32;
    (*ctxt).html = 0 as i32;
    (*ctxt).external = 0 as i32;
    (*ctxt).instate = XML_PARSER_START;
    (*ctxt).token = 0 as i32;
    let fresh57 = &mut ((*ctxt).directory);
    *fresh57 = 0 as *mut i8;
    if ((*ctxt).nodeTab).is_null() {
        let fresh58 = &mut ((*ctxt).nodeTab);
        *fresh58 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            (10 as i32 as u64)
                .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
        ) as *mut xmlNodePtr;
        (*ctxt).nodeMax = 10 as i32;
    }
    if ((*ctxt).nodeTab).is_null() {
        xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"cannot initialize parser context\n\0" as *const u8 as *const i8,
        );
        (*ctxt).nodeNr = 0 as i32;
        (*ctxt).nodeMax = 0 as i32;
        let fresh59 = &mut ((*ctxt).node);
        *fresh59 = 0 as xmlNodePtr;
        (*ctxt).inputNr = 0 as i32;
        (*ctxt).inputMax = 0 as i32;
        let fresh60 = &mut ((*ctxt).input);
        *fresh60 = 0 as xmlParserInputPtr;
        return -(1 as i32);
    }
    (*ctxt).nodeNr = 0 as i32;
    let fresh61 = &mut ((*ctxt).node);
    *fresh61 = 0 as xmlNodePtr;
    if ((*ctxt).nameTab).is_null() {
        let fresh62 = &mut ((*ctxt).nameTab);
        *fresh62 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            (10 as i32 as u64)
                .wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as u64),
        ) as *mut *const xmlChar;
        (*ctxt).nameMax = 10 as i32;
    }
    if ((*ctxt).nameTab).is_null() {
        xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"cannot initialize parser context\n\0" as *const u8 as *const i8,
        );
        (*ctxt).nodeNr = 0 as i32;
        (*ctxt).nodeMax = 0 as i32;
        let fresh63 = &mut ((*ctxt).node);
        *fresh63 = 0 as xmlNodePtr;
        (*ctxt).inputNr = 0 as i32;
        (*ctxt).inputMax = 0 as i32;
        let fresh64 = &mut ((*ctxt).input);
        *fresh64 = 0 as xmlParserInputPtr;
        (*ctxt).nameNr = 0 as i32;
        (*ctxt).nameMax = 0 as i32;
        let fresh65 = &mut ((*ctxt).name);
        *fresh65 = 0 as *const xmlChar;
        return -(1 as i32);
    }
    (*ctxt).nameNr = 0 as i32;
    let fresh66 = &mut ((*ctxt).name);
    *fresh66 = 0 as *const xmlChar;
    if ((*ctxt).spaceTab).is_null() {
        let fresh67 = &mut ((*ctxt).spaceTab);
        *fresh67 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            (10 as i32 as u64)
                .wrapping_mul(::std::mem::size_of::<i32>() as u64),
        ) as *mut i32;
        (*ctxt).spaceMax = 10 as i32;
    }
    if ((*ctxt).spaceTab).is_null() {
        xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"cannot initialize parser context\n\0" as *const u8 as *const i8,
        );
        (*ctxt).nodeNr = 0 as i32;
        (*ctxt).nodeMax = 0 as i32;
        let fresh68 = &mut ((*ctxt).node);
        *fresh68 = 0 as xmlNodePtr;
        (*ctxt).inputNr = 0 as i32;
        (*ctxt).inputMax = 0 as i32;
        let fresh69 = &mut ((*ctxt).input);
        *fresh69 = 0 as xmlParserInputPtr;
        (*ctxt).nameNr = 0 as i32;
        (*ctxt).nameMax = 0 as i32;
        let fresh70 = &mut ((*ctxt).name);
        *fresh70 = 0 as *const xmlChar;
        (*ctxt).spaceNr = 0 as i32;
        (*ctxt).spaceMax = 0 as i32;
        let fresh71 = &mut ((*ctxt).space);
        *fresh71 = 0 as *mut i32;
        return -(1 as i32);
    }
    (*ctxt).spaceNr = 1 as i32;
    (*ctxt).spaceMax = 10 as i32;
    *((*ctxt).spaceTab).offset(0 as i32 as isize) = -(1 as i32);
    let fresh72 = &mut ((*ctxt).space);
    *fresh72 = &mut *((*ctxt).spaceTab).offset(0 as i32 as isize)
        as *mut i32;
    let fresh73 = &mut ((*ctxt).userData);
    *fresh73 = ctxt as *mut libc::c_void;
    let fresh74 = &mut ((*ctxt).myDoc);
    *fresh74 = 0 as xmlDocPtr;
    (*ctxt).wellFormed = 1 as i32;
    (*ctxt).nsWellFormed = 1 as i32;
    (*ctxt).valid = 1 as i32;
    (*ctxt).loadsubset = *__xmlLoadExtDtdDefaultValue();
    if (*ctxt).loadsubset != 0 {
        (*ctxt).options |= XML_PARSE_DTDLOAD as i32;
    }
    (*ctxt).validate = *__xmlDoValidityCheckingDefaultValue();
    (*ctxt).pedantic = *__xmlPedanticParserDefaultValue();
    if (*ctxt).pedantic != 0 {
        (*ctxt).options |= XML_PARSE_PEDANTIC as i32;
    }
    (*ctxt).linenumbers = *__xmlLineNumbersDefaultValue();
    (*ctxt).keepBlanks = *__xmlKeepBlanksDefaultValue();
    if (*ctxt).keepBlanks == 0 as i32 {
        let fresh75 = &mut ((*(*ctxt).sax).ignorableWhitespace);
        *fresh75 = Some(
            xmlSAX2IgnorableWhitespace
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const xmlChar,
                    i32,
                ) -> (),
        );
        (*ctxt).options |= XML_PARSE_NOBLANKS as i32;
    }
    (*ctxt).vctxt.flags = (1 as u32) << 1 as i32;
    let fresh76 = &mut ((*ctxt).vctxt.userData);
    *fresh76 = ctxt as *mut libc::c_void;
    let fresh77 = &mut ((*ctxt).vctxt.error);
    *fresh77 = Some(
        xmlParserValidityError
            as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
    );
    let fresh78 = &mut ((*ctxt).vctxt.warning);
    *fresh78 = Some(
        xmlParserValidityWarning
            as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
    );
    if (*ctxt).validate != 0 {
        if *__xmlGetWarningsDefaultValue() == 0 as i32 {
            let fresh79 = &mut ((*ctxt).vctxt.warning);
            *fresh79 = None;
        } else {
            let fresh80 = &mut ((*ctxt).vctxt.warning);
            *fresh80 = Some(
                xmlParserValidityWarning
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const i8,
                        ...
                    ) -> (),
            );
        }
        (*ctxt).vctxt.nodeMax = 0 as i32;
        (*ctxt).options |= XML_PARSE_DTDVALID as i32;
    }
    (*ctxt).replaceEntities = *__xmlSubstituteEntitiesDefaultValue();
    if (*ctxt).replaceEntities != 0 {
        (*ctxt).options |= XML_PARSE_NOENT as i32;
    }
    (*ctxt).record_info = 0 as i32;
    (*ctxt).checkIndex = 0 as i32 as i64;
    (*ctxt).inSubset = 0 as i32;
    (*ctxt).errNo = XML_ERR_OK as i32;
    (*ctxt).depth = 0 as i32;
    (*ctxt).charset = XML_CHAR_ENCODING_UTF8 as i32;
    let fresh81 = &mut ((*ctxt).catalogs);
    *fresh81 = 0 as *mut libc::c_void;
    (*ctxt).nbentities = 0 as i32 as u64;
    (*ctxt).sizeentities = 0 as i32 as u64;
    (*ctxt).sizeentcopy = 0 as i32 as u64;
    (*ctxt).input_id = 1 as i32;
    xmlInitNodeInfoSeq(&mut (*ctxt).node_seq);
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeParserCtxt(mut ctxt: xmlParserCtxtPtr) {
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ctxt.is_null() {
        return;
    }
    loop {
        input = inputPop(ctxt);
        if input.is_null() {
            break;
        }
        xmlFreeInputStream(input);
    }
    if !((*ctxt).spaceTab).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).spaceTab as *mut libc::c_void);
    }
    if !((*ctxt).nameTab).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).nameTab as *mut *mut xmlChar as *mut libc::c_void);
    }
    if !((*ctxt).nodeTab).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).nodeTab as *mut libc::c_void);
    }
    if !((*ctxt).nodeInfoTab).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).nodeInfoTab as *mut libc::c_void);
    }
    if !((*ctxt).inputTab).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).inputTab as *mut libc::c_void);
    }
    if !((*ctxt).version).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).version as *mut i8 as *mut libc::c_void);
    }
    if !((*ctxt).encoding).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).encoding as *mut i8 as *mut libc::c_void);
    }
    if !((*ctxt).extSubURI).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).extSubURI as *mut i8 as *mut libc::c_void);
    }
    if !((*ctxt).extSubSystem).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).extSubSystem as *mut i8 as *mut libc::c_void);
    }
    if !((*ctxt).sax).is_null()
        && (*ctxt).sax != __xmlDefaultSAXHandler() as xmlSAXHandlerPtr
    {
        xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
    }
    if !((*ctxt).directory).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).directory as *mut libc::c_void);
    }
    if !((*ctxt).vctxt.nodeTab).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).vctxt.nodeTab as *mut libc::c_void);
    }
    if !((*ctxt).atts).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).atts as *mut *mut xmlChar as *mut libc::c_void);
    }
    if !((*ctxt).dict).is_null() {
        xmlDictFree((*ctxt).dict);
    }
    if !((*ctxt).nsTab).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).nsTab as *mut i8 as *mut libc::c_void);
    }
    if !((*ctxt).pushTab).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).pushTab as *mut libc::c_void);
    }
    if !((*ctxt).attallocs).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).attallocs as *mut libc::c_void);
    }
    if !((*ctxt).attsDefault).is_null() {
        xmlHashFree(
            (*ctxt).attsDefault,
            Some(
                xmlHashDefaultDeallocator
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
        );
    }
    if !((*ctxt).attsSpecial).is_null() {
        xmlHashFree((*ctxt).attsSpecial, None);
    }
    if !((*ctxt).freeElems).is_null() {
        let mut cur: xmlNodePtr = 0 as *mut xmlNode;
        let mut next: xmlNodePtr = 0 as *mut xmlNode;
        cur = (*ctxt).freeElems;
        while !cur.is_null() {
            next = (*cur).next;
            xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
            cur = next;
        }
    }
    if !((*ctxt).freeAttrs).is_null() {
        let mut cur_0: xmlAttrPtr = 0 as *mut xmlAttr;
        let mut next_0: xmlAttrPtr = 0 as *mut xmlAttr;
        cur_0 = (*ctxt).freeAttrs;
        while !cur_0.is_null() {
            next_0 = (*cur_0).next;
            xmlFree.expect("non-null function pointer")(cur_0 as *mut libc::c_void);
            cur_0 = next_0;
        }
    }
    if !((*ctxt).lastError.message).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).lastError.message as *mut libc::c_void);
    }
    if !((*ctxt).lastError.file).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).lastError.file as *mut libc::c_void);
    }
    if !((*ctxt).lastError.str1).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).lastError.str1 as *mut libc::c_void);
    }
    if !((*ctxt).lastError.str2).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).lastError.str2 as *mut libc::c_void);
    }
    if !((*ctxt).lastError.str3).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).lastError.str3 as *mut libc::c_void);
    }
    if !((*ctxt).catalogs).is_null() {
        xmlCatalogFreeLocal((*ctxt).catalogs);
    }
    xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewParserCtxt() -> xmlParserCtxtPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    ctxt = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlParserCtxt>() as u64) as xmlParserCtxtPtr;
    if ctxt.is_null() {
        xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"cannot allocate parser context\n\0" as *const u8 as *const i8,
        );
        return 0 as xmlParserCtxtPtr;
    }
    memset(
        ctxt as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlParserCtxt>() as u64,
    );
    if xmlInitParserCtxt(ctxt) < 0 as i32 {
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlParserCtxtPtr;
    }
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn xmlClearParserCtxt(mut ctxt: xmlParserCtxtPtr) {
    if ctxt.is_null() {
        return;
    }
    xmlClearNodeInfoSeq(&mut (*ctxt).node_seq);
    xmlCtxtReset(ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserFindNodeInfo(
  mut  ctx: xmlParserCtxtPtr,
    node: xmlNodePtr,
) -> *const xmlParserNodeInfo {
    let mut pos: u64 = 0;
    if ctx.is_null() || node.is_null() {
        return 0 as *const xmlParserNodeInfo;
    }
    pos = xmlParserFindNodeInfoIndex(&mut (*ctx).node_seq, node);
    if pos < (*ctx).node_seq.length
        && (*((*ctx).node_seq.buffer).offset(pos as isize)).node
            == node as *const _xmlNode
    {
        return &mut *((*ctx).node_seq.buffer).offset(pos as isize)
            as *mut xmlParserNodeInfo
    } else {
        return 0 as *const xmlParserNodeInfo
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlInitNodeInfoSeq(mut seq: xmlParserNodeInfoSeqPtr) {
    if seq.is_null() {
        return;
    }
    (*seq).length = 0 as i32 as u64;
    (*seq).maximum = 0 as i32 as u64;
    let fresh82 = &mut ((*seq).buffer);
    *fresh82 = 0 as *mut xmlParserNodeInfo;
}
#[no_mangle]
pub unsafe extern "C" fn xmlClearNodeInfoSeq(mut seq: xmlParserNodeInfoSeqPtr) {
    if seq.is_null() {
        return;
    }
    if !((*seq).buffer).is_null() {
        xmlFree.expect("non-null function pointer")((*seq).buffer as *mut libc::c_void);
    }
    xmlInitNodeInfoSeq(seq);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserFindNodeInfoIndex(
  mut  seq: xmlParserNodeInfoSeqPtr,
    node: xmlNodePtr,
) -> u64 {
    let mut upper: u64 = 0;
    let mut lower: u64 = 0;
    let mut middle: u64 = 0;
    let mut found: i32 = 0 as i32;
    if seq.is_null() || node.is_null() {
        return -(1 as i32) as u64;
    }
    lower = 1 as i32 as u64;
    upper = (*seq).length;
    middle = 0 as i32 as u64;
    while lower <= upper && found == 0 {
        middle = lower
            .wrapping_add(
                upper.wrapping_sub(lower).wrapping_div(2 as i32 as u64),
            );
        if node
            == (*((*seq).buffer)
                .offset(middle.wrapping_sub(1 as i32 as u64) as isize))
                .node as xmlNodePtr
        {
            found = 1 as i32;
        } else if node
                < (*((*seq).buffer)
                    .offset(
                        middle.wrapping_sub(1 as i32 as u64) as isize,
                    ))
                    .node as xmlNodePtr
            {
            upper = middle.wrapping_sub(1 as i32 as u64);
        } else {
            lower = middle.wrapping_add(1 as i32 as u64);
        }
    }
    if middle == 0 as i32 as u64
        || (*((*seq).buffer)
            .offset(middle.wrapping_sub(1 as i32 as u64) as isize))
            .node < node as *const _xmlNode
    {
        return middle
    } else {
        return middle.wrapping_sub(1 as i32 as u64)
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserAddNodeInfo(
    mut ctxt: xmlParserCtxtPtr,
    info: xmlParserNodeInfoPtr,
) {
    let mut pos: u64 = 0;
    if ctxt.is_null() || info.is_null() {
        return;
    }
    pos = xmlParserFindNodeInfoIndex(&mut (*ctxt).node_seq, (*info).node as xmlNodePtr);
    if pos < (*ctxt).node_seq.length && !((*ctxt).node_seq.buffer).is_null()
        && (*((*ctxt).node_seq.buffer).offset(pos as isize)).node == (*info).node
    {
        *((*ctxt).node_seq.buffer).offset(pos as isize) = *info;
    } else {
        if ((*ctxt).node_seq.length).wrapping_add(1 as i32 as u64)
            > (*ctxt).node_seq.maximum || ((*ctxt).node_seq.buffer).is_null()
        {
            let mut tmp_buffer: *mut xmlParserNodeInfo = 0 as *mut xmlParserNodeInfo;
            let mut byte_size: u32 = 0;
            if (*ctxt).node_seq.maximum == 0 as i32 as u64 {
                (*ctxt).node_seq.maximum = 2 as i32 as u64;
            }
            byte_size = (::std::mem::size_of::<xmlParserNodeInfo>() as u64)
                .wrapping_mul(
                    (2 as i32 as u64)
                        .wrapping_mul((*ctxt).node_seq.maximum),
                ) as u32;
            if ((*ctxt).node_seq.buffer).is_null() {
                tmp_buffer = xmlMalloc
                    .expect("non-null function pointer")(byte_size as size_t)
                    as *mut xmlParserNodeInfo;
            } else {
                tmp_buffer = xmlRealloc
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).node_seq.buffer as *mut libc::c_void, byte_size as size_t)
                    as *mut xmlParserNodeInfo;
            }
            if tmp_buffer.is_null() {
                xmlErrMemory(
                    ctxt,
                    b"failed to allocate buffer\n\0" as *const u8 as *const i8,
                );
                return;
            }
            let fresh83 = &mut ((*ctxt).node_seq.buffer);
            *fresh83 = tmp_buffer;
            let fresh84 = &mut ((*ctxt).node_seq.maximum);
            *fresh84 = (*fresh84).wrapping_mul(2 as i32 as u64);
        }
        if pos != (*ctxt).node_seq.length {
            let mut i: u64 = 0;
            i = (*ctxt).node_seq.length;
            while i > pos {
                *((*ctxt).node_seq.buffer)
                    .offset(
                        i as isize,
                    ) = *((*ctxt).node_seq.buffer)
                    .offset(i.wrapping_sub(1 as i32 as u64) as isize);
                i = i.wrapping_sub(1);
            }
        }
        *((*ctxt).node_seq.buffer).offset(pos as isize) = *info;
        let fresh85 = &mut ((*ctxt).node_seq.length);
        *fresh85 = (*fresh85).wrapping_add(1);
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlPedanticParserDefault(mut val: i32) -> i32 {
    let mut old: i32 = *__xmlPedanticParserDefaultValue();
    *__xmlPedanticParserDefaultValue() = val;
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn xmlLineNumbersDefault(mut val: i32) -> i32 {
    let mut old: i32 = *__xmlLineNumbersDefaultValue();
    *__xmlLineNumbersDefaultValue() = val;
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSubstituteEntitiesDefault(
    mut val: i32,
) -> i32 {
    let mut old: i32 = *__xmlSubstituteEntitiesDefaultValue();
    *__xmlSubstituteEntitiesDefaultValue() = val;
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn xmlKeepBlanksDefault(mut val: i32) -> i32 {
    let mut old: i32 = *__xmlKeepBlanksDefaultValue();
    *__xmlKeepBlanksDefaultValue() = val;
    if val == 0 {
        *__xmlIndentTreeOutput() = 1 as i32;
    }
    return old;
}
