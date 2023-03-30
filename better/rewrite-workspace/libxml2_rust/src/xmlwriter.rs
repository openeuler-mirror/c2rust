use ::libc;
extern "C" {
    
    
    
    
    
    
    
    
    
    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::std::ffi::VaList,
    ) -> libc::c_int;
    
    
    
    
    
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    static mut xmlMalloc: xmlMallocFunc;
    static mut xmlFree: xmlFreeFunc;
    
    
    
    
    
}
pub use crate::src::HTMLparser::htmlNewDocNoDtD;
pub use crate::src::SAX2::xmlSAX2EndElement;
pub use crate::src::SAX2::xmlSAX2InitDefaultSAXHandler;
pub use crate::src::SAX2::xmlSAX2StartElement;
pub use crate::src::buf::xmlBufCreateSize;
pub use crate::src::encoding::xmlCharEncOutput;
pub use crate::src::encoding::xmlFindCharEncodingHandler;
pub use crate::src::entities::xmlEncodeSpecialChars;
pub use crate::src::error::__xmlRaiseError;
pub use crate::src::list::xmlLinkGetData;
pub use crate::src::list::xmlListCreate;
pub use crate::src::list::xmlListDelete;
pub use crate::src::list::xmlListEmpty;
pub use crate::src::list::xmlListFront;
pub use crate::src::list::xmlListPopFront;
pub use crate::src::list::xmlListPushFront;
pub use crate::src::list::xmlListSearch;
pub use crate::src::list::xmlListSize;
pub use crate::src::parser::xmlCreatePushParserCtxt;
pub use crate::src::parser::xmlParseChunk;
pub use crate::src::parserInternals::xmlFreeParserCtxt;
pub use crate::src::tree::xmlFreeDoc;
pub use crate::src::tree::xmlNewDoc;
pub use crate::src::tree::xmlSetDocCompressMode;
pub use crate::src::uri::xmlCanonicPath;
pub use crate::src::xmlIO::xmlOutputBufferClose;
pub use crate::src::xmlIO::xmlOutputBufferCreateBuffer;
pub use crate::src::xmlIO::xmlOutputBufferCreateFilename;
pub use crate::src::xmlIO::xmlOutputBufferCreateIO;
pub use crate::src::xmlIO::xmlOutputBufferFlush;
pub use crate::src::xmlIO::xmlOutputBufferWrite;
pub use crate::src::xmlIO::xmlOutputBufferWriteString;
pub use crate::src::xmlsave::xmlBufAttrSerializeTxtContent;
pub use crate::src::xmlstring::xmlStrcasecmp;
pub use crate::src::xmlstring::xmlStrcat;
pub use crate::src::xmlstring::xmlStrcmp;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrlen;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::list::_xmlLink;
pub use crate::src::list::_xmlList;
pub use crate::src::parser::_xmlStartTag;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::error::__builtin_va_list;
// #[derive(Copy, Clone)]

pub use crate::src::error::__va_list_tag;
pub use crate::src::error::va_list;
pub use crate::src::HTMLparser::xmlChar;
pub use crate::src::HTMLparser::size_t;
pub use crate::src::HTMLparser::xmlFreeFunc;
pub use crate::src::HTMLparser::xmlMallocFunc;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserInputBuffer;
pub use crate::src::HTMLparser::xmlBufPtr;
pub use crate::src::HTMLparser::xmlBuf;
pub use crate::src::HTMLparser::xmlCharEncodingHandlerPtr;
pub use crate::src::HTMLparser::xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlCharEncodingHandler;
pub use crate::src::HTMLparser::iconv_t;
pub use crate::src::HTMLparser::xmlCharEncodingOutputFunc;
pub use crate::src::HTMLparser::xmlCharEncodingInputFunc;
pub use crate::src::HTMLparser::xmlInputCloseCallback;
pub use crate::src::HTMLparser::xmlInputReadCallback;
pub use crate::src::HTMLparser::xmlParserInputBuffer;
pub use crate::src::HTMLparser::xmlParserInputBufferPtr;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLtree::_xmlOutputBuffer;
pub use crate::src::HTMLtree::xmlOutputCloseCallback;
pub use crate::src::HTMLtree::xmlOutputWriteCallback;
pub use crate::src::HTMLtree::xmlOutputBuffer;
pub use crate::src::HTMLtree::xmlOutputBufferPtr;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserInput;
pub use crate::src::HTMLparser::xmlParserInputDeallocate;
pub use crate::src::HTMLparser::xmlParserInput;
pub use crate::src::HTMLparser::xmlParserInputPtr;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserCtxt;
pub use crate::src::HTMLparser::xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlNode;
pub use crate::src::HTMLparser::xmlNs;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlNs;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlDoc;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlDtd;
pub use crate::src::HTMLparser::xmlElementType;
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
pub use crate::src::HTMLparser::xmlNsType;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlAttr;
pub use crate::src::HTMLparser::xmlAttributeType;
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
pub use crate::src::HTMLparser::xmlParserMode;
pub const XML_PARSE_READER: xmlParserMode = 5;
pub const XML_PARSE_PUSH_SAX: xmlParserMode = 4;
pub const XML_PARSE_PUSH_DOM: xmlParserMode = 3;
pub const XML_PARSE_SAX: xmlParserMode = 2;
pub const XML_PARSE_DOM: xmlParserMode = 1;
pub const XML_PARSE_UNKNOWN: xmlParserMode = 0;
pub use crate::src::HTMLparser::xmlError;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlError;
pub use crate::src::HTMLparser::xmlErrorLevel;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub use crate::src::HTMLparser::xmlAttrPtr;
pub use crate::src::HTMLparser::xmlAttr;
pub use crate::src::HTMLparser::xmlNodePtr;
pub use crate::src::HTMLparser::xmlNode;
pub use crate::src::HTMLparser::xmlHashTablePtr;
pub use crate::src::HTMLparser::xmlHashTable;
pub use crate::src::HTMLparser::xmlStartTag;
pub use crate::src::HTMLparser::xmlDictPtr;
pub use crate::src::HTMLparser::xmlDict;
pub use crate::src::HTMLparser::xmlParserInputState;
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
pub use crate::src::HTMLparser::xmlValidCtxt;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlValidCtxt;
pub use crate::src::HTMLparser::xmlAutomataStatePtr;
pub use crate::src::HTMLparser::xmlAutomataState;
pub use crate::src::HTMLparser::xmlAutomataPtr;
pub use crate::src::HTMLparser::xmlAutomata;
pub use crate::src::HTMLparser::xmlValidState;
pub use crate::src::HTMLparser::xmlDocPtr;
pub use crate::src::HTMLparser::xmlDoc;
pub use crate::src::HTMLparser::xmlValidityWarningFunc;
pub use crate::src::HTMLparser::xmlValidityErrorFunc;
pub use crate::src::HTMLparser::xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlSAXHandler;
pub use crate::src::HTMLparser::xmlStructuredErrorFunc;
pub use crate::src::HTMLparser::xmlErrorPtr;
pub use crate::src::HTMLparser::endElementNsSAX2Func;
pub use crate::src::HTMLparser::startElementNsSAX2Func;
pub use crate::src::HTMLparser::externalSubsetSAXFunc;
pub use crate::src::HTMLparser::cdataBlockSAXFunc;
pub use crate::src::HTMLparser::getParameterEntitySAXFunc;
pub use crate::src::HTMLparser::xmlEntityPtr;
pub use crate::src::HTMLparser::xmlEntity;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlEntity;
pub use crate::src::HTMLparser::xmlEntityType;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub use crate::src::HTMLparser::fatalErrorSAXFunc;
pub use crate::src::HTMLparser::errorSAXFunc;
pub use crate::src::HTMLparser::warningSAXFunc;
pub use crate::src::HTMLparser::commentSAXFunc;
pub use crate::src::HTMLparser::processingInstructionSAXFunc;
pub use crate::src::HTMLparser::ignorableWhitespaceSAXFunc;
pub use crate::src::HTMLparser::charactersSAXFunc;
pub use crate::src::HTMLparser::referenceSAXFunc;
pub use crate::src::HTMLparser::endElementSAXFunc;
pub use crate::src::HTMLparser::startElementSAXFunc;
pub use crate::src::HTMLparser::endDocumentSAXFunc;
pub use crate::src::HTMLparser::startDocumentSAXFunc;
pub use crate::src::HTMLparser::setDocumentLocatorSAXFunc;
pub use crate::src::HTMLparser::xmlSAXLocatorPtr;
pub use crate::src::HTMLparser::xmlSAXLocator;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlSAXLocator;
pub use crate::src::HTMLparser::unparsedEntityDeclSAXFunc;
pub use crate::src::HTMLparser::elementDeclSAXFunc;
pub use crate::src::HTMLparser::xmlElementContentPtr;
pub use crate::src::HTMLparser::xmlElementContent;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlElementContent;
pub use crate::src::HTMLparser::xmlElementContentOccur;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub use crate::src::HTMLparser::xmlElementContentType;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub use crate::src::HTMLparser::attributeDeclSAXFunc;
pub use crate::src::HTMLparser::xmlEnumerationPtr;
pub use crate::src::HTMLparser::xmlEnumeration;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlEnumeration;
pub use crate::src::HTMLparser::notationDeclSAXFunc;
pub use crate::src::HTMLparser::entityDeclSAXFunc;
pub use crate::src::HTMLparser::getEntitySAXFunc;
pub use crate::src::HTMLparser::resolveEntitySAXFunc;
pub use crate::src::HTMLparser::hasExternalSubsetSAXFunc;
pub use crate::src::HTMLparser::hasInternalSubsetSAXFunc;
pub use crate::src::HTMLparser::isStandaloneSAXFunc;
pub use crate::src::HTMLparser::internalSubsetSAXFunc;
pub use crate::src::HTMLparser::xmlParserCtxt;
pub use crate::src::HTMLparser::xmlParserCtxtPtr;
pub use crate::src::HTMLparser::xmlSAXHandler;
pub use crate::src::HTMLparser::xmlSAXHandlerPtr;
pub use crate::src::HTMLtree::xmlBufferAllocationScheme;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLtree::_xmlBuffer;
pub use crate::src::HTMLtree::xmlBuffer;
pub use crate::src::HTMLtree::xmlBufferPtr;
pub type C2RustUnnamed = libc::c_uint;
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
pub use crate::src::HTMLparser::xmlParserErrors;
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
pub use crate::src::HTMLparser::xmlGenericErrorFunc;
pub use crate::src::c14n::xmlLink;
pub use crate::src::c14n::xmlLinkPtr;
pub use crate::src::c14n::xmlList;
pub use crate::src::c14n::xmlListPtr;
pub use crate::src::c14n::xmlListDeallocator;
pub use crate::src::c14n::xmlListDataCompare;
pub use crate::src::HTMLparser::htmlDocPtr;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlTextWriter {
    pub out: xmlOutputBufferPtr,
    pub nodes: xmlListPtr,
    pub nsstack: xmlListPtr,
    pub level: libc::c_int,
    pub indent: libc::c_int,
    pub doindent: libc::c_int,
    pub ichar: *mut xmlChar,
    pub qchar: libc::c_char,
    pub ctxt: xmlParserCtxtPtr,
    pub no_doc_free: libc::c_int,
    pub doc: xmlDocPtr,
}
pub type xmlTextWriter = _xmlTextWriter;
pub type xmlTextWriterPtr = *mut xmlTextWriter;
pub type xmlTextWriterNsStackEntry = _xmlTextWriterNsStackEntry;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlTextWriterNsStackEntry {
    pub prefix: *mut xmlChar,
    pub uri: *mut xmlChar,
    pub elem: xmlLinkPtr,
}
pub type xmlTextWriterStackEntry = _xmlTextWriterStackEntry;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlTextWriterStackEntry {
    pub name: *mut xmlChar,
    pub state: xmlTextWriterState,
}
pub type xmlTextWriterState = libc::c_uint;
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
unsafe extern "C" fn xmlWriterErrMsg(
    mut ctxt: xmlTextWriterPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
) {
    if !ctxt.is_null() {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            (*ctxt).ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_WRITER as libc::c_int,
            error as libc::c_int,
            XML_ERR_FATAL,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as libc::c_int,
            b"%s\0" as *const u8 as *const libc::c_char,
            msg,
        );
    } else {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_WRITER as libc::c_int,
            error as libc::c_int,
            XML_ERR_FATAL,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as libc::c_int,
            b"%s\0" as *const u8 as *const libc::c_char,
            msg,
        );
    };
}
unsafe extern "C" fn xmlWriterErrMsgInt(
    mut ctxt: xmlTextWriterPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut val: libc::c_int,
) {
    if !ctxt.is_null() {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            (*ctxt).ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_WRITER as libc::c_int,
            error as libc::c_int,
            XML_ERR_FATAL,
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
    } else {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_WRITER as libc::c_int,
            error as libc::c_int,
            XML_ERR_FATAL,
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
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewTextWriter(
    mut out: xmlOutputBufferPtr,
) -> xmlTextWriterPtr {
    let mut ret: xmlTextWriterPtr = 0 as *mut xmlTextWriter;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlTextWriter>() as libc::c_ulong) as xmlTextWriterPtr;
    if ret.is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriter : out of memory!\n\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlTextWriterPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlTextWriter>() as libc::c_ulong,
    );
    let ref mut fresh0 = (*ret).nodes;
    *fresh0 = xmlListCreate(
        Some(xmlFreeTextWriterStackEntry as unsafe extern "C" fn(xmlLinkPtr) -> ()),
        Some(
            xmlCmpTextWriterStackEntry
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
    if ((*ret).nodes).is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriter : out of memory!\n\0" as *const u8 as *const libc::c_char,
        );
        xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
        return 0 as xmlTextWriterPtr;
    }
    let ref mut fresh1 = (*ret).nsstack;
    *fresh1 = xmlListCreate(
        Some(xmlFreeTextWriterNsStackEntry as unsafe extern "C" fn(xmlLinkPtr) -> ()),
        Some(
            xmlCmpTextWriterNsStackEntry
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
    if ((*ret).nsstack).is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriter : out of memory!\n\0" as *const u8 as *const libc::c_char,
        );
        xmlListDelete((*ret).nodes);
        xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
        return 0 as xmlTextWriterPtr;
    }
    let ref mut fresh2 = (*ret).out;
    *fresh2 = out;
    let ref mut fresh3 = (*ret).ichar;
    *fresh3 = xmlStrdup(b" \0" as *const u8 as *const libc::c_char as *mut xmlChar);
    (*ret).qchar = '"' as i32 as libc::c_char;
    if ((*ret).ichar).is_null() {
        xmlListDelete((*ret).nodes);
        xmlListDelete((*ret).nsstack);
        xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriter : out of memory!\n\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlTextWriterPtr;
    }
    let ref mut fresh4 = (*ret).doc;
    *fresh4 = xmlNewDoc(0 as *const xmlChar);
    (*ret).no_doc_free = 0 as libc::c_int;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewTextWriterFilename(
    mut uri: *const libc::c_char,
    mut compression: libc::c_int,
) -> xmlTextWriterPtr {
    let mut ret: xmlTextWriterPtr = 0 as *mut xmlTextWriter;
    let mut out: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    out = xmlOutputBufferCreateFilename(
        uri,
        0 as xmlCharEncodingHandlerPtr,
        compression,
    );
    if out.is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_IO_EIO,
            b"xmlNewTextWriterFilename : cannot open uri\n\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as xmlTextWriterPtr;
    }
    ret = xmlNewTextWriter(out);
    if ret.is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriterFilename : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlOutputBufferClose(out);
        return 0 as xmlTextWriterPtr;
    }
    (*ret).indent = 0 as libc::c_int;
    (*ret).doindent = 0 as libc::c_int;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewTextWriterMemory(
    mut buf: xmlBufferPtr,
    mut compression: libc::c_int,
) -> xmlTextWriterPtr {
    let mut ret: xmlTextWriterPtr = 0 as *mut xmlTextWriter;
    let mut out: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    out = xmlOutputBufferCreateBuffer(buf, 0 as xmlCharEncodingHandlerPtr);
    if out.is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriterMemory : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as xmlTextWriterPtr;
    }
    ret = xmlNewTextWriter(out);
    if ret.is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_NO_MEMORY,
            b"xmlNewTextWriterMemory : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlOutputBufferClose(out);
        return 0 as xmlTextWriterPtr;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewTextWriterPushParser(
    mut ctxt: xmlParserCtxtPtr,
    mut compression: libc::c_int,
) -> xmlTextWriterPtr {
    let mut ret: xmlTextWriterPtr = 0 as *mut xmlTextWriter;
    let mut out: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    if ctxt.is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterPushParser : invalid context!\n\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as xmlTextWriterPtr;
    }
    out = xmlOutputBufferCreateIO(
        Some(
            xmlTextWriterWriteDocCallback
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    libc::c_int,
                ) -> libc::c_int,
        ),
        Some(
            xmlTextWriterCloseDocCallback
                as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
        ),
        ctxt as *mut libc::c_void,
        0 as xmlCharEncodingHandlerPtr,
    );
    if out.is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterPushParser : error at xmlOutputBufferCreateIO!\n\0"
                as *const u8 as *const libc::c_char,
        );
        return 0 as xmlTextWriterPtr;
    }
    ret = xmlNewTextWriter(out);
    if ret.is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterPushParser : error at xmlNewTextWriter!\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlOutputBufferClose(out);
        return 0 as xmlTextWriterPtr;
    }
    let ref mut fresh5 = (*ret).ctxt;
    *fresh5 = ctxt;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewTextWriterDoc(
    mut doc: *mut xmlDocPtr,
    mut compression: libc::c_int,
) -> xmlTextWriterPtr {
    let mut ret: xmlTextWriterPtr = 0 as *mut xmlTextWriter;
    let mut saxHandler: xmlSAXHandler = xmlSAXHandler {
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
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    memset(
        &mut saxHandler as *mut xmlSAXHandler as *mut libc::c_void,
        '\u{0}' as i32,
        ::std::mem::size_of::<xmlSAXHandler>() as libc::c_ulong,
    );
    xmlSAX2InitDefaultSAXHandler(&mut saxHandler, 1 as libc::c_int);
    saxHandler
        .startDocument = Some(
        xmlTextWriterStartDocumentCallback
            as unsafe extern "C" fn(*mut libc::c_void) -> (),
    );
    saxHandler
        .startElement = Some(
        xmlSAX2StartElement
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *mut *const xmlChar,
            ) -> (),
    );
    saxHandler
        .endElement = Some(
        xmlSAX2EndElement
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
    );
    ctxt = xmlCreatePushParserCtxt(
        &mut saxHandler,
        0 as *mut libc::c_void,
        0 as *const libc::c_char,
        0 as libc::c_int,
        0 as *const libc::c_char,
    );
    if ctxt.is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterDoc : error at xmlCreatePushParserCtxt!\n\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as xmlTextWriterPtr;
    }
    (*ctxt).dictNames = 0 as libc::c_int;
    let ref mut fresh6 = (*ctxt).myDoc;
    *fresh6 = xmlNewDoc(b"1.0\0" as *const u8 as *const libc::c_char as *mut xmlChar);
    if ((*ctxt).myDoc).is_null() {
        xmlFreeParserCtxt(ctxt);
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterDoc : error at xmlNewDoc!\n\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as xmlTextWriterPtr;
    }
    ret = xmlNewTextWriterPushParser(ctxt, compression);
    if ret.is_null() {
        xmlFreeDoc((*ctxt).myDoc);
        xmlFreeParserCtxt(ctxt);
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterDoc : error at xmlNewTextWriterPushParser!\n\0"
                as *const u8 as *const libc::c_char,
        );
        return 0 as xmlTextWriterPtr;
    }
    xmlSetDocCompressMode((*ctxt).myDoc, compression);
    if !doc.is_null() {
        *doc = (*ctxt).myDoc;
        (*ret).no_doc_free = 1 as libc::c_int;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewTextWriterTree(
    mut doc: xmlDocPtr,
    mut node: xmlNodePtr,
    mut compression: libc::c_int,
) -> xmlTextWriterPtr {
    let mut ret: xmlTextWriterPtr = 0 as *mut xmlTextWriter;
    let mut saxHandler: xmlSAXHandler = xmlSAXHandler {
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
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    if doc.is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterTree : invalid document tree!\n\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as xmlTextWriterPtr;
    }
    memset(
        &mut saxHandler as *mut xmlSAXHandler as *mut libc::c_void,
        '\u{0}' as i32,
        ::std::mem::size_of::<xmlSAXHandler>() as libc::c_ulong,
    );
    xmlSAX2InitDefaultSAXHandler(&mut saxHandler, 1 as libc::c_int);
    saxHandler
        .startDocument = Some(
        xmlTextWriterStartDocumentCallback
            as unsafe extern "C" fn(*mut libc::c_void) -> (),
    );
    saxHandler
        .startElement = Some(
        xmlSAX2StartElement
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *mut *const xmlChar,
            ) -> (),
    );
    saxHandler
        .endElement = Some(
        xmlSAX2EndElement
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
    );
    ctxt = xmlCreatePushParserCtxt(
        &mut saxHandler,
        0 as *mut libc::c_void,
        0 as *const libc::c_char,
        0 as libc::c_int,
        0 as *const libc::c_char,
    );
    if ctxt.is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterDoc : error at xmlCreatePushParserCtxt!\n\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as xmlTextWriterPtr;
    }
    (*ctxt).dictNames = 0 as libc::c_int;
    ret = xmlNewTextWriterPushParser(ctxt, compression);
    if ret.is_null() {
        xmlFreeParserCtxt(ctxt);
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_INTERNAL_ERROR,
            b"xmlNewTextWriterDoc : error at xmlNewTextWriterPushParser!\n\0"
                as *const u8 as *const libc::c_char,
        );
        return 0 as xmlTextWriterPtr;
    }
    let ref mut fresh7 = (*ctxt).myDoc;
    *fresh7 = doc;
    let ref mut fresh8 = (*ctxt).node;
    *fresh8 = node;
    (*ret).no_doc_free = 1 as libc::c_int;
    xmlSetDocCompressMode(doc, compression);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeTextWriter(mut writer: xmlTextWriterPtr) {
    if writer.is_null() {
        return;
    }
    if !((*writer).out).is_null() {
        xmlOutputBufferClose((*writer).out);
    }
    if !((*writer).nodes).is_null() {
        xmlListDelete((*writer).nodes);
    }
    if !((*writer).nsstack).is_null() {
        xmlListDelete((*writer).nsstack);
    }
    if !((*writer).ctxt).is_null() {
        if !((*(*writer).ctxt).myDoc).is_null()
            && (*writer).no_doc_free == 0 as libc::c_int
        {
            xmlFreeDoc((*(*writer).ctxt).myDoc);
            let ref mut fresh9 = (*(*writer).ctxt).myDoc;
            *fresh9 = 0 as xmlDocPtr;
        }
        xmlFreeParserCtxt((*writer).ctxt);
    }
    if !((*writer).doc).is_null() {
        xmlFreeDoc((*writer).doc);
    }
    if !((*writer).ichar).is_null() {
        xmlFree
            .expect("non-null function pointer")((*writer).ichar as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(writer as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterStartDocument(
    mut writer: xmlTextWriterPtr,
    mut version: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut standalone: *const libc::c_char,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut encoder: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
    if writer.is_null() || ((*writer).out).is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterStartDocument : invalid writer!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    lk = xmlListFront((*writer).nodes);
    if !lk.is_null() && !(xmlLinkGetData(lk)).is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterStartDocument : not allowed in this context!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    encoder = 0 as xmlCharEncodingHandlerPtr;
    if !encoding.is_null() {
        encoder = xmlFindCharEncodingHandler(encoding);
        if encoder.is_null() {
            xmlWriterErrMsg(
                writer,
                XML_ERR_UNSUPPORTED_ENCODING,
                b"xmlTextWriterStartDocument : unsupported encoding\n\0" as *const u8
                    as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
    }
    let ref mut fresh10 = (*(*writer).out).encoder;
    *fresh10 = encoder;
    if !encoder.is_null() {
        if ((*(*writer).out).conv).is_null() {
            let ref mut fresh11 = (*(*writer).out).conv;
            *fresh11 = xmlBufCreateSize(4000 as libc::c_int as size_t);
        }
        xmlCharEncOutput((*writer).out, 1 as libc::c_int);
        if !((*writer).doc).is_null() && ((*(*writer).doc).encoding).is_null() {
            let ref mut fresh12 = (*(*writer).doc).encoding;
            *fresh12 = xmlStrdup((*(*(*writer).out).encoder).name as *mut xmlChar);
        }
    } else {
        let ref mut fresh13 = (*(*writer).out).conv;
        *fresh13 = 0 as xmlBufPtr;
    }
    sum = 0 as libc::c_int;
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b"<?xml version=\0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlOutputBufferWrite((*writer).out, 1 as libc::c_int, &mut (*writer).qchar);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    if !version.is_null() {
        count = xmlOutputBufferWriteString((*writer).out, version);
    } else {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b"1.0\0" as *const u8 as *const libc::c_char,
        );
    }
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlOutputBufferWrite((*writer).out, 1 as libc::c_int, &mut (*writer).qchar);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    if !((*(*writer).out).encoder).is_null() {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b" encoding=\0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWriteString(
            (*writer).out,
            (*(*(*writer).out).encoder).name,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    if !standalone.is_null() {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b" standalone=\0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWriteString((*writer).out, standalone);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b"?>\n\0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterEndDocument(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterEndDocument : invalid writer!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    loop {
        lk = xmlListFront((*writer).nodes);
        if lk.is_null() {
            break;
        }
        p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
        if p.is_null() {
            break;
        }
        match (*p).state as libc::c_uint {
            1 | 2 | 3 => {
                count = xmlTextWriterEndElement(writer);
                if count < 0 as libc::c_int {
                    return -(1 as libc::c_int);
                }
                sum += count;
            }
            4 | 5 => {
                count = xmlTextWriterEndPI(writer);
                if count < 0 as libc::c_int {
                    return -(1 as libc::c_int);
                }
                sum += count;
            }
            6 => {
                count = xmlTextWriterEndCDATA(writer);
                if count < 0 as libc::c_int {
                    return -(1 as libc::c_int);
                }
                sum += count;
            }
            7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 => {
                count = xmlTextWriterEndDTD(writer);
                if count < 0 as libc::c_int {
                    return -(1 as libc::c_int);
                }
                sum += count;
            }
            16 => {
                count = xmlTextWriterEndComment(writer);
                if count < 0 as libc::c_int {
                    return -(1 as libc::c_int);
                }
                sum += count;
            }
            _ => {}
        }
    }
    if (*writer).indent == 0 {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b"\n\0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    sum += xmlTextWriterFlush(writer);
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterStartComment(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterStartComment : invalid writer!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if !lk.is_null() {
        p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            match (*p).state as libc::c_uint {
                3 | 0 => {}
                1 => {
                    count = xmlTextWriterOutputNSDecl(writer);
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                    count = xmlOutputBufferWriteString(
                        (*writer).out,
                        b">\0" as *const u8 as *const libc::c_char,
                    );
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                    if (*writer).indent != 0 {
                        count = xmlOutputBufferWriteString(
                            (*writer).out,
                            b"\n\0" as *const u8 as *const libc::c_char,
                        );
                        if count < 0 as libc::c_int {
                            return -(1 as libc::c_int);
                        }
                        sum += count;
                    }
                    (*p).state = XML_TEXTWRITER_TEXT;
                }
                _ => return -(1 as libc::c_int),
            }
        }
    }
    p = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlTextWriterStackEntry>() as libc::c_ulong)
        as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartElement : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    let ref mut fresh14 = (*p).name;
    *fresh14 = 0 as *mut xmlChar;
    (*p).state = XML_TEXTWRITER_COMMENT;
    xmlListPushFront((*writer).nodes, p as *mut libc::c_void);
    if (*writer).indent != 0 {
        count = xmlTextWriterWriteIndent(writer);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b"<!--\0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterEndComment(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterEndComment : invalid writer!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterEndComment : not allowed in this context!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    match (*p).state as libc::c_uint {
        16 => {
            count = xmlOutputBufferWriteString(
                (*writer).out,
                b"-->\0" as *const u8 as *const libc::c_char,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
        _ => return -(1 as libc::c_int),
    }
    if (*writer).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b"\n\0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    xmlListPopFront((*writer).nodes);
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatComment(
    mut writer: xmlTextWriterPtr,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatComment(writer, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteVFormatComment(
    mut writer: xmlTextWriterPtr,
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterWriteVFormatComment : invalid writer!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    rc = xmlTextWriterWriteComment(writer, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteComment(
    mut writer: xmlTextWriterPtr,
    mut content: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartComment(writer);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterWriteString(writer, content);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterEndComment(writer);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterStartElement(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() || name.is_null() || *name as libc::c_int == '\u{0}' as i32 {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if !lk.is_null() {
        p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            let mut current_block_20: u64;
            match (*p).state as libc::c_uint {
                4 | 5 => return -(1 as libc::c_int),
                2 => {
                    count = xmlTextWriterEndAttribute(writer);
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
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
                    count = xmlTextWriterOutputNSDecl(writer);
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                    count = xmlOutputBufferWriteString(
                        (*writer).out,
                        b">\0" as *const u8 as *const libc::c_char,
                    );
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                    if (*writer).indent != 0 {
                        count = xmlOutputBufferWriteString(
                            (*writer).out,
                            b"\n\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    (*p).state = XML_TEXTWRITER_TEXT;
                }
                _ => {}
            }
        }
    }
    p = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlTextWriterStackEntry>() as libc::c_ulong)
        as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartElement : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    let ref mut fresh15 = (*p).name;
    *fresh15 = xmlStrdup(name);
    if ((*p).name).is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartElement : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlFree.expect("non-null function pointer")(p as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    (*p).state = XML_TEXTWRITER_NAME;
    xmlListPushFront((*writer).nodes, p as *mut libc::c_void);
    if (*writer).indent != 0 {
        count = xmlTextWriterWriteIndent(writer);
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b"<\0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlOutputBufferWriteString((*writer).out, (*p).name as *const libc::c_char);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterStartElementNS(
    mut writer: xmlTextWriterPtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
    mut namespaceURI: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() || name.is_null() || *name as libc::c_int == '\u{0}' as i32 {
        return -(1 as libc::c_int);
    }
    buf = 0 as *mut xmlChar;
    if !prefix.is_null() {
        buf = xmlStrdup(prefix);
        buf = xmlStrcat(buf, b":\0" as *const u8 as *const libc::c_char as *mut xmlChar);
    }
    buf = xmlStrcat(buf, name);
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartElement(writer, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    if !namespaceURI.is_null() {
        let mut p: *mut xmlTextWriterNsStackEntry = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlTextWriterNsStackEntry>() as libc::c_ulong)
            as *mut xmlTextWriterNsStackEntry;
        if p.is_null() {
            xmlWriterErrMsg(
                writer,
                XML_ERR_NO_MEMORY,
                b"xmlTextWriterStartElementNS : out of memory!\n\0" as *const u8
                    as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        buf = xmlStrdup(b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar);
        if !prefix.is_null() {
            buf = xmlStrcat(
                buf,
                b":\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
            buf = xmlStrcat(buf, prefix);
        }
        let ref mut fresh16 = (*p).prefix;
        *fresh16 = buf;
        let ref mut fresh17 = (*p).uri;
        *fresh17 = xmlStrdup(namespaceURI);
        if ((*p).uri).is_null() {
            xmlWriterErrMsg(
                writer,
                XML_ERR_NO_MEMORY,
                b"xmlTextWriterStartElementNS : out of memory!\n\0" as *const u8
                    as *const libc::c_char,
            );
            xmlFree.expect("non-null function pointer")(p as *mut libc::c_void);
            return -(1 as libc::c_int);
        }
        let ref mut fresh18 = (*p).elem;
        *fresh18 = xmlListFront((*writer).nodes);
        xmlListPushFront((*writer).nsstack, p as *mut libc::c_void);
    }
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterEndElement(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        xmlListDelete((*writer).nsstack);
        let ref mut fresh19 = (*writer).nsstack;
        *fresh19 = 0 as xmlListPtr;
        return -(1 as libc::c_int);
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlListDelete((*writer).nsstack);
        let ref mut fresh20 = (*writer).nsstack;
        *fresh20 = 0 as xmlListPtr;
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    let mut current_block_50: u64;
    match (*p).state as libc::c_uint {
        2 => {
            count = xmlTextWriterEndAttribute(writer);
            if count < 0 as libc::c_int {
                xmlListDelete((*writer).nsstack);
                let ref mut fresh21 = (*writer).nsstack;
                *fresh21 = 0 as xmlListPtr;
                return -(1 as libc::c_int);
            }
            sum += count;
            current_block_50 = 9733961473582153922;
        }
        1 => {
            current_block_50 = 9733961473582153922;
        }
        3 => {
            if (*writer).indent != 0 && (*writer).doindent != 0 {
                count = xmlTextWriterWriteIndent(writer);
                sum += count;
                (*writer).doindent = 1 as libc::c_int;
            } else {
                (*writer).doindent = 1 as libc::c_int;
            }
            count = xmlOutputBufferWriteString(
                (*writer).out,
                b"</\0" as *const u8 as *const libc::c_char,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
            count = xmlOutputBufferWriteString(
                (*writer).out,
                (*p).name as *const libc::c_char,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
            count = xmlOutputBufferWriteString(
                (*writer).out,
                b">\0" as *const u8 as *const libc::c_char,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
            current_block_50 = 3160140712158701372;
        }
        _ => return -(1 as libc::c_int),
    }
    match current_block_50 {
        9733961473582153922 => {
            count = xmlTextWriterOutputNSDecl(writer);
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
            if (*writer).indent != 0 {
                (*writer).doindent = 1 as libc::c_int;
            }
            count = xmlOutputBufferWriteString(
                (*writer).out,
                b"/>\0" as *const u8 as *const libc::c_char,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
        _ => {}
    }
    if (*writer).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b"\n\0" as *const u8 as *const libc::c_char,
        );
        sum += count;
    }
    xmlListPopFront((*writer).nodes);
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterFullEndElement(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        return -(1 as libc::c_int);
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    let mut current_block_41: u64;
    match (*p).state as libc::c_uint {
        2 => {
            count = xmlTextWriterEndAttribute(writer);
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
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
        _ => return -(1 as libc::c_int),
    }
    match current_block_41 {
        16476552305145445901 => {
            count = xmlTextWriterOutputNSDecl(writer);
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
            count = xmlOutputBufferWriteString(
                (*writer).out,
                b">\0" as *const u8 as *const libc::c_char,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
            if (*writer).indent != 0 {
                (*writer).doindent = 0 as libc::c_int;
            }
        }
        _ => {}
    }
    if (*writer).indent != 0 && (*writer).doindent != 0 {
        count = xmlTextWriterWriteIndent(writer);
        sum += count;
        (*writer).doindent = 1 as libc::c_int;
    } else {
        (*writer).doindent = 1 as libc::c_int;
    }
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b"</\0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlOutputBufferWriteString((*writer).out, (*p).name as *const libc::c_char);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b">\0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    if (*writer).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b"\n\0" as *const u8 as *const libc::c_char,
        );
        sum += count;
    }
    xmlListPopFront((*writer).nodes);
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatRaw(
    mut writer: xmlTextWriterPtr,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatRaw(writer, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteVFormatRaw(
    mut writer: xmlTextWriterPtr,
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    rc = xmlTextWriterWriteRaw(writer, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteRawLen(
    mut writer: xmlTextWriterPtr,
    mut content: *const xmlChar,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterWriteRawLen : invalid writer!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if content.is_null() || len < 0 as libc::c_int {
        xmlWriterErrMsg(
            writer,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterWriteRawLen : invalid content!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if !lk.is_null() {
        p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
        count = xmlTextWriterHandleStateDependencies(writer, p);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    if (*writer).indent != 0 {
        (*writer).doindent = 0 as libc::c_int;
    }
    if !content.is_null() {
        count = xmlOutputBufferWrite((*writer).out, len, content as *const libc::c_char);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteRaw(
    mut writer: xmlTextWriterPtr,
    mut content: *const xmlChar,
) -> libc::c_int {
    return xmlTextWriterWriteRawLen(writer, content, xmlStrlen(content));
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatString(
    mut writer: xmlTextWriterPtr,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut ap: ::std::ffi::VaListImpl;
    if writer.is_null() || format.is_null() {
        return -(1 as libc::c_int);
    }
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatString(writer, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteVFormatString(
    mut writer: xmlTextWriterPtr,
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() || format.is_null() {
        return -(1 as libc::c_int);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    rc = xmlTextWriterWriteString(writer, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteString(
    mut writer: xmlTextWriterPtr,
    mut content: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() || content.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    buf = content as *mut xmlChar;
    lk = xmlListFront((*writer).nodes);
    if !lk.is_null() {
        p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            match (*p).state as libc::c_uint {
                1 | 3 => {
                    buf = xmlEncodeSpecialChars(0 as *const xmlDoc, content);
                }
                2 => {
                    buf = 0 as *mut xmlChar;
                    xmlBufAttrSerializeTxtContent(
                        (*(*writer).out).buffer,
                        (*writer).doc,
                        0 as xmlAttrPtr,
                        content,
                    );
                }
                _ => {}
            }
        }
    }
    if !buf.is_null() {
        count = xmlTextWriterWriteRaw(writer, buf);
        if buf != content as *mut xmlChar {
            xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
        }
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    return sum;
}
unsafe extern "C" fn xmlOutputBufferWriteBase64(
    mut out: xmlOutputBufferPtr,
    mut len: libc::c_int,
    mut data: *const libc::c_uchar,
) -> libc::c_int {
    static mut dtable: [libc::c_uchar; 64] = [
        'A' as i32 as libc::c_uchar,
        'B' as i32 as libc::c_uchar,
        'C' as i32 as libc::c_uchar,
        'D' as i32 as libc::c_uchar,
        'E' as i32 as libc::c_uchar,
        'F' as i32 as libc::c_uchar,
        'G' as i32 as libc::c_uchar,
        'H' as i32 as libc::c_uchar,
        'I' as i32 as libc::c_uchar,
        'J' as i32 as libc::c_uchar,
        'K' as i32 as libc::c_uchar,
        'L' as i32 as libc::c_uchar,
        'M' as i32 as libc::c_uchar,
        'N' as i32 as libc::c_uchar,
        'O' as i32 as libc::c_uchar,
        'P' as i32 as libc::c_uchar,
        'Q' as i32 as libc::c_uchar,
        'R' as i32 as libc::c_uchar,
        'S' as i32 as libc::c_uchar,
        'T' as i32 as libc::c_uchar,
        'U' as i32 as libc::c_uchar,
        'V' as i32 as libc::c_uchar,
        'W' as i32 as libc::c_uchar,
        'X' as i32 as libc::c_uchar,
        'Y' as i32 as libc::c_uchar,
        'Z' as i32 as libc::c_uchar,
        'a' as i32 as libc::c_uchar,
        'b' as i32 as libc::c_uchar,
        'c' as i32 as libc::c_uchar,
        'd' as i32 as libc::c_uchar,
        'e' as i32 as libc::c_uchar,
        'f' as i32 as libc::c_uchar,
        'g' as i32 as libc::c_uchar,
        'h' as i32 as libc::c_uchar,
        'i' as i32 as libc::c_uchar,
        'j' as i32 as libc::c_uchar,
        'k' as i32 as libc::c_uchar,
        'l' as i32 as libc::c_uchar,
        'm' as i32 as libc::c_uchar,
        'n' as i32 as libc::c_uchar,
        'o' as i32 as libc::c_uchar,
        'p' as i32 as libc::c_uchar,
        'q' as i32 as libc::c_uchar,
        'r' as i32 as libc::c_uchar,
        's' as i32 as libc::c_uchar,
        't' as i32 as libc::c_uchar,
        'u' as i32 as libc::c_uchar,
        'v' as i32 as libc::c_uchar,
        'w' as i32 as libc::c_uchar,
        'x' as i32 as libc::c_uchar,
        'y' as i32 as libc::c_uchar,
        'z' as i32 as libc::c_uchar,
        '0' as i32 as libc::c_uchar,
        '1' as i32 as libc::c_uchar,
        '2' as i32 as libc::c_uchar,
        '3' as i32 as libc::c_uchar,
        '4' as i32 as libc::c_uchar,
        '5' as i32 as libc::c_uchar,
        '6' as i32 as libc::c_uchar,
        '7' as i32 as libc::c_uchar,
        '8' as i32 as libc::c_uchar,
        '9' as i32 as libc::c_uchar,
        '+' as i32 as libc::c_uchar,
        '/' as i32 as libc::c_uchar,
    ];
    let mut i: libc::c_int = 0;
    let mut linelen: libc::c_int = 0;
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    if out.is_null() || len < 0 as libc::c_int || data.is_null() {
        return -(1 as libc::c_int);
    }
    linelen = 0 as libc::c_int;
    sum = 0 as libc::c_int;
    i = 0 as libc::c_int;
    loop {
        let mut igroup: [libc::c_uchar; 3] = [0; 3];
        let mut ogroup: [libc::c_uchar; 4] = [0; 4];
        let mut c: libc::c_int = 0;
        let mut n: libc::c_int = 0;
        igroup[2 as libc::c_int as usize] = 0 as libc::c_int as libc::c_uchar;
        igroup[1 as libc::c_int as usize] = igroup[2 as libc::c_int as usize];
        igroup[0 as libc::c_int as usize] = igroup[1 as libc::c_int as usize];
        n = 0 as libc::c_int;
        while n < 3 as libc::c_int && i < len {
            c = *data.offset(i as isize) as libc::c_int;
            igroup[n as usize] = c as libc::c_uchar;
            n += 1;
            i += 1;
        }
        if n > 0 as libc::c_int {
            ogroup[0 as libc::c_int
                as usize] = dtable[(igroup[0 as libc::c_int as usize] as libc::c_int
                >> 2 as libc::c_int) as usize];
            ogroup[1 as libc::c_int
                as usize] = dtable[((igroup[0 as libc::c_int as usize] as libc::c_int
                & 3 as libc::c_int) << 4 as libc::c_int
                | igroup[1 as libc::c_int as usize] as libc::c_int >> 4 as libc::c_int)
                as usize];
            ogroup[2 as libc::c_int
                as usize] = dtable[((igroup[1 as libc::c_int as usize] as libc::c_int
                & 0xf as libc::c_int) << 2 as libc::c_int
                | igroup[2 as libc::c_int as usize] as libc::c_int >> 6 as libc::c_int)
                as usize];
            ogroup[3 as libc::c_int
                as usize] = dtable[(igroup[2 as libc::c_int as usize] as libc::c_int
                & 0x3f as libc::c_int) as usize];
            if n < 3 as libc::c_int {
                ogroup[3 as libc::c_int as usize] = '=' as i32 as libc::c_uchar;
                if n < 2 as libc::c_int {
                    ogroup[2 as libc::c_int as usize] = '=' as i32 as libc::c_uchar;
                }
            }
            if linelen >= 72 as libc::c_int {
                count = xmlOutputBufferWrite(
                    out,
                    2 as libc::c_int,
                    b"\r\n\0" as *const u8 as *const libc::c_char,
                );
                if count == -(1 as libc::c_int) {
                    return -(1 as libc::c_int);
                }
                sum += count;
                linelen = 0 as libc::c_int;
            }
            count = xmlOutputBufferWrite(
                out,
                4 as libc::c_int,
                ogroup.as_mut_ptr() as *const libc::c_char,
            );
            if count == -(1 as libc::c_int) {
                return -(1 as libc::c_int);
            }
            sum += count;
            linelen += 4 as libc::c_int;
        }
        if i >= len {
            break;
        }
    }
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteBase64(
    mut writer: xmlTextWriterPtr,
    mut data: *const libc::c_char,
    mut start: libc::c_int,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() || data.is_null() || start < 0 as libc::c_int
        || len < 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if !lk.is_null() {
        p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            count = xmlTextWriterHandleStateDependencies(writer, p);
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
    }
    if (*writer).indent != 0 {
        (*writer).doindent = 0 as libc::c_int;
    }
    count = xmlOutputBufferWriteBase64(
        (*writer).out,
        len,
        (data as *mut libc::c_uchar).offset(start as isize),
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
unsafe extern "C" fn xmlOutputBufferWriteBinHex(
    mut out: xmlOutputBufferPtr,
    mut len: libc::c_int,
    mut data: *const libc::c_uchar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    static mut hex: [libc::c_char; 16] = [
        '0' as i32 as libc::c_char,
        '1' as i32 as libc::c_char,
        '2' as i32 as libc::c_char,
        '3' as i32 as libc::c_char,
        '4' as i32 as libc::c_char,
        '5' as i32 as libc::c_char,
        '6' as i32 as libc::c_char,
        '7' as i32 as libc::c_char,
        '8' as i32 as libc::c_char,
        '9' as i32 as libc::c_char,
        'A' as i32 as libc::c_char,
        'B' as i32 as libc::c_char,
        'C' as i32 as libc::c_char,
        'D' as i32 as libc::c_char,
        'E' as i32 as libc::c_char,
        'F' as i32 as libc::c_char,
    ];
    let mut i: libc::c_int = 0;
    if out.is_null() || data.is_null() || len < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    i = 0 as libc::c_int;
    while i < len {
        count = xmlOutputBufferWrite(
            out,
            1 as libc::c_int,
            &*hex
                .as_ptr()
                .offset(
                    (*data.offset(i as isize) as libc::c_int >> 4 as libc::c_int)
                        as isize,
                ) as *const libc::c_char,
        );
        if count == -(1 as libc::c_int) {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            out,
            1 as libc::c_int,
            &*hex
                .as_ptr()
                .offset(
                    (*data.offset(i as isize) as libc::c_int & 0xf as libc::c_int)
                        as isize,
                ) as *const libc::c_char,
        );
        if count == -(1 as libc::c_int) {
            return -(1 as libc::c_int);
        }
        sum += count;
        i += 1;
    }
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteBinHex(
    mut writer: xmlTextWriterPtr,
    mut data: *const libc::c_char,
    mut start: libc::c_int,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() || data.is_null() || start < 0 as libc::c_int
        || len < 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if !lk.is_null() {
        p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            count = xmlTextWriterHandleStateDependencies(writer, p);
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
    }
    if (*writer).indent != 0 {
        (*writer).doindent = 0 as libc::c_int;
    }
    count = xmlOutputBufferWriteBinHex(
        (*writer).out,
        len,
        (data as *mut libc::c_uchar).offset(start as isize),
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterStartAttribute(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() || name.is_null() || *name as libc::c_int == '\u{0}' as i32 {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        return -(1 as libc::c_int);
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    match (*p).state as libc::c_uint {
        2 => {
            count = xmlTextWriterEndAttribute(writer);
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
        1 => {}
        _ => return -(1 as libc::c_int),
    }
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b" \0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlOutputBufferWriteString((*writer).out, name as *const libc::c_char);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b"=\0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlOutputBufferWrite((*writer).out, 1 as libc::c_int, &mut (*writer).qchar);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    (*p).state = XML_TEXTWRITER_ATTRIBUTE;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterStartAttributeNS(
    mut writer: xmlTextWriterPtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
    mut namespaceURI: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut p: *mut xmlTextWriterNsStackEntry = 0 as *mut xmlTextWriterNsStackEntry;
    if writer.is_null() || name.is_null() || *name as libc::c_int == '\u{0}' as i32 {
        return -(1 as libc::c_int);
    }
    if !namespaceURI.is_null() {
        let mut nsentry: xmlTextWriterNsStackEntry = xmlTextWriterNsStackEntry {
            prefix: 0 as *mut xmlChar,
            uri: 0 as *mut xmlChar,
            elem: 0 as *mut xmlLink,
        };
        let mut curns: *mut xmlTextWriterNsStackEntry = 0
            as *mut xmlTextWriterNsStackEntry;
        buf = xmlStrdup(b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar);
        if !prefix.is_null() {
            buf = xmlStrcat(
                buf,
                b":\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
            buf = xmlStrcat(buf, prefix);
        }
        nsentry.prefix = buf;
        nsentry.uri = namespaceURI as *mut xmlChar;
        nsentry.elem = xmlListFront((*writer).nodes);
        curns = xmlListSearch(
            (*writer).nsstack,
            &mut nsentry as *mut xmlTextWriterNsStackEntry as *mut libc::c_void,
        ) as *mut xmlTextWriterNsStackEntry;
        if !curns.is_null() {
            xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
            if xmlStrcmp((*curns).uri, namespaceURI) == 0 as libc::c_int {
                buf = 0 as *mut xmlChar;
            } else {
                return -(1 as libc::c_int)
            }
        }
        if !buf.is_null() {
            p = xmlMalloc
                .expect(
                    "non-null function pointer",
                )(::std::mem::size_of::<xmlTextWriterNsStackEntry>() as libc::c_ulong)
                as *mut xmlTextWriterNsStackEntry;
            if p.is_null() {
                xmlWriterErrMsg(
                    writer,
                    XML_ERR_NO_MEMORY,
                    b"xmlTextWriterStartAttributeNS : out of memory!\n\0" as *const u8
                        as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            let ref mut fresh22 = (*p).prefix;
            *fresh22 = buf;
            let ref mut fresh23 = (*p).uri;
            *fresh23 = xmlStrdup(namespaceURI);
            if ((*p).uri).is_null() {
                xmlWriterErrMsg(
                    writer,
                    XML_ERR_NO_MEMORY,
                    b"xmlTextWriterStartAttributeNS : out of memory!\n\0" as *const u8
                        as *const libc::c_char,
                );
                xmlFree.expect("non-null function pointer")(p as *mut libc::c_void);
                return -(1 as libc::c_int);
            }
            let ref mut fresh24 = (*p).elem;
            *fresh24 = xmlListFront((*writer).nodes);
            xmlListPushFront((*writer).nsstack, p as *mut libc::c_void);
        }
    }
    buf = 0 as *mut xmlChar;
    if !prefix.is_null() {
        buf = xmlStrdup(prefix);
        buf = xmlStrcat(buf, b":\0" as *const u8 as *const libc::c_char as *mut xmlChar);
    }
    buf = xmlStrcat(buf, name);
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartAttribute(writer, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterEndAttribute(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        return -(1 as libc::c_int);
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    match (*p).state as libc::c_uint {
        2 => {
            (*p).state = XML_TEXTWRITER_NAME;
            count = xmlOutputBufferWrite(
                (*writer).out,
                1 as libc::c_int,
                &mut (*writer).qchar,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
        _ => return -(1 as libc::c_int),
    }
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatAttribute(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatAttribute(writer, name, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteVFormatAttribute(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    rc = xmlTextWriterWriteAttribute(writer, name, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteAttribute(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut content: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartAttribute(writer, name);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterWriteString(writer, content);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterEndAttribute(writer);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatAttributeNS(
    mut writer: xmlTextWriterPtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
    mut namespaceURI: *const xmlChar,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatAttributeNS(
        writer,
        prefix,
        name,
        namespaceURI,
        format,
        ap.as_va_list(),
    );
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteVFormatAttributeNS(
    mut writer: xmlTextWriterPtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
    mut namespaceURI: *const xmlChar,
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    rc = xmlTextWriterWriteAttributeNS(writer, prefix, name, namespaceURI, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteAttributeNS(
    mut writer: xmlTextWriterPtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
    mut namespaceURI: *const xmlChar,
    mut content: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    if writer.is_null() || name.is_null() || *name as libc::c_int == '\u{0}' as i32 {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartAttributeNS(writer, prefix, name, namespaceURI);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterWriteString(writer, content);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterEndAttribute(writer);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatElement(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatElement(writer, name, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteVFormatElement(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    rc = xmlTextWriterWriteElement(writer, name, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteElement(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut content: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartElement(writer, name);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    if !content.is_null() {
        count = xmlTextWriterWriteString(writer, content);
        if count == -(1 as libc::c_int) {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    count = xmlTextWriterEndElement(writer);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatElementNS(
    mut writer: xmlTextWriterPtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
    mut namespaceURI: *const xmlChar,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatElementNS(
        writer,
        prefix,
        name,
        namespaceURI,
        format,
        ap.as_va_list(),
    );
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteVFormatElementNS(
    mut writer: xmlTextWriterPtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
    mut namespaceURI: *const xmlChar,
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    rc = xmlTextWriterWriteElementNS(writer, prefix, name, namespaceURI, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteElementNS(
    mut writer: xmlTextWriterPtr,
    mut prefix: *const xmlChar,
    mut name: *const xmlChar,
    mut namespaceURI: *const xmlChar,
    mut content: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    if writer.is_null() || name.is_null() || *name as libc::c_int == '\u{0}' as i32 {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartElementNS(writer, prefix, name, namespaceURI);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterWriteString(writer, content);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterEndElement(writer);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterStartPI(
    mut writer: xmlTextWriterPtr,
    mut target: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() || target.is_null() || *target as libc::c_int == '\u{0}' as i32 {
        return -(1 as libc::c_int);
    }
    if xmlStrcasecmp(
        target,
        b"xml\0" as *const u8 as *const libc::c_char as *const xmlChar,
    ) == 0 as libc::c_int
    {
        xmlWriterErrMsg(
            writer,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterStartPI : target name [Xx][Mm][Ll] is reserved for xml standardization!\n\0"
                as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if !lk.is_null() {
        p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            let mut current_block_24: u64;
            match (*p).state as libc::c_uint {
                2 => {
                    count = xmlTextWriterEndAttribute(writer);
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
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
                        writer,
                        XML_ERR_INTERNAL_ERROR,
                        b"xmlTextWriterStartPI : nested PI!\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    return -(1 as libc::c_int);
                }
                _ => return -(1 as libc::c_int),
            }
            match current_block_24 {
                51576440349808026 => {
                    count = xmlTextWriterOutputNSDecl(writer);
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                    count = xmlOutputBufferWriteString(
                        (*writer).out,
                        b">\0" as *const u8 as *const libc::c_char,
                    );
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                    (*p).state = XML_TEXTWRITER_TEXT;
                }
                _ => {}
            }
        }
    }
    p = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlTextWriterStackEntry>() as libc::c_ulong)
        as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartPI : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    let ref mut fresh25 = (*p).name;
    *fresh25 = xmlStrdup(target);
    if ((*p).name).is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartPI : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlFree.expect("non-null function pointer")(p as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    (*p).state = XML_TEXTWRITER_PI;
    xmlListPushFront((*writer).nodes, p as *mut libc::c_void);
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b"<?\0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlOutputBufferWriteString((*writer).out, (*p).name as *const libc::c_char);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterEndPI(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        return 0 as libc::c_int;
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return 0 as libc::c_int;
    }
    sum = 0 as libc::c_int;
    match (*p).state as libc::c_uint {
        4 | 5 => {
            count = xmlOutputBufferWriteString(
                (*writer).out,
                b"?>\0" as *const u8 as *const libc::c_char,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
        _ => return -(1 as libc::c_int),
    }
    if (*writer).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b"\n\0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    xmlListPopFront((*writer).nodes);
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatPI(
    mut writer: xmlTextWriterPtr,
    mut target: *const xmlChar,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatPI(writer, target, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteVFormatPI(
    mut writer: xmlTextWriterPtr,
    mut target: *const xmlChar,
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    rc = xmlTextWriterWritePI(writer, target, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWritePI(
    mut writer: xmlTextWriterPtr,
    mut target: *const xmlChar,
    mut content: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartPI(writer, target);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    if !content.is_null() {
        count = xmlTextWriterWriteString(writer, content);
        if count == -(1 as libc::c_int) {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    count = xmlTextWriterEndPI(writer);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterStartCDATA(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if !lk.is_null() {
        p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            let mut current_block_20: u64;
            match (*p).state as libc::c_uint {
                0 | 3 | 4 | 5 => {
                    current_block_20 = 13472856163611868459;
                }
                2 => {
                    count = xmlTextWriterEndAttribute(writer);
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                    current_block_20 = 1628216707406609217;
                }
                1 => {
                    current_block_20 = 1628216707406609217;
                }
                6 => {
                    xmlWriterErrMsg(
                        writer,
                        XML_ERR_INTERNAL_ERROR,
                        b"xmlTextWriterStartCDATA : CDATA not allowed in this context!\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                    return -(1 as libc::c_int);
                }
                _ => return -(1 as libc::c_int),
            }
            match current_block_20 {
                1628216707406609217 => {
                    count = xmlTextWriterOutputNSDecl(writer);
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                    count = xmlOutputBufferWriteString(
                        (*writer).out,
                        b">\0" as *const u8 as *const libc::c_char,
                    );
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                    (*p).state = XML_TEXTWRITER_TEXT;
                }
                _ => {}
            }
        }
    }
    p = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlTextWriterStackEntry>() as libc::c_ulong)
        as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartCDATA : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    let ref mut fresh26 = (*p).name;
    *fresh26 = 0 as *mut xmlChar;
    (*p).state = XML_TEXTWRITER_CDATA;
    xmlListPushFront((*writer).nodes, p as *mut libc::c_void);
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b"<![CDATA[\0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterEndCDATA(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        return -(1 as libc::c_int);
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    match (*p).state as libc::c_uint {
        6 => {
            count = xmlOutputBufferWriteString(
                (*writer).out,
                b"]]>\0" as *const u8 as *const libc::c_char,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
        _ => return -(1 as libc::c_int),
    }
    xmlListPopFront((*writer).nodes);
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatCDATA(
    mut writer: xmlTextWriterPtr,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatCDATA(writer, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteVFormatCDATA(
    mut writer: xmlTextWriterPtr,
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    rc = xmlTextWriterWriteCDATA(writer, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteCDATA(
    mut writer: xmlTextWriterPtr,
    mut content: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartCDATA(writer);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    if !content.is_null() {
        count = xmlTextWriterWriteString(writer, content);
        if count == -(1 as libc::c_int) {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    count = xmlTextWriterEndCDATA(writer);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterStartDTD(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut pubid: *const xmlChar,
    mut sysid: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() || name.is_null() || *name as libc::c_int == '\u{0}' as i32 {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if !lk.is_null() && !(xmlLinkGetData(lk)).is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterStartDTD : DTD allowed only in prolog!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    p = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlTextWriterStackEntry>() as libc::c_ulong)
        as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTD : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    let ref mut fresh27 = (*p).name;
    *fresh27 = xmlStrdup(name);
    if ((*p).name).is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTD : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlFree.expect("non-null function pointer")(p as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    (*p).state = XML_TEXTWRITER_DTD;
    xmlListPushFront((*writer).nodes, p as *mut libc::c_void);
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b"<!DOCTYPE \0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlOutputBufferWriteString((*writer).out, name as *const libc::c_char);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    if !pubid.is_null() {
        if sysid.is_null() {
            xmlWriterErrMsg(
                writer,
                XML_ERR_INTERNAL_ERROR,
                b"xmlTextWriterStartDTD : system identifier needed!\n\0" as *const u8
                    as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        if (*writer).indent != 0 {
            count = xmlOutputBufferWrite(
                (*writer).out,
                1 as libc::c_int,
                b"\n\0" as *const u8 as *const libc::c_char,
            );
        } else {
            count = xmlOutputBufferWrite(
                (*writer).out,
                1 as libc::c_int,
                b" \0" as *const u8 as *const libc::c_char,
            );
        }
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b"PUBLIC \0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWriteString((*writer).out, pubid as *const libc::c_char);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    if !sysid.is_null() {
        if pubid.is_null() {
            if (*writer).indent != 0 {
                count = xmlOutputBufferWrite(
                    (*writer).out,
                    1 as libc::c_int,
                    b"\n\0" as *const u8 as *const libc::c_char,
                );
            } else {
                count = xmlOutputBufferWrite(
                    (*writer).out,
                    1 as libc::c_int,
                    b" \0" as *const u8 as *const libc::c_char,
                );
            }
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
            count = xmlOutputBufferWriteString(
                (*writer).out,
                b"SYSTEM \0" as *const u8 as *const libc::c_char,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        } else {
            if (*writer).indent != 0 {
                count = xmlOutputBufferWriteString(
                    (*writer).out,
                    b"\n       \0" as *const u8 as *const libc::c_char,
                );
            } else {
                count = xmlOutputBufferWrite(
                    (*writer).out,
                    1 as libc::c_int,
                    b" \0" as *const u8 as *const libc::c_char,
                );
            }
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWriteString((*writer).out, sysid as *const libc::c_char);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterEndDTD(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut loop_0: libc::c_int = 0;
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    loop_0 = 1 as libc::c_int;
    let mut current_block_25: u64;
    while loop_0 != 0 {
        lk = xmlListFront((*writer).nodes);
        if lk.is_null() {
            break;
        }
        p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
        if p.is_null() {
            break;
        }
        match (*p).state as libc::c_uint {
            8 => {
                count = xmlOutputBufferWriteString(
                    (*writer).out,
                    b"]\0" as *const u8 as *const libc::c_char,
                );
                if count < 0 as libc::c_int {
                    return -(1 as libc::c_int);
                }
                sum += count;
                current_block_25 = 1862023469299908377;
            }
            7 => {
                current_block_25 = 1862023469299908377;
            }
            9 | 10 => {
                count = xmlTextWriterEndDTDElement(writer);
                current_block_25 = 17500079516916021833;
            }
            11 | 12 => {
                count = xmlTextWriterEndDTDAttlist(writer);
                current_block_25 = 17500079516916021833;
            }
            13 | 15 | 14 => {
                count = xmlTextWriterEndDTDEntity(writer);
                current_block_25 = 17500079516916021833;
            }
            16 => {
                count = xmlTextWriterEndComment(writer);
                current_block_25 = 17500079516916021833;
            }
            _ => {
                loop_0 = 0 as libc::c_int;
                continue;
            }
        }
        match current_block_25 {
            1862023469299908377 => {
                count = xmlOutputBufferWriteString(
                    (*writer).out,
                    b">\0" as *const u8 as *const libc::c_char,
                );
                if (*writer).indent != 0 {
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                    count = xmlOutputBufferWriteString(
                        (*writer).out,
                        b"\n\0" as *const u8 as *const libc::c_char,
                    );
                }
                xmlListPopFront((*writer).nodes);
            }
            _ => {}
        }
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatDTD(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut pubid: *const xmlChar,
    mut sysid: *const xmlChar,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatDTD(
        writer,
        name,
        pubid,
        sysid,
        format,
        ap.as_va_list(),
    );
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteVFormatDTD(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut pubid: *const xmlChar,
    mut sysid: *const xmlChar,
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    rc = xmlTextWriterWriteDTD(writer, name, pubid, sysid, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteDTD(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut pubid: *const xmlChar,
    mut sysid: *const xmlChar,
    mut subset: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartDTD(writer, name, pubid, sysid);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    if !subset.is_null() {
        count = xmlTextWriterWriteString(writer, subset);
        if count == -(1 as libc::c_int) {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    count = xmlTextWriterEndDTD(writer);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterStartDTDElement(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() || name.is_null() || *name as libc::c_int == '\u{0}' as i32 {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        return -(1 as libc::c_int);
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if !p.is_null() {
        match (*p).state as libc::c_uint {
            7 => {
                count = xmlOutputBufferWriteString(
                    (*writer).out,
                    b" [\0" as *const u8 as *const libc::c_char,
                );
                if count < 0 as libc::c_int {
                    return -(1 as libc::c_int);
                }
                sum += count;
                if (*writer).indent != 0 {
                    count = xmlOutputBufferWriteString(
                        (*writer).out,
                        b"\n\0" as *const u8 as *const libc::c_char,
                    );
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                }
                (*p).state = XML_TEXTWRITER_DTD_TEXT;
            }
            8 | 0 => {}
            _ => return -(1 as libc::c_int),
        }
    }
    p = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlTextWriterStackEntry>() as libc::c_ulong)
        as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTDElement : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    let ref mut fresh28 = (*p).name;
    *fresh28 = xmlStrdup(name);
    if ((*p).name).is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTDElement : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlFree.expect("non-null function pointer")(p as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    (*p).state = XML_TEXTWRITER_DTD_ELEM;
    xmlListPushFront((*writer).nodes, p as *mut libc::c_void);
    if (*writer).indent != 0 {
        count = xmlTextWriterWriteIndent(writer);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b"<!ELEMENT \0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlOutputBufferWriteString((*writer).out, name as *const libc::c_char);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterEndDTDElement(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        return -(1 as libc::c_int);
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    match (*p).state as libc::c_uint {
        9 | 10 => {
            count = xmlOutputBufferWriteString(
                (*writer).out,
                b">\0" as *const u8 as *const libc::c_char,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
        _ => return -(1 as libc::c_int),
    }
    if (*writer).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b"\n\0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    xmlListPopFront((*writer).nodes);
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatDTDElement(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatDTDElement(writer, name, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteVFormatDTDElement(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    rc = xmlTextWriterWriteDTDElement(writer, name, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteDTDElement(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut content: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    if content.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartDTDElement(writer, name);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterWriteString(writer, content);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterEndDTDElement(writer);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterStartDTDAttlist(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() || name.is_null() || *name as libc::c_int == '\u{0}' as i32 {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        return -(1 as libc::c_int);
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if !p.is_null() {
        match (*p).state as libc::c_uint {
            7 => {
                count = xmlOutputBufferWriteString(
                    (*writer).out,
                    b" [\0" as *const u8 as *const libc::c_char,
                );
                if count < 0 as libc::c_int {
                    return -(1 as libc::c_int);
                }
                sum += count;
                if (*writer).indent != 0 {
                    count = xmlOutputBufferWriteString(
                        (*writer).out,
                        b"\n\0" as *const u8 as *const libc::c_char,
                    );
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                }
                (*p).state = XML_TEXTWRITER_DTD_TEXT;
            }
            8 | 0 => {}
            _ => return -(1 as libc::c_int),
        }
    }
    p = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlTextWriterStackEntry>() as libc::c_ulong)
        as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTDAttlist : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    let ref mut fresh29 = (*p).name;
    *fresh29 = xmlStrdup(name);
    if ((*p).name).is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTDAttlist : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlFree.expect("non-null function pointer")(p as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    (*p).state = XML_TEXTWRITER_DTD_ATTL;
    xmlListPushFront((*writer).nodes, p as *mut libc::c_void);
    if (*writer).indent != 0 {
        count = xmlTextWriterWriteIndent(writer);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b"<!ATTLIST \0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlOutputBufferWriteString((*writer).out, name as *const libc::c_char);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterEndDTDAttlist(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        return -(1 as libc::c_int);
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    match (*p).state as libc::c_uint {
        11 | 12 => {
            count = xmlOutputBufferWriteString(
                (*writer).out,
                b">\0" as *const u8 as *const libc::c_char,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
        _ => return -(1 as libc::c_int),
    }
    if (*writer).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b"\n\0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    xmlListPopFront((*writer).nodes);
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatDTDAttlist(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatDTDAttlist(writer, name, format, ap.as_va_list());
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteVFormatDTDAttlist(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    rc = xmlTextWriterWriteDTDAttlist(writer, name, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteDTDAttlist(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut content: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    if content.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartDTDAttlist(writer, name);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterWriteString(writer, content);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterEndDTDAttlist(writer);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterStartDTDEntity(
    mut writer: xmlTextWriterPtr,
    mut pe: libc::c_int,
    mut name: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() || name.is_null() || *name as libc::c_int == '\u{0}' as i32 {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if !lk.is_null() {
        p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
        if !p.is_null() {
            match (*p).state as libc::c_uint {
                7 => {
                    count = xmlOutputBufferWriteString(
                        (*writer).out,
                        b" [\0" as *const u8 as *const libc::c_char,
                    );
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                    if (*writer).indent != 0 {
                        count = xmlOutputBufferWriteString(
                            (*writer).out,
                            b"\n\0" as *const u8 as *const libc::c_char,
                        );
                        if count < 0 as libc::c_int {
                            return -(1 as libc::c_int);
                        }
                        sum += count;
                    }
                    (*p).state = XML_TEXTWRITER_DTD_TEXT;
                }
                8 | 0 => {}
                _ => return -(1 as libc::c_int),
            }
        }
    }
    p = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlTextWriterStackEntry>() as libc::c_ulong)
        as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTDElement : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    let ref mut fresh30 = (*p).name;
    *fresh30 = xmlStrdup(name);
    if ((*p).name).is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterStartDTDElement : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlFree.expect("non-null function pointer")(p as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    if pe != 0 as libc::c_int {
        (*p).state = XML_TEXTWRITER_DTD_PENT;
    } else {
        (*p).state = XML_TEXTWRITER_DTD_ENTY;
    }
    xmlListPushFront((*writer).nodes, p as *mut libc::c_void);
    if (*writer).indent != 0 {
        count = xmlTextWriterWriteIndent(writer);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b"<!ENTITY \0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    if pe != 0 as libc::c_int {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b"% \0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString((*writer).out, name as *const libc::c_char);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterEndDTDEntity(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        return -(1 as libc::c_int);
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    match (*p).state as libc::c_uint {
        14 => {
            count = xmlOutputBufferWrite(
                (*writer).out,
                1 as libc::c_int,
                &mut (*writer).qchar,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
        13 | 15 => {}
        _ => return -(1 as libc::c_int),
    }
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b">\0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    if (*writer).indent != 0 {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b"\n\0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    xmlListPopFront((*writer).nodes);
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteFormatDTDInternalEntity(
    mut writer: xmlTextWriterPtr,
    mut pe: libc::c_int,
    mut name: *const xmlChar,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    rc = xmlTextWriterWriteVFormatDTDInternalEntity(
        writer,
        pe,
        name,
        format,
        ap.as_va_list(),
    );
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteVFormatDTDInternalEntity(
    mut writer: xmlTextWriterPtr,
    mut pe: libc::c_int,
    mut name: *const xmlChar,
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    buf = xmlTextWriterVSprintf(format, argptr.as_va_list());
    if buf.is_null() {
        return -(1 as libc::c_int);
    }
    rc = xmlTextWriterWriteDTDInternalEntity(writer, pe, name, buf);
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteDTDEntity(
    mut writer: xmlTextWriterPtr,
    mut pe: libc::c_int,
    mut name: *const xmlChar,
    mut pubid: *const xmlChar,
    mut sysid: *const xmlChar,
    mut ndataid: *const xmlChar,
    mut content: *const xmlChar,
) -> libc::c_int {
    if content.is_null() && pubid.is_null() && sysid.is_null() {
        return -(1 as libc::c_int);
    }
    if pe != 0 as libc::c_int && !ndataid.is_null() {
        return -(1 as libc::c_int);
    }
    if pubid.is_null() && sysid.is_null() {
        return xmlTextWriterWriteDTDInternalEntity(writer, pe, name, content);
    }
    return xmlTextWriterWriteDTDExternalEntity(writer, pe, name, pubid, sysid, ndataid);
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteDTDInternalEntity(
    mut writer: xmlTextWriterPtr,
    mut pe: libc::c_int,
    mut name: *const xmlChar,
    mut content: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    if name.is_null() || *name as libc::c_int == '\u{0}' as i32 || content.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartDTDEntity(writer, pe, name);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterWriteString(writer, content);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterEndDTDEntity(writer);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteDTDExternalEntity(
    mut writer: xmlTextWriterPtr,
    mut pe: libc::c_int,
    mut name: *const xmlChar,
    mut pubid: *const xmlChar,
    mut sysid: *const xmlChar,
    mut ndataid: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    if pubid.is_null() && sysid.is_null() {
        return -(1 as libc::c_int);
    }
    if pe != 0 as libc::c_int && !ndataid.is_null() {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    count = xmlTextWriterStartDTDEntity(writer, pe, name);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterWriteDTDExternalEntityContents(writer, pubid, sysid, ndataid);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlTextWriterEndDTDEntity(writer);
    if count == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteDTDExternalEntityContents(
    mut writer: xmlTextWriterPtr,
    mut pubid: *const xmlChar,
    mut sysid: *const xmlChar,
    mut ndataid: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterWriteDTDExternalEntityContents: xmlTextWriterPtr invalid!\n\0"
                as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        xmlWriterErrMsg(
            writer,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterWriteDTDExternalEntityContents: you must call xmlTextWriterStartDTDEntity before the call to this function!\n\0"
                as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    match (*p).state as libc::c_uint {
        13 => {}
        15 => {
            if !ndataid.is_null() {
                xmlWriterErrMsg(
                    writer,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlTextWriterWriteDTDExternalEntityContents: notation not allowed with parameter entities!\n\0"
                        as *const u8 as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
        }
        _ => {
            xmlWriterErrMsg(
                writer,
                XML_ERR_INTERNAL_ERROR,
                b"xmlTextWriterWriteDTDExternalEntityContents: you must call xmlTextWriterStartDTDEntity before the call to this function!\n\0"
                    as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
    }
    if !pubid.is_null() {
        if sysid.is_null() {
            xmlWriterErrMsg(
                writer,
                XML_ERR_INTERNAL_ERROR,
                b"xmlTextWriterWriteDTDExternalEntityContents: system identifier needed!\n\0"
                    as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b" PUBLIC \0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWriteString((*writer).out, pubid as *const libc::c_char);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    if !sysid.is_null() {
        if pubid.is_null() {
            count = xmlOutputBufferWriteString(
                (*writer).out,
                b" SYSTEM\0" as *const u8 as *const libc::c_char,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b" \0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWriteString((*writer).out, sysid as *const libc::c_char);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    if !ndataid.is_null() {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b" NDATA \0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWriteString(
            (*writer).out,
            ndataid as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterWriteDTDNotation(
    mut writer: xmlTextWriterPtr,
    mut name: *const xmlChar,
    mut pubid: *const xmlChar,
    mut sysid: *const xmlChar,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if writer.is_null() || name.is_null() || *name as libc::c_int == '\u{0}' as i32 {
        return -(1 as libc::c_int);
    }
    sum = 0 as libc::c_int;
    lk = xmlListFront((*writer).nodes);
    if lk.is_null() {
        return -(1 as libc::c_int);
    }
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if !p.is_null() {
        match (*p).state as libc::c_uint {
            7 => {
                count = xmlOutputBufferWriteString(
                    (*writer).out,
                    b" [\0" as *const u8 as *const libc::c_char,
                );
                if count < 0 as libc::c_int {
                    return -(1 as libc::c_int);
                }
                sum += count;
                if (*writer).indent != 0 {
                    count = xmlOutputBufferWriteString(
                        (*writer).out,
                        b"\n\0" as *const u8 as *const libc::c_char,
                    );
                    if count < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    sum += count;
                }
                (*p).state = XML_TEXTWRITER_DTD_TEXT;
            }
            8 => {}
            _ => return -(1 as libc::c_int),
        }
    }
    if (*writer).indent != 0 {
        count = xmlTextWriterWriteIndent(writer);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b"<!NOTATION \0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    count = xmlOutputBufferWriteString((*writer).out, name as *const libc::c_char);
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    if !pubid.is_null() {
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b" PUBLIC \0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWriteString((*writer).out, pubid as *const libc::c_char);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    if !sysid.is_null() {
        if pubid.is_null() {
            count = xmlOutputBufferWriteString(
                (*writer).out,
                b" SYSTEM\0" as *const u8 as *const libc::c_char,
            );
            if count < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            sum += count;
        }
        count = xmlOutputBufferWriteString(
            (*writer).out,
            b" \0" as *const u8 as *const libc::c_char,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWriteString((*writer).out, sysid as *const libc::c_char);
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
        count = xmlOutputBufferWrite(
            (*writer).out,
            1 as libc::c_int,
            &mut (*writer).qchar,
        );
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    count = xmlOutputBufferWriteString(
        (*writer).out,
        b">\0" as *const u8 as *const libc::c_char,
    );
    if count < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    sum += count;
    return sum;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterFlush(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    if ((*writer).out).is_null() {
        count = 0 as libc::c_int;
    } else {
        count = xmlOutputBufferFlush((*writer).out);
    }
    return count;
}
unsafe extern "C" fn xmlFreeTextWriterStackEntry(mut lk: xmlLinkPtr) {
    let mut p: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    p = xmlLinkGetData(lk) as *mut xmlTextWriterStackEntry;
    if p.is_null() {
        return;
    }
    if !((*p).name).is_null() {
        xmlFree.expect("non-null function pointer")((*p).name as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(p as *mut libc::c_void);
}
unsafe extern "C" fn xmlCmpTextWriterStackEntry(
    mut data0: *const libc::c_void,
    mut data1: *const libc::c_void,
) -> libc::c_int {
    let mut p0: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    let mut p1: *mut xmlTextWriterStackEntry = 0 as *mut xmlTextWriterStackEntry;
    if data0 == data1 {
        return 0 as libc::c_int;
    }
    if data0.is_null() {
        return -(1 as libc::c_int);
    }
    if data1.is_null() {
        return 1 as libc::c_int;
    }
    p0 = data0 as *mut xmlTextWriterStackEntry;
    p1 = data1 as *mut xmlTextWriterStackEntry;
    return xmlStrcmp((*p0).name, (*p1).name);
}
unsafe extern "C" fn xmlTextWriterOutputNSDecl(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut lk: xmlLinkPtr = 0 as *mut xmlLink;
    let mut np: *mut xmlTextWriterNsStackEntry = 0 as *mut xmlTextWriterNsStackEntry;
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    sum = 0 as libc::c_int;
    while xmlListEmpty((*writer).nsstack) == 0 {
        let mut namespaceURI: *mut xmlChar = 0 as *mut xmlChar;
        let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
        lk = xmlListFront((*writer).nsstack);
        np = xmlLinkGetData(lk) as *mut xmlTextWriterNsStackEntry;
        if !np.is_null() {
            namespaceURI = xmlStrdup((*np).uri);
            prefix = xmlStrdup((*np).prefix);
        }
        xmlListPopFront((*writer).nsstack);
        if !np.is_null() {
            count = xmlTextWriterWriteAttribute(writer, prefix, namespaceURI);
            xmlFree
                .expect("non-null function pointer")(namespaceURI as *mut libc::c_void);
            xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void);
            if count < 0 as libc::c_int {
                xmlListDelete((*writer).nsstack);
                let ref mut fresh31 = (*writer).nsstack;
                *fresh31 = 0 as xmlListPtr;
                return -(1 as libc::c_int);
            }
            sum += count;
        }
    }
    return sum;
}
unsafe extern "C" fn xmlFreeTextWriterNsStackEntry(mut lk: xmlLinkPtr) {
    let mut p: *mut xmlTextWriterNsStackEntry = 0 as *mut xmlTextWriterNsStackEntry;
    p = xmlLinkGetData(lk) as *mut xmlTextWriterNsStackEntry;
    if p.is_null() {
        return;
    }
    if !((*p).prefix).is_null() {
        xmlFree.expect("non-null function pointer")((*p).prefix as *mut libc::c_void);
    }
    if !((*p).uri).is_null() {
        xmlFree.expect("non-null function pointer")((*p).uri as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(p as *mut libc::c_void);
}
unsafe extern "C" fn xmlCmpTextWriterNsStackEntry(
    mut data0: *const libc::c_void,
    mut data1: *const libc::c_void,
) -> libc::c_int {
    let mut p0: *mut xmlTextWriterNsStackEntry = 0 as *mut xmlTextWriterNsStackEntry;
    let mut p1: *mut xmlTextWriterNsStackEntry = 0 as *mut xmlTextWriterNsStackEntry;
    let mut rc: libc::c_int = 0;
    if data0 == data1 {
        return 0 as libc::c_int;
    }
    if data0.is_null() {
        return -(1 as libc::c_int);
    }
    if data1.is_null() {
        return 1 as libc::c_int;
    }
    p0 = data0 as *mut xmlTextWriterNsStackEntry;
    p1 = data1 as *mut xmlTextWriterNsStackEntry;
    rc = xmlStrcmp((*p0).prefix, (*p1).prefix);
    if rc != 0 as libc::c_int || (*p0).elem != (*p1).elem {
        rc = -(1 as libc::c_int);
    }
    return rc;
}
unsafe extern "C" fn xmlTextWriterWriteDocCallback(
    mut context: *mut libc::c_void,
    mut str: *const libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut ctxt: xmlParserCtxtPtr = context as xmlParserCtxtPtr;
    let mut rc: libc::c_int = 0;
    rc = xmlParseChunk(ctxt, str, len, 0 as libc::c_int);
    if rc != 0 as libc::c_int {
        xmlWriterErrMsgInt(
            0 as xmlTextWriterPtr,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterWriteDocCallback : XML error %d !\n\0" as *const u8
                as *const libc::c_char,
            rc,
        );
        return -(1 as libc::c_int);
    }
    return len;
}
unsafe extern "C" fn xmlTextWriterCloseDocCallback(
    mut context: *mut libc::c_void,
) -> libc::c_int {
    let mut ctxt: xmlParserCtxtPtr = context as xmlParserCtxtPtr;
    let mut rc: libc::c_int = 0;
    rc = xmlParseChunk(
        ctxt,
        0 as *const libc::c_char,
        0 as libc::c_int,
        1 as libc::c_int,
    );
    if rc != 0 as libc::c_int {
        xmlWriterErrMsgInt(
            0 as xmlTextWriterPtr,
            XML_ERR_INTERNAL_ERROR,
            b"xmlTextWriterCloseDocCallback : XML error %d !\n\0" as *const u8
                as *const libc::c_char,
            rc,
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlTextWriterVSprintf(
    mut format: *const libc::c_char,
    mut argptr: ::std::ffi::VaList,
) -> *mut xmlChar {
    let mut size: libc::c_int = 0;
    let mut count: libc::c_int = 0;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut locarg: ::std::ffi::VaListImpl;
    size = 8192 as libc::c_int;
    buf = xmlMalloc.expect("non-null function pointer")(size as size_t) as *mut xmlChar;
    if buf.is_null() {
        xmlWriterErrMsg(
            0 as xmlTextWriterPtr,
            XML_ERR_NO_MEMORY,
            b"xmlTextWriterVSprintf : out of memory!\n\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as *mut xmlChar;
    }
    locarg = argptr.clone();
    loop {
        count = vsnprintf(
            buf as *mut libc::c_char,
            size as libc::c_ulong,
            format,
            locarg.as_va_list(),
        );
        if !(count < 0 as libc::c_int || count == size - 1 as libc::c_int
            || count == size || count > size)
        {
            break;
        }
        xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
        size += 8192 as libc::c_int;
        buf = xmlMalloc.expect("non-null function pointer")(size as size_t)
            as *mut xmlChar;
        if buf.is_null() {
            xmlWriterErrMsg(
                0 as xmlTextWriterPtr,
                XML_ERR_NO_MEMORY,
                b"xmlTextWriterVSprintf : out of memory!\n\0" as *const u8
                    as *const libc::c_char,
            );
            return 0 as *mut xmlChar;
        }
        locarg = argptr.clone();
    }
    return buf;
}
unsafe extern "C" fn xmlTextWriterStartDocumentCallback(mut ctx: *mut libc::c_void) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    if (*ctxt).html != 0 {
        if ((*ctxt).myDoc).is_null() {
            let ref mut fresh32 = (*ctxt).myDoc;
            *fresh32 = htmlNewDocNoDtD(0 as *const xmlChar, 0 as *const xmlChar);
        }
        if ((*ctxt).myDoc).is_null() {
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).error).is_some() {
                ((*(*ctxt).sax).error)
                    .expect(
                        "non-null function pointer",
                    )(
                    (*ctxt).userData,
                    b"SAX.startDocument(): out of memory\n\0" as *const u8
                        as *const libc::c_char,
                );
            }
            (*ctxt).errNo = XML_ERR_NO_MEMORY as libc::c_int;
            (*ctxt).instate = XML_PARSER_EOF;
            (*ctxt).disableSAX = 1 as libc::c_int;
            return;
        }
    } else {
        doc = (*ctxt).myDoc;
        if doc.is_null() {
            let ref mut fresh33 = (*ctxt).myDoc;
            *fresh33 = xmlNewDoc((*ctxt).version);
            doc = *fresh33;
        }
        if !doc.is_null() {
            if ((*doc).children).is_null() {
                if !((*ctxt).encoding).is_null() {
                    let ref mut fresh34 = (*doc).encoding;
                    *fresh34 = xmlStrdup((*ctxt).encoding);
                } else {
                    let ref mut fresh35 = (*doc).encoding;
                    *fresh35 = 0 as *const xmlChar;
                }
                (*doc).standalone = (*ctxt).standalone;
            }
        } else {
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).error).is_some() {
                ((*(*ctxt).sax).error)
                    .expect(
                        "non-null function pointer",
                    )(
                    (*ctxt).userData,
                    b"SAX.startDocument(): out of memory\n\0" as *const u8
                        as *const libc::c_char,
                );
            }
            (*ctxt).errNo = XML_ERR_NO_MEMORY as libc::c_int;
            (*ctxt).instate = XML_PARSER_EOF;
            (*ctxt).disableSAX = 1 as libc::c_int;
            return;
        }
    }
    if !((*ctxt).myDoc).is_null() && ((*(*ctxt).myDoc).URL).is_null()
        && !((*ctxt).input).is_null() && !((*(*ctxt).input).filename).is_null()
    {
        let ref mut fresh36 = (*(*ctxt).myDoc).URL;
        *fresh36 = xmlCanonicPath((*(*ctxt).input).filename as *const xmlChar);
        if ((*(*ctxt).myDoc).URL).is_null() {
            let ref mut fresh37 = (*(*ctxt).myDoc).URL;
            *fresh37 = xmlStrdup((*(*ctxt).input).filename as *const xmlChar);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterSetIndent(
    mut writer: xmlTextWriterPtr,
    mut indent: libc::c_int,
) -> libc::c_int {
    if writer.is_null() || indent < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    (*writer).indent = indent;
    (*writer).doindent = 1 as libc::c_int;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterSetIndentString(
    mut writer: xmlTextWriterPtr,
    mut str: *const xmlChar,
) -> libc::c_int {
    if writer.is_null() || str.is_null() {
        return -(1 as libc::c_int);
    }
    if !((*writer).ichar).is_null() {
        xmlFree
            .expect("non-null function pointer")((*writer).ichar as *mut libc::c_void);
    }
    let ref mut fresh38 = (*writer).ichar;
    *fresh38 = xmlStrdup(str);
    if ((*writer).ichar).is_null() {
        return -(1 as libc::c_int)
    } else {
        return 0 as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlTextWriterSetQuoteChar(
    mut writer: xmlTextWriterPtr,
    mut quotechar: xmlChar,
) -> libc::c_int {
    if writer.is_null()
        || quotechar as libc::c_int != '\'' as i32
            && quotechar as libc::c_int != '"' as i32
    {
        return -(1 as libc::c_int);
    }
    (*writer).qchar = quotechar as libc::c_char;
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlTextWriterWriteIndent(
    mut writer: xmlTextWriterPtr,
) -> libc::c_int {
    let mut lksize: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    lksize = xmlListSize((*writer).nodes);
    if lksize < 1 as libc::c_int {
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int;
    while i < lksize - 1 as libc::c_int {
        ret = xmlOutputBufferWriteString(
            (*writer).out,
            (*writer).ichar as *const libc::c_char,
        );
        if ret == -(1 as libc::c_int) {
            return -(1 as libc::c_int);
        }
        i += 1;
    }
    return lksize - 1 as libc::c_int;
}
unsafe extern "C" fn xmlTextWriterHandleStateDependencies(
    mut writer: xmlTextWriterPtr,
    mut p: *mut xmlTextWriterStackEntry,
) -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    let mut extra: [libc::c_char; 3] = [0; 3];
    if writer.is_null() {
        return -(1 as libc::c_int);
    }
    if p.is_null() {
        return 0 as libc::c_int;
    }
    sum = 0 as libc::c_int;
    extra[2 as libc::c_int as usize] = '\u{0}' as i32 as libc::c_char;
    extra[1 as libc::c_int as usize] = extra[2 as libc::c_int as usize];
    extra[0 as libc::c_int as usize] = extra[1 as libc::c_int as usize];
    if !p.is_null() {
        sum = 0 as libc::c_int;
        match (*p).state as libc::c_uint {
            1 => {
                count = xmlTextWriterOutputNSDecl(writer);
                if count < 0 as libc::c_int {
                    return -(1 as libc::c_int);
                }
                sum += count;
                extra[0 as libc::c_int as usize] = '>' as i32 as libc::c_char;
                (*p).state = XML_TEXTWRITER_TEXT;
            }
            4 => {
                extra[0 as libc::c_int as usize] = ' ' as i32 as libc::c_char;
                (*p).state = XML_TEXTWRITER_PI_TEXT;
            }
            7 => {
                extra[0 as libc::c_int as usize] = ' ' as i32 as libc::c_char;
                extra[1 as libc::c_int as usize] = '[' as i32 as libc::c_char;
                (*p).state = XML_TEXTWRITER_DTD_TEXT;
            }
            9 => {
                extra[0 as libc::c_int as usize] = ' ' as i32 as libc::c_char;
                (*p).state = XML_TEXTWRITER_DTD_ELEM_TEXT;
            }
            11 => {
                extra[0 as libc::c_int as usize] = ' ' as i32 as libc::c_char;
                (*p).state = XML_TEXTWRITER_DTD_ATTL_TEXT;
            }
            13 | 15 => {
                extra[0 as libc::c_int as usize] = ' ' as i32 as libc::c_char;
                extra[1 as libc::c_int as usize] = (*writer).qchar;
                (*p).state = XML_TEXTWRITER_DTD_ENTY_TEXT;
            }
            _ => {}
        }
    }
    if *extra.as_mut_ptr() as libc::c_int != '\u{0}' as i32 {
        count = xmlOutputBufferWriteString((*writer).out, extra.as_mut_ptr());
        if count < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        sum += count;
    }
    return sum;
}
