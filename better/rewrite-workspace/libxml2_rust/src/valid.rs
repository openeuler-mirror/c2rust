use ::libc;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcat(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    static mut xmlFree: xmlFreeFunc;
    static mut xmlMalloc: xmlMallocFunc;
    
    static mut xmlRealloc: xmlReallocFunc;
    
    
    static xmlIsCombiningGroup: xmlChRangeGroup;
    
    
    static xmlIsBaseCharGroup: xmlChRangeGroup;
    static xmlIsExtenderGroup: xmlChRangeGroup;
    static xmlIsDigitGroup: xmlChRangeGroup;
}
pub use crate::src::chvalid::xmlCharInRange;
pub use crate::src::dict::xmlDictLookup;
pub use crate::src::dict::xmlDictOwns;
pub use crate::src::entities::xmlGetDocEntity;
pub use crate::src::error::__xmlRaiseError;
pub use crate::src::hash::xmlHashAddEntry;
pub use crate::src::hash::xmlHashAddEntry2;
pub use crate::src::hash::xmlHashAddEntry3;
pub use crate::src::hash::xmlHashCopy;
pub use crate::src::hash::xmlHashCreateDict;
pub use crate::src::hash::xmlHashFree;
pub use crate::src::hash::xmlHashLookup;
pub use crate::src::hash::xmlHashLookup2;
pub use crate::src::hash::xmlHashLookup3;
pub use crate::src::hash::xmlHashRemoveEntry;
pub use crate::src::hash::xmlHashRemoveEntry2;
pub use crate::src::hash::xmlHashScan;
pub use crate::src::hash::xmlHashScan3;
pub use crate::src::hash::xmlHashUpdateEntry;
pub use crate::src::list::xmlLinkGetData;
pub use crate::src::list::xmlListAppend;
pub use crate::src::list::xmlListCreate;
pub use crate::src::list::xmlListDelete;
pub use crate::src::list::xmlListEmpty;
pub use crate::src::list::xmlListRemoveFirst;
pub use crate::src::list::xmlListWalk;
pub use crate::src::parser::xmlParseDTD;
pub use crate::src::parserInternals::xmlStringCurrentChar;
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
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrlen;
pub use crate::src::xmlstring::xmlStrncmp;
pub use crate::src::xmlstring::xmlStrndup;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::list::_xmlLink;
pub use crate::src::list::_xmlList;
pub use crate::src::parser::_xmlStartTag;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::xmlregexp::_xmlRegExecCtxt;
pub use crate::src::xmlregexp::_xmlRegexp;
pub use crate::src::HTMLparser::xmlChar;
pub use crate::src::HTMLparser::size_t;
pub use crate::src::HTMLparser::xmlFreeFunc;
pub use crate::src::HTMLparser::xmlMallocFunc;
pub use crate::src::HTMLparser::xmlReallocFunc;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlValidState {
    pub elemDecl: xmlElementPtr,
    pub node: xmlNodePtr,
    pub exec: xmlRegExecCtxtPtr,
}
pub use crate::src::relaxng::xmlRegExecCtxtPtr;
pub use crate::src::relaxng::xmlRegExecCtxt;
pub use crate::src::SAX2::xmlElementPtr;
pub use crate::src::SAX2::xmlElement;
// #[derive(Copy, Clone)]

pub use crate::src::SAX2::_xmlElement;
pub use crate::src::SAX2::xmlRegexpPtr;
pub use crate::src::SAX2::xmlRegexp;
pub use crate::src::SAX2::xmlAttributePtr;
pub use crate::src::SAX2::xmlAttribute;
// #[derive(Copy, Clone)]

pub use crate::src::SAX2::_xmlAttribute;
pub use crate::src::HTMLparser::xmlEnumerationPtr;
pub use crate::src::HTMLparser::xmlEnumeration;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlEnumeration;
pub use crate::src::SAX2::xmlAttributeDefault;
pub const XML_ATTRIBUTE_FIXED: xmlAttributeDefault = 4;
pub const XML_ATTRIBUTE_IMPLIED: xmlAttributeDefault = 3;
pub const XML_ATTRIBUTE_REQUIRED: xmlAttributeDefault = 2;
pub const XML_ATTRIBUTE_NONE: xmlAttributeDefault = 1;
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
pub use crate::src::SAX2::xmlElementTypeVal;
pub const XML_ELEMENT_TYPE_ELEMENT: xmlElementTypeVal = 4;
pub const XML_ELEMENT_TYPE_MIXED: xmlElementTypeVal = 3;
pub const XML_ELEMENT_TYPE_ANY: xmlElementTypeVal = 2;
pub const XML_ELEMENT_TYPE_EMPTY: xmlElementTypeVal = 1;
pub const XML_ELEMENT_TYPE_UNDEFINED: xmlElementTypeVal = 0;
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
pub use crate::src::HTMLparser::attributeDeclSAXFunc;
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
// #[derive(Copy, Clone)]

pub use crate::src::SAX2::_xmlNotation;
pub use crate::src::SAX2::xmlNotation;
pub use crate::src::SAX2::xmlNotationPtr;
pub use crate::src::relaxng::xmlRegExecCallbacks;
pub use crate::src::HTMLtree::xmlNsPtr;
pub use crate::src::HTMLparser::xmlDtd;
pub use crate::src::HTMLparser::xmlDtdPtr;
// #[derive(Copy, Clone)]

pub use crate::src::SAX2::_xmlID;
pub use crate::src::SAX2::xmlID;
pub use crate::src::SAX2::xmlIDPtr;
// #[derive(Copy, Clone)]

pub use crate::src::SAX2::_xmlRef;
pub use crate::src::SAX2::xmlRef;
pub use crate::src::SAX2::xmlRefPtr;
pub type C2RustUnnamed = libc::c_uint;
pub const XML_DOC_HTML: C2RustUnnamed = 128;
pub const XML_DOC_INTERNAL: C2RustUnnamed = 64;
pub const XML_DOC_USERBUILT: C2RustUnnamed = 32;
pub const XML_DOC_XINCLUDE: C2RustUnnamed = 16;
pub const XML_DOC_DTDVALID: C2RustUnnamed = 8;
pub const XML_DOC_OLD10: C2RustUnnamed = 4;
pub const XML_DOC_NSVALID: C2RustUnnamed = 2;
pub const XML_DOC_WELLFORMED: C2RustUnnamed = 1;
pub use crate::src::HTMLparser::xmlHashDeallocator;
pub use crate::src::entities::xmlHashCopier;
pub use crate::src::catalog::xmlHashScanner;
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
pub const XML_FROM_TREE: C2RustUnnamed_0 = 2;
pub const XML_FROM_PARSER: C2RustUnnamed_0 = 1;
pub const XML_FROM_NONE: C2RustUnnamed_0 = 0;
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
pub use crate::src::c14n::xmlListWalker;
pub type xmlValidStatePtr = *mut xmlValidState;
pub use crate::src::SAX2::xmlValidCtxtPtr;
pub use crate::src::tree::xmlNotationTable;
pub use crate::src::tree::xmlNotationTablePtr;
pub use crate::src::tree::xmlElementTable;
pub use crate::src::tree::xmlElementTablePtr;
pub use crate::src::tree::xmlAttributeTable;
pub use crate::src::tree::xmlAttributeTablePtr;
pub use crate::src::tree::xmlIDTable;
pub use crate::src::tree::xmlIDTablePtr;
pub use crate::src::tree::xmlRefTable;
pub use crate::src::tree::xmlRefTablePtr;
pub use crate::src::HTMLparser::xmlChRangeGroup;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlChRangeGroup;
pub use crate::src::HTMLparser::xmlChLRange;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlChLRange;
pub use crate::src::HTMLparser::xmlChSRange;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlChSRange;
pub type xmlRemoveMemo = xmlRemoveMemo_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlRemoveMemo_t {
    pub l: xmlListPtr,
    pub ap: xmlAttrPtr,
}
pub type xmlRemoveMemoPtr = *mut xmlRemoveMemo;
pub type xmlValidateMemo = xmlValidateMemo_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlValidateMemo_t {
    pub ctxt: xmlValidCtxtPtr,
    pub name: *const xmlChar,
}
pub type xmlValidateMemoPtr = *mut xmlValidateMemo;
pub use crate::src::debugXML::xmlEntitiesTablePtr;
pub use crate::src::debugXML::xmlEntitiesTable;
unsafe extern "C" fn xmlVErrMemory(
    mut ctxt: xmlValidCtxtPtr,
    mut extra: *const libc::c_char,
) {
    let mut channel: xmlGenericErrorFunc = None;
    let mut pctxt: xmlParserCtxtPtr = 0 as xmlParserCtxtPtr;
    let mut data: *mut libc::c_void = 0 as *mut libc::c_void;
    if !ctxt.is_null() {
        channel = (*ctxt).error;
        data = (*ctxt).userData;
        if (*ctxt).flags & (1 as libc::c_uint) << 1 as libc::c_int != 0 {
            let mut delta: libc::c_long = (ctxt as *mut libc::c_char)
                .offset_from((*ctxt).userData as *mut libc::c_char) as libc::c_long;
            if delta > 0 as libc::c_int as libc::c_long
                && delta < 250 as libc::c_int as libc::c_long
            {
                pctxt = (*ctxt).userData as xmlParserCtxtPtr;
            }
        }
    }
    if !extra.is_null() {
        __xmlRaiseError(
            None,
            channel,
            data,
            pctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_VALID as libc::c_int,
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
            channel,
            data,
            pctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_VALID as libc::c_int,
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
unsafe extern "C" fn xmlErrValid(
    mut ctxt: xmlValidCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut extra: *const libc::c_char,
) {
    let mut channel: xmlGenericErrorFunc = None;
    let mut pctxt: xmlParserCtxtPtr = 0 as xmlParserCtxtPtr;
    let mut data: *mut libc::c_void = 0 as *mut libc::c_void;
    if !ctxt.is_null() {
        channel = (*ctxt).error;
        data = (*ctxt).userData;
        if (*ctxt).flags & (1 as libc::c_uint) << 1 as libc::c_int != 0 {
            let mut delta: libc::c_long = (ctxt as *mut libc::c_char)
                .offset_from((*ctxt).userData as *mut libc::c_char) as libc::c_long;
            if delta > 0 as libc::c_int as libc::c_long
                && delta < 250 as libc::c_int as libc::c_long
            {
                pctxt = (*ctxt).userData as xmlParserCtxtPtr;
            }
        }
    }
    if !extra.is_null() {
        __xmlRaiseError(
            None,
            channel,
            data,
            pctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_VALID as libc::c_int,
            error as libc::c_int,
            XML_ERR_ERROR,
            0 as *const libc::c_char,
            0 as libc::c_int,
            extra,
            0 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as libc::c_int,
            msg,
            extra,
        );
    } else {
        __xmlRaiseError(
            None,
            channel,
            data,
            pctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_VALID as libc::c_int,
            error as libc::c_int,
            XML_ERR_ERROR,
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
unsafe extern "C" fn xmlErrValidNode(
    mut ctxt: xmlValidCtxtPtr,
    mut node: xmlNodePtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut str3: *const xmlChar,
) {
    let mut schannel: xmlStructuredErrorFunc = None;
    let mut channel: xmlGenericErrorFunc = None;
    let mut pctxt: xmlParserCtxtPtr = 0 as xmlParserCtxtPtr;
    let mut data: *mut libc::c_void = 0 as *mut libc::c_void;
    if !ctxt.is_null() {
        channel = (*ctxt).error;
        data = (*ctxt).userData;
        if (*ctxt).flags & (1 as libc::c_uint) << 1 as libc::c_int != 0 {
            let mut delta: libc::c_long = (ctxt as *mut libc::c_char)
                .offset_from((*ctxt).userData as *mut libc::c_char) as libc::c_long;
            if delta > 0 as libc::c_int as libc::c_long
                && delta < 250 as libc::c_int as libc::c_long
            {
                pctxt = (*ctxt).userData as xmlParserCtxtPtr;
            }
        }
    }
    __xmlRaiseError(
        schannel,
        channel,
        data,
        pctxt as *mut libc::c_void,
        node as *mut libc::c_void,
        XML_FROM_VALID as libc::c_int,
        error as libc::c_int,
        XML_ERR_ERROR,
        0 as *const libc::c_char,
        0 as libc::c_int,
        str1 as *const libc::c_char,
        str2 as *const libc::c_char,
        str3 as *const libc::c_char,
        0 as libc::c_int,
        0 as libc::c_int,
        msg,
        str1,
        str2,
        str3,
    );
}
unsafe extern "C" fn xmlErrValidNodeNr(
    mut ctxt: xmlValidCtxtPtr,
    mut node: xmlNodePtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut str1: *const xmlChar,
    mut int2: libc::c_int,
    mut str3: *const xmlChar,
) {
    let mut schannel: xmlStructuredErrorFunc = None;
    let mut channel: xmlGenericErrorFunc = None;
    let mut pctxt: xmlParserCtxtPtr = 0 as xmlParserCtxtPtr;
    let mut data: *mut libc::c_void = 0 as *mut libc::c_void;
    if !ctxt.is_null() {
        channel = (*ctxt).error;
        data = (*ctxt).userData;
        if (*ctxt).flags & (1 as libc::c_uint) << 1 as libc::c_int != 0 {
            let mut delta: libc::c_long = (ctxt as *mut libc::c_char)
                .offset_from((*ctxt).userData as *mut libc::c_char) as libc::c_long;
            if delta > 0 as libc::c_int as libc::c_long
                && delta < 250 as libc::c_int as libc::c_long
            {
                pctxt = (*ctxt).userData as xmlParserCtxtPtr;
            }
        }
    }
    __xmlRaiseError(
        schannel,
        channel,
        data,
        pctxt as *mut libc::c_void,
        node as *mut libc::c_void,
        XML_FROM_VALID as libc::c_int,
        error as libc::c_int,
        XML_ERR_ERROR,
        0 as *const libc::c_char,
        0 as libc::c_int,
        str1 as *const libc::c_char,
        str3 as *const libc::c_char,
        0 as *const libc::c_char,
        int2,
        0 as libc::c_int,
        msg,
        str1,
        int2,
        str3,
    );
}
unsafe extern "C" fn xmlErrValidWarning(
    mut ctxt: xmlValidCtxtPtr,
    mut node: xmlNodePtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut str3: *const xmlChar,
) {
    let mut schannel: xmlStructuredErrorFunc = None;
    let mut channel: xmlGenericErrorFunc = None;
    let mut pctxt: xmlParserCtxtPtr = 0 as xmlParserCtxtPtr;
    let mut data: *mut libc::c_void = 0 as *mut libc::c_void;
    if !ctxt.is_null() {
        channel = (*ctxt).warning;
        data = (*ctxt).userData;
        if (*ctxt).flags & (1 as libc::c_uint) << 1 as libc::c_int != 0 {
            let mut delta: libc::c_long = (ctxt as *mut libc::c_char)
                .offset_from((*ctxt).userData as *mut libc::c_char) as libc::c_long;
            if delta > 0 as libc::c_int as libc::c_long
                && delta < 250 as libc::c_int as libc::c_long
            {
                pctxt = (*ctxt).userData as xmlParserCtxtPtr;
            }
        }
    }
    __xmlRaiseError(
        schannel,
        channel,
        data,
        pctxt as *mut libc::c_void,
        node as *mut libc::c_void,
        XML_FROM_VALID as libc::c_int,
        error as libc::c_int,
        XML_ERR_WARNING,
        0 as *const libc::c_char,
        0 as libc::c_int,
        str1 as *const libc::c_char,
        str2 as *const libc::c_char,
        str3 as *const libc::c_char,
        0 as libc::c_int,
        0 as libc::c_int,
        msg,
        str1,
        str2,
        str3,
    );
}
unsafe extern "C" fn vstateVPush(
    mut ctxt: xmlValidCtxtPtr,
    mut elemDecl: xmlElementPtr,
    mut node: xmlNodePtr,
) -> libc::c_int {
    if (*ctxt).vstateMax == 0 as libc::c_int || ((*ctxt).vstateTab).is_null() {
        (*ctxt).vstateMax = 10 as libc::c_int;
        let ref mut fresh0 = (*ctxt).vstateTab;
        *fresh0 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*ctxt).vstateMax as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlValidState>() as libc::c_ulong),
        ) as *mut xmlValidState;
        if ((*ctxt).vstateTab).is_null() {
            xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const libc::c_char);
            return -(1 as libc::c_int);
        }
    }
    if (*ctxt).vstateNr >= (*ctxt).vstateMax {
        let mut tmp: *mut xmlValidState = 0 as *mut xmlValidState;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).vstateTab as *mut libc::c_void,
            ((2 as libc::c_int * (*ctxt).vstateMax) as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlValidState>() as libc::c_ulong),
        ) as *mut xmlValidState;
        if tmp.is_null() {
            xmlVErrMemory(ctxt, b"realloc failed\0" as *const u8 as *const libc::c_char);
            return -(1 as libc::c_int);
        }
        (*ctxt).vstateMax *= 2 as libc::c_int;
        let ref mut fresh1 = (*ctxt).vstateTab;
        *fresh1 = tmp;
    }
    let ref mut fresh2 = (*ctxt).vstate;
    *fresh2 = &mut *((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)
        as *mut xmlValidState;
    let ref mut fresh3 = (*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize))
        .elemDecl;
    *fresh3 = elemDecl;
    let ref mut fresh4 = (*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).node;
    *fresh4 = node;
    if !elemDecl.is_null()
        && (*elemDecl).etype as libc::c_uint
            == XML_ELEMENT_TYPE_ELEMENT as libc::c_int as libc::c_uint
    {
        if ((*elemDecl).contModel).is_null() {
            xmlValidBuildContentModel(ctxt, elemDecl);
        }
        if !((*elemDecl).contModel).is_null() {
            let ref mut fresh5 = (*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize))
                .exec;
            *fresh5 = xmlRegNewExecCtxt(
                (*elemDecl).contModel,
                None,
                0 as *mut libc::c_void,
            );
        } else {
            let ref mut fresh6 = (*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize))
                .exec;
            *fresh6 = 0 as xmlRegExecCtxtPtr;
            xmlErrValidNode(
                ctxt,
                elemDecl as xmlNodePtr,
                XML_ERR_INTERNAL_ERROR,
                b"Failed to build content model regexp for %s\n\0" as *const u8
                    as *const libc::c_char,
                (*node).name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
    }
    let ref mut fresh7 = (*ctxt).vstateNr;
    let fresh8 = *fresh7;
    *fresh7 = *fresh7 + 1;
    return fresh8;
}
unsafe extern "C" fn vstateVPop(mut ctxt: xmlValidCtxtPtr) -> libc::c_int {
    let mut elemDecl: xmlElementPtr = 0 as *mut xmlElement;
    if (*ctxt).vstateNr < 1 as libc::c_int {
        return -(1 as libc::c_int);
    }
    let ref mut fresh9 = (*ctxt).vstateNr;
    *fresh9 -= 1;
    elemDecl = (*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).elemDecl;
    let ref mut fresh10 = (*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize))
        .elemDecl;
    *fresh10 = 0 as xmlElementPtr;
    let ref mut fresh11 = (*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).node;
    *fresh11 = 0 as xmlNodePtr;
    if !elemDecl.is_null()
        && (*elemDecl).etype as libc::c_uint
            == XML_ELEMENT_TYPE_ELEMENT as libc::c_int as libc::c_uint
    {
        xmlRegFreeExecCtxt(
            (*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).exec,
        );
    }
    let ref mut fresh12 = (*((*ctxt).vstateTab).offset((*ctxt).vstateNr as isize)).exec;
    *fresh12 = 0 as xmlRegExecCtxtPtr;
    if (*ctxt).vstateNr >= 1 as libc::c_int {
        let ref mut fresh13 = (*ctxt).vstate;
        *fresh13 = &mut *((*ctxt).vstateTab)
            .offset(((*ctxt).vstateNr - 1 as libc::c_int) as isize)
            as *mut xmlValidState;
    } else {
        let ref mut fresh14 = (*ctxt).vstate;
        *fresh14 = 0 as *mut xmlValidState;
    }
    return (*ctxt).vstateNr;
}
unsafe extern "C" fn nodeVPush(
    mut ctxt: xmlValidCtxtPtr,
    mut value: xmlNodePtr,
) -> libc::c_int {
    if (*ctxt).nodeMax <= 0 as libc::c_int {
        (*ctxt).nodeMax = 4 as libc::c_int;
        let ref mut fresh15 = (*ctxt).nodeTab;
        *fresh15 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*ctxt).nodeMax as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as libc::c_ulong),
        ) as *mut xmlNodePtr;
        if ((*ctxt).nodeTab).is_null() {
            xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const libc::c_char);
            (*ctxt).nodeMax = 0 as libc::c_int;
            return 0 as libc::c_int;
        }
    }
    if (*ctxt).nodeNr >= (*ctxt).nodeMax {
        let mut tmp: *mut xmlNodePtr = 0 as *mut xmlNodePtr;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).nodeTab as *mut libc::c_void,
            (((*ctxt).nodeMax * 2 as libc::c_int) as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as libc::c_ulong),
        ) as *mut xmlNodePtr;
        if tmp.is_null() {
            xmlVErrMemory(ctxt, b"realloc failed\0" as *const u8 as *const libc::c_char);
            return 0 as libc::c_int;
        }
        (*ctxt).nodeMax *= 2 as libc::c_int;
        let ref mut fresh16 = (*ctxt).nodeTab;
        *fresh16 = tmp;
    }
    let ref mut fresh17 = *((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize);
    *fresh17 = value;
    let ref mut fresh18 = (*ctxt).node;
    *fresh18 = value;
    let ref mut fresh19 = (*ctxt).nodeNr;
    let fresh20 = *fresh19;
    *fresh19 = *fresh19 + 1;
    return fresh20;
}
unsafe extern "C" fn nodeVPop(mut ctxt: xmlValidCtxtPtr) -> xmlNodePtr {
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    if (*ctxt).nodeNr <= 0 as libc::c_int {
        return 0 as xmlNodePtr;
    }
    let ref mut fresh21 = (*ctxt).nodeNr;
    *fresh21 -= 1;
    if (*ctxt).nodeNr > 0 as libc::c_int {
        let ref mut fresh22 = (*ctxt).node;
        *fresh22 = *((*ctxt).nodeTab)
            .offset(((*ctxt).nodeNr - 1 as libc::c_int) as isize);
    } else {
        let ref mut fresh23 = (*ctxt).node;
        *fresh23 = 0 as xmlNodePtr;
    }
    ret = *((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize);
    let ref mut fresh24 = *((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize);
    *fresh24 = 0 as xmlNodePtr;
    return ret;
}
unsafe extern "C" fn xmlValidBuildAContentModel(
    mut content: xmlElementContentPtr,
    mut ctxt: xmlValidCtxtPtr,
    mut name: *const xmlChar,
) -> libc::c_int {
    if content.is_null() {
        xmlErrValidNode(
            ctxt,
            0 as xmlNodePtr,
            XML_ERR_INTERNAL_ERROR,
            b"Found NULL content in content model of %s\n\0" as *const u8
                as *const libc::c_char,
            name,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as libc::c_int;
    }
    match (*content).type_0 as libc::c_uint {
        1 => {
            xmlErrValidNode(
                ctxt,
                0 as xmlNodePtr,
                XML_ERR_INTERNAL_ERROR,
                b"Found PCDATA in content model of %s\n\0" as *const u8
                    as *const libc::c_char,
                name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as libc::c_int;
        }
        2 => {
            let mut oldstate: xmlAutomataStatePtr = (*ctxt).state;
            let mut fn_0: [xmlChar; 50] = [0; 50];
            let mut fullname: *mut xmlChar = 0 as *mut xmlChar;
            fullname = xmlBuildQName(
                (*content).name,
                (*content).prefix,
                fn_0.as_mut_ptr(),
                50 as libc::c_int,
            );
            if fullname.is_null() {
                xmlVErrMemory(
                    ctxt,
                    b"Building content model\0" as *const u8 as *const libc::c_char,
                );
                return 0 as libc::c_int;
            }
            match (*content).ocur as libc::c_uint {
                1 => {
                    let ref mut fresh25 = (*ctxt).state;
                    *fresh25 = xmlAutomataNewTransition(
                        (*ctxt).am,
                        (*ctxt).state,
                        0 as xmlAutomataStatePtr,
                        fullname,
                        0 as *mut libc::c_void,
                    );
                }
                2 => {
                    let ref mut fresh26 = (*ctxt).state;
                    *fresh26 = xmlAutomataNewTransition(
                        (*ctxt).am,
                        (*ctxt).state,
                        0 as xmlAutomataStatePtr,
                        fullname,
                        0 as *mut libc::c_void,
                    );
                    xmlAutomataNewEpsilon((*ctxt).am, oldstate, (*ctxt).state);
                }
                4 => {
                    let ref mut fresh27 = (*ctxt).state;
                    *fresh27 = xmlAutomataNewTransition(
                        (*ctxt).am,
                        (*ctxt).state,
                        0 as xmlAutomataStatePtr,
                        fullname,
                        0 as *mut libc::c_void,
                    );
                    xmlAutomataNewTransition(
                        (*ctxt).am,
                        (*ctxt).state,
                        (*ctxt).state,
                        fullname,
                        0 as *mut libc::c_void,
                    );
                }
                3 => {
                    let ref mut fresh28 = (*ctxt).state;
                    *fresh28 = xmlAutomataNewEpsilon(
                        (*ctxt).am,
                        (*ctxt).state,
                        0 as xmlAutomataStatePtr,
                    );
                    xmlAutomataNewTransition(
                        (*ctxt).am,
                        (*ctxt).state,
                        (*ctxt).state,
                        fullname,
                        0 as *mut libc::c_void,
                    );
                }
                _ => {}
            }
            if fullname != fn_0.as_mut_ptr()
                && fullname != (*content).name as *mut xmlChar
            {
                xmlFree
                    .expect("non-null function pointer")(fullname as *mut libc::c_void);
            }
        }
        3 => {
            let mut oldstate_0: xmlAutomataStatePtr = 0 as *mut xmlAutomataState;
            let mut oldend: xmlAutomataStatePtr = 0 as *mut xmlAutomataState;
            let mut ocur: xmlElementContentOccur = 0 as xmlElementContentOccur;
            oldstate_0 = (*ctxt).state;
            ocur = (*content).ocur;
            if ocur as libc::c_uint
                != XML_ELEMENT_CONTENT_ONCE as libc::c_int as libc::c_uint
            {
                let ref mut fresh29 = (*ctxt).state;
                *fresh29 = xmlAutomataNewEpsilon(
                    (*ctxt).am,
                    oldstate_0,
                    0 as xmlAutomataStatePtr,
                );
                oldstate_0 = (*ctxt).state;
            }
            loop {
                xmlValidBuildAContentModel((*content).c1, ctxt, name);
                content = (*content).c2;
                if !((*content).type_0 as libc::c_uint
                    == XML_ELEMENT_CONTENT_SEQ as libc::c_int as libc::c_uint
                    && (*content).ocur as libc::c_uint
                        == XML_ELEMENT_CONTENT_ONCE as libc::c_int as libc::c_uint)
                {
                    break;
                }
            }
            xmlValidBuildAContentModel(content, ctxt, name);
            oldend = (*ctxt).state;
            let ref mut fresh30 = (*ctxt).state;
            *fresh30 = xmlAutomataNewEpsilon(
                (*ctxt).am,
                oldend,
                0 as xmlAutomataStatePtr,
            );
            match ocur as libc::c_uint {
                2 => {
                    xmlAutomataNewEpsilon((*ctxt).am, oldstate_0, (*ctxt).state);
                }
                3 => {
                    xmlAutomataNewEpsilon((*ctxt).am, oldstate_0, (*ctxt).state);
                    xmlAutomataNewEpsilon((*ctxt).am, oldend, oldstate_0);
                }
                4 => {
                    xmlAutomataNewEpsilon((*ctxt).am, oldend, oldstate_0);
                }
                1 | _ => {}
            }
        }
        4 => {
            let mut oldstate_1: xmlAutomataStatePtr = 0 as *mut xmlAutomataState;
            let mut oldend_0: xmlAutomataStatePtr = 0 as *mut xmlAutomataState;
            let mut ocur_0: xmlElementContentOccur = 0 as xmlElementContentOccur;
            ocur_0 = (*content).ocur;
            if ocur_0 as libc::c_uint
                == XML_ELEMENT_CONTENT_PLUS as libc::c_int as libc::c_uint
                || ocur_0 as libc::c_uint
                    == XML_ELEMENT_CONTENT_MULT as libc::c_int as libc::c_uint
            {
                let ref mut fresh31 = (*ctxt).state;
                *fresh31 = xmlAutomataNewEpsilon(
                    (*ctxt).am,
                    (*ctxt).state,
                    0 as xmlAutomataStatePtr,
                );
            }
            oldstate_1 = (*ctxt).state;
            oldend_0 = xmlAutomataNewState((*ctxt).am);
            loop {
                let ref mut fresh32 = (*ctxt).state;
                *fresh32 = oldstate_1;
                xmlValidBuildAContentModel((*content).c1, ctxt, name);
                xmlAutomataNewEpsilon((*ctxt).am, (*ctxt).state, oldend_0);
                content = (*content).c2;
                if !((*content).type_0 as libc::c_uint
                    == XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                    && (*content).ocur as libc::c_uint
                        == XML_ELEMENT_CONTENT_ONCE as libc::c_int as libc::c_uint)
                {
                    break;
                }
            }
            let ref mut fresh33 = (*ctxt).state;
            *fresh33 = oldstate_1;
            xmlValidBuildAContentModel(content, ctxt, name);
            xmlAutomataNewEpsilon((*ctxt).am, (*ctxt).state, oldend_0);
            let ref mut fresh34 = (*ctxt).state;
            *fresh34 = xmlAutomataNewEpsilon(
                (*ctxt).am,
                oldend_0,
                0 as xmlAutomataStatePtr,
            );
            match ocur_0 as libc::c_uint {
                2 => {
                    xmlAutomataNewEpsilon((*ctxt).am, oldstate_1, (*ctxt).state);
                }
                3 => {
                    xmlAutomataNewEpsilon((*ctxt).am, oldstate_1, (*ctxt).state);
                    xmlAutomataNewEpsilon((*ctxt).am, oldend_0, oldstate_1);
                }
                4 => {
                    xmlAutomataNewEpsilon((*ctxt).am, oldend_0, oldstate_1);
                }
                1 | _ => {}
            }
        }
        _ => {
            xmlErrValid(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"ContentModel broken for element %s\n\0" as *const u8
                    as *const libc::c_char,
                name as *const libc::c_char,
            );
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidBuildContentModel(
    mut ctxt: xmlValidCtxtPtr,
    mut elem: xmlElementPtr,
) -> libc::c_int {
    if ctxt.is_null() || elem.is_null() {
        return 0 as libc::c_int;
    }
    if (*elem).type_0 as libc::c_uint != XML_ELEMENT_DECL as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    if (*elem).etype as libc::c_uint
        != XML_ELEMENT_TYPE_ELEMENT as libc::c_int as libc::c_uint
    {
        return 1 as libc::c_int;
    }
    if !((*elem).contModel).is_null() {
        if xmlRegexpIsDeterminist((*elem).contModel) == 0 {
            (*ctxt).valid = 0 as libc::c_int;
            return 0 as libc::c_int;
        }
        return 1 as libc::c_int;
    }
    let ref mut fresh35 = (*ctxt).am;
    *fresh35 = xmlNewAutomata();
    if ((*ctxt).am).is_null() {
        xmlErrValidNode(
            ctxt,
            elem as xmlNodePtr,
            XML_ERR_INTERNAL_ERROR,
            b"Cannot create automata for element %s\n\0" as *const u8
                as *const libc::c_char,
            (*elem).name,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as libc::c_int;
    }
    let ref mut fresh36 = (*ctxt).state;
    *fresh36 = xmlAutomataGetInitState((*ctxt).am);
    xmlValidBuildAContentModel((*elem).content, ctxt, (*elem).name);
    xmlAutomataSetFinalState((*ctxt).am, (*ctxt).state);
    let ref mut fresh37 = (*elem).contModel;
    *fresh37 = xmlAutomataCompile((*ctxt).am);
    if xmlRegexpIsDeterminist((*elem).contModel) != 1 as libc::c_int {
        let mut expr: [libc::c_char; 5000] = [0; 5000];
        expr[0 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
        xmlSnprintfElementContent(
            expr.as_mut_ptr(),
            5000 as libc::c_int,
            (*elem).content,
            1 as libc::c_int,
        );
        xmlErrValidNode(
            ctxt,
            elem as xmlNodePtr,
            XML_DTD_CONTENT_NOT_DETERMINIST,
            b"Content model of %s is not determinist: %s\n\0" as *const u8
                as *const libc::c_char,
            (*elem).name,
            expr.as_mut_ptr() as *mut xmlChar,
            0 as *const xmlChar,
        );
        (*ctxt).valid = 0 as libc::c_int;
        let ref mut fresh38 = (*ctxt).state;
        *fresh38 = 0 as xmlAutomataStatePtr;
        xmlFreeAutomata((*ctxt).am);
        let ref mut fresh39 = (*ctxt).am;
        *fresh39 = 0 as xmlAutomataPtr;
        return 0 as libc::c_int;
    }
    let ref mut fresh40 = (*ctxt).state;
    *fresh40 = 0 as xmlAutomataStatePtr;
    xmlFreeAutomata((*ctxt).am);
    let ref mut fresh41 = (*ctxt).am;
    *fresh41 = 0 as xmlAutomataPtr;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewValidCtxt() -> xmlValidCtxtPtr {
    let mut ret: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlValidCtxt>() as libc::c_ulong) as xmlValidCtxtPtr;
    if ret.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlValidCtxtPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlValidCtxt>() as libc::c_ulong,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeValidCtxt(mut cur: xmlValidCtxtPtr) {
    if !((*cur).vstateTab).is_null() {
        xmlFree
            .expect("non-null function pointer")((*cur).vstateTab as *mut libc::c_void);
    }
    if !((*cur).nodeTab).is_null() {
        xmlFree.expect("non-null function pointer")((*cur).nodeTab as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewDocElementContent(
    mut doc: xmlDocPtr,
    mut name: *const xmlChar,
    mut type_0: xmlElementContentType,
) -> xmlElementContentPtr {
    let mut ret: xmlElementContentPtr = 0 as *mut xmlElementContent;
    let mut dict: xmlDictPtr = 0 as xmlDictPtr;
    if !doc.is_null() {
        dict = (*doc).dict;
    }
    match type_0 as libc::c_uint {
        2 => {
            if name.is_null() {
                xmlErrValid(
                    0 as xmlValidCtxtPtr,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlNewElementContent : name == NULL !\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const libc::c_char,
                );
            }
        }
        1 | 3 | 4 => {
            if !name.is_null() {
                xmlErrValid(
                    0 as xmlValidCtxtPtr,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlNewElementContent : name != NULL !\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const libc::c_char,
                );
            }
        }
        _ => {
            xmlErrValid(
                0 as xmlValidCtxtPtr,
                XML_ERR_INTERNAL_ERROR,
                b"Internal: ELEMENT content corrupted invalid type\n\0" as *const u8
                    as *const libc::c_char,
                0 as *const libc::c_char,
            );
            return 0 as xmlElementContentPtr;
        }
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlElementContent>() as libc::c_ulong)
        as xmlElementContentPtr;
    if ret.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlElementContentPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlElementContent>() as libc::c_ulong,
    );
    (*ret).type_0 = type_0;
    (*ret).ocur = XML_ELEMENT_CONTENT_ONCE;
    if !name.is_null() {
        let mut l: libc::c_int = 0;
        let mut tmp: *const xmlChar = 0 as *const xmlChar;
        tmp = xmlSplitQName3(name, &mut l);
        if tmp.is_null() {
            if dict.is_null() {
                let ref mut fresh42 = (*ret).name;
                *fresh42 = xmlStrdup(name);
            } else {
                let ref mut fresh43 = (*ret).name;
                *fresh43 = xmlDictLookup(dict, name, -(1 as libc::c_int));
            }
        } else if dict.is_null() {
            let ref mut fresh44 = (*ret).prefix;
            *fresh44 = xmlStrndup(name, l);
            let ref mut fresh45 = (*ret).name;
            *fresh45 = xmlStrdup(tmp);
        } else {
            let ref mut fresh46 = (*ret).prefix;
            *fresh46 = xmlDictLookup(dict, name, l);
            let ref mut fresh47 = (*ret).name;
            *fresh47 = xmlDictLookup(dict, tmp, -(1 as libc::c_int));
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewElementContent(
    mut name: *const xmlChar,
    mut type_0: xmlElementContentType,
) -> xmlElementContentPtr {
    return xmlNewDocElementContent(0 as xmlDocPtr, name, type_0);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyDocElementContent(
    mut doc: xmlDocPtr,
    mut cur: xmlElementContentPtr,
) -> xmlElementContentPtr {
    let mut ret: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut prev: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut tmp: xmlElementContentPtr = 0 as *mut xmlElementContent;
    let mut dict: xmlDictPtr = 0 as xmlDictPtr;
    if cur.is_null() {
        return 0 as xmlElementContentPtr;
    }
    if !doc.is_null() {
        dict = (*doc).dict;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlElementContent>() as libc::c_ulong)
        as xmlElementContentPtr;
    if ret.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlElementContentPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlElementContent>() as libc::c_ulong,
    );
    (*ret).type_0 = (*cur).type_0;
    (*ret).ocur = (*cur).ocur;
    if !((*cur).name).is_null() {
        if !dict.is_null() {
            let ref mut fresh48 = (*ret).name;
            *fresh48 = xmlDictLookup(dict, (*cur).name, -(1 as libc::c_int));
        } else {
            let ref mut fresh49 = (*ret).name;
            *fresh49 = xmlStrdup((*cur).name);
        }
    }
    if !((*cur).prefix).is_null() {
        if !dict.is_null() {
            let ref mut fresh50 = (*ret).prefix;
            *fresh50 = xmlDictLookup(dict, (*cur).prefix, -(1 as libc::c_int));
        } else {
            let ref mut fresh51 = (*ret).prefix;
            *fresh51 = xmlStrdup((*cur).prefix);
        }
    }
    if !((*cur).c1).is_null() {
        let ref mut fresh52 = (*ret).c1;
        *fresh52 = xmlCopyDocElementContent(doc, (*cur).c1);
    }
    if !((*ret).c1).is_null() {
        let ref mut fresh53 = (*(*ret).c1).parent;
        *fresh53 = ret;
    }
    if !((*cur).c2).is_null() {
        prev = ret;
        cur = (*cur).c2;
        while !cur.is_null() {
            tmp = xmlMalloc
                .expect(
                    "non-null function pointer",
                )(::std::mem::size_of::<xmlElementContent>() as libc::c_ulong)
                as xmlElementContentPtr;
            if tmp.is_null() {
                xmlVErrMemory(
                    0 as xmlValidCtxtPtr,
                    b"malloc failed\0" as *const u8 as *const libc::c_char,
                );
                return ret;
            }
            memset(
                tmp as *mut libc::c_void,
                0 as libc::c_int,
                ::std::mem::size_of::<xmlElementContent>() as libc::c_ulong,
            );
            (*tmp).type_0 = (*cur).type_0;
            (*tmp).ocur = (*cur).ocur;
            let ref mut fresh54 = (*prev).c2;
            *fresh54 = tmp;
            let ref mut fresh55 = (*tmp).parent;
            *fresh55 = prev;
            if !((*cur).name).is_null() {
                if !dict.is_null() {
                    let ref mut fresh56 = (*tmp).name;
                    *fresh56 = xmlDictLookup(dict, (*cur).name, -(1 as libc::c_int));
                } else {
                    let ref mut fresh57 = (*tmp).name;
                    *fresh57 = xmlStrdup((*cur).name);
                }
            }
            if !((*cur).prefix).is_null() {
                if !dict.is_null() {
                    let ref mut fresh58 = (*tmp).prefix;
                    *fresh58 = xmlDictLookup(dict, (*cur).prefix, -(1 as libc::c_int));
                } else {
                    let ref mut fresh59 = (*tmp).prefix;
                    *fresh59 = xmlStrdup((*cur).prefix);
                }
            }
            if !((*cur).c1).is_null() {
                let ref mut fresh60 = (*tmp).c1;
                *fresh60 = xmlCopyDocElementContent(doc, (*cur).c1);
            }
            if !((*tmp).c1).is_null() {
                let ref mut fresh61 = (*(*tmp).c1).parent;
                *fresh61 = ret;
            }
            prev = tmp;
            cur = (*cur).c2;
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyElementContent(
    mut cur: xmlElementContentPtr,
) -> xmlElementContentPtr {
    return xmlCopyDocElementContent(0 as xmlDocPtr, cur);
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeDocElementContent(
    mut doc: xmlDocPtr,
    mut cur: xmlElementContentPtr,
) {
    let mut dict: xmlDictPtr = 0 as xmlDictPtr;
    let mut depth: size_t = 0 as libc::c_int as size_t;
    if cur.is_null() {
        return;
    }
    if !doc.is_null() {
        dict = (*doc).dict;
    }
    loop {
        let mut parent: xmlElementContentPtr = 0 as *mut xmlElementContent;
        while !((*cur).c1).is_null() || !((*cur).c2).is_null() {
            cur = if !((*cur).c1).is_null() { (*cur).c1 } else { (*cur).c2 };
            depth = (depth as libc::c_ulong)
                .wrapping_add(1 as libc::c_int as libc::c_ulong) as size_t as size_t;
        }
        match (*cur).type_0 as libc::c_uint {
            1 | 2 | 3 | 4 => {}
            _ => {
                xmlErrValid(
                    0 as xmlValidCtxtPtr,
                    XML_ERR_INTERNAL_ERROR,
                    b"Internal: ELEMENT content corrupted invalid type\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const libc::c_char,
                );
                return;
            }
        }
        if !dict.is_null() {
            if !((*cur).name).is_null() && xmlDictOwns(dict, (*cur).name) == 0 {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*cur).name as *mut xmlChar as *mut libc::c_void);
            }
            if !((*cur).prefix).is_null() && xmlDictOwns(dict, (*cur).prefix) == 0 {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*cur).prefix as *mut xmlChar as *mut libc::c_void);
            }
        } else {
            if !((*cur).name).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*cur).name as *mut xmlChar as *mut libc::c_void);
            }
            if !((*cur).prefix).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*cur).prefix as *mut xmlChar as *mut libc::c_void);
            }
        }
        parent = (*cur).parent;
        if depth == 0 as libc::c_int as libc::c_ulong || parent.is_null() {
            xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
            break;
        } else {
            if cur == (*parent).c1 {
                let ref mut fresh62 = (*parent).c1;
                *fresh62 = 0 as *mut _xmlElementContent;
            } else {
                let ref mut fresh63 = (*parent).c2;
                *fresh63 = 0 as *mut _xmlElementContent;
            }
            xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
            if !((*parent).c2).is_null() {
                cur = (*parent).c2;
            } else {
                depth = (depth as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as size_t as size_t;
                cur = parent;
            }
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeElementContent(mut cur: xmlElementContentPtr) {
    xmlFreeDocElementContent(0 as xmlDocPtr, cur);
}
unsafe extern "C" fn xmlDumpElementOccur(
    mut buf: xmlBufferPtr,
    mut cur: xmlElementContentPtr,
) {
    match (*cur).ocur as libc::c_uint {
        2 => {
            xmlBufferWriteChar(buf, b"?\0" as *const u8 as *const libc::c_char);
        }
        3 => {
            xmlBufferWriteChar(buf, b"*\0" as *const u8 as *const libc::c_char);
        }
        4 => {
            xmlBufferWriteChar(buf, b"+\0" as *const u8 as *const libc::c_char);
        }
        1 | _ => {}
    };
}
unsafe extern "C" fn xmlDumpElementContent(
    mut buf: xmlBufferPtr,
    mut content: xmlElementContentPtr,
) {
    let mut cur: xmlElementContentPtr = 0 as *mut xmlElementContent;
    if content.is_null() {
        return;
    }
    xmlBufferWriteChar(buf, b"(\0" as *const u8 as *const libc::c_char);
    cur = content;
    let mut current_block_27: u64;
    loop {
        if cur.is_null() {
            return;
        }
        match (*cur).type_0 as libc::c_uint {
            1 => {
                xmlBufferWriteChar(
                    buf,
                    b"#PCDATA\0" as *const u8 as *const libc::c_char,
                );
                current_block_27 = 12124785117276362961;
            }
            2 => {
                if !((*cur).prefix).is_null() {
                    xmlBufferWriteCHAR(buf, (*cur).prefix);
                    xmlBufferWriteChar(buf, b":\0" as *const u8 as *const libc::c_char);
                }
                xmlBufferWriteCHAR(buf, (*cur).name);
                current_block_27 = 12124785117276362961;
            }
            3 | 4 => {
                if cur != content && !((*cur).parent).is_null()
                    && ((*cur).type_0 as libc::c_uint
                        != (*(*cur).parent).type_0 as libc::c_uint
                        || (*cur).ocur as libc::c_uint
                            != XML_ELEMENT_CONTENT_ONCE as libc::c_int as libc::c_uint)
                {
                    xmlBufferWriteChar(buf, b"(\0" as *const u8 as *const libc::c_char);
                }
                cur = (*cur).c1;
                current_block_27 = 17179679302217393232;
            }
            _ => {
                xmlErrValid(
                    0 as xmlValidCtxtPtr,
                    XML_ERR_INTERNAL_ERROR,
                    b"Internal: ELEMENT cur corrupted invalid type\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const libc::c_char,
                );
                current_block_27 = 12124785117276362961;
            }
        }
        match current_block_27 {
            12124785117276362961 => {
                while cur != content {
                    let mut parent: xmlElementContentPtr = (*cur).parent;
                    if parent.is_null() {
                        return;
                    }
                    if ((*cur).type_0 as libc::c_uint
                        == XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                        || (*cur).type_0 as libc::c_uint
                            == XML_ELEMENT_CONTENT_SEQ as libc::c_int as libc::c_uint)
                        && ((*cur).type_0 as libc::c_uint
                            != (*parent).type_0 as libc::c_uint
                            || (*cur).ocur as libc::c_uint
                                != XML_ELEMENT_CONTENT_ONCE as libc::c_int as libc::c_uint)
                    {
                        xmlBufferWriteChar(
                            buf,
                            b")\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    xmlDumpElementOccur(buf, cur);
                    if cur == (*parent).c1 {
                        if (*parent).type_0 as libc::c_uint
                            == XML_ELEMENT_CONTENT_SEQ as libc::c_int as libc::c_uint
                        {
                            xmlBufferWriteChar(
                                buf,
                                b" , \0" as *const u8 as *const libc::c_char,
                            );
                        } else if (*parent).type_0 as libc::c_uint
                                == XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                            {
                            xmlBufferWriteChar(
                                buf,
                                b" | \0" as *const u8 as *const libc::c_char,
                            );
                        }
                        cur = (*parent).c2;
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
    xmlBufferWriteChar(buf, b")\0" as *const u8 as *const libc::c_char);
    xmlDumpElementOccur(buf, content);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSprintfElementContent(
    mut buf: *mut libc::c_char,
    mut content: xmlElementContentPtr,
    mut englob: libc::c_int,
) {}
#[no_mangle]
pub unsafe extern "C" fn xmlSnprintfElementContent(
    mut buf: *mut libc::c_char,
    mut size: libc::c_int,
    mut content: xmlElementContentPtr,
    mut englob: libc::c_int,
) {
    let mut len: libc::c_int = 0;
    if content.is_null() {
        return;
    }
    len = strlen(buf) as libc::c_int;
    if size - len < 50 as libc::c_int {
        if size - len > 4 as libc::c_int
            && *buf.offset((len - 1 as libc::c_int) as isize) as libc::c_int
                != '.' as i32
        {
            strcat(buf, b" ...\0" as *const u8 as *const libc::c_char);
        }
        return;
    }
    if englob != 0 {
        strcat(buf, b"(\0" as *const u8 as *const libc::c_char);
    }
    match (*content).type_0 as libc::c_uint {
        1 => {
            strcat(buf, b"#PCDATA\0" as *const u8 as *const libc::c_char);
        }
        2 => {
            let mut qnameLen: libc::c_int = xmlStrlen((*content).name);
            if !((*content).prefix).is_null() {
                qnameLen += xmlStrlen((*content).prefix) + 1 as libc::c_int;
            }
            if size - len < qnameLen + 10 as libc::c_int {
                strcat(buf, b" ...\0" as *const u8 as *const libc::c_char);
                return;
            }
            if !((*content).prefix).is_null() {
                strcat(buf, (*content).prefix as *mut libc::c_char);
                strcat(buf, b":\0" as *const u8 as *const libc::c_char);
            }
            if !((*content).name).is_null() {
                strcat(buf, (*content).name as *mut libc::c_char);
            }
        }
        3 => {
            if (*(*content).c1).type_0 as libc::c_uint
                == XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                || (*(*content).c1).type_0 as libc::c_uint
                    == XML_ELEMENT_CONTENT_SEQ as libc::c_int as libc::c_uint
            {
                xmlSnprintfElementContent(buf, size, (*content).c1, 1 as libc::c_int);
            } else {
                xmlSnprintfElementContent(buf, size, (*content).c1, 0 as libc::c_int);
            }
            len = strlen(buf) as libc::c_int;
            if size - len < 50 as libc::c_int {
                if size - len > 4 as libc::c_int
                    && *buf.offset((len - 1 as libc::c_int) as isize) as libc::c_int
                        != '.' as i32
                {
                    strcat(buf, b" ...\0" as *const u8 as *const libc::c_char);
                }
                return;
            }
            strcat(buf, b" , \0" as *const u8 as *const libc::c_char);
            if ((*(*content).c2).type_0 as libc::c_uint
                == XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                || (*(*content).c2).ocur as libc::c_uint
                    != XML_ELEMENT_CONTENT_ONCE as libc::c_int as libc::c_uint)
                && (*(*content).c2).type_0 as libc::c_uint
                    != XML_ELEMENT_CONTENT_ELEMENT as libc::c_int as libc::c_uint
            {
                xmlSnprintfElementContent(buf, size, (*content).c2, 1 as libc::c_int);
            } else {
                xmlSnprintfElementContent(buf, size, (*content).c2, 0 as libc::c_int);
            }
        }
        4 => {
            if (*(*content).c1).type_0 as libc::c_uint
                == XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                || (*(*content).c1).type_0 as libc::c_uint
                    == XML_ELEMENT_CONTENT_SEQ as libc::c_int as libc::c_uint
            {
                xmlSnprintfElementContent(buf, size, (*content).c1, 1 as libc::c_int);
            } else {
                xmlSnprintfElementContent(buf, size, (*content).c1, 0 as libc::c_int);
            }
            len = strlen(buf) as libc::c_int;
            if size - len < 50 as libc::c_int {
                if size - len > 4 as libc::c_int
                    && *buf.offset((len - 1 as libc::c_int) as isize) as libc::c_int
                        != '.' as i32
                {
                    strcat(buf, b" ...\0" as *const u8 as *const libc::c_char);
                }
                return;
            }
            strcat(buf, b" | \0" as *const u8 as *const libc::c_char);
            if ((*(*content).c2).type_0 as libc::c_uint
                == XML_ELEMENT_CONTENT_SEQ as libc::c_int as libc::c_uint
                || (*(*content).c2).ocur as libc::c_uint
                    != XML_ELEMENT_CONTENT_ONCE as libc::c_int as libc::c_uint)
                && (*(*content).c2).type_0 as libc::c_uint
                    != XML_ELEMENT_CONTENT_ELEMENT as libc::c_int as libc::c_uint
            {
                xmlSnprintfElementContent(buf, size, (*content).c2, 1 as libc::c_int);
            } else {
                xmlSnprintfElementContent(buf, size, (*content).c2, 0 as libc::c_int);
            }
        }
        _ => {}
    }
    if (size as libc::c_ulong).wrapping_sub(strlen(buf))
        <= 2 as libc::c_int as libc::c_ulong
    {
        return;
    }
    if englob != 0 {
        strcat(buf, b")\0" as *const u8 as *const libc::c_char);
    }
    match (*content).ocur as libc::c_uint {
        2 => {
            strcat(buf, b"?\0" as *const u8 as *const libc::c_char);
        }
        3 => {
            strcat(buf, b"*\0" as *const u8 as *const libc::c_char);
        }
        4 => {
            strcat(buf, b"+\0" as *const u8 as *const libc::c_char);
        }
        1 | _ => {}
    };
}
unsafe extern "C" fn xmlFreeElement(mut elem: xmlElementPtr) {
    if elem.is_null() {
        return;
    }
    xmlUnlinkNode(elem as xmlNodePtr);
    xmlFreeDocElementContent((*elem).doc, (*elem).content);
    if !((*elem).name).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*elem).name as *mut xmlChar as *mut libc::c_void);
    }
    if !((*elem).prefix).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*elem).prefix as *mut xmlChar as *mut libc::c_void);
    }
    if !((*elem).contModel).is_null() {
        xmlRegFreeRegexp((*elem).contModel);
    }
    xmlFree.expect("non-null function pointer")(elem as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlAddElementDecl(
    mut ctxt: xmlValidCtxtPtr,
    mut dtd: xmlDtdPtr,
    mut name: *const xmlChar,
    mut type_0: xmlElementTypeVal,
    mut content: xmlElementContentPtr,
) -> xmlElementPtr {
    let mut ret: xmlElementPtr = 0 as *mut xmlElement;
    let mut table: xmlElementTablePtr = 0 as *mut xmlElementTable;
    let mut oldAttributes: xmlAttributePtr = 0 as xmlAttributePtr;
    let mut ns: *mut xmlChar = 0 as *mut xmlChar;
    let mut uqname: *mut xmlChar = 0 as *mut xmlChar;
    if dtd.is_null() {
        return 0 as xmlElementPtr;
    }
    if name.is_null() {
        return 0 as xmlElementPtr;
    }
    match type_0 as libc::c_uint {
        1 => {
            if !content.is_null() {
                xmlErrValid(
                    ctxt,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlAddElementDecl: content != NULL for EMPTY\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const libc::c_char,
                );
                return 0 as xmlElementPtr;
            }
        }
        2 => {
            if !content.is_null() {
                xmlErrValid(
                    ctxt,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlAddElementDecl: content != NULL for ANY\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const libc::c_char,
                );
                return 0 as xmlElementPtr;
            }
        }
        3 => {
            if content.is_null() {
                xmlErrValid(
                    ctxt,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlAddElementDecl: content == NULL for MIXED\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const libc::c_char,
                );
                return 0 as xmlElementPtr;
            }
        }
        4 => {
            if content.is_null() {
                xmlErrValid(
                    ctxt,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlAddElementDecl: content == NULL for ELEMENT\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const libc::c_char,
                );
                return 0 as xmlElementPtr;
            }
        }
        _ => {
            xmlErrValid(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"Internal: ELEMENT decl corrupted invalid type\n\0" as *const u8
                    as *const libc::c_char,
                0 as *const libc::c_char,
            );
            return 0 as xmlElementPtr;
        }
    }
    uqname = xmlSplitQName2(name, &mut ns);
    if !uqname.is_null() {
        name = uqname;
    }
    table = (*dtd).elements as xmlElementTablePtr;
    if table.is_null() {
        let mut dict: xmlDictPtr = 0 as xmlDictPtr;
        if !((*dtd).doc).is_null() {
            dict = (*(*dtd).doc).dict;
        }
        table = xmlHashCreateDict(0 as libc::c_int, dict);
        let ref mut fresh64 = (*dtd).elements;
        *fresh64 = table as *mut libc::c_void;
    }
    if table.is_null() {
        xmlVErrMemory(
            ctxt,
            b"xmlAddElementDecl: Table creation failed!\n\0" as *const u8
                as *const libc::c_char,
        );
        if !uqname.is_null() {
            xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void);
        }
        if !ns.is_null() {
            xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void);
        }
        return 0 as xmlElementPtr;
    }
    if !((*dtd).doc).is_null() && !((*(*dtd).doc).intSubset).is_null() {
        ret = xmlHashLookup2(
            (*(*(*dtd).doc).intSubset).elements as xmlHashTablePtr,
            name,
            ns,
        ) as xmlElementPtr;
        if !ret.is_null()
            && (*ret).etype as libc::c_uint
                == XML_ELEMENT_TYPE_UNDEFINED as libc::c_int as libc::c_uint
        {
            oldAttributes = (*ret).attributes;
            let ref mut fresh65 = (*ret).attributes;
            *fresh65 = 0 as xmlAttributePtr;
            xmlHashRemoveEntry2(
                (*(*(*dtd).doc).intSubset).elements as xmlHashTablePtr,
                name,
                ns,
                None,
            );
            xmlFreeElement(ret);
        }
    }
    ret = xmlHashLookup2(table, name, ns) as xmlElementPtr;
    if !ret.is_null() {
        if (*ret).etype as libc::c_uint
            != XML_ELEMENT_TYPE_UNDEFINED as libc::c_int as libc::c_uint
        {
            xmlErrValidNode(
                ctxt,
                dtd as xmlNodePtr,
                XML_DTD_ELEM_REDEFINED,
                b"Redefinition of element %s\n\0" as *const u8 as *const libc::c_char,
                name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            if !uqname.is_null() {
                xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void);
            }
            if !ns.is_null() {
                xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void);
            }
            return 0 as xmlElementPtr;
        }
        if !ns.is_null() {
            xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void);
            ns = 0 as *mut xmlChar;
        }
    } else {
        ret = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlElement>() as libc::c_ulong) as xmlElementPtr;
        if ret.is_null() {
            xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const libc::c_char);
            if !uqname.is_null() {
                xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void);
            }
            if !ns.is_null() {
                xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void);
            }
            return 0 as xmlElementPtr;
        }
        memset(
            ret as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<xmlElement>() as libc::c_ulong,
        );
        (*ret).type_0 = XML_ELEMENT_DECL;
        let ref mut fresh66 = (*ret).name;
        *fresh66 = xmlStrdup(name);
        if ((*ret).name).is_null() {
            xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const libc::c_char);
            if !uqname.is_null() {
                xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void);
            }
            if !ns.is_null() {
                xmlFree.expect("non-null function pointer")(ns as *mut libc::c_void);
            }
            xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
            return 0 as xmlElementPtr;
        }
        let ref mut fresh67 = (*ret).prefix;
        *fresh67 = ns;
        if xmlHashAddEntry2(table, name, ns, ret as *mut libc::c_void) != 0 {
            xmlErrValidNode(
                ctxt,
                dtd as xmlNodePtr,
                XML_DTD_ELEM_REDEFINED,
                b"Redefinition of element %s\n\0" as *const u8 as *const libc::c_char,
                name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            xmlFreeElement(ret);
            if !uqname.is_null() {
                xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void);
            }
            return 0 as xmlElementPtr;
        }
        let ref mut fresh68 = (*ret).attributes;
        *fresh68 = oldAttributes;
    }
    (*ret).etype = type_0;
    if !ctxt.is_null() && (*ctxt).flags & (1 as libc::c_uint) << 1 as libc::c_int != 0 {
        let ref mut fresh69 = (*ret).content;
        *fresh69 = content;
        if !content.is_null() {
            let ref mut fresh70 = (*content).parent;
            *fresh70 = 1 as libc::c_int as xmlElementContentPtr;
        }
    } else {
        let ref mut fresh71 = (*ret).content;
        *fresh71 = xmlCopyDocElementContent((*dtd).doc, content);
    }
    let ref mut fresh72 = (*ret).parent;
    *fresh72 = dtd;
    let ref mut fresh73 = (*ret).doc;
    *fresh73 = (*dtd).doc;
    if ((*dtd).last).is_null() {
        let ref mut fresh74 = (*dtd).last;
        *fresh74 = ret as xmlNodePtr;
        let ref mut fresh75 = (*dtd).children;
        *fresh75 = *fresh74;
    } else {
        let ref mut fresh76 = (*(*dtd).last).next;
        *fresh76 = ret as xmlNodePtr;
        let ref mut fresh77 = (*ret).prev;
        *fresh77 = (*dtd).last;
        let ref mut fresh78 = (*dtd).last;
        *fresh78 = ret as xmlNodePtr;
    }
    if !uqname.is_null() {
        xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void);
    }
    return ret;
}
unsafe extern "C" fn xmlFreeElementTableEntry(
    mut elem: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    xmlFreeElement(elem as xmlElementPtr);
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeElementTable(mut table: xmlElementTablePtr) {
    xmlHashFree(
        table,
        Some(
            xmlFreeElementTableEntry
                as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        ),
    );
}
unsafe extern "C" fn xmlCopyElement(
    mut payload: *mut libc::c_void,
    mut name: *const xmlChar,
) -> *mut libc::c_void {
    let mut elem: xmlElementPtr = payload as xmlElementPtr;
    let mut cur: xmlElementPtr = 0 as *mut xmlElement;
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlElement>() as libc::c_ulong) as xmlElementPtr;
    if cur.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut libc::c_void;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlElement>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_ELEMENT_DECL;
    (*cur).etype = (*elem).etype;
    if !((*elem).name).is_null() {
        let ref mut fresh79 = (*cur).name;
        *fresh79 = xmlStrdup((*elem).name);
    } else {
        let ref mut fresh80 = (*cur).name;
        *fresh80 = 0 as *const xmlChar;
    }
    if !((*elem).prefix).is_null() {
        let ref mut fresh81 = (*cur).prefix;
        *fresh81 = xmlStrdup((*elem).prefix);
    } else {
        let ref mut fresh82 = (*cur).prefix;
        *fresh82 = 0 as *const xmlChar;
    }
    let ref mut fresh83 = (*cur).content;
    *fresh83 = xmlCopyElementContent((*elem).content);
    let ref mut fresh84 = (*cur).attributes;
    *fresh84 = 0 as xmlAttributePtr;
    return cur as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyElementTable(
    mut table: xmlElementTablePtr,
) -> xmlElementTablePtr {
    return xmlHashCopy(
        table,
        Some(
            xmlCopyElement
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const xmlChar,
                ) -> *mut libc::c_void,
        ),
    ) as xmlElementTablePtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDumpElementDecl(
    mut buf: xmlBufferPtr,
    mut elem: xmlElementPtr,
) {
    if buf.is_null() || elem.is_null() {
        return;
    }
    match (*elem).etype as libc::c_uint {
        1 => {
            xmlBufferWriteChar(buf, b"<!ELEMENT \0" as *const u8 as *const libc::c_char);
            if !((*elem).prefix).is_null() {
                xmlBufferWriteCHAR(buf, (*elem).prefix);
                xmlBufferWriteChar(buf, b":\0" as *const u8 as *const libc::c_char);
            }
            xmlBufferWriteCHAR(buf, (*elem).name);
            xmlBufferWriteChar(buf, b" EMPTY>\n\0" as *const u8 as *const libc::c_char);
        }
        2 => {
            xmlBufferWriteChar(buf, b"<!ELEMENT \0" as *const u8 as *const libc::c_char);
            if !((*elem).prefix).is_null() {
                xmlBufferWriteCHAR(buf, (*elem).prefix);
                xmlBufferWriteChar(buf, b":\0" as *const u8 as *const libc::c_char);
            }
            xmlBufferWriteCHAR(buf, (*elem).name);
            xmlBufferWriteChar(buf, b" ANY>\n\0" as *const u8 as *const libc::c_char);
        }
        3 => {
            xmlBufferWriteChar(buf, b"<!ELEMENT \0" as *const u8 as *const libc::c_char);
            if !((*elem).prefix).is_null() {
                xmlBufferWriteCHAR(buf, (*elem).prefix);
                xmlBufferWriteChar(buf, b":\0" as *const u8 as *const libc::c_char);
            }
            xmlBufferWriteCHAR(buf, (*elem).name);
            xmlBufferWriteChar(buf, b" \0" as *const u8 as *const libc::c_char);
            xmlDumpElementContent(buf, (*elem).content);
            xmlBufferWriteChar(buf, b">\n\0" as *const u8 as *const libc::c_char);
        }
        4 => {
            xmlBufferWriteChar(buf, b"<!ELEMENT \0" as *const u8 as *const libc::c_char);
            if !((*elem).prefix).is_null() {
                xmlBufferWriteCHAR(buf, (*elem).prefix);
                xmlBufferWriteChar(buf, b":\0" as *const u8 as *const libc::c_char);
            }
            xmlBufferWriteCHAR(buf, (*elem).name);
            xmlBufferWriteChar(buf, b" \0" as *const u8 as *const libc::c_char);
            xmlDumpElementContent(buf, (*elem).content);
            xmlBufferWriteChar(buf, b">\n\0" as *const u8 as *const libc::c_char);
        }
        _ => {
            xmlErrValid(
                0 as xmlValidCtxtPtr,
                XML_ERR_INTERNAL_ERROR,
                b"Internal: ELEMENT struct corrupted invalid type\n\0" as *const u8
                    as *const libc::c_char,
                0 as *const libc::c_char,
            );
        }
    };
}
unsafe extern "C" fn xmlDumpElementDeclScan(
    mut elem: *mut libc::c_void,
    mut buf: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    xmlDumpElementDecl(buf as xmlBufferPtr, elem as xmlElementPtr);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDumpElementTable(
    mut buf: xmlBufferPtr,
    mut table: xmlElementTablePtr,
) {
    if buf.is_null() || table.is_null() {
        return;
    }
    xmlHashScan(
        table,
        Some(
            xmlDumpElementDeclScan
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_void,
                    *const xmlChar,
                ) -> (),
        ),
        buf as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateEnumeration(
    mut name: *const xmlChar,
) -> xmlEnumerationPtr {
    let mut ret: xmlEnumerationPtr = 0 as *mut xmlEnumeration;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlEnumeration>() as libc::c_ulong) as xmlEnumerationPtr;
    if ret.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlEnumerationPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlEnumeration>() as libc::c_ulong,
    );
    if !name.is_null() {
        let ref mut fresh85 = (*ret).name;
        *fresh85 = xmlStrdup(name);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeEnumeration(mut cur: xmlEnumerationPtr) {
    if cur.is_null() {
        return;
    }
    if !((*cur).next).is_null() {
        xmlFreeEnumeration((*cur).next);
    }
    if !((*cur).name).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*cur).name as *mut xmlChar as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyEnumeration(
    mut cur: xmlEnumerationPtr,
) -> xmlEnumerationPtr {
    let mut ret: xmlEnumerationPtr = 0 as *mut xmlEnumeration;
    if cur.is_null() {
        return 0 as xmlEnumerationPtr;
    }
    ret = xmlCreateEnumeration((*cur).name as *mut xmlChar);
    if ret.is_null() {
        return 0 as xmlEnumerationPtr;
    }
    if !((*cur).next).is_null() {
        let ref mut fresh86 = (*ret).next;
        *fresh86 = xmlCopyEnumeration((*cur).next);
    } else {
        let ref mut fresh87 = (*ret).next;
        *fresh87 = 0 as *mut _xmlEnumeration;
    }
    return ret;
}
unsafe extern "C" fn xmlDumpEnumeration(
    mut buf: xmlBufferPtr,
    mut cur: xmlEnumerationPtr,
) {
    if buf.is_null() || cur.is_null() {
        return;
    }
    xmlBufferWriteCHAR(buf, (*cur).name);
    if ((*cur).next).is_null() {
        xmlBufferWriteChar(buf, b")\0" as *const u8 as *const libc::c_char);
    } else {
        xmlBufferWriteChar(buf, b" | \0" as *const u8 as *const libc::c_char);
        xmlDumpEnumeration(buf, (*cur).next);
    };
}
unsafe extern "C" fn xmlScanIDAttributeDecl(
    mut ctxt: xmlValidCtxtPtr,
    mut elem: xmlElementPtr,
    mut err: libc::c_int,
) -> libc::c_int {
    let mut cur: xmlAttributePtr = 0 as *mut xmlAttribute;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if elem.is_null() {
        return 0 as libc::c_int;
    }
    cur = (*elem).attributes;
    while !cur.is_null() {
        if (*cur).atype as libc::c_uint
            == XML_ATTRIBUTE_ID as libc::c_int as libc::c_uint
        {
            ret += 1;
            if ret > 1 as libc::c_int && err != 0 {
                xmlErrValidNode(
                    ctxt,
                    elem as xmlNodePtr,
                    XML_DTD_MULTIPLE_ID,
                    b"Element %s has too many ID attributes defined : %s\n\0"
                        as *const u8 as *const libc::c_char,
                    (*elem).name,
                    (*cur).name,
                    0 as *const xmlChar,
                );
            }
        }
        cur = (*cur).nexth;
    }
    return ret;
}
unsafe extern "C" fn xmlFreeAttribute(mut attr: xmlAttributePtr) {
    let mut dict: xmlDictPtr = 0 as *mut xmlDict;
    if attr.is_null() {
        return;
    }
    if !((*attr).doc).is_null() {
        dict = (*(*attr).doc).dict;
    } else {
        dict = 0 as xmlDictPtr;
    }
    xmlUnlinkNode(attr as xmlNodePtr);
    if !((*attr).tree).is_null() {
        xmlFreeEnumeration((*attr).tree);
    }
    if !dict.is_null() {
        if !((*attr).elem).is_null() && xmlDictOwns(dict, (*attr).elem) == 0 {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*attr).elem as *mut xmlChar as *mut libc::c_void);
        }
        if !((*attr).name).is_null() && xmlDictOwns(dict, (*attr).name) == 0 {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*attr).name as *mut xmlChar as *mut libc::c_void);
        }
        if !((*attr).prefix).is_null() && xmlDictOwns(dict, (*attr).prefix) == 0 {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*attr).prefix as *mut xmlChar as *mut libc::c_void);
        }
        if !((*attr).defaultValue).is_null()
            && xmlDictOwns(dict, (*attr).defaultValue) == 0
        {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*attr).defaultValue as *mut xmlChar as *mut libc::c_void);
        }
    } else {
        if !((*attr).elem).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*attr).elem as *mut xmlChar as *mut libc::c_void);
        }
        if !((*attr).name).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*attr).name as *mut xmlChar as *mut libc::c_void);
        }
        if !((*attr).defaultValue).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*attr).defaultValue as *mut xmlChar as *mut libc::c_void);
        }
        if !((*attr).prefix).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*attr).prefix as *mut xmlChar as *mut libc::c_void);
        }
    }
    xmlFree.expect("non-null function pointer")(attr as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlAddAttributeDecl(
    mut ctxt: xmlValidCtxtPtr,
    mut dtd: xmlDtdPtr,
    mut elem: *const xmlChar,
    mut name: *const xmlChar,
    mut ns: *const xmlChar,
    mut type_0: xmlAttributeType,
    mut def: xmlAttributeDefault,
    mut defaultValue: *const xmlChar,
    mut tree: xmlEnumerationPtr,
) -> xmlAttributePtr {
    let mut ret: xmlAttributePtr = 0 as *mut xmlAttribute;
    let mut table: xmlAttributeTablePtr = 0 as *mut xmlAttributeTable;
    let mut elemDef: xmlElementPtr = 0 as *mut xmlElement;
    let mut dict: xmlDictPtr = 0 as xmlDictPtr;
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
    if !((*dtd).doc).is_null() {
        dict = (*(*dtd).doc).dict;
    }
    match type_0 as libc::c_uint {
        1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 => {}
        _ => {
            xmlErrValid(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"Internal: ATTRIBUTE struct corrupted invalid type\n\0" as *const u8
                    as *const libc::c_char,
                0 as *const libc::c_char,
            );
            xmlFreeEnumeration(tree);
            return 0 as xmlAttributePtr;
        }
    }
    if !defaultValue.is_null()
        && xmlValidateAttributeValueInternal((*dtd).doc, type_0, defaultValue) == 0
    {
        xmlErrValidNode(
            ctxt,
            dtd as xmlNodePtr,
            XML_DTD_ATTRIBUTE_DEFAULT,
            b"Attribute %s of %s: invalid default value\n\0" as *const u8
                as *const libc::c_char,
            elem,
            name,
            defaultValue,
        );
        defaultValue = 0 as *const xmlChar;
        if !ctxt.is_null() {
            (*ctxt).valid = 0 as libc::c_int;
        }
    }
    if !((*dtd).doc).is_null() && (*(*dtd).doc).extSubset == dtd
        && !((*(*dtd).doc).intSubset).is_null()
        && !((*(*(*dtd).doc).intSubset).attributes).is_null()
    {
        ret = xmlHashLookup3(
            (*(*(*dtd).doc).intSubset).attributes as xmlHashTablePtr,
            name,
            ns,
            elem,
        ) as xmlAttributePtr;
        if !ret.is_null() {
            xmlFreeEnumeration(tree);
            return 0 as xmlAttributePtr;
        }
    }
    table = (*dtd).attributes as xmlAttributeTablePtr;
    if table.is_null() {
        table = xmlHashCreateDict(0 as libc::c_int, dict);
        let ref mut fresh88 = (*dtd).attributes;
        *fresh88 = table as *mut libc::c_void;
    }
    if table.is_null() {
        xmlVErrMemory(
            ctxt,
            b"xmlAddAttributeDecl: Table creation failed!\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlFreeEnumeration(tree);
        return 0 as xmlAttributePtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlAttribute>() as libc::c_ulong) as xmlAttributePtr;
    if ret.is_null() {
        xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const libc::c_char);
        xmlFreeEnumeration(tree);
        return 0 as xmlAttributePtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlAttribute>() as libc::c_ulong,
    );
    (*ret).type_0 = XML_ATTRIBUTE_DECL;
    (*ret).atype = type_0;
    let ref mut fresh89 = (*ret).doc;
    *fresh89 = (*dtd).doc;
    if !dict.is_null() {
        let ref mut fresh90 = (*ret).name;
        *fresh90 = xmlDictLookup(dict, name, -(1 as libc::c_int));
        let ref mut fresh91 = (*ret).prefix;
        *fresh91 = xmlDictLookup(dict, ns, -(1 as libc::c_int));
        let ref mut fresh92 = (*ret).elem;
        *fresh92 = xmlDictLookup(dict, elem, -(1 as libc::c_int));
    } else {
        let ref mut fresh93 = (*ret).name;
        *fresh93 = xmlStrdup(name);
        let ref mut fresh94 = (*ret).prefix;
        *fresh94 = xmlStrdup(ns);
        let ref mut fresh95 = (*ret).elem;
        *fresh95 = xmlStrdup(elem);
    }
    (*ret).def = def;
    let ref mut fresh96 = (*ret).tree;
    *fresh96 = tree;
    if !defaultValue.is_null() {
        if !dict.is_null() {
            let ref mut fresh97 = (*ret).defaultValue;
            *fresh97 = xmlDictLookup(dict, defaultValue, -(1 as libc::c_int));
        } else {
            let ref mut fresh98 = (*ret).defaultValue;
            *fresh98 = xmlStrdup(defaultValue);
        }
    }
    if xmlHashAddEntry3(
        table,
        (*ret).name,
        (*ret).prefix,
        (*ret).elem,
        ret as *mut libc::c_void,
    ) < 0 as libc::c_int
    {
        xmlErrValidWarning(
            ctxt,
            dtd as xmlNodePtr,
            XML_DTD_ATTRIBUTE_REDEFINED,
            b"Attribute %s of element %s: already defined\n\0" as *const u8
                as *const libc::c_char,
            name,
            elem,
            0 as *const xmlChar,
        );
        xmlFreeAttribute(ret);
        return 0 as xmlAttributePtr;
    }
    elemDef = xmlGetDtdElementDesc2(dtd, elem, 1 as libc::c_int);
    if !elemDef.is_null() {
        if type_0 as libc::c_uint == XML_ATTRIBUTE_ID as libc::c_int as libc::c_uint
            && xmlScanIDAttributeDecl(0 as xmlValidCtxtPtr, elemDef, 1 as libc::c_int)
                != 0 as libc::c_int
        {
            xmlErrValidNode(
                ctxt,
                dtd as xmlNodePtr,
                XML_DTD_MULTIPLE_ID,
                b"Element %s has too may ID attributes defined : %s\n\0" as *const u8
                    as *const libc::c_char,
                elem,
                name,
                0 as *const xmlChar,
            );
            if !ctxt.is_null() {
                (*ctxt).valid = 0 as libc::c_int;
            }
        }
        if xmlStrEqual(
            (*ret).name,
            b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
            || !((*ret).prefix).is_null()
                && xmlStrEqual(
                    (*ret).prefix,
                    b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) != 0
        {
            let ref mut fresh99 = (*ret).nexth;
            *fresh99 = (*elemDef).attributes;
            let ref mut fresh100 = (*elemDef).attributes;
            *fresh100 = ret;
        } else {
            let mut tmp: xmlAttributePtr = (*elemDef).attributes;
            while !tmp.is_null()
                && (xmlStrEqual(
                    (*tmp).name,
                    b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) != 0
                    || !((*ret).prefix).is_null()
                        && xmlStrEqual(
                            (*ret).prefix,
                            b"xmlns\0" as *const u8 as *const libc::c_char
                                as *mut xmlChar,
                        ) != 0)
            {
                if ((*tmp).nexth).is_null() {
                    break;
                }
                tmp = (*tmp).nexth;
            }
            if !tmp.is_null() {
                let ref mut fresh101 = (*ret).nexth;
                *fresh101 = (*tmp).nexth;
                let ref mut fresh102 = (*tmp).nexth;
                *fresh102 = ret;
            } else {
                let ref mut fresh103 = (*ret).nexth;
                *fresh103 = (*elemDef).attributes;
                let ref mut fresh104 = (*elemDef).attributes;
                *fresh104 = ret;
            }
        }
    }
    let ref mut fresh105 = (*ret).parent;
    *fresh105 = dtd;
    if ((*dtd).last).is_null() {
        let ref mut fresh106 = (*dtd).last;
        *fresh106 = ret as xmlNodePtr;
        let ref mut fresh107 = (*dtd).children;
        *fresh107 = *fresh106;
    } else {
        let ref mut fresh108 = (*(*dtd).last).next;
        *fresh108 = ret as xmlNodePtr;
        let ref mut fresh109 = (*ret).prev;
        *fresh109 = (*dtd).last;
        let ref mut fresh110 = (*dtd).last;
        *fresh110 = ret as xmlNodePtr;
    }
    return ret;
}
unsafe extern "C" fn xmlFreeAttributeTableEntry(
    mut attr: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    xmlFreeAttribute(attr as xmlAttributePtr);
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeAttributeTable(mut table: xmlAttributeTablePtr) {
    xmlHashFree(
        table,
        Some(
            xmlFreeAttributeTableEntry
                as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        ),
    );
}
unsafe extern "C" fn xmlCopyAttribute(
    mut payload: *mut libc::c_void,
    mut name: *const xmlChar,
) -> *mut libc::c_void {
    let mut attr: xmlAttributePtr = payload as xmlAttributePtr;
    let mut cur: xmlAttributePtr = 0 as *mut xmlAttribute;
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlAttribute>() as libc::c_ulong) as xmlAttributePtr;
    if cur.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut libc::c_void;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlAttribute>() as libc::c_ulong,
    );
    (*cur).type_0 = XML_ATTRIBUTE_DECL;
    (*cur).atype = (*attr).atype;
    (*cur).def = (*attr).def;
    let ref mut fresh111 = (*cur).tree;
    *fresh111 = xmlCopyEnumeration((*attr).tree);
    if !((*attr).elem).is_null() {
        let ref mut fresh112 = (*cur).elem;
        *fresh112 = xmlStrdup((*attr).elem);
    }
    if !((*attr).name).is_null() {
        let ref mut fresh113 = (*cur).name;
        *fresh113 = xmlStrdup((*attr).name);
    }
    if !((*attr).prefix).is_null() {
        let ref mut fresh114 = (*cur).prefix;
        *fresh114 = xmlStrdup((*attr).prefix);
    }
    if !((*attr).defaultValue).is_null() {
        let ref mut fresh115 = (*cur).defaultValue;
        *fresh115 = xmlStrdup((*attr).defaultValue);
    }
    return cur as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyAttributeTable(
    mut table: xmlAttributeTablePtr,
) -> xmlAttributeTablePtr {
    return xmlHashCopy(
        table,
        Some(
            xmlCopyAttribute
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const xmlChar,
                ) -> *mut libc::c_void,
        ),
    ) as xmlAttributeTablePtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDumpAttributeDecl(
    mut buf: xmlBufferPtr,
    mut attr: xmlAttributePtr,
) {
    if buf.is_null() || attr.is_null() {
        return;
    }
    xmlBufferWriteChar(buf, b"<!ATTLIST \0" as *const u8 as *const libc::c_char);
    xmlBufferWriteCHAR(buf, (*attr).elem);
    xmlBufferWriteChar(buf, b" \0" as *const u8 as *const libc::c_char);
    if !((*attr).prefix).is_null() {
        xmlBufferWriteCHAR(buf, (*attr).prefix);
        xmlBufferWriteChar(buf, b":\0" as *const u8 as *const libc::c_char);
    }
    xmlBufferWriteCHAR(buf, (*attr).name);
    match (*attr).atype as libc::c_uint {
        1 => {
            xmlBufferWriteChar(buf, b" CDATA\0" as *const u8 as *const libc::c_char);
        }
        2 => {
            xmlBufferWriteChar(buf, b" ID\0" as *const u8 as *const libc::c_char);
        }
        3 => {
            xmlBufferWriteChar(buf, b" IDREF\0" as *const u8 as *const libc::c_char);
        }
        4 => {
            xmlBufferWriteChar(buf, b" IDREFS\0" as *const u8 as *const libc::c_char);
        }
        5 => {
            xmlBufferWriteChar(buf, b" ENTITY\0" as *const u8 as *const libc::c_char);
        }
        6 => {
            xmlBufferWriteChar(buf, b" ENTITIES\0" as *const u8 as *const libc::c_char);
        }
        7 => {
            xmlBufferWriteChar(buf, b" NMTOKEN\0" as *const u8 as *const libc::c_char);
        }
        8 => {
            xmlBufferWriteChar(buf, b" NMTOKENS\0" as *const u8 as *const libc::c_char);
        }
        9 => {
            xmlBufferWriteChar(buf, b" (\0" as *const u8 as *const libc::c_char);
            xmlDumpEnumeration(buf, (*attr).tree);
        }
        10 => {
            xmlBufferWriteChar(
                buf,
                b" NOTATION (\0" as *const u8 as *const libc::c_char,
            );
            xmlDumpEnumeration(buf, (*attr).tree);
        }
        _ => {
            xmlErrValid(
                0 as xmlValidCtxtPtr,
                XML_ERR_INTERNAL_ERROR,
                b"Internal: ATTRIBUTE struct corrupted invalid type\n\0" as *const u8
                    as *const libc::c_char,
                0 as *const libc::c_char,
            );
        }
    }
    match (*attr).def as libc::c_uint {
        1 => {}
        2 => {
            xmlBufferWriteChar(buf, b" #REQUIRED\0" as *const u8 as *const libc::c_char);
        }
        3 => {
            xmlBufferWriteChar(buf, b" #IMPLIED\0" as *const u8 as *const libc::c_char);
        }
        4 => {
            xmlBufferWriteChar(buf, b" #FIXED\0" as *const u8 as *const libc::c_char);
        }
        _ => {
            xmlErrValid(
                0 as xmlValidCtxtPtr,
                XML_ERR_INTERNAL_ERROR,
                b"Internal: ATTRIBUTE struct corrupted invalid def\n\0" as *const u8
                    as *const libc::c_char,
                0 as *const libc::c_char,
            );
        }
    }
    if !((*attr).defaultValue).is_null() {
        xmlBufferWriteChar(buf, b" \0" as *const u8 as *const libc::c_char);
        xmlBufferWriteQuotedString(buf, (*attr).defaultValue);
    }
    xmlBufferWriteChar(buf, b">\n\0" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn xmlDumpAttributeDeclScan(
    mut attr: *mut libc::c_void,
    mut buf: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    xmlDumpAttributeDecl(buf as xmlBufferPtr, attr as xmlAttributePtr);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDumpAttributeTable(
    mut buf: xmlBufferPtr,
    mut table: xmlAttributeTablePtr,
) {
    if buf.is_null() || table.is_null() {
        return;
    }
    xmlHashScan(
        table,
        Some(
            xmlDumpAttributeDeclScan
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_void,
                    *const xmlChar,
                ) -> (),
        ),
        buf as *mut libc::c_void,
    );
}
unsafe extern "C" fn xmlFreeNotation(mut nota: xmlNotationPtr) {
    if nota.is_null() {
        return;
    }
    if !((*nota).name).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*nota).name as *mut xmlChar as *mut libc::c_void);
    }
    if !((*nota).PublicID).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*nota).PublicID as *mut xmlChar as *mut libc::c_void);
    }
    if !((*nota).SystemID).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*nota).SystemID as *mut xmlChar as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(nota as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlAddNotationDecl(
    mut ctxt: xmlValidCtxtPtr,
    mut dtd: xmlDtdPtr,
    mut name: *const xmlChar,
    mut PublicID: *const xmlChar,
    mut SystemID: *const xmlChar,
) -> xmlNotationPtr {
    let mut ret: xmlNotationPtr = 0 as *mut xmlNotation;
    let mut table: xmlNotationTablePtr = 0 as *mut xmlNotationTable;
    if dtd.is_null() {
        return 0 as xmlNotationPtr;
    }
    if name.is_null() {
        return 0 as xmlNotationPtr;
    }
    if PublicID.is_null() && SystemID.is_null() {
        return 0 as xmlNotationPtr;
    }
    table = (*dtd).notations as xmlNotationTablePtr;
    if table.is_null() {
        let mut dict: xmlDictPtr = 0 as xmlDictPtr;
        if !((*dtd).doc).is_null() {
            dict = (*(*dtd).doc).dict;
        }
        table = xmlHashCreateDict(0 as libc::c_int, dict);
        let ref mut fresh116 = (*dtd).notations;
        *fresh116 = table as *mut libc::c_void;
    }
    if table.is_null() {
        xmlVErrMemory(
            ctxt,
            b"xmlAddNotationDecl: Table creation failed!\n\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as xmlNotationPtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNotation>() as libc::c_ulong) as xmlNotationPtr;
    if ret.is_null() {
        xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const libc::c_char);
        return 0 as xmlNotationPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlNotation>() as libc::c_ulong,
    );
    let ref mut fresh117 = (*ret).name;
    *fresh117 = xmlStrdup(name);
    if !SystemID.is_null() {
        let ref mut fresh118 = (*ret).SystemID;
        *fresh118 = xmlStrdup(SystemID);
    }
    if !PublicID.is_null() {
        let ref mut fresh119 = (*ret).PublicID;
        *fresh119 = xmlStrdup(PublicID);
    }
    if xmlHashAddEntry(table, name, ret as *mut libc::c_void) != 0 {
        xmlErrValid(
            0 as xmlValidCtxtPtr,
            XML_DTD_NOTATION_REDEFINED,
            b"xmlAddNotationDecl: %s already defined\n\0" as *const u8
                as *const libc::c_char,
            name as *const libc::c_char,
        );
        xmlFreeNotation(ret);
        return 0 as xmlNotationPtr;
    }
    return ret;
}
unsafe extern "C" fn xmlFreeNotationTableEntry(
    mut nota: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    xmlFreeNotation(nota as xmlNotationPtr);
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeNotationTable(mut table: xmlNotationTablePtr) {
    xmlHashFree(
        table,
        Some(
            xmlFreeNotationTableEntry
                as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        ),
    );
}
unsafe extern "C" fn xmlCopyNotation(
    mut payload: *mut libc::c_void,
    mut name: *const xmlChar,
) -> *mut libc::c_void {
    let mut nota: xmlNotationPtr = payload as xmlNotationPtr;
    let mut cur: xmlNotationPtr = 0 as *mut xmlNotation;
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNotation>() as libc::c_ulong) as xmlNotationPtr;
    if cur.is_null() {
        xmlVErrMemory(
            0 as xmlValidCtxtPtr,
            b"malloc failed\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut libc::c_void;
    }
    if !((*nota).name).is_null() {
        let ref mut fresh120 = (*cur).name;
        *fresh120 = xmlStrdup((*nota).name);
    } else {
        let ref mut fresh121 = (*cur).name;
        *fresh121 = 0 as *const xmlChar;
    }
    if !((*nota).PublicID).is_null() {
        let ref mut fresh122 = (*cur).PublicID;
        *fresh122 = xmlStrdup((*nota).PublicID);
    } else {
        let ref mut fresh123 = (*cur).PublicID;
        *fresh123 = 0 as *const xmlChar;
    }
    if !((*nota).SystemID).is_null() {
        let ref mut fresh124 = (*cur).SystemID;
        *fresh124 = xmlStrdup((*nota).SystemID);
    } else {
        let ref mut fresh125 = (*cur).SystemID;
        *fresh125 = 0 as *const xmlChar;
    }
    return cur as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCopyNotationTable(
    mut table: xmlNotationTablePtr,
) -> xmlNotationTablePtr {
    return xmlHashCopy(
        table,
        Some(
            xmlCopyNotation
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const xmlChar,
                ) -> *mut libc::c_void,
        ),
    ) as xmlNotationTablePtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDumpNotationDecl(
    mut buf: xmlBufferPtr,
    mut nota: xmlNotationPtr,
) {
    if buf.is_null() || nota.is_null() {
        return;
    }
    xmlBufferWriteChar(buf, b"<!NOTATION \0" as *const u8 as *const libc::c_char);
    xmlBufferWriteCHAR(buf, (*nota).name);
    if !((*nota).PublicID).is_null() {
        xmlBufferWriteChar(buf, b" PUBLIC \0" as *const u8 as *const libc::c_char);
        xmlBufferWriteQuotedString(buf, (*nota).PublicID);
        if !((*nota).SystemID).is_null() {
            xmlBufferWriteChar(buf, b" \0" as *const u8 as *const libc::c_char);
            xmlBufferWriteQuotedString(buf, (*nota).SystemID);
        }
    } else {
        xmlBufferWriteChar(buf, b" SYSTEM \0" as *const u8 as *const libc::c_char);
        xmlBufferWriteQuotedString(buf, (*nota).SystemID);
    }
    xmlBufferWriteChar(buf, b" >\n\0" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn xmlDumpNotationDeclScan(
    mut nota: *mut libc::c_void,
    mut buf: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    xmlDumpNotationDecl(buf as xmlBufferPtr, nota as xmlNotationPtr);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDumpNotationTable(
    mut buf: xmlBufferPtr,
    mut table: xmlNotationTablePtr,
) {
    if buf.is_null() || table.is_null() {
        return;
    }
    xmlHashScan(
        table,
        Some(
            xmlDumpNotationDeclScan
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_void,
                    *const xmlChar,
                ) -> (),
        ),
        buf as *mut libc::c_void,
    );
}
unsafe extern "C" fn xmlValidNormalizeString(mut str: *mut xmlChar) {
    let mut dst: *mut xmlChar = 0 as *mut xmlChar;
    let mut src: *const xmlChar = 0 as *const xmlChar;
    if str.is_null() {
        return;
    }
    src = str;
    dst = str;
    while *src as libc::c_int == 0x20 as libc::c_int {
        src = src.offset(1);
    }
    while *src as libc::c_int != 0 as libc::c_int {
        if *src as libc::c_int == 0x20 as libc::c_int {
            while *src as libc::c_int == 0x20 as libc::c_int {
                src = src.offset(1);
            }
            if *src as libc::c_int != 0 as libc::c_int {
                let fresh126 = dst;
                dst = dst.offset(1);
                *fresh126 = 0x20 as libc::c_int as xmlChar;
            }
        } else {
            let fresh127 = src;
            src = src.offset(1);
            let fresh128 = dst;
            dst = dst.offset(1);
            *fresh128 = *fresh127;
        }
    }
    *dst = 0 as libc::c_int as xmlChar;
}
unsafe extern "C" fn xmlIsStreaming(mut ctxt: xmlValidCtxtPtr) -> libc::c_int {
    let mut pctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    if ctxt.is_null() {
        return 0 as libc::c_int;
    }
    if (*ctxt).flags & (1 as libc::c_uint) << 1 as libc::c_int
        == 0 as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    pctxt = (*ctxt).userData as xmlParserCtxtPtr;
    return ((*pctxt).parseMode as libc::c_uint
        == XML_PARSE_READER as libc::c_int as libc::c_uint) as libc::c_int;
}
unsafe extern "C" fn xmlFreeID(mut id: xmlIDPtr) {
    let mut dict: xmlDictPtr = 0 as xmlDictPtr;
    if id.is_null() {
        return;
    }
    if !((*id).doc).is_null() {
        dict = (*(*id).doc).dict;
    }
    if !((*id).value).is_null() {
        if !((*id).value).is_null()
            && (dict.is_null() || xmlDictOwns(dict, (*id).value) == 0 as libc::c_int)
        {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*id).value as *mut libc::c_char as *mut libc::c_void);
        }
    }
    if !((*id).name).is_null() {
        if !((*id).name).is_null()
            && (dict.is_null() || xmlDictOwns(dict, (*id).name) == 0 as libc::c_int)
        {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*id).name as *mut libc::c_char as *mut libc::c_void);
        }
    }
    xmlFree.expect("non-null function pointer")(id as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlAddID(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut value: *const xmlChar,
    mut attr: xmlAttrPtr,
) -> xmlIDPtr {
    let mut ret: xmlIDPtr = 0 as *mut xmlID;
    let mut table: xmlIDTablePtr = 0 as *mut xmlIDTable;
    if doc.is_null() {
        return 0 as xmlIDPtr;
    }
    if value.is_null()
        || *value.offset(0 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
    {
        return 0 as xmlIDPtr;
    }
    if attr.is_null() {
        return 0 as xmlIDPtr;
    }
    table = (*doc).ids as xmlIDTablePtr;
    if table.is_null() {
        table = xmlHashCreateDict(0 as libc::c_int, (*doc).dict);
        let ref mut fresh129 = (*doc).ids;
        *fresh129 = table as *mut libc::c_void;
    }
    if table.is_null() {
        xmlVErrMemory(
            ctxt,
            b"xmlAddID: Table creation failed!\n\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlIDPtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlID>() as libc::c_ulong) as xmlIDPtr;
    if ret.is_null() {
        xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const libc::c_char);
        return 0 as xmlIDPtr;
    }
    let ref mut fresh130 = (*ret).value;
    *fresh130 = xmlStrdup(value);
    let ref mut fresh131 = (*ret).doc;
    *fresh131 = doc;
    if xmlIsStreaming(ctxt) != 0 {
        if !((*doc).dict).is_null() {
            let ref mut fresh132 = (*ret).name;
            *fresh132 = xmlDictLookup((*doc).dict, (*attr).name, -(1 as libc::c_int));
        } else {
            let ref mut fresh133 = (*ret).name;
            *fresh133 = xmlStrdup((*attr).name);
        }
        let ref mut fresh134 = (*ret).attr;
        *fresh134 = 0 as xmlAttrPtr;
    } else {
        let ref mut fresh135 = (*ret).attr;
        *fresh135 = attr;
        let ref mut fresh136 = (*ret).name;
        *fresh136 = 0 as *const xmlChar;
    }
    (*ret).lineno = xmlGetLineNo((*attr).parent) as libc::c_int;
    if xmlHashAddEntry(table, value, ret as *mut libc::c_void) < 0 as libc::c_int {
        if !ctxt.is_null() {
            xmlErrValidNode(
                ctxt,
                (*attr).parent,
                XML_DTD_ID_REDEFINED,
                b"ID %s already defined\n\0" as *const u8 as *const libc::c_char,
                value,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        xmlFreeID(ret);
        return 0 as xmlIDPtr;
    }
    if !attr.is_null() {
        (*attr).atype = XML_ATTRIBUTE_ID;
    }
    return ret;
}
unsafe extern "C" fn xmlFreeIDTableEntry(
    mut id: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    xmlFreeID(id as xmlIDPtr);
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeIDTable(mut table: xmlIDTablePtr) {
    xmlHashFree(
        table,
        Some(
            xmlFreeIDTableEntry
                as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        ),
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsID(
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
    mut attr: xmlAttrPtr,
) -> libc::c_int {
    if attr.is_null() || ((*attr).name).is_null() {
        return 0 as libc::c_int;
    }
    if !((*attr).ns).is_null() && !((*(*attr).ns).prefix).is_null()
        && strcmp(
            (*attr).name as *mut libc::c_char,
            b"id\0" as *const u8 as *const libc::c_char,
        ) == 0
        && strcmp(
            (*(*attr).ns).prefix as *mut libc::c_char,
            b"xml\0" as *const u8 as *const libc::c_char,
        ) == 0
    {
        return 1 as libc::c_int;
    }
    if doc.is_null() {
        return 0 as libc::c_int;
    }
    if ((*doc).intSubset).is_null() && ((*doc).extSubset).is_null()
        && (*doc).type_0 as libc::c_uint
            != XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int
    } else {
        if (*doc).type_0 as libc::c_uint
            == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
        {
            if xmlStrEqual(
                b"id\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                (*attr).name,
            ) != 0
                || xmlStrEqual(
                    b"name\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    (*attr).name,
                ) != 0
                    && (elem.is_null()
                        || xmlStrEqual(
                            (*elem).name,
                            b"a\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                        ) != 0)
            {
                return 1 as libc::c_int;
            }
            return 0 as libc::c_int;
        } else {
            if elem.is_null() {
                return 0 as libc::c_int
            } else {
                let mut attrDecl: xmlAttributePtr = 0 as xmlAttributePtr;
                let mut felem: [xmlChar; 50] = [0; 50];
                let mut fattr: [xmlChar; 50] = [0; 50];
                let mut fullelemname: *mut xmlChar = 0 as *mut xmlChar;
                let mut fullattrname: *mut xmlChar = 0 as *mut xmlChar;
                fullelemname = if !((*elem).ns).is_null()
                    && !((*(*elem).ns).prefix).is_null()
                {
                    xmlBuildQName(
                        (*elem).name,
                        (*(*elem).ns).prefix,
                        felem.as_mut_ptr(),
                        50 as libc::c_int,
                    )
                } else {
                    (*elem).name as *mut xmlChar
                };
                fullattrname = if !((*attr).ns).is_null()
                    && !((*(*attr).ns).prefix).is_null()
                {
                    xmlBuildQName(
                        (*attr).name,
                        (*(*attr).ns).prefix,
                        fattr.as_mut_ptr(),
                        50 as libc::c_int,
                    )
                } else {
                    (*attr).name as *mut xmlChar
                };
                if !fullelemname.is_null() && !fullattrname.is_null() {
                    attrDecl = xmlGetDtdAttrDesc(
                        (*doc).intSubset,
                        fullelemname,
                        fullattrname,
                    );
                    if attrDecl.is_null() && !((*doc).extSubset).is_null() {
                        attrDecl = xmlGetDtdAttrDesc(
                            (*doc).extSubset,
                            fullelemname,
                            fullattrname,
                        );
                    }
                }
                if fullattrname != fattr.as_mut_ptr()
                    && fullattrname != (*attr).name as *mut xmlChar
                {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(fullattrname as *mut libc::c_void);
                }
                if fullelemname != felem.as_mut_ptr()
                    && fullelemname != (*elem).name as *mut xmlChar
                {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(fullelemname as *mut libc::c_void);
                }
                if !attrDecl.is_null()
                    && (*attrDecl).atype as libc::c_uint
                        == XML_ATTRIBUTE_ID as libc::c_int as libc::c_uint
                {
                    return 1 as libc::c_int;
                }
            }
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlRemoveID(
    mut doc: xmlDocPtr,
    mut attr: xmlAttrPtr,
) -> libc::c_int {
    let mut table: xmlIDTablePtr = 0 as *mut xmlIDTable;
    let mut id: xmlIDPtr = 0 as *mut xmlID;
    let mut ID: *mut xmlChar = 0 as *mut xmlChar;
    if doc.is_null() {
        return -(1 as libc::c_int);
    }
    if attr.is_null() {
        return -(1 as libc::c_int);
    }
    table = (*doc).ids as xmlIDTablePtr;
    if table.is_null() {
        return -(1 as libc::c_int);
    }
    ID = xmlNodeListGetString(doc, (*attr).children, 1 as libc::c_int);
    if ID.is_null() {
        return -(1 as libc::c_int);
    }
    xmlValidNormalizeString(ID);
    id = xmlHashLookup(table, ID) as xmlIDPtr;
    if id.is_null() || (*id).attr != attr {
        xmlFree.expect("non-null function pointer")(ID as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    xmlHashRemoveEntry(
        table,
        ID,
        Some(
            xmlFreeIDTableEntry
                as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        ),
    );
    xmlFree.expect("non-null function pointer")(ID as *mut libc::c_void);
    (*attr).atype = 0 as xmlAttributeType;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetID(
    mut doc: xmlDocPtr,
    mut ID: *const xmlChar,
) -> xmlAttrPtr {
    let mut table: xmlIDTablePtr = 0 as *mut xmlIDTable;
    let mut id: xmlIDPtr = 0 as *mut xmlID;
    if doc.is_null() {
        return 0 as xmlAttrPtr;
    }
    if ID.is_null() {
        return 0 as xmlAttrPtr;
    }
    table = (*doc).ids as xmlIDTablePtr;
    if table.is_null() {
        return 0 as xmlAttrPtr;
    }
    id = xmlHashLookup(table, ID) as xmlIDPtr;
    if id.is_null() {
        return 0 as xmlAttrPtr;
    }
    if ((*id).attr).is_null() {
        return doc as xmlAttrPtr;
    }
    return (*id).attr;
}
unsafe extern "C" fn xmlFreeRef(mut lk: xmlLinkPtr) {
    let mut ref_0: xmlRefPtr = xmlLinkGetData(lk) as xmlRefPtr;
    if ref_0.is_null() {
        return;
    }
    if !((*ref_0).value).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ref_0).value as *mut xmlChar as *mut libc::c_void);
    }
    if !((*ref_0).name).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ref_0).name as *mut xmlChar as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(ref_0 as *mut libc::c_void);
}
unsafe extern "C" fn xmlFreeRefTableEntry(
    mut payload: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    let mut list_ref: xmlListPtr = payload as xmlListPtr;
    if list_ref.is_null() {
        return;
    }
    xmlListDelete(list_ref);
}
unsafe extern "C" fn xmlWalkRemoveRef(
    mut data: *const libc::c_void,
    mut user: *mut libc::c_void,
) -> libc::c_int {
    let mut attr0: xmlAttrPtr = (*(data as xmlRefPtr)).attr;
    let mut attr1: xmlAttrPtr = (*(user as xmlRemoveMemoPtr)).ap;
    let mut ref_list: xmlListPtr = (*(user as xmlRemoveMemoPtr)).l;
    if attr0 == attr1 {
        xmlListRemoveFirst(ref_list, data as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn xmlDummyCompare(
    mut data0: *const libc::c_void,
    mut data1: *const libc::c_void,
) -> libc::c_int {
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAddRef(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut value: *const xmlChar,
    mut attr: xmlAttrPtr,
) -> xmlRefPtr {
    let mut current_block: u64;
    let mut ret: xmlRefPtr = 0 as *mut xmlRef;
    let mut table: xmlRefTablePtr = 0 as *mut xmlRefTable;
    let mut ref_list: xmlListPtr = 0 as *mut xmlList;
    if doc.is_null() {
        return 0 as xmlRefPtr;
    }
    if value.is_null() {
        return 0 as xmlRefPtr;
    }
    if attr.is_null() {
        return 0 as xmlRefPtr;
    }
    table = (*doc).refs as xmlRefTablePtr;
    if table.is_null() {
        table = xmlHashCreateDict(0 as libc::c_int, (*doc).dict);
        let ref mut fresh137 = (*doc).refs;
        *fresh137 = table as *mut libc::c_void;
    }
    if table.is_null() {
        xmlVErrMemory(
            ctxt,
            b"xmlAddRef: Table creation failed!\n\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlRefPtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlRef>() as libc::c_ulong) as xmlRefPtr;
    if ret.is_null() {
        xmlVErrMemory(ctxt, b"malloc failed\0" as *const u8 as *const libc::c_char);
        return 0 as xmlRefPtr;
    }
    let ref mut fresh138 = (*ret).value;
    *fresh138 = xmlStrdup(value);
    if xmlIsStreaming(ctxt) != 0 {
        let ref mut fresh139 = (*ret).name;
        *fresh139 = xmlStrdup((*attr).name);
        let ref mut fresh140 = (*ret).attr;
        *fresh140 = 0 as xmlAttrPtr;
    } else {
        let ref mut fresh141 = (*ret).name;
        *fresh141 = 0 as *const xmlChar;
        let ref mut fresh142 = (*ret).attr;
        *fresh142 = attr;
    }
    (*ret).lineno = xmlGetLineNo((*attr).parent) as libc::c_int;
    ref_list = xmlHashLookup(table, value) as xmlListPtr;
    if ref_list.is_null() {
        ref_list = xmlListCreate(
            Some(xmlFreeRef as unsafe extern "C" fn(xmlLinkPtr) -> ()),
            Some(
                xmlDummyCompare
                    as unsafe extern "C" fn(
                        *const libc::c_void,
                        *const libc::c_void,
                    ) -> libc::c_int,
            ),
        );
        if ref_list.is_null() {
            xmlErrValid(
                0 as xmlValidCtxtPtr,
                XML_ERR_INTERNAL_ERROR,
                b"xmlAddRef: Reference list creation failed!\n\0" as *const u8
                    as *const libc::c_char,
                0 as *const libc::c_char,
            );
            current_block = 11302113584356292201;
        } else if xmlHashAddEntry(table, value, ref_list as *mut libc::c_void)
                < 0 as libc::c_int
            {
            xmlListDelete(ref_list);
            xmlErrValid(
                0 as xmlValidCtxtPtr,
                XML_ERR_INTERNAL_ERROR,
                b"xmlAddRef: Reference list insertion failed!\n\0" as *const u8
                    as *const libc::c_char,
                0 as *const libc::c_char,
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
            if xmlListAppend(ref_list, ret as *mut libc::c_void) != 0 as libc::c_int {
                xmlErrValid(
                    0 as xmlValidCtxtPtr,
                    XML_ERR_INTERNAL_ERROR,
                    b"xmlAddRef: Reference list insertion failed!\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const libc::c_char,
                );
            } else {
                return ret
            }
        }
        _ => {}
    }
    if !ret.is_null() {
        if !((*ret).value).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ret).value as *mut libc::c_char as *mut libc::c_void);
        }
        if !((*ret).name).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ret).name as *mut libc::c_char as *mut libc::c_void);
        }
        xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
    }
    return 0 as xmlRefPtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeRefTable(mut table: xmlRefTablePtr) {
    xmlHashFree(
        table,
        Some(
            xmlFreeRefTableEntry
                as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        ),
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsRef(
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
    mut attr: xmlAttrPtr,
) -> libc::c_int {
    if attr.is_null() {
        return 0 as libc::c_int;
    }
    if doc.is_null() {
        doc = (*attr).doc;
        if doc.is_null() {
            return 0 as libc::c_int;
        }
    }
    if ((*doc).intSubset).is_null() && ((*doc).extSubset).is_null() {
        return 0 as libc::c_int
    } else {
        if (*doc).type_0 as libc::c_uint
            == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
        {
            return 0 as libc::c_int
        } else {
            let mut attrDecl: xmlAttributePtr = 0 as *mut xmlAttribute;
            if elem.is_null() {
                return 0 as libc::c_int;
            }
            attrDecl = xmlGetDtdAttrDesc((*doc).intSubset, (*elem).name, (*attr).name);
            if attrDecl.is_null() && !((*doc).extSubset).is_null() {
                attrDecl = xmlGetDtdAttrDesc(
                    (*doc).extSubset,
                    (*elem).name,
                    (*attr).name,
                );
            }
            if !attrDecl.is_null()
                && ((*attrDecl).atype as libc::c_uint
                    == XML_ATTRIBUTE_IDREF as libc::c_int as libc::c_uint
                    || (*attrDecl).atype as libc::c_uint
                        == XML_ATTRIBUTE_IDREFS as libc::c_int as libc::c_uint)
            {
                return 1 as libc::c_int;
            }
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlRemoveRef(
    mut doc: xmlDocPtr,
    mut attr: xmlAttrPtr,
) -> libc::c_int {
    let mut ref_list: xmlListPtr = 0 as *mut xmlList;
    let mut table: xmlRefTablePtr = 0 as *mut xmlRefTable;
    let mut ID: *mut xmlChar = 0 as *mut xmlChar;
    let mut target: xmlRemoveMemo = xmlRemoveMemo {
        l: 0 as *mut xmlList,
        ap: 0 as *mut xmlAttr,
    };
    if doc.is_null() {
        return -(1 as libc::c_int);
    }
    if attr.is_null() {
        return -(1 as libc::c_int);
    }
    table = (*doc).refs as xmlRefTablePtr;
    if table.is_null() {
        return -(1 as libc::c_int);
    }
    ID = xmlNodeListGetString(doc, (*attr).children, 1 as libc::c_int);
    if ID.is_null() {
        return -(1 as libc::c_int);
    }
    ref_list = xmlHashLookup(table, ID) as xmlListPtr;
    if ref_list.is_null() {
        xmlFree.expect("non-null function pointer")(ID as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    target.l = ref_list;
    target.ap = attr;
    xmlListWalk(
        ref_list,
        Some(
            xmlWalkRemoveRef
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut libc::c_void,
                ) -> libc::c_int,
        ),
        &mut target as *mut xmlRemoveMemo as *mut libc::c_void,
    );
    if xmlListEmpty(ref_list) != 0 {
        xmlHashUpdateEntry(
            table,
            ID,
            0 as *mut libc::c_void,
            Some(
                xmlFreeRefTableEntry
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
        );
    }
    xmlFree.expect("non-null function pointer")(ID as *mut libc::c_void);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetRefs(
    mut doc: xmlDocPtr,
    mut ID: *const xmlChar,
) -> xmlListPtr {
    let mut table: xmlRefTablePtr = 0 as *mut xmlRefTable;
    if doc.is_null() {
        return 0 as xmlListPtr;
    }
    if ID.is_null() {
        return 0 as xmlListPtr;
    }
    table = (*doc).refs as xmlRefTablePtr;
    if table.is_null() {
        return 0 as xmlListPtr;
    }
    return xmlHashLookup(table, ID) as xmlListPtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetDtdElementDesc(
    mut dtd: xmlDtdPtr,
    mut name: *const xmlChar,
) -> xmlElementPtr {
    let mut table: xmlElementTablePtr = 0 as *mut xmlElementTable;
    let mut cur: xmlElementPtr = 0 as *mut xmlElement;
    let mut uqname: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if dtd.is_null() || name.is_null() {
        return 0 as xmlElementPtr;
    }
    if ((*dtd).elements).is_null() {
        return 0 as xmlElementPtr;
    }
    table = (*dtd).elements as xmlElementTablePtr;
    uqname = xmlSplitQName2(name, &mut prefix);
    if !uqname.is_null() {
        name = uqname;
    }
    cur = xmlHashLookup2(table, name, prefix) as xmlElementPtr;
    if !prefix.is_null() {
        xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void);
    }
    if !uqname.is_null() {
        xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void);
    }
    return cur;
}
unsafe extern "C" fn xmlGetDtdElementDesc2(
    mut dtd: xmlDtdPtr,
    mut name: *const xmlChar,
    mut create: libc::c_int,
) -> xmlElementPtr {
    let mut table: xmlElementTablePtr = 0 as *mut xmlElementTable;
    let mut cur: xmlElementPtr = 0 as *mut xmlElement;
    let mut uqname: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if dtd.is_null() {
        return 0 as xmlElementPtr;
    }
    if ((*dtd).elements).is_null() {
        let mut dict: xmlDictPtr = 0 as xmlDictPtr;
        if !((*dtd).doc).is_null() {
            dict = (*(*dtd).doc).dict;
        }
        if create == 0 {
            return 0 as xmlElementPtr;
        }
        table = (*dtd).elements as xmlElementTablePtr;
        if table.is_null() {
            table = xmlHashCreateDict(0 as libc::c_int, dict);
            let ref mut fresh143 = (*dtd).elements;
            *fresh143 = table as *mut libc::c_void;
        }
        if table.is_null() {
            xmlVErrMemory(
                0 as xmlValidCtxtPtr,
                b"element table allocation failed\0" as *const u8 as *const libc::c_char,
            );
            return 0 as xmlElementPtr;
        }
    }
    table = (*dtd).elements as xmlElementTablePtr;
    uqname = xmlSplitQName2(name, &mut prefix);
    if !uqname.is_null() {
        name = uqname;
    }
    cur = xmlHashLookup2(table, name, prefix) as xmlElementPtr;
    if cur.is_null() && create != 0 {
        cur = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlElement>() as libc::c_ulong) as xmlElementPtr;
        if cur.is_null() {
            xmlVErrMemory(
                0 as xmlValidCtxtPtr,
                b"malloc failed\0" as *const u8 as *const libc::c_char,
            );
            return 0 as xmlElementPtr;
        }
        memset(
            cur as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<xmlElement>() as libc::c_ulong,
        );
        (*cur).type_0 = XML_ELEMENT_DECL;
        let ref mut fresh144 = (*cur).name;
        *fresh144 = xmlStrdup(name);
        let ref mut fresh145 = (*cur).prefix;
        *fresh145 = xmlStrdup(prefix);
        (*cur).etype = XML_ELEMENT_TYPE_UNDEFINED;
        xmlHashAddEntry2(table, name, prefix, cur as *mut libc::c_void);
    }
    if !prefix.is_null() {
        xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void);
    }
    if !uqname.is_null() {
        xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void);
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetDtdQElementDesc(
    mut dtd: xmlDtdPtr,
    mut name: *const xmlChar,
    mut prefix: *const xmlChar,
) -> xmlElementPtr {
    let mut table: xmlElementTablePtr = 0 as *mut xmlElementTable;
    if dtd.is_null() {
        return 0 as xmlElementPtr;
    }
    if ((*dtd).elements).is_null() {
        return 0 as xmlElementPtr;
    }
    table = (*dtd).elements as xmlElementTablePtr;
    return xmlHashLookup2(table, name, prefix) as xmlElementPtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetDtdAttrDesc(
    mut dtd: xmlDtdPtr,
    mut elem: *const xmlChar,
    mut name: *const xmlChar,
) -> xmlAttributePtr {
    let mut table: xmlAttributeTablePtr = 0 as *mut xmlAttributeTable;
    let mut cur: xmlAttributePtr = 0 as *mut xmlAttribute;
    let mut uqname: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if dtd.is_null() {
        return 0 as xmlAttributePtr;
    }
    if ((*dtd).attributes).is_null() {
        return 0 as xmlAttributePtr;
    }
    table = (*dtd).attributes as xmlAttributeTablePtr;
    if table.is_null() {
        return 0 as xmlAttributePtr;
    }
    uqname = xmlSplitQName2(name, &mut prefix);
    if !uqname.is_null() {
        cur = xmlHashLookup3(table, uqname, prefix, elem) as xmlAttributePtr;
        if !prefix.is_null() {
            xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void);
        }
        if !uqname.is_null() {
            xmlFree.expect("non-null function pointer")(uqname as *mut libc::c_void);
        }
    } else {
        cur = xmlHashLookup3(table, name, 0 as *const xmlChar, elem) as xmlAttributePtr;
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetDtdQAttrDesc(
    mut dtd: xmlDtdPtr,
    mut elem: *const xmlChar,
    mut name: *const xmlChar,
    mut prefix: *const xmlChar,
) -> xmlAttributePtr {
    let mut table: xmlAttributeTablePtr = 0 as *mut xmlAttributeTable;
    if dtd.is_null() {
        return 0 as xmlAttributePtr;
    }
    if ((*dtd).attributes).is_null() {
        return 0 as xmlAttributePtr;
    }
    table = (*dtd).attributes as xmlAttributeTablePtr;
    return xmlHashLookup3(table, name, prefix, elem) as xmlAttributePtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetDtdNotationDesc(
    mut dtd: xmlDtdPtr,
    mut name: *const xmlChar,
) -> xmlNotationPtr {
    let mut table: xmlNotationTablePtr = 0 as *mut xmlNotationTable;
    if dtd.is_null() {
        return 0 as xmlNotationPtr;
    }
    if ((*dtd).notations).is_null() {
        return 0 as xmlNotationPtr;
    }
    table = (*dtd).notations as xmlNotationTablePtr;
    return xmlHashLookup(table, name) as xmlNotationPtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateNotationUse(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut notationName: *const xmlChar,
) -> libc::c_int {
    let mut notaDecl: xmlNotationPtr = 0 as *mut xmlNotation;
    if doc.is_null() || ((*doc).intSubset).is_null() || notationName.is_null() {
        return -(1 as libc::c_int);
    }
    notaDecl = xmlGetDtdNotationDesc((*doc).intSubset, notationName);
    if notaDecl.is_null() && !((*doc).extSubset).is_null() {
        notaDecl = xmlGetDtdNotationDesc((*doc).extSubset, notationName);
    }
    if notaDecl.is_null() && !ctxt.is_null() {
        xmlErrValidNode(
            ctxt,
            doc as xmlNodePtr,
            XML_DTD_UNKNOWN_NOTATION,
            b"NOTATION %s is not declared\n\0" as *const u8 as *const libc::c_char,
            notationName,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlIsMixedElement(
    mut doc: xmlDocPtr,
    mut name: *const xmlChar,
) -> libc::c_int {
    let mut elemDecl: xmlElementPtr = 0 as *mut xmlElement;
    if doc.is_null() || ((*doc).intSubset).is_null() {
        return -(1 as libc::c_int);
    }
    elemDecl = xmlGetDtdElementDesc((*doc).intSubset, name);
    if elemDecl.is_null() && !((*doc).extSubset).is_null() {
        elemDecl = xmlGetDtdElementDesc((*doc).extSubset, name);
    }
    if elemDecl.is_null() {
        return -(1 as libc::c_int);
    }
    match (*elemDecl).etype as libc::c_uint {
        0 => return -(1 as libc::c_int),
        4 => return 0 as libc::c_int,
        1 | 2 | 3 => return 1 as libc::c_int,
        _ => {}
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn xmlIsDocNameStartChar(
    mut doc: xmlDocPtr,
    mut c: libc::c_int,
) -> libc::c_int {
    if doc.is_null()
        || (*doc).properties & XML_DOC_OLD10 as libc::c_int == 0 as libc::c_int
    {
        if c >= 'a' as i32 && c <= 'z' as i32 || c >= 'A' as i32 && c <= 'Z' as i32
            || c == '_' as i32 || c == ':' as i32
            || c >= 0xc0 as libc::c_int && c <= 0xd6 as libc::c_int
            || c >= 0xd8 as libc::c_int && c <= 0xf6 as libc::c_int
            || c >= 0xf8 as libc::c_int && c <= 0x2ff as libc::c_int
            || c >= 0x370 as libc::c_int && c <= 0x37d as libc::c_int
            || c >= 0x37f as libc::c_int && c <= 0x1fff as libc::c_int
            || c >= 0x200c as libc::c_int && c <= 0x200d as libc::c_int
            || c >= 0x2070 as libc::c_int && c <= 0x218f as libc::c_int
            || c >= 0x2c00 as libc::c_int && c <= 0x2fef as libc::c_int
            || c >= 0x3001 as libc::c_int && c <= 0xd7ff as libc::c_int
            || c >= 0xf900 as libc::c_int && c <= 0xfdcf as libc::c_int
            || c >= 0xfdf0 as libc::c_int && c <= 0xfffd as libc::c_int
            || c >= 0x10000 as libc::c_int && c <= 0xeffff as libc::c_int
        {
            return 1 as libc::c_int;
        }
    } else if (if c < 0x100 as libc::c_int {
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
            }) != 0 || c == '_' as i32 || c == ':' as i32
        {
        return 1 as libc::c_int
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlIsDocNameChar(
    mut doc: xmlDocPtr,
    mut c: libc::c_int,
) -> libc::c_int {
    if doc.is_null()
        || (*doc).properties & XML_DOC_OLD10 as libc::c_int == 0 as libc::c_int
    {
        if c >= 'a' as i32 && c <= 'z' as i32 || c >= 'A' as i32 && c <= 'Z' as i32
            || c >= '0' as i32 && c <= '9' as i32 || c == '_' as i32 || c == ':' as i32
            || c == '-' as i32 || c == '.' as i32 || c == 0xb7 as libc::c_int
            || c >= 0xc0 as libc::c_int && c <= 0xd6 as libc::c_int
            || c >= 0xd8 as libc::c_int && c <= 0xf6 as libc::c_int
            || c >= 0xf8 as libc::c_int && c <= 0x2ff as libc::c_int
            || c >= 0x300 as libc::c_int && c <= 0x36f as libc::c_int
            || c >= 0x370 as libc::c_int && c <= 0x37d as libc::c_int
            || c >= 0x37f as libc::c_int && c <= 0x1fff as libc::c_int
            || c >= 0x200c as libc::c_int && c <= 0x200d as libc::c_int
            || c >= 0x203f as libc::c_int && c <= 0x2040 as libc::c_int
            || c >= 0x2070 as libc::c_int && c <= 0x218f as libc::c_int
            || c >= 0x2c00 as libc::c_int && c <= 0x2fef as libc::c_int
            || c >= 0x3001 as libc::c_int && c <= 0xd7ff as libc::c_int
            || c >= 0xf900 as libc::c_int && c <= 0xfdcf as libc::c_int
            || c >= 0xfdf0 as libc::c_int && c <= 0xfffd as libc::c_int
            || c >= 0x10000 as libc::c_int && c <= 0xeffff as libc::c_int
        {
            return 1 as libc::c_int;
        }
    } else if (if c < 0x100 as libc::c_int {
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
            }) != 0
        {
        return 1 as libc::c_int
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlValidateNameValueInternal(
    mut doc: xmlDocPtr,
    mut value: *const xmlChar,
) -> libc::c_int {
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut val: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    if value.is_null() {
        return 0 as libc::c_int;
    }
    cur = value;
    val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
    cur = cur.offset(len as isize);
    if xmlIsDocNameStartChar(doc, val) == 0 {
        return 0 as libc::c_int;
    }
    val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
    cur = cur.offset(len as isize);
    while xmlIsDocNameChar(doc, val) != 0 {
        val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
        cur = cur.offset(len as isize);
    }
    if val != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateNameValue(mut value: *const xmlChar) -> libc::c_int {
    return xmlValidateNameValueInternal(0 as xmlDocPtr, value);
}
unsafe extern "C" fn xmlValidateNamesValueInternal(
    mut doc: xmlDocPtr,
    mut value: *const xmlChar,
) -> libc::c_int {
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut val: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    if value.is_null() {
        return 0 as libc::c_int;
    }
    cur = value;
    val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
    cur = cur.offset(len as isize);
    if xmlIsDocNameStartChar(doc, val) == 0 {
        return 0 as libc::c_int;
    }
    val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
    cur = cur.offset(len as isize);
    while xmlIsDocNameChar(doc, val) != 0 {
        val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
        cur = cur.offset(len as isize);
    }
    while val == 0x20 as libc::c_int {
        while val == 0x20 as libc::c_int {
            val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
            cur = cur.offset(len as isize);
        }
        if xmlIsDocNameStartChar(doc, val) == 0 {
            return 0 as libc::c_int;
        }
        val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
        cur = cur.offset(len as isize);
        while xmlIsDocNameChar(doc, val) != 0 {
            val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
            cur = cur.offset(len as isize);
        }
    }
    if val != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateNamesValue(
    mut value: *const xmlChar,
) -> libc::c_int {
    return xmlValidateNamesValueInternal(0 as xmlDocPtr, value);
}
unsafe extern "C" fn xmlValidateNmtokenValueInternal(
    mut doc: xmlDocPtr,
    mut value: *const xmlChar,
) -> libc::c_int {
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut val: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    if value.is_null() {
        return 0 as libc::c_int;
    }
    cur = value;
    val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
    cur = cur.offset(len as isize);
    if xmlIsDocNameChar(doc, val) == 0 {
        return 0 as libc::c_int;
    }
    val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
    cur = cur.offset(len as isize);
    while xmlIsDocNameChar(doc, val) != 0 {
        val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
        cur = cur.offset(len as isize);
    }
    if val != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateNmtokenValue(
    mut value: *const xmlChar,
) -> libc::c_int {
    return xmlValidateNmtokenValueInternal(0 as xmlDocPtr, value);
}
unsafe extern "C" fn xmlValidateNmtokensValueInternal(
    mut doc: xmlDocPtr,
    mut value: *const xmlChar,
) -> libc::c_int {
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut val: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    if value.is_null() {
        return 0 as libc::c_int;
    }
    cur = value;
    val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
    cur = cur.offset(len as isize);
    while if val < 0x100 as libc::c_int {
        (val == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= val && val <= 0xa as libc::c_int
            || val == 0xd as libc::c_int) as libc::c_int
    } else {
        0 as libc::c_int
    } != 0
    {
        val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
        cur = cur.offset(len as isize);
    }
    if xmlIsDocNameChar(doc, val) == 0 {
        return 0 as libc::c_int;
    }
    while xmlIsDocNameChar(doc, val) != 0 {
        val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
        cur = cur.offset(len as isize);
    }
    while val == 0x20 as libc::c_int {
        while val == 0x20 as libc::c_int {
            val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
            cur = cur.offset(len as isize);
        }
        if val == 0 as libc::c_int {
            return 1 as libc::c_int;
        }
        if xmlIsDocNameChar(doc, val) == 0 {
            return 0 as libc::c_int;
        }
        val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
        cur = cur.offset(len as isize);
        while xmlIsDocNameChar(doc, val) != 0 {
            val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
            cur = cur.offset(len as isize);
        }
    }
    if val != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateNmtokensValue(
    mut value: *const xmlChar,
) -> libc::c_int {
    return xmlValidateNmtokensValueInternal(0 as xmlDocPtr, value);
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateNotationDecl(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut nota: xmlNotationPtr,
) -> libc::c_int {
    let mut ret: libc::c_int = 1 as libc::c_int;
    return ret;
}
unsafe extern "C" fn xmlValidateAttributeValueInternal(
    mut doc: xmlDocPtr,
    mut type_0: xmlAttributeType,
    mut value: *const xmlChar,
) -> libc::c_int {
    match type_0 as libc::c_uint {
        6 | 4 => return xmlValidateNamesValueInternal(doc, value),
        5 | 3 | 2 | 10 => return xmlValidateNameValueInternal(doc, value),
        8 | 9 => return xmlValidateNmtokensValueInternal(doc, value),
        7 => return xmlValidateNmtokenValueInternal(doc, value),
        1 | _ => {}
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateAttributeValue(
    mut type_0: xmlAttributeType,
    mut value: *const xmlChar,
) -> libc::c_int {
    return xmlValidateAttributeValueInternal(0 as xmlDocPtr, type_0, value);
}
unsafe extern "C" fn xmlValidateAttributeValue2(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut name: *const xmlChar,
    mut type_0: xmlAttributeType,
    mut value: *const xmlChar,
) -> libc::c_int {
    let mut ret: libc::c_int = 1 as libc::c_int;
    match type_0 as libc::c_uint {
        5 => {
            let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
            ent = xmlGetDocEntity(doc as *const xmlDoc, value);
            if ent.is_null() && (*doc).standalone == 1 as libc::c_int {
                (*doc).standalone = 0 as libc::c_int;
                ent = xmlGetDocEntity(doc as *const xmlDoc, value);
            }
            if ent.is_null() {
                xmlErrValidNode(
                    ctxt,
                    doc as xmlNodePtr,
                    XML_DTD_UNKNOWN_ENTITY,
                    b"ENTITY attribute %s reference an unknown entity \"%s\"\n\0"
                        as *const u8 as *const libc::c_char,
                    name,
                    value,
                    0 as *const xmlChar,
                );
                ret = 0 as libc::c_int;
            } else if (*ent).etype as libc::c_uint
                    != XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as libc::c_int
                        as libc::c_uint
                {
                xmlErrValidNode(
                    ctxt,
                    doc as xmlNodePtr,
                    XML_DTD_ENTITY_TYPE,
                    b"ENTITY attribute %s reference an entity \"%s\" of wrong type\n\0"
                        as *const u8 as *const libc::c_char,
                    name,
                    value,
                    0 as *const xmlChar,
                );
                ret = 0 as libc::c_int;
            }
        }
        6 => {
            let mut dup: *mut xmlChar = 0 as *mut xmlChar;
            let mut nam: *mut xmlChar = 0 as *mut xmlChar;
            let mut cur: *mut xmlChar = 0 as *mut xmlChar;
            let mut save: xmlChar = 0;
            let mut ent_0: xmlEntityPtr = 0 as *mut xmlEntity;
            dup = xmlStrdup(value);
            if dup.is_null() {
                return 0 as libc::c_int;
            }
            cur = dup;
            while *cur as libc::c_int != 0 as libc::c_int {
                nam = cur;
                while *cur as libc::c_int != 0 as libc::c_int
                    && !(*cur as libc::c_int == 0x20 as libc::c_int
                        || 0x9 as libc::c_int <= *cur as libc::c_int
                            && *cur as libc::c_int <= 0xa as libc::c_int
                        || *cur as libc::c_int == 0xd as libc::c_int)
                {
                    cur = cur.offset(1);
                }
                save = *cur;
                *cur = 0 as libc::c_int as xmlChar;
                ent_0 = xmlGetDocEntity(doc as *const xmlDoc, nam);
                if ent_0.is_null() {
                    xmlErrValidNode(
                        ctxt,
                        doc as xmlNodePtr,
                        XML_DTD_UNKNOWN_ENTITY,
                        b"ENTITIES attribute %s reference an unknown entity \"%s\"\n\0"
                            as *const u8 as *const libc::c_char,
                        name,
                        nam,
                        0 as *const xmlChar,
                    );
                    ret = 0 as libc::c_int;
                } else if (*ent_0).etype as libc::c_uint
                        != XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as libc::c_int
                            as libc::c_uint
                    {
                    xmlErrValidNode(
                        ctxt,
                        doc as xmlNodePtr,
                        XML_DTD_ENTITY_TYPE,
                        b"ENTITIES attribute %s reference an entity \"%s\" of wrong type\n\0"
                            as *const u8 as *const libc::c_char,
                        name,
                        nam,
                        0 as *const xmlChar,
                    );
                    ret = 0 as libc::c_int;
                }
                if save as libc::c_int == 0 as libc::c_int {
                    break;
                }
                *cur = save;
                while *cur as libc::c_int == 0x20 as libc::c_int
                    || 0x9 as libc::c_int <= *cur as libc::c_int
                        && *cur as libc::c_int <= 0xa as libc::c_int
                    || *cur as libc::c_int == 0xd as libc::c_int
                {
                    cur = cur.offset(1);
                }
            }
            xmlFree.expect("non-null function pointer")(dup as *mut libc::c_void);
        }
        10 => {
            let mut nota: xmlNotationPtr = 0 as *mut xmlNotation;
            nota = xmlGetDtdNotationDesc((*doc).intSubset, value);
            if nota.is_null() && !((*doc).extSubset).is_null() {
                nota = xmlGetDtdNotationDesc((*doc).extSubset, value);
            }
            if nota.is_null() {
                xmlErrValidNode(
                    ctxt,
                    doc as xmlNodePtr,
                    XML_DTD_UNKNOWN_NOTATION,
                    b"NOTATION attribute %s reference an unknown notation \"%s\"\n\0"
                        as *const u8 as *const libc::c_char,
                    name,
                    value,
                    0 as *const xmlChar,
                );
                ret = 0 as libc::c_int;
            }
        }
        4 | 3 | 2 | 8 | 9 | 7 | 1 | _ => {}
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidCtxtNormalizeAttributeValue(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
    mut name: *const xmlChar,
    mut value: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut attrDecl: xmlAttributePtr = 0 as xmlAttributePtr;
    let mut extsubset: libc::c_int = 0 as libc::c_int;
    if doc.is_null() {
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
    if !((*elem).ns).is_null() && !((*(*elem).ns).prefix).is_null() {
        let mut fn_0: [xmlChar; 50] = [0; 50];
        let mut fullname: *mut xmlChar = 0 as *mut xmlChar;
        fullname = xmlBuildQName(
            (*elem).name,
            (*(*elem).ns).prefix,
            fn_0.as_mut_ptr(),
            50 as libc::c_int,
        );
        if fullname.is_null() {
            return 0 as *mut xmlChar;
        }
        attrDecl = xmlGetDtdAttrDesc((*doc).intSubset, fullname, name);
        if attrDecl.is_null() && !((*doc).extSubset).is_null() {
            attrDecl = xmlGetDtdAttrDesc((*doc).extSubset, fullname, name);
            if !attrDecl.is_null() {
                extsubset = 1 as libc::c_int;
            }
        }
        if fullname != fn_0.as_mut_ptr() && fullname != (*elem).name as *mut xmlChar {
            xmlFree.expect("non-null function pointer")(fullname as *mut libc::c_void);
        }
    }
    if attrDecl.is_null() && !((*doc).intSubset).is_null() {
        attrDecl = xmlGetDtdAttrDesc((*doc).intSubset, (*elem).name, name);
    }
    if attrDecl.is_null() && !((*doc).extSubset).is_null() {
        attrDecl = xmlGetDtdAttrDesc((*doc).extSubset, (*elem).name, name);
        if !attrDecl.is_null() {
            extsubset = 1 as libc::c_int;
        }
    }
    if attrDecl.is_null() {
        return 0 as *mut xmlChar;
    }
    if (*attrDecl).atype as libc::c_uint
        == XML_ATTRIBUTE_CDATA as libc::c_int as libc::c_uint
    {
        return 0 as *mut xmlChar;
    }
    ret = xmlStrdup(value);
    if ret.is_null() {
        return 0 as *mut xmlChar;
    }
    xmlValidNormalizeString(ret);
    if (*doc).standalone != 0 && extsubset == 1 as libc::c_int
        && xmlStrEqual(value, ret) == 0
    {
        xmlErrValidNode(
            ctxt,
            elem,
            XML_DTD_NOT_STANDALONE,
            b"standalone: %s on %s value had to be normalized based on external subset declaration\n\0"
                as *const u8 as *const libc::c_char,
            name,
            (*elem).name,
            0 as *const xmlChar,
        );
        (*ctxt).valid = 0 as libc::c_int;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidNormalizeAttributeValue(
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
    mut name: *const xmlChar,
    mut value: *const xmlChar,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut attrDecl: xmlAttributePtr = 0 as xmlAttributePtr;
    if doc.is_null() {
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
    if !((*elem).ns).is_null() && !((*(*elem).ns).prefix).is_null() {
        let mut fn_0: [xmlChar; 50] = [0; 50];
        let mut fullname: *mut xmlChar = 0 as *mut xmlChar;
        fullname = xmlBuildQName(
            (*elem).name,
            (*(*elem).ns).prefix,
            fn_0.as_mut_ptr(),
            50 as libc::c_int,
        );
        if fullname.is_null() {
            return 0 as *mut xmlChar;
        }
        if fullname != fn_0.as_mut_ptr() && fullname != (*elem).name as *mut xmlChar {
            xmlFree.expect("non-null function pointer")(fullname as *mut libc::c_void);
        }
    }
    attrDecl = xmlGetDtdAttrDesc((*doc).intSubset, (*elem).name, name);
    if attrDecl.is_null() && !((*doc).extSubset).is_null() {
        attrDecl = xmlGetDtdAttrDesc((*doc).extSubset, (*elem).name, name);
    }
    if attrDecl.is_null() {
        return 0 as *mut xmlChar;
    }
    if (*attrDecl).atype as libc::c_uint
        == XML_ATTRIBUTE_CDATA as libc::c_int as libc::c_uint
    {
        return 0 as *mut xmlChar;
    }
    ret = xmlStrdup(value);
    if ret.is_null() {
        return 0 as *mut xmlChar;
    }
    xmlValidNormalizeString(ret);
    return ret;
}
unsafe extern "C" fn xmlValidateAttributeIdCallback(
    mut payload: *mut libc::c_void,
    mut data: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    let mut attr: xmlAttributePtr = payload as xmlAttributePtr;
    let mut count: *mut libc::c_int = data as *mut libc::c_int;
    if (*attr).atype as libc::c_uint == XML_ATTRIBUTE_ID as libc::c_int as libc::c_uint {
        *count += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateAttributeDecl(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut attr: xmlAttributePtr,
) -> libc::c_int {
    let mut ret: libc::c_int = 1 as libc::c_int;
    let mut val: libc::c_int = 0;
    if doc.is_null() {
        return 0 as libc::c_int
    } else {
        if ((*doc).intSubset).is_null() && ((*doc).extSubset).is_null() {
            return 0 as libc::c_int;
        }
    }
    if attr.is_null() {
        return 1 as libc::c_int;
    }
    if !((*attr).defaultValue).is_null() {
        val = xmlValidateAttributeValueInternal(
            doc,
            (*attr).atype,
            (*attr).defaultValue,
        );
        if val == 0 as libc::c_int {
            xmlErrValidNode(
                ctxt,
                attr as xmlNodePtr,
                XML_DTD_ATTRIBUTE_DEFAULT,
                b"Syntax of default value for attribute %s of %s is not valid\n\0"
                    as *const u8 as *const libc::c_char,
                (*attr).name,
                (*attr).elem,
                0 as *const xmlChar,
            );
        }
        ret &= val;
    }
    if (*attr).atype as libc::c_uint == XML_ATTRIBUTE_ID as libc::c_int as libc::c_uint
        && (*attr).def as libc::c_uint
            != XML_ATTRIBUTE_IMPLIED as libc::c_int as libc::c_uint
        && (*attr).def as libc::c_uint
            != XML_ATTRIBUTE_REQUIRED as libc::c_int as libc::c_uint
    {
        xmlErrValidNode(
            ctxt,
            attr as xmlNodePtr,
            XML_DTD_ID_FIXED,
            b"ID attribute %s of %s is not valid must be #IMPLIED or #REQUIRED\n\0"
                as *const u8 as *const libc::c_char,
            (*attr).name,
            (*attr).elem,
            0 as *const xmlChar,
        );
        ret = 0 as libc::c_int;
    }
    if (*attr).atype as libc::c_uint == XML_ATTRIBUTE_ID as libc::c_int as libc::c_uint {
        let mut nbId: libc::c_int = 0;
        let mut elem: xmlElementPtr = xmlGetDtdElementDesc(
            (*doc).intSubset,
            (*attr).elem,
        );
        if !elem.is_null() {
            nbId = xmlScanIDAttributeDecl(0 as xmlValidCtxtPtr, elem, 0 as libc::c_int);
        } else {
            let mut table: xmlAttributeTablePtr = 0 as *mut xmlAttributeTable;
            nbId = 0 as libc::c_int;
            if !((*doc).intSubset).is_null() {
                table = (*(*doc).intSubset).attributes as xmlAttributeTablePtr;
                xmlHashScan3(
                    table,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    (*attr).elem,
                    Some(
                        xmlValidateAttributeIdCallback
                            as unsafe extern "C" fn(
                                *mut libc::c_void,
                                *mut libc::c_void,
                                *const xmlChar,
                            ) -> (),
                    ),
                    &mut nbId as *mut libc::c_int as *mut libc::c_void,
                );
            }
        }
        if nbId > 1 as libc::c_int {
            xmlErrValidNodeNr(
                ctxt,
                attr as xmlNodePtr,
                XML_DTD_ID_SUBSET,
                b"Element %s has %d ID attribute defined in the internal subset : %s\n\0"
                    as *const u8 as *const libc::c_char,
                (*attr).elem,
                nbId,
                (*attr).name,
            );
        } else if !((*doc).extSubset).is_null() {
            let mut extId: libc::c_int = 0 as libc::c_int;
            elem = xmlGetDtdElementDesc((*doc).extSubset, (*attr).elem);
            if !elem.is_null() {
                extId = xmlScanIDAttributeDecl(
                    0 as xmlValidCtxtPtr,
                    elem,
                    0 as libc::c_int,
                );
            }
            if extId > 1 as libc::c_int {
                xmlErrValidNodeNr(
                    ctxt,
                    attr as xmlNodePtr,
                    XML_DTD_ID_SUBSET,
                    b"Element %s has %d ID attribute defined in the external subset : %s\n\0"
                        as *const u8 as *const libc::c_char,
                    (*attr).elem,
                    extId,
                    (*attr).name,
                );
            } else if extId + nbId > 1 as libc::c_int {
                xmlErrValidNode(
                    ctxt,
                    attr as xmlNodePtr,
                    XML_DTD_ID_SUBSET,
                    b"Element %s has ID attributes defined in the internal and external subset : %s\n\0"
                        as *const u8 as *const libc::c_char,
                    (*attr).elem,
                    (*attr).name,
                    0 as *const xmlChar,
                );
            }
        }
    }
    if !((*attr).defaultValue).is_null() && !((*attr).tree).is_null() {
        let mut tree: xmlEnumerationPtr = (*attr).tree;
        while !tree.is_null() {
            if xmlStrEqual((*tree).name, (*attr).defaultValue) != 0 {
                break;
            }
            tree = (*tree).next;
        }
        if tree.is_null() {
            xmlErrValidNode(
                ctxt,
                attr as xmlNodePtr,
                XML_DTD_ATTRIBUTE_VALUE,
                b"Default value \"%s\" for attribute %s of %s is not among the enumerated set\n\0"
                    as *const u8 as *const libc::c_char,
                (*attr).defaultValue,
                (*attr).name,
                (*attr).elem,
            );
            ret = 0 as libc::c_int;
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateElementDecl(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut elem: xmlElementPtr,
) -> libc::c_int {
    let mut ret: libc::c_int = 1 as libc::c_int;
    let mut tst: xmlElementPtr = 0 as *mut xmlElement;
    if doc.is_null() {
        return 0 as libc::c_int
    } else {
        if ((*doc).intSubset).is_null() && ((*doc).extSubset).is_null() {
            return 0 as libc::c_int;
        }
    }
    if elem.is_null() {
        return 1 as libc::c_int;
    }
    if (*elem).etype as libc::c_uint
        == XML_ELEMENT_TYPE_MIXED as libc::c_int as libc::c_uint
    {
        let mut cur: xmlElementContentPtr = 0 as *mut xmlElementContent;
        let mut next: xmlElementContentPtr = 0 as *mut xmlElementContent;
        let mut name: *const xmlChar = 0 as *const xmlChar;
        cur = (*elem).content;
        while !cur.is_null() {
            if (*cur).type_0 as libc::c_uint
                != XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
            {
                break;
            }
            if ((*cur).c1).is_null() {
                break;
            }
            if (*(*cur).c1).type_0 as libc::c_uint
                == XML_ELEMENT_CONTENT_ELEMENT as libc::c_int as libc::c_uint
            {
                name = (*(*cur).c1).name;
                next = (*cur).c2;
                while !next.is_null() {
                    if (*next).type_0 as libc::c_uint
                        == XML_ELEMENT_CONTENT_ELEMENT as libc::c_int as libc::c_uint
                    {
                        if xmlStrEqual((*next).name, name) != 0
                            && xmlStrEqual((*next).prefix, (*(*cur).c1).prefix) != 0
                        {
                            if ((*(*cur).c1).prefix).is_null() {
                                xmlErrValidNode(
                                    ctxt,
                                    elem as xmlNodePtr,
                                    XML_DTD_CONTENT_ERROR,
                                    b"Definition of %s has duplicate references of %s\n\0"
                                        as *const u8 as *const libc::c_char,
                                    (*elem).name,
                                    name,
                                    0 as *const xmlChar,
                                );
                            } else {
                                xmlErrValidNode(
                                    ctxt,
                                    elem as xmlNodePtr,
                                    XML_DTD_CONTENT_ERROR,
                                    b"Definition of %s has duplicate references of %s:%s\n\0"
                                        as *const u8 as *const libc::c_char,
                                    (*elem).name,
                                    (*(*cur).c1).prefix,
                                    name,
                                );
                            }
                            ret = 0 as libc::c_int;
                        }
                        break;
                    } else {
                        if ((*next).c1).is_null() {
                            break;
                        }
                        if (*(*next).c1).type_0 as libc::c_uint
                            != XML_ELEMENT_CONTENT_ELEMENT as libc::c_int as libc::c_uint
                        {
                            break;
                        }
                        if xmlStrEqual((*(*next).c1).name, name) != 0
                            && xmlStrEqual((*(*next).c1).prefix, (*(*cur).c1).prefix)
                                != 0
                        {
                            if ((*(*cur).c1).prefix).is_null() {
                                xmlErrValidNode(
                                    ctxt,
                                    elem as xmlNodePtr,
                                    XML_DTD_CONTENT_ERROR,
                                    b"Definition of %s has duplicate references to %s\n\0"
                                        as *const u8 as *const libc::c_char,
                                    (*elem).name,
                                    name,
                                    0 as *const xmlChar,
                                );
                            } else {
                                xmlErrValidNode(
                                    ctxt,
                                    elem as xmlNodePtr,
                                    XML_DTD_CONTENT_ERROR,
                                    b"Definition of %s has duplicate references to %s:%s\n\0"
                                        as *const u8 as *const libc::c_char,
                                    (*elem).name,
                                    (*(*cur).c1).prefix,
                                    name,
                                );
                            }
                            ret = 0 as libc::c_int;
                        }
                        next = (*next).c2;
                    }
                }
            }
            cur = (*cur).c2;
        }
    }
    tst = xmlGetDtdElementDesc((*doc).intSubset, (*elem).name);
    if !tst.is_null() && tst != elem
        && ((*tst).prefix == (*elem).prefix
            || xmlStrEqual((*tst).prefix, (*elem).prefix) != 0)
        && (*tst).etype as libc::c_uint
            != XML_ELEMENT_TYPE_UNDEFINED as libc::c_int as libc::c_uint
    {
        xmlErrValidNode(
            ctxt,
            elem as xmlNodePtr,
            XML_DTD_ELEM_REDEFINED,
            b"Redefinition of element %s\n\0" as *const u8 as *const libc::c_char,
            (*elem).name,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        ret = 0 as libc::c_int;
    }
    tst = xmlGetDtdElementDesc((*doc).extSubset, (*elem).name);
    if !tst.is_null() && tst != elem
        && ((*tst).prefix == (*elem).prefix
            || xmlStrEqual((*tst).prefix, (*elem).prefix) != 0)
        && (*tst).etype as libc::c_uint
            != XML_ELEMENT_TYPE_UNDEFINED as libc::c_int as libc::c_uint
    {
        xmlErrValidNode(
            ctxt,
            elem as xmlNodePtr,
            XML_DTD_ELEM_REDEFINED,
            b"Redefinition of element %s\n\0" as *const u8 as *const libc::c_char,
            (*elem).name,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        ret = 0 as libc::c_int;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateOneAttribute(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
    mut attr: xmlAttrPtr,
    mut value: *const xmlChar,
) -> libc::c_int {
    let mut attrDecl: xmlAttributePtr = 0 as xmlAttributePtr;
    let mut val: libc::c_int = 0;
    let mut ret: libc::c_int = 1 as libc::c_int;
    if doc.is_null() {
        return 0 as libc::c_int
    } else {
        if ((*doc).intSubset).is_null() && ((*doc).extSubset).is_null() {
            return 0 as libc::c_int;
        }
    }
    if elem.is_null() || ((*elem).name).is_null() {
        return 0 as libc::c_int;
    }
    if attr.is_null() || ((*attr).name).is_null() {
        return 0 as libc::c_int;
    }
    if !((*elem).ns).is_null() && !((*(*elem).ns).prefix).is_null() {
        let mut fn_0: [xmlChar; 50] = [0; 50];
        let mut fullname: *mut xmlChar = 0 as *mut xmlChar;
        fullname = xmlBuildQName(
            (*elem).name,
            (*(*elem).ns).prefix,
            fn_0.as_mut_ptr(),
            50 as libc::c_int,
        );
        if fullname.is_null() {
            return 0 as libc::c_int;
        }
        if !((*attr).ns).is_null() {
            attrDecl = xmlGetDtdQAttrDesc(
                (*doc).intSubset,
                fullname,
                (*attr).name,
                (*(*attr).ns).prefix,
            );
            if attrDecl.is_null() && !((*doc).extSubset).is_null() {
                attrDecl = xmlGetDtdQAttrDesc(
                    (*doc).extSubset,
                    fullname,
                    (*attr).name,
                    (*(*attr).ns).prefix,
                );
            }
        } else {
            attrDecl = xmlGetDtdAttrDesc((*doc).intSubset, fullname, (*attr).name);
            if attrDecl.is_null() && !((*doc).extSubset).is_null() {
                attrDecl = xmlGetDtdAttrDesc((*doc).extSubset, fullname, (*attr).name);
            }
        }
        if fullname != fn_0.as_mut_ptr() && fullname != (*elem).name as *mut xmlChar {
            xmlFree.expect("non-null function pointer")(fullname as *mut libc::c_void);
        }
    }
    if attrDecl.is_null() {
        if !((*attr).ns).is_null() {
            attrDecl = xmlGetDtdQAttrDesc(
                (*doc).intSubset,
                (*elem).name,
                (*attr).name,
                (*(*attr).ns).prefix,
            );
            if attrDecl.is_null() && !((*doc).extSubset).is_null() {
                attrDecl = xmlGetDtdQAttrDesc(
                    (*doc).extSubset,
                    (*elem).name,
                    (*attr).name,
                    (*(*attr).ns).prefix,
                );
            }
        } else {
            attrDecl = xmlGetDtdAttrDesc((*doc).intSubset, (*elem).name, (*attr).name);
            if attrDecl.is_null() && !((*doc).extSubset).is_null() {
                attrDecl = xmlGetDtdAttrDesc(
                    (*doc).extSubset,
                    (*elem).name,
                    (*attr).name,
                );
            }
        }
    }
    if attrDecl.is_null() {
        xmlErrValidNode(
            ctxt,
            elem,
            XML_DTD_UNKNOWN_ATTRIBUTE,
            b"No declaration for attribute %s of element %s\n\0" as *const u8
                as *const libc::c_char,
            (*attr).name,
            (*elem).name,
            0 as *const xmlChar,
        );
        return 0 as libc::c_int;
    }
    (*attr).atype = (*attrDecl).atype;
    val = xmlValidateAttributeValueInternal(doc, (*attrDecl).atype, value);
    if val == 0 as libc::c_int {
        xmlErrValidNode(
            ctxt,
            elem,
            XML_DTD_ATTRIBUTE_VALUE,
            b"Syntax of value for attribute %s of %s is not valid\n\0" as *const u8
                as *const libc::c_char,
            (*attr).name,
            (*elem).name,
            0 as *const xmlChar,
        );
        ret = 0 as libc::c_int;
    }
    if (*attrDecl).def as libc::c_uint
        == XML_ATTRIBUTE_FIXED as libc::c_int as libc::c_uint
    {
        if xmlStrEqual(value, (*attrDecl).defaultValue) == 0 {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_ATTRIBUTE_DEFAULT,
                b"Value for attribute %s of %s is different from default \"%s\"\n\0"
                    as *const u8 as *const libc::c_char,
                (*attr).name,
                (*elem).name,
                (*attrDecl).defaultValue,
            );
            ret = 0 as libc::c_int;
        }
    }
    if (*attrDecl).atype as libc::c_uint
        == XML_ATTRIBUTE_ID as libc::c_int as libc::c_uint
    {
        if (xmlAddID(ctxt, doc, value, attr)).is_null() {
            ret = 0 as libc::c_int;
        }
    }
    if (*attrDecl).atype as libc::c_uint
        == XML_ATTRIBUTE_IDREF as libc::c_int as libc::c_uint
        || (*attrDecl).atype as libc::c_uint
            == XML_ATTRIBUTE_IDREFS as libc::c_int as libc::c_uint
    {
        if (xmlAddRef(ctxt, doc, value, attr)).is_null() {
            ret = 0 as libc::c_int;
        }
    }
    if (*attrDecl).atype as libc::c_uint
        == XML_ATTRIBUTE_NOTATION as libc::c_int as libc::c_uint
    {
        let mut tree: xmlEnumerationPtr = (*attrDecl).tree;
        let mut nota: xmlNotationPtr = 0 as *mut xmlNotation;
        nota = xmlGetDtdNotationDesc((*doc).intSubset, value);
        if nota.is_null() {
            nota = xmlGetDtdNotationDesc((*doc).extSubset, value);
        }
        if nota.is_null() {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_UNKNOWN_NOTATION,
                b"Value \"%s\" for attribute %s of %s is not a declared Notation\n\0"
                    as *const u8 as *const libc::c_char,
                value,
                (*attr).name,
                (*elem).name,
            );
            ret = 0 as libc::c_int;
        }
        while !tree.is_null() {
            if xmlStrEqual((*tree).name, value) != 0 {
                break;
            }
            tree = (*tree).next;
        }
        if tree.is_null() {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_NOTATION_VALUE,
                b"Value \"%s\" for attribute %s of %s is not among the enumerated notations\n\0"
                    as *const u8 as *const libc::c_char,
                value,
                (*attr).name,
                (*elem).name,
            );
            ret = 0 as libc::c_int;
        }
    }
    if (*attrDecl).atype as libc::c_uint
        == XML_ATTRIBUTE_ENUMERATION as libc::c_int as libc::c_uint
    {
        let mut tree_0: xmlEnumerationPtr = (*attrDecl).tree;
        while !tree_0.is_null() {
            if xmlStrEqual((*tree_0).name, value) != 0 {
                break;
            }
            tree_0 = (*tree_0).next;
        }
        if tree_0.is_null() {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_ATTRIBUTE_VALUE,
                b"Value \"%s\" for attribute %s of %s is not among the enumerated set\n\0"
                    as *const u8 as *const libc::c_char,
                value,
                (*attr).name,
                (*elem).name,
            );
            ret = 0 as libc::c_int;
        }
    }
    if (*attrDecl).def as libc::c_uint
        == XML_ATTRIBUTE_FIXED as libc::c_int as libc::c_uint
        && xmlStrEqual((*attrDecl).defaultValue, value) == 0
    {
        xmlErrValidNode(
            ctxt,
            elem,
            XML_DTD_ATTRIBUTE_VALUE,
            b"Value for attribute %s of %s must be \"%s\"\n\0" as *const u8
                as *const libc::c_char,
            (*attr).name,
            (*elem).name,
            (*attrDecl).defaultValue,
        );
        ret = 0 as libc::c_int;
    }
    ret &= xmlValidateAttributeValue2(ctxt, doc, (*attr).name, (*attrDecl).atype, value);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateOneNamespace(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
    mut prefix: *const xmlChar,
    mut ns: xmlNsPtr,
    mut value: *const xmlChar,
) -> libc::c_int {
    let mut attrDecl: xmlAttributePtr = 0 as xmlAttributePtr;
    let mut val: libc::c_int = 0;
    let mut ret: libc::c_int = 1 as libc::c_int;
    if doc.is_null() {
        return 0 as libc::c_int
    } else {
        if ((*doc).intSubset).is_null() && ((*doc).extSubset).is_null() {
            return 0 as libc::c_int;
        }
    }
    if elem.is_null() || ((*elem).name).is_null() {
        return 0 as libc::c_int;
    }
    if ns.is_null() || ((*ns).href).is_null() {
        return 0 as libc::c_int;
    }
    if !prefix.is_null() {
        let mut fn_0: [xmlChar; 50] = [0; 50];
        let mut fullname: *mut xmlChar = 0 as *mut xmlChar;
        fullname = xmlBuildQName(
            (*elem).name,
            prefix,
            fn_0.as_mut_ptr(),
            50 as libc::c_int,
        );
        if fullname.is_null() {
            xmlVErrMemory(
                ctxt,
                b"Validating namespace\0" as *const u8 as *const libc::c_char,
            );
            return 0 as libc::c_int;
        }
        if !((*ns).prefix).is_null() {
            attrDecl = xmlGetDtdQAttrDesc(
                (*doc).intSubset,
                fullname,
                (*ns).prefix,
                b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
            if attrDecl.is_null() && !((*doc).extSubset).is_null() {
                attrDecl = xmlGetDtdQAttrDesc(
                    (*doc).extSubset,
                    fullname,
                    (*ns).prefix,
                    b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                );
            }
        } else {
            attrDecl = xmlGetDtdAttrDesc(
                (*doc).intSubset,
                fullname,
                b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
            if attrDecl.is_null() && !((*doc).extSubset).is_null() {
                attrDecl = xmlGetDtdAttrDesc(
                    (*doc).extSubset,
                    fullname,
                    b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                );
            }
        }
        if fullname != fn_0.as_mut_ptr() && fullname != (*elem).name as *mut xmlChar {
            xmlFree.expect("non-null function pointer")(fullname as *mut libc::c_void);
        }
    }
    if attrDecl.is_null() {
        if !((*ns).prefix).is_null() {
            attrDecl = xmlGetDtdQAttrDesc(
                (*doc).intSubset,
                (*elem).name,
                (*ns).prefix,
                b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
            if attrDecl.is_null() && !((*doc).extSubset).is_null() {
                attrDecl = xmlGetDtdQAttrDesc(
                    (*doc).extSubset,
                    (*elem).name,
                    (*ns).prefix,
                    b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                );
            }
        } else {
            attrDecl = xmlGetDtdAttrDesc(
                (*doc).intSubset,
                (*elem).name,
                b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
            if attrDecl.is_null() && !((*doc).extSubset).is_null() {
                attrDecl = xmlGetDtdAttrDesc(
                    (*doc).extSubset,
                    (*elem).name,
                    b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                );
            }
        }
    }
    if attrDecl.is_null() {
        if !((*ns).prefix).is_null() {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_UNKNOWN_ATTRIBUTE,
                b"No declaration for attribute xmlns:%s of element %s\n\0" as *const u8
                    as *const libc::c_char,
                (*ns).prefix,
                (*elem).name,
                0 as *const xmlChar,
            );
        } else {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_UNKNOWN_ATTRIBUTE,
                b"No declaration for attribute xmlns of element %s\n\0" as *const u8
                    as *const libc::c_char,
                (*elem).name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        return 0 as libc::c_int;
    }
    val = xmlValidateAttributeValueInternal(doc, (*attrDecl).atype, value);
    if val == 0 as libc::c_int {
        if !((*ns).prefix).is_null() {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_INVALID_DEFAULT,
                b"Syntax of value for attribute xmlns:%s of %s is not valid\n\0"
                    as *const u8 as *const libc::c_char,
                (*ns).prefix,
                (*elem).name,
                0 as *const xmlChar,
            );
        } else {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_INVALID_DEFAULT,
                b"Syntax of value for attribute xmlns of %s is not valid\n\0"
                    as *const u8 as *const libc::c_char,
                (*elem).name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        ret = 0 as libc::c_int;
    }
    if (*attrDecl).def as libc::c_uint
        == XML_ATTRIBUTE_FIXED as libc::c_int as libc::c_uint
    {
        if xmlStrEqual(value, (*attrDecl).defaultValue) == 0 {
            if !((*ns).prefix).is_null() {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_ATTRIBUTE_DEFAULT,
                    b"Value for attribute xmlns:%s of %s is different from default \"%s\"\n\0"
                        as *const u8 as *const libc::c_char,
                    (*ns).prefix,
                    (*elem).name,
                    (*attrDecl).defaultValue,
                );
            } else {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_ATTRIBUTE_DEFAULT,
                    b"Value for attribute xmlns of %s is different from default \"%s\"\n\0"
                        as *const u8 as *const libc::c_char,
                    (*elem).name,
                    (*attrDecl).defaultValue,
                    0 as *const xmlChar,
                );
            }
            ret = 0 as libc::c_int;
        }
    }
    if (*attrDecl).atype as libc::c_uint
        == XML_ATTRIBUTE_NOTATION as libc::c_int as libc::c_uint
    {
        let mut tree: xmlEnumerationPtr = (*attrDecl).tree;
        let mut nota: xmlNotationPtr = 0 as *mut xmlNotation;
        nota = xmlGetDtdNotationDesc((*doc).intSubset, value);
        if nota.is_null() {
            nota = xmlGetDtdNotationDesc((*doc).extSubset, value);
        }
        if nota.is_null() {
            if !((*ns).prefix).is_null() {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_UNKNOWN_NOTATION,
                    b"Value \"%s\" for attribute xmlns:%s of %s is not a declared Notation\n\0"
                        as *const u8 as *const libc::c_char,
                    value,
                    (*ns).prefix,
                    (*elem).name,
                );
            } else {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_UNKNOWN_NOTATION,
                    b"Value \"%s\" for attribute xmlns of %s is not a declared Notation\n\0"
                        as *const u8 as *const libc::c_char,
                    value,
                    (*elem).name,
                    0 as *const xmlChar,
                );
            }
            ret = 0 as libc::c_int;
        }
        while !tree.is_null() {
            if xmlStrEqual((*tree).name, value) != 0 {
                break;
            }
            tree = (*tree).next;
        }
        if tree.is_null() {
            if !((*ns).prefix).is_null() {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_NOTATION_VALUE,
                    b"Value \"%s\" for attribute xmlns:%s of %s is not among the enumerated notations\n\0"
                        as *const u8 as *const libc::c_char,
                    value,
                    (*ns).prefix,
                    (*elem).name,
                );
            } else {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_NOTATION_VALUE,
                    b"Value \"%s\" for attribute xmlns of %s is not among the enumerated notations\n\0"
                        as *const u8 as *const libc::c_char,
                    value,
                    (*elem).name,
                    0 as *const xmlChar,
                );
            }
            ret = 0 as libc::c_int;
        }
    }
    if (*attrDecl).atype as libc::c_uint
        == XML_ATTRIBUTE_ENUMERATION as libc::c_int as libc::c_uint
    {
        let mut tree_0: xmlEnumerationPtr = (*attrDecl).tree;
        while !tree_0.is_null() {
            if xmlStrEqual((*tree_0).name, value) != 0 {
                break;
            }
            tree_0 = (*tree_0).next;
        }
        if tree_0.is_null() {
            if !((*ns).prefix).is_null() {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_ATTRIBUTE_VALUE,
                    b"Value \"%s\" for attribute xmlns:%s of %s is not among the enumerated set\n\0"
                        as *const u8 as *const libc::c_char,
                    value,
                    (*ns).prefix,
                    (*elem).name,
                );
            } else {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_ATTRIBUTE_VALUE,
                    b"Value \"%s\" for attribute xmlns of %s is not among the enumerated set\n\0"
                        as *const u8 as *const libc::c_char,
                    value,
                    (*elem).name,
                    0 as *const xmlChar,
                );
            }
            ret = 0 as libc::c_int;
        }
    }
    if (*attrDecl).def as libc::c_uint
        == XML_ATTRIBUTE_FIXED as libc::c_int as libc::c_uint
        && xmlStrEqual((*attrDecl).defaultValue, value) == 0
    {
        if !((*ns).prefix).is_null() {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_ELEM_NAMESPACE,
                b"Value for attribute xmlns:%s of %s must be \"%s\"\n\0" as *const u8
                    as *const libc::c_char,
                (*ns).prefix,
                (*elem).name,
                (*attrDecl).defaultValue,
            );
        } else {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_DTD_ELEM_NAMESPACE,
                b"Value for attribute xmlns of %s must be \"%s\"\n\0" as *const u8
                    as *const libc::c_char,
                (*elem).name,
                (*attrDecl).defaultValue,
                0 as *const xmlChar,
            );
        }
        ret = 0 as libc::c_int;
    }
    if !((*ns).prefix).is_null() {
        ret
            &= xmlValidateAttributeValue2(
                ctxt,
                doc,
                (*ns).prefix,
                (*attrDecl).atype,
                value,
            );
    } else {
        ret
            &= xmlValidateAttributeValue2(
                ctxt,
                doc,
                b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                (*attrDecl).atype,
                value,
            );
    }
    return ret;
}
unsafe extern "C" fn xmlSnprintfElements(
    mut buf: *mut libc::c_char,
    mut size: libc::c_int,
    mut node: xmlNodePtr,
    mut glob: libc::c_int,
) {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut len: libc::c_int = 0;
    if node.is_null() {
        return;
    }
    if glob != 0 {
        strcat(buf, b"(\0" as *const u8 as *const libc::c_char);
    }
    cur = node;
    while !cur.is_null() {
        len = strlen(buf) as libc::c_int;
        if size - len < 50 as libc::c_int {
            if size - len > 4 as libc::c_int
                && *buf.offset((len - 1 as libc::c_int) as isize) as libc::c_int
                    != '.' as i32
            {
                strcat(buf, b" ...\0" as *const u8 as *const libc::c_char);
            }
            return;
        }
        let mut current_block_33: u64;
        match (*cur).type_0 as libc::c_uint {
            1 => {
                if !((*cur).ns).is_null() && !((*(*cur).ns).prefix).is_null() {
                    if size - len < xmlStrlen((*(*cur).ns).prefix) + 10 as libc::c_int {
                        if size - len > 4 as libc::c_int
                            && *buf.offset((len - 1 as libc::c_int) as isize)
                                as libc::c_int != '.' as i32
                        {
                            strcat(buf, b" ...\0" as *const u8 as *const libc::c_char);
                        }
                        return;
                    }
                    strcat(buf, (*(*cur).ns).prefix as *mut libc::c_char);
                    strcat(buf, b":\0" as *const u8 as *const libc::c_char);
                }
                if size - len < xmlStrlen((*cur).name) + 10 as libc::c_int {
                    if size - len > 4 as libc::c_int
                        && *buf.offset((len - 1 as libc::c_int) as isize) as libc::c_int
                            != '.' as i32
                    {
                        strcat(buf, b" ...\0" as *const u8 as *const libc::c_char);
                    }
                    return;
                }
                strcat(buf, (*cur).name as *mut libc::c_char);
                if !((*cur).next).is_null() {
                    strcat(buf, b" \0" as *const u8 as *const libc::c_char);
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
                strcat(buf, b"???\0" as *const u8 as *const libc::c_char);
                if !((*cur).next).is_null() {
                    strcat(buf, b" \0" as *const u8 as *const libc::c_char);
                }
                current_block_33 = 572715077006366937;
            }
            6 | 7 | 14 | 8 | 15 | 16 | 17 | 19 | 20 | _ => {
                current_block_33 = 572715077006366937;
            }
        }
        match current_block_33 {
            17094473893460782832 => {
                strcat(buf, b"CDATA\0" as *const u8 as *const libc::c_char);
                if !((*cur).next).is_null() {
                    strcat(buf, b" \0" as *const u8 as *const libc::c_char);
                }
            }
            _ => {}
        }
        cur = (*cur).next;
    }
    if glob != 0 {
        strcat(buf, b")\0" as *const u8 as *const libc::c_char);
    }
}
unsafe extern "C" fn xmlValidateElementContent(
    mut ctxt: xmlValidCtxtPtr,
    mut child: xmlNodePtr,
    mut elemDecl: xmlElementPtr,
    mut warn: libc::c_int,
    mut parent: xmlNodePtr,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 1 as libc::c_int;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut cont: xmlElementContentPtr = 0 as *mut xmlElementContent;
    let mut name: *const xmlChar = 0 as *const xmlChar;
    if elemDecl.is_null() || parent.is_null() || ctxt.is_null() {
        return -(1 as libc::c_int);
    }
    cont = (*elemDecl).content;
    name = (*elemDecl).name;
    if ((*elemDecl).contModel).is_null() {
        ret = xmlValidBuildContentModel(ctxt, elemDecl);
    }
    if ((*elemDecl).contModel).is_null() {
        return -(1 as libc::c_int)
    } else {
        let mut exec: xmlRegExecCtxtPtr = 0 as *mut xmlRegExecCtxt;
        if xmlRegexpIsDeterminist((*elemDecl).contModel) == 0 {
            return -(1 as libc::c_int);
        }
        (*ctxt).nodeMax = 0 as libc::c_int;
        (*ctxt).nodeNr = 0 as libc::c_int;
        let ref mut fresh146 = (*ctxt).nodeTab;
        *fresh146 = 0 as *mut xmlNodePtr;
        exec = xmlRegNewExecCtxt((*elemDecl).contModel, None, 0 as *mut libc::c_void);
        if !exec.is_null() {
            cur = child;
            loop {
                if cur.is_null() {
                    current_block = 1345366029464561491;
                    break;
                }
                match (*cur).type_0 as libc::c_uint {
                    5 => {
                        if !((*cur).children).is_null()
                            && !((*(*cur).children).children).is_null()
                        {
                            nodeVPush(ctxt, cur);
                            cur = (*(*cur).children).children;
                            continue;
                        }
                    }
                    3 => {
                        if !(xmlIsBlankNode(cur as *const xmlNode) != 0) {
                            ret = 0 as libc::c_int;
                            current_block = 9694673564057544886;
                            break;
                        }
                    }
                    4 => {
                        ret = 0 as libc::c_int;
                        current_block = 9694673564057544886;
                        break;
                    }
                    1 => {
                        if !((*cur).ns).is_null() && !((*(*cur).ns).prefix).is_null() {
                            let mut fn_0: [xmlChar; 50] = [0; 50];
                            let mut fullname: *mut xmlChar = 0 as *mut xmlChar;
                            fullname = xmlBuildQName(
                                (*cur).name,
                                (*(*cur).ns).prefix,
                                fn_0.as_mut_ptr(),
                                50 as libc::c_int,
                            );
                            if fullname.is_null() {
                                ret = -(1 as libc::c_int);
                                current_block = 9694673564057544886;
                                break;
                            } else {
                                ret = xmlRegExecPushString(
                                    exec,
                                    fullname,
                                    0 as *mut libc::c_void,
                                );
                                if fullname != fn_0.as_mut_ptr()
                                    && fullname != (*cur).name as *mut xmlChar
                                {
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(fullname as *mut libc::c_void);
                                }
                            }
                        } else {
                            ret = xmlRegExecPushString(
                                exec,
                                (*cur).name,
                                0 as *mut libc::c_void,
                            );
                        }
                    }
                    _ => {}
                }
                cur = (*cur).next;
                while cur.is_null() {
                    cur = nodeVPop(ctxt);
                    if cur.is_null() {
                        break;
                    }
                    cur = (*cur).next;
                }
            }
            match current_block {
                1345366029464561491 => {
                    ret = xmlRegExecPushString(
                        exec,
                        0 as *const xmlChar,
                        0 as *mut libc::c_void,
                    );
                }
                _ => {}
            }
            xmlRegFreeExecCtxt(exec);
        }
        if warn != 0 && (ret != 1 as libc::c_int && ret != -(3 as libc::c_int)) {
            if !ctxt.is_null() {
                let mut expr: [libc::c_char; 5000] = [0; 5000];
                let mut list: [libc::c_char; 5000] = [0; 5000];
                expr[0 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
                xmlSnprintfElementContent(
                    &mut *expr.as_mut_ptr().offset(0 as libc::c_int as isize),
                    5000 as libc::c_int,
                    cont,
                    1 as libc::c_int,
                );
                list[0 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
                xmlSnprintfElements(
                    &mut *list.as_mut_ptr().offset(0 as libc::c_int as isize),
                    5000 as libc::c_int,
                    child,
                    1 as libc::c_int,
                );
                if !name.is_null() {
                    xmlErrValidNode(
                        ctxt,
                        parent,
                        XML_DTD_CONTENT_MODEL,
                        b"Element %s content does not follow the DTD, expecting %s, got %s\n\0"
                            as *const u8 as *const libc::c_char,
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
                            as *const u8 as *const libc::c_char,
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
                    b"Element %s content does not follow the DTD\n\0" as *const u8
                        as *const libc::c_char,
                    name,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
            } else {
                xmlErrValidNode(
                    ctxt,
                    parent,
                    XML_DTD_CONTENT_MODEL,
                    b"Element content does not follow the DTD\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
            }
            ret = 0 as libc::c_int;
        }
        if ret == -(3 as libc::c_int) {
            ret = 1 as libc::c_int;
        }
        (*ctxt).nodeMax = 0 as libc::c_int;
        (*ctxt).nodeNr = 0 as libc::c_int;
        if !((*ctxt).nodeTab).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).nodeTab as *mut libc::c_void);
            let ref mut fresh147 = (*ctxt).nodeTab;
            *fresh147 = 0 as *mut xmlNodePtr;
        }
        return ret;
    };
}
unsafe extern "C" fn xmlValidateOneCdataElement(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
) -> libc::c_int {
    let mut ret: libc::c_int = 1 as libc::c_int;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut child: xmlNodePtr = 0 as *mut xmlNode;
    if ctxt.is_null() || doc.is_null() || elem.is_null()
        || (*elem).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    child = (*elem).children;
    cur = child;
    while !cur.is_null() {
        match (*cur).type_0 as libc::c_uint {
            5 => {
                if !((*cur).children).is_null()
                    && !((*(*cur).children).children).is_null()
                {
                    nodeVPush(ctxt, cur);
                    cur = (*(*cur).children).children;
                    continue;
                }
            }
            8 | 7 | 3 | 4 => {}
            _ => {
                ret = 0 as libc::c_int;
                break;
            }
        }
        cur = (*cur).next;
        while cur.is_null() {
            cur = nodeVPop(ctxt);
            if cur.is_null() {
                break;
            }
            cur = (*cur).next;
        }
    }
    (*ctxt).nodeMax = 0 as libc::c_int;
    (*ctxt).nodeNr = 0 as libc::c_int;
    if !((*ctxt).nodeTab).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).nodeTab as *mut libc::c_void);
        let ref mut fresh148 = (*ctxt).nodeTab;
        *fresh148 = 0 as *mut xmlNodePtr;
    }
    return ret;
}
unsafe extern "C" fn xmlValidateCheckMixed(
    mut ctxt: xmlValidCtxtPtr,
    mut cont: xmlElementContentPtr,
    mut qname: *const xmlChar,
) -> libc::c_int {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut plen: libc::c_int = 0;
    name = xmlSplitQName3(qname, &mut plen);
    if name.is_null() {
        while !cont.is_null() {
            if (*cont).type_0 as libc::c_uint
                == XML_ELEMENT_CONTENT_ELEMENT as libc::c_int as libc::c_uint
            {
                if ((*cont).prefix).is_null() && xmlStrEqual((*cont).name, qname) != 0 {
                    return 1 as libc::c_int;
                }
            } else if (*cont).type_0 as libc::c_uint
                    == XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                    && !((*cont).c1).is_null()
                    && (*(*cont).c1).type_0 as libc::c_uint
                        == XML_ELEMENT_CONTENT_ELEMENT as libc::c_int as libc::c_uint
                {
                if ((*(*cont).c1).prefix).is_null()
                    && xmlStrEqual((*(*cont).c1).name, qname) != 0
                {
                    return 1 as libc::c_int;
                }
            } else if (*cont).type_0 as libc::c_uint
                    != XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                    || ((*cont).c1).is_null()
                    || (*(*cont).c1).type_0 as libc::c_uint
                        != XML_ELEMENT_CONTENT_PCDATA as libc::c_int as libc::c_uint
                {
                xmlErrValid(
                    0 as xmlValidCtxtPtr,
                    XML_DTD_MIXED_CORRUPT,
                    b"Internal: MIXED struct corrupted\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const libc::c_char,
                );
                break;
            }
            cont = (*cont).c2;
        }
    } else {
        while !cont.is_null() {
            if (*cont).type_0 as libc::c_uint
                == XML_ELEMENT_CONTENT_ELEMENT as libc::c_int as libc::c_uint
            {
                if !((*cont).prefix).is_null()
                    && xmlStrncmp((*cont).prefix, qname, plen) == 0 as libc::c_int
                    && xmlStrEqual((*cont).name, name) != 0
                {
                    return 1 as libc::c_int;
                }
            } else if (*cont).type_0 as libc::c_uint
                    == XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                    && !((*cont).c1).is_null()
                    && (*(*cont).c1).type_0 as libc::c_uint
                        == XML_ELEMENT_CONTENT_ELEMENT as libc::c_int as libc::c_uint
                {
                if !((*(*cont).c1).prefix).is_null()
                    && xmlStrncmp((*(*cont).c1).prefix, qname, plen) == 0 as libc::c_int
                    && xmlStrEqual((*(*cont).c1).name, name) != 0
                {
                    return 1 as libc::c_int;
                }
            } else if (*cont).type_0 as libc::c_uint
                    != XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                    || ((*cont).c1).is_null()
                    || (*(*cont).c1).type_0 as libc::c_uint
                        != XML_ELEMENT_CONTENT_PCDATA as libc::c_int as libc::c_uint
                {
                xmlErrValid(
                    ctxt,
                    XML_DTD_MIXED_CORRUPT,
                    b"Internal: MIXED struct corrupted\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const libc::c_char,
                );
                break;
            }
            cont = (*cont).c2;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlValidGetElemDecl(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
    mut extsubset: *mut libc::c_int,
) -> xmlElementPtr {
    let mut elemDecl: xmlElementPtr = 0 as xmlElementPtr;
    let mut prefix: *const xmlChar = 0 as *const xmlChar;
    if ctxt.is_null() || doc.is_null() || elem.is_null() || ((*elem).name).is_null() {
        return 0 as xmlElementPtr;
    }
    if !extsubset.is_null() {
        *extsubset = 0 as libc::c_int;
    }
    if !((*elem).ns).is_null() && !((*(*elem).ns).prefix).is_null() {
        prefix = (*(*elem).ns).prefix;
    }
    if !prefix.is_null() {
        elemDecl = xmlGetDtdQElementDesc((*doc).intSubset, (*elem).name, prefix);
        if elemDecl.is_null() && !((*doc).extSubset).is_null() {
            elemDecl = xmlGetDtdQElementDesc((*doc).extSubset, (*elem).name, prefix);
            if !elemDecl.is_null() && !extsubset.is_null() {
                *extsubset = 1 as libc::c_int;
            }
        }
    }
    if elemDecl.is_null() {
        elemDecl = xmlGetDtdElementDesc((*doc).intSubset, (*elem).name);
        if elemDecl.is_null() && !((*doc).extSubset).is_null() {
            elemDecl = xmlGetDtdElementDesc((*doc).extSubset, (*elem).name);
            if !elemDecl.is_null() && !extsubset.is_null() {
                *extsubset = 1 as libc::c_int;
            }
        }
    }
    if elemDecl.is_null() {
        xmlErrValidNode(
            ctxt,
            elem,
            XML_DTD_UNKNOWN_ELEM,
            b"No declaration for element %s\n\0" as *const u8 as *const libc::c_char,
            (*elem).name,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    }
    return elemDecl;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidatePushElement(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
    mut qname: *const xmlChar,
) -> libc::c_int {
    let mut ret: libc::c_int = 1 as libc::c_int;
    let mut eDecl: xmlElementPtr = 0 as *mut xmlElement;
    let mut extsubset: libc::c_int = 0 as libc::c_int;
    if ctxt.is_null() {
        return 0 as libc::c_int;
    }
    if (*ctxt).vstateNr > 0 as libc::c_int && !((*ctxt).vstate).is_null() {
        let mut state: xmlValidStatePtr = (*ctxt).vstate;
        let mut elemDecl: xmlElementPtr = 0 as *mut xmlElement;
        if !((*state).elemDecl).is_null() {
            elemDecl = (*state).elemDecl;
            match (*elemDecl).etype as libc::c_uint {
                0 => {
                    ret = 0 as libc::c_int;
                }
                1 => {
                    xmlErrValidNode(
                        ctxt,
                        (*state).node,
                        XML_DTD_NOT_EMPTY,
                        b"Element %s was declared EMPTY this one has content\n\0"
                            as *const u8 as *const libc::c_char,
                        (*(*state).node).name,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    ret = 0 as libc::c_int;
                }
                3 => {
                    if !((*elemDecl).content).is_null()
                        && (*(*elemDecl).content).type_0 as libc::c_uint
                            == XML_ELEMENT_CONTENT_PCDATA as libc::c_int as libc::c_uint
                    {
                        xmlErrValidNode(
                            ctxt,
                            (*state).node,
                            XML_DTD_NOT_PCDATA,
                            b"Element %s was declared #PCDATA but contains non text nodes\n\0"
                                as *const u8 as *const libc::c_char,
                            (*(*state).node).name,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                        ret = 0 as libc::c_int;
                    } else {
                        ret = xmlValidateCheckMixed(ctxt, (*elemDecl).content, qname);
                        if ret != 1 as libc::c_int {
                            xmlErrValidNode(
                                ctxt,
                                (*state).node,
                                XML_DTD_INVALID_CHILD,
                                b"Element %s is not declared in %s list of possible children\n\0"
                                    as *const u8 as *const libc::c_char,
                                qname,
                                (*(*state).node).name,
                                0 as *const xmlChar,
                            );
                        }
                    }
                }
                4 => {
                    if !((*state).exec).is_null() {
                        ret = xmlRegExecPushString(
                            (*state).exec,
                            qname,
                            0 as *mut libc::c_void,
                        );
                        if ret < 0 as libc::c_int {
                            xmlErrValidNode(
                                ctxt,
                                (*state).node,
                                XML_DTD_CONTENT_MODEL,
                                b"Element %s content does not follow the DTD, Misplaced %s\n\0"
                                    as *const u8 as *const libc::c_char,
                                (*(*state).node).name,
                                qname,
                                0 as *const xmlChar,
                            );
                            ret = 0 as libc::c_int;
                        } else {
                            ret = 1 as libc::c_int;
                        }
                    }
                }
                2 | _ => {}
            }
        }
    }
    eDecl = xmlValidGetElemDecl(ctxt, doc, elem, &mut extsubset);
    vstateVPush(ctxt, eDecl, elem);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidatePushCData(
    mut ctxt: xmlValidCtxtPtr,
    mut data: *const xmlChar,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 1 as libc::c_int;
    if ctxt.is_null() {
        return 0 as libc::c_int;
    }
    if len <= 0 as libc::c_int {
        return ret;
    }
    if (*ctxt).vstateNr > 0 as libc::c_int && !((*ctxt).vstate).is_null() {
        let mut state: xmlValidStatePtr = (*ctxt).vstate;
        let mut elemDecl: xmlElementPtr = 0 as *mut xmlElement;
        if !((*state).elemDecl).is_null() {
            elemDecl = (*state).elemDecl;
            match (*elemDecl).etype as libc::c_uint {
                0 => {
                    current_block = 8999518187244832834;
                    match current_block {
                        8999518187244832834 => {
                            ret = 0 as libc::c_int;
                        }
                        10599921512955367680 => {
                            let mut i: libc::c_int = 0;
                            i = 0 as libc::c_int;
                            while i < len {
                                if !(*data.offset(i as isize) as libc::c_int
                                    == 0x20 as libc::c_int
                                    || 0x9 as libc::c_int
                                        <= *data.offset(i as isize) as libc::c_int
                                        && *data.offset(i as isize) as libc::c_int
                                            <= 0xa as libc::c_int
                                    || *data.offset(i as isize) as libc::c_int
                                        == 0xd as libc::c_int)
                                {
                                    xmlErrValidNode(
                                        ctxt,
                                        (*state).node,
                                        XML_DTD_CONTENT_MODEL,
                                        b"Element %s content does not follow the DTD, Text not allowed\n\0"
                                            as *const u8 as *const libc::c_char,
                                        (*(*state).node).name,
                                        0 as *const xmlChar,
                                        0 as *const xmlChar,
                                    );
                                    ret = 0 as libc::c_int;
                                    break;
                                } else {
                                    i += 1;
                                }
                            }
                        }
                        _ => {
                            xmlErrValidNode(
                                ctxt,
                                (*state).node,
                                XML_DTD_NOT_EMPTY,
                                b"Element %s was declared EMPTY this one has content\n\0"
                                    as *const u8 as *const libc::c_char,
                                (*(*state).node).name,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                            );
                            ret = 0 as libc::c_int;
                        }
                    }
                }
                1 => {
                    current_block = 11090157271596910899;
                    match current_block {
                        8999518187244832834 => {
                            ret = 0 as libc::c_int;
                        }
                        10599921512955367680 => {
                            let mut i: libc::c_int = 0;
                            i = 0 as libc::c_int;
                            while i < len {
                                if !(*data.offset(i as isize) as libc::c_int
                                    == 0x20 as libc::c_int
                                    || 0x9 as libc::c_int
                                        <= *data.offset(i as isize) as libc::c_int
                                        && *data.offset(i as isize) as libc::c_int
                                            <= 0xa as libc::c_int
                                    || *data.offset(i as isize) as libc::c_int
                                        == 0xd as libc::c_int)
                                {
                                    xmlErrValidNode(
                                        ctxt,
                                        (*state).node,
                                        XML_DTD_CONTENT_MODEL,
                                        b"Element %s content does not follow the DTD, Text not allowed\n\0"
                                            as *const u8 as *const libc::c_char,
                                        (*(*state).node).name,
                                        0 as *const xmlChar,
                                        0 as *const xmlChar,
                                    );
                                    ret = 0 as libc::c_int;
                                    break;
                                } else {
                                    i += 1;
                                }
                            }
                        }
                        _ => {
                            xmlErrValidNode(
                                ctxt,
                                (*state).node,
                                XML_DTD_NOT_EMPTY,
                                b"Element %s was declared EMPTY this one has content\n\0"
                                    as *const u8 as *const libc::c_char,
                                (*(*state).node).name,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                            );
                            ret = 0 as libc::c_int;
                        }
                    }
                }
                4 => {
                    current_block = 10599921512955367680;
                    match current_block {
                        8999518187244832834 => {
                            ret = 0 as libc::c_int;
                        }
                        10599921512955367680 => {
                            let mut i: libc::c_int = 0;
                            i = 0 as libc::c_int;
                            while i < len {
                                if !(*data.offset(i as isize) as libc::c_int
                                    == 0x20 as libc::c_int
                                    || 0x9 as libc::c_int
                                        <= *data.offset(i as isize) as libc::c_int
                                        && *data.offset(i as isize) as libc::c_int
                                            <= 0xa as libc::c_int
                                    || *data.offset(i as isize) as libc::c_int
                                        == 0xd as libc::c_int)
                                {
                                    xmlErrValidNode(
                                        ctxt,
                                        (*state).node,
                                        XML_DTD_CONTENT_MODEL,
                                        b"Element %s content does not follow the DTD, Text not allowed\n\0"
                                            as *const u8 as *const libc::c_char,
                                        (*(*state).node).name,
                                        0 as *const xmlChar,
                                        0 as *const xmlChar,
                                    );
                                    ret = 0 as libc::c_int;
                                    break;
                                } else {
                                    i += 1;
                                }
                            }
                        }
                        _ => {
                            xmlErrValidNode(
                                ctxt,
                                (*state).node,
                                XML_DTD_NOT_EMPTY,
                                b"Element %s was declared EMPTY this one has content\n\0"
                                    as *const u8 as *const libc::c_char,
                                (*(*state).node).name,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                            );
                            ret = 0 as libc::c_int;
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
pub unsafe extern "C" fn xmlValidatePopElement(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
    mut qname: *const xmlChar,
) -> libc::c_int {
    let mut ret: libc::c_int = 1 as libc::c_int;
    if ctxt.is_null() {
        return 0 as libc::c_int;
    }
    if (*ctxt).vstateNr > 0 as libc::c_int && !((*ctxt).vstate).is_null() {
        let mut state: xmlValidStatePtr = (*ctxt).vstate;
        let mut elemDecl: xmlElementPtr = 0 as *mut xmlElement;
        if !((*state).elemDecl).is_null() {
            elemDecl = (*state).elemDecl;
            if (*elemDecl).etype as libc::c_uint
                == XML_ELEMENT_TYPE_ELEMENT as libc::c_int as libc::c_uint
            {
                if !((*state).exec).is_null() {
                    ret = xmlRegExecPushString(
                        (*state).exec,
                        0 as *const xmlChar,
                        0 as *mut libc::c_void,
                    );
                    if ret == 0 as libc::c_int {
                        xmlErrValidNode(
                            ctxt,
                            (*state).node,
                            XML_DTD_CONTENT_MODEL,
                            b"Element %s content does not follow the DTD, Expecting more child\n\0"
                                as *const u8 as *const libc::c_char,
                            (*(*state).node).name,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                    } else {
                        ret = 1 as libc::c_int;
                    }
                }
            }
        }
        vstateVPop(ctxt);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateOneElement(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
) -> libc::c_int {
    let mut current_block: u64;
    let mut elemDecl: xmlElementPtr = 0 as xmlElementPtr;
    let mut cont: xmlElementContentPtr = 0 as *mut xmlElementContent;
    let mut attr: xmlAttributePtr = 0 as *mut xmlAttribute;
    let mut child: xmlNodePtr = 0 as *mut xmlNode;
    let mut ret: libc::c_int = 1 as libc::c_int;
    let mut tmp: libc::c_int = 0;
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut extsubset: libc::c_int = 0 as libc::c_int;
    if doc.is_null() {
        return 0 as libc::c_int
    } else {
        if ((*doc).intSubset).is_null() && ((*doc).extSubset).is_null() {
            return 0 as libc::c_int;
        }
    }
    if elem.is_null() {
        return 0 as libc::c_int;
    }
    match (*elem).type_0 as libc::c_uint {
        2 => {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_ERR_INTERNAL_ERROR,
                b"Attribute element not expected\n\0" as *const u8
                    as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as libc::c_int;
        }
        3 => {
            if !((*elem).children).is_null() {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_ERR_INTERNAL_ERROR,
                    b"Text element has children !\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                return 0 as libc::c_int;
            }
            if !((*elem).ns).is_null() {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_ERR_INTERNAL_ERROR,
                    b"Text element has namespace !\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                return 0 as libc::c_int;
            }
            if ((*elem).content).is_null() {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_ERR_INTERNAL_ERROR,
                    b"Text element has no content !\n\0" as *const u8
                        as *const libc::c_char,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                return 0 as libc::c_int;
            }
            return 1 as libc::c_int;
        }
        19 | 20 => return 1 as libc::c_int,
        4 | 5 | 7 | 8 => return 1 as libc::c_int,
        6 => {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_ERR_INTERNAL_ERROR,
                b"Entity element not expected\n\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as libc::c_int;
        }
        12 => {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_ERR_INTERNAL_ERROR,
                b"Notation element not expected\n\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as libc::c_int;
        }
        9 | 10 | 11 => {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_ERR_INTERNAL_ERROR,
                b"Document element not expected\n\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as libc::c_int;
        }
        13 => {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_ERR_INTERNAL_ERROR,
                b"HTML Document not expected\n\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as libc::c_int;
        }
        1 => {}
        _ => {
            xmlErrValidNode(
                ctxt,
                elem,
                XML_ERR_INTERNAL_ERROR,
                b"unknown element type\n\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as libc::c_int;
        }
    }
    elemDecl = xmlValidGetElemDecl(ctxt, doc, elem, &mut extsubset);
    if elemDecl.is_null() {
        return 0 as libc::c_int;
    }
    if (*ctxt).vstateNr == 0 as libc::c_int {
        match (*elemDecl).etype as libc::c_uint {
            0 => {
                xmlErrValidNode(
                    ctxt,
                    elem,
                    XML_DTD_UNKNOWN_ELEM,
                    b"No declaration for element %s\n\0" as *const u8
                        as *const libc::c_char,
                    (*elem).name,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                return 0 as libc::c_int;
            }
            1 => {
                if !((*elem).children).is_null() {
                    xmlErrValidNode(
                        ctxt,
                        elem,
                        XML_DTD_NOT_EMPTY,
                        b"Element %s was declared EMPTY this one has content\n\0"
                            as *const u8 as *const libc::c_char,
                        (*elem).name,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    ret = 0 as libc::c_int;
                }
            }
            3 => {
                if !((*elemDecl).content).is_null()
                    && (*(*elemDecl).content).type_0 as libc::c_uint
                        == XML_ELEMENT_CONTENT_PCDATA as libc::c_int as libc::c_uint
                {
                    ret = xmlValidateOneCdataElement(ctxt, doc, elem);
                    if ret == 0 {
                        xmlErrValidNode(
                            ctxt,
                            elem,
                            XML_DTD_NOT_PCDATA,
                            b"Element %s was declared #PCDATA but contains non text nodes\n\0"
                                as *const u8 as *const libc::c_char,
                            (*elem).name,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                    }
                } else {
                    child = (*elem).children;
                    while !child.is_null() {
                        let mut current_block_66: u64;
                        if (*child).type_0 as libc::c_uint
                            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                        {
                            name = (*child).name;
                            if !((*child).ns).is_null()
                                && !((*(*child).ns).prefix).is_null()
                            {
                                let mut fn_0: [xmlChar; 50] = [0; 50];
                                let mut fullname: *mut xmlChar = 0 as *mut xmlChar;
                                fullname = xmlBuildQName(
                                    (*child).name,
                                    (*(*child).ns).prefix,
                                    fn_0.as_mut_ptr(),
                                    50 as libc::c_int,
                                );
                                if fullname.is_null() {
                                    return 0 as libc::c_int;
                                }
                                cont = (*elemDecl).content;
                                while !cont.is_null() {
                                    if (*cont).type_0 as libc::c_uint
                                        == XML_ELEMENT_CONTENT_ELEMENT as libc::c_int
                                            as libc::c_uint
                                    {
                                        if xmlStrEqual((*cont).name, fullname) != 0 {
                                            break;
                                        }
                                    } else if (*cont).type_0 as libc::c_uint
                                            == XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                                            && !((*cont).c1).is_null()
                                            && (*(*cont).c1).type_0 as libc::c_uint
                                                == XML_ELEMENT_CONTENT_ELEMENT as libc::c_int
                                                    as libc::c_uint
                                        {
                                        if xmlStrEqual((*(*cont).c1).name, fullname) != 0 {
                                            break;
                                        }
                                    } else if (*cont).type_0 as libc::c_uint
                                            != XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                                            || ((*cont).c1).is_null()
                                            || (*(*cont).c1).type_0 as libc::c_uint
                                                != XML_ELEMENT_CONTENT_PCDATA as libc::c_int as libc::c_uint
                                        {
                                        xmlErrValid(
                                            0 as xmlValidCtxtPtr,
                                            XML_DTD_MIXED_CORRUPT,
                                            b"Internal: MIXED struct corrupted\n\0" as *const u8
                                                as *const libc::c_char,
                                            0 as *const libc::c_char,
                                        );
                                        break;
                                    }
                                    cont = (*cont).c2;
                                }
                                if fullname != fn_0.as_mut_ptr()
                                    && fullname != (*child).name as *mut xmlChar
                                {
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(fullname as *mut libc::c_void);
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
                                    cont = (*elemDecl).content;
                                    while !cont.is_null() {
                                        if (*cont).type_0 as libc::c_uint
                                            == XML_ELEMENT_CONTENT_ELEMENT as libc::c_int
                                                as libc::c_uint
                                        {
                                            if xmlStrEqual((*cont).name, name) != 0 {
                                                break;
                                            }
                                        } else if (*cont).type_0 as libc::c_uint
                                                == XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                                                && !((*cont).c1).is_null()
                                                && (*(*cont).c1).type_0 as libc::c_uint
                                                    == XML_ELEMENT_CONTENT_ELEMENT as libc::c_int
                                                        as libc::c_uint
                                            {
                                            if xmlStrEqual((*(*cont).c1).name, name) != 0 {
                                                break;
                                            }
                                        } else if (*cont).type_0 as libc::c_uint
                                                != XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
                                                || ((*cont).c1).is_null()
                                                || (*(*cont).c1).type_0 as libc::c_uint
                                                    != XML_ELEMENT_CONTENT_PCDATA as libc::c_int as libc::c_uint
                                            {
                                            xmlErrValid(
                                                ctxt,
                                                XML_DTD_MIXED_CORRUPT,
                                                b"Internal: MIXED struct corrupted\n\0" as *const u8
                                                    as *const libc::c_char,
                                                0 as *const libc::c_char,
                                            );
                                            break;
                                        }
                                        cont = (*cont).c2;
                                    }
                                    if cont.is_null() {
                                        xmlErrValidNode(
                                            ctxt,
                                            elem,
                                            XML_DTD_INVALID_CHILD,
                                            b"Element %s is not declared in %s list of possible children\n\0"
                                                as *const u8 as *const libc::c_char,
                                            name,
                                            (*elem).name,
                                            0 as *const xmlChar,
                                        );
                                        ret = 0 as libc::c_int;
                                    }
                                }
                            }
                        }
                        child = (*child).next;
                    }
                }
            }
            4 => {
                if (*doc).standalone == 1 as libc::c_int && extsubset == 1 as libc::c_int
                {
                    child = (*elem).children;
                    while !child.is_null() {
                        if (*child).type_0 as libc::c_uint
                            == XML_TEXT_NODE as libc::c_int as libc::c_uint
                        {
                            let mut content: *const xmlChar = (*child).content;
                            while *content as libc::c_int == 0x20 as libc::c_int
                                || 0x9 as libc::c_int <= *content as libc::c_int
                                    && *content as libc::c_int <= 0xa as libc::c_int
                                || *content as libc::c_int == 0xd as libc::c_int
                            {
                                content = content.offset(1);
                            }
                            if *content as libc::c_int == 0 as libc::c_int {
                                xmlErrValidNode(
                                    ctxt,
                                    elem,
                                    XML_DTD_STANDALONE_WHITE_SPACE,
                                    b"standalone: %s declared in the external subset contains white spaces nodes\n\0"
                                        as *const u8 as *const libc::c_char,
                                    (*elem).name,
                                    0 as *const xmlChar,
                                    0 as *const xmlChar,
                                );
                                ret = 0 as libc::c_int;
                                break;
                            }
                        }
                        child = (*child).next;
                    }
                }
                child = (*elem).children;
                cont = (*elemDecl).content;
                tmp = xmlValidateElementContent(
                    ctxt,
                    child,
                    elemDecl,
                    1 as libc::c_int,
                    elem,
                );
                if tmp <= 0 as libc::c_int {
                    ret = tmp;
                }
            }
            2 | _ => {}
        }
    }
    attr = (*elemDecl).attributes;
    while !attr.is_null() {
        if (*attr).def as libc::c_uint
            == XML_ATTRIBUTE_REQUIRED as libc::c_int as libc::c_uint
        {
            let mut qualified: libc::c_int = -(1 as libc::c_int);
            if ((*attr).prefix).is_null()
                && xmlStrEqual(
                    (*attr).name,
                    b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) != 0
            {
                let mut ns: xmlNsPtr = 0 as *mut xmlNs;
                ns = (*elem).nsDef;
                loop {
                    if ns.is_null() {
                        current_block = 14184516523743666873;
                        break;
                    }
                    if ((*ns).prefix).is_null() {
                        current_block = 10877472729522060806;
                        break;
                    }
                    ns = (*ns).next;
                }
            } else if xmlStrEqual(
                    (*attr).prefix,
                    b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) != 0
                {
                let mut ns_0: xmlNsPtr = 0 as *mut xmlNs;
                ns_0 = (*elem).nsDef;
                loop {
                    if ns_0.is_null() {
                        current_block = 14184516523743666873;
                        break;
                    }
                    if xmlStrEqual((*attr).name, (*ns_0).prefix) != 0 {
                        current_block = 10877472729522060806;
                        break;
                    }
                    ns_0 = (*ns_0).next;
                }
            } else {
                let mut attrib: xmlAttrPtr = 0 as *mut xmlAttr;
                attrib = (*elem).properties;
                loop {
                    if attrib.is_null() {
                        current_block = 14184516523743666873;
                        break;
                    }
                    if xmlStrEqual((*attrib).name, (*attr).name) != 0 {
                        if ((*attr).prefix).is_null() {
                            current_block = 10877472729522060806;
                            break;
                        }
                        let mut nameSpace: xmlNsPtr = (*attrib).ns;
                        if nameSpace.is_null() {
                            nameSpace = (*elem).ns;
                        }
                        if nameSpace.is_null() {
                            if qualified < 0 as libc::c_int {
                                qualified = 0 as libc::c_int;
                            }
                        } else {
                            if !(xmlStrEqual((*nameSpace).prefix, (*attr).prefix) == 0) {
                                current_block = 10877472729522060806;
                                break;
                            }
                            if qualified < 1 as libc::c_int {
                                qualified = 1 as libc::c_int;
                            }
                        }
                    }
                    attrib = (*attrib).next;
                }
            }
            match current_block {
                10877472729522060806 => {}
                _ => {
                    if qualified == -(1 as libc::c_int) {
                        if ((*attr).prefix).is_null() {
                            xmlErrValidNode(
                                ctxt,
                                elem,
                                XML_DTD_MISSING_ATTRIBUTE,
                                b"Element %s does not carry attribute %s\n\0" as *const u8
                                    as *const libc::c_char,
                                (*elem).name,
                                (*attr).name,
                                0 as *const xmlChar,
                            );
                            ret = 0 as libc::c_int;
                        } else {
                            xmlErrValidNode(
                                ctxt,
                                elem,
                                XML_DTD_MISSING_ATTRIBUTE,
                                b"Element %s does not carry attribute %s:%s\n\0"
                                    as *const u8 as *const libc::c_char,
                                (*elem).name,
                                (*attr).prefix,
                                (*attr).name,
                            );
                            ret = 0 as libc::c_int;
                        }
                    } else if qualified == 0 as libc::c_int {
                        xmlErrValidWarning(
                            ctxt,
                            elem,
                            XML_DTD_NO_PREFIX,
                            b"Element %s required attribute %s:%s has no prefix\n\0"
                                as *const u8 as *const libc::c_char,
                            (*elem).name,
                            (*attr).prefix,
                            (*attr).name,
                        );
                    } else if qualified == 1 as libc::c_int {
                        xmlErrValidWarning(
                            ctxt,
                            elem,
                            XML_DTD_DIFFERENT_PREFIX,
                            b"Element %s required attribute %s:%s has different prefix\n\0"
                                as *const u8 as *const libc::c_char,
                            (*elem).name,
                            (*attr).prefix,
                            (*attr).name,
                        );
                    }
                }
            }
        } else if (*attr).def as libc::c_uint
                == XML_ATTRIBUTE_FIXED as libc::c_int as libc::c_uint
            {
            if ((*attr).prefix).is_null()
                && xmlStrEqual(
                    (*attr).name,
                    b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) != 0
            {
                let mut ns_1: xmlNsPtr = 0 as *mut xmlNs;
                ns_1 = (*elem).nsDef;
                while !ns_1.is_null() {
                    if ((*ns_1).prefix).is_null() {
                        if xmlStrEqual((*attr).defaultValue, (*ns_1).href) == 0 {
                            xmlErrValidNode(
                                ctxt,
                                elem,
                                XML_DTD_ELEM_DEFAULT_NAMESPACE,
                                b"Element %s namespace name for default namespace does not match the DTD\n\0"
                                    as *const u8 as *const libc::c_char,
                                (*elem).name,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                            );
                            ret = 0 as libc::c_int;
                        }
                        break;
                    } else {
                        ns_1 = (*ns_1).next;
                    }
                }
            } else if xmlStrEqual(
                    (*attr).prefix,
                    b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) != 0
                {
                let mut ns_2: xmlNsPtr = 0 as *mut xmlNs;
                ns_2 = (*elem).nsDef;
                while !ns_2.is_null() {
                    if xmlStrEqual((*attr).name, (*ns_2).prefix) != 0 {
                        if xmlStrEqual((*attr).defaultValue, (*ns_2).href) == 0 {
                            xmlErrValidNode(
                                ctxt,
                                elem,
                                XML_DTD_ELEM_NAMESPACE,
                                b"Element %s namespace name for %s does not match the DTD\n\0"
                                    as *const u8 as *const libc::c_char,
                                (*elem).name,
                                (*ns_2).prefix,
                                0 as *const xmlChar,
                            );
                            ret = 0 as libc::c_int;
                        }
                        break;
                    } else {
                        ns_2 = (*ns_2).next;
                    }
                }
            }
        }
        attr = (*attr).nexth;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateRoot(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
) -> libc::c_int {
    let mut current_block: u64;
    let mut root: xmlNodePtr = 0 as *mut xmlNode;
    let mut ret: libc::c_int = 0;
    if doc.is_null() {
        return 0 as libc::c_int;
    }
    root = xmlDocGetRootElement(doc as *const xmlDoc);
    if root.is_null() || ((*root).name).is_null() {
        xmlErrValid(
            ctxt,
            XML_DTD_NO_ROOT,
            b"no root element\n\0" as *const u8 as *const libc::c_char,
            0 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if !((*doc).intSubset).is_null() && !((*(*doc).intSubset).name).is_null() {
        if xmlStrEqual((*(*doc).intSubset).name, (*root).name) == 0 {
            if !((*root).ns).is_null() && !((*(*root).ns).prefix).is_null() {
                let mut fn_0: [xmlChar; 50] = [0; 50];
                let mut fullname: *mut xmlChar = 0 as *mut xmlChar;
                fullname = xmlBuildQName(
                    (*root).name,
                    (*(*root).ns).prefix,
                    fn_0.as_mut_ptr(),
                    50 as libc::c_int,
                );
                if fullname.is_null() {
                    xmlVErrMemory(ctxt, 0 as *const libc::c_char);
                    return 0 as libc::c_int;
                }
                ret = xmlStrEqual((*(*doc).intSubset).name, fullname);
                if fullname != fn_0.as_mut_ptr()
                    && fullname != (*root).name as *mut xmlChar
                {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(fullname as *mut libc::c_void);
                }
                if ret == 1 as libc::c_int {
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
                        (*(*doc).intSubset).name,
                        b"HTML\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    ) != 0
                        && xmlStrEqual(
                            (*root).name,
                            b"html\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                        ) != 0)
                    {
                        xmlErrValidNode(
                            ctxt,
                            root,
                            XML_DTD_ROOT_NAME,
                            b"root and DTD name do not match '%s' and '%s'\n\0"
                                as *const u8 as *const libc::c_char,
                            (*root).name,
                            (*(*doc).intSubset).name,
                            0 as *const xmlChar,
                        );
                        return 0 as libc::c_int;
                    }
                }
            }
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateElement(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut elem: xmlNodePtr,
) -> libc::c_int {
    let mut child: xmlNodePtr = 0 as *mut xmlNode;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut value: *const xmlChar = 0 as *const xmlChar;
    let mut ret: libc::c_int = 1 as libc::c_int;
    if elem.is_null() {
        return 0 as libc::c_int;
    }
    if (*elem).type_0 as libc::c_uint
        == XML_XINCLUDE_START as libc::c_int as libc::c_uint
        || (*elem).type_0 as libc::c_uint
            == XML_XINCLUDE_END as libc::c_int as libc::c_uint
        || (*elem).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
    {
        return 1 as libc::c_int;
    }
    if doc.is_null() {
        return 0 as libc::c_int
    } else {
        if ((*doc).intSubset).is_null() && ((*doc).extSubset).is_null() {
            return 0 as libc::c_int;
        }
    }
    if (*elem).type_0 as libc::c_uint
        == XML_ENTITY_REF_NODE as libc::c_int as libc::c_uint
    {
        return 1 as libc::c_int;
    }
    ret &= xmlValidateOneElement(ctxt, doc, elem);
    if (*elem).type_0 as libc::c_uint == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        attr = (*elem).properties;
        while !attr.is_null() {
            value = xmlNodeListGetString(doc, (*attr).children, 0 as libc::c_int);
            ret &= xmlValidateOneAttribute(ctxt, doc, elem, attr, value);
            if !value.is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(value as *mut libc::c_char as *mut libc::c_void);
            }
            attr = (*attr).next;
        }
        ns = (*elem).nsDef;
        while !ns.is_null() {
            if ((*elem).ns).is_null() {
                ret
                    &= xmlValidateOneNamespace(
                        ctxt,
                        doc,
                        elem,
                        0 as *const xmlChar,
                        ns,
                        (*ns).href,
                    );
            } else {
                ret
                    &= xmlValidateOneNamespace(
                        ctxt,
                        doc,
                        elem,
                        (*(*elem).ns).prefix,
                        ns,
                        (*ns).href,
                    );
            }
            ns = (*ns).next;
        }
    }
    child = (*elem).children;
    while !child.is_null() {
        ret &= xmlValidateElement(ctxt, doc, child);
        child = (*child).next;
    }
    return ret;
}
unsafe extern "C" fn xmlValidateRef(
    mut ref_0: xmlRefPtr,
    mut ctxt: xmlValidCtxtPtr,
    mut name: *const xmlChar,
) {
    let mut id: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    if ref_0.is_null() {
        return;
    }
    if ((*ref_0).attr).is_null() && ((*ref_0).name).is_null() {
        return;
    }
    attr = (*ref_0).attr;
    if attr.is_null() {
        let mut dup: *mut xmlChar = 0 as *mut xmlChar;
        let mut str: *mut xmlChar = 0 as *mut xmlChar;
        let mut cur: *mut xmlChar = 0 as *mut xmlChar;
        let mut save: xmlChar = 0;
        dup = xmlStrdup(name);
        if dup.is_null() {
            (*ctxt).valid = 0 as libc::c_int;
            return;
        }
        cur = dup;
        while *cur as libc::c_int != 0 as libc::c_int {
            str = cur;
            while *cur as libc::c_int != 0 as libc::c_int
                && !(*cur as libc::c_int == 0x20 as libc::c_int
                    || 0x9 as libc::c_int <= *cur as libc::c_int
                        && *cur as libc::c_int <= 0xa as libc::c_int
                    || *cur as libc::c_int == 0xd as libc::c_int)
            {
                cur = cur.offset(1);
            }
            save = *cur;
            *cur = 0 as libc::c_int as xmlChar;
            id = xmlGetID((*ctxt).doc, str);
            if id.is_null() {
                xmlErrValidNodeNr(
                    ctxt,
                    0 as xmlNodePtr,
                    XML_DTD_UNKNOWN_ID,
                    b"attribute %s line %d references an unknown ID \"%s\"\n\0"
                        as *const u8 as *const libc::c_char,
                    (*ref_0).name,
                    (*ref_0).lineno,
                    str,
                );
                (*ctxt).valid = 0 as libc::c_int;
            }
            if save as libc::c_int == 0 as libc::c_int {
                break;
            }
            *cur = save;
            while *cur as libc::c_int == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= *cur as libc::c_int
                    && *cur as libc::c_int <= 0xa as libc::c_int
                || *cur as libc::c_int == 0xd as libc::c_int
            {
                cur = cur.offset(1);
            }
        }
        xmlFree.expect("non-null function pointer")(dup as *mut libc::c_void);
    } else if (*attr).atype as libc::c_uint
            == XML_ATTRIBUTE_IDREF as libc::c_int as libc::c_uint
        {
        id = xmlGetID((*ctxt).doc, name);
        if id.is_null() {
            xmlErrValidNode(
                ctxt,
                (*attr).parent,
                XML_DTD_UNKNOWN_ID,
                b"IDREF attribute %s references an unknown ID \"%s\"\n\0" as *const u8
                    as *const libc::c_char,
                (*attr).name,
                name,
                0 as *const xmlChar,
            );
            (*ctxt).valid = 0 as libc::c_int;
        }
    } else if (*attr).atype as libc::c_uint
            == XML_ATTRIBUTE_IDREFS as libc::c_int as libc::c_uint
        {
        let mut dup_0: *mut xmlChar = 0 as *mut xmlChar;
        let mut str_0: *mut xmlChar = 0 as *mut xmlChar;
        let mut cur_0: *mut xmlChar = 0 as *mut xmlChar;
        let mut save_0: xmlChar = 0;
        dup_0 = xmlStrdup(name);
        if dup_0.is_null() {
            xmlVErrMemory(ctxt, b"IDREFS split\0" as *const u8 as *const libc::c_char);
            (*ctxt).valid = 0 as libc::c_int;
            return;
        }
        cur_0 = dup_0;
        while *cur_0 as libc::c_int != 0 as libc::c_int {
            str_0 = cur_0;
            while *cur_0 as libc::c_int != 0 as libc::c_int
                && !(*cur_0 as libc::c_int == 0x20 as libc::c_int
                    || 0x9 as libc::c_int <= *cur_0 as libc::c_int
                        && *cur_0 as libc::c_int <= 0xa as libc::c_int
                    || *cur_0 as libc::c_int == 0xd as libc::c_int)
            {
                cur_0 = cur_0.offset(1);
            }
            save_0 = *cur_0;
            *cur_0 = 0 as libc::c_int as xmlChar;
            id = xmlGetID((*ctxt).doc, str_0);
            if id.is_null() {
                xmlErrValidNode(
                    ctxt,
                    (*attr).parent,
                    XML_DTD_UNKNOWN_ID,
                    b"IDREFS attribute %s references an unknown ID \"%s\"\n\0"
                        as *const u8 as *const libc::c_char,
                    (*attr).name,
                    str_0,
                    0 as *const xmlChar,
                );
                (*ctxt).valid = 0 as libc::c_int;
            }
            if save_0 as libc::c_int == 0 as libc::c_int {
                break;
            }
            *cur_0 = save_0;
            while *cur_0 as libc::c_int == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= *cur_0 as libc::c_int
                    && *cur_0 as libc::c_int <= 0xa as libc::c_int
                || *cur_0 as libc::c_int == 0xd as libc::c_int
            {
                cur_0 = cur_0.offset(1);
            }
        }
        xmlFree.expect("non-null function pointer")(dup_0 as *mut libc::c_void);
    }
}
unsafe extern "C" fn xmlWalkValidateList(
    mut data: *const libc::c_void,
    mut user: *mut libc::c_void,
) -> libc::c_int {
    let mut memo: xmlValidateMemoPtr = user as xmlValidateMemoPtr;
    xmlValidateRef(data as xmlRefPtr, (*memo).ctxt, (*memo).name);
    return 1 as libc::c_int;
}
unsafe extern "C" fn xmlValidateCheckRefCallback(
    mut payload: *mut libc::c_void,
    mut data: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    let mut ref_list: xmlListPtr = payload as xmlListPtr;
    let mut ctxt: xmlValidCtxtPtr = data as xmlValidCtxtPtr;
    let mut memo: xmlValidateMemo = xmlValidateMemo {
        ctxt: 0 as *mut xmlValidCtxt,
        name: 0 as *const xmlChar,
    };
    if ref_list.is_null() {
        return;
    }
    memo.ctxt = ctxt;
    memo.name = name;
    xmlListWalk(
        ref_list,
        Some(
            xmlWalkValidateList
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut libc::c_void,
                ) -> libc::c_int,
        ),
        &mut memo as *mut xmlValidateMemo as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateDocumentFinal(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
) -> libc::c_int {
    let mut table: xmlRefTablePtr = 0 as *mut xmlRefTable;
    let mut save: libc::c_uint = 0;
    if ctxt.is_null() {
        return 0 as libc::c_int;
    }
    if doc.is_null() {
        xmlErrValid(
            ctxt,
            XML_DTD_NO_DOC,
            b"xmlValidateDocumentFinal: doc == NULL\n\0" as *const u8
                as *const libc::c_char,
            0 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    save = (*ctxt).flags;
    (*ctxt).flags &= !((1 as libc::c_uint) << 1 as libc::c_int);
    table = (*doc).refs as xmlRefTablePtr;
    let ref mut fresh149 = (*ctxt).doc;
    *fresh149 = doc;
    (*ctxt).valid = 1 as libc::c_int;
    xmlHashScan(
        table,
        Some(
            xmlValidateCheckRefCallback
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_void,
                    *const xmlChar,
                ) -> (),
        ),
        ctxt as *mut libc::c_void,
    );
    (*ctxt).flags = save;
    return (*ctxt).valid;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateDtd(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
    mut dtd: xmlDtdPtr,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    let mut oldExt: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut oldInt: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut root: xmlNodePtr = 0 as *mut xmlNode;
    if dtd.is_null() {
        return 0 as libc::c_int;
    }
    if doc.is_null() {
        return 0 as libc::c_int;
    }
    oldExt = (*doc).extSubset;
    oldInt = (*doc).intSubset;
    let ref mut fresh150 = (*doc).extSubset;
    *fresh150 = dtd;
    let ref mut fresh151 = (*doc).intSubset;
    *fresh151 = 0 as *mut _xmlDtd;
    ret = xmlValidateRoot(ctxt, doc);
    if ret == 0 as libc::c_int {
        let ref mut fresh152 = (*doc).extSubset;
        *fresh152 = oldExt;
        let ref mut fresh153 = (*doc).intSubset;
        *fresh153 = oldInt;
        return ret;
    }
    if !((*doc).ids).is_null() {
        xmlFreeIDTable((*doc).ids as xmlIDTablePtr);
        let ref mut fresh154 = (*doc).ids;
        *fresh154 = 0 as *mut libc::c_void;
    }
    if !((*doc).refs).is_null() {
        xmlFreeRefTable((*doc).refs as xmlRefTablePtr);
        let ref mut fresh155 = (*doc).refs;
        *fresh155 = 0 as *mut libc::c_void;
    }
    root = xmlDocGetRootElement(doc as *const xmlDoc);
    ret = xmlValidateElement(ctxt, doc, root);
    ret &= xmlValidateDocumentFinal(ctxt, doc);
    let ref mut fresh156 = (*doc).extSubset;
    *fresh156 = oldExt;
    let ref mut fresh157 = (*doc).intSubset;
    *fresh157 = oldInt;
    return ret;
}
unsafe extern "C" fn xmlValidateNotationCallback(
    mut payload: *mut libc::c_void,
    mut data: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    let mut cur: xmlEntityPtr = payload as xmlEntityPtr;
    let mut ctxt: xmlValidCtxtPtr = data as xmlValidCtxtPtr;
    if cur.is_null() {
        return;
    }
    if (*cur).etype as libc::c_uint
        == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as libc::c_int as libc::c_uint
    {
        let mut notation: *mut xmlChar = (*cur).content;
        if !notation.is_null() {
            let mut ret: libc::c_int = 0;
            ret = xmlValidateNotationUse(ctxt, (*cur).doc, notation);
            if ret != 1 as libc::c_int {
                (*ctxt).valid = 0 as libc::c_int;
            }
        }
    }
}
unsafe extern "C" fn xmlValidateAttributeCallback(
    mut payload: *mut libc::c_void,
    mut data: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    let mut cur: xmlAttributePtr = payload as xmlAttributePtr;
    let mut ctxt: xmlValidCtxtPtr = data as xmlValidCtxtPtr;
    let mut ret: libc::c_int = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut elem: xmlElementPtr = 0 as xmlElementPtr;
    if cur.is_null() {
        return;
    }
    match (*cur).atype as libc::c_uint {
        5 | 6 | 10 => {
            if !((*cur).defaultValue).is_null() {
                ret = xmlValidateAttributeValue2(
                    ctxt,
                    (*ctxt).doc,
                    (*cur).name,
                    (*cur).atype,
                    (*cur).defaultValue,
                );
                if ret == 0 as libc::c_int && (*ctxt).valid == 1 as libc::c_int {
                    (*ctxt).valid = 0 as libc::c_int;
                }
            }
            if !((*cur).tree).is_null() {
                let mut tree: xmlEnumerationPtr = (*cur).tree;
                while !tree.is_null() {
                    ret = xmlValidateAttributeValue2(
                        ctxt,
                        (*ctxt).doc,
                        (*cur).name,
                        (*cur).atype,
                        (*tree).name,
                    );
                    if ret == 0 as libc::c_int && (*ctxt).valid == 1 as libc::c_int {
                        (*ctxt).valid = 0 as libc::c_int;
                    }
                    tree = (*tree).next;
                }
            }
        }
        1 | 2 | 3 | 4 | 7 | 8 | 9 | _ => {}
    }
    if (*cur).atype as libc::c_uint
        == XML_ATTRIBUTE_NOTATION as libc::c_int as libc::c_uint
    {
        doc = (*cur).doc;
        if ((*cur).elem).is_null() {
            xmlErrValid(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"xmlValidateAttributeCallback(%s): internal error\n\0" as *const u8
                    as *const libc::c_char,
                (*cur).name as *const libc::c_char,
            );
            return;
        }
        if !doc.is_null() {
            elem = xmlGetDtdElementDesc((*doc).intSubset, (*cur).elem);
        }
        if elem.is_null() && !doc.is_null() {
            elem = xmlGetDtdElementDesc((*doc).extSubset, (*cur).elem);
        }
        if elem.is_null() && !((*cur).parent).is_null()
            && (*(*cur).parent).type_0 as libc::c_uint
                == XML_DTD_NODE as libc::c_int as libc::c_uint
        {
            elem = xmlGetDtdElementDesc((*cur).parent as xmlDtdPtr, (*cur).elem);
        }
        if elem.is_null() {
            xmlErrValidNode(
                ctxt,
                0 as xmlNodePtr,
                XML_DTD_UNKNOWN_ELEM,
                b"attribute %s: could not find decl for element %s\n\0" as *const u8
                    as *const libc::c_char,
                (*cur).name,
                (*cur).elem,
                0 as *const xmlChar,
            );
            return;
        }
        if (*elem).etype as libc::c_uint
            == XML_ELEMENT_TYPE_EMPTY as libc::c_int as libc::c_uint
        {
            xmlErrValidNode(
                ctxt,
                0 as xmlNodePtr,
                XML_DTD_EMPTY_NOTATION,
                b"NOTATION attribute %s declared for EMPTY element %s\n\0" as *const u8
                    as *const libc::c_char,
                (*cur).name,
                (*cur).elem,
                0 as *const xmlChar,
            );
            (*ctxt).valid = 0 as libc::c_int;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateDtdFinal(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
) -> libc::c_int {
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut table: xmlAttributeTablePtr = 0 as *mut xmlAttributeTable;
    let mut entities: xmlEntitiesTablePtr = 0 as *mut xmlEntitiesTable;
    if doc.is_null() || ctxt.is_null() {
        return 0 as libc::c_int;
    }
    if ((*doc).intSubset).is_null() && ((*doc).extSubset).is_null() {
        return 0 as libc::c_int;
    }
    let ref mut fresh158 = (*ctxt).doc;
    *fresh158 = doc;
    (*ctxt).valid = 1 as libc::c_int;
    dtd = (*doc).intSubset;
    if !dtd.is_null() && !((*dtd).attributes).is_null() {
        table = (*dtd).attributes as xmlAttributeTablePtr;
        xmlHashScan(
            table,
            Some(
                xmlValidateAttributeCallback
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> (),
            ),
            ctxt as *mut libc::c_void,
        );
    }
    if !dtd.is_null() && !((*dtd).entities).is_null() {
        entities = (*dtd).entities as xmlEntitiesTablePtr;
        xmlHashScan(
            entities,
            Some(
                xmlValidateNotationCallback
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> (),
            ),
            ctxt as *mut libc::c_void,
        );
    }
    dtd = (*doc).extSubset;
    if !dtd.is_null() && !((*dtd).attributes).is_null() {
        table = (*dtd).attributes as xmlAttributeTablePtr;
        xmlHashScan(
            table,
            Some(
                xmlValidateAttributeCallback
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> (),
            ),
            ctxt as *mut libc::c_void,
        );
    }
    if !dtd.is_null() && !((*dtd).entities).is_null() {
        entities = (*dtd).entities as xmlEntitiesTablePtr;
        xmlHashScan(
            entities,
            Some(
                xmlValidateNotationCallback
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> (),
            ),
            ctxt as *mut libc::c_void,
        );
    }
    return (*ctxt).valid;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidateDocument(
    mut ctxt: xmlValidCtxtPtr,
    mut doc: xmlDocPtr,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    let mut root: xmlNodePtr = 0 as *mut xmlNode;
    if doc.is_null() {
        return 0 as libc::c_int;
    }
    if ((*doc).intSubset).is_null() && ((*doc).extSubset).is_null() {
        xmlErrValid(
            ctxt,
            XML_DTD_NO_DTD,
            b"no DTD found!\n\0" as *const u8 as *const libc::c_char,
            0 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if !((*doc).intSubset).is_null()
        && (!((*(*doc).intSubset).SystemID).is_null()
            || !((*(*doc).intSubset).ExternalID).is_null())
        && ((*doc).extSubset).is_null()
    {
        let mut sysID: *mut xmlChar = 0 as *mut xmlChar;
        if !((*(*doc).intSubset).SystemID).is_null() {
            sysID = xmlBuildURI((*(*doc).intSubset).SystemID, (*doc).URL);
            if sysID.is_null() {
                xmlErrValid(
                    ctxt,
                    XML_DTD_LOAD_ERROR,
                    b"Could not build URI for external subset \"%s\"\n\0" as *const u8
                        as *const libc::c_char,
                    (*(*doc).intSubset).SystemID as *const libc::c_char,
                );
                return 0 as libc::c_int;
            }
        } else {
            sysID = 0 as *mut xmlChar;
        }
        let ref mut fresh159 = (*doc).extSubset;
        *fresh159 = xmlParseDTD((*(*doc).intSubset).ExternalID, sysID as *const xmlChar);
        if !sysID.is_null() {
            xmlFree.expect("non-null function pointer")(sysID as *mut libc::c_void);
        }
        if ((*doc).extSubset).is_null() {
            if !((*(*doc).intSubset).SystemID).is_null() {
                xmlErrValid(
                    ctxt,
                    XML_DTD_LOAD_ERROR,
                    b"Could not load the external subset \"%s\"\n\0" as *const u8
                        as *const libc::c_char,
                    (*(*doc).intSubset).SystemID as *const libc::c_char,
                );
            } else {
                xmlErrValid(
                    ctxt,
                    XML_DTD_LOAD_ERROR,
                    b"Could not load the external subset \"%s\"\n\0" as *const u8
                        as *const libc::c_char,
                    (*(*doc).intSubset).ExternalID as *const libc::c_char,
                );
            }
            return 0 as libc::c_int;
        }
    }
    if !((*doc).ids).is_null() {
        xmlFreeIDTable((*doc).ids as xmlIDTablePtr);
        let ref mut fresh160 = (*doc).ids;
        *fresh160 = 0 as *mut libc::c_void;
    }
    if !((*doc).refs).is_null() {
        xmlFreeRefTable((*doc).refs as xmlRefTablePtr);
        let ref mut fresh161 = (*doc).refs;
        *fresh161 = 0 as *mut libc::c_void;
    }
    ret = xmlValidateDtdFinal(ctxt, doc);
    if xmlValidateRoot(ctxt, doc) == 0 {
        return 0 as libc::c_int;
    }
    root = xmlDocGetRootElement(doc as *const xmlDoc);
    ret &= xmlValidateElement(ctxt, doc, root);
    ret &= xmlValidateDocumentFinal(ctxt, doc);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlValidGetPotentialChildren(
    mut ctree: *mut xmlElementContent,
    mut names: *mut *const xmlChar,
    mut len: *mut libc::c_int,
    mut max: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    if ctree.is_null() || names.is_null() || len.is_null() {
        return -(1 as libc::c_int);
    }
    if *len >= max {
        return *len;
    }
    match (*ctree).type_0 as libc::c_uint {
        1 => {
            i = 0 as libc::c_int;
            while i < *len {
                if xmlStrEqual(
                    b"#PCDATA\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    *names.offset(i as isize),
                ) != 0
                {
                    return *len;
                }
                i += 1;
            }
            let fresh162 = *len;
            *len = *len + 1;
            let ref mut fresh163 = *names.offset(fresh162 as isize);
            *fresh163 = b"#PCDATA\0" as *const u8 as *const libc::c_char as *mut xmlChar;
        }
        2 => {
            i = 0 as libc::c_int;
            while i < *len {
                if xmlStrEqual((*ctree).name, *names.offset(i as isize)) != 0 {
                    return *len;
                }
                i += 1;
            }
            let fresh164 = *len;
            *len = *len + 1;
            let ref mut fresh165 = *names.offset(fresh164 as isize);
            *fresh165 = (*ctree).name;
        }
        3 => {
            xmlValidGetPotentialChildren((*ctree).c1, names, len, max);
            xmlValidGetPotentialChildren((*ctree).c2, names, len, max);
        }
        4 => {
            xmlValidGetPotentialChildren((*ctree).c1, names, len, max);
            xmlValidGetPotentialChildren((*ctree).c2, names, len, max);
        }
        _ => {}
    }
    return *len;
}
unsafe extern "C" fn xmlNoValidityErr(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {}
#[no_mangle]
pub unsafe extern "C" fn xmlValidGetValidElements(
    mut prev: *mut xmlNode,
    mut next: *mut xmlNode,
    mut names: *mut *const xmlChar,
    mut max: libc::c_int,
) -> libc::c_int {
    let mut vctxt: xmlValidCtxt = xmlValidCtxt {
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
    let mut nb_valid_elements: libc::c_int = 0 as libc::c_int;
    let mut elements: [*const xmlChar; 256] = [
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
    ];
    let mut nb_elements: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut ref_node: *mut xmlNode = 0 as *mut xmlNode;
    let mut parent: *mut xmlNode = 0 as *mut xmlNode;
    let mut test_node: *mut xmlNode = 0 as *mut xmlNode;
    let mut prev_next: *mut xmlNode = 0 as *mut xmlNode;
    let mut next_prev: *mut xmlNode = 0 as *mut xmlNode;
    let mut parent_childs: *mut xmlNode = 0 as *mut xmlNode;
    let mut parent_last: *mut xmlNode = 0 as *mut xmlNode;
    let mut element_desc: *mut xmlElement = 0 as *mut xmlElement;
    if prev.is_null() && next.is_null() {
        return -(1 as libc::c_int);
    }
    if names.is_null() {
        return -(1 as libc::c_int);
    }
    if max <= 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    memset(
        &mut vctxt as *mut xmlValidCtxt as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlValidCtxt>() as libc::c_ulong,
    );
    vctxt
        .error = Some(
        xmlNoValidityErr
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    );
    nb_valid_elements = 0 as libc::c_int;
    ref_node = if !prev.is_null() { prev } else { next };
    parent = (*ref_node).parent;
    element_desc = xmlGetDtdElementDesc((*(*parent).doc).intSubset, (*parent).name);
    if element_desc.is_null() && !((*(*parent).doc).extSubset).is_null() {
        element_desc = xmlGetDtdElementDesc((*(*parent).doc).extSubset, (*parent).name);
    }
    if element_desc.is_null() {
        return -(1 as libc::c_int);
    }
    prev_next = if !prev.is_null() { (*prev).next } else { 0 as *mut _xmlNode };
    next_prev = if !next.is_null() { (*next).prev } else { 0 as *mut _xmlNode };
    parent_childs = (*parent).children;
    parent_last = (*parent).last;
    test_node = xmlNewDocNode(
        (*ref_node).doc,
        0 as xmlNsPtr,
        b"<!dummy?>\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        0 as *const xmlChar,
    );
    if test_node.is_null() {
        return -(1 as libc::c_int);
    }
    let ref mut fresh166 = (*test_node).parent;
    *fresh166 = parent;
    let ref mut fresh167 = (*test_node).prev;
    *fresh167 = prev;
    let ref mut fresh168 = (*test_node).next;
    *fresh168 = next;
    name = (*test_node).name;
    if !prev.is_null() {
        let ref mut fresh169 = (*prev).next;
        *fresh169 = test_node;
    } else {
        let ref mut fresh170 = (*parent).children;
        *fresh170 = test_node;
    }
    if !next.is_null() {
        let ref mut fresh171 = (*next).prev;
        *fresh171 = test_node;
    } else {
        let ref mut fresh172 = (*parent).last;
        *fresh172 = test_node;
    }
    nb_elements = xmlValidGetPotentialChildren(
        (*element_desc).content,
        elements.as_mut_ptr(),
        &mut nb_elements,
        256 as libc::c_int,
    );
    i = 0 as libc::c_int;
    while i < nb_elements {
        let ref mut fresh173 = (*test_node).name;
        *fresh173 = elements[i as usize];
        if xmlValidateOneElement(&mut vctxt, (*parent).doc, parent) != 0 {
            let mut j: libc::c_int = 0;
            j = 0 as libc::c_int;
            while j < nb_valid_elements {
                if xmlStrEqual(elements[i as usize], *names.offset(j as isize)) != 0 {
                    break;
                }
                j += 1;
            }
            let fresh174 = nb_valid_elements;
            nb_valid_elements = nb_valid_elements + 1;
            let ref mut fresh175 = *names.offset(fresh174 as isize);
            *fresh175 = elements[i as usize];
            if nb_valid_elements >= max {
                break;
            }
        }
        i += 1;
    }
    if !prev.is_null() {
        let ref mut fresh176 = (*prev).next;
        *fresh176 = prev_next;
    }
    if !next.is_null() {
        let ref mut fresh177 = (*next).prev;
        *fresh177 = next_prev;
    }
    let ref mut fresh178 = (*parent).children;
    *fresh178 = parent_childs;
    let ref mut fresh179 = (*parent).last;
    *fresh179 = parent_last;
    let ref mut fresh180 = (*test_node).name;
    *fresh180 = name;
    xmlFreeNode(test_node);
    return nb_valid_elements;
}
