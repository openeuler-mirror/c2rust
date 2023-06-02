use ::libc;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fclose(__stream: *mut FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    fn snprintf(
        _: *mut i8,
        _: u64,
        _: *const i8,
        _: ...
    ) -> i32;
    fn sscanf(_: *const i8, _: *const i8, _: ...) -> i32;
    
    
    
    
    
    fn fputc(__c: i32, __stream: *mut FILE) -> i32;
    
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strlen(_: *const i8) -> u64;
    fn free(__ptr: *mut libc::c_void);
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::HTMLparser::htmlParseFile;
pub use crate::src::HTMLtree::htmlDocDump;
pub use crate::src::HTMLtree::htmlNodeDumpFile;
pub use crate::src::HTMLtree::htmlSaveFile;
pub use crate::src::dict::xmlDictLookup;
pub use crate::src::dict::xmlDictOwns;
pub use crate::src::entities::xmlGetDocEntity;
pub use crate::src::error::__xmlRaiseError;
pub use crate::src::globals::__xmlGenericError;
pub use crate::src::globals::__xmlGenericErrorContext;
pub use crate::src::hash::xmlHashScan;
pub use crate::src::parser::xmlParseDTD;
pub use crate::src::parser::xmlParseInNodeContext;
pub use crate::src::parser::xmlReadFile;
pub use crate::src::relaxng::xmlRelaxNGFree;
pub use crate::src::relaxng::xmlRelaxNGFreeParserCtxt;
pub use crate::src::relaxng::xmlRelaxNGFreeValidCtxt;
pub use crate::src::relaxng::xmlRelaxNGNewParserCtxt;
pub use crate::src::relaxng::xmlRelaxNGNewValidCtxt;
pub use crate::src::relaxng::xmlRelaxNGParse;
pub use crate::src::relaxng::xmlRelaxNGSetParserErrors;
pub use crate::src::relaxng::xmlRelaxNGSetValidErrors;
pub use crate::src::relaxng::xmlRelaxNGValidateDoc;
pub use crate::src::tree::xmlAddChildList;
pub use crate::src::tree::xmlDocGetRootElement;
pub use crate::src::tree::xmlFreeDoc;
pub use crate::src::tree::xmlFreeDtd;
pub use crate::src::tree::xmlFreeNodeList;
pub use crate::src::tree::xmlGetNodePath;
pub use crate::src::tree::xmlNodeGetBase;
pub use crate::src::tree::xmlNodeSetBase;
pub use crate::src::tree::xmlValidateName;
pub use crate::src::uri::xmlCanonicPath;
pub use crate::src::valid::xmlSnprintfElementContent;
pub use crate::src::valid::xmlValidateDocument;
pub use crate::src::valid::xmlValidateDtd;
pub use crate::src::xmlmemory::xmlMemShow;
pub use crate::src::xmlsave::xmlDocDump;
pub use crate::src::xmlsave::xmlElemDump;
pub use crate::src::xmlsave::xmlSaveFile;
pub use crate::src::xmlstring::xmlCheckUTF8;
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrchr;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrlen;
pub use crate::src::xmlstring::xmlStrstr;
pub use crate::src::xpath::xmlXPathDebugDumpObject;
pub use crate::src::xpath::xmlXPathEval;
pub use crate::src::xpath::xmlXPathFreeContext;
pub use crate::src::xpath::xmlXPathFreeObject;
pub use crate::src::xpath::xmlXPathNewContext;
pub use crate::src::xpath::xmlXPathRegisterNs;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub use crate::src::parserInternals::_IO_wide_data;
pub use crate::src::relaxng::_IO_codecvt;
pub use crate::src::tree::xmlStringComment;
pub use crate::src::tree::xmlStringText;
pub use crate::src::tree::xmlStringTextNoenc;
pub use crate::src::uri::_IO_marker;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::relaxng::_xmlRelaxNG;
pub use crate::src::relaxng::_xmlRelaxNGParserCtxt;
pub use crate::src::relaxng::_xmlRelaxNGValidCtxt;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::xmlregexp::_xmlRegexp;
pub use crate::src::xpath::_xmlXPathCompExpr;
pub type xmlChar = crate::src::HTMLparser::xmlChar;
pub type size_t = crate::src::HTMLparser::size_t;
pub type __off_t = crate::src::HTMLtree::__off_t;
pub type __off64_t = crate::src::HTMLtree::__off64_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::HTMLtree::_IO_FILE;
pub type _IO_lock_t = crate::src::HTMLtree::_IO_lock_t;
pub type FILE = crate::src::HTMLtree::FILE;
pub type xmlFreeFunc = crate::src::HTMLparser::xmlFreeFunc;
pub type xmlMallocFunc = crate::src::HTMLparser::xmlMallocFunc;
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
pub type xmlDictPtr = crate::src::HTMLparser::xmlDictPtr;
pub type xmlDict = crate::src::HTMLparser::xmlDict;
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
pub type xmlStructuredErrorFunc = crate::src::HTMLparser::xmlStructuredErrorFunc;
pub type xmlErrorPtr = crate::src::HTMLparser::xmlErrorPtr;
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
pub type xmlEnumerationPtr = crate::src::HTMLparser::xmlEnumerationPtr;
pub type xmlEnumeration = crate::src::HTMLparser::xmlEnumeration;
// #[derive(Copy, Clone)]

pub type _xmlEnumeration = crate::src::HTMLparser::_xmlEnumeration;
pub type xmlAttributeDefault = crate::src::SAX2::xmlAttributeDefault;
pub const XML_ATTRIBUTE_FIXED: xmlAttributeDefault = 4;
pub const XML_ATTRIBUTE_IMPLIED: xmlAttributeDefault = 3;
pub const XML_ATTRIBUTE_REQUIRED: xmlAttributeDefault = 2;
pub const XML_ATTRIBUTE_NONE: xmlAttributeDefault = 1;
// #[derive(Copy, Clone)]

pub type _xmlAttribute = crate::src::SAX2::_xmlAttribute;
pub type xmlAttribute = crate::src::SAX2::xmlAttribute;
pub type xmlAttributePtr = crate::src::SAX2::xmlAttributePtr;
pub type xmlElementTypeVal = crate::src::SAX2::xmlElementTypeVal;
pub const XML_ELEMENT_TYPE_ELEMENT: xmlElementTypeVal = 4;
pub const XML_ELEMENT_TYPE_MIXED: xmlElementTypeVal = 3;
pub const XML_ELEMENT_TYPE_ANY: xmlElementTypeVal = 2;
pub const XML_ELEMENT_TYPE_EMPTY: xmlElementTypeVal = 1;
pub const XML_ELEMENT_TYPE_UNDEFINED: xmlElementTypeVal = 0;
pub type xmlRegexp = crate::src::SAX2::xmlRegexp;
pub type xmlRegexpPtr = crate::src::SAX2::xmlRegexpPtr;
// #[derive(Copy, Clone)]

pub type _xmlElement = crate::src::SAX2::_xmlElement;
pub type xmlElement = crate::src::SAX2::xmlElement;
pub type xmlElementPtr = crate::src::SAX2::xmlElementPtr;
pub type xmlNsPtr = crate::src::HTMLtree::xmlNsPtr;
pub type xmlDtd = crate::src::HTMLparser::xmlDtd;
pub type xmlDtdPtr = crate::src::HTMLparser::xmlDtdPtr;
pub type xmlHashScanner = crate::src::catalog::xmlHashScanner;
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
pub type xmlGenericErrorFunc = crate::src::HTMLparser::xmlGenericErrorFunc;
pub type xmlValidCtxtPtr = crate::src::SAX2::xmlValidCtxtPtr;
pub type xmlEntitiesTable = _xmlHashTable;
pub type xmlEntitiesTablePtr = *mut xmlEntitiesTable;
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
pub const XML_PARSE_NOBLANKS: C2RustUnnamed_0 = 256;
pub const XML_PARSE_PEDANTIC: C2RustUnnamed_0 = 128;
pub const XML_PARSE_NOWARNING: C2RustUnnamed_0 = 64;
pub const XML_PARSE_NOERROR: C2RustUnnamed_0 = 32;
pub const XML_PARSE_DTDVALID: C2RustUnnamed_0 = 16;
pub const XML_PARSE_DTDATTR: C2RustUnnamed_0 = 8;
pub const XML_PARSE_DTDLOAD: C2RustUnnamed_0 = 4;
pub const XML_PARSE_NOENT: C2RustUnnamed_0 = 2;
pub const XML_PARSE_RECOVER: C2RustUnnamed_0 = 1;
pub type htmlDocPtr = crate::src::HTMLparser::htmlDocPtr;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathContext {
    pub doc: xmlDocPtr,
    pub node: xmlNodePtr,
    pub nb_variables_unused: i32,
    pub max_variables_unused: i32,
    pub varHash: xmlHashTablePtr,
    pub nb_types: i32,
    pub max_types: i32,
    pub types: xmlXPathTypePtr,
    pub nb_funcs_unused: i32,
    pub max_funcs_unused: i32,
    pub funcHash: xmlHashTablePtr,
    pub nb_axis: i32,
    pub max_axis: i32,
    pub axis: xmlXPathAxisPtr,
    pub namespaces: *mut xmlNsPtr,
    pub nsNr: i32,
    pub user: *mut libc::c_void,
    pub contextSize: i32,
    pub proximityPosition: i32,
    pub xptr: i32,
    pub here: xmlNodePtr,
    pub origin: xmlNodePtr,
    pub nsHash: xmlHashTablePtr,
    pub varLookupFunc: xmlXPathVariableLookupFunc,
    pub varLookupData: *mut libc::c_void,
    pub extra: *mut libc::c_void,
    pub function: *const xmlChar,
    pub functionURI: *const xmlChar,
    pub funcLookupFunc: xmlXPathFuncLookupFunc,
    pub funcLookupData: *mut libc::c_void,
    pub tmpNsList: *mut xmlNsPtr,
    pub tmpNsNr: i32,
    pub userData: *mut libc::c_void,
    pub error: xmlStructuredErrorFunc,
    pub lastError: xmlError,
    pub debugNode: xmlNodePtr,
    pub dict: xmlDictPtr,
    pub flags: i32,
    pub cache: *mut libc::c_void,
    pub opLimit: u64,
    pub opCount: u64,
    pub depth: i32,
}
pub type xmlXPathFuncLookupFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
    ) -> xmlXPathFunction,
>;
pub type xmlXPathFunction = Option::<
    unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> (),
>;
pub type xmlXPathParserContextPtr = *mut xmlXPathParserContext;
pub type xmlXPathParserContext = _xmlXPathParserContext;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathParserContext {
    pub cur: *const xmlChar,
    pub base: *const xmlChar,
    pub error: i32,
    pub context: xmlXPathContextPtr,
    pub value: xmlXPathObjectPtr,
    pub valueNr: i32,
    pub valueMax: i32,
    pub valueTab: *mut xmlXPathObjectPtr,
    pub comp: xmlXPathCompExprPtr,
    pub xptr: i32,
    pub ancestor: xmlNodePtr,
    pub valueFrame: i32,
}
pub type xmlXPathCompExprPtr = *mut xmlXPathCompExpr;
pub type xmlXPathCompExpr = _xmlXPathCompExpr;
pub type xmlXPathObjectPtr = *mut xmlXPathObject;
pub type xmlXPathObject = _xmlXPathObject;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathObject {
    pub type_0: xmlXPathObjectType,
    pub nodesetval: xmlNodeSetPtr,
    pub boolval: i32,
    pub floatval: f64,
    pub stringval: *mut xmlChar,
    pub user: *mut libc::c_void,
    pub index: i32,
    pub user2: *mut libc::c_void,
    pub index2: i32,
}
pub type xmlNodeSetPtr = crate::src::c14n::xmlNodeSetPtr;
pub type xmlNodeSet = crate::src::c14n::xmlNodeSet;
// #[derive(Copy, Clone)]

pub type _xmlNodeSet = crate::src::c14n::_xmlNodeSet;
pub type xmlXPathObjectType = u32;
pub const XPATH_XSLT_TREE: xmlXPathObjectType = 9;
pub const XPATH_USERS: xmlXPathObjectType = 8;
pub const XPATH_STRING: xmlXPathObjectType = 4;
pub const XPATH_NUMBER: xmlXPathObjectType = 3;
pub const XPATH_BOOLEAN: xmlXPathObjectType = 2;
pub const XPATH_NODESET: xmlXPathObjectType = 1;
pub const XPATH_UNDEFINED: xmlXPathObjectType = 0;
pub type xmlXPathContextPtr = *mut xmlXPathContext;
pub type xmlXPathContext = _xmlXPathContext;
pub type xmlXPathVariableLookupFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
    ) -> xmlXPathObjectPtr,
>;
pub type xmlXPathAxisPtr = *mut xmlXPathAxis;
pub type xmlXPathAxis = _xmlXPathAxis;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathAxis {
    pub name: *const xmlChar,
    pub func: xmlXPathAxisFunc,
}
pub type xmlXPathAxisFunc = Option::<
    unsafe extern "C" fn(
        xmlXPathParserContextPtr,
        xmlXPathObjectPtr,
    ) -> xmlXPathObjectPtr,
>;
pub type xmlXPathTypePtr = *mut xmlXPathType;
pub type xmlXPathType = _xmlXPathType;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathType {
    pub name: *const xmlChar,
    pub func: xmlXPathConvertFunc,
}
pub type xmlXPathConvertFunc = Option::<
    unsafe extern "C" fn(xmlXPathObjectPtr, i32) -> i32,
>;
pub type xmlDebugCtxt = _xmlDebugCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDebugCtxt {
    pub output: *mut FILE,
    pub shift: [i8; 101],
    pub depth: i32,
    pub doc: xmlDocPtr,
    pub node: xmlNodePtr,
    pub dict: xmlDictPtr,
    pub check: i32,
    pub errors: i32,
    pub nodict: i32,
    pub options: i32,
}
pub type xmlDebugCtxtPtr = *mut xmlDebugCtxt;
pub type xmlShellReadlineFunc = Option::<
    unsafe extern "C" fn(*mut i8) -> *mut i8,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlShellCtxt {
    pub filename: *mut i8,
    pub doc: xmlDocPtr,
    pub node: xmlNodePtr,
    pub pctxt: xmlXPathContextPtr,
    pub loaded: i32,
    pub output: *mut FILE,
    pub input: xmlShellReadlineFunc,
}
pub type xmlShellCtxt = _xmlShellCtxt;
pub type xmlShellCtxtPtr = *mut xmlShellCtxt;
pub type xmlRelaxNGPtr = *mut xmlRelaxNG;
pub type xmlRelaxNG = _xmlRelaxNG;
pub type xmlRelaxNGValidCtxtPtr = *mut xmlRelaxNGValidCtxt;
pub type xmlRelaxNGValidCtxt = _xmlRelaxNGValidCtxt;
pub type xmlRelaxNGValidityWarningFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
>;
pub type xmlRelaxNGValidityErrorFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
>;
pub type xmlRelaxNGParserCtxtPtr = *mut xmlRelaxNGParserCtxt;
pub type xmlRelaxNGParserCtxt = _xmlRelaxNGParserCtxt;
unsafe extern "C" fn xmlCtxtDumpInitCtxt(mut ctxt: xmlDebugCtxtPtr) {
    let mut i: i32 = 0;
    (*ctxt).depth = 0 as i32;
    (*ctxt).check = 0 as i32;
    (*ctxt).errors = 0 as i32;
    let fresh0 = &mut ((*ctxt).output);
    *fresh0 = stdout;
    let fresh1 = &mut ((*ctxt).doc);
    *fresh1 = 0 as xmlDocPtr;
    let fresh2 = &mut ((*ctxt).node);
    *fresh2 = 0 as xmlNodePtr;
    let fresh3 = &mut ((*ctxt).dict);
    *fresh3 = 0 as xmlDictPtr;
    (*ctxt).nodict = 0 as i32;
    (*ctxt).options = 0 as i32;
    i = 0 as i32;
    while i < 100 as i32 {
        (*ctxt).shift[i as usize] = ' ' as i32 as i8;
        i += 1;
    }
    (*ctxt).shift[100 as i32 as usize] = 0 as i32 as i8;
}
 extern "C" fn xmlCtxtDumpCleanCtxt(mut ctxt: xmlDebugCtxtPtr) {}
unsafe extern "C" fn xmlNsCheckScope(
    mut node: xmlNodePtr,
    mut ns: xmlNsPtr,
) -> i32 {
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    if node.is_null() || ns.is_null() {
        return -(1 as i32);
    }
    if (*node).type_0 as u32 != XML_ELEMENT_NODE as i32 as u32
        && (*node).type_0 as u32
            != XML_ATTRIBUTE_NODE as i32 as u32
        && (*node).type_0 as u32
            != XML_DOCUMENT_NODE as i32 as u32
        && (*node).type_0 as u32 != XML_TEXT_NODE as i32 as u32
        && (*node).type_0 as u32
            != XML_HTML_DOCUMENT_NODE as i32 as u32
        && (*node).type_0 as u32
            != XML_XINCLUDE_START as i32 as u32
    {
        return -(2 as i32);
    }
    while !node.is_null()
        && ((*node).type_0 as u32
            == XML_ELEMENT_NODE as i32 as u32
            || (*node).type_0 as u32
                == XML_ATTRIBUTE_NODE as i32 as u32
            || (*node).type_0 as u32
                == XML_TEXT_NODE as i32 as u32
            || (*node).type_0 as u32
                == XML_XINCLUDE_START as i32 as u32)
    {
        if (*node).type_0 as u32
            == XML_ELEMENT_NODE as i32 as u32
            || (*node).type_0 as u32
                == XML_XINCLUDE_START as i32 as u32
        {
            cur = (*node).nsDef;
            while !cur.is_null() {
                if cur == ns {
                    return 1 as i32;
                }
                if xmlStrEqual((*cur).prefix, (*ns).prefix) != 0 {
                    return -(2 as i32);
                }
                cur = (*cur).next;
            }
        }
        node = (*node).parent;
    }
    if !node.is_null()
        && ((*node).type_0 as u32
            == XML_DOCUMENT_NODE as i32 as u32
            || (*node).type_0 as u32
                == XML_HTML_DOCUMENT_NODE as i32 as u32)
    {
        let mut oldNs: xmlNsPtr = (*(node as xmlDocPtr)).oldNs;
        if oldNs == ns {
            return 1 as i32;
        }
    }
    return -(3 as i32);
}
unsafe extern "C" fn xmlCtxtDumpSpaces(mut ctxt: xmlDebugCtxtPtr) {
    if (*ctxt).check != 0 {
        return;
    }
    if !((*ctxt).output).is_null() && (*ctxt).depth > 0 as i32 {
        if (*ctxt).depth < 50 as i32 {
            fprintf(
                (*ctxt).output,
                b"%s\0" as *const u8 as *const i8,
                &mut *((*ctxt).shift)
                    .as_mut_ptr()
                    .offset(
                        (100 as i32 - 2 as i32 * (*ctxt).depth) as isize,
                    ) as *mut i8,
            );
        } else {
            fprintf(
                (*ctxt).output,
                b"%s\0" as *const u8 as *const i8,
                ((*ctxt).shift).as_mut_ptr(),
            );
        }
    }
}
unsafe extern "C" fn xmlDebugErr(
    mut ctxt: xmlDebugCtxtPtr,
    mut error: i32,
    mut msg: *const i8,
) {
    let fresh4 = &mut ((*ctxt).errors);
    *fresh4 += 1;
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        0 as *mut libc::c_void,
        (*ctxt).node as *mut libc::c_void,
        XML_FROM_CHECK as i32,
        error,
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
    );
}
unsafe extern "C" fn xmlDebugErr2(
    mut ctxt: xmlDebugCtxtPtr,
    mut error: i32,
    mut msg: *const i8,
    mut extra: i32,
) {
    let fresh5 = &mut ((*ctxt).errors);
    *fresh5 += 1;
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        0 as *mut libc::c_void,
        (*ctxt).node as *mut libc::c_void,
        XML_FROM_CHECK as i32,
        error,
        XML_ERR_ERROR,
        0 as *const i8,
        0 as i32,
        0 as *const i8,
        0 as *const i8,
        0 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        extra,
    );
}
unsafe extern "C" fn xmlDebugErr3(
    mut ctxt: xmlDebugCtxtPtr,
    mut error: i32,
    mut msg: *const i8,
    mut extra: *const i8,
) {
    let fresh6 = &mut ((*ctxt).errors);
    *fresh6 += 1;
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        0 as *mut libc::c_void,
        (*ctxt).node as *mut libc::c_void,
        XML_FROM_CHECK as i32,
        error,
        XML_ERR_ERROR,
        0 as *const i8,
        0 as i32,
        0 as *const i8,
        0 as *const i8,
        0 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        extra,
    );
}
unsafe extern "C" fn xmlCtxtNsCheckScope(
    mut ctxt: xmlDebugCtxtPtr,
    mut node: xmlNodePtr,
    mut ns: xmlNsPtr,
) {
    let mut ret: i32 = 0;
    ret = xmlNsCheckScope(node, ns);
    if ret == -(2 as i32) {
        if ((*ns).prefix).is_null() {
            xmlDebugErr(
                ctxt,
                XML_CHECK_NS_SCOPE as i32,
                b"Reference to default namespace not in scope\n\0" as *const u8
                    as *const i8,
            );
        } else {
            xmlDebugErr3(
                ctxt,
                XML_CHECK_NS_SCOPE as i32,
                b"Reference to namespace '%s' not in scope\n\0" as *const u8
                    as *const i8,
                (*ns).prefix as *mut i8,
            );
        }
    }
    if ret == -(3 as i32) {
        if ((*ns).prefix).is_null() {
            xmlDebugErr(
                ctxt,
                XML_CHECK_NS_ANCESTOR as i32,
                b"Reference to default namespace not on ancestor\n\0" as *const u8
                    as *const i8,
            );
        } else {
            xmlDebugErr3(
                ctxt,
                XML_CHECK_NS_ANCESTOR as i32,
                b"Reference to namespace '%s' not on ancestor\n\0" as *const u8
                    as *const i8,
                (*ns).prefix as *mut i8,
            );
        }
    }
}
unsafe extern "C" fn xmlCtxtCheckString(
    mut ctxt: xmlDebugCtxtPtr,
    mut str: *const xmlChar,
) {
    if str.is_null() {
        return;
    }
    if (*ctxt).check != 0 {
        if xmlCheckUTF8(str) == 0 {
            xmlDebugErr3(
                ctxt,
                XML_CHECK_NOT_UTF8 as i32,
                b"String is not UTF-8 %s\0" as *const u8 as *const i8,
                str as *const i8,
            );
        }
    }
}
unsafe extern "C" fn xmlCtxtCheckName(
    mut ctxt: xmlDebugCtxtPtr,
    mut name: *const xmlChar,
) {
    if (*ctxt).check != 0 {
        if name.is_null() {
            xmlDebugErr(
                ctxt,
                XML_CHECK_NO_NAME as i32,
                b"Name is NULL\0" as *const u8 as *const i8,
            );
            return;
        }
        if xmlValidateName(name, 0 as i32) != 0 {
            xmlDebugErr3(
                ctxt,
                XML_CHECK_NOT_NCNAME as i32,
                b"Name is not an NCName '%s'\0" as *const u8 as *const i8,
                name as *const i8,
            );
        }
        if !((*ctxt).dict).is_null() && xmlDictOwns((*ctxt).dict, name) == 0
            && (((*ctxt).doc).is_null()
                || (*(*ctxt).doc).parseFlags
                    & (XML_PARSE_SAX1 as i32 | XML_PARSE_NODICT as i32)
                    == 0 as i32)
        {
            xmlDebugErr3(
                ctxt,
                XML_CHECK_OUTSIDE_DICT as i32,
                b"Name is not from the document dictionary '%s'\0" as *const u8
                    as *const i8,
                name as *const i8,
            );
        }
    }
}
unsafe extern "C" fn xmlCtxtGenericNodeCheck(
    mut ctxt: xmlDebugCtxtPtr,
    mut node: xmlNodePtr,
) {
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut dict: xmlDictPtr = 0 as *mut xmlDict;
    doc = (*node).doc;
    if ((*node).parent).is_null() {
        xmlDebugErr(
            ctxt,
            XML_CHECK_NO_PARENT as i32,
            b"Node has no parent\n\0" as *const u8 as *const i8,
        );
    }
    if ((*node).doc).is_null() {
        xmlDebugErr(
            ctxt,
            XML_CHECK_NO_DOC as i32,
            b"Node has no doc\n\0" as *const u8 as *const i8,
        );
        dict = 0 as xmlDictPtr;
    } else {
        dict = (*doc).dict;
        if dict.is_null() && (*ctxt).nodict == 0 as i32 {
            (*ctxt).nodict = 1 as i32;
        }
        if ((*ctxt).doc).is_null() {
            let fresh7 = &mut ((*ctxt).doc);
            *fresh7 = doc;
        }
        if ((*ctxt).dict).is_null() {
            let fresh8 = &mut ((*ctxt).dict);
            *fresh8 = dict;
        }
    }
    if !((*node).parent).is_null() && (*node).doc != (*(*node).parent).doc
        && xmlStrEqual(
            (*node).name,
            b"pseudoroot\0" as *const u8 as *const i8 as *mut xmlChar,
        ) == 0
    {
        xmlDebugErr(
            ctxt,
            XML_CHECK_WRONG_DOC as i32,
            b"Node doc differs from parent's one\n\0" as *const u8 as *const i8,
        );
    }
    if ((*node).prev).is_null() {
        if (*node).type_0 as u32
            == XML_ATTRIBUTE_NODE as i32 as u32
        {
            if !((*node).parent).is_null()
                && node != (*(*node).parent).properties as xmlNodePtr
            {
                xmlDebugErr(
                    ctxt,
                    XML_CHECK_NO_PREV as i32,
                    b"Attr has no prev and not first of attr list\n\0" as *const u8
                        as *const i8,
                );
            }
        } else if !((*node).parent).is_null() && (*(*node).parent).children != node {
            xmlDebugErr(
                ctxt,
                XML_CHECK_NO_PREV as i32,
                b"Node has no prev and not first of parent list\n\0" as *const u8
                    as *const i8,
            );
        }
    } else if (*(*node).prev).next != node {
        xmlDebugErr(
            ctxt,
            XML_CHECK_WRONG_PREV as i32,
            b"Node prev->next : back link wrong\n\0" as *const u8 as *const i8,
        );
    }
    if ((*node).next).is_null() {
        if !((*node).parent).is_null()
            && (*node).type_0 as u32
                != XML_ATTRIBUTE_NODE as i32 as u32
            && (*(*node).parent).last != node
            && (*(*node).parent).type_0 as u32
                == XML_ELEMENT_NODE as i32 as u32
        {
            xmlDebugErr(
                ctxt,
                XML_CHECK_NO_NEXT as i32,
                b"Node has no next and not last of parent list\n\0" as *const u8
                    as *const i8,
            );
        }
    } else {
        if (*(*node).next).prev != node {
            xmlDebugErr(
                ctxt,
                XML_CHECK_WRONG_NEXT as i32,
                b"Node next->prev : forward link wrong\n\0" as *const u8
                    as *const i8,
            );
        }
        if (*(*node).next).parent != (*node).parent {
            xmlDebugErr(
                ctxt,
                XML_CHECK_WRONG_PARENT as i32,
                b"Node next->prev : forward link wrong\n\0" as *const u8
                    as *const i8,
            );
        }
    }
    if (*node).type_0 as u32 == XML_ELEMENT_NODE as i32 as u32
    {
        let mut ns: xmlNsPtr = 0 as *mut xmlNs;
        ns = (*node).nsDef;
        while !ns.is_null() {
            xmlCtxtNsCheckScope(ctxt, node, ns);
            ns = (*ns).next;
        }
        if !((*node).ns).is_null() {
            xmlCtxtNsCheckScope(ctxt, node, (*node).ns);
        }
    } else if (*node).type_0 as u32
            == XML_ATTRIBUTE_NODE as i32 as u32
        {
        if !((*node).ns).is_null() {
            xmlCtxtNsCheckScope(ctxt, node, (*node).ns);
        }
    }
    if (*node).type_0 as u32 != XML_ELEMENT_NODE as i32 as u32
        && (*node).type_0 as u32
            != XML_ATTRIBUTE_NODE as i32 as u32
        && (*node).type_0 as u32
            != XML_ELEMENT_DECL as i32 as u32
        && (*node).type_0 as u32
            != XML_ATTRIBUTE_DECL as i32 as u32
        && (*node).type_0 as u32 != XML_DTD_NODE as i32 as u32
        && (*node).type_0 as u32
            != XML_HTML_DOCUMENT_NODE as i32 as u32
        && (*node).type_0 as u32
            != XML_DOCUMENT_NODE as i32 as u32
    {
        if !((*node).content).is_null() {
            xmlCtxtCheckString(ctxt, (*node).content as *const xmlChar);
        }
    }
    match (*node).type_0 as u32 {
        1 | 2 => {
            xmlCtxtCheckName(ctxt, (*node).name);
        }
        3 => {
            if !((*node).name == xmlStringText.as_ptr()
                || (*node).name == xmlStringTextNoenc.as_ptr())
            {
                if !(!((*ctxt).dict).is_null()
                    && (*node).name
                        == xmlDictLookup(
                            (*ctxt).dict,
                            b"nbktext\0" as *const u8 as *const i8
                                as *mut xmlChar,
                            7 as i32,
                        ))
                {
                    xmlDebugErr3(
                        ctxt,
                        XML_CHECK_WRONG_NAME as i32,
                        b"Text node has wrong name '%s'\0" as *const u8
                            as *const i8,
                        (*node).name as *const i8,
                    );
                }
            }
        }
        8 => {
            if !((*node).name == xmlStringComment.as_ptr()) {
                xmlDebugErr3(
                    ctxt,
                    XML_CHECK_WRONG_NAME as i32,
                    b"Comment node has wrong name '%s'\0" as *const u8
                        as *const i8,
                    (*node).name as *const i8,
                );
            }
        }
        7 => {
            xmlCtxtCheckName(ctxt, (*node).name);
        }
        4 => {
            if !((*node).name).is_null() {
                xmlDebugErr3(
                    ctxt,
                    XML_CHECK_NAME_NOT_NULL as i32,
                    b"CData section has non NULL name '%s'\0" as *const u8
                        as *const i8,
                    (*node).name as *const i8,
                );
            }
        }
        5 | 6 | 10 | 11 | 12 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 9 | 13 | _ => {}
    };
}
unsafe extern "C" fn xmlCtxtDumpString(
    mut ctxt: xmlDebugCtxtPtr,
    mut str: *const xmlChar,
) {
    let mut i: i32 = 0;
    if (*ctxt).check != 0 {
        return;
    }
    if str.is_null() {
        fprintf((*ctxt).output, b"(NULL)\0" as *const u8 as *const i8);
        return;
    }
    i = 0 as i32;
    while i < 40 as i32 {
        if *str.offset(i as isize) as i32 == 0 as i32 {
            return
        } else {
            if *str.offset(i as isize) as i32 == 0x20 as i32
                || 0x9 as i32 <= *str.offset(i as isize) as i32
                    && *str.offset(i as isize) as i32 <= 0xa as i32
                || *str.offset(i as isize) as i32 == 0xd as i32
            {
                fputc(' ' as i32, (*ctxt).output);
            } else if *str.offset(i as isize) as i32 >= 0x80 as i32 {
                fprintf(
                    (*ctxt).output,
                    b"#%X\0" as *const u8 as *const i8,
                    *str.offset(i as isize) as i32,
                );
            } else {
                fputc(*str.offset(i as isize) as i32, (*ctxt).output);
            }
        }
        i += 1;
    }
    fprintf((*ctxt).output, b"...\0" as *const u8 as *const i8);
}
unsafe extern "C" fn xmlCtxtDumpDtdNode(mut ctxt: xmlDebugCtxtPtr, mut dtd: xmlDtdPtr) {
    xmlCtxtDumpSpaces(ctxt);
    if dtd.is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"DTD node is NULL\n\0" as *const u8 as *const i8,
            );
        }
        return;
    }
    if (*dtd).type_0 as u32 != XML_DTD_NODE as i32 as u32 {
        xmlDebugErr(
            ctxt,
            XML_CHECK_NOT_DTD as i32,
            b"Node is not a DTD\0" as *const u8 as *const i8,
        );
        return;
    }
    if (*ctxt).check == 0 {
        if !((*dtd).name).is_null() {
            fprintf(
                (*ctxt).output,
                b"DTD(%s)\0" as *const u8 as *const i8,
                (*dtd).name as *mut i8,
            );
        } else {
            fprintf((*ctxt).output, b"DTD\0" as *const u8 as *const i8);
        }
        if !((*dtd).ExternalID).is_null() {
            fprintf(
                (*ctxt).output,
                b", PUBLIC %s\0" as *const u8 as *const i8,
                (*dtd).ExternalID as *mut i8,
            );
        }
        if !((*dtd).SystemID).is_null() {
            fprintf(
                (*ctxt).output,
                b", SYSTEM %s\0" as *const u8 as *const i8,
                (*dtd).SystemID as *mut i8,
            );
        }
        fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
    }
    xmlCtxtGenericNodeCheck(ctxt, dtd as xmlNodePtr);
}
unsafe extern "C" fn xmlCtxtDumpAttrDecl(
    mut ctxt: xmlDebugCtxtPtr,
    mut attr: xmlAttributePtr,
) {
    xmlCtxtDumpSpaces(ctxt);
    if attr.is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"Attribute declaration is NULL\n\0" as *const u8 as *const i8,
            );
        }
        return;
    }
    if (*attr).type_0 as u32
        != XML_ATTRIBUTE_DECL as i32 as u32
    {
        xmlDebugErr(
            ctxt,
            XML_CHECK_NOT_ATTR_DECL as i32,
            b"Node is not an attribute declaration\0" as *const u8 as *const i8,
        );
        return;
    }
    if !((*attr).name).is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"ATTRDECL(%s)\0" as *const u8 as *const i8,
                (*attr).name as *mut i8,
            );
        }
    } else {
        xmlDebugErr(
            ctxt,
            XML_CHECK_NO_NAME as i32,
            b"Node attribute declaration has no name\0" as *const u8
                as *const i8,
        );
    }
    if !((*attr).elem).is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b" for %s\0" as *const u8 as *const i8,
                (*attr).elem as *mut i8,
            );
        }
    } else {
        xmlDebugErr(
            ctxt,
            XML_CHECK_NO_ELEM as i32,
            b"Node attribute declaration has no element name\0" as *const u8
                as *const i8,
        );
    }
    if (*ctxt).check == 0 {
        match (*attr).atype as u32 {
            1 => {
                fprintf((*ctxt).output, b" CDATA\0" as *const u8 as *const i8);
            }
            2 => {
                fprintf((*ctxt).output, b" ID\0" as *const u8 as *const i8);
            }
            3 => {
                fprintf((*ctxt).output, b" IDREF\0" as *const u8 as *const i8);
            }
            4 => {
                fprintf(
                    (*ctxt).output,
                    b" IDREFS\0" as *const u8 as *const i8,
                );
            }
            5 => {
                fprintf(
                    (*ctxt).output,
                    b" ENTITY\0" as *const u8 as *const i8,
                );
            }
            6 => {
                fprintf(
                    (*ctxt).output,
                    b" ENTITIES\0" as *const u8 as *const i8,
                );
            }
            7 => {
                fprintf(
                    (*ctxt).output,
                    b" NMTOKEN\0" as *const u8 as *const i8,
                );
            }
            8 => {
                fprintf(
                    (*ctxt).output,
                    b" NMTOKENS\0" as *const u8 as *const i8,
                );
            }
            9 => {
                fprintf(
                    (*ctxt).output,
                    b" ENUMERATION\0" as *const u8 as *const i8,
                );
            }
            10 => {
                fprintf(
                    (*ctxt).output,
                    b" NOTATION \0" as *const u8 as *const i8,
                );
            }
            _ => {}
        }
        if !((*attr).tree).is_null() {
            let mut indx: i32 = 0;
            let mut cur: xmlEnumerationPtr = (*attr).tree;
            indx = 0 as i32;
            while indx < 5 as i32 {
                if indx != 0 as i32 {
                    fprintf(
                        (*ctxt).output,
                        b"|%s\0" as *const u8 as *const i8,
                        (*cur).name as *mut i8,
                    );
                } else {
                    fprintf(
                        (*ctxt).output,
                        b" (%s\0" as *const u8 as *const i8,
                        (*cur).name as *mut i8,
                    );
                }
                cur = (*cur).next;
                if cur.is_null() {
                    break;
                }
                indx += 1;
            }
            if cur.is_null() {
                fprintf((*ctxt).output, b")\0" as *const u8 as *const i8);
            } else {
                fprintf((*ctxt).output, b"...)\0" as *const u8 as *const i8);
            }
        }
        match (*attr).def as u32 {
            2 => {
                fprintf(
                    (*ctxt).output,
                    b" REQUIRED\0" as *const u8 as *const i8,
                );
            }
            3 => {
                fprintf(
                    (*ctxt).output,
                    b" IMPLIED\0" as *const u8 as *const i8,
                );
            }
            4 => {
                fprintf((*ctxt).output, b" FIXED\0" as *const u8 as *const i8);
            }
            1 | _ => {}
        }
        if !((*attr).defaultValue).is_null() {
            fprintf((*ctxt).output, b"\"\0" as *const u8 as *const i8);
            xmlCtxtDumpString(ctxt, (*attr).defaultValue);
            fprintf((*ctxt).output, b"\"\0" as *const u8 as *const i8);
        }
        fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
    }
    xmlCtxtGenericNodeCheck(ctxt, attr as xmlNodePtr);
}
unsafe extern "C" fn xmlCtxtDumpElemDecl(
    mut ctxt: xmlDebugCtxtPtr,
    mut elem: xmlElementPtr,
) {
    xmlCtxtDumpSpaces(ctxt);
    if elem.is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"Element declaration is NULL\n\0" as *const u8 as *const i8,
            );
        }
        return;
    }
    if (*elem).type_0 as u32 != XML_ELEMENT_DECL as i32 as u32
    {
        xmlDebugErr(
            ctxt,
            XML_CHECK_NOT_ELEM_DECL as i32,
            b"Node is not an element declaration\0" as *const u8 as *const i8,
        );
        return;
    }
    if !((*elem).name).is_null() {
        if (*ctxt).check == 0 {
            fprintf((*ctxt).output, b"ELEMDECL(\0" as *const u8 as *const i8);
            xmlCtxtDumpString(ctxt, (*elem).name);
            fprintf((*ctxt).output, b")\0" as *const u8 as *const i8);
        }
    } else {
        xmlDebugErr(
            ctxt,
            XML_CHECK_NO_NAME as i32,
            b"Element declaration has no name\0" as *const u8 as *const i8,
        );
    }
    if (*ctxt).check == 0 {
        match (*elem).etype as u32 {
            0 => {
                fprintf(
                    (*ctxt).output,
                    b", UNDEFINED\0" as *const u8 as *const i8,
                );
            }
            1 => {
                fprintf(
                    (*ctxt).output,
                    b", EMPTY\0" as *const u8 as *const i8,
                );
            }
            2 => {
                fprintf((*ctxt).output, b", ANY\0" as *const u8 as *const i8);
            }
            3 => {
                fprintf(
                    (*ctxt).output,
                    b", MIXED \0" as *const u8 as *const i8,
                );
            }
            4 => {
                fprintf(
                    (*ctxt).output,
                    b", MIXED \0" as *const u8 as *const i8,
                );
            }
            _ => {}
        }
        if (*elem).type_0 as u32
            != XML_ELEMENT_NODE as i32 as u32
            && !((*elem).content).is_null()
        {
            let mut buf: [i8; 5001] = [0; 5001];
            buf[0 as i32 as usize] = 0 as i32 as i8;
            xmlSnprintfElementContent(
                buf.as_mut_ptr(),
                5000 as i32,
                (*elem).content,
                1 as i32,
            );
            buf[5000 as i32 as usize] = 0 as i32 as i8;
            fprintf(
                (*ctxt).output,
                b"%s\0" as *const u8 as *const i8,
                buf.as_mut_ptr(),
            );
        }
        fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
    }
    xmlCtxtGenericNodeCheck(ctxt, elem as xmlNodePtr);
}
unsafe extern "C" fn xmlCtxtDumpEntityDecl(
    mut ctxt: xmlDebugCtxtPtr,
    mut ent: xmlEntityPtr,
) {
    xmlCtxtDumpSpaces(ctxt);
    if ent.is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"Entity declaration is NULL\n\0" as *const u8 as *const i8,
            );
        }
        return;
    }
    if (*ent).type_0 as u32 != XML_ENTITY_DECL as i32 as u32 {
        xmlDebugErr(
            ctxt,
            XML_CHECK_NOT_ENTITY_DECL as i32,
            b"Node is not an entity declaration\0" as *const u8 as *const i8,
        );
        return;
    }
    if !((*ent).name).is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"ENTITYDECL(\0" as *const u8 as *const i8,
            );
            xmlCtxtDumpString(ctxt, (*ent).name);
            fprintf((*ctxt).output, b")\0" as *const u8 as *const i8);
        }
    } else {
        xmlDebugErr(
            ctxt,
            XML_CHECK_NO_NAME as i32,
            b"Entity declaration has no name\0" as *const u8 as *const i8,
        );
    }
    if (*ctxt).check == 0 {
        match (*ent).etype as u32 {
            1 => {
                fprintf(
                    (*ctxt).output,
                    b", internal\n\0" as *const u8 as *const i8,
                );
            }
            2 => {
                fprintf(
                    (*ctxt).output,
                    b", external parsed\n\0" as *const u8 as *const i8,
                );
            }
            3 => {
                fprintf(
                    (*ctxt).output,
                    b", unparsed\n\0" as *const u8 as *const i8,
                );
            }
            4 => {
                fprintf(
                    (*ctxt).output,
                    b", parameter\n\0" as *const u8 as *const i8,
                );
            }
            5 => {
                fprintf(
                    (*ctxt).output,
                    b", external parameter\n\0" as *const u8 as *const i8,
                );
            }
            6 => {
                fprintf(
                    (*ctxt).output,
                    b", predefined\n\0" as *const u8 as *const i8,
                );
            }
            _ => {}
        }
        if !((*ent).ExternalID).is_null() {
            xmlCtxtDumpSpaces(ctxt);
            fprintf(
                (*ctxt).output,
                b" ExternalID=%s\n\0" as *const u8 as *const i8,
                (*ent).ExternalID as *mut i8,
            );
        }
        if !((*ent).SystemID).is_null() {
            xmlCtxtDumpSpaces(ctxt);
            fprintf(
                (*ctxt).output,
                b" SystemID=%s\n\0" as *const u8 as *const i8,
                (*ent).SystemID as *mut i8,
            );
        }
        if !((*ent).URI).is_null() {
            xmlCtxtDumpSpaces(ctxt);
            fprintf(
                (*ctxt).output,
                b" URI=%s\n\0" as *const u8 as *const i8,
                (*ent).URI as *mut i8,
            );
        }
        if !((*ent).content).is_null() {
            xmlCtxtDumpSpaces(ctxt);
            fprintf((*ctxt).output, b" content=\0" as *const u8 as *const i8);
            xmlCtxtDumpString(ctxt, (*ent).content);
            fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
        }
    }
    xmlCtxtGenericNodeCheck(ctxt, ent as xmlNodePtr);
}
unsafe extern "C" fn xmlCtxtDumpNamespace(mut ctxt: xmlDebugCtxtPtr, mut ns: xmlNsPtr) {
    xmlCtxtDumpSpaces(ctxt);
    if ns.is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"namespace node is NULL\n\0" as *const u8 as *const i8,
            );
        }
        return;
    }
    if (*ns).type_0 as u32 != XML_NAMESPACE_DECL as i32 as u32
    {
        xmlDebugErr(
            ctxt,
            XML_CHECK_NOT_NS_DECL as i32,
            b"Node is not a namespace declaration\0" as *const u8 as *const i8,
        );
        return;
    }
    if ((*ns).href).is_null() {
        if !((*ns).prefix).is_null() {
            xmlDebugErr3(
                ctxt,
                XML_CHECK_NO_HREF as i32,
                b"Incomplete namespace %s href=NULL\n\0" as *const u8
                    as *const i8,
                (*ns).prefix as *mut i8,
            );
        } else {
            xmlDebugErr(
                ctxt,
                XML_CHECK_NO_HREF as i32,
                b"Incomplete default namespace href=NULL\n\0" as *const u8
                    as *const i8,
            );
        }
    } else if (*ctxt).check == 0 {
        if !((*ns).prefix).is_null() {
            fprintf(
                (*ctxt).output,
                b"namespace %s href=\0" as *const u8 as *const i8,
                (*ns).prefix as *mut i8,
            );
        } else {
            fprintf(
                (*ctxt).output,
                b"default namespace href=\0" as *const u8 as *const i8,
            );
        }
        xmlCtxtDumpString(ctxt, (*ns).href);
        fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
    }
}
unsafe extern "C" fn xmlCtxtDumpNamespaceList(
    mut ctxt: xmlDebugCtxtPtr,
    mut ns: xmlNsPtr,
) {
    while !ns.is_null() {
        xmlCtxtDumpNamespace(ctxt, ns);
        ns = (*ns).next;
    }
}
unsafe extern "C" fn xmlCtxtDumpEntity(
    mut ctxt: xmlDebugCtxtPtr,
    mut ent: xmlEntityPtr,
) {
    xmlCtxtDumpSpaces(ctxt);
    if ent.is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"Entity is NULL\n\0" as *const u8 as *const i8,
            );
        }
        return;
    }
    if (*ctxt).check == 0 {
        match (*ent).etype as u32 {
            1 => {
                fprintf(
                    (*ctxt).output,
                    b"INTERNAL_GENERAL_ENTITY \0" as *const u8 as *const i8,
                );
            }
            2 => {
                fprintf(
                    (*ctxt).output,
                    b"EXTERNAL_GENERAL_PARSED_ENTITY \0" as *const u8
                        as *const i8,
                );
            }
            3 => {
                fprintf(
                    (*ctxt).output,
                    b"EXTERNAL_GENERAL_UNPARSED_ENTITY \0" as *const u8
                        as *const i8,
                );
            }
            4 => {
                fprintf(
                    (*ctxt).output,
                    b"INTERNAL_PARAMETER_ENTITY \0" as *const u8 as *const i8,
                );
            }
            5 => {
                fprintf(
                    (*ctxt).output,
                    b"EXTERNAL_PARAMETER_ENTITY \0" as *const u8 as *const i8,
                );
            }
            _ => {
                fprintf(
                    (*ctxt).output,
                    b"ENTITY_%d ! \0" as *const u8 as *const i8,
                    (*ent).etype as i32,
                );
            }
        }
        fprintf(
            (*ctxt).output,
            b"%s\n\0" as *const u8 as *const i8,
            (*ent).name,
        );
        if !((*ent).ExternalID).is_null() {
            xmlCtxtDumpSpaces(ctxt);
            fprintf(
                (*ctxt).output,
                b"ExternalID=%s\n\0" as *const u8 as *const i8,
                (*ent).ExternalID as *mut i8,
            );
        }
        if !((*ent).SystemID).is_null() {
            xmlCtxtDumpSpaces(ctxt);
            fprintf(
                (*ctxt).output,
                b"SystemID=%s\n\0" as *const u8 as *const i8,
                (*ent).SystemID as *mut i8,
            );
        }
        if !((*ent).URI).is_null() {
            xmlCtxtDumpSpaces(ctxt);
            fprintf(
                (*ctxt).output,
                b"URI=%s\n\0" as *const u8 as *const i8,
                (*ent).URI as *mut i8,
            );
        }
        if !((*ent).content).is_null() {
            xmlCtxtDumpSpaces(ctxt);
            fprintf((*ctxt).output, b"content=\0" as *const u8 as *const i8);
            xmlCtxtDumpString(ctxt, (*ent).content);
            fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
        }
    }
}
unsafe extern "C" fn xmlCtxtDumpAttr(mut ctxt: xmlDebugCtxtPtr, mut attr: xmlAttrPtr) {
    xmlCtxtDumpSpaces(ctxt);
    if attr.is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"Attr is NULL\0" as *const u8 as *const i8,
            );
        }
        return;
    }
    if (*ctxt).check == 0 {
        fprintf((*ctxt).output, b"ATTRIBUTE \0" as *const u8 as *const i8);
        xmlCtxtDumpString(ctxt, (*attr).name);
        fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
        if !((*attr).children).is_null() {
            let fresh9 = &mut ((*ctxt).depth);
            *fresh9 += 1;
            xmlCtxtDumpNodeList(ctxt, (*attr).children);
            let fresh10 = &mut ((*ctxt).depth);
            *fresh10 -= 1;
        }
    }
    if ((*attr).name).is_null() {
        xmlDebugErr(
            ctxt,
            XML_CHECK_NO_NAME as i32,
            b"Attribute has no name\0" as *const u8 as *const i8,
        );
    }
    xmlCtxtGenericNodeCheck(ctxt, attr as xmlNodePtr);
}
unsafe extern "C" fn xmlCtxtDumpAttrList(
    mut ctxt: xmlDebugCtxtPtr,
    mut attr: xmlAttrPtr,
) {
    while !attr.is_null() {
        xmlCtxtDumpAttr(ctxt, attr);
        attr = (*attr).next;
    }
}
unsafe extern "C" fn xmlCtxtDumpOneNode(
    mut ctxt: xmlDebugCtxtPtr,
    mut node: xmlNodePtr,
) {
    if node.is_null() {
        if (*ctxt).check == 0 {
            xmlCtxtDumpSpaces(ctxt);
            fprintf(
                (*ctxt).output,
                b"node is NULL\n\0" as *const u8 as *const i8,
            );
        }
        return;
    }
    let fresh11 = &mut ((*ctxt).node);
    *fresh11 = node;
    match (*node).type_0 as u32 {
        1 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
                fprintf(
                    (*ctxt).output,
                    b"ELEMENT \0" as *const u8 as *const i8,
                );
                if !((*node).ns).is_null() && !((*(*node).ns).prefix).is_null() {
                    xmlCtxtDumpString(ctxt, (*(*node).ns).prefix);
                    fprintf((*ctxt).output, b":\0" as *const u8 as *const i8);
                }
                xmlCtxtDumpString(ctxt, (*node).name);
                fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
            }
        }
        2 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
            }
            fprintf(
                (*ctxt).output,
                b"Error, ATTRIBUTE found here\n\0" as *const u8 as *const i8,
            );
            xmlCtxtGenericNodeCheck(ctxt, node);
            return;
        }
        3 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
                if (*node).name == xmlStringTextNoenc.as_ptr() {
                    fprintf(
                        (*ctxt).output,
                        b"TEXT no enc\0" as *const u8 as *const i8,
                    );
                } else {
                    fprintf(
                        (*ctxt).output,
                        b"TEXT\0" as *const u8 as *const i8,
                    );
                }
                if (*ctxt).options & 1 as i32 != 0 {
                    if (*node).content
                        == &mut (*node).properties as *mut *mut _xmlAttr as *mut xmlChar
                    {
                        fprintf(
                            (*ctxt).output,
                            b" compact\n\0" as *const u8 as *const i8,
                        );
                    } else if xmlDictOwns((*ctxt).dict, (*node).content)
                            == 1 as i32
                        {
                        fprintf(
                            (*ctxt).output,
                            b" interned\n\0" as *const u8 as *const i8,
                        );
                    } else {
                        fprintf(
                            (*ctxt).output,
                            b"\n\0" as *const u8 as *const i8,
                        );
                    }
                } else {
                    fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
                }
            }
        }
        4 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
                fprintf(
                    (*ctxt).output,
                    b"CDATA_SECTION\n\0" as *const u8 as *const i8,
                );
            }
        }
        5 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
                fprintf(
                    (*ctxt).output,
                    b"ENTITY_REF(%s)\n\0" as *const u8 as *const i8,
                    (*node).name as *mut i8,
                );
            }
        }
        6 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
                fprintf(
                    (*ctxt).output,
                    b"ENTITY\n\0" as *const u8 as *const i8,
                );
            }
        }
        7 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
                fprintf(
                    (*ctxt).output,
                    b"PI %s\n\0" as *const u8 as *const i8,
                    (*node).name as *mut i8,
                );
            }
        }
        8 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
                fprintf(
                    (*ctxt).output,
                    b"COMMENT\n\0" as *const u8 as *const i8,
                );
            }
        }
        9 | 13 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
            }
            fprintf(
                (*ctxt).output,
                b"Error, DOCUMENT found here\n\0" as *const u8 as *const i8,
            );
            xmlCtxtGenericNodeCheck(ctxt, node);
            return;
        }
        10 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
                fprintf(
                    (*ctxt).output,
                    b"DOCUMENT_TYPE\n\0" as *const u8 as *const i8,
                );
            }
        }
        11 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
                fprintf(
                    (*ctxt).output,
                    b"DOCUMENT_FRAG\n\0" as *const u8 as *const i8,
                );
            }
        }
        12 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
                fprintf(
                    (*ctxt).output,
                    b"NOTATION\n\0" as *const u8 as *const i8,
                );
            }
        }
        14 => {
            xmlCtxtDumpDtdNode(ctxt, node as xmlDtdPtr);
            return;
        }
        15 => {
            xmlCtxtDumpElemDecl(ctxt, node as xmlElementPtr);
            return;
        }
        16 => {
            xmlCtxtDumpAttrDecl(ctxt, node as xmlAttributePtr);
            return;
        }
        17 => {
            xmlCtxtDumpEntityDecl(ctxt, node as xmlEntityPtr);
            return;
        }
        18 => {
            xmlCtxtDumpNamespace(ctxt, node as xmlNsPtr);
            return;
        }
        19 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
                fprintf(
                    (*ctxt).output,
                    b"INCLUDE START\n\0" as *const u8 as *const i8,
                );
            }
            return;
        }
        20 => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
                fprintf(
                    (*ctxt).output,
                    b"INCLUDE END\n\0" as *const u8 as *const i8,
                );
            }
            return;
        }
        _ => {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
            }
            xmlDebugErr2(
                ctxt,
                XML_CHECK_UNKNOWN_NODE as i32,
                b"Unknown node type %d\n\0" as *const u8 as *const i8,
                (*node).type_0 as i32,
            );
            return;
        }
    }
    if ((*node).doc).is_null() {
        if (*ctxt).check == 0 {
            xmlCtxtDumpSpaces(ctxt);
        }
        fprintf(
            (*ctxt).output,
            b"PBM: doc == NULL !!!\n\0" as *const u8 as *const i8,
        );
    }
    let fresh12 = &mut ((*ctxt).depth);
    *fresh12 += 1;
    if (*node).type_0 as u32 == XML_ELEMENT_NODE as i32 as u32
        && !((*node).nsDef).is_null()
    {
        xmlCtxtDumpNamespaceList(ctxt, (*node).nsDef);
    }
    if (*node).type_0 as u32 == XML_ELEMENT_NODE as i32 as u32
        && !((*node).properties).is_null()
    {
        xmlCtxtDumpAttrList(ctxt, (*node).properties);
    }
    if (*node).type_0 as u32
        != XML_ENTITY_REF_NODE as i32 as u32
    {
        if (*node).type_0 as u32
            != XML_ELEMENT_NODE as i32 as u32
            && !((*node).content).is_null()
        {
            if (*ctxt).check == 0 {
                xmlCtxtDumpSpaces(ctxt);
                fprintf(
                    (*ctxt).output,
                    b"content=\0" as *const u8 as *const i8,
                );
                xmlCtxtDumpString(ctxt, (*node).content);
                fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
            }
        }
    } else {
        let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
        ent = xmlGetDocEntity((*node).doc, (*node).name);
        if !ent.is_null() {
            xmlCtxtDumpEntity(ctxt, ent);
        }
    }
    let fresh13 = &mut ((*ctxt).depth);
    *fresh13 -= 1;
    xmlCtxtGenericNodeCheck(ctxt, node);
}
unsafe extern "C" fn xmlCtxtDumpNode(mut ctxt: xmlDebugCtxtPtr, mut node: xmlNodePtr) {
    if node.is_null() {
        if (*ctxt).check == 0 {
            xmlCtxtDumpSpaces(ctxt);
            fprintf(
                (*ctxt).output,
                b"node is NULL\n\0" as *const u8 as *const i8,
            );
        }
        return;
    }
    xmlCtxtDumpOneNode(ctxt, node);
    if (*node).type_0 as u32
        != XML_NAMESPACE_DECL as i32 as u32
        && !((*node).children).is_null()
        && (*node).type_0 as u32
            != XML_ENTITY_REF_NODE as i32 as u32
    {
        let fresh14 = &mut ((*ctxt).depth);
        *fresh14 += 1;
        xmlCtxtDumpNodeList(ctxt, (*node).children);
        let fresh15 = &mut ((*ctxt).depth);
        *fresh15 -= 1;
    }
}
unsafe extern "C" fn xmlCtxtDumpNodeList(
    mut ctxt: xmlDebugCtxtPtr,
    mut node: xmlNodePtr,
) {
    while !node.is_null() {
        xmlCtxtDumpNode(ctxt, node);
        node = (*node).next;
    }
}
unsafe extern "C" fn xmlCtxtDumpDocHead(mut ctxt: xmlDebugCtxtPtr, mut doc: xmlDocPtr) {
    if doc.is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"DOCUMENT == NULL !\n\0" as *const u8 as *const i8,
            );
        }
        return;
    }
    let fresh16 = &mut ((*ctxt).node);
    *fresh16 = doc as xmlNodePtr;
    match (*doc).type_0 as u32 {
        1 => {
            xmlDebugErr(
                ctxt,
                XML_CHECK_FOUND_ELEMENT as i32,
                b"Misplaced ELEMENT node\n\0" as *const u8 as *const i8,
            );
        }
        2 => {
            xmlDebugErr(
                ctxt,
                XML_CHECK_FOUND_ATTRIBUTE as i32,
                b"Misplaced ATTRIBUTE node\n\0" as *const u8 as *const i8,
            );
        }
        3 => {
            xmlDebugErr(
                ctxt,
                XML_CHECK_FOUND_TEXT as i32,
                b"Misplaced TEXT node\n\0" as *const u8 as *const i8,
            );
        }
        4 => {
            xmlDebugErr(
                ctxt,
                XML_CHECK_FOUND_CDATA as i32,
                b"Misplaced CDATA node\n\0" as *const u8 as *const i8,
            );
        }
        5 => {
            xmlDebugErr(
                ctxt,
                XML_CHECK_FOUND_ENTITYREF as i32,
                b"Misplaced ENTITYREF node\n\0" as *const u8 as *const i8,
            );
        }
        6 => {
            xmlDebugErr(
                ctxt,
                XML_CHECK_FOUND_ENTITY as i32,
                b"Misplaced ENTITY node\n\0" as *const u8 as *const i8,
            );
        }
        7 => {
            xmlDebugErr(
                ctxt,
                XML_CHECK_FOUND_PI as i32,
                b"Misplaced PI node\n\0" as *const u8 as *const i8,
            );
        }
        8 => {
            xmlDebugErr(
                ctxt,
                XML_CHECK_FOUND_COMMENT as i32,
                b"Misplaced COMMENT node\n\0" as *const u8 as *const i8,
            );
        }
        9 => {
            if (*ctxt).check == 0 {
                fprintf(
                    (*ctxt).output,
                    b"DOCUMENT\n\0" as *const u8 as *const i8,
                );
            }
        }
        13 => {
            if (*ctxt).check == 0 {
                fprintf(
                    (*ctxt).output,
                    b"HTML DOCUMENT\n\0" as *const u8 as *const i8,
                );
            }
        }
        10 => {
            xmlDebugErr(
                ctxt,
                XML_CHECK_FOUND_DOCTYPE as i32,
                b"Misplaced DOCTYPE node\n\0" as *const u8 as *const i8,
            );
        }
        11 => {
            xmlDebugErr(
                ctxt,
                XML_CHECK_FOUND_FRAGMENT as i32,
                b"Misplaced FRAGMENT node\n\0" as *const u8 as *const i8,
            );
        }
        12 => {
            xmlDebugErr(
                ctxt,
                XML_CHECK_FOUND_NOTATION as i32,
                b"Misplaced NOTATION node\n\0" as *const u8 as *const i8,
            );
        }
        _ => {
            xmlDebugErr2(
                ctxt,
                XML_CHECK_UNKNOWN_NODE as i32,
                b"Unknown node type %d\n\0" as *const u8 as *const i8,
                (*doc).type_0 as i32,
            );
        }
    };
}
unsafe extern "C" fn xmlCtxtDumpDocumentHead(
    mut ctxt: xmlDebugCtxtPtr,
    mut doc: xmlDocPtr,
) {
    if doc.is_null() {
        return;
    }
    xmlCtxtDumpDocHead(ctxt, doc);
    if (*ctxt).check == 0 {
        if !((*doc).name).is_null() {
            fprintf((*ctxt).output, b"name=\0" as *const u8 as *const i8);
            xmlCtxtDumpString(ctxt, (*doc).name as *mut xmlChar);
            fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
        }
        if !((*doc).version).is_null() {
            fprintf((*ctxt).output, b"version=\0" as *const u8 as *const i8);
            xmlCtxtDumpString(ctxt, (*doc).version);
            fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
        }
        if !((*doc).encoding).is_null() {
            fprintf((*ctxt).output, b"encoding=\0" as *const u8 as *const i8);
            xmlCtxtDumpString(ctxt, (*doc).encoding);
            fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
        }
        if !((*doc).URL).is_null() {
            fprintf((*ctxt).output, b"URL=\0" as *const u8 as *const i8);
            xmlCtxtDumpString(ctxt, (*doc).URL);
            fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
        }
        if (*doc).standalone != 0 {
            fprintf(
                (*ctxt).output,
                b"standalone=true\n\0" as *const u8 as *const i8,
            );
        }
    }
    if !((*doc).oldNs).is_null() {
        xmlCtxtDumpNamespaceList(ctxt, (*doc).oldNs);
    }
}
unsafe extern "C" fn xmlCtxtDumpDocument(mut ctxt: xmlDebugCtxtPtr, mut doc: xmlDocPtr) {
    if doc.is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"DOCUMENT == NULL !\n\0" as *const u8 as *const i8,
            );
        }
        return;
    }
    xmlCtxtDumpDocumentHead(ctxt, doc);
    if ((*doc).type_0 as u32 == XML_DOCUMENT_NODE as i32 as u32
        || (*doc).type_0 as u32
            == XML_HTML_DOCUMENT_NODE as i32 as u32)
        && !((*doc).children).is_null()
    {
        let fresh17 = &mut ((*ctxt).depth);
        *fresh17 += 1;
        xmlCtxtDumpNodeList(ctxt, (*doc).children);
        let fresh18 = &mut ((*ctxt).depth);
        *fresh18 -= 1;
    }
}
unsafe extern "C" fn xmlCtxtDumpEntityCallback(
    mut payload: *mut libc::c_void,
    mut data: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    let mut cur: xmlEntityPtr = payload as xmlEntityPtr;
    let mut ctxt: xmlDebugCtxtPtr = data as xmlDebugCtxtPtr;
    if cur.is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"Entity is NULL\0" as *const u8 as *const i8,
            );
        }
        return;
    }
    if (*ctxt).check == 0 {
        fprintf(
            (*ctxt).output,
            b"%s : \0" as *const u8 as *const i8,
            (*cur).name as *mut i8,
        );
        match (*cur).etype as u32 {
            1 => {
                fprintf(
                    (*ctxt).output,
                    b"INTERNAL GENERAL, \0" as *const u8 as *const i8,
                );
            }
            2 => {
                fprintf(
                    (*ctxt).output,
                    b"EXTERNAL PARSED, \0" as *const u8 as *const i8,
                );
            }
            3 => {
                fprintf(
                    (*ctxt).output,
                    b"EXTERNAL UNPARSED, \0" as *const u8 as *const i8,
                );
            }
            4 => {
                fprintf(
                    (*ctxt).output,
                    b"INTERNAL PARAMETER, \0" as *const u8 as *const i8,
                );
            }
            5 => {
                fprintf(
                    (*ctxt).output,
                    b"EXTERNAL PARAMETER, \0" as *const u8 as *const i8,
                );
            }
            _ => {
                xmlDebugErr2(
                    ctxt,
                    XML_CHECK_ENTITY_TYPE as i32,
                    b"Unknown entity type %d\n\0" as *const u8 as *const i8,
                    (*cur).etype as i32,
                );
            }
        }
        if !((*cur).ExternalID).is_null() {
            fprintf(
                (*ctxt).output,
                b"ID \"%s\"\0" as *const u8 as *const i8,
                (*cur).ExternalID as *mut i8,
            );
        }
        if !((*cur).SystemID).is_null() {
            fprintf(
                (*ctxt).output,
                b"SYSTEM \"%s\"\0" as *const u8 as *const i8,
                (*cur).SystemID as *mut i8,
            );
        }
        if !((*cur).orig).is_null() {
            fprintf(
                (*ctxt).output,
                b"\n orig \"%s\"\0" as *const u8 as *const i8,
                (*cur).orig as *mut i8,
            );
        }
        if (*cur).type_0 as u32
            != XML_ELEMENT_NODE as i32 as u32
            && !((*cur).content).is_null()
        {
            fprintf(
                (*ctxt).output,
                b"\n content \"%s\"\0" as *const u8 as *const i8,
                (*cur).content as *mut i8,
            );
        }
        fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
    }
}
unsafe extern "C" fn xmlCtxtDumpEntities(mut ctxt: xmlDebugCtxtPtr, mut doc: xmlDocPtr) {
    if doc.is_null() {
        return;
    }
    xmlCtxtDumpDocHead(ctxt, doc);
    if !((*doc).intSubset).is_null() && !((*(*doc).intSubset).entities).is_null() {
        let mut table: xmlEntitiesTablePtr = (*(*doc).intSubset).entities
            as xmlEntitiesTablePtr;
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"Entities in internal subset\n\0" as *const u8 as *const i8,
            );
        }
        xmlHashScan(
            table,
            Some(
                xmlCtxtDumpEntityCallback
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> (),
            ),
            ctxt as *mut libc::c_void,
        );
    } else {
        fprintf(
            (*ctxt).output,
            b"No entities in internal subset\n\0" as *const u8 as *const i8,
        );
    }
    if !((*doc).extSubset).is_null() && !((*(*doc).extSubset).entities).is_null() {
        let mut table_0: xmlEntitiesTablePtr = (*(*doc).extSubset).entities
            as xmlEntitiesTablePtr;
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"Entities in external subset\n\0" as *const u8 as *const i8,
            );
        }
        xmlHashScan(
            table_0,
            Some(
                xmlCtxtDumpEntityCallback
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> (),
            ),
            ctxt as *mut libc::c_void,
        );
    } else if (*ctxt).check == 0 {
        fprintf(
            (*ctxt).output,
            b"No entities in external subset\n\0" as *const u8 as *const i8,
        );
    }
}
unsafe extern "C" fn xmlCtxtDumpDTD(mut ctxt: xmlDebugCtxtPtr, mut dtd: xmlDtdPtr) {
    if dtd.is_null() {
        if (*ctxt).check == 0 {
            fprintf(
                (*ctxt).output,
                b"DTD is NULL\n\0" as *const u8 as *const i8,
            );
        }
        return;
    }
    xmlCtxtDumpDtdNode(ctxt, dtd);
    if ((*dtd).children).is_null() {
        fprintf(
            (*ctxt).output,
            b"    DTD is empty\n\0" as *const u8 as *const i8,
        );
    } else {
        let fresh19 = &mut ((*ctxt).depth);
        *fresh19 += 1;
        xmlCtxtDumpNodeList(ctxt, (*dtd).children);
        let fresh20 = &mut ((*ctxt).depth);
        *fresh20 -= 1;
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlDebugDumpString(
    mut output: *mut FILE,
    mut str: *const xmlChar,
) {
    let mut i: i32 = 0;
    if output.is_null() {
        output = stdout;
    }
    if str.is_null() {
        fprintf(output, b"(NULL)\0" as *const u8 as *const i8);
        return;
    }
    i = 0 as i32;
    while i < 40 as i32 {
        if *str.offset(i as isize) as i32 == 0 as i32 {
            return
        } else {
            if *str.offset(i as isize) as i32 == 0x20 as i32
                || 0x9 as i32 <= *str.offset(i as isize) as i32
                    && *str.offset(i as isize) as i32 <= 0xa as i32
                || *str.offset(i as isize) as i32 == 0xd as i32
            {
                fputc(' ' as i32, output);
            } else if *str.offset(i as isize) as i32 >= 0x80 as i32 {
                fprintf(
                    output,
                    b"#%X\0" as *const u8 as *const i8,
                    *str.offset(i as isize) as i32,
                );
            } else {
                fputc(*str.offset(i as isize) as i32, output);
            }
        }
        i += 1;
    }
    fprintf(output, b"...\0" as *const u8 as *const i8);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDebugDumpAttr(
    mut output: *mut FILE,
    mut attr: xmlAttrPtr,
    mut depth: i32,
) {
    let mut ctxt: xmlDebugCtxt = xmlDebugCtxt {
        output: 0 as *mut FILE,
        shift: [0; 101],
        depth: 0,
        doc: 0 as *mut xmlDoc,
        node: 0 as *mut xmlNode,
        dict: 0 as *mut xmlDict,
        check: 0,
        errors: 0,
        nodict: 0,
        options: 0,
    };
    if output.is_null() {
        return;
    }
    xmlCtxtDumpInitCtxt(&mut ctxt);
    ctxt.output = output;
    ctxt.depth = depth;
    xmlCtxtDumpAttr(&mut ctxt, attr);
    xmlCtxtDumpCleanCtxt(&mut ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDebugDumpEntities(
    mut output: *mut FILE,
    mut doc: xmlDocPtr,
) {
    let mut ctxt: xmlDebugCtxt = xmlDebugCtxt {
        output: 0 as *mut FILE,
        shift: [0; 101],
        depth: 0,
        doc: 0 as *mut xmlDoc,
        node: 0 as *mut xmlNode,
        dict: 0 as *mut xmlDict,
        check: 0,
        errors: 0,
        nodict: 0,
        options: 0,
    };
    if output.is_null() {
        return;
    }
    xmlCtxtDumpInitCtxt(&mut ctxt);
    ctxt.output = output;
    xmlCtxtDumpEntities(&mut ctxt, doc);
    xmlCtxtDumpCleanCtxt(&mut ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDebugDumpAttrList(
    mut output: *mut FILE,
    mut attr: xmlAttrPtr,
    mut depth: i32,
) {
    let mut ctxt: xmlDebugCtxt = xmlDebugCtxt {
        output: 0 as *mut FILE,
        shift: [0; 101],
        depth: 0,
        doc: 0 as *mut xmlDoc,
        node: 0 as *mut xmlNode,
        dict: 0 as *mut xmlDict,
        check: 0,
        errors: 0,
        nodict: 0,
        options: 0,
    };
    if output.is_null() {
        return;
    }
    xmlCtxtDumpInitCtxt(&mut ctxt);
    ctxt.output = output;
    ctxt.depth = depth;
    xmlCtxtDumpAttrList(&mut ctxt, attr);
    xmlCtxtDumpCleanCtxt(&mut ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDebugDumpOneNode(
    mut output: *mut FILE,
    mut node: xmlNodePtr,
    mut depth: i32,
) {
    let mut ctxt: xmlDebugCtxt = xmlDebugCtxt {
        output: 0 as *mut FILE,
        shift: [0; 101],
        depth: 0,
        doc: 0 as *mut xmlDoc,
        node: 0 as *mut xmlNode,
        dict: 0 as *mut xmlDict,
        check: 0,
        errors: 0,
        nodict: 0,
        options: 0,
    };
    if output.is_null() {
        return;
    }
    xmlCtxtDumpInitCtxt(&mut ctxt);
    ctxt.output = output;
    ctxt.depth = depth;
    xmlCtxtDumpOneNode(&mut ctxt, node);
    xmlCtxtDumpCleanCtxt(&mut ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDebugDumpNode(
    mut output: *mut FILE,
    mut node: xmlNodePtr,
    mut depth: i32,
) {
    let mut ctxt: xmlDebugCtxt = xmlDebugCtxt {
        output: 0 as *mut FILE,
        shift: [0; 101],
        depth: 0,
        doc: 0 as *mut xmlDoc,
        node: 0 as *mut xmlNode,
        dict: 0 as *mut xmlDict,
        check: 0,
        errors: 0,
        nodict: 0,
        options: 0,
    };
    if output.is_null() {
        output = stdout;
    }
    xmlCtxtDumpInitCtxt(&mut ctxt);
    ctxt.output = output;
    ctxt.depth = depth;
    xmlCtxtDumpNode(&mut ctxt, node);
    xmlCtxtDumpCleanCtxt(&mut ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDebugDumpNodeList(
    mut output: *mut FILE,
    mut node: xmlNodePtr,
    mut depth: i32,
) {
    let mut ctxt: xmlDebugCtxt = xmlDebugCtxt {
        output: 0 as *mut FILE,
        shift: [0; 101],
        depth: 0,
        doc: 0 as *mut xmlDoc,
        node: 0 as *mut xmlNode,
        dict: 0 as *mut xmlDict,
        check: 0,
        errors: 0,
        nodict: 0,
        options: 0,
    };
    if output.is_null() {
        output = stdout;
    }
    xmlCtxtDumpInitCtxt(&mut ctxt);
    ctxt.output = output;
    ctxt.depth = depth;
    xmlCtxtDumpNodeList(&mut ctxt, node);
    xmlCtxtDumpCleanCtxt(&mut ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDebugDumpDocumentHead(
    mut output: *mut FILE,
    mut doc: xmlDocPtr,
) {
    let mut ctxt: xmlDebugCtxt = xmlDebugCtxt {
        output: 0 as *mut FILE,
        shift: [0; 101],
        depth: 0,
        doc: 0 as *mut xmlDoc,
        node: 0 as *mut xmlNode,
        dict: 0 as *mut xmlDict,
        check: 0,
        errors: 0,
        nodict: 0,
        options: 0,
    };
    if output.is_null() {
        output = stdout;
    }
    xmlCtxtDumpInitCtxt(&mut ctxt);
    ctxt.options |= 1 as i32;
    ctxt.output = output;
    xmlCtxtDumpDocumentHead(&mut ctxt, doc);
    xmlCtxtDumpCleanCtxt(&mut ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDebugDumpDocument(
    mut output: *mut FILE,
    mut doc: xmlDocPtr,
) {
    let mut ctxt: xmlDebugCtxt = xmlDebugCtxt {
        output: 0 as *mut FILE,
        shift: [0; 101],
        depth: 0,
        doc: 0 as *mut xmlDoc,
        node: 0 as *mut xmlNode,
        dict: 0 as *mut xmlDict,
        check: 0,
        errors: 0,
        nodict: 0,
        options: 0,
    };
    if output.is_null() {
        output = stdout;
    }
    xmlCtxtDumpInitCtxt(&mut ctxt);
    ctxt.options |= 1 as i32;
    ctxt.output = output;
    xmlCtxtDumpDocument(&mut ctxt, doc);
    xmlCtxtDumpCleanCtxt(&mut ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDebugDumpDTD(mut output: *mut FILE, mut dtd: xmlDtdPtr) {
    let mut ctxt: xmlDebugCtxt = xmlDebugCtxt {
        output: 0 as *mut FILE,
        shift: [0; 101],
        depth: 0,
        doc: 0 as *mut xmlDoc,
        node: 0 as *mut xmlNode,
        dict: 0 as *mut xmlDict,
        check: 0,
        errors: 0,
        nodict: 0,
        options: 0,
    };
    if output.is_null() {
        output = stdout;
    }
    xmlCtxtDumpInitCtxt(&mut ctxt);
    ctxt.options |= 1 as i32;
    ctxt.output = output;
    xmlCtxtDumpDTD(&mut ctxt, dtd);
    xmlCtxtDumpCleanCtxt(&mut ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlDebugCheckDocument(
    mut output: *mut FILE,
    mut doc: xmlDocPtr,
) -> i32 {
    let mut ctxt: xmlDebugCtxt = xmlDebugCtxt {
        output: 0 as *mut FILE,
        shift: [0; 101],
        depth: 0,
        doc: 0 as *mut xmlDoc,
        node: 0 as *mut xmlNode,
        dict: 0 as *mut xmlDict,
        check: 0,
        errors: 0,
        nodict: 0,
        options: 0,
    };
    if output.is_null() {
        output = stdout;
    }
    xmlCtxtDumpInitCtxt(&mut ctxt);
    ctxt.output = output;
    ctxt.check = 1 as i32;
    xmlCtxtDumpDocument(&mut ctxt, doc);
    xmlCtxtDumpCleanCtxt(&mut ctxt);
    return ctxt.errors;
}
#[no_mangle]
pub unsafe extern "C" fn xmlLsCountNode(mut node: xmlNodePtr) -> i32 {
    let mut ret: i32 = 0 as i32;
    let mut list: xmlNodePtr = 0 as xmlNodePtr;
    if node.is_null() {
        return 0 as i32;
    }
    match (*node).type_0 as u32 {
        1 => {
            list = (*node).children;
        }
        9 | 13 => {
            list = (*(node as xmlDocPtr)).children;
        }
        2 => {
            list = (*(node as xmlAttrPtr)).children;
        }
        3 | 4 | 7 | 8 => {
            if !((*node).content).is_null() {
                ret = xmlStrlen((*node).content);
            }
        }
        5 | 10 | 6 | 11 | 12 | 14 | 15 | 16 | 17 | 18 | 19 | 20 => {
            ret = 1 as i32;
        }
        _ => {}
    }
    while !list.is_null() {
        list = (*list).next;
        ret += 1;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlLsOneNode(mut output: *mut FILE, mut node: xmlNodePtr) {
    if output.is_null() {
        return;
    }
    if node.is_null() {
        fprintf(output, b"NULL\n\0" as *const u8 as *const i8);
        return;
    }
    match (*node).type_0 as u32 {
        1 => {
            fprintf(output, b"-\0" as *const u8 as *const i8);
        }
        2 => {
            fprintf(output, b"a\0" as *const u8 as *const i8);
        }
        3 => {
            fprintf(output, b"t\0" as *const u8 as *const i8);
        }
        4 => {
            fprintf(output, b"C\0" as *const u8 as *const i8);
        }
        5 => {
            fprintf(output, b"e\0" as *const u8 as *const i8);
        }
        6 => {
            fprintf(output, b"E\0" as *const u8 as *const i8);
        }
        7 => {
            fprintf(output, b"p\0" as *const u8 as *const i8);
        }
        8 => {
            fprintf(output, b"c\0" as *const u8 as *const i8);
        }
        9 => {
            fprintf(output, b"d\0" as *const u8 as *const i8);
        }
        13 => {
            fprintf(output, b"h\0" as *const u8 as *const i8);
        }
        10 => {
            fprintf(output, b"T\0" as *const u8 as *const i8);
        }
        11 => {
            fprintf(output, b"F\0" as *const u8 as *const i8);
        }
        12 => {
            fprintf(output, b"N\0" as *const u8 as *const i8);
        }
        18 => {
            fprintf(output, b"n\0" as *const u8 as *const i8);
        }
        _ => {
            fprintf(output, b"?\0" as *const u8 as *const i8);
        }
    }
    if (*node).type_0 as u32
        != XML_NAMESPACE_DECL as i32 as u32
    {
        if !((*node).properties).is_null() {
            fprintf(output, b"a\0" as *const u8 as *const i8);
        } else {
            fprintf(output, b"-\0" as *const u8 as *const i8);
        }
        if !((*node).nsDef).is_null() {
            fprintf(output, b"n\0" as *const u8 as *const i8);
        } else {
            fprintf(output, b"-\0" as *const u8 as *const i8);
        }
    }
    fprintf(
        output,
        b" %8d \0" as *const u8 as *const i8,
        xmlLsCountNode(node),
    );
    match (*node).type_0 as u32 {
        1 => {
            if !((*node).name).is_null() {
                if !((*node).ns).is_null() && !((*(*node).ns).prefix).is_null() {
                    fprintf(
                        output,
                        b"%s:\0" as *const u8 as *const i8,
                        (*(*node).ns).prefix,
                    );
                }
                fprintf(
                    output,
                    b"%s\0" as *const u8 as *const i8,
                    (*node).name as *const i8,
                );
            }
        }
        2 => {
            if !((*node).name).is_null() {
                fprintf(
                    output,
                    b"%s\0" as *const u8 as *const i8,
                    (*node).name as *const i8,
                );
            }
        }
        3 => {
            if !((*node).content).is_null() {
                xmlDebugDumpString(output, (*node).content);
            }
        }
        5 => {
            if !((*node).name).is_null() {
                fprintf(
                    output,
                    b"%s\0" as *const u8 as *const i8,
                    (*node).name as *const i8,
                );
            }
        }
        6 => {
            if !((*node).name).is_null() {
                fprintf(
                    output,
                    b"%s\0" as *const u8 as *const i8,
                    (*node).name as *const i8,
                );
            }
        }
        7 => {
            if !((*node).name).is_null() {
                fprintf(
                    output,
                    b"%s\0" as *const u8 as *const i8,
                    (*node).name as *const i8,
                );
            }
        }
        4 | 8 | 9 | 13 | 10 | 11 | 12 => {}
        18 => {
            let mut ns: xmlNsPtr = node as xmlNsPtr;
            if ((*ns).prefix).is_null() {
                fprintf(
                    output,
                    b"default -> %s\0" as *const u8 as *const i8,
                    (*ns).href as *mut i8,
                );
            } else {
                fprintf(
                    output,
                    b"%s -> %s\0" as *const u8 as *const i8,
                    (*ns).prefix as *mut i8,
                    (*ns).href as *mut i8,
                );
            }
        }
        _ => {
            if !((*node).name).is_null() {
                fprintf(
                    output,
                    b"%s\0" as *const u8 as *const i8,
                    (*node).name as *const i8,
                );
            }
        }
    }
    fprintf(output, b"\n\0" as *const u8 as *const i8);
}
#[no_mangle]
pub extern "C" fn xmlBoolToText(mut boolval: i32) -> *const i8 {
    if boolval != 0 {
        return b"True\0" as *const u8 as *const i8
    } else {
        return b"False\0" as *const u8 as *const i8
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlShellPrintXPathError(
    mut errorType: i32,
    mut arg: *const i8,
) {
    let mut default_arg: *const i8 = b"Result\0" as *const u8
        as *const i8;
    if arg.is_null() {
        arg = default_arg;
    }
    match errorType {
        0 => {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"%s: no such node\n\0" as *const u8 as *const i8,
                arg,
            );
        }
        2 => {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"%s is a Boolean\n\0" as *const u8 as *const i8,
                arg,
            );
        }
        3 => {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"%s is a number\n\0" as *const u8 as *const i8,
                arg,
            );
        }
        4 => {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"%s is a string\n\0" as *const u8 as *const i8,
                arg,
            );
        }
        8 => {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"%s is user-defined\n\0" as *const u8 as *const i8,
                arg,
            );
        }
        9 => {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"%s is an XSLT value tree\n\0" as *const u8 as *const i8,
                arg,
            );
        }
        _ => {}
    };
}
unsafe extern "C" fn xmlShellPrintNodeCtxt(
    mut ctxt: xmlShellCtxtPtr,
    mut node: xmlNodePtr,
) {
    let mut fp: *mut FILE = 0 as *mut FILE;
    if node.is_null() {
        return;
    }
    if ctxt.is_null() {
        fp = stdout;
    } else {
        fp = (*ctxt).output;
    }
    if (*node).type_0 as u32 == XML_DOCUMENT_NODE as i32 as u32
    {
        xmlDocDump(fp, node as xmlDocPtr);
    } else if (*node).type_0 as u32
            == XML_ATTRIBUTE_NODE as i32 as u32
        {
        xmlDebugDumpAttrList(fp, node as xmlAttrPtr, 0 as i32);
    } else {
        xmlElemDump(fp, (*node).doc, node);
    }
    fprintf(fp, b"\n\0" as *const u8 as *const i8);
}
#[no_mangle]
pub unsafe extern "C" fn xmlShellPrintNode(mut node: xmlNodePtr) {
    xmlShellPrintNodeCtxt(0 as xmlShellCtxtPtr, node);
}
unsafe extern "C" fn xmlShellPrintXPathResultCtxt(
    mut ctxt: xmlShellCtxtPtr,
    mut list: xmlXPathObjectPtr,
) {
    if ctxt.is_null() {
        return;
    }
    if !list.is_null() {
        match (*list).type_0 as u32 {
            1 => {
                let mut indx: i32 = 0;
                if !((*list).nodesetval).is_null() {
                    indx = 0 as i32;
                    while indx < (*(*list).nodesetval).nodeNr {
                        xmlShellPrintNodeCtxt(
                            ctxt,
                            *((*(*list).nodesetval).nodeTab).offset(indx as isize),
                        );
                        indx += 1;
                    }
                } else {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"Empty node set\n\0" as *const u8 as *const i8,
                    );
                }
            }
            2 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Is a Boolean:%s\n\0" as *const u8 as *const i8,
                    xmlBoolToText((*list).boolval),
                );
            }
            3 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Is a number:%0g\n\0" as *const u8 as *const i8,
                    (*list).floatval,
                );
            }
            4 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Is a string:%s\n\0" as *const u8 as *const i8,
                    (*list).stringval,
                );
            }
            _ => {
                xmlShellPrintXPathError(
                    (*list).type_0 as i32,
                    0 as *const i8,
                );
            }
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlShellPrintXPathResult(mut list: xmlXPathObjectPtr) {
    xmlShellPrintXPathResultCtxt(0 as xmlShellCtxtPtr, list);
}
#[no_mangle]
pub unsafe extern "C" fn xmlShellList(
    mut ctxt: xmlShellCtxtPtr,
    mut arg: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    if ctxt.is_null() {
        return 0 as i32;
    }
    if node.is_null() {
        fprintf((*ctxt).output, b"NULL\n\0" as *const u8 as *const i8);
        return 0 as i32;
    }
    if (*node).type_0 as u32 == XML_DOCUMENT_NODE as i32 as u32
        || (*node).type_0 as u32
            == XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        cur = (*(node as xmlDocPtr)).children;
    } else if (*node).type_0 as u32
            == XML_NAMESPACE_DECL as i32 as u32
        {
        xmlLsOneNode((*ctxt).output, node);
        return 0 as i32;
    } else {
        if !((*node).children).is_null() {
            cur = (*node).children;
        } else {
            xmlLsOneNode((*ctxt).output, node);
            return 0 as i32;
        }
    }
    while !cur.is_null() {
        xmlLsOneNode((*ctxt).output, cur);
        cur = (*cur).next;
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlShellBase(
    mut ctxt: xmlShellCtxtPtr,
    mut arg: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    let mut base: *mut xmlChar = 0 as *mut xmlChar;
    if ctxt.is_null() {
        return 0 as i32;
    }
    if node.is_null() {
        fprintf((*ctxt).output, b"NULL\n\0" as *const u8 as *const i8);
        return 0 as i32;
    }
    base = xmlNodeGetBase((*node).doc, node as *const xmlNode);
    if base.is_null() {
        fprintf(
            (*ctxt).output,
            b" No base found !!!\n\0" as *const u8 as *const i8,
        );
    } else {
        fprintf((*ctxt).output, b"%s\n\0" as *const u8 as *const i8, base);
        xmlFree.expect("non-null function pointer")(base as *mut libc::c_void);
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlShellSetBase(
    mut ctxt: xmlShellCtxtPtr,
    mut arg: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    xmlNodeSetBase(node, arg as *mut xmlChar);
    return 0 as i32;
}
unsafe extern "C" fn xmlShellRegisterNamespace(
    mut ctxt: xmlShellCtxtPtr,
    mut arg: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    let mut nsListDup: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    let mut href: *mut xmlChar = 0 as *mut xmlChar;
    let mut next: *mut xmlChar = 0 as *mut xmlChar;
    nsListDup = xmlStrdup(arg as *mut xmlChar);
    next = nsListDup;
    while !next.is_null() {
        if *next as i32 == '\u{0}' as i32 {
            break;
        }
        prefix = next;
        next = xmlStrchr(next, '=' as i32 as xmlChar) as *mut xmlChar;
        if next.is_null() {
            fprintf(
                (*ctxt).output,
                b"setns: prefix=[nsuri] required\n\0" as *const u8 as *const i8,
            );
            xmlFree.expect("non-null function pointer")(nsListDup as *mut libc::c_void);
            return -(1 as i32);
        }
        let fresh21 = next;
        next = next.offset(1);
        *fresh21 = '\u{0}' as i32 as xmlChar;
        href = next;
        next = xmlStrchr(next, ' ' as i32 as xmlChar) as *mut xmlChar;
        if !next.is_null() {
            let fresh22 = next;
            next = next.offset(1);
            *fresh22 = '\u{0}' as i32 as xmlChar;
        }
        if xmlXPathRegisterNs((*ctxt).pctxt, prefix, href) != 0 as i32 {
            fprintf(
                (*ctxt).output,
                b"Error: unable to register NS with prefix=\"%s\" and href=\"%s\"\n\0"
                    as *const u8 as *const i8,
                prefix,
                href,
            );
            xmlFree.expect("non-null function pointer")(nsListDup as *mut libc::c_void);
            return -(1 as i32);
        }
    }
    xmlFree.expect("non-null function pointer")(nsListDup as *mut libc::c_void);
    return 0 as i32;
}
unsafe extern "C" fn xmlShellRegisterRootNamespaces(
    mut ctxt: xmlShellCtxtPtr,
    mut arg: *mut i8,
    mut root: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    if root.is_null()
        || (*root).type_0 as u32
            != XML_ELEMENT_NODE as i32 as u32
        || ((*root).nsDef).is_null() || ctxt.is_null() || ((*ctxt).pctxt).is_null()
    {
        return -(1 as i32);
    }
    ns = (*root).nsDef;
    while !ns.is_null() {
        if ((*ns).prefix).is_null() {
            xmlXPathRegisterNs(
                (*ctxt).pctxt,
                b"defaultns\0" as *const u8 as *const i8 as *mut xmlChar,
                (*ns).href,
            );
        } else {
            xmlXPathRegisterNs((*ctxt).pctxt, (*ns).prefix, (*ns).href);
        }
        ns = (*ns).next;
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlShellGrep(
    mut ctxt: xmlShellCtxtPtr,
    mut arg: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    if ctxt.is_null() {
        return 0 as i32;
    }
    if node.is_null() {
        return 0 as i32;
    }
    if arg.is_null() {
        return 0 as i32;
    }
    !(xmlStrchr(arg as *mut xmlChar, '?' as i32 as xmlChar)).is_null()
        || !(xmlStrchr(arg as *mut xmlChar, '*' as i32 as xmlChar)).is_null()
        || !(xmlStrchr(arg as *mut xmlChar, '.' as i32 as xmlChar)).is_null()
        || !(xmlStrchr(arg as *mut xmlChar, '[' as i32 as xmlChar)).is_null();
    while !node.is_null() {
        if (*node).type_0 as u32
            == XML_COMMENT_NODE as i32 as u32
        {
            if !(xmlStrstr((*node).content, arg as *mut xmlChar)).is_null() {
                fprintf(
                    (*ctxt).output,
                    b"%s : \0" as *const u8 as *const i8,
                    xmlGetNodePath(node as *const xmlNode),
                );
                xmlShellList(ctxt, 0 as *mut i8, node, 0 as xmlNodePtr);
            }
        } else if (*node).type_0 as u32
                == XML_TEXT_NODE as i32 as u32
            {
            if !(xmlStrstr((*node).content, arg as *mut xmlChar)).is_null() {
                fprintf(
                    (*ctxt).output,
                    b"%s : \0" as *const u8 as *const i8,
                    xmlGetNodePath((*node).parent),
                );
                xmlShellList(
                    ctxt,
                    0 as *mut i8,
                    (*node).parent,
                    0 as xmlNodePtr,
                );
            }
        }
        if (*node).type_0 as u32
            == XML_DOCUMENT_NODE as i32 as u32
            || (*node).type_0 as u32
                == XML_HTML_DOCUMENT_NODE as i32 as u32
        {
            node = (*(node as xmlDocPtr)).children;
        } else if !((*node).children).is_null()
                && (*node).type_0 as u32
                    != XML_ENTITY_REF_NODE as i32 as u32
            {
            node = (*node).children;
        } else if !((*node).next).is_null() {
            node = (*node).next;
        } else {
            while !node.is_null() {
                if !((*node).parent).is_null() {
                    node = (*node).parent;
                }
                if !((*node).next).is_null() {
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
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlShellDir(
    mut ctxt: xmlShellCtxtPtr,
    mut arg: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    if ctxt.is_null() {
        return 0 as i32;
    }
    if node.is_null() {
        fprintf((*ctxt).output, b"NULL\n\0" as *const u8 as *const i8);
        return 0 as i32;
    }
    if (*node).type_0 as u32 == XML_DOCUMENT_NODE as i32 as u32
        || (*node).type_0 as u32
            == XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        xmlDebugDumpDocumentHead((*ctxt).output, node as xmlDocPtr);
    } else if (*node).type_0 as u32
            == XML_ATTRIBUTE_NODE as i32 as u32
        {
        xmlDebugDumpAttr((*ctxt).output, node as xmlAttrPtr, 0 as i32);
    } else {
        xmlDebugDumpOneNode((*ctxt).output, node, 0 as i32);
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlShellSetContent(
    mut ctxt: xmlShellCtxtPtr,
    mut value: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    let mut results: xmlNodePtr = 0 as *mut xmlNode;
    let mut ret: xmlParserErrors = XML_ERR_OK;
    if ctxt.is_null() {
        return 0 as i32;
    }
    if node.is_null() {
        fprintf((*ctxt).output, b"NULL\n\0" as *const u8 as *const i8);
        return 0 as i32;
    }
    if value.is_null() {
        fprintf((*ctxt).output, b"NULL\n\0" as *const u8 as *const i8);
        return 0 as i32;
    }
    ret = xmlParseInNodeContext(
        node,
        value,
        strlen(value) as i32,
        0 as i32,
        &mut results,
    );
    if ret as u32 == XML_ERR_OK as i32 as u32 {
        if !((*node).children).is_null() {
            xmlFreeNodeList((*node).children);
            let fresh23 = &mut ((*node).children);
            *fresh23 = 0 as *mut _xmlNode;
            let fresh24 = &mut ((*node).last);
            *fresh24 = 0 as *mut _xmlNode;
        }
        xmlAddChildList(node, results);
    } else {
        fprintf(
            (*ctxt).output,
            b"failed to parse content\n\0" as *const u8 as *const i8,
        );
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlShellRNGValidate(
    mut sctxt: xmlShellCtxtPtr,
    mut schemas: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    let mut relaxngschemas: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut ctxt: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut vctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut ret: i32 = 0;
    ctxt = xmlRelaxNGNewParserCtxt(schemas);
    xmlRelaxNGSetParserErrors(
        ctxt,
        *__xmlGenericError(),
        *__xmlGenericError(),
        0 as *mut libc::c_void,
    );
    relaxngschemas = xmlRelaxNGParse(ctxt);
    xmlRelaxNGFreeParserCtxt(ctxt);
    if relaxngschemas.is_null() {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Relax-NG schema %s failed to compile\n\0" as *const u8
                as *const i8,
            schemas,
        );
        return -(1 as i32);
    }
    vctxt = xmlRelaxNGNewValidCtxt(relaxngschemas);
    xmlRelaxNGSetValidErrors(
        vctxt,
        *__xmlGenericError(),
        *__xmlGenericError(),
        0 as *mut libc::c_void,
    );
    ret = xmlRelaxNGValidateDoc(vctxt, (*sctxt).doc);
    if ret == 0 as i32 {
        fprintf(
            stderr,
            b"%s validates\n\0" as *const u8 as *const i8,
            (*sctxt).filename,
        );
    } else if ret > 0 as i32 {
        fprintf(
            stderr,
            b"%s fails to validate\n\0" as *const u8 as *const i8,
            (*sctxt).filename,
        );
    } else {
        fprintf(
            stderr,
            b"%s validation generated an internal error\n\0" as *const u8
                as *const i8,
            (*sctxt).filename,
        );
    }
    xmlRelaxNGFreeValidCtxt(vctxt);
    if !relaxngschemas.is_null() {
        xmlRelaxNGFree(relaxngschemas);
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlShellCat(
    mut ctxt: xmlShellCtxtPtr,
    mut arg: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    if ctxt.is_null() {
        return 0 as i32;
    }
    if node.is_null() {
        fprintf((*ctxt).output, b"NULL\n\0" as *const u8 as *const i8);
        return 0 as i32;
    }
    if (*(*ctxt).doc).type_0 as u32
        == XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        if (*node).type_0 as u32
            == XML_HTML_DOCUMENT_NODE as i32 as u32
        {
            htmlDocDump((*ctxt).output, node as htmlDocPtr);
        } else {
            htmlNodeDumpFile((*ctxt).output, (*ctxt).doc, node);
        }
    } else if (*node).type_0 as u32
            == XML_DOCUMENT_NODE as i32 as u32
        {
        xmlDocDump((*ctxt).output, node as xmlDocPtr);
    } else {
        xmlElemDump((*ctxt).output, (*ctxt).doc, node);
    }
    fprintf((*ctxt).output, b"\n\0" as *const u8 as *const i8);
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlShellLoad(
    mut ctxt: xmlShellCtxtPtr,
    mut filename: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut html: i32 = 0 as i32;
    if ctxt.is_null() || filename.is_null() {
        return -(1 as i32);
    }
    if !((*ctxt).doc).is_null() {
        html = ((*(*ctxt).doc).type_0 as u32
            == XML_HTML_DOCUMENT_NODE as i32 as u32) as i32;
    }
    if html != 0 {
        doc = htmlParseFile(filename, 0 as *const i8);
    } else {
        doc = xmlReadFile(filename, 0 as *const i8, 0 as i32);
    }
    if !doc.is_null() {
        if (*ctxt).loaded == 1 as i32 {
            xmlFreeDoc((*ctxt).doc);
        }
        (*ctxt).loaded = 1 as i32;
        xmlXPathFreeContext((*ctxt).pctxt);
        xmlFree
            .expect("non-null function pointer")((*ctxt).filename as *mut libc::c_void);
        let fresh25 = &mut ((*ctxt).doc);
        *fresh25 = doc;
        let fresh26 = &mut ((*ctxt).node);
        *fresh26 = doc as xmlNodePtr;
        let fresh27 = &mut ((*ctxt).pctxt);
        *fresh27 = xmlXPathNewContext(doc);
        let fresh28 = &mut ((*ctxt).filename);
        *fresh28 = xmlCanonicPath(filename as *mut xmlChar) as *mut i8;
    } else {
        return -(1 as i32)
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlShellWrite(
    mut ctxt: xmlShellCtxtPtr,
    mut filename: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    if node.is_null() {
        return -(1 as i32);
    }
    if filename.is_null()
        || *filename.offset(0 as i32 as isize) as i32 == 0 as i32
    {
        return -(1 as i32);
    }
    match (*node).type_0 as u32 {
        9 => {
            if xmlSaveFile(filename, (*ctxt).doc) < -(1 as i32) {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Failed to write to %s\n\0" as *const u8 as *const i8,
                    filename,
                );
                return -(1 as i32);
            }
        }
        13 => {
            if htmlSaveFile(filename, (*ctxt).doc) < 0 as i32 {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Failed to write to %s\n\0" as *const u8 as *const i8,
                    filename,
                );
                return -(1 as i32);
            }
        }
        _ => {
            let mut f: *mut FILE = 0 as *mut FILE;
            f = fopen(filename, b"w\0" as *const u8 as *const i8);
            if f.is_null() {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Failed to write to %s\n\0" as *const u8 as *const i8,
                    filename,
                );
                return -(1 as i32);
            }
            xmlElemDump(f, (*ctxt).doc, node);
            fclose(f);
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlShellSave(
    mut ctxt: xmlShellCtxtPtr,
    mut filename: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    if ctxt.is_null() || ((*ctxt).doc).is_null() {
        return -(1 as i32);
    }
    if filename.is_null()
        || *filename.offset(0 as i32 as isize) as i32 == 0 as i32
    {
        filename = (*ctxt).filename;
    }
    if filename.is_null() {
        return -(1 as i32);
    }
    match (*(*ctxt).doc).type_0 as u32 {
        9 => {
            if xmlSaveFile(filename, (*ctxt).doc) < 0 as i32 {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Failed to save to %s\n\0" as *const u8 as *const i8,
                    filename,
                );
            }
        }
        13 => {
            if htmlSaveFile(filename, (*ctxt).doc) < 0 as i32 {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Failed to save to %s\n\0" as *const u8 as *const i8,
                    filename,
                );
            }
        }
        _ => {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"To save to subparts of a document use the 'write' command\n\0"
                    as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlShellValidate(
    mut ctxt: xmlShellCtxtPtr,
    mut dtd: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
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
    let mut res: i32 = -(1 as i32);
    if ctxt.is_null() || ((*ctxt).doc).is_null() {
        return -(1 as i32);
    }
    vctxt.userData = 0 as *mut libc::c_void;
    vctxt.error = *__xmlGenericError();
    vctxt.warning = *__xmlGenericError();
    if dtd.is_null()
        || *dtd.offset(0 as i32 as isize) as i32 == 0 as i32
    {
        res = xmlValidateDocument(&mut vctxt, (*ctxt).doc);
    } else {
        let mut subset: xmlDtdPtr = 0 as *mut xmlDtd;
        subset = xmlParseDTD(0 as *const xmlChar, dtd as *mut xmlChar);
        if !subset.is_null() {
            res = xmlValidateDtd(&mut vctxt, (*ctxt).doc, subset);
            xmlFreeDtd(subset);
        }
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlShellDu(
    mut ctxt: xmlShellCtxtPtr,
    mut arg: *mut i8,
    mut tree: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut indent: i32 = 0 as i32;
    let mut i: i32 = 0;
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if tree.is_null() {
        return -(1 as i32);
    }
    node = tree;
    while !node.is_null() {
        if (*node).type_0 as u32
            == XML_DOCUMENT_NODE as i32 as u32
            || (*node).type_0 as u32
                == XML_HTML_DOCUMENT_NODE as i32 as u32
        {
            fprintf((*ctxt).output, b"/\n\0" as *const u8 as *const i8);
        } else if (*node).type_0 as u32
                == XML_ELEMENT_NODE as i32 as u32
            {
            i = 0 as i32;
            while i < indent {
                fprintf((*ctxt).output, b"  \0" as *const u8 as *const i8);
                i += 1;
            }
            if !((*node).ns).is_null() && !((*(*node).ns).prefix).is_null() {
                fprintf(
                    (*ctxt).output,
                    b"%s:\0" as *const u8 as *const i8,
                    (*(*node).ns).prefix,
                );
            }
            fprintf(
                (*ctxt).output,
                b"%s\n\0" as *const u8 as *const i8,
                (*node).name,
            );
        }
        if (*node).type_0 as u32
            == XML_DOCUMENT_NODE as i32 as u32
            || (*node).type_0 as u32
                == XML_HTML_DOCUMENT_NODE as i32 as u32
        {
            node = (*(node as xmlDocPtr)).children;
        } else if !((*node).children).is_null()
                && (*node).type_0 as u32
                    != XML_ENTITY_REF_NODE as i32 as u32
            {
            node = (*node).children;
            indent += 1;
        } else if node != tree && !((*node).next).is_null() {
            node = (*node).next;
        } else if node != tree {
            while node != tree {
                if !((*node).parent).is_null() {
                    node = (*node).parent;
                    indent -= 1;
                }
                if node != tree && !((*node).next).is_null() {
                    node = (*node).next;
                    break;
                } else if ((*node).parent).is_null() {
                    node = 0 as xmlNodePtr;
                    break;
                } else {
                    if !(node == tree) {
                        continue;
                    }
                    node = 0 as xmlNodePtr;
                    break;
                }
            }
            if node == tree {
                node = 0 as xmlNodePtr;
            }
        } else {
            node = 0 as xmlNodePtr;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlShellPwd(
    mut ctxt: xmlShellCtxtPtr,
    mut buffer: *mut i8,
    mut node: xmlNodePtr,
    mut node2: xmlNodePtr,
) -> i32 {
    let mut path: *mut xmlChar = 0 as *mut xmlChar;
    if node.is_null() || buffer.is_null() {
        return -(1 as i32);
    }
    path = xmlGetNodePath(node as *const xmlNode);
    if path.is_null() {
        return -(1 as i32);
    }
    snprintf(
        buffer,
        499 as i32 as u64,
        b"%s\0" as *const u8 as *const i8,
        path,
    );
    *buffer.offset(499 as i32 as isize) = '0' as i32 as i8;
    xmlFree.expect("non-null function pointer")(path as *mut libc::c_void);
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlShell(
    mut doc: xmlDocPtr,
    mut filename: *mut i8,
    mut input: xmlShellReadlineFunc,
    mut output: *mut FILE,
) {
    let mut prompt: [i8; 500] = *::std::mem::transmute::<
        &[u8; 500],
        &mut [i8; 500],
    >(
        b"/ > \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut cmdline: *mut i8 = 0 as *mut i8;
    let mut cur: *mut i8 = 0 as *mut i8;
    let mut command: [i8; 100] = [0; 100];
    let mut arg: [i8; 400] = [0; 400];
    let mut i: i32 = 0;
    let mut ctxt: xmlShellCtxtPtr = 0 as *mut xmlShellCtxt;
    let mut list: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if doc.is_null() {
        return;
    }
    if filename.is_null() {
        return;
    }
    if input.is_none() {
        return;
    }
    if output.is_null() {
        output = stdout;
    }
    ctxt = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlShellCtxt>() as u64) as xmlShellCtxtPtr;
    if ctxt.is_null() {
        return;
    }
    (*ctxt).loaded = 0 as i32;
    let fresh29 = &mut ((*ctxt).doc);
    *fresh29 = doc;
    let fresh30 = &mut ((*ctxt).input);
    *fresh30 = input;
    let fresh31 = &mut ((*ctxt).output);
    *fresh31 = output;
    let fresh32 = &mut ((*ctxt).filename);
    *fresh32 = xmlStrdup(filename as *mut xmlChar) as *mut i8;
    let fresh33 = &mut ((*ctxt).node);
    *fresh33 = (*ctxt).doc as xmlNodePtr;
    let fresh34 = &mut ((*ctxt).pctxt);
    *fresh34 = xmlXPathNewContext((*ctxt).doc);
    if ((*ctxt).pctxt).is_null() {
        xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void);
        return;
    }
    loop {
        if (*ctxt).node == (*ctxt).doc as xmlNodePtr {
            snprintf(
                prompt.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 500]>() as u64,
                b"%s > \0" as *const u8 as *const i8,
                b"/\0" as *const u8 as *const i8,
            );
        } else if !((*ctxt).node).is_null() && !((*(*ctxt).node).name).is_null()
                && !((*(*ctxt).node).ns).is_null()
                && !((*(*(*ctxt).node).ns).prefix).is_null()
            {
            snprintf(
                prompt.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 500]>() as u64,
                b"%s:%s > \0" as *const u8 as *const i8,
                (*(*(*ctxt).node).ns).prefix,
                (*(*ctxt).node).name,
            );
        } else if !((*ctxt).node).is_null() && !((*(*ctxt).node).name).is_null() {
            snprintf(
                prompt.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 500]>() as u64,
                b"%s > \0" as *const u8 as *const i8,
                (*(*ctxt).node).name,
            );
        } else {
            snprintf(
                prompt.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 500]>() as u64,
                b"? > \0" as *const u8 as *const i8,
            );
        }
        prompt[(::std::mem::size_of::<[i8; 500]>() as u64)
            .wrapping_sub(1 as i32 as u64)
            as usize] = 0 as i32 as i8;
        cmdline = ((*ctxt).input)
            .expect("non-null function pointer")(prompt.as_mut_ptr());
        if cmdline.is_null() {
            break;
        }
        cur = cmdline;
        while *cur as i32 == ' ' as i32 || *cur as i32 == '\t' as i32 {
            cur = cur.offset(1);
        }
        i = 0 as i32;
        while *cur as i32 != ' ' as i32 && *cur as i32 != '\t' as i32
            && *cur as i32 != '\n' as i32 && *cur as i32 != '\r' as i32
        {
            if *cur as i32 == 0 as i32 {
                break;
            }
            let fresh35 = cur;
            cur = cur.offset(1);
            let fresh36 = i;
            i = i + 1;
            command[fresh36 as usize] = *fresh35;
        }
        command[i as usize] = 0 as i32 as i8;
        if i == 0 as i32 {
            continue;
        }
        while *cur as i32 == ' ' as i32 || *cur as i32 == '\t' as i32 {
            cur = cur.offset(1);
        }
        i = 0 as i32;
        while *cur as i32 != '\n' as i32 && *cur as i32 != '\r' as i32
            && *cur as i32 != 0 as i32
        {
            if *cur as i32 == 0 as i32 {
                break;
            }
            let fresh37 = cur;
            cur = cur.offset(1);
            let fresh38 = i;
            i = i + 1;
            arg[fresh38 as usize] = *fresh37;
        }
        arg[i as usize] = 0 as i32 as i8;
        if strcmp(command.as_mut_ptr(), b"exit\0" as *const u8 as *const i8)
            == 0
        {
            break;
        }
        if strcmp(command.as_mut_ptr(), b"quit\0" as *const u8 as *const i8)
            == 0
        {
            break;
        }
        if strcmp(command.as_mut_ptr(), b"bye\0" as *const u8 as *const i8)
            == 0
        {
            break;
        }
        if strcmp(command.as_mut_ptr(), b"help\0" as *const u8 as *const i8)
            == 0
        {
            fprintf(
                (*ctxt).output,
                b"\tbase         display XML base of the node\n\0" as *const u8
                    as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tsetbase URI  change the XML base of the node\n\0" as *const u8
                    as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tbye          leave shell\n\0" as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tcat [node]   display node or current node\n\0" as *const u8
                    as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tcd [path]    change directory to path or to root\n\0" as *const u8
                    as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tdir [path]   dumps information about the node (namespace, attributes, content)\n\0"
                    as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tdu [path]    show the structure of the subtree under path or the current node\n\0"
                    as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\texit         leave shell\n\0" as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\thelp         display this help\n\0" as *const u8
                    as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tfree         display memory usage\n\0" as *const u8
                    as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tload [name]  load a new document with name\n\0" as *const u8
                    as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tls [path]    list contents of path or the current directory\n\0"
                    as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tset xml_fragment replace the current node content with the fragment parsed in context\n\0"
                    as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\txpath expr   evaluate the XPath expression in that context and print the result\n\0"
                    as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tsetns nsreg  register a namespace to a prefix in the XPath evaluation context\n\0"
                    as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\t             format for nsreg is: prefix=[nsuri] (i.e. prefix= unsets a prefix)\n\0"
                    as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tsetrootns    register all namespace found on the root element\n\0"
                    as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\t             the default namespace if any uses 'defaultns' prefix\n\0"
                    as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tpwd          display current working directory\n\0" as *const u8
                    as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\twhereis      display absolute path of [path] or current working directory\n\0"
                    as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tquit         leave shell\n\0" as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tsave [name]  save this document to name or the original name\n\0"
                    as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\twrite [name] write the current node to the filename\n\0" as *const u8
                    as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tvalidate     check the document for errors\n\0" as *const u8
                    as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\trelaxng rng  validate the document against the Relax-NG schemas\n\0"
                    as *const u8 as *const i8,
            );
            fprintf(
                (*ctxt).output,
                b"\tgrep string  search for a string in the subtree\n\0" as *const u8
                    as *const i8,
            );
        } else if strcmp(
                command.as_mut_ptr(),
                b"validate\0" as *const u8 as *const i8,
            ) == 0
            {
            xmlShellValidate(ctxt, arg.as_mut_ptr(), 0 as xmlNodePtr, 0 as xmlNodePtr);
        } else if strcmp(
                command.as_mut_ptr(),
                b"load\0" as *const u8 as *const i8,
            ) == 0
            {
            xmlShellLoad(ctxt, arg.as_mut_ptr(), 0 as xmlNodePtr, 0 as xmlNodePtr);
        } else if strcmp(
                command.as_mut_ptr(),
                b"relaxng\0" as *const u8 as *const i8,
            ) == 0
            {
            xmlShellRNGValidate(
                ctxt,
                arg.as_mut_ptr(),
                0 as xmlNodePtr,
                0 as xmlNodePtr,
            );
        } else if strcmp(
                command.as_mut_ptr(),
                b"save\0" as *const u8 as *const i8,
            ) == 0
            {
            xmlShellSave(ctxt, arg.as_mut_ptr(), 0 as xmlNodePtr, 0 as xmlNodePtr);
        } else if strcmp(
                command.as_mut_ptr(),
                b"write\0" as *const u8 as *const i8,
            ) == 0
            {
            if arg[0 as i32 as usize] as i32 == 0 as i32 {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Write command requires a filename argument\n\0" as *const u8
                        as *const i8,
                );
            } else {
                xmlShellWrite(ctxt, arg.as_mut_ptr(), (*ctxt).node, 0 as xmlNodePtr);
            }
        } else if strcmp(
                command.as_mut_ptr(),
                b"grep\0" as *const u8 as *const i8,
            ) == 0
            {
            xmlShellGrep(ctxt, arg.as_mut_ptr(), (*ctxt).node, 0 as xmlNodePtr);
        } else if strcmp(
                command.as_mut_ptr(),
                b"free\0" as *const u8 as *const i8,
            ) == 0
            {
            if arg[0 as i32 as usize] as i32 == 0 as i32 {
                xmlMemShow((*ctxt).output, 0 as i32);
            } else {
                let mut len: i32 = 0 as i32;
                sscanf(
                    arg.as_mut_ptr(),
                    b"%d\0" as *const u8 as *const i8,
                    &mut len as *mut i32,
                );
                xmlMemShow((*ctxt).output, len);
            }
        } else if strcmp(
                command.as_mut_ptr(),
                b"pwd\0" as *const u8 as *const i8,
            ) == 0
            {
            let mut dir: [i8; 500] = [0; 500];
            if xmlShellPwd(ctxt, dir.as_mut_ptr(), (*ctxt).node, 0 as xmlNodePtr) == 0 {
                fprintf(
                    (*ctxt).output,
                    b"%s\n\0" as *const u8 as *const i8,
                    dir.as_mut_ptr(),
                );
            }
        } else if strcmp(
                command.as_mut_ptr(),
                b"du\0" as *const u8 as *const i8,
            ) == 0
            {
            if arg[0 as i32 as usize] as i32 == 0 as i32 {
                xmlShellDu(ctxt, 0 as *mut i8, (*ctxt).node, 0 as xmlNodePtr);
            } else {
                let fresh39 = &mut ((*(*ctxt).pctxt).node);
                *fresh39 = (*ctxt).node;
                let fresh40 = &mut ((*(*ctxt).pctxt).node);
                *fresh40 = (*ctxt).node;
                list = xmlXPathEval(arg.as_mut_ptr() as *mut xmlChar, (*ctxt).pctxt);
                if !list.is_null() {
                    match (*list).type_0 as u32 {
                        0 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s: no such node\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        1 => {
                            let mut indx: i32 = 0;
                            if !((*list).nodesetval).is_null() {
                                indx = 0 as i32;
                                while indx < (*(*list).nodesetval).nodeNr {
                                    xmlShellDu(
                                        ctxt,
                                        0 as *mut i8,
                                        *((*(*list).nodesetval).nodeTab).offset(indx as isize),
                                        0 as xmlNodePtr,
                                    );
                                    indx += 1;
                                }
                            }
                        }
                        2 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a Boolean\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        3 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a number\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        4 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a string\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        8 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is user-defined\n\0" as *const u8
                                    as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        9 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is an XSLT value tree\n\0" as *const u8
                                    as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        _ => {}
                    }
                    xmlXPathFreeObject(list);
                } else {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"%s: no such node\n\0" as *const u8 as *const i8,
                        arg.as_mut_ptr(),
                    );
                }
                let fresh41 = &mut ((*(*ctxt).pctxt).node);
                *fresh41 = 0 as xmlNodePtr;
            }
        } else if strcmp(
                command.as_mut_ptr(),
                b"base\0" as *const u8 as *const i8,
            ) == 0
            {
            xmlShellBase(ctxt, 0 as *mut i8, (*ctxt).node, 0 as xmlNodePtr);
        } else if strcmp(
                command.as_mut_ptr(),
                b"set\0" as *const u8 as *const i8,
            ) == 0
            {
            xmlShellSetContent(ctxt, arg.as_mut_ptr(), (*ctxt).node, 0 as xmlNodePtr);
        } else if strcmp(
                command.as_mut_ptr(),
                b"setns\0" as *const u8 as *const i8,
            ) == 0
            {
            if arg[0 as i32 as usize] as i32 == 0 as i32 {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"setns: prefix=[nsuri] required\n\0" as *const u8
                        as *const i8,
                );
            } else {
                xmlShellRegisterNamespace(
                    ctxt,
                    arg.as_mut_ptr(),
                    0 as xmlNodePtr,
                    0 as xmlNodePtr,
                );
            }
        } else if strcmp(
                command.as_mut_ptr(),
                b"setrootns\0" as *const u8 as *const i8,
            ) == 0
            {
            let mut root: xmlNodePtr = 0 as *mut xmlNode;
            root = xmlDocGetRootElement((*ctxt).doc as *const xmlDoc);
            xmlShellRegisterRootNamespaces(
                ctxt,
                0 as *mut i8,
                root,
                0 as xmlNodePtr,
            );
        } else if strcmp(
                command.as_mut_ptr(),
                b"xpath\0" as *const u8 as *const i8,
            ) == 0
            {
            if arg[0 as i32 as usize] as i32 == 0 as i32 {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"xpath: expression required\n\0" as *const u8 as *const i8,
                );
            } else {
                let fresh42 = &mut ((*(*ctxt).pctxt).node);
                *fresh42 = (*ctxt).node;
                list = xmlXPathEval(arg.as_mut_ptr() as *mut xmlChar, (*ctxt).pctxt);
                xmlXPathDebugDumpObject((*ctxt).output, list, 0 as i32);
                xmlXPathFreeObject(list);
            }
        } else if strcmp(
                command.as_mut_ptr(),
                b"setbase\0" as *const u8 as *const i8,
            ) == 0
            {
            xmlShellSetBase(ctxt, arg.as_mut_ptr(), (*ctxt).node, 0 as xmlNodePtr);
        } else if strcmp(
                command.as_mut_ptr(),
                b"ls\0" as *const u8 as *const i8,
            ) == 0
                || strcmp(
                    command.as_mut_ptr(),
                    b"dir\0" as *const u8 as *const i8,
                ) == 0
            {
            let mut dir_0: i32 = (strcmp(
                command.as_mut_ptr(),
                b"dir\0" as *const u8 as *const i8,
            ) == 0) as i32;
            if arg[0 as i32 as usize] as i32 == 0 as i32 {
                if dir_0 != 0 {
                    xmlShellDir(
                        ctxt,
                        0 as *mut i8,
                        (*ctxt).node,
                        0 as xmlNodePtr,
                    );
                } else {
                    xmlShellList(
                        ctxt,
                        0 as *mut i8,
                        (*ctxt).node,
                        0 as xmlNodePtr,
                    );
                }
            } else {
                let fresh43 = &mut ((*(*ctxt).pctxt).node);
                *fresh43 = (*ctxt).node;
                let fresh44 = &mut ((*(*ctxt).pctxt).node);
                *fresh44 = (*ctxt).node;
                list = xmlXPathEval(arg.as_mut_ptr() as *mut xmlChar, (*ctxt).pctxt);
                if !list.is_null() {
                    match (*list).type_0 as u32 {
                        0 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s: no such node\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        1 => {
                            let mut indx_0: i32 = 0;
                            if !((*list).nodesetval).is_null() {
                                indx_0 = 0 as i32;
                                while indx_0 < (*(*list).nodesetval).nodeNr {
                                    if dir_0 != 0 {
                                        xmlShellDir(
                                            ctxt,
                                            0 as *mut i8,
                                            *((*(*list).nodesetval).nodeTab).offset(indx_0 as isize),
                                            0 as xmlNodePtr,
                                        );
                                    } else {
                                        xmlShellList(
                                            ctxt,
                                            0 as *mut i8,
                                            *((*(*list).nodesetval).nodeTab).offset(indx_0 as isize),
                                            0 as xmlNodePtr,
                                        );
                                    }
                                    indx_0 += 1;
                                }
                            }
                        }
                        2 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a Boolean\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        3 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a number\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        4 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a string\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        8 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is user-defined\n\0" as *const u8
                                    as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        9 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is an XSLT value tree\n\0" as *const u8
                                    as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        _ => {}
                    }
                    xmlXPathFreeObject(list);
                } else {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"%s: no such node\n\0" as *const u8 as *const i8,
                        arg.as_mut_ptr(),
                    );
                }
                let fresh45 = &mut ((*(*ctxt).pctxt).node);
                *fresh45 = 0 as xmlNodePtr;
            }
        } else if strcmp(
                command.as_mut_ptr(),
                b"whereis\0" as *const u8 as *const i8,
            ) == 0
            {
            let mut dir_1: [i8; 500] = [0; 500];
            if arg[0 as i32 as usize] as i32 == 0 as i32 {
                if xmlShellPwd(ctxt, dir_1.as_mut_ptr(), (*ctxt).node, 0 as xmlNodePtr)
                    == 0
                {
                    fprintf(
                        (*ctxt).output,
                        b"%s\n\0" as *const u8 as *const i8,
                        dir_1.as_mut_ptr(),
                    );
                }
            } else {
                let fresh46 = &mut ((*(*ctxt).pctxt).node);
                *fresh46 = (*ctxt).node;
                list = xmlXPathEval(arg.as_mut_ptr() as *mut xmlChar, (*ctxt).pctxt);
                if !list.is_null() {
                    match (*list).type_0 as u32 {
                        0 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s: no such node\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        1 => {
                            let mut indx_1: i32 = 0;
                            if !((*list).nodesetval).is_null() {
                                indx_1 = 0 as i32;
                                while indx_1 < (*(*list).nodesetval).nodeNr {
                                    if xmlShellPwd(
                                        ctxt,
                                        dir_1.as_mut_ptr(),
                                        *((*(*list).nodesetval).nodeTab).offset(indx_1 as isize),
                                        0 as xmlNodePtr,
                                    ) == 0
                                    {
                                        fprintf(
                                            (*ctxt).output,
                                            b"%s\n\0" as *const u8 as *const i8,
                                            dir_1.as_mut_ptr(),
                                        );
                                    }
                                    indx_1 += 1;
                                }
                            }
                        }
                        2 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a Boolean\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        3 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a number\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        4 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a string\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        8 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is user-defined\n\0" as *const u8
                                    as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        9 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is an XSLT value tree\n\0" as *const u8
                                    as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        _ => {}
                    }
                    xmlXPathFreeObject(list);
                } else {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"%s: no such node\n\0" as *const u8 as *const i8,
                        arg.as_mut_ptr(),
                    );
                }
                let fresh47 = &mut ((*(*ctxt).pctxt).node);
                *fresh47 = 0 as xmlNodePtr;
            }
        } else if strcmp(
                command.as_mut_ptr(),
                b"cd\0" as *const u8 as *const i8,
            ) == 0
            {
            if arg[0 as i32 as usize] as i32 == 0 as i32 {
                let fresh48 = &mut ((*ctxt).node);
                *fresh48 = (*ctxt).doc as xmlNodePtr;
            } else {
                let mut l: i32 = 0;
                let fresh49 = &mut ((*(*ctxt).pctxt).node);
                *fresh49 = (*ctxt).node;
                l = strlen(arg.as_mut_ptr()) as i32;
                if l >= 2 as i32
                    && arg[(l - 1 as i32) as usize] as i32 == '/' as i32
                {
                    arg[(l - 1 as i32)
                        as usize] = 0 as i32 as i8;
                }
                list = xmlXPathEval(arg.as_mut_ptr() as *mut xmlChar, (*ctxt).pctxt);
                if !list.is_null() {
                    match (*list).type_0 as u32 {
                        0 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s: no such node\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        1 => {
                            if !((*list).nodesetval).is_null() {
                                if (*(*list).nodesetval).nodeNr == 1 as i32 {
                                    let fresh50 = &mut ((*ctxt).node);
                                    *fresh50 = *((*(*list).nodesetval).nodeTab)
                                        .offset(0 as i32 as isize);
                                    if !((*ctxt).node).is_null()
                                        && (*(*ctxt).node).type_0 as u32
                                            == XML_NAMESPACE_DECL as i32 as u32
                                    {
                                        (*__xmlGenericError())
                                            .expect(
                                                "non-null function pointer",
                                            )(
                                            *__xmlGenericErrorContext(),
                                            b"cannot cd to namespace\n\0" as *const u8
                                                as *const i8,
                                        );
                                        let fresh51 = &mut ((*ctxt).node);
                                        *fresh51 = 0 as xmlNodePtr;
                                    }
                                } else {
                                    (*__xmlGenericError())
                                        .expect(
                                            "non-null function pointer",
                                        )(
                                        *__xmlGenericErrorContext(),
                                        b"%s is a %d Node Set\n\0" as *const u8
                                            as *const i8,
                                        arg.as_mut_ptr(),
                                        (*(*list).nodesetval).nodeNr,
                                    );
                                }
                            } else {
                                (*__xmlGenericError())
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    *__xmlGenericErrorContext(),
                                    b"%s is an empty Node Set\n\0" as *const u8
                                        as *const i8,
                                    arg.as_mut_ptr(),
                                );
                            }
                        }
                        2 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a Boolean\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        3 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a number\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        4 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a string\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        8 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is user-defined\n\0" as *const u8
                                    as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        9 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is an XSLT value tree\n\0" as *const u8
                                    as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        _ => {}
                    }
                    xmlXPathFreeObject(list);
                } else {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"%s: no such node\n\0" as *const u8 as *const i8,
                        arg.as_mut_ptr(),
                    );
                }
                let fresh52 = &mut ((*(*ctxt).pctxt).node);
                *fresh52 = 0 as xmlNodePtr;
            }
        } else if strcmp(
                command.as_mut_ptr(),
                b"cat\0" as *const u8 as *const i8,
            ) == 0
            {
            if arg[0 as i32 as usize] as i32 == 0 as i32 {
                xmlShellCat(ctxt, 0 as *mut i8, (*ctxt).node, 0 as xmlNodePtr);
            } else {
                let fresh53 = &mut ((*(*ctxt).pctxt).node);
                *fresh53 = (*ctxt).node;
                let fresh54 = &mut ((*(*ctxt).pctxt).node);
                *fresh54 = (*ctxt).node;
                list = xmlXPathEval(arg.as_mut_ptr() as *mut xmlChar, (*ctxt).pctxt);
                if !list.is_null() {
                    match (*list).type_0 as u32 {
                        0 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s: no such node\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        1 => {
                            let mut indx_2: i32 = 0;
                            if !((*list).nodesetval).is_null() {
                                indx_2 = 0 as i32;
                                while indx_2 < (*(*list).nodesetval).nodeNr {
                                    if i > 0 as i32 {
                                        fprintf(
                                            (*ctxt).output,
                                            b" -------\n\0" as *const u8 as *const i8,
                                        );
                                    }
                                    xmlShellCat(
                                        ctxt,
                                        0 as *mut i8,
                                        *((*(*list).nodesetval).nodeTab).offset(indx_2 as isize),
                                        0 as xmlNodePtr,
                                    );
                                    indx_2 += 1;
                                }
                            }
                        }
                        2 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a Boolean\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        3 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a number\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        4 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is a string\n\0" as *const u8 as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        8 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is user-defined\n\0" as *const u8
                                    as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        9 => {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"%s is an XSLT value tree\n\0" as *const u8
                                    as *const i8,
                                arg.as_mut_ptr(),
                            );
                        }
                        _ => {}
                    }
                    xmlXPathFreeObject(list);
                } else {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"%s: no such node\n\0" as *const u8 as *const i8,
                        arg.as_mut_ptr(),
                    );
                }
                let fresh55 = &mut ((*(*ctxt).pctxt).node);
                *fresh55 = 0 as xmlNodePtr;
            }
        } else {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Unknown command %s\n\0" as *const u8 as *const i8,
                command.as_mut_ptr(),
            );
        }
        free(cmdline as *mut libc::c_void);
        cmdline = 0 as *mut i8;
    }
    xmlXPathFreeContext((*ctxt).pctxt);
    if (*ctxt).loaded != 0 {
        xmlFreeDoc((*ctxt).doc);
    }
    if !((*ctxt).filename).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).filename as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void);
    if !cmdline.is_null() {
        free(cmdline as *mut libc::c_void);
    }
}
