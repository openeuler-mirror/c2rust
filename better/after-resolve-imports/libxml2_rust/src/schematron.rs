use ::libc;
extern "C" {
    
    
    
    
    
    
    
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    fn sprintf(_: *mut i8, _: *const i8, _: ...) -> i32;
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
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn malloc(_: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::dict::xmlDictCreate;
pub use crate::src::dict::xmlDictFree;
pub use crate::src::dict::xmlDictLookup;
pub use crate::src::dict::xmlDictReference;
pub use crate::src::error::__xmlRaiseError;
pub use crate::src::error::__xmlSimpleError;
pub use crate::src::globals::__xmlGenericError;
pub use crate::src::globals::__xmlGenericErrorContext;
pub use crate::src::parser::xmlReadFile;
pub use crate::src::parser::xmlReadMemory;
pub use crate::src::pattern::xmlFreePattern;
pub use crate::src::pattern::xmlPatternMatch;
pub use crate::src::pattern::xmlPatterncompile;
pub use crate::src::tree::xmlDocGetRootElement;
pub use crate::src::tree::xmlFreeDoc;
pub use crate::src::tree::xmlGetLineNo;
pub use crate::src::tree::xmlGetNoNsProp;
pub use crate::src::tree::xmlGetNodePath;
pub use crate::src::tree::xmlNodeGetContent;
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrcat;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrlen;
pub use crate::src::xpath::xmlXPathCompiledEval;
pub use crate::src::xpath::xmlXPathCtxtCompile;
pub use crate::src::xpath::xmlXPathEval;
pub use crate::src::xpath::xmlXPathFreeCompExpr;
pub use crate::src::xpath::xmlXPathFreeContext;
pub use crate::src::xpath::xmlXPathFreeObject;
pub use crate::src::xpath::xmlXPathIsNaN;
pub use crate::src::xpath::xmlXPathNewContext;
pub use crate::src::xpath::xmlXPathRegisterNs;
pub use crate::src::xpath::xmlXPathRegisterVariableNS;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::pattern::_xmlPattern;
pub use crate::src::HTMLtree::_IO_codecvt;
pub use crate::src::buf::_IO_marker;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub use crate::src::globals::xmlRealloc;
pub use crate::src::python::types::_IO_wide_data;
pub use crate::src::xpath::_xmlXPathCompExpr;
pub type xmlChar = crate::src::HTMLparser::xmlChar;
pub type size_t = crate::src::HTMLparser::size_t;
pub type __off_t = crate::src::HTMLtree::__off_t;
pub type __off64_t = crate::src::HTMLtree::__off64_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::HTMLtree::_IO_FILE;
pub type _IO_lock_t = crate::src::HTMLtree::_IO_lock_t;
pub type FILE = crate::src::HTMLtree::FILE;
pub type xmlOutputCloseCallback = crate::src::HTMLtree::xmlOutputCloseCallback;
pub type xmlOutputWriteCallback = crate::src::HTMLtree::xmlOutputWriteCallback;
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
pub type xmlNodePtr = crate::src::HTMLparser::xmlNodePtr;
pub type xmlNode = crate::src::HTMLparser::xmlNode;
pub type xmlHashTablePtr = crate::src::HTMLparser::xmlHashTablePtr;
pub type xmlHashTable = crate::src::HTMLparser::xmlHashTable;
pub type xmlDictPtr = crate::src::HTMLparser::xmlDictPtr;
pub type xmlDict = crate::src::HTMLparser::xmlDict;
pub type xmlDocPtr = crate::src::HTMLparser::xmlDocPtr;
pub type xmlDoc = crate::src::HTMLparser::xmlDoc;
pub type xmlStructuredErrorFunc = crate::src::HTMLparser::xmlStructuredErrorFunc;
pub type xmlErrorPtr = crate::src::HTMLparser::xmlErrorPtr;
pub type xmlBufferAllocationScheme = crate::src::HTMLtree::xmlBufferAllocationScheme;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
// #[derive(Copy, Clone)]

pub type _xmlBuffer = crate::src::HTMLtree::_xmlBuffer;
pub type xmlBuffer = crate::src::HTMLtree::xmlBuffer;
pub type xmlBufferPtr = crate::src::HTMLtree::xmlBufferPtr;
pub type xmlNsPtr = crate::src::HTMLtree::xmlNsPtr;
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
pub type C2RustUnnamed_0 = u32;
pub const XML_BUF_OVERFLOW: C2RustUnnamed_0 = 7000;
pub const XML_I18N_NO_OUTPUT: C2RustUnnamed_0 = 6004;
pub const XML_I18N_CONV_FAILED: C2RustUnnamed_0 = 6003;
pub const XML_I18N_EXCESS_HANDLER: C2RustUnnamed_0 = 6002;
pub const XML_I18N_NO_HANDLER: C2RustUnnamed_0 = 6001;
pub const XML_I18N_NO_NAME: C2RustUnnamed_0 = 6000;
pub const XML_CHECK_NAME_NOT_NULL: C2RustUnnamed_0 = 5037;
pub const XML_CHECK_WRONG_NAME: C2RustUnnamed_0 = 5036;
pub const XML_CHECK_OUTSIDE_DICT: C2RustUnnamed_0 = 5035;
pub const XML_CHECK_NOT_NCNAME: C2RustUnnamed_0 = 5034;
pub const XML_CHECK_NO_DICT: C2RustUnnamed_0 = 5033;
pub const XML_CHECK_NOT_UTF8: C2RustUnnamed_0 = 5032;
pub const XML_CHECK_NS_ANCESTOR: C2RustUnnamed_0 = 5031;
pub const XML_CHECK_NS_SCOPE: C2RustUnnamed_0 = 5030;
pub const XML_CHECK_WRONG_PARENT: C2RustUnnamed_0 = 5029;
pub const XML_CHECK_NO_HREF: C2RustUnnamed_0 = 5028;
pub const XML_CHECK_NOT_NS_DECL: C2RustUnnamed_0 = 5027;
pub const XML_CHECK_NOT_ENTITY_DECL: C2RustUnnamed_0 = 5026;
pub const XML_CHECK_NOT_ELEM_DECL: C2RustUnnamed_0 = 5025;
pub const XML_CHECK_NOT_ATTR_DECL: C2RustUnnamed_0 = 5024;
pub const XML_CHECK_NOT_ATTR: C2RustUnnamed_0 = 5023;
pub const XML_CHECK_NOT_DTD: C2RustUnnamed_0 = 5022;
pub const XML_CHECK_WRONG_NEXT: C2RustUnnamed_0 = 5021;
pub const XML_CHECK_NO_NEXT: C2RustUnnamed_0 = 5020;
pub const XML_CHECK_WRONG_PREV: C2RustUnnamed_0 = 5019;
pub const XML_CHECK_NO_PREV: C2RustUnnamed_0 = 5018;
pub const XML_CHECK_WRONG_DOC: C2RustUnnamed_0 = 5017;
pub const XML_CHECK_NO_ELEM: C2RustUnnamed_0 = 5016;
pub const XML_CHECK_NO_NAME: C2RustUnnamed_0 = 5015;
pub const XML_CHECK_NO_DOC: C2RustUnnamed_0 = 5014;
pub const XML_CHECK_NO_PARENT: C2RustUnnamed_0 = 5013;
pub const XML_CHECK_ENTITY_TYPE: C2RustUnnamed_0 = 5012;
pub const XML_CHECK_UNKNOWN_NODE: C2RustUnnamed_0 = 5011;
pub const XML_CHECK_FOUND_NOTATION: C2RustUnnamed_0 = 5010;
pub const XML_CHECK_FOUND_FRAGMENT: C2RustUnnamed_0 = 5009;
pub const XML_CHECK_FOUND_DOCTYPE: C2RustUnnamed_0 = 5008;
pub const XML_CHECK_FOUND_COMMENT: C2RustUnnamed_0 = 5007;
pub const XML_CHECK_FOUND_PI: C2RustUnnamed_0 = 5006;
pub const XML_CHECK_FOUND_ENTITY: C2RustUnnamed_0 = 5005;
pub const XML_CHECK_FOUND_ENTITYREF: C2RustUnnamed_0 = 5004;
pub const XML_CHECK_FOUND_CDATA: C2RustUnnamed_0 = 5003;
pub const XML_CHECK_FOUND_TEXT: C2RustUnnamed_0 = 5002;
pub const XML_CHECK_FOUND_ATTRIBUTE: C2RustUnnamed_0 = 5001;
pub const XML_CHECK_FOUND_ELEMENT: C2RustUnnamed_0 = 5000;
pub const XML_MODULE_CLOSE: C2RustUnnamed_0 = 4901;
pub const XML_MODULE_OPEN: C2RustUnnamed_0 = 4900;
pub const XML_SCHEMATRONV_REPORT: C2RustUnnamed_0 = 4001;
pub const XML_SCHEMATRONV_ASSERT: C2RustUnnamed_0 = 4000;
pub const XML_SCHEMAP_COS_ALL_LIMITED: C2RustUnnamed_0 = 3091;
pub const XML_SCHEMAP_A_PROPS_CORRECT_3: C2RustUnnamed_0 = 3090;
pub const XML_SCHEMAP_AU_PROPS_CORRECT: C2RustUnnamed_0 = 3089;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_2: C2RustUnnamed_0 = 3088;
pub const XML_SCHEMAP_AG_PROPS_CORRECT: C2RustUnnamed_0 = 3087;
pub const XML_SCHEMAP_WARN_ATTR_POINTLESS_PROH: C2RustUnnamed_0 = 3086;
pub const XML_SCHEMAP_WARN_ATTR_REDECL_PROH: C2RustUnnamed_0 = 3085;
pub const XML_SCHEMAP_WARN_UNLOCATED_SCHEMA: C2RustUnnamed_0 = 3084;
pub const XML_SCHEMAP_WARN_SKIP_SCHEMA: C2RustUnnamed_0 = 3083;
pub const XML_SCHEMAP_SRC_IMPORT: C2RustUnnamed_0 = 3082;
pub const XML_SCHEMAP_SRC_REDEFINE: C2RustUnnamed_0 = 3081;
pub const XML_SCHEMAP_C_PROPS_CORRECT: C2RustUnnamed_0 = 3080;
pub const XML_SCHEMAP_A_PROPS_CORRECT_2: C2RustUnnamed_0 = 3079;
pub const XML_SCHEMAP_AU_PROPS_CORRECT_2: C2RustUnnamed_0 = 3078;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_3: C2RustUnnamed_0 = 3077;
pub const XML_SCHEMAP_SRC_CT_1: C2RustUnnamed_0 = 3076;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_2: C2RustUnnamed_0 = 3075;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_1: C2RustUnnamed_0 = 3074;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_3: C2RustUnnamed_0 = 3073;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_2: C2RustUnnamed_0 = 3072;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_1: C2RustUnnamed_0 = 3071;
pub const XML_SCHEMAP_NOT_DETERMINISTIC: C2RustUnnamed_0 = 3070;
pub const XML_SCHEMAP_INTERNAL: C2RustUnnamed_0 = 3069;
pub const XML_SCHEMAP_SRC_IMPORT_2_2: C2RustUnnamed_0 = 3068;
pub const XML_SCHEMAP_SRC_IMPORT_2_1: C2RustUnnamed_0 = 3067;
pub const XML_SCHEMAP_SRC_IMPORT_2: C2RustUnnamed_0 = 3066;
pub const XML_SCHEMAP_SRC_IMPORT_1_2: C2RustUnnamed_0 = 3065;
pub const XML_SCHEMAP_SRC_IMPORT_1_1: C2RustUnnamed_0 = 3064;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_1: C2RustUnnamed_0 = 3063;
pub const XML_SCHEMAP_CVC_SIMPLE_TYPE: C2RustUnnamed_0 = 3062;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_2: C2RustUnnamed_0 = 3061;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_1: C2RustUnnamed_0 = 3060;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_1: C2RustUnnamed_0 = 3059;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_1: C2RustUnnamed_0 = 3058;
pub const XML_SCHEMAP_NO_XSI: C2RustUnnamed_0 = 3057;
pub const XML_SCHEMAP_NO_XMLNS: C2RustUnnamed_0 = 3056;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_4: C2RustUnnamed_0 = 3055;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_2: C2RustUnnamed_0 = 3054;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_1: C2RustUnnamed_0 = 3053;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_2: C2RustUnnamed_0 = 3052;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_1: C2RustUnnamed_0 = 3051;
pub const XML_SCHEMAP_SRC_INCLUDE: C2RustUnnamed_0 = 3050;
pub const XML_SCHEMAP_E_PROPS_CORRECT_6: C2RustUnnamed_0 = 3049;
pub const XML_SCHEMAP_E_PROPS_CORRECT_5: C2RustUnnamed_0 = 3048;
pub const XML_SCHEMAP_E_PROPS_CORRECT_4: C2RustUnnamed_0 = 3047;
pub const XML_SCHEMAP_E_PROPS_CORRECT_3: C2RustUnnamed_0 = 3046;
pub const XML_SCHEMAP_E_PROPS_CORRECT_2: C2RustUnnamed_0 = 3045;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_2: C2RustUnnamed_0 = 3044;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_1: C2RustUnnamed_0 = 3043;
pub const XML_SCHEMAP_P_PROPS_CORRECT_1: C2RustUnnamed_0 = 3042;
pub const XML_SCHEMAP_SRC_ELEMENT_3: C2RustUnnamed_0 = 3041;
pub const XML_SCHEMAP_SRC_ELEMENT_2_2: C2RustUnnamed_0 = 3040;
pub const XML_SCHEMAP_SRC_ELEMENT_2_1: C2RustUnnamed_0 = 3039;
pub const XML_SCHEMAP_SRC_ELEMENT_1: C2RustUnnamed_0 = 3038;
pub const XML_SCHEMAP_S4S_ATTR_INVALID_VALUE: C2RustUnnamed_0 = 3037;
pub const XML_SCHEMAP_S4S_ATTR_MISSING: C2RustUnnamed_0 = 3036;
pub const XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED: C2RustUnnamed_0 = 3035;
pub const XML_SCHEMAP_S4S_ELEM_MISSING: C2RustUnnamed_0 = 3034;
pub const XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED: C2RustUnnamed_0 = 3033;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_2: C2RustUnnamed_0 = 3032;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_1: C2RustUnnamed_0 = 3031;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_5: C2RustUnnamed_0 = 3030;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_4: C2RustUnnamed_0 = 3029;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_3: C2RustUnnamed_0 = 3028;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_1: C2RustUnnamed_0 = 3027;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_2: C2RustUnnamed_0 = 3026;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1_2: C2RustUnnamed_0 = 3025;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1: C2RustUnnamed_0 = 3024;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_1: C2RustUnnamed_0 = 3023;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_5: C2RustUnnamed_0 = 3022;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_4: C2RustUnnamed_0 = 3021;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_3: C2RustUnnamed_0 = 3020;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_2: C2RustUnnamed_0 = 3019;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_1: C2RustUnnamed_0 = 3018;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_2: C2RustUnnamed_0 = 3017;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_1: C2RustUnnamed_0 = 3016;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_1: C2RustUnnamed_0 = 3015;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_2: C2RustUnnamed_0 = 3014;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_1: C2RustUnnamed_0 = 3013;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_2: C2RustUnnamed_0 = 3012;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_1: C2RustUnnamed_0 = 3011;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_3: C2RustUnnamed_0 = 3010;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_2: C2RustUnnamed_0 = 3009;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_1: C2RustUnnamed_0 = 3008;
pub const XML_SCHEMAP_SRC_UNION_MEMBERTYPES_OR_SIMPLETYPES: C2RustUnnamed_0 = 3007;
pub const XML_SCHEMAP_SRC_LIST_ITEMTYPE_OR_SIMPLETYPE: C2RustUnnamed_0 = 3006;
pub const XML_SCHEMAP_SRC_RESTRICTION_BASE_OR_SIMPLETYPE: C2RustUnnamed_0 = 3005;
pub const XML_SCHEMAP_SRC_RESOLVE: C2RustUnnamed_0 = 3004;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_4: C2RustUnnamed_0 = 3003;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_3: C2RustUnnamed_0 = 3002;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_2: C2RustUnnamed_0 = 3001;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_1: C2RustUnnamed_0 = 3000;
pub const XML_HTTP_UNKNOWN_HOST: C2RustUnnamed_0 = 2022;
pub const XML_HTTP_USE_IP: C2RustUnnamed_0 = 2021;
pub const XML_HTTP_URL_SYNTAX: C2RustUnnamed_0 = 2020;
pub const XML_FTP_URL_SYNTAX: C2RustUnnamed_0 = 2003;
pub const XML_FTP_ACCNT: C2RustUnnamed_0 = 2002;
pub const XML_FTP_EPSV_ANSWER: C2RustUnnamed_0 = 2001;
pub const XML_FTP_PASV_ANSWER: C2RustUnnamed_0 = 2000;
pub const XML_C14N_RELATIVE_NAMESPACE: C2RustUnnamed_0 = 1955;
pub const XML_C14N_UNKNOW_NODE: C2RustUnnamed_0 = 1954;
pub const XML_C14N_INVALID_NODE: C2RustUnnamed_0 = 1953;
pub const XML_C14N_CREATE_STACK: C2RustUnnamed_0 = 1952;
pub const XML_C14N_REQUIRES_UTF8: C2RustUnnamed_0 = 1951;
pub const XML_C14N_CREATE_CTXT: C2RustUnnamed_0 = 1950;
pub const XML_XPTR_EXTRA_OBJECTS: C2RustUnnamed_0 = 1903;
pub const XML_XPTR_EVAL_FAILED: C2RustUnnamed_0 = 1902;
pub const XML_XPTR_CHILDSEQ_START: C2RustUnnamed_0 = 1901;
pub const XML_XPTR_UNKNOWN_SCHEME: C2RustUnnamed_0 = 1900;
pub const XML_SCHEMAV_MISC: C2RustUnnamed_0 = 1879;
pub const XML_SCHEMAV_CVC_WILDCARD: C2RustUnnamed_0 = 1878;
pub const XML_SCHEMAV_CVC_IDC: C2RustUnnamed_0 = 1877;
pub const XML_SCHEMAV_CVC_TYPE_2: C2RustUnnamed_0 = 1876;
pub const XML_SCHEMAV_CVC_TYPE_1: C2RustUnnamed_0 = 1875;
pub const XML_SCHEMAV_CVC_AU: C2RustUnnamed_0 = 1874;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_1: C2RustUnnamed_0 = 1873;
pub const XML_SCHEMAV_DOCUMENT_ELEMENT_MISSING: C2RustUnnamed_0 = 1872;
pub const XML_SCHEMAV_ELEMENT_CONTENT: C2RustUnnamed_0 = 1871;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_2: C2RustUnnamed_0 = 1870;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_1: C2RustUnnamed_0 = 1869;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_4: C2RustUnnamed_0 = 1868;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_2: C2RustUnnamed_0 = 1867;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_1: C2RustUnnamed_0 = 1866;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_1: C2RustUnnamed_0 = 1865;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_4: C2RustUnnamed_0 = 1864;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_3: C2RustUnnamed_0 = 1863;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_2: C2RustUnnamed_0 = 1862;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_1: C2RustUnnamed_0 = 1861;
pub const XML_SCHEMAV_CVC_ELT_7: C2RustUnnamed_0 = 1860;
pub const XML_SCHEMAV_CVC_ELT_6: C2RustUnnamed_0 = 1859;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_2: C2RustUnnamed_0 = 1858;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_1: C2RustUnnamed_0 = 1857;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_1: C2RustUnnamed_0 = 1856;
pub const XML_SCHEMAV_CVC_ELT_5_2_1: C2RustUnnamed_0 = 1855;
pub const XML_SCHEMAV_CVC_ELT_5_1_2: C2RustUnnamed_0 = 1854;
pub const XML_SCHEMAV_CVC_ELT_5_1_1: C2RustUnnamed_0 = 1853;
pub const XML_SCHEMAV_CVC_ELT_4_3: C2RustUnnamed_0 = 1852;
pub const XML_SCHEMAV_CVC_ELT_4_2: C2RustUnnamed_0 = 1851;
pub const XML_SCHEMAV_CVC_ELT_4_1: C2RustUnnamed_0 = 1850;
pub const XML_SCHEMAV_CVC_ELT_3_2_2: C2RustUnnamed_0 = 1849;
pub const XML_SCHEMAV_CVC_ELT_3_2_1: C2RustUnnamed_0 = 1848;
pub const XML_SCHEMAV_CVC_ELT_3_1: C2RustUnnamed_0 = 1847;
pub const XML_SCHEMAV_CVC_ELT_2: C2RustUnnamed_0 = 1846;
pub const XML_SCHEMAV_CVC_ELT_1: C2RustUnnamed_0 = 1845;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_4: C2RustUnnamed_0 = 1844;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_3: C2RustUnnamed_0 = 1843;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2: C2RustUnnamed_0 = 1842;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_1: C2RustUnnamed_0 = 1841;
pub const XML_SCHEMAV_CVC_ENUMERATION_VALID: C2RustUnnamed_0 = 1840;
pub const XML_SCHEMAV_CVC_PATTERN_VALID: C2RustUnnamed_0 = 1839;
pub const XML_SCHEMAV_CVC_FRACTIONDIGITS_VALID: C2RustUnnamed_0 = 1838;
pub const XML_SCHEMAV_CVC_TOTALDIGITS_VALID: C2RustUnnamed_0 = 1837;
pub const XML_SCHEMAV_CVC_MAXEXCLUSIVE_VALID: C2RustUnnamed_0 = 1836;
pub const XML_SCHEMAV_CVC_MINEXCLUSIVE_VALID: C2RustUnnamed_0 = 1835;
pub const XML_SCHEMAV_CVC_MAXINCLUSIVE_VALID: C2RustUnnamed_0 = 1834;
pub const XML_SCHEMAV_CVC_MININCLUSIVE_VALID: C2RustUnnamed_0 = 1833;
pub const XML_SCHEMAV_CVC_MAXLENGTH_VALID: C2RustUnnamed_0 = 1832;
pub const XML_SCHEMAV_CVC_MINLENGTH_VALID: C2RustUnnamed_0 = 1831;
pub const XML_SCHEMAV_CVC_LENGTH_VALID: C2RustUnnamed_0 = 1830;
pub const XML_SCHEMAV_CVC_FACET_VALID: C2RustUnnamed_0 = 1829;
pub const XML_SCHEMAV_CVC_TYPE_3_1_2: C2RustUnnamed_0 = 1828;
pub const XML_SCHEMAV_CVC_TYPE_3_1_1: C2RustUnnamed_0 = 1827;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_3: C2RustUnnamed_0 = 1826;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2: C2RustUnnamed_0 = 1825;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1: C2RustUnnamed_0 = 1824;
pub const XML_SCHEMAV_FACET: C2RustUnnamed_0 = 1823;
pub const XML_SCHEMAV_VALUE: C2RustUnnamed_0 = 1822;
pub const XML_SCHEMAV_ATTRINVALID: C2RustUnnamed_0 = 1821;
pub const XML_SCHEMAV_ATTRUNKNOWN: C2RustUnnamed_0 = 1820;
pub const XML_SCHEMAV_NOTSIMPLE: C2RustUnnamed_0 = 1819;
pub const XML_SCHEMAV_INTERNAL: C2RustUnnamed_0 = 1818;
pub const XML_SCHEMAV_CONSTRUCT: C2RustUnnamed_0 = 1817;
pub const XML_SCHEMAV_NOTDETERMINIST: C2RustUnnamed_0 = 1816;
pub const XML_SCHEMAV_INVALIDELEM: C2RustUnnamed_0 = 1815;
pub const XML_SCHEMAV_INVALIDATTR: C2RustUnnamed_0 = 1814;
pub const XML_SCHEMAV_EXTRACONTENT: C2RustUnnamed_0 = 1813;
pub const XML_SCHEMAV_NOTNILLABLE: C2RustUnnamed_0 = 1812;
pub const XML_SCHEMAV_HAVEDEFAULT: C2RustUnnamed_0 = 1811;
pub const XML_SCHEMAV_ELEMCONT: C2RustUnnamed_0 = 1810;
pub const XML_SCHEMAV_NOTEMPTY: C2RustUnnamed_0 = 1809;
pub const XML_SCHEMAV_ISABSTRACT: C2RustUnnamed_0 = 1808;
pub const XML_SCHEMAV_NOROLLBACK: C2RustUnnamed_0 = 1807;
pub const XML_SCHEMAV_NOTYPE: C2RustUnnamed_0 = 1806;
pub const XML_SCHEMAV_WRONGELEM: C2RustUnnamed_0 = 1805;
pub const XML_SCHEMAV_MISSING: C2RustUnnamed_0 = 1804;
pub const XML_SCHEMAV_NOTTOPLEVEL: C2RustUnnamed_0 = 1803;
pub const XML_SCHEMAV_UNDECLAREDELEM: C2RustUnnamed_0 = 1802;
pub const XML_SCHEMAV_NOROOT: C2RustUnnamed_0 = 1801;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_3: C2RustUnnamed_0 = 1800;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_3: C2RustUnnamed_0 = 1799;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_2: C2RustUnnamed_0 = 1798;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_1: C2RustUnnamed_0 = 1797;
pub const XML_SCHEMAP_SRC_IMPORT_3_2: C2RustUnnamed_0 = 1796;
pub const XML_SCHEMAP_SRC_IMPORT_3_1: C2RustUnnamed_0 = 1795;
pub const XML_SCHEMAP_UNION_NOT_EXPRESSIBLE: C2RustUnnamed_0 = 1794;
pub const XML_SCHEMAP_INTERSECTION_NOT_EXPRESSIBLE: C2RustUnnamed_0 = 1793;
pub const XML_SCHEMAP_WILDCARD_INVALID_NS_MEMBER: C2RustUnnamed_0 = 1792;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_3: C2RustUnnamed_0 = 1791;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_2: C2RustUnnamed_0 = 1790;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_2: C2RustUnnamed_0 = 1789;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_1: C2RustUnnamed_0 = 1788;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_1: C2RustUnnamed_0 = 1787;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_5: C2RustUnnamed_0 = 1786;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_4: C2RustUnnamed_0 = 1785;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_3: C2RustUnnamed_0 = 1784;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_2: C2RustUnnamed_0 = 1783;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_1: C2RustUnnamed_0 = 1782;
pub const XML_SCHEMAP_REF_AND_CONTENT: C2RustUnnamed_0 = 1781;
pub const XML_SCHEMAP_INVALID_ATTR_NAME: C2RustUnnamed_0 = 1780;
pub const XML_SCHEMAP_MISSING_SIMPLETYPE_CHILD: C2RustUnnamed_0 = 1779;
pub const XML_SCHEMAP_INVALID_ATTR_INLINE_COMBINATION: C2RustUnnamed_0 = 1778;
pub const XML_SCHEMAP_INVALID_ATTR_COMBINATION: C2RustUnnamed_0 = 1777;
pub const XML_SCHEMAP_SUPERNUMEROUS_LIST_ITEM_TYPE: C2RustUnnamed_0 = 1776;
pub const XML_SCHEMAP_RECURSIVE: C2RustUnnamed_0 = 1775;
pub const XML_SCHEMAP_INVALID_ATTR_USE: C2RustUnnamed_0 = 1774;
pub const XML_SCHEMAP_UNKNOWN_MEMBER_TYPE: C2RustUnnamed_0 = 1773;
pub const XML_SCHEMAP_NOT_SCHEMA: C2RustUnnamed_0 = 1772;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NO_URI: C2RustUnnamed_0 = 1771;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NOT_URI: C2RustUnnamed_0 = 1770;
pub const XML_SCHEMAP_UNKNOWN_INCLUDE_CHILD: C2RustUnnamed_0 = 1769;
pub const XML_SCHEMAP_DEF_AND_PREFIX: C2RustUnnamed_0 = 1768;
pub const XML_SCHEMAP_UNKNOWN_PREFIX: C2RustUnnamed_0 = 1767;
pub const XML_SCHEMAP_FAILED_PARSE: C2RustUnnamed_0 = 1766;
pub const XML_SCHEMAP_REDEFINED_NOTATION: C2RustUnnamed_0 = 1765;
pub const XML_SCHEMAP_REDEFINED_ATTR: C2RustUnnamed_0 = 1764;
pub const XML_SCHEMAP_REDEFINED_ATTRGROUP: C2RustUnnamed_0 = 1763;
pub const XML_SCHEMAP_REDEFINED_ELEMENT: C2RustUnnamed_0 = 1762;
pub const XML_SCHEMAP_REDEFINED_TYPE: C2RustUnnamed_0 = 1761;
pub const XML_SCHEMAP_REDEFINED_GROUP: C2RustUnnamed_0 = 1760;
pub const XML_SCHEMAP_NOROOT: C2RustUnnamed_0 = 1759;
pub const XML_SCHEMAP_NOTHING_TO_PARSE: C2RustUnnamed_0 = 1758;
pub const XML_SCHEMAP_FAILED_LOAD: C2RustUnnamed_0 = 1757;
pub const XML_SCHEMAP_REGEXP_INVALID: C2RustUnnamed_0 = 1756;
pub const XML_SCHEMAP_ELEM_DEFAULT_FIXED: C2RustUnnamed_0 = 1755;
pub const XML_SCHEMAP_UNKNOWN_UNION_CHILD: C2RustUnnamed_0 = 1754;
pub const XML_SCHEMAP_UNKNOWN_TYPE: C2RustUnnamed_0 = 1753;
pub const XML_SCHEMAP_UNKNOWN_SIMPLETYPE_CHILD: C2RustUnnamed_0 = 1752;
pub const XML_SCHEMAP_UNKNOWN_SIMPLECONTENT_CHILD: C2RustUnnamed_0 = 1751;
pub const XML_SCHEMAP_UNKNOWN_SEQUENCE_CHILD: C2RustUnnamed_0 = 1750;
pub const XML_SCHEMAP_UNKNOWN_SCHEMAS_CHILD: C2RustUnnamed_0 = 1749;
pub const XML_SCHEMAP_UNKNOWN_RESTRICTION_CHILD: C2RustUnnamed_0 = 1748;
pub const XML_SCHEMAP_UNKNOWN_REF: C2RustUnnamed_0 = 1747;
pub const XML_SCHEMAP_UNKNOWN_PROCESSCONTENT_CHILD: C2RustUnnamed_0 = 1746;
pub const XML_SCHEMAP_UNKNOWN_NOTATION_CHILD: C2RustUnnamed_0 = 1745;
pub const XML_SCHEMAP_UNKNOWN_LIST_CHILD: C2RustUnnamed_0 = 1744;
pub const XML_SCHEMAP_UNKNOWN_IMPORT_CHILD: C2RustUnnamed_0 = 1743;
pub const XML_SCHEMAP_UNKNOWN_GROUP_CHILD: C2RustUnnamed_0 = 1742;
pub const XML_SCHEMAP_UNKNOWN_FACET_TYPE: C2RustUnnamed_0 = 1741;
pub const XML_SCHEMAP_UNKNOWN_FACET_CHILD: C2RustUnnamed_0 = 1740;
pub const XML_SCHEMAP_UNKNOWN_EXTENSION_CHILD: C2RustUnnamed_0 = 1739;
pub const XML_SCHEMAP_UNKNOWN_ELEM_CHILD: C2RustUnnamed_0 = 1738;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXTYPE_CHILD: C2RustUnnamed_0 = 1737;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXCONTENT_CHILD: C2RustUnnamed_0 = 1736;
pub const XML_SCHEMAP_UNKNOWN_CHOICE_CHILD: C2RustUnnamed_0 = 1735;
pub const XML_SCHEMAP_UNKNOWN_BASE_TYPE: C2RustUnnamed_0 = 1734;
pub const XML_SCHEMAP_UNKNOWN_ATTRIBUTE_GROUP: C2RustUnnamed_0 = 1733;
pub const XML_SCHEMAP_UNKNOWN_ATTRGRP_CHILD: C2RustUnnamed_0 = 1732;
pub const XML_SCHEMAP_UNKNOWN_ATTR_CHILD: C2RustUnnamed_0 = 1731;
pub const XML_SCHEMAP_UNKNOWN_ANYATTRIBUTE_CHILD: C2RustUnnamed_0 = 1730;
pub const XML_SCHEMAP_UNKNOWN_ALL_CHILD: C2RustUnnamed_0 = 1729;
pub const XML_SCHEMAP_TYPE_AND_SUBTYPE: C2RustUnnamed_0 = 1728;
pub const XML_SCHEMAP_SIMPLETYPE_NONAME: C2RustUnnamed_0 = 1727;
pub const XML_SCHEMAP_RESTRICTION_NONAME_NOREF: C2RustUnnamed_0 = 1726;
pub const XML_SCHEMAP_REF_AND_SUBTYPE: C2RustUnnamed_0 = 1725;
pub const XML_SCHEMAP_NOTYPE_NOREF: C2RustUnnamed_0 = 1724;
pub const XML_SCHEMAP_NOTATION_NO_NAME: C2RustUnnamed_0 = 1723;
pub const XML_SCHEMAP_NOATTR_NOREF: C2RustUnnamed_0 = 1722;
pub const XML_SCHEMAP_INVALID_WHITE_SPACE: C2RustUnnamed_0 = 1721;
pub const XML_SCHEMAP_INVALID_REF_AND_SUBTYPE: C2RustUnnamed_0 = 1720;
pub const XML_SCHEMAP_INVALID_MINOCCURS: C2RustUnnamed_0 = 1719;
pub const XML_SCHEMAP_INVALID_MAXOCCURS: C2RustUnnamed_0 = 1718;
pub const XML_SCHEMAP_INVALID_FACET_VALUE: C2RustUnnamed_0 = 1717;
pub const XML_SCHEMAP_INVALID_FACET: C2RustUnnamed_0 = 1716;
pub const XML_SCHEMAP_INVALID_ENUM: C2RustUnnamed_0 = 1715;
pub const XML_SCHEMAP_INVALID_BOOLEAN: C2RustUnnamed_0 = 1714;
pub const XML_SCHEMAP_IMPORT_SCHEMA_NOT_URI: C2RustUnnamed_0 = 1713;
pub const XML_SCHEMAP_IMPORT_REDEFINE_NSNAME: C2RustUnnamed_0 = 1712;
pub const XML_SCHEMAP_IMPORT_NAMESPACE_NOT_URI: C2RustUnnamed_0 = 1711;
pub const XML_SCHEMAP_GROUP_NONAME_NOREF: C2RustUnnamed_0 = 1710;
pub const XML_SCHEMAP_FAILED_BUILD_IMPORT: C2RustUnnamed_0 = 1709;
pub const XML_SCHEMAP_FACET_NO_VALUE: C2RustUnnamed_0 = 1708;
pub const XML_SCHEMAP_EXTENSION_NO_BASE: C2RustUnnamed_0 = 1707;
pub const XML_SCHEMAP_ELEM_NONAME_NOREF: C2RustUnnamed_0 = 1706;
pub const XML_SCHEMAP_ELEMFORMDEFAULT_VALUE: C2RustUnnamed_0 = 1705;
pub const XML_SCHEMAP_COMPLEXTYPE_NONAME_NOREF: C2RustUnnamed_0 = 1704;
pub const XML_SCHEMAP_ATTR_NONAME_NOREF: C2RustUnnamed_0 = 1703;
pub const XML_SCHEMAP_ATTRGRP_NONAME_NOREF: C2RustUnnamed_0 = 1702;
pub const XML_SCHEMAP_ATTRFORMDEFAULT_VALUE: C2RustUnnamed_0 = 1701;
pub const XML_SCHEMAP_PREFIX_UNDEFINED: C2RustUnnamed_0 = 1700;
pub const XML_CATALOG_RECURSION: C2RustUnnamed_0 = 1654;
pub const XML_CATALOG_NOT_CATALOG: C2RustUnnamed_0 = 1653;
pub const XML_CATALOG_PREFER_VALUE: C2RustUnnamed_0 = 1652;
pub const XML_CATALOG_ENTRY_BROKEN: C2RustUnnamed_0 = 1651;
pub const XML_CATALOG_MISSING_ATTR: C2RustUnnamed_0 = 1650;
pub const XML_XINCLUDE_FRAGMENT_ID: C2RustUnnamed_0 = 1618;
pub const XML_XINCLUDE_DEPRECATED_NS: C2RustUnnamed_0 = 1617;
pub const XML_XINCLUDE_FALLBACK_NOT_IN_INCLUDE: C2RustUnnamed_0 = 1616;
pub const XML_XINCLUDE_FALLBACKS_IN_INCLUDE: C2RustUnnamed_0 = 1615;
pub const XML_XINCLUDE_INCLUDE_IN_INCLUDE: C2RustUnnamed_0 = 1614;
pub const XML_XINCLUDE_XPTR_RESULT: C2RustUnnamed_0 = 1613;
pub const XML_XINCLUDE_XPTR_FAILED: C2RustUnnamed_0 = 1612;
pub const XML_XINCLUDE_MULTIPLE_ROOT: C2RustUnnamed_0 = 1611;
pub const XML_XINCLUDE_UNKNOWN_ENCODING: C2RustUnnamed_0 = 1610;
pub const XML_XINCLUDE_BUILD_FAILED: C2RustUnnamed_0 = 1609;
pub const XML_XINCLUDE_INVALID_CHAR: C2RustUnnamed_0 = 1608;
pub const XML_XINCLUDE_TEXT_DOCUMENT: C2RustUnnamed_0 = 1607;
pub const XML_XINCLUDE_TEXT_FRAGMENT: C2RustUnnamed_0 = 1606;
pub const XML_XINCLUDE_HREF_URI: C2RustUnnamed_0 = 1605;
pub const XML_XINCLUDE_NO_FALLBACK: C2RustUnnamed_0 = 1604;
pub const XML_XINCLUDE_NO_HREF: C2RustUnnamed_0 = 1603;
pub const XML_XINCLUDE_ENTITY_DEF_MISMATCH: C2RustUnnamed_0 = 1602;
pub const XML_XINCLUDE_PARSE_VALUE: C2RustUnnamed_0 = 1601;
pub const XML_XINCLUDE_RECURSION: C2RustUnnamed_0 = 1600;
pub const XML_IO_EAFNOSUPPORT: C2RustUnnamed_0 = 1556;
pub const XML_IO_EALREADY: C2RustUnnamed_0 = 1555;
pub const XML_IO_EADDRINUSE: C2RustUnnamed_0 = 1554;
pub const XML_IO_ENETUNREACH: C2RustUnnamed_0 = 1553;
pub const XML_IO_ECONNREFUSED: C2RustUnnamed_0 = 1552;
pub const XML_IO_EISCONN: C2RustUnnamed_0 = 1551;
pub const XML_IO_ENOTSOCK: C2RustUnnamed_0 = 1550;
pub const XML_IO_LOAD_ERROR: C2RustUnnamed_0 = 1549;
pub const XML_IO_BUFFER_FULL: C2RustUnnamed_0 = 1548;
pub const XML_IO_NO_INPUT: C2RustUnnamed_0 = 1547;
pub const XML_IO_WRITE: C2RustUnnamed_0 = 1546;
pub const XML_IO_FLUSH: C2RustUnnamed_0 = 1545;
pub const XML_IO_ENCODER: C2RustUnnamed_0 = 1544;
pub const XML_IO_NETWORK_ATTEMPT: C2RustUnnamed_0 = 1543;
pub const XML_IO_EXDEV: C2RustUnnamed_0 = 1542;
pub const XML_IO_ETIMEDOUT: C2RustUnnamed_0 = 1541;
pub const XML_IO_ESRCH: C2RustUnnamed_0 = 1540;
pub const XML_IO_ESPIPE: C2RustUnnamed_0 = 1539;
pub const XML_IO_EROFS: C2RustUnnamed_0 = 1538;
pub const XML_IO_ERANGE: C2RustUnnamed_0 = 1537;
pub const XML_IO_EPIPE: C2RustUnnamed_0 = 1536;
pub const XML_IO_EPERM: C2RustUnnamed_0 = 1535;
pub const XML_IO_ENXIO: C2RustUnnamed_0 = 1534;
pub const XML_IO_ENOTTY: C2RustUnnamed_0 = 1533;
pub const XML_IO_ENOTSUP: C2RustUnnamed_0 = 1532;
pub const XML_IO_ENOTEMPTY: C2RustUnnamed_0 = 1531;
pub const XML_IO_ENOTDIR: C2RustUnnamed_0 = 1530;
pub const XML_IO_ENOSYS: C2RustUnnamed_0 = 1529;
pub const XML_IO_ENOSPC: C2RustUnnamed_0 = 1528;
pub const XML_IO_ENOMEM: C2RustUnnamed_0 = 1527;
pub const XML_IO_ENOLCK: C2RustUnnamed_0 = 1526;
pub const XML_IO_ENOEXEC: C2RustUnnamed_0 = 1525;
pub const XML_IO_ENOENT: C2RustUnnamed_0 = 1524;
pub const XML_IO_ENODEV: C2RustUnnamed_0 = 1523;
pub const XML_IO_ENFILE: C2RustUnnamed_0 = 1522;
pub const XML_IO_ENAMETOOLONG: C2RustUnnamed_0 = 1521;
pub const XML_IO_EMSGSIZE: C2RustUnnamed_0 = 1520;
pub const XML_IO_EMLINK: C2RustUnnamed_0 = 1519;
pub const XML_IO_EMFILE: C2RustUnnamed_0 = 1518;
pub const XML_IO_EISDIR: C2RustUnnamed_0 = 1517;
pub const XML_IO_EIO: C2RustUnnamed_0 = 1516;
pub const XML_IO_EINVAL: C2RustUnnamed_0 = 1515;
pub const XML_IO_EINTR: C2RustUnnamed_0 = 1514;
pub const XML_IO_EINPROGRESS: C2RustUnnamed_0 = 1513;
pub const XML_IO_EFBIG: C2RustUnnamed_0 = 1512;
pub const XML_IO_EFAULT: C2RustUnnamed_0 = 1511;
pub const XML_IO_EEXIST: C2RustUnnamed_0 = 1510;
pub const XML_IO_EDOM: C2RustUnnamed_0 = 1509;
pub const XML_IO_EDEADLK: C2RustUnnamed_0 = 1508;
pub const XML_IO_ECHILD: C2RustUnnamed_0 = 1507;
pub const XML_IO_ECANCELED: C2RustUnnamed_0 = 1506;
pub const XML_IO_EBUSY: C2RustUnnamed_0 = 1505;
pub const XML_IO_EBADMSG: C2RustUnnamed_0 = 1504;
pub const XML_IO_EBADF: C2RustUnnamed_0 = 1503;
pub const XML_IO_EAGAIN: C2RustUnnamed_0 = 1502;
pub const XML_IO_EACCES: C2RustUnnamed_0 = 1501;
pub const XML_IO_UNKNOWN: C2RustUnnamed_0 = 1500;
pub const XML_REGEXP_COMPILE_ERROR: C2RustUnnamed_0 = 1450;
pub const XML_SAVE_UNKNOWN_ENCODING: C2RustUnnamed_0 = 1403;
pub const XML_SAVE_NO_DOCTYPE: C2RustUnnamed_0 = 1402;
pub const XML_SAVE_CHAR_INVALID: C2RustUnnamed_0 = 1401;
pub const XML_SAVE_NOT_UTF8: C2RustUnnamed_0 = 1400;
pub const XML_TREE_NOT_UTF8: C2RustUnnamed_0 = 1303;
pub const XML_TREE_UNTERMINATED_ENTITY: C2RustUnnamed_0 = 1302;
pub const XML_TREE_INVALID_DEC: C2RustUnnamed_0 = 1301;
pub const XML_TREE_INVALID_HEX: C2RustUnnamed_0 = 1300;
pub const XML_XPATH_INVALID_CHAR_ERROR: C2RustUnnamed_0 = 1221;
pub const XML_XPATH_ENCODING_ERROR: C2RustUnnamed_0 = 1220;
pub const XML_XPATH_UNDEF_PREFIX_ERROR: C2RustUnnamed_0 = 1219;
pub const XML_XPTR_SUB_RESOURCE_ERROR: C2RustUnnamed_0 = 1218;
pub const XML_XPTR_RESOURCE_ERROR: C2RustUnnamed_0 = 1217;
pub const XML_XPTR_SYNTAX_ERROR: C2RustUnnamed_0 = 1216;
pub const XML_XPATH_MEMORY_ERROR: C2RustUnnamed_0 = 1215;
pub const XML_XPATH_INVALID_CTXT_POSITION: C2RustUnnamed_0 = 1214;
pub const XML_XPATH_INVALID_CTXT_SIZE: C2RustUnnamed_0 = 1213;
pub const XML_XPATH_INVALID_ARITY: C2RustUnnamed_0 = 1212;
pub const XML_XPATH_INVALID_TYPE: C2RustUnnamed_0 = 1211;
pub const XML_XPATH_INVALID_OPERAND: C2RustUnnamed_0 = 1210;
pub const XML_XPATH_UNKNOWN_FUNC_ERROR: C2RustUnnamed_0 = 1209;
pub const XML_XPATH_UNCLOSED_ERROR: C2RustUnnamed_0 = 1208;
pub const XML_XPATH_EXPR_ERROR: C2RustUnnamed_0 = 1207;
pub const XML_XPATH_INVALID_PREDICATE_ERROR: C2RustUnnamed_0 = 1206;
pub const XML_XPATH_UNDEF_VARIABLE_ERROR: C2RustUnnamed_0 = 1205;
pub const XML_XPATH_VARIABLE_REF_ERROR: C2RustUnnamed_0 = 1204;
pub const XML_XPATH_START_LITERAL_ERROR: C2RustUnnamed_0 = 1203;
pub const XML_XPATH_UNFINISHED_LITERAL_ERROR: C2RustUnnamed_0 = 1202;
pub const XML_XPATH_NUMBER_ERROR: C2RustUnnamed_0 = 1201;
pub const XML_XPATH_EXPRESSION_OK: C2RustUnnamed_0 = 1200;
pub const XML_RNGP_XML_NS: C2RustUnnamed_0 = 1122;
pub const XML_RNGP_XMLNS_NAME: C2RustUnnamed_0 = 1121;
pub const XML_RNGP_VALUE_NO_CONTENT: C2RustUnnamed_0 = 1120;
pub const XML_RNGP_VALUE_EMPTY: C2RustUnnamed_0 = 1119;
pub const XML_RNGP_URI_NOT_ABSOLUTE: C2RustUnnamed_0 = 1118;
pub const XML_RNGP_URI_FRAGMENT: C2RustUnnamed_0 = 1117;
pub const XML_RNGP_UNKNOWN_TYPE_LIB: C2RustUnnamed_0 = 1116;
pub const XML_RNGP_UNKNOWN_CONSTRUCT: C2RustUnnamed_0 = 1115;
pub const XML_RNGP_UNKNOWN_COMBINE: C2RustUnnamed_0 = 1114;
pub const XML_RNGP_UNKNOWN_ATTRIBUTE: C2RustUnnamed_0 = 1113;
pub const XML_RNGP_TYPE_VALUE: C2RustUnnamed_0 = 1112;
pub const XML_RNGP_TYPE_NOT_FOUND: C2RustUnnamed_0 = 1111;
pub const XML_RNGP_TYPE_MISSING: C2RustUnnamed_0 = 1110;
pub const XML_RNGP_TEXT_HAS_CHILD: C2RustUnnamed_0 = 1109;
pub const XML_RNGP_TEXT_EXPECTED: C2RustUnnamed_0 = 1108;
pub const XML_RNGP_START_MISSING: C2RustUnnamed_0 = 1107;
pub const XML_RNGP_START_EMPTY: C2RustUnnamed_0 = 1106;
pub const XML_RNGP_START_CONTENT: C2RustUnnamed_0 = 1105;
pub const XML_RNGP_START_CHOICE_AND_INTERLEAVE: C2RustUnnamed_0 = 1104;
pub const XML_RNGP_REF_NOT_EMPTY: C2RustUnnamed_0 = 1103;
pub const XML_RNGP_REF_NO_NAME: C2RustUnnamed_0 = 1102;
pub const XML_RNGP_REF_NO_DEF: C2RustUnnamed_0 = 1101;
pub const XML_RNGP_REF_NAME_INVALID: C2RustUnnamed_0 = 1100;
pub const XML_RNGP_REF_CYCLE: C2RustUnnamed_0 = 1099;
pub const XML_RNGP_REF_CREATE_FAILED: C2RustUnnamed_0 = 1098;
pub const XML_RNGP_PREFIX_UNDEFINED: C2RustUnnamed_0 = 1097;
pub const XML_RNGP_PAT_START_VALUE: C2RustUnnamed_0 = 1096;
pub const XML_RNGP_PAT_START_TEXT: C2RustUnnamed_0 = 1095;
pub const XML_RNGP_PAT_START_ONEMORE: C2RustUnnamed_0 = 1094;
pub const XML_RNGP_PAT_START_LIST: C2RustUnnamed_0 = 1093;
pub const XML_RNGP_PAT_START_INTERLEAVE: C2RustUnnamed_0 = 1092;
pub const XML_RNGP_PAT_START_GROUP: C2RustUnnamed_0 = 1091;
pub const XML_RNGP_PAT_START_EMPTY: C2RustUnnamed_0 = 1090;
pub const XML_RNGP_PAT_START_DATA: C2RustUnnamed_0 = 1089;
pub const XML_RNGP_PAT_START_ATTR: C2RustUnnamed_0 = 1088;
pub const XML_RNGP_PAT_ONEMORE_INTERLEAVE_ATTR: C2RustUnnamed_0 = 1087;
pub const XML_RNGP_PAT_ONEMORE_GROUP_ATTR: C2RustUnnamed_0 = 1086;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_NSNAME: C2RustUnnamed_0 = 1085;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_ANYNAME: C2RustUnnamed_0 = 1084;
pub const XML_RNGP_PAT_LIST_TEXT: C2RustUnnamed_0 = 1083;
pub const XML_RNGP_PAT_LIST_REF: C2RustUnnamed_0 = 1082;
pub const XML_RNGP_PAT_LIST_LIST: C2RustUnnamed_0 = 1081;
pub const XML_RNGP_PAT_LIST_INTERLEAVE: C2RustUnnamed_0 = 1080;
pub const XML_RNGP_PAT_LIST_ELEM: C2RustUnnamed_0 = 1079;
pub const XML_RNGP_PAT_LIST_ATTR: C2RustUnnamed_0 = 1078;
pub const XML_RNGP_PAT_DATA_EXCEPT_TEXT: C2RustUnnamed_0 = 1077;
pub const XML_RNGP_PAT_DATA_EXCEPT_REF: C2RustUnnamed_0 = 1076;
pub const XML_RNGP_PAT_DATA_EXCEPT_ONEMORE: C2RustUnnamed_0 = 1075;
pub const XML_RNGP_PAT_DATA_EXCEPT_LIST: C2RustUnnamed_0 = 1074;
pub const XML_RNGP_PAT_DATA_EXCEPT_INTERLEAVE: C2RustUnnamed_0 = 1073;
pub const XML_RNGP_PAT_DATA_EXCEPT_GROUP: C2RustUnnamed_0 = 1072;
pub const XML_RNGP_PAT_DATA_EXCEPT_EMPTY: C2RustUnnamed_0 = 1071;
pub const XML_RNGP_PAT_DATA_EXCEPT_ELEM: C2RustUnnamed_0 = 1070;
pub const XML_RNGP_PAT_DATA_EXCEPT_ATTR: C2RustUnnamed_0 = 1069;
pub const XML_RNGP_PAT_ATTR_ELEM: C2RustUnnamed_0 = 1068;
pub const XML_RNGP_PAT_ATTR_ATTR: C2RustUnnamed_0 = 1067;
pub const XML_RNGP_PAT_ANYNAME_EXCEPT_ANYNAME: C2RustUnnamed_0 = 1066;
pub const XML_RNGP_PARSE_ERROR: C2RustUnnamed_0 = 1065;
pub const XML_RNGP_PARENTREF_NOT_EMPTY: C2RustUnnamed_0 = 1064;
pub const XML_RNGP_PARENTREF_NO_PARENT: C2RustUnnamed_0 = 1063;
pub const XML_RNGP_PARENTREF_NO_NAME: C2RustUnnamed_0 = 1062;
pub const XML_RNGP_PARENTREF_NAME_INVALID: C2RustUnnamed_0 = 1061;
pub const XML_RNGP_PARENTREF_CREATE_FAILED: C2RustUnnamed_0 = 1060;
pub const XML_RNGP_PARAM_NAME_MISSING: C2RustUnnamed_0 = 1059;
pub const XML_RNGP_PARAM_FORBIDDEN: C2RustUnnamed_0 = 1058;
pub const XML_RNGP_NSNAME_NO_NS: C2RustUnnamed_0 = 1057;
pub const XML_RNGP_NSNAME_ATTR_ANCESTOR: C2RustUnnamed_0 = 1056;
pub const XML_RNGP_NOTALLOWED_NOT_EMPTY: C2RustUnnamed_0 = 1055;
pub const XML_RNGP_NEED_COMBINE: C2RustUnnamed_0 = 1054;
pub const XML_RNGP_NAME_MISSING: C2RustUnnamed_0 = 1053;
pub const XML_RNGP_MISSING_HREF: C2RustUnnamed_0 = 1052;
pub const XML_RNGP_INVALID_VALUE: C2RustUnnamed_0 = 1051;
pub const XML_RNGP_INVALID_URI: C2RustUnnamed_0 = 1050;
pub const XML_RNGP_INVALID_DEFINE_NAME: C2RustUnnamed_0 = 1049;
pub const XML_RNGP_INTERLEAVE_NO_CONTENT: C2RustUnnamed_0 = 1048;
pub const XML_RNGP_INTERLEAVE_EMPTY: C2RustUnnamed_0 = 1047;
pub const XML_RNGP_INTERLEAVE_CREATE_FAILED: C2RustUnnamed_0 = 1046;
pub const XML_RNGP_INTERLEAVE_ADD: C2RustUnnamed_0 = 1045;
pub const XML_RNGP_INCLUDE_RECURSE: C2RustUnnamed_0 = 1044;
pub const XML_RNGP_INCLUDE_FAILURE: C2RustUnnamed_0 = 1043;
pub const XML_RNGP_INCLUDE_EMPTY: C2RustUnnamed_0 = 1042;
pub const XML_RNGP_HREF_ERROR: C2RustUnnamed_0 = 1041;
pub const XML_RNGP_GROUP_ATTR_CONFLICT: C2RustUnnamed_0 = 1040;
pub const XML_RNGP_GRAMMAR_NO_START: C2RustUnnamed_0 = 1039;
pub const XML_RNGP_GRAMMAR_MISSING: C2RustUnnamed_0 = 1038;
pub const XML_RNGP_GRAMMAR_EMPTY: C2RustUnnamed_0 = 1037;
pub const XML_RNGP_GRAMMAR_CONTENT: C2RustUnnamed_0 = 1036;
pub const XML_RNGP_FOREIGN_ELEMENT: C2RustUnnamed_0 = 1035;
pub const XML_RNGP_FORBIDDEN_ATTRIBUTE: C2RustUnnamed_0 = 1034;
pub const XML_RNGP_EXTERNALREF_RECURSE: C2RustUnnamed_0 = 1033;
pub const XML_RNGP_EXTERNAL_REF_FAILURE: C2RustUnnamed_0 = 1032;
pub const XML_RNGP_EXTERNALREF_EMTPY: C2RustUnnamed_0 = 1031;
pub const XML_RNGP_EXCEPT_NO_CONTENT: C2RustUnnamed_0 = 1030;
pub const XML_RNGP_EXCEPT_MULTIPLE: C2RustUnnamed_0 = 1029;
pub const XML_RNGP_EXCEPT_MISSING: C2RustUnnamed_0 = 1028;
pub const XML_RNGP_EXCEPT_EMPTY: C2RustUnnamed_0 = 1027;
pub const XML_RNGP_ERROR_TYPE_LIB: C2RustUnnamed_0 = 1026;
pub const XML_RNGP_EMPTY_NOT_EMPTY: C2RustUnnamed_0 = 1025;
pub const XML_RNGP_EMPTY_CONTENT: C2RustUnnamed_0 = 1024;
pub const XML_RNGP_EMPTY_CONSTRUCT: C2RustUnnamed_0 = 1023;
pub const XML_RNGP_EMPTY: C2RustUnnamed_0 = 1022;
pub const XML_RNGP_ELEM_TEXT_CONFLICT: C2RustUnnamed_0 = 1021;
pub const XML_RNGP_ELEMENT_NO_CONTENT: C2RustUnnamed_0 = 1020;
pub const XML_RNGP_ELEMENT_NAME: C2RustUnnamed_0 = 1019;
pub const XML_RNGP_ELEMENT_CONTENT: C2RustUnnamed_0 = 1018;
pub const XML_RNGP_ELEMENT_EMPTY: C2RustUnnamed_0 = 1017;
pub const XML_RNGP_ELEM_CONTENT_ERROR: C2RustUnnamed_0 = 1016;
pub const XML_RNGP_ELEM_CONTENT_EMPTY: C2RustUnnamed_0 = 1015;
pub const XML_RNGP_DEFINE_NAME_MISSING: C2RustUnnamed_0 = 1014;
pub const XML_RNGP_DEFINE_MISSING: C2RustUnnamed_0 = 1013;
pub const XML_RNGP_DEFINE_EMPTY: C2RustUnnamed_0 = 1012;
pub const XML_RNGP_DEFINE_CREATE_FAILED: C2RustUnnamed_0 = 1011;
pub const XML_RNGP_DEF_CHOICE_AND_INTERLEAVE: C2RustUnnamed_0 = 1010;
pub const XML_RNGP_DATA_CONTENT: C2RustUnnamed_0 = 1009;
pub const XML_RNGP_CREATE_FAILURE: C2RustUnnamed_0 = 1008;
pub const XML_RNGP_CHOICE_EMPTY: C2RustUnnamed_0 = 1007;
pub const XML_RNGP_CHOICE_CONTENT: C2RustUnnamed_0 = 1006;
pub const XML_RNGP_ATTRIBUTE_NOOP: C2RustUnnamed_0 = 1005;
pub const XML_RNGP_ATTRIBUTE_EMPTY: C2RustUnnamed_0 = 1004;
pub const XML_RNGP_ATTRIBUTE_CONTENT: C2RustUnnamed_0 = 1003;
pub const XML_RNGP_ATTRIBUTE_CHILDREN: C2RustUnnamed_0 = 1002;
pub const XML_RNGP_ATTR_CONFLICT: C2RustUnnamed_0 = 1001;
pub const XML_RNGP_ANYNAME_ATTR_ANCESTOR: C2RustUnnamed_0 = 1000;
pub const XML_HTML_INCORRECTLY_OPENED_COMMENT: C2RustUnnamed_0 = 802;
pub const XML_HTML_UNKNOWN_TAG: C2RustUnnamed_0 = 801;
pub const XML_HTML_STRUCURE_ERROR: C2RustUnnamed_0 = 800;
pub const XML_DTD_DUP_TOKEN: C2RustUnnamed_0 = 541;
pub const XML_DTD_XMLID_TYPE: C2RustUnnamed_0 = 540;
pub const XML_DTD_XMLID_VALUE: C2RustUnnamed_0 = 539;
pub const XML_DTD_STANDALONE_DEFAULTED: C2RustUnnamed_0 = 538;
pub const XML_DTD_UNKNOWN_NOTATION: C2RustUnnamed_0 = 537;
pub const XML_DTD_UNKNOWN_ID: C2RustUnnamed_0 = 536;
pub const XML_DTD_UNKNOWN_ENTITY: C2RustUnnamed_0 = 535;
pub const XML_DTD_UNKNOWN_ELEM: C2RustUnnamed_0 = 534;
pub const XML_DTD_UNKNOWN_ATTRIBUTE: C2RustUnnamed_0 = 533;
pub const XML_DTD_STANDALONE_WHITE_SPACE: C2RustUnnamed_0 = 532;
pub const XML_DTD_ROOT_NAME: C2RustUnnamed_0 = 531;
pub const XML_DTD_NOT_STANDALONE: C2RustUnnamed_0 = 530;
pub const XML_DTD_NOT_PCDATA: C2RustUnnamed_0 = 529;
pub const XML_DTD_NOT_EMPTY: C2RustUnnamed_0 = 528;
pub const XML_DTD_NOTATION_VALUE: C2RustUnnamed_0 = 527;
pub const XML_DTD_NOTATION_REDEFINED: C2RustUnnamed_0 = 526;
pub const XML_DTD_NO_ROOT: C2RustUnnamed_0 = 525;
pub const XML_DTD_NO_PREFIX: C2RustUnnamed_0 = 524;
pub const XML_DTD_NO_ELEM_NAME: C2RustUnnamed_0 = 523;
pub const XML_DTD_NO_DTD: C2RustUnnamed_0 = 522;
pub const XML_DTD_NO_DOC: C2RustUnnamed_0 = 521;
pub const XML_DTD_MULTIPLE_ID: C2RustUnnamed_0 = 520;
pub const XML_DTD_MIXED_CORRUPT: C2RustUnnamed_0 = 519;
pub const XML_DTD_MISSING_ATTRIBUTE: C2RustUnnamed_0 = 518;
pub const XML_DTD_LOAD_ERROR: C2RustUnnamed_0 = 517;
pub const XML_DTD_INVALID_DEFAULT: C2RustUnnamed_0 = 516;
pub const XML_DTD_INVALID_CHILD: C2RustUnnamed_0 = 515;
pub const XML_DTD_ID_SUBSET: C2RustUnnamed_0 = 514;
pub const XML_DTD_ID_REDEFINED: C2RustUnnamed_0 = 513;
pub const XML_DTD_ID_FIXED: C2RustUnnamed_0 = 512;
pub const XML_DTD_ENTITY_TYPE: C2RustUnnamed_0 = 511;
pub const XML_DTD_EMPTY_NOTATION: C2RustUnnamed_0 = 510;
pub const XML_DTD_ELEM_REDEFINED: C2RustUnnamed_0 = 509;
pub const XML_DTD_ELEM_NAMESPACE: C2RustUnnamed_0 = 508;
pub const XML_DTD_ELEM_DEFAULT_NAMESPACE: C2RustUnnamed_0 = 507;
pub const XML_DTD_DIFFERENT_PREFIX: C2RustUnnamed_0 = 506;
pub const XML_DTD_CONTENT_NOT_DETERMINIST: C2RustUnnamed_0 = 505;
pub const XML_DTD_CONTENT_MODEL: C2RustUnnamed_0 = 504;
pub const XML_DTD_CONTENT_ERROR: C2RustUnnamed_0 = 503;
pub const XML_DTD_ATTRIBUTE_VALUE: C2RustUnnamed_0 = 502;
pub const XML_DTD_ATTRIBUTE_REDEFINED: C2RustUnnamed_0 = 501;
pub const XML_DTD_ATTRIBUTE_DEFAULT: C2RustUnnamed_0 = 500;
pub const XML_NS_ERR_COLON: C2RustUnnamed_0 = 205;
pub const XML_NS_ERR_EMPTY: C2RustUnnamed_0 = 204;
pub const XML_NS_ERR_ATTRIBUTE_REDEFINED: C2RustUnnamed_0 = 203;
pub const XML_NS_ERR_QNAME: C2RustUnnamed_0 = 202;
pub const XML_NS_ERR_UNDEFINED_NAMESPACE: C2RustUnnamed_0 = 201;
pub const XML_NS_ERR_XML_NAMESPACE: C2RustUnnamed_0 = 200;
pub const XML_ERR_COMMENT_ABRUPTLY_ENDED: C2RustUnnamed_0 = 112;
pub const XML_ERR_USER_STOP: C2RustUnnamed_0 = 111;
pub const XML_ERR_NAME_TOO_LONG: C2RustUnnamed_0 = 110;
pub const XML_ERR_VERSION_MISMATCH: C2RustUnnamed_0 = 109;
pub const XML_ERR_UNKNOWN_VERSION: C2RustUnnamed_0 = 108;
pub const XML_WAR_ENTITY_REDEFINED: C2RustUnnamed_0 = 107;
pub const XML_WAR_NS_COLUMN: C2RustUnnamed_0 = 106;
pub const XML_ERR_NOTATION_PROCESSING: C2RustUnnamed_0 = 105;
pub const XML_ERR_ENTITY_PROCESSING: C2RustUnnamed_0 = 104;
pub const XML_ERR_NOT_STANDALONE: C2RustUnnamed_0 = 103;
pub const XML_WAR_SPACE_VALUE: C2RustUnnamed_0 = 102;
pub const XML_ERR_MISSING_ENCODING: C2RustUnnamed_0 = 101;
pub const XML_WAR_NS_URI_RELATIVE: C2RustUnnamed_0 = 100;
pub const XML_WAR_NS_URI: C2RustUnnamed_0 = 99;
pub const XML_WAR_LANG_VALUE: C2RustUnnamed_0 = 98;
pub const XML_WAR_UNKNOWN_VERSION: C2RustUnnamed_0 = 97;
pub const XML_ERR_VERSION_MISSING: C2RustUnnamed_0 = 96;
pub const XML_ERR_CONDSEC_INVALID_KEYWORD: C2RustUnnamed_0 = 95;
pub const XML_ERR_NO_DTD: C2RustUnnamed_0 = 94;
pub const XML_WAR_CATALOG_PI: C2RustUnnamed_0 = 93;
pub const XML_ERR_URI_FRAGMENT: C2RustUnnamed_0 = 92;
pub const XML_ERR_INVALID_URI: C2RustUnnamed_0 = 91;
pub const XML_ERR_ENTITY_BOUNDARY: C2RustUnnamed_0 = 90;
pub const XML_ERR_ENTITY_LOOP: C2RustUnnamed_0 = 89;
pub const XML_ERR_ENTITY_PE_INTERNAL: C2RustUnnamed_0 = 88;
pub const XML_ERR_ENTITY_CHAR_ERROR: C2RustUnnamed_0 = 87;
pub const XML_ERR_EXTRA_CONTENT: C2RustUnnamed_0 = 86;
pub const XML_ERR_NOT_WELL_BALANCED: C2RustUnnamed_0 = 85;
pub const XML_ERR_VALUE_REQUIRED: C2RustUnnamed_0 = 84;
pub const XML_ERR_CONDSEC_INVALID: C2RustUnnamed_0 = 83;
pub const XML_ERR_EXT_ENTITY_STANDALONE: C2RustUnnamed_0 = 82;
pub const XML_ERR_INVALID_ENCODING: C2RustUnnamed_0 = 81;
pub const XML_ERR_HYPHEN_IN_COMMENT: C2RustUnnamed_0 = 80;
pub const XML_ERR_ENCODING_NAME: C2RustUnnamed_0 = 79;
pub const XML_ERR_STANDALONE_VALUE: C2RustUnnamed_0 = 78;
pub const XML_ERR_TAG_NOT_FINISHED: C2RustUnnamed_0 = 77;
pub const XML_ERR_TAG_NAME_MISMATCH: C2RustUnnamed_0 = 76;
pub const XML_ERR_EQUAL_REQUIRED: C2RustUnnamed_0 = 75;
pub const XML_ERR_LTSLASH_REQUIRED: C2RustUnnamed_0 = 74;
pub const XML_ERR_GT_REQUIRED: C2RustUnnamed_0 = 73;
pub const XML_ERR_LT_REQUIRED: C2RustUnnamed_0 = 72;
pub const XML_ERR_PUBID_REQUIRED: C2RustUnnamed_0 = 71;
pub const XML_ERR_URI_REQUIRED: C2RustUnnamed_0 = 70;
pub const XML_ERR_PCDATA_REQUIRED: C2RustUnnamed_0 = 69;
pub const XML_ERR_NAME_REQUIRED: C2RustUnnamed_0 = 68;
pub const XML_ERR_NMTOKEN_REQUIRED: C2RustUnnamed_0 = 67;
pub const XML_ERR_SEPARATOR_REQUIRED: C2RustUnnamed_0 = 66;
pub const XML_ERR_SPACE_REQUIRED: C2RustUnnamed_0 = 65;
pub const XML_ERR_RESERVED_XML_NAME: C2RustUnnamed_0 = 64;
pub const XML_ERR_CDATA_NOT_FINISHED: C2RustUnnamed_0 = 63;
pub const XML_ERR_MISPLACED_CDATA_END: C2RustUnnamed_0 = 62;
pub const XML_ERR_DOCTYPE_NOT_FINISHED: C2RustUnnamed_0 = 61;
pub const XML_ERR_EXT_SUBSET_NOT_FINISHED: C2RustUnnamed_0 = 60;
pub const XML_ERR_CONDSEC_NOT_FINISHED: C2RustUnnamed_0 = 59;
pub const XML_ERR_CONDSEC_NOT_STARTED: C2RustUnnamed_0 = 58;
pub const XML_ERR_XMLDECL_NOT_FINISHED: C2RustUnnamed_0 = 57;
pub const XML_ERR_XMLDECL_NOT_STARTED: C2RustUnnamed_0 = 56;
pub const XML_ERR_ELEMCONTENT_NOT_FINISHED: C2RustUnnamed_0 = 55;
pub const XML_ERR_ELEMCONTENT_NOT_STARTED: C2RustUnnamed_0 = 54;
pub const XML_ERR_MIXED_NOT_FINISHED: C2RustUnnamed_0 = 53;
pub const XML_ERR_MIXED_NOT_STARTED: C2RustUnnamed_0 = 52;
pub const XML_ERR_ATTLIST_NOT_FINISHED: C2RustUnnamed_0 = 51;
pub const XML_ERR_ATTLIST_NOT_STARTED: C2RustUnnamed_0 = 50;
pub const XML_ERR_NOTATION_NOT_FINISHED: C2RustUnnamed_0 = 49;
pub const XML_ERR_NOTATION_NOT_STARTED: C2RustUnnamed_0 = 48;
pub const XML_ERR_PI_NOT_FINISHED: C2RustUnnamed_0 = 47;
pub const XML_ERR_PI_NOT_STARTED: C2RustUnnamed_0 = 46;
pub const XML_ERR_COMMENT_NOT_FINISHED: C2RustUnnamed_0 = 45;
pub const XML_ERR_LITERAL_NOT_FINISHED: C2RustUnnamed_0 = 44;
pub const XML_ERR_LITERAL_NOT_STARTED: C2RustUnnamed_0 = 43;
pub const XML_ERR_ATTRIBUTE_REDEFINED: C2RustUnnamed_0 = 42;
pub const XML_ERR_ATTRIBUTE_WITHOUT_VALUE: C2RustUnnamed_0 = 41;
pub const XML_ERR_ATTRIBUTE_NOT_FINISHED: C2RustUnnamed_0 = 40;
pub const XML_ERR_ATTRIBUTE_NOT_STARTED: C2RustUnnamed_0 = 39;
pub const XML_ERR_LT_IN_ATTRIBUTE: C2RustUnnamed_0 = 38;
pub const XML_ERR_ENTITY_NOT_FINISHED: C2RustUnnamed_0 = 37;
pub const XML_ERR_ENTITY_NOT_STARTED: C2RustUnnamed_0 = 36;
pub const XML_ERR_NS_DECL_ERROR: C2RustUnnamed_0 = 35;
pub const XML_ERR_STRING_NOT_CLOSED: C2RustUnnamed_0 = 34;
pub const XML_ERR_STRING_NOT_STARTED: C2RustUnnamed_0 = 33;
pub const XML_ERR_UNSUPPORTED_ENCODING: C2RustUnnamed_0 = 32;
pub const XML_ERR_UNKNOWN_ENCODING: C2RustUnnamed_0 = 31;
pub const XML_ERR_ENTITY_IS_PARAMETER: C2RustUnnamed_0 = 30;
pub const XML_ERR_ENTITY_IS_EXTERNAL: C2RustUnnamed_0 = 29;
pub const XML_ERR_UNPARSED_ENTITY: C2RustUnnamed_0 = 28;
pub const XML_WAR_UNDECLARED_ENTITY: C2RustUnnamed_0 = 27;
pub const XML_ERR_UNDECLARED_ENTITY: C2RustUnnamed_0 = 26;
pub const XML_ERR_PEREF_SEMICOL_MISSING: C2RustUnnamed_0 = 25;
pub const XML_ERR_PEREF_NO_NAME: C2RustUnnamed_0 = 24;
pub const XML_ERR_ENTITYREF_SEMICOL_MISSING: C2RustUnnamed_0 = 23;
pub const XML_ERR_ENTITYREF_NO_NAME: C2RustUnnamed_0 = 22;
pub const XML_ERR_PEREF_IN_INT_SUBSET: C2RustUnnamed_0 = 21;
pub const XML_ERR_PEREF_IN_EPILOG: C2RustUnnamed_0 = 20;
pub const XML_ERR_PEREF_IN_PROLOG: C2RustUnnamed_0 = 19;
pub const XML_ERR_PEREF_AT_EOF: C2RustUnnamed_0 = 18;
pub const XML_ERR_ENTITYREF_IN_DTD: C2RustUnnamed_0 = 17;
pub const XML_ERR_ENTITYREF_IN_EPILOG: C2RustUnnamed_0 = 16;
pub const XML_ERR_ENTITYREF_IN_PROLOG: C2RustUnnamed_0 = 15;
pub const XML_ERR_ENTITYREF_AT_EOF: C2RustUnnamed_0 = 14;
pub const XML_ERR_CHARREF_IN_DTD: C2RustUnnamed_0 = 13;
pub const XML_ERR_CHARREF_IN_EPILOG: C2RustUnnamed_0 = 12;
pub const XML_ERR_CHARREF_IN_PROLOG: C2RustUnnamed_0 = 11;
pub const XML_ERR_CHARREF_AT_EOF: C2RustUnnamed_0 = 10;
pub const XML_ERR_INVALID_CHAR: C2RustUnnamed_0 = 9;
pub const XML_ERR_INVALID_CHARREF: C2RustUnnamed_0 = 8;
pub const XML_ERR_INVALID_DEC_CHARREF: C2RustUnnamed_0 = 7;
pub const XML_ERR_INVALID_HEX_CHARREF: C2RustUnnamed_0 = 6;
pub const XML_ERR_DOCUMENT_END: C2RustUnnamed_0 = 5;
pub const XML_ERR_DOCUMENT_EMPTY: C2RustUnnamed_0 = 4;
pub const XML_ERR_DOCUMENT_START: C2RustUnnamed_0 = 3;
pub const XML_ERR_NO_MEMORY: C2RustUnnamed_0 = 2;
pub const XML_ERR_INTERNAL_ERROR: C2RustUnnamed_0 = 1;
pub const XML_ERR_OK: C2RustUnnamed_0 = 0;
pub type xmlGenericErrorFunc = crate::src::HTMLparser::xmlGenericErrorFunc;
pub type xmlFreeFunc = crate::src::HTMLparser::xmlFreeFunc;
pub type xmlMallocFunc = crate::src::HTMLparser::xmlMallocFunc;
pub type xmlReallocFunc = crate::src::HTMLparser::xmlReallocFunc;
pub type C2RustUnnamed_1 = u32;
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
// #[derive(Copy, Clone)]

pub type _xmlXPathContext = crate::src::debugXML::_xmlXPathContext;
pub type xmlXPathFuncLookupFunc = crate::src::debugXML::xmlXPathFuncLookupFunc;
pub type xmlXPathFunction = crate::src::debugXML::xmlXPathFunction;
pub type xmlXPathParserContextPtr = crate::src::debugXML::xmlXPathParserContextPtr;
pub type xmlXPathParserContext = crate::src::debugXML::xmlXPathParserContext;
// #[derive(Copy, Clone)]

pub type _xmlXPathParserContext = crate::src::debugXML::_xmlXPathParserContext;
pub type xmlXPathCompExprPtr = crate::src::debugXML::xmlXPathCompExprPtr;
pub type xmlXPathCompExpr = crate::src::debugXML::xmlXPathCompExpr;
pub type xmlXPathObjectPtr = crate::src::debugXML::xmlXPathObjectPtr;
pub type xmlXPathObject = crate::src::debugXML::xmlXPathObject;
// #[derive(Copy, Clone)]

pub type _xmlXPathObject = crate::src::debugXML::_xmlXPathObject;
pub type xmlNodeSetPtr = crate::src::c14n::xmlNodeSetPtr;
pub type xmlNodeSet = crate::src::c14n::xmlNodeSet;
// #[derive(Copy, Clone)]

pub type _xmlNodeSet = crate::src::c14n::_xmlNodeSet;
pub type xmlXPathObjectType = crate::src::debugXML::xmlXPathObjectType;
pub const XPATH_XSLT_TREE: xmlXPathObjectType = 9;
pub const XPATH_USERS: xmlXPathObjectType = 8;
pub const XPATH_STRING: xmlXPathObjectType = 4;
pub const XPATH_NUMBER: xmlXPathObjectType = 3;
pub const XPATH_BOOLEAN: xmlXPathObjectType = 2;
pub const XPATH_NODESET: xmlXPathObjectType = 1;
pub const XPATH_UNDEFINED: xmlXPathObjectType = 0;
pub type xmlXPathContextPtr = crate::src::debugXML::xmlXPathContextPtr;
pub type xmlXPathContext = crate::src::debugXML::xmlXPathContext;
pub type xmlXPathVariableLookupFunc = crate::src::debugXML::xmlXPathVariableLookupFunc;
pub type xmlXPathAxisPtr = crate::src::debugXML::xmlXPathAxisPtr;
pub type xmlXPathAxis = crate::src::debugXML::xmlXPathAxis;
// #[derive(Copy, Clone)]

pub type _xmlXPathAxis = crate::src::debugXML::_xmlXPathAxis;
pub type xmlXPathAxisFunc = crate::src::debugXML::xmlXPathAxisFunc;
pub type xmlXPathTypePtr = crate::src::debugXML::xmlXPathTypePtr;
pub type xmlXPathType = crate::src::debugXML::xmlXPathType;
// #[derive(Copy, Clone)]

pub type _xmlXPathType = crate::src::debugXML::_xmlXPathType;
pub type xmlXPathConvertFunc = crate::src::debugXML::xmlXPathConvertFunc;
pub type xmlPattern = crate::src::pattern::xmlPattern;
pub type xmlPatternPtr = crate::src::pattern::xmlPatternPtr;
pub type C2RustUnnamed_2 = u32;
pub const XML_PATTERN_XSFIELD: C2RustUnnamed_2 = 4;
pub const XML_PATTERN_XSSEL: C2RustUnnamed_2 = 2;
pub const XML_PATTERN_XPATH: C2RustUnnamed_2 = 1;
pub const XML_PATTERN_DEFAULT: C2RustUnnamed_2 = 0;
pub type C2RustUnnamed_3 = u32;
pub const XML_SCHEMATRON_OUT_IO: C2RustUnnamed_3 = 1024;
pub const XML_SCHEMATRON_OUT_BUFFER: C2RustUnnamed_3 = 512;
pub const XML_SCHEMATRON_OUT_FILE: C2RustUnnamed_3 = 256;
pub const XML_SCHEMATRON_OUT_ERROR: C2RustUnnamed_3 = 8;
pub const XML_SCHEMATRON_OUT_XML: C2RustUnnamed_3 = 4;
pub const XML_SCHEMATRON_OUT_TEXT: C2RustUnnamed_3 = 2;
pub const XML_SCHEMATRON_OUT_QUIET: C2RustUnnamed_3 = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchematron {
    pub name: *const xmlChar,
    pub preserve: i32,
    pub doc: xmlDocPtr,
    pub flags: i32,
    pub _private: *mut libc::c_void,
    pub dict: xmlDictPtr,
    pub title: *const xmlChar,
    pub nbNs: i32,
    pub nbPattern: i32,
    pub patterns: xmlSchematronPatternPtr,
    pub rules: xmlSchematronRulePtr,
    pub nbNamespaces: i32,
    pub maxNamespaces: i32,
    pub namespaces: *mut *const xmlChar,
}
pub type xmlSchematronRulePtr = *mut xmlSchematronRule;
pub type xmlSchematronRule = _xmlSchematronRule;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchematronRule {
    pub next: xmlSchematronRulePtr,
    pub patnext: xmlSchematronRulePtr,
    pub node: xmlNodePtr,
    pub context: *mut xmlChar,
    pub tests: xmlSchematronTestPtr,
    pub pattern: xmlPatternPtr,
    pub report: *mut xmlChar,
    pub lets: xmlSchematronLetPtr,
}
pub type xmlSchematronLetPtr = *mut xmlSchematronLet;
pub type xmlSchematronLet = _xmlSchematronLet;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchematronLet {
    pub next: xmlSchematronLetPtr,
    pub name: *mut xmlChar,
    pub comp: xmlXPathCompExprPtr,
}
pub type xmlSchematronTestPtr = *mut xmlSchematronTest;
pub type xmlSchematronTest = _xmlSchematronTest;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchematronTest {
    pub next: xmlSchematronTestPtr,
    pub type_0: xmlSchematronTestType,
    pub node: xmlNodePtr,
    pub test: *mut xmlChar,
    pub comp: xmlXPathCompExprPtr,
    pub report: *mut xmlChar,
}
pub type xmlSchematronTestType = u32;
pub const XML_SCHEMATRON_REPORT: xmlSchematronTestType = 2;
pub const XML_SCHEMATRON_ASSERT: xmlSchematronTestType = 1;
pub type xmlSchematronPatternPtr = *mut xmlSchematronPattern;
pub type xmlSchematronPattern = _xmlSchematronPattern;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchematronPattern {
    pub next: xmlSchematronPatternPtr,
    pub rules: xmlSchematronRulePtr,
    pub name: *mut xmlChar,
}
pub type xmlSchematron = _xmlSchematron;
pub type xmlSchematronPtr = *mut xmlSchematron;
pub type xmlSchematronValidityErrorFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
>;
pub type xmlSchematronValidityWarningFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchematronParserCtxt {
    pub type_0: i32,
    pub URL: *const xmlChar,
    pub doc: xmlDocPtr,
    pub preserve: i32,
    pub buffer: *const i8,
    pub size: i32,
    pub dict: xmlDictPtr,
    pub nberrors: i32,
    pub err: i32,
    pub xctxt: xmlXPathContextPtr,
    pub schema: xmlSchematronPtr,
    pub nbNamespaces: i32,
    pub maxNamespaces: i32,
    pub namespaces: *mut *const xmlChar,
    pub nbIncludes: i32,
    pub maxIncludes: i32,
    pub includes: *mut xmlNodePtr,
    pub userData: *mut libc::c_void,
    pub error: xmlSchematronValidityErrorFunc,
    pub warning: xmlSchematronValidityWarningFunc,
    pub serror: xmlStructuredErrorFunc,
}
pub type xmlSchematronParserCtxt = _xmlSchematronParserCtxt;
pub type xmlSchematronParserCtxtPtr = *mut xmlSchematronParserCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchematronValidCtxt {
    pub type_0: i32,
    pub flags: i32,
    pub dict: xmlDictPtr,
    pub nberrors: i32,
    pub err: i32,
    pub schema: xmlSchematronPtr,
    pub xctxt: xmlXPathContextPtr,
    pub outputFile: *mut FILE,
    pub outputBuffer: xmlBufferPtr,
    pub iowrite: xmlOutputWriteCallback,
    pub ioclose: xmlOutputCloseCallback,
    pub ioctx: *mut libc::c_void,
    pub userData: *mut libc::c_void,
    pub error: xmlSchematronValidityErrorFunc,
    pub warning: xmlSchematronValidityWarningFunc,
    pub serror: xmlStructuredErrorFunc,
}
pub type xmlSchematronValidCtxt = _xmlSchematronValidCtxt;
pub type xmlSchematronValidCtxtPtr = *mut xmlSchematronValidCtxt;
static mut xmlSchematronNs: *const xmlChar = b"http://purl.oclc.org/dsdl/schematron\0"
    as *const u8 as *const i8 as *mut xmlChar;
static mut xmlOldSchematronNs: *const xmlChar = b"http://www.ascc.net/xml/schematron\0"
    as *const u8 as *const i8 as *mut xmlChar;
unsafe extern "C" fn xmlSchematronPErrMemory(
    mut ctxt: xmlSchematronParserCtxtPtr,
    mut extra: *const i8,
    mut node: xmlNodePtr,
) {
    if !ctxt.is_null() {
        let fresh0 = &mut ((*ctxt).nberrors);
        *fresh0 += 1;
    }
    __xmlSimpleError(
        XML_FROM_SCHEMASP as i32,
        XML_ERR_NO_MEMORY as i32,
        node,
        0 as *const i8,
        extra,
    );
}
unsafe extern "C" fn xmlSchematronPErr(
    mut ctxt: xmlSchematronParserCtxtPtr,
    mut node: xmlNodePtr,
    mut error: i32,
    mut msg: *const i8,
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) {
    let mut channel: xmlGenericErrorFunc = None;
    let mut schannel: xmlStructuredErrorFunc = None;
    let mut data: *mut libc::c_void = 0 as *mut libc::c_void;
    if !ctxt.is_null() {
        let fresh1 = &mut ((*ctxt).nberrors);
        *fresh1 += 1;
        channel = (*ctxt).error;
        data = (*ctxt).userData;
        schannel = (*ctxt).serror;
    }
    __xmlRaiseError(
        schannel,
        channel,
        data,
        ctxt as *mut libc::c_void,
        node as *mut libc::c_void,
        XML_FROM_SCHEMASP as i32,
        error,
        XML_ERR_ERROR,
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
}
unsafe extern "C" fn xmlSchematronVErrMemory(
    mut ctxt: xmlSchematronValidCtxtPtr,
    mut extra: *const i8,
    mut node: xmlNodePtr,
) {
    if !ctxt.is_null() {
        let fresh2 = &mut ((*ctxt).nberrors);
        *fresh2 += 1;
        (*ctxt).err = XML_SCHEMAV_INTERNAL as i32;
    }
    __xmlSimpleError(
        XML_FROM_SCHEMASV as i32,
        XML_ERR_NO_MEMORY as i32,
        node,
        0 as *const i8,
        extra,
    );
}
unsafe extern "C" fn xmlSchematronAddTest(
    mut ctxt: xmlSchematronParserCtxtPtr,
    mut type_0: xmlSchematronTestType,
    mut rule: xmlSchematronRulePtr,
    mut node: xmlNodePtr,
    mut test: *mut xmlChar,
    mut report: *mut xmlChar,
) -> xmlSchematronTestPtr {
    let mut ret: xmlSchematronTestPtr = 0 as *mut xmlSchematronTest;
    let mut comp: xmlXPathCompExprPtr = 0 as *mut xmlXPathCompExpr;
    if ctxt.is_null() || rule.is_null() || node.is_null() || test.is_null() {
        return 0 as xmlSchematronTestPtr;
    }
    comp = xmlXPathCtxtCompile((*ctxt).xctxt, test);
    if comp.is_null() {
        xmlSchematronPErr(
            ctxt,
            node,
            XML_SCHEMAP_NOROOT as i32,
            b"Failed to compile test expression %s\0" as *const u8
                as *const i8,
            test,
            0 as *const xmlChar,
        );
        return 0 as xmlSchematronTestPtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlSchematronTest>() as u64)
        as xmlSchematronTestPtr;
    if ret.is_null() {
        xmlSchematronPErrMemory(
            ctxt,
            b"allocating schema test\0" as *const u8 as *const i8,
            node,
        );
        return 0 as xmlSchematronTestPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSchematronTest>() as u64,
    );
    (*ret).type_0 = type_0;
    let fresh3 = &mut ((*ret).node);
    *fresh3 = node;
    let fresh4 = &mut ((*ret).test);
    *fresh4 = test;
    let fresh5 = &mut ((*ret).comp);
    *fresh5 = comp;
    let fresh6 = &mut ((*ret).report);
    *fresh6 = report;
    let fresh7 = &mut ((*ret).next);
    *fresh7 = 0 as xmlSchematronTestPtr;
    if ((*rule).tests).is_null() {
        let fresh8 = &mut ((*rule).tests);
        *fresh8 = ret;
    } else {
        let mut prev: xmlSchematronTestPtr = (*rule).tests;
        while !((*prev).next).is_null() {
            prev = (*prev).next;
        }
        let fresh9 = &mut ((*prev).next);
        *fresh9 = ret;
    }
    return ret;
}
unsafe extern "C" fn xmlSchematronFreeTests(mut tests: xmlSchematronTestPtr) {
    let mut next: xmlSchematronTestPtr = 0 as *mut xmlSchematronTest;
    while !tests.is_null() {
        next = (*tests).next;
        if !((*tests).test).is_null() {
            xmlFree
                .expect("non-null function pointer")((*tests).test as *mut libc::c_void);
        }
        if !((*tests).comp).is_null() {
            xmlXPathFreeCompExpr((*tests).comp);
        }
        if !((*tests).report).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*tests).report as *mut libc::c_void);
        }
        xmlFree.expect("non-null function pointer")(tests as *mut libc::c_void);
        tests = next;
    }
}
unsafe extern "C" fn xmlSchematronFreeLets(mut lets: xmlSchematronLetPtr) {
    let mut next: xmlSchematronLetPtr = 0 as *mut xmlSchematronLet;
    while !lets.is_null() {
        next = (*lets).next;
        if !((*lets).name).is_null() {
            xmlFree
                .expect("non-null function pointer")((*lets).name as *mut libc::c_void);
        }
        if !((*lets).comp).is_null() {
            xmlXPathFreeCompExpr((*lets).comp);
        }
        xmlFree.expect("non-null function pointer")(lets as *mut libc::c_void);
        lets = next;
    }
}
unsafe extern "C" fn xmlSchematronAddRule(
    mut ctxt: xmlSchematronParserCtxtPtr,
    mut schema: xmlSchematronPtr,
    mut pat: xmlSchematronPatternPtr,
    mut node: xmlNodePtr,
    mut context: *mut xmlChar,
    mut report: *mut xmlChar,
) -> xmlSchematronRulePtr {
    let mut ret: xmlSchematronRulePtr = 0 as *mut xmlSchematronRule;
    let mut pattern: xmlPatternPtr = 0 as *mut xmlPattern;
    if ctxt.is_null() || schema.is_null() || node.is_null() || context.is_null() {
        return 0 as xmlSchematronRulePtr;
    }
    pattern = xmlPatterncompile(
        context,
        (*ctxt).dict,
        XML_PATTERN_XPATH as i32,
        (*ctxt).namespaces,
    );
    if pattern.is_null() {
        xmlSchematronPErr(
            ctxt,
            node,
            XML_SCHEMAP_NOROOT as i32,
            b"Failed to compile context expression %s\0" as *const u8
                as *const i8,
            context,
            0 as *const xmlChar,
        );
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlSchematronRule>() as u64)
        as xmlSchematronRulePtr;
    if ret.is_null() {
        xmlSchematronPErrMemory(
            ctxt,
            b"allocating schema rule\0" as *const u8 as *const i8,
            node,
        );
        return 0 as xmlSchematronRulePtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSchematronRule>() as u64,
    );
    let fresh10 = &mut ((*ret).node);
    *fresh10 = node;
    let fresh11 = &mut ((*ret).context);
    *fresh11 = context;
    let fresh12 = &mut ((*ret).pattern);
    *fresh12 = pattern;
    let fresh13 = &mut ((*ret).report);
    *fresh13 = report;
    let fresh14 = &mut ((*ret).next);
    *fresh14 = 0 as xmlSchematronRulePtr;
    let fresh15 = &mut ((*ret).lets);
    *fresh15 = 0 as xmlSchematronLetPtr;
    if ((*schema).rules).is_null() {
        let fresh16 = &mut ((*schema).rules);
        *fresh16 = ret;
    } else {
        let mut prev: xmlSchematronRulePtr = (*schema).rules;
        while !((*prev).next).is_null() {
            prev = (*prev).next;
        }
        let fresh17 = &mut ((*prev).next);
        *fresh17 = ret;
    }
    let fresh18 = &mut ((*ret).patnext);
    *fresh18 = 0 as xmlSchematronRulePtr;
    if ((*pat).rules).is_null() {
        let fresh19 = &mut ((*pat).rules);
        *fresh19 = ret;
    } else {
        let mut prev_0: xmlSchematronRulePtr = (*pat).rules;
        while !((*prev_0).patnext).is_null() {
            prev_0 = (*prev_0).patnext;
        }
        let fresh20 = &mut ((*prev_0).patnext);
        *fresh20 = ret;
    }
    return ret;
}
unsafe extern "C" fn xmlSchematronFreeRules(mut rules: xmlSchematronRulePtr) {
    let mut next: xmlSchematronRulePtr = 0 as *mut xmlSchematronRule;
    while !rules.is_null() {
        next = (*rules).next;
        if !((*rules).tests).is_null() {
            xmlSchematronFreeTests((*rules).tests);
        }
        if !((*rules).context).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*rules).context as *mut libc::c_void);
        }
        if !((*rules).pattern).is_null() {
            xmlFreePattern((*rules).pattern);
        }
        if !((*rules).report).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*rules).report as *mut libc::c_void);
        }
        if !((*rules).lets).is_null() {
            xmlSchematronFreeLets((*rules).lets);
        }
        xmlFree.expect("non-null function pointer")(rules as *mut libc::c_void);
        rules = next;
    }
}
unsafe extern "C" fn xmlSchematronAddPattern(
    mut ctxt: xmlSchematronParserCtxtPtr,
    mut schema: xmlSchematronPtr,
    mut node: xmlNodePtr,
    mut name: *mut xmlChar,
) -> xmlSchematronPatternPtr {
    let mut ret: xmlSchematronPatternPtr = 0 as *mut xmlSchematronPattern;
    if ctxt.is_null() || schema.is_null() || node.is_null() || name.is_null() {
        return 0 as xmlSchematronPatternPtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlSchematronPattern>() as u64)
        as xmlSchematronPatternPtr;
    if ret.is_null() {
        xmlSchematronPErrMemory(
            ctxt,
            b"allocating schema pattern\0" as *const u8 as *const i8,
            node,
        );
        return 0 as xmlSchematronPatternPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSchematronPattern>() as u64,
    );
    let fresh21 = &mut ((*ret).name);
    *fresh21 = name;
    let fresh22 = &mut ((*ret).next);
    *fresh22 = 0 as xmlSchematronPatternPtr;
    if ((*schema).patterns).is_null() {
        let fresh23 = &mut ((*schema).patterns);
        *fresh23 = ret;
    } else {
        let mut prev: xmlSchematronPatternPtr = (*schema).patterns;
        while !((*prev).next).is_null() {
            prev = (*prev).next;
        }
        let fresh24 = &mut ((*prev).next);
        *fresh24 = ret;
    }
    return ret;
}
unsafe extern "C" fn xmlSchematronFreePatterns(mut patterns: xmlSchematronPatternPtr) {
    let mut next: xmlSchematronPatternPtr = 0 as *mut xmlSchematronPattern;
    while !patterns.is_null() {
        next = (*patterns).next;
        if !((*patterns).name).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*patterns).name as *mut libc::c_void);
        }
        xmlFree.expect("non-null function pointer")(patterns as *mut libc::c_void);
        patterns = next;
    }
}
unsafe extern "C" fn xmlSchematronNewSchematron(
    mut ctxt: xmlSchematronParserCtxtPtr,
) -> xmlSchematronPtr {
    let mut ret: xmlSchematronPtr = 0 as *mut xmlSchematron;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlSchematron>() as u64) as xmlSchematronPtr;
    if ret.is_null() {
        xmlSchematronPErrMemory(
            ctxt,
            b"allocating schema\0" as *const u8 as *const i8,
            0 as xmlNodePtr,
        );
        return 0 as xmlSchematronPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSchematron>() as u64,
    );
    let fresh25 = &mut ((*ret).dict);
    *fresh25 = (*ctxt).dict;
    xmlDictReference((*ret).dict);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSchematronFree(mut schema: xmlSchematronPtr) {
    if schema.is_null() {
        return;
    }
    if !((*schema).doc).is_null() && (*schema).preserve == 0 {
        xmlFreeDoc((*schema).doc);
    }
    if !((*schema).namespaces).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*schema).namespaces as *mut *mut i8 as *mut libc::c_void);
    }
    xmlSchematronFreeRules((*schema).rules);
    xmlSchematronFreePatterns((*schema).patterns);
    xmlDictFree((*schema).dict);
    xmlFree.expect("non-null function pointer")(schema as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSchematronNewParserCtxt(
    mut URL: *const i8,
) -> xmlSchematronParserCtxtPtr {
    let mut ret: xmlSchematronParserCtxtPtr = 0 as *mut xmlSchematronParserCtxt;
    if URL.is_null() {
        return 0 as xmlSchematronParserCtxtPtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlSchematronParserCtxt>() as u64)
        as xmlSchematronParserCtxtPtr;
    if ret.is_null() {
        xmlSchematronPErrMemory(
            0 as xmlSchematronParserCtxtPtr,
            b"allocating schema parser context\0" as *const u8 as *const i8,
            0 as xmlNodePtr,
        );
        return 0 as xmlSchematronParserCtxtPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSchematronParserCtxt>() as u64,
    );
    (*ret).type_0 = 1 as i32;
    let fresh26 = &mut ((*ret).dict);
    *fresh26 = xmlDictCreate();
    let fresh27 = &mut ((*ret).URL);
    *fresh27 = xmlDictLookup((*ret).dict, URL as *const xmlChar, -(1 as i32));
    let fresh28 = &mut ((*ret).includes);
    *fresh28 = 0 as *mut xmlNodePtr;
    let fresh29 = &mut ((*ret).xctxt);
    *fresh29 = xmlXPathNewContext(0 as xmlDocPtr);
    if ((*ret).xctxt).is_null() {
        xmlSchematronPErrMemory(
            0 as xmlSchematronParserCtxtPtr,
            b"allocating schema parser XPath context\0" as *const u8
                as *const i8,
            0 as xmlNodePtr,
        );
        xmlSchematronFreeParserCtxt(ret);
        return 0 as xmlSchematronParserCtxtPtr;
    }
    (*(*ret).xctxt).flags = (1 as i32) << 0 as i32;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSchematronNewMemParserCtxt(
    mut buffer: *const i8,
    mut size: i32,
) -> xmlSchematronParserCtxtPtr {
    let mut ret: xmlSchematronParserCtxtPtr = 0 as *mut xmlSchematronParserCtxt;
    if buffer.is_null() || size <= 0 as i32 {
        return 0 as xmlSchematronParserCtxtPtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlSchematronParserCtxt>() as u64)
        as xmlSchematronParserCtxtPtr;
    if ret.is_null() {
        xmlSchematronPErrMemory(
            0 as xmlSchematronParserCtxtPtr,
            b"allocating schema parser context\0" as *const u8 as *const i8,
            0 as xmlNodePtr,
        );
        return 0 as xmlSchematronParserCtxtPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSchematronParserCtxt>() as u64,
    );
    let fresh30 = &mut ((*ret).buffer);
    *fresh30 = buffer;
    (*ret).size = size;
    let fresh31 = &mut ((*ret).dict);
    *fresh31 = xmlDictCreate();
    let fresh32 = &mut ((*ret).xctxt);
    *fresh32 = xmlXPathNewContext(0 as xmlDocPtr);
    if ((*ret).xctxt).is_null() {
        xmlSchematronPErrMemory(
            0 as xmlSchematronParserCtxtPtr,
            b"allocating schema parser XPath context\0" as *const u8
                as *const i8,
            0 as xmlNodePtr,
        );
        xmlSchematronFreeParserCtxt(ret);
        return 0 as xmlSchematronParserCtxtPtr;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSchematronNewDocParserCtxt(
    mut doc: xmlDocPtr,
) -> xmlSchematronParserCtxtPtr {
    let mut ret: xmlSchematronParserCtxtPtr = 0 as *mut xmlSchematronParserCtxt;
    if doc.is_null() {
        return 0 as xmlSchematronParserCtxtPtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlSchematronParserCtxt>() as u64)
        as xmlSchematronParserCtxtPtr;
    if ret.is_null() {
        xmlSchematronPErrMemory(
            0 as xmlSchematronParserCtxtPtr,
            b"allocating schema parser context\0" as *const u8 as *const i8,
            0 as xmlNodePtr,
        );
        return 0 as xmlSchematronParserCtxtPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSchematronParserCtxt>() as u64,
    );
    let fresh33 = &mut ((*ret).doc);
    *fresh33 = doc;
    let fresh34 = &mut ((*ret).dict);
    *fresh34 = xmlDictCreate();
    (*ret).preserve = 1 as i32;
    let fresh35 = &mut ((*ret).xctxt);
    *fresh35 = xmlXPathNewContext(doc);
    if ((*ret).xctxt).is_null() {
        xmlSchematronPErrMemory(
            0 as xmlSchematronParserCtxtPtr,
            b"allocating schema parser XPath context\0" as *const u8
                as *const i8,
            0 as xmlNodePtr,
        );
        xmlSchematronFreeParserCtxt(ret);
        return 0 as xmlSchematronParserCtxtPtr;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSchematronFreeParserCtxt(
    mut ctxt: xmlSchematronParserCtxtPtr,
) {
    if ctxt.is_null() {
        return;
    }
    if !((*ctxt).doc).is_null() && (*ctxt).preserve == 0 {
        xmlFreeDoc((*ctxt).doc);
    }
    if !((*ctxt).xctxt).is_null() {
        xmlXPathFreeContext((*ctxt).xctxt);
    }
    if !((*ctxt).namespaces).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).namespaces as *mut *mut i8 as *mut libc::c_void);
    }
    xmlDictFree((*ctxt).dict);
    xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void);
}
unsafe extern "C" fn xmlSchematronAddNamespace(
    mut ctxt: xmlSchematronParserCtxtPtr,
    mut prefix: *const xmlChar,
    mut ns: *const xmlChar,
) {
    if ((*ctxt).namespaces).is_null() {
        (*ctxt).maxNamespaces = 10 as i32;
        let fresh36 = &mut ((*ctxt).namespaces);
        *fresh36 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            (((*ctxt).maxNamespaces * 2 as i32) as u64)
                .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as u64),
        ) as *mut *const xmlChar;
        if ((*ctxt).namespaces).is_null() {
            xmlSchematronPErrMemory(
                0 as xmlSchematronParserCtxtPtr,
                b"allocating parser namespaces\0" as *const u8 as *const i8,
                0 as xmlNodePtr,
            );
            return;
        }
        (*ctxt).nbNamespaces = 0 as i32;
    } else if (*ctxt).nbNamespaces + 2 as i32 >= (*ctxt).maxNamespaces {
        let mut tmp: *mut *const xmlChar = 0 as *mut *const xmlChar;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).namespaces as *mut *mut xmlChar as *mut libc::c_void,
            (((*ctxt).maxNamespaces * 4 as i32) as u64)
                .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as u64),
        ) as *mut *const xmlChar;
        if tmp.is_null() {
            xmlSchematronPErrMemory(
                0 as xmlSchematronParserCtxtPtr,
                b"allocating parser namespaces\0" as *const u8 as *const i8,
                0 as xmlNodePtr,
            );
            return;
        }
        let fresh37 = &mut ((*ctxt).namespaces);
        *fresh37 = tmp;
        (*ctxt).maxNamespaces *= 2 as i32;
    }
    let fresh38 = &mut (*((*ctxt).namespaces)
        .offset((2 as i32 * (*ctxt).nbNamespaces) as isize));
    *fresh38 = xmlDictLookup((*ctxt).dict, ns, -(1 as i32));
    let fresh39 = &mut (*((*ctxt).namespaces)
        .offset((2 as i32 * (*ctxt).nbNamespaces + 1 as i32) as isize));
    *fresh39 = xmlDictLookup((*ctxt).dict, prefix, -(1 as i32));
    let fresh40 = &mut ((*ctxt).nbNamespaces);
    *fresh40 += 1;
    let fresh41 = &mut (*((*ctxt).namespaces)
        .offset((2 as i32 * (*ctxt).nbNamespaces) as isize));
    *fresh41 = 0 as *const xmlChar;
    let fresh42 = &mut (*((*ctxt).namespaces)
        .offset((2 as i32 * (*ctxt).nbNamespaces + 1 as i32) as isize));
    *fresh42 = 0 as *const xmlChar;
}
unsafe extern "C" fn xmlSchematronParseTestReportMsg(
    mut ctxt: xmlSchematronParserCtxtPtr,
    mut con: xmlNodePtr,
) {
    let mut child: xmlNodePtr = 0 as *mut xmlNode;
    let mut comp: xmlXPathCompExprPtr = 0 as *mut xmlXPathCompExpr;
    child = (*con).children;
    while !child.is_null() {
        if !((*child).type_0 as u32
            == XML_TEXT_NODE as i32 as u32
            || (*child).type_0 as u32
                == XML_CDATA_SECTION_NODE as i32 as u32)
        {
            if !(!child.is_null()
                && (*child).type_0 as u32
                    == XML_ELEMENT_NODE as i32 as u32
                && !((*child).ns).is_null()
                && xmlStrEqual(
                    (*child).name,
                    b"name\0" as *const u8 as *const i8 as *const xmlChar,
                ) != 0
                && (xmlStrEqual((*(*child).ns).href, xmlSchematronNs) != 0
                    || xmlStrEqual((*(*child).ns).href, xmlOldSchematronNs) != 0))
            {
                if !child.is_null()
                    && (*child).type_0 as u32
                        == XML_ELEMENT_NODE as i32 as u32
                    && !((*child).ns).is_null()
                    && xmlStrEqual(
                        (*child).name,
                        b"value-of\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) != 0
                    && (xmlStrEqual((*(*child).ns).href, xmlSchematronNs) != 0
                        || xmlStrEqual((*(*child).ns).href, xmlOldSchematronNs) != 0)
                {
                    let mut select: *mut xmlChar = 0 as *mut xmlChar;
                    select = xmlGetNoNsProp(
                        child as *const xmlNode,
                        b"select\0" as *const u8 as *const i8 as *mut xmlChar,
                    );
                    if select.is_null() {
                        xmlSchematronPErr(
                            ctxt,
                            child,
                            XML_SCHEMAV_ATTRINVALID as i32,
                            b"value-of has no select attribute\0" as *const u8
                                as *const i8,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                    } else {
                        comp = xmlXPathCtxtCompile((*ctxt).xctxt, select);
                        if comp.is_null() {
                            xmlSchematronPErr(
                                ctxt,
                                child,
                                XML_SCHEMAV_ATTRINVALID as i32,
                                b"Failed to compile select expression %s\0" as *const u8
                                    as *const i8,
                                select,
                                0 as *const xmlChar,
                            );
                        }
                        xmlXPathFreeCompExpr(comp);
                    }
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(select as *mut libc::c_void);
                }
            }
        }
        child = (*child).next;
    }
}
unsafe extern "C" fn xmlSchematronParseRule(
    mut ctxt: xmlSchematronParserCtxtPtr,
    mut pattern: xmlSchematronPatternPtr,
    mut rule: xmlNodePtr,
) {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut nbChecks: i32 = 0 as i32;
    let mut test: *mut xmlChar = 0 as *mut xmlChar;
    let mut context: *mut xmlChar = 0 as *mut xmlChar;
    let mut report: *mut xmlChar = 0 as *mut xmlChar;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut ruleptr: xmlSchematronRulePtr = 0 as *mut xmlSchematronRule;
    let mut testptr: xmlSchematronTestPtr = 0 as *mut xmlSchematronTest;
    if ctxt.is_null() || rule.is_null() {
        return;
    }
    context = xmlGetNoNsProp(
        rule as *const xmlNode,
        b"context\0" as *const u8 as *const i8 as *mut xmlChar,
    );
    if context.is_null() {
        xmlSchematronPErr(
            ctxt,
            rule,
            XML_SCHEMAP_NOROOT as i32,
            b"rule has no context attribute\0" as *const u8 as *const i8,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return;
    } else {
        if *context.offset(0 as i32 as isize) as i32 == 0 as i32
        {
            xmlSchematronPErr(
                ctxt,
                rule,
                XML_SCHEMAP_NOROOT as i32,
                b"rule has an empty context attribute\0" as *const u8
                    as *const i8,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            xmlFree.expect("non-null function pointer")(context as *mut libc::c_void);
            return;
        } else {
            ruleptr = xmlSchematronAddRule(
                ctxt,
                (*ctxt).schema,
                pattern,
                rule,
                context,
                0 as *mut xmlChar,
            );
            if ruleptr.is_null() {
                xmlFree
                    .expect("non-null function pointer")(context as *mut libc::c_void);
                return;
            }
        }
    }
    cur = (*rule).children;
    while !cur.is_null() {
        if (*cur).type_0 as u32
            == XML_ELEMENT_NODE as i32 as u32 && !((*cur).ns).is_null()
            && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
        {
            break;
        }
        cur = (*cur).next;
    }
    while !cur.is_null() {
        if !cur.is_null()
            && (*cur).type_0 as u32
                == XML_ELEMENT_NODE as i32 as u32
            && !((*cur).ns).is_null()
            && xmlStrEqual(
                (*cur).name,
                b"let\0" as *const u8 as *const i8 as *const xmlChar,
            ) != 0
            && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
        {
            let mut var_comp: xmlXPathCompExprPtr = 0 as *mut xmlXPathCompExpr;
            let mut let_0: xmlSchematronLetPtr = 0 as *mut xmlSchematronLet;
            name = xmlGetNoNsProp(
                cur as *const xmlNode,
                b"name\0" as *const u8 as *const i8 as *mut xmlChar,
            );
            if name.is_null() {
                xmlSchematronPErr(
                    ctxt,
                    cur,
                    XML_SCHEMAP_NOROOT as i32,
                    b"let has no name attribute\0" as *const u8 as *const i8,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                return;
            } else {
                if *name.offset(0 as i32 as isize) as i32
                    == 0 as i32
                {
                    xmlSchematronPErr(
                        ctxt,
                        cur,
                        XML_SCHEMAP_NOROOT as i32,
                        b"let has an empty name attribute\0" as *const u8
                            as *const i8,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    xmlFree
                        .expect("non-null function pointer")(name as *mut libc::c_void);
                    return;
                }
            }
            value = xmlGetNoNsProp(
                cur as *const xmlNode,
                b"value\0" as *const u8 as *const i8 as *mut xmlChar,
            );
            if value.is_null() {
                xmlSchematronPErr(
                    ctxt,
                    cur,
                    XML_SCHEMAP_NOROOT as i32,
                    b"let has no value attribute\0" as *const u8 as *const i8,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                return;
            } else {
                if *value.offset(0 as i32 as isize) as i32
                    == 0 as i32
                {
                    xmlSchematronPErr(
                        ctxt,
                        cur,
                        XML_SCHEMAP_NOROOT as i32,
                        b"let has an empty value attribute\0" as *const u8
                            as *const i8,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                    xmlFree
                        .expect("non-null function pointer")(value as *mut libc::c_void);
                    return;
                }
            }
            var_comp = xmlXPathCtxtCompile((*ctxt).xctxt, value);
            if var_comp.is_null() {
                xmlSchematronPErr(
                    ctxt,
                    cur,
                    XML_SCHEMAP_NOROOT as i32,
                    b"Failed to compile let expression %s\0" as *const u8
                        as *const i8,
                    value,
                    0 as *const xmlChar,
                );
                return;
            }
            let_0 = malloc(::std::mem::size_of::<xmlSchematronLet>() as u64)
                as xmlSchematronLetPtr;
            let fresh43 = &mut ((*let_0).name);
            *fresh43 = name;
            let fresh44 = &mut ((*let_0).comp);
            *fresh44 = var_comp;
            let fresh45 = &mut ((*let_0).next);
            *fresh45 = 0 as xmlSchematronLetPtr;
            if !((*ruleptr).lets).is_null() {
                let fresh46 = &mut ((*let_0).next);
                *fresh46 = (*ruleptr).lets;
            }
            let fresh47 = &mut ((*ruleptr).lets);
            *fresh47 = let_0;
            xmlFree.expect("non-null function pointer")(value as *mut libc::c_void);
        } else if !cur.is_null()
                && (*cur).type_0 as u32
                    == XML_ELEMENT_NODE as i32 as u32
                && !((*cur).ns).is_null()
                && xmlStrEqual(
                    (*cur).name,
                    b"assert\0" as *const u8 as *const i8 as *const xmlChar,
                ) != 0
                && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                    || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
            {
            nbChecks += 1;
            test = xmlGetNoNsProp(
                cur as *const xmlNode,
                b"test\0" as *const u8 as *const i8 as *mut xmlChar,
            );
            if test.is_null() {
                xmlSchematronPErr(
                    ctxt,
                    cur,
                    XML_SCHEMAP_NOROOT as i32,
                    b"assert has no test attribute\0" as *const u8
                        as *const i8,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
            } else if *test.offset(0 as i32 as isize) as i32
                    == 0 as i32
                {
                xmlSchematronPErr(
                    ctxt,
                    cur,
                    XML_SCHEMAP_NOROOT as i32,
                    b"assert has an empty test attribute\0" as *const u8
                        as *const i8,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                xmlFree.expect("non-null function pointer")(test as *mut libc::c_void);
            } else {
                xmlSchematronParseTestReportMsg(ctxt, cur);
                report = xmlNodeGetContent(cur as *const xmlNode);
                testptr = xmlSchematronAddTest(
                    ctxt,
                    XML_SCHEMATRON_ASSERT,
                    ruleptr,
                    cur,
                    test,
                    report,
                );
                if testptr.is_null() {
                    xmlFree
                        .expect("non-null function pointer")(test as *mut libc::c_void);
                }
            }
        } else if !cur.is_null()
                && (*cur).type_0 as u32
                    == XML_ELEMENT_NODE as i32 as u32
                && !((*cur).ns).is_null()
                && xmlStrEqual(
                    (*cur).name,
                    b"report\0" as *const u8 as *const i8 as *const xmlChar,
                ) != 0
                && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                    || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
            {
            nbChecks += 1;
            test = xmlGetNoNsProp(
                cur as *const xmlNode,
                b"test\0" as *const u8 as *const i8 as *mut xmlChar,
            );
            if test.is_null() {
                xmlSchematronPErr(
                    ctxt,
                    cur,
                    XML_SCHEMAP_NOROOT as i32,
                    b"assert has no test attribute\0" as *const u8
                        as *const i8,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
            } else if *test.offset(0 as i32 as isize) as i32
                    == 0 as i32
                {
                xmlSchematronPErr(
                    ctxt,
                    cur,
                    XML_SCHEMAP_NOROOT as i32,
                    b"assert has an empty test attribute\0" as *const u8
                        as *const i8,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                xmlFree.expect("non-null function pointer")(test as *mut libc::c_void);
            } else {
                xmlSchematronParseTestReportMsg(ctxt, cur);
                report = xmlNodeGetContent(cur as *const xmlNode);
                testptr = xmlSchematronAddTest(
                    ctxt,
                    XML_SCHEMATRON_REPORT,
                    ruleptr,
                    cur,
                    test,
                    report,
                );
                if testptr.is_null() {
                    xmlFree
                        .expect("non-null function pointer")(test as *mut libc::c_void);
                }
            }
        } else {
            xmlSchematronPErr(
                ctxt,
                cur,
                XML_SCHEMAP_NOROOT as i32,
                b"Expecting an assert or a report element instead of %s\0" as *const u8
                    as *const i8,
                (*cur).name,
                0 as *const xmlChar,
            );
        }
        cur = (*cur).next;
        while !cur.is_null() {
            if (*cur).type_0 as u32
                == XML_ELEMENT_NODE as i32 as u32
                && !((*cur).ns).is_null()
                && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                    || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
            {
                break;
            }
            cur = (*cur).next;
        }
    }
    if nbChecks == 0 as i32 {
        xmlSchematronPErr(
            ctxt,
            rule,
            XML_SCHEMAP_NOROOT as i32,
            b"rule has no assert nor report element\0" as *const u8
                as *const i8,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    }
}
unsafe extern "C" fn xmlSchematronParsePattern(
    mut ctxt: xmlSchematronParserCtxtPtr,
    mut pat: xmlNodePtr,
) {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pattern: xmlSchematronPatternPtr = 0 as *mut xmlSchematronPattern;
    let mut nbRules: i32 = 0 as i32;
    let mut id: *mut xmlChar = 0 as *mut xmlChar;
    if ctxt.is_null() || pat.is_null() {
        return;
    }
    id = xmlGetNoNsProp(
        pat as *const xmlNode,
        b"id\0" as *const u8 as *const i8 as *mut xmlChar,
    );
    if id.is_null() {
        id = xmlGetNoNsProp(
            pat as *const xmlNode,
            b"name\0" as *const u8 as *const i8 as *mut xmlChar,
        );
    }
    pattern = xmlSchematronAddPattern(ctxt, (*ctxt).schema, pat, id);
    if pattern.is_null() {
        if !id.is_null() {
            xmlFree.expect("non-null function pointer")(id as *mut libc::c_void);
        }
        return;
    }
    cur = (*pat).children;
    while !cur.is_null() {
        if (*cur).type_0 as u32
            == XML_ELEMENT_NODE as i32 as u32 && !((*cur).ns).is_null()
            && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
        {
            break;
        }
        cur = (*cur).next;
    }
    while !cur.is_null() {
        if !cur.is_null()
            && (*cur).type_0 as u32
                == XML_ELEMENT_NODE as i32 as u32
            && !((*cur).ns).is_null()
            && xmlStrEqual(
                (*cur).name,
                b"rule\0" as *const u8 as *const i8 as *const xmlChar,
            ) != 0
            && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
        {
            xmlSchematronParseRule(ctxt, pattern, cur);
            nbRules += 1;
        } else {
            xmlSchematronPErr(
                ctxt,
                cur,
                XML_SCHEMAP_NOROOT as i32,
                b"Expecting a rule element instead of %s\0" as *const u8
                    as *const i8,
                (*cur).name,
                0 as *const xmlChar,
            );
        }
        cur = (*cur).next;
        while !cur.is_null() {
            if (*cur).type_0 as u32
                == XML_ELEMENT_NODE as i32 as u32
                && !((*cur).ns).is_null()
                && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                    || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
            {
                break;
            }
            cur = (*cur).next;
        }
    }
    if nbRules == 0 as i32 {
        xmlSchematronPErr(
            ctxt,
            pat,
            XML_SCHEMAP_NOROOT as i32,
            b"Pattern has no rule element\0" as *const u8 as *const i8,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlSchematronParse(
    mut ctxt: xmlSchematronParserCtxtPtr,
) -> xmlSchematronPtr {
    let mut ret: xmlSchematronPtr = 0 as xmlSchematronPtr;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut root: xmlNodePtr = 0 as *mut xmlNode;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut preserve: i32 = 0 as i32;
    if ctxt.is_null() {
        return 0 as xmlSchematronPtr;
    }
    (*ctxt).nberrors = 0 as i32;
    if !((*ctxt).URL).is_null() {
        doc = xmlReadFile(
            (*ctxt).URL as *const i8,
            0 as *const i8,
            XML_PARSE_NOENT as i32,
        );
        if doc.is_null() {
            xmlSchematronPErr(
                ctxt,
                0 as xmlNodePtr,
                XML_SCHEMAP_FAILED_LOAD as i32,
                b"xmlSchematronParse: could not load '%s'.\n\0" as *const u8
                    as *const i8,
                (*ctxt).URL,
                0 as *const xmlChar,
            );
            return 0 as xmlSchematronPtr;
        }
        (*ctxt).preserve = 0 as i32;
    } else if !((*ctxt).buffer).is_null() {
        doc = xmlReadMemory(
            (*ctxt).buffer,
            (*ctxt).size,
            0 as *const i8,
            0 as *const i8,
            XML_PARSE_NOENT as i32,
        );
        if doc.is_null() {
            xmlSchematronPErr(
                ctxt,
                0 as xmlNodePtr,
                XML_SCHEMAP_FAILED_PARSE as i32,
                b"xmlSchematronParse: could not parse.\n\0" as *const u8
                    as *const i8,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            return 0 as xmlSchematronPtr;
        }
        let fresh48 = &mut ((*doc).URL);
        *fresh48 = xmlStrdup(
            b"in_memory_buffer\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        let fresh49 = &mut ((*ctxt).URL);
        *fresh49 = xmlDictLookup(
            (*ctxt).dict,
            b"in_memory_buffer\0" as *const u8 as *const i8 as *mut xmlChar,
            -(1 as i32),
        );
        (*ctxt).preserve = 0 as i32;
    } else if !((*ctxt).doc).is_null() {
        doc = (*ctxt).doc;
        preserve = 1 as i32;
        (*ctxt).preserve = 1 as i32;
    } else {
        xmlSchematronPErr(
            ctxt,
            0 as xmlNodePtr,
            XML_SCHEMAP_NOTHING_TO_PARSE as i32,
            b"xmlSchematronParse: could not parse.\n\0" as *const u8
                as *const i8,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        return 0 as xmlSchematronPtr;
    }
    root = xmlDocGetRootElement(doc as *const xmlDoc);
    if root.is_null() {
        xmlSchematronPErr(
            ctxt,
            doc as xmlNodePtr,
            XML_SCHEMAP_NOROOT as i32,
            b"The schema has no document element.\n\0" as *const u8
                as *const i8,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
        if preserve == 0 {
            xmlFreeDoc(doc);
        }
        return 0 as xmlSchematronPtr;
    }
    if !(!root.is_null()
        && (*root).type_0 as u32
            == XML_ELEMENT_NODE as i32 as u32 && !((*root).ns).is_null()
        && xmlStrEqual(
            (*root).name,
            b"schema\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        && (xmlStrEqual((*(*root).ns).href, xmlSchematronNs) != 0
            || xmlStrEqual((*(*root).ns).href, xmlOldSchematronNs) != 0))
    {
        xmlSchematronPErr(
            ctxt,
            root,
            XML_SCHEMAP_NOROOT as i32,
            b"The XML document '%s' is not a XML schematron document\0" as *const u8
                as *const i8,
            (*ctxt).URL,
            0 as *const xmlChar,
        );
    } else {
        ret = xmlSchematronNewSchematron(ctxt);
        if !ret.is_null() {
            let fresh50 = &mut ((*ctxt).schema);
            *fresh50 = ret;
            cur = (*root).children;
            while !cur.is_null() {
                if (*cur).type_0 as u32
                    == XML_ELEMENT_NODE as i32 as u32
                    && !((*cur).ns).is_null()
                    && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                        || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
                {
                    break;
                }
                cur = (*cur).next;
            }
            if !cur.is_null()
                && (*cur).type_0 as u32
                    == XML_ELEMENT_NODE as i32 as u32
                && !((*cur).ns).is_null()
                && xmlStrEqual(
                    (*cur).name,
                    b"title\0" as *const u8 as *const i8 as *const xmlChar,
                ) != 0
                && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                    || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
            {
                let mut title: *mut xmlChar = xmlNodeGetContent(cur as *const xmlNode);
                if !title.is_null() {
                    let fresh51 = &mut ((*ret).title);
                    *fresh51 = xmlDictLookup((*ret).dict, title, -(1 as i32));
                    xmlFree
                        .expect("non-null function pointer")(title as *mut libc::c_void);
                }
                cur = (*cur).next;
                while !cur.is_null() {
                    if (*cur).type_0 as u32
                        == XML_ELEMENT_NODE as i32 as u32
                        && !((*cur).ns).is_null()
                        && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                            || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
                    {
                        break;
                    }
                    cur = (*cur).next;
                }
            }
            while !cur.is_null()
                && (*cur).type_0 as u32
                    == XML_ELEMENT_NODE as i32 as u32
                && !((*cur).ns).is_null()
                && xmlStrEqual(
                    (*cur).name,
                    b"ns\0" as *const u8 as *const i8 as *const xmlChar,
                ) != 0
                && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                    || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
            {
                let mut prefix: *mut xmlChar = xmlGetNoNsProp(
                    cur as *const xmlNode,
                    b"prefix\0" as *const u8 as *const i8 as *mut xmlChar,
                );
                let mut uri: *mut xmlChar = xmlGetNoNsProp(
                    cur as *const xmlNode,
                    b"uri\0" as *const u8 as *const i8 as *mut xmlChar,
                );
                if uri.is_null()
                    || *uri.offset(0 as i32 as isize) as i32
                        == 0 as i32
                {
                    xmlSchematronPErr(
                        ctxt,
                        cur,
                        XML_SCHEMAP_NOROOT as i32,
                        b"ns element has no uri\0" as *const u8 as *const i8,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                }
                if prefix.is_null()
                    || *prefix.offset(0 as i32 as isize) as i32
                        == 0 as i32
                {
                    xmlSchematronPErr(
                        ctxt,
                        cur,
                        XML_SCHEMAP_NOROOT as i32,
                        b"ns element has no prefix\0" as *const u8
                            as *const i8,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                }
                if !prefix.is_null() && !uri.is_null() {
                    xmlXPathRegisterNs((*ctxt).xctxt, prefix, uri);
                    xmlSchematronAddNamespace(ctxt, prefix, uri);
                    let fresh52 = &mut ((*ret).nbNs);
                    *fresh52 += 1;
                }
                if !uri.is_null() {
                    xmlFree
                        .expect("non-null function pointer")(uri as *mut libc::c_void);
                }
                if !prefix.is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(prefix as *mut libc::c_void);
                }
                cur = (*cur).next;
                while !cur.is_null() {
                    if (*cur).type_0 as u32
                        == XML_ELEMENT_NODE as i32 as u32
                        && !((*cur).ns).is_null()
                        && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                            || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
                    {
                        break;
                    }
                    cur = (*cur).next;
                }
            }
            while !cur.is_null() {
                if !cur.is_null()
                    && (*cur).type_0 as u32
                        == XML_ELEMENT_NODE as i32 as u32
                    && !((*cur).ns).is_null()
                    && xmlStrEqual(
                        (*cur).name,
                        b"pattern\0" as *const u8 as *const i8
                            as *const xmlChar,
                    ) != 0
                    && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                        || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
                {
                    xmlSchematronParsePattern(ctxt, cur);
                    let fresh53 = &mut ((*ret).nbPattern);
                    *fresh53 += 1;
                } else {
                    xmlSchematronPErr(
                        ctxt,
                        cur,
                        XML_SCHEMAP_NOROOT as i32,
                        b"Expecting a pattern element instead of %s\0" as *const u8
                            as *const i8,
                        (*cur).name,
                        0 as *const xmlChar,
                    );
                }
                cur = (*cur).next;
                while !cur.is_null() {
                    if (*cur).type_0 as u32
                        == XML_ELEMENT_NODE as i32 as u32
                        && !((*cur).ns).is_null()
                        && (xmlStrEqual((*(*cur).ns).href, xmlSchematronNs) != 0
                            || xmlStrEqual((*(*cur).ns).href, xmlOldSchematronNs) != 0)
                    {
                        break;
                    }
                    cur = (*cur).next;
                }
            }
            if (*ret).nbPattern == 0 as i32 {
                xmlSchematronPErr(
                    ctxt,
                    root,
                    XML_SCHEMAP_NOROOT as i32,
                    b"The schematron document '%s' has no pattern\0" as *const u8
                        as *const i8,
                    (*ctxt).URL,
                    0 as *const xmlChar,
                );
            } else {
                let fresh54 = &mut ((*ret).doc);
                *fresh54 = doc;
                if preserve != 0 {
                    (*ret).preserve = 1 as i32;
                }
                preserve = 1 as i32;
            }
        }
    }
    if preserve == 0 {
        xmlFreeDoc(doc);
    }
    if !ret.is_null() {
        if (*ctxt).nberrors != 0 as i32 {
            xmlSchematronFree(ret);
            ret = 0 as xmlSchematronPtr;
        } else {
            let fresh55 = &mut ((*ret).namespaces);
            *fresh55 = (*ctxt).namespaces;
            (*ret).nbNamespaces = (*ctxt).nbNamespaces;
            let fresh56 = &mut ((*ctxt).namespaces);
            *fresh56 = 0 as *mut *const xmlChar;
        }
    }
    return ret;
}
unsafe extern "C" fn xmlSchematronGetNode(
    mut ctxt: xmlSchematronValidCtxtPtr,
    mut cur: xmlNodePtr,
    mut xpath: *const xmlChar,
) -> xmlNodePtr {
    let mut node: xmlNodePtr = 0 as xmlNodePtr;
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    if ctxt.is_null() || cur.is_null() || xpath.is_null() {
        return 0 as xmlNodePtr;
    }
    let fresh57 = &mut ((*(*ctxt).xctxt).doc);
    *fresh57 = (*cur).doc;
    let fresh58 = &mut ((*(*ctxt).xctxt).node);
    *fresh58 = cur;
    ret = xmlXPathEval(xpath, (*ctxt).xctxt);
    if ret.is_null() {
        return 0 as xmlNodePtr;
    }
    if (*ret).type_0 as u32 == XPATH_NODESET as i32 as u32
        && !((*ret).nodesetval).is_null()
        && (*(*ret).nodesetval).nodeNr > 0 as i32
    {
        node = *((*(*ret).nodesetval).nodeTab).offset(0 as i32 as isize);
    }
    xmlXPathFreeObject(ret);
    return node;
}
unsafe extern "C" fn xmlSchematronReportOutput(
    mut ctxt: xmlSchematronValidCtxtPtr,
    mut cur: xmlNodePtr,
    mut msg: *const i8,
) {
    fprintf(stderr, b"%s\0" as *const u8 as *const i8, msg);
}
unsafe extern "C" fn xmlSchematronFormatReport(
    mut ctxt: xmlSchematronValidCtxtPtr,
    mut test: xmlNodePtr,
    mut cur: xmlNodePtr,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut child: xmlNodePtr = 0 as *mut xmlNode;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut comp: xmlXPathCompExprPtr = 0 as *mut xmlXPathCompExpr;
    if test.is_null() || cur.is_null() {
        return ret;
    }
    child = (*test).children;
    while !child.is_null() {
        if (*child).type_0 as u32
            == XML_TEXT_NODE as i32 as u32
            || (*child).type_0 as u32
                == XML_CDATA_SECTION_NODE as i32 as u32
        {
            ret = xmlStrcat(ret, (*child).content);
        } else if !child.is_null()
                && (*child).type_0 as u32
                    == XML_ELEMENT_NODE as i32 as u32
                && !((*child).ns).is_null()
                && xmlStrEqual(
                    (*child).name,
                    b"name\0" as *const u8 as *const i8 as *const xmlChar,
                ) != 0
                && (xmlStrEqual((*(*child).ns).href, xmlSchematronNs) != 0
                    || xmlStrEqual((*(*child).ns).href, xmlOldSchematronNs) != 0)
            {
            let mut path: *mut xmlChar = 0 as *mut xmlChar;
            path = xmlGetNoNsProp(
                child as *const xmlNode,
                b"path\0" as *const u8 as *const i8 as *mut xmlChar,
            );
            node = cur;
            if !path.is_null() {
                node = xmlSchematronGetNode(ctxt, cur, path);
                if node.is_null() {
                    node = cur;
                }
                xmlFree.expect("non-null function pointer")(path as *mut libc::c_void);
            }
            if ((*node).ns).is_null() || ((*(*node).ns).prefix).is_null() {
                ret = xmlStrcat(ret, (*node).name);
            } else {
                ret = xmlStrcat(ret, (*(*node).ns).prefix);
                ret = xmlStrcat(
                    ret,
                    b":\0" as *const u8 as *const i8 as *mut xmlChar,
                );
                ret = xmlStrcat(ret, (*node).name);
            }
        } else if !child.is_null()
                && (*child).type_0 as u32
                    == XML_ELEMENT_NODE as i32 as u32
                && !((*child).ns).is_null()
                && xmlStrEqual(
                    (*child).name,
                    b"value-of\0" as *const u8 as *const i8 as *const xmlChar,
                ) != 0
                && (xmlStrEqual((*(*child).ns).href, xmlSchematronNs) != 0
                    || xmlStrEqual((*(*child).ns).href, xmlOldSchematronNs) != 0)
            {
            let mut select: *mut xmlChar = 0 as *mut xmlChar;
            let mut eval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
            select = xmlGetNoNsProp(
                child as *const xmlNode,
                b"select\0" as *const u8 as *const i8 as *mut xmlChar,
            );
            comp = xmlXPathCtxtCompile((*ctxt).xctxt, select);
            eval = xmlXPathCompiledEval(comp, (*ctxt).xctxt);
            match (*eval).type_0 as u32 {
                1 => {
                    let mut indx: i32 = 0;
                    let mut spacer: *mut xmlChar = b" \0" as *const u8
                        as *const i8 as *mut xmlChar;
                    if !((*eval).nodesetval).is_null() {
                        indx = 0 as i32;
                        while indx < (*(*eval).nodesetval).nodeNr {
                            if indx > 0 as i32 {
                                ret = xmlStrcat(ret, spacer);
                            }
                            ret = xmlStrcat(
                                ret,
                                (**((*(*eval).nodesetval).nodeTab).offset(indx as isize))
                                    .name,
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
                    let mut str: *const i8 = if (*eval).boolval != 0 {
                        b"True\0" as *const u8 as *const i8
                    } else {
                        b"False\0" as *const u8 as *const i8
                    };
                    ret = xmlStrcat(ret, str as *mut xmlChar);
                }
                3 => {
                    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
                    let mut size: i32 = 0;
                    size = snprintf(
                        0 as *mut i8,
                        0 as i32 as u64,
                        b"%0g\0" as *const u8 as *const i8,
                        (*eval).floatval,
                    );
                    buf = malloc(
                        (size as u64)
                            .wrapping_mul(
                                ::std::mem::size_of::<xmlChar>() as u64,
                            ),
                    ) as *mut xmlChar;
                    sprintf(
                        buf as *mut i8,
                        b"%0g\0" as *const u8 as *const i8,
                        (*eval).floatval,
                    );
                    ret = xmlStrcat(ret, buf);
                    free(buf as *mut libc::c_void);
                }
                4 => {
                    ret = xmlStrcat(ret, (*eval).stringval);
                }
                _ => {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"Unsupported XPATH Type: %d\n\0" as *const u8
                            as *const i8,
                        (*eval).type_0 as u32,
                    );
                }
            }
            xmlXPathFreeObject(eval);
            xmlXPathFreeCompExpr(comp);
            xmlFree.expect("non-null function pointer")(select as *mut libc::c_void);
        } else {
            child = (*child).next;
            continue;
        }
        if !ret.is_null() {
            let mut len: i32 = xmlStrlen(ret);
            let mut c: xmlChar = 0;
            if len > 0 as i32 {
                c = *ret.offset((len - 1 as i32) as isize);
                if c as i32 == ' ' as i32 || c as i32 == '\n' as i32
                    || c as i32 == '\r' as i32 || c as i32 == '\t' as i32
                {
                    while c as i32 == ' ' as i32
                        || c as i32 == '\n' as i32
                        || c as i32 == '\r' as i32
                        || c as i32 == '\t' as i32
                    {
                        len -= 1;
                        if len == 0 as i32 {
                            break;
                        }
                        c = *ret.offset((len - 1 as i32) as isize);
                    }
                    *ret.offset(len as isize) = ' ' as i32 as xmlChar;
                    *ret
                        .offset(
                            (len + 1 as i32) as isize,
                        ) = 0 as i32 as xmlChar;
                }
            }
        }
        child = (*child).next;
    }
    return ret;
}
unsafe extern "C" fn xmlSchematronReportSuccess(
    mut ctxt: xmlSchematronValidCtxtPtr,
    mut test: xmlSchematronTestPtr,
    mut cur: xmlNodePtr,
    mut pattern: xmlSchematronPatternPtr,
    mut success: i32,
) {
    if ctxt.is_null() || cur.is_null() || test.is_null() {
        return;
    }
    if (*ctxt).flags & XML_SCHEMATRON_OUT_QUIET as i32 != 0
        && (*ctxt).flags & XML_SCHEMATRON_OUT_XML as i32 == 0 as i32
        && (*test).type_0 as u32
            == XML_SCHEMATRON_REPORT as i32 as u32
    {
        return;
    }
    if (*ctxt).flags & XML_SCHEMATRON_OUT_XML as i32 != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
            b"schematron.c\0" as *const u8 as *const i8,
            1580 as i32,
        );
    } else {
        let mut path: *mut xmlChar = 0 as *mut xmlChar;
        let mut msg: [i8; 1000] = [0; 1000];
        let mut line: i64 = 0;
        let mut report: *const xmlChar = 0 as *const xmlChar;
        if ((*test).type_0 as u32
            == XML_SCHEMATRON_REPORT as i32 as u32) as i32
            & (success == 0) as i32 != 0
            || ((*test).type_0 as u32
                == XML_SCHEMATRON_ASSERT as i32 as u32) as i32
                & success != 0
        {
            return;
        }
        line = xmlGetLineNo(cur as *const xmlNode);
        path = xmlGetNodePath(cur as *const xmlNode);
        if path.is_null() {
            path = (*cur).name as *mut xmlChar;
        }
        if !((*test).node).is_null() {
            report = xmlSchematronFormatReport(ctxt, (*test).node, cur);
        }
        if report.is_null() {
            if (*test).type_0 as u32
                == XML_SCHEMATRON_ASSERT as i32 as u32
            {
                report = xmlStrdup(
                    b"node failed assert\0" as *const u8 as *const i8
                        as *const xmlChar,
                );
            } else {
                report = xmlStrdup(
                    b"node failed report\0" as *const u8 as *const i8
                        as *const xmlChar,
                );
            }
        }
        snprintf(
            msg.as_mut_ptr(),
            999 as i32 as u64,
            b"%s line %ld: %s\n\0" as *const u8 as *const i8,
            path as *const i8,
            line,
            report as *const i8,
        );
        if (*ctxt).flags & XML_SCHEMATRON_OUT_ERROR as i32 != 0 {
            let mut schannel: xmlStructuredErrorFunc = None;
            let mut channel: xmlGenericErrorFunc = None;
            let mut data: *mut libc::c_void = 0 as *mut libc::c_void;
            if !ctxt.is_null() {
                if ((*ctxt).serror).is_some() {
                    schannel = (*ctxt).serror;
                } else {
                    channel = (*ctxt).error;
                }
                data = (*ctxt).userData;
            }
            __xmlRaiseError(
                schannel,
                channel,
                data,
                0 as *mut libc::c_void,
                cur as *mut libc::c_void,
                XML_FROM_SCHEMATRONV as i32,
                if (*test).type_0 as u32
                    == XML_SCHEMATRON_ASSERT as i32 as u32
                {
                    XML_SCHEMATRONV_ASSERT as i32
                } else {
                    XML_SCHEMATRONV_REPORT as i32
                },
                XML_ERR_ERROR,
                0 as *const i8,
                line as i32,
                if pattern.is_null() {
                    0 as *const i8
                } else {
                    (*pattern).name as *const i8
                },
                path as *const i8,
                report as *const i8,
                0 as i32,
                0 as i32,
                b"%s\0" as *const u8 as *const i8,
                msg.as_mut_ptr(),
            );
        } else {
            xmlSchematronReportOutput(
                ctxt,
                cur,
                &mut *msg.as_mut_ptr().offset(0 as i32 as isize),
            );
        }
        xmlFree
            .expect(
                "non-null function pointer",
            )(report as *mut i8 as *mut libc::c_void);
        if !path.is_null() && path != (*cur).name as *mut xmlChar {
            xmlFree.expect("non-null function pointer")(path as *mut libc::c_void);
        }
    };
}
unsafe extern "C" fn xmlSchematronReportPattern(
    mut ctxt: xmlSchematronValidCtxtPtr,
    mut pattern: xmlSchematronPatternPtr,
) {
    if ctxt.is_null() || pattern.is_null() {
        return;
    }
    if (*ctxt).flags & XML_SCHEMATRON_OUT_QUIET as i32 != 0
        || (*ctxt).flags & XML_SCHEMATRON_OUT_ERROR as i32 != 0
    {
        return;
    }
    if (*ctxt).flags & XML_SCHEMATRON_OUT_XML as i32 != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
            b"schematron.c\0" as *const u8 as *const i8,
            1657 as i32,
        );
    } else {
        let mut msg: [i8; 1000] = [0; 1000];
        if ((*pattern).name).is_null() {
            return;
        }
        snprintf(
            msg.as_mut_ptr(),
            999 as i32 as u64,
            b"Pattern: %s\n\0" as *const u8 as *const i8,
            (*pattern).name as *const i8,
        );
        xmlSchematronReportOutput(
            ctxt,
            0 as xmlNodePtr,
            &mut *msg.as_mut_ptr().offset(0 as i32 as isize),
        );
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlSchematronSetValidStructuredErrors(
    mut ctxt: xmlSchematronValidCtxtPtr,
    mut serror: xmlStructuredErrorFunc,
    mut ctx: *mut libc::c_void,
) {
    if ctxt.is_null() {
        return;
    }
    let fresh59 = &mut ((*ctxt).serror);
    *fresh59 = serror;
    let fresh60 = &mut ((*ctxt).error);
    *fresh60 = None;
    let fresh61 = &mut ((*ctxt).warning);
    *fresh61 = None;
    let fresh62 = &mut ((*ctxt).userData);
    *fresh62 = ctx;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSchematronNewValidCtxt(
    mut schema: xmlSchematronPtr,
    mut options: i32,
) -> xmlSchematronValidCtxtPtr {
    let mut i: i32 = 0;
    let mut ret: xmlSchematronValidCtxtPtr = 0 as *mut xmlSchematronValidCtxt;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlSchematronValidCtxt>() as u64)
        as xmlSchematronValidCtxtPtr;
    if ret.is_null() {
        xmlSchematronVErrMemory(
            0 as xmlSchematronValidCtxtPtr,
            b"allocating validation context\0" as *const u8 as *const i8,
            0 as xmlNodePtr,
        );
        return 0 as xmlSchematronValidCtxtPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlSchematronValidCtxt>() as u64,
    );
    (*ret).type_0 = 2 as i32;
    let fresh63 = &mut ((*ret).schema);
    *fresh63 = schema;
    let fresh64 = &mut ((*ret).xctxt);
    *fresh64 = xmlXPathNewContext(0 as xmlDocPtr);
    (*ret).flags = options;
    if ((*ret).xctxt).is_null() {
        xmlSchematronPErrMemory(
            0 as xmlSchematronParserCtxtPtr,
            b"allocating schema parser XPath context\0" as *const u8
                as *const i8,
            0 as xmlNodePtr,
        );
        xmlSchematronFreeValidCtxt(ret);
        return 0 as xmlSchematronValidCtxtPtr;
    }
    i = 0 as i32;
    while i < (*schema).nbNamespaces {
        if (*((*schema).namespaces).offset((2 as i32 * i) as isize)).is_null()
            || (*((*schema).namespaces)
                .offset((2 as i32 * i + 1 as i32) as isize))
                .is_null()
        {
            break;
        }
        xmlXPathRegisterNs(
            (*ret).xctxt,
            *((*schema).namespaces)
                .offset((2 as i32 * i + 1 as i32) as isize),
            *((*schema).namespaces).offset((2 as i32 * i) as isize),
        );
        i += 1;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSchematronFreeValidCtxt(
    mut ctxt: xmlSchematronValidCtxtPtr,
) {
    if ctxt.is_null() {
        return;
    }
    if !((*ctxt).xctxt).is_null() {
        xmlXPathFreeContext((*ctxt).xctxt);
    }
    if !((*ctxt).dict).is_null() {
        xmlDictFree((*ctxt).dict);
    }
    xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void);
}
unsafe extern "C" fn xmlSchematronNextNode(mut cur: xmlNodePtr) -> xmlNodePtr {
    if !((*cur).children).is_null() {
        if (*(*cur).children).type_0 as u32
            != XML_ENTITY_DECL as i32 as u32
        {
            cur = (*cur).children;
            if (*cur).type_0 as u32
                != XML_DTD_NODE as i32 as u32
            {
                return cur;
            }
        }
    }
    while !((*cur).next).is_null() {
        cur = (*cur).next;
        if (*cur).type_0 as u32
            != XML_ENTITY_DECL as i32 as u32
            && (*cur).type_0 as u32
                != XML_DTD_NODE as i32 as u32
        {
            return cur;
        }
    }
    loop {
        cur = (*cur).parent;
        if cur.is_null() {
            break;
        }
        if (*cur).type_0 as u32
            == XML_DOCUMENT_NODE as i32 as u32
        {
            return 0 as xmlNodePtr;
        }
        if !((*cur).next).is_null() {
            cur = (*cur).next;
            return cur;
        }
        if cur.is_null() {
            break;
        }
    }
    return cur;
}
unsafe extern "C" fn xmlSchematronRunTest(
    mut ctxt: xmlSchematronValidCtxtPtr,
    mut test: xmlSchematronTestPtr,
    mut instance: xmlDocPtr,
    mut cur: xmlNodePtr,
    mut pattern: xmlSchematronPatternPtr,
) -> i32 {
    let mut ret: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut failed: i32 = 0;
    failed = 0 as i32;
    let fresh65 = &mut ((*(*ctxt).xctxt).doc);
    *fresh65 = instance;
    let fresh66 = &mut ((*(*ctxt).xctxt).node);
    *fresh66 = cur;
    ret = xmlXPathCompiledEval((*test).comp, (*ctxt).xctxt);
    if ret.is_null() {
        failed = 1 as i32;
    } else {
        match (*ret).type_0 as u32 {
            9 | 1 => {
                if ((*ret).nodesetval).is_null()
                    || (*(*ret).nodesetval).nodeNr == 0 as i32
                {
                    failed = 1 as i32;
                }
            }
            2 => {
                failed = ((*ret).boolval == 0) as i32;
            }
            3 => {
                if xmlXPathIsNaN((*ret).floatval) != 0 || (*ret).floatval == 0.0f64 {
                    failed = 1 as i32;
                }
            }
            4 => {
                if ((*ret).stringval).is_null()
                    || *((*ret).stringval).offset(0 as i32 as isize)
                        as i32 == 0 as i32
                {
                    failed = 1 as i32;
                }
            }
            0 | 8 => {
                failed = 1 as i32;
            }
            _ => {}
        }
        xmlXPathFreeObject(ret);
    }
    if failed != 0
        && (*test).type_0 as u32
            == XML_SCHEMATRON_ASSERT as i32 as u32
    {
        let fresh67 = &mut ((*ctxt).nberrors);
        *fresh67 += 1;
    } else if failed == 0
            && (*test).type_0 as u32
                == XML_SCHEMATRON_REPORT as i32 as u32
        {
        let fresh68 = &mut ((*ctxt).nberrors);
        *fresh68 += 1;
    }
    xmlSchematronReportSuccess(ctxt, test, cur, pattern, (failed == 0) as i32);
    return (failed == 0) as i32;
}
unsafe extern "C" fn xmlSchematronRegisterVariables(
    mut ctxt: xmlXPathContextPtr,
    mut let_0: xmlSchematronLetPtr,
    mut instance: xmlDocPtr,
    mut cur: xmlNodePtr,
) -> i32 {
    let mut let_eval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let fresh69 = &mut ((*ctxt).doc);
    *fresh69 = instance;
    let fresh70 = &mut ((*ctxt).node);
    *fresh70 = cur;
    while !let_0.is_null() {
        let_eval = xmlXPathCompiledEval((*let_0).comp, ctxt);
        if let_eval.is_null() {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Evaluation of compiled expression failed\n\0" as *const u8
                    as *const i8,
            );
            return -(1 as i32);
        }
        if xmlXPathRegisterVariableNS(ctxt, (*let_0).name, 0 as *const xmlChar, let_eval)
            != 0
        {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Registering a let variable failed\n\0" as *const u8
                    as *const i8,
            );
            return -(1 as i32);
        }
        let_0 = (*let_0).next;
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlSchematronUnregisterVariables(
    mut ctxt: xmlXPathContextPtr,
    mut let_0: xmlSchematronLetPtr,
) -> i32 {
    while !let_0.is_null() {
        if xmlXPathRegisterVariableNS(
            ctxt,
            (*let_0).name,
            0 as *const xmlChar,
            0 as xmlXPathObjectPtr,
        ) != 0
        {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Unregistering a let variable failed\n\0" as *const u8
                    as *const i8,
            );
            return -(1 as i32);
        }
        let_0 = (*let_0).next;
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSchematronValidateDoc(
    mut ctxt: xmlSchematronValidCtxtPtr,
    mut instance: xmlDocPtr,
) -> i32 {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut root: xmlNodePtr = 0 as *mut xmlNode;
    let mut pattern: xmlSchematronPatternPtr = 0 as *mut xmlSchematronPattern;
    let mut rule: xmlSchematronRulePtr = 0 as *mut xmlSchematronRule;
    let mut test: xmlSchematronTestPtr = 0 as *mut xmlSchematronTest;
    if ctxt.is_null() || ((*ctxt).schema).is_null()
        || ((*(*ctxt).schema).rules).is_null() || instance.is_null()
    {
        return -(1 as i32);
    }
    (*ctxt).nberrors = 0 as i32;
    root = xmlDocGetRootElement(instance as *const xmlDoc);
    if root.is_null() {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Unimplemented block at %s:%d\n\0" as *const u8 as *const i8,
            b"schematron.c\0" as *const u8 as *const i8,
            1940 as i32,
        );
        let fresh71 = &mut ((*ctxt).nberrors);
        *fresh71 += 1;
        return 1 as i32;
    }
    if (*ctxt).flags & XML_SCHEMATRON_OUT_QUIET as i32 != 0
        || (*ctxt).flags == 0 as i32
    {
        cur = root;
        while !cur.is_null() {
            rule = (*(*ctxt).schema).rules;
            while !rule.is_null() {
                if xmlPatternMatch((*rule).pattern, cur) == 1 as i32 {
                    test = (*rule).tests;
                    if xmlSchematronRegisterVariables(
                        (*ctxt).xctxt,
                        (*rule).lets,
                        instance,
                        cur,
                    ) != 0
                    {
                        return -(1 as i32);
                    }
                    while !test.is_null() {
                        xmlSchematronRunTest(
                            ctxt,
                            test,
                            instance,
                            cur,
                            (*rule).pattern as xmlSchematronPatternPtr,
                        );
                        test = (*test).next;
                    }
                    if xmlSchematronUnregisterVariables((*ctxt).xctxt, (*rule).lets) != 0
                    {
                        return -(1 as i32);
                    }
                }
                rule = (*rule).next;
            }
            cur = xmlSchematronNextNode(cur);
        }
    } else {
        pattern = (*(*ctxt).schema).patterns;
        while !pattern.is_null() {
            xmlSchematronReportPattern(ctxt, pattern);
            cur = root;
            while !cur.is_null() {
                rule = (*pattern).rules;
                while !rule.is_null() {
                    if xmlPatternMatch((*rule).pattern, cur) == 1 as i32 {
                        test = (*rule).tests;
                        xmlSchematronRegisterVariables(
                            (*ctxt).xctxt,
                            (*rule).lets,
                            instance,
                            cur,
                        );
                        while !test.is_null() {
                            xmlSchematronRunTest(ctxt, test, instance, cur, pattern);
                            test = (*test).next;
                        }
                        xmlSchematronUnregisterVariables((*ctxt).xctxt, (*rule).lets);
                    }
                    rule = (*rule).patnext;
                }
                cur = xmlSchematronNextNode(cur);
            }
            pattern = (*pattern).next;
        }
    }
    return (*ctxt).nberrors;
}
