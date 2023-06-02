use :: libc;
extern "C" {
    fn xmlStrlen(str: *const u8) -> i32;
    fn xmlStrcmp(str1: *const u8, str2: *const u8) -> i32;
    fn xmlStrndup(cur: *const u8, len: i32) -> *mut u8;
    fn xmlStrEqual(str1: *const u8, str2: *const u8) -> i32;
    fn xmlStrcat(cur: *mut u8, add: *const u8) -> *mut u8;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn xmlNewNsProp(
        node: *mut crate::src::HTMLparser::_xmlNode,
        ns: *mut crate::src::HTMLparser::_xmlNs,
        name: *const u8,
        value: *const u8,
    ) -> *mut crate::src::HTMLparser::_xmlAttr;
    fn xmlFreePropList(cur: *mut crate::src::HTMLparser::_xmlAttr);
    fn xmlSearchNs(
        doc: *mut crate::src::HTMLparser::_xmlDoc,
        node: *mut crate::src::HTMLparser::_xmlNode,
        nameSpace: *const u8,
    ) -> *mut crate::src::HTMLparser::_xmlNs;
    fn xmlHasNsProp(
        node: *const crate::src::HTMLparser::_xmlNode,
        name: *const u8,
        nameSpace: *const u8,
    ) -> *mut crate::src::HTMLparser::_xmlAttr;
    fn xmlNodeListGetString(
        doc: *mut crate::src::HTMLparser::_xmlDoc,
        list: *const crate::src::HTMLparser::_xmlNode,
        inLine: i32,
    ) -> *mut u8;
    fn xmlGetCompressMode() -> i32;
    fn xmlAllocOutputBuffer(
        encoder: *mut crate::src::HTMLparser::_xmlCharEncodingHandler,
    ) -> *mut crate::src::HTMLtree::_xmlOutputBuffer;
    fn xmlOutputBufferCreateFilename(
        URI: *const i8,
        encoder: *mut crate::src::HTMLparser::_xmlCharEncodingHandler,
        compression: i32,
    ) -> *mut crate::src::HTMLtree::_xmlOutputBuffer;
    fn xmlOutputBufferWriteString(
        out: *mut crate::src::HTMLtree::_xmlOutputBuffer,
        str: *const i8,
    ) -> i32;
    fn xmlOutputBufferFlush(out: *mut crate::src::HTMLtree::_xmlOutputBuffer) -> i32;
    fn xmlOutputBufferClose(out: *mut crate::src::HTMLtree::_xmlOutputBuffer) -> i32;
    fn xmlBuildURI(URI: *const u8, base: *const u8) -> *mut u8;
    fn xmlParseURI(str: *const i8) -> *mut crate::src::SAX2::_xmlURI;
    fn xmlFreeURI(uri: *mut crate::src::SAX2::_xmlURI);
    fn xmlXPathNodeSetContains(
        cur: *mut crate::src::c14n::_xmlNodeSet,
        val: *mut crate::src::HTMLparser::_xmlNode,
    ) -> i32;
}
pub use crate::src::buf::_xmlBuf;
pub use crate::src::buf::xmlBufContent;
pub use crate::src::buf::xmlBufUse;
pub use crate::src::buf::xmlBufWriteQuotedString;
pub use crate::src::dict::_xmlDict;
pub use crate::src::error::__xmlRaiseError;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub use crate::src::globals::xmlMallocAtomic;
pub use crate::src::globals::xmlRealloc;
pub use crate::src::list::_xmlLink;
pub use crate::src::list::_xmlList;
pub use crate::src::list::xmlListCreate;
pub use crate::src::list::xmlListDelete;
pub use crate::src::list::xmlListInsert;
pub use crate::src::list::xmlListSearch;
pub use crate::src::list::xmlListWalk;
pub type xmlChar = u8;
pub type size_t = u64;
pub type xmlBufPtr = *mut crate::src::buf::_xmlBuf;
pub type xmlBuf = crate::src::buf::_xmlBuf;
pub type xmlCharEncodingHandlerPtr = *mut crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type _xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type iconv_t = *mut core::ffi::c_void;
pub type xmlCharEncodingOutputFunc =
    Option<unsafe extern "C" fn(_: *mut u8, _: *mut i32, _: *const u8, _: *mut i32) -> i32>;
pub type xmlCharEncodingInputFunc =
    Option<unsafe extern "C" fn(_: *mut u8, _: *mut i32, _: *const u8, _: *mut i32) -> i32>;
pub type _xmlOutputBuffer = crate::src::HTMLtree::_xmlOutputBuffer;
pub type xmlOutputCloseCallback = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type xmlOutputWriteCallback =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, _: i32) -> i32>;
pub type xmlOutputBuffer = crate::src::HTMLtree::_xmlOutputBuffer;
pub type xmlOutputBufferPtr = *mut crate::src::HTMLtree::_xmlOutputBuffer;
pub type _xmlNode = crate::src::HTMLparser::_xmlNode;
pub type xmlNs = crate::src::HTMLparser::_xmlNs;
pub type _xmlNs = crate::src::HTMLparser::_xmlNs;
pub type _xmlDoc = crate::src::HTMLparser::_xmlDoc;
pub type _xmlDtd = crate::src::HTMLparser::_xmlDtd;
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
pub type _xmlAttr = crate::src::HTMLparser::_xmlAttr;
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
pub type xmlError = crate::src::HTMLparser::_xmlError;
pub type _xmlError = crate::src::HTMLparser::_xmlError;
pub type xmlErrorLevel = u32;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlAttrPtr = *mut crate::src::HTMLparser::_xmlAttr;
pub type xmlAttr = crate::src::HTMLparser::_xmlAttr;
pub type xmlNodePtr = *mut crate::src::HTMLparser::_xmlNode;
pub type xmlNode = crate::src::HTMLparser::_xmlNode;
pub type xmlDocPtr = *mut crate::src::HTMLparser::_xmlDoc;
pub type xmlDoc = crate::src::HTMLparser::_xmlDoc;
pub type xmlStructuredErrorFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *mut crate::src::HTMLparser::_xmlError,
    ) -> (),
>;
pub type xmlErrorPtr = *mut crate::src::HTMLparser::_xmlError;
pub type xmlNsPtr = *mut crate::src::HTMLparser::_xmlNs;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
pub type xmlReallocFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void>;
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
pub type xmlGenericErrorFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type xmlLink = crate::src::list::_xmlLink;
pub type xmlLinkPtr = *mut crate::src::list::_xmlLink;
pub type xmlList = crate::src::list::_xmlList;
pub type xmlListPtr = *mut crate::src::list::_xmlList;
pub type xmlListDeallocator =
    Option<unsafe extern "C" fn(_: *mut crate::src::list::_xmlLink) -> ()>;
pub type xmlListDataCompare =
    Option<unsafe extern "C" fn(_: *const core::ffi::c_void, _: *const core::ffi::c_void) -> i32>;
pub type xmlListWalker =
    Option<unsafe extern "C" fn(_: *const core::ffi::c_void, _: *mut core::ffi::c_void) -> i32>;
pub type _xmlURI = crate::src::SAX2::_xmlURI;
pub type xmlURI = crate::src::SAX2::_xmlURI;
pub type xmlURIPtr = *mut crate::src::SAX2::_xmlURI;
pub type xmlNodeSetPtr = *mut crate::src::c14n::_xmlNodeSet;
pub type xmlNodeSet = crate::src::c14n::_xmlNodeSet;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNodeSet {
    pub nodeNr: i32,
    pub nodeMax: i32,
    pub nodeTab: *mut *mut crate::src::HTMLparser::_xmlNode,
}
impl _xmlNodeSet {
    pub const fn new() -> Self {
        _xmlNodeSet {
            nodeNr: 0,
            nodeMax: 0,
            nodeTab: (0 as *mut *mut crate::src::HTMLparser::_xmlNode),
        }
    }
}
impl std::default::Default for _xmlNodeSet {
    fn default() -> Self {
        _xmlNodeSet::new()
    }
}
pub type xmlC14NMode = u32;
pub const XML_C14N_1_1: xmlC14NMode = 2;
pub const XML_C14N_EXCLUSIVE_1_0: xmlC14NMode = 1;
pub const XML_C14N_1_0: xmlC14NMode = 0;
pub type xmlC14NIsVisibleCallback = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *mut crate::src::HTMLparser::_xmlNode,
        _: *mut crate::src::HTMLparser::_xmlNode,
    ) -> i32,
>;
pub type xmlC14NCtxPtr<'a> = *mut crate::src::c14n::_xmlC14NCtx<'a>;
#[repr(C)]
pub struct _xmlC14NCtx<'a> {
    pub doc: *mut crate::src::HTMLparser::_xmlDoc,
    pub is_visible_callback: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *mut crate::src::HTMLparser::_xmlNode,
            _: *mut crate::src::HTMLparser::_xmlNode,
        ) -> i32,
    >,
    pub user_data: *mut core::ffi::c_void,
    pub with_comments: i32,
    pub buf: *mut crate::src::HTMLtree::_xmlOutputBuffer,
    pub pos: u32,
    pub parent_is_doc: i32,
    pub ns_rendered: *mut crate::src::c14n::_xmlC14NVisibleNsStack,
    pub mode: u32,
    pub inclusive_ns_prefixes:
        Option<crate::__laertes_array::CustomSlice<'a, *mut u8, &'a mut [*mut u8]>>,
    pub error: i32,
}
impl<'a> _xmlC14NCtx<'a> {
    pub const fn new() -> Self {
        _xmlC14NCtx {
            doc: (0 as *mut crate::src::HTMLparser::_xmlDoc),
            is_visible_callback: None,
            user_data: (0 as *mut core::ffi::c_void),
            with_comments: 0,
            buf: (0 as *mut crate::src::HTMLtree::_xmlOutputBuffer),
            pos: 0,
            parent_is_doc: 0,
            ns_rendered: (0 as *mut crate::src::c14n::_xmlC14NVisibleNsStack),
            mode: 0,
            inclusive_ns_prefixes: None,
            error: 0,
        }
    }
}
impl<'a> std::default::Default for _xmlC14NCtx<'a> {
    fn default() -> Self {
        _xmlC14NCtx::new()
    }
}
pub type xmlC14NVisibleNsStackPtr = *mut crate::src::c14n::_xmlC14NVisibleNsStack;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlC14NVisibleNsStack {
    pub nsCurEnd: i32,
    pub nsPrevStart: i32,
    pub nsPrevEnd: i32,
    pub nsMax: i32,
    pub nsTab: *mut *mut crate::src::HTMLparser::_xmlNs,
    pub nodeTab: *mut *mut crate::src::HTMLparser::_xmlNode,
}
impl _xmlC14NVisibleNsStack {
    pub const fn new() -> Self {
        _xmlC14NVisibleNsStack {
            nsCurEnd: 0,
            nsPrevStart: 0,
            nsPrevEnd: 0,
            nsMax: 0,
            nsTab: (0 as *mut *mut crate::src::HTMLparser::_xmlNs),
            nodeTab: (0 as *mut *mut crate::src::HTMLparser::_xmlNode),
        }
    }
}
impl std::default::Default for _xmlC14NVisibleNsStack {
    fn default() -> Self {
        _xmlC14NVisibleNsStack::new()
    }
}
pub type xmlC14NPosition = u32;
pub const XMLC14N_AFTER_DOCUMENT_ELEMENT: xmlC14NPosition = 2;
pub const XMLC14N_INSIDE_DOCUMENT_ELEMENT: xmlC14NPosition = 1;
pub const XMLC14N_BEFORE_DOCUMENT_ELEMENT: xmlC14NPosition = 0;
pub type xmlC14NVisibleNsStack = crate::src::c14n::_xmlC14NVisibleNsStack;
pub type xmlC14NNormalizationMode = u32;
pub const XMLC14N_NORMALIZE_TEXT: xmlC14NNormalizationMode = 3;
pub const XMLC14N_NORMALIZE_PI: xmlC14NNormalizationMode = 2;
pub const XMLC14N_NORMALIZE_COMMENT: xmlC14NNormalizationMode = 1;
pub const XMLC14N_NORMALIZE_ATTR: xmlC14NNormalizationMode = 0;
pub type xmlC14NCtx<'a> = crate::src::c14n::_xmlC14NCtx<'a>;
extern "C" fn xmlC14NErrMemory(mut extra: *const i8) {
    (unsafe {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_C14N as i32,
            XML_ERR_NO_MEMORY as i32,
            XML_ERR_ERROR,
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
}
extern "C" fn xmlC14NErrParam(mut extra: *const i8) {
    (unsafe {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_C14N as i32,
            XML_ERR_INTERNAL_ERROR as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            extra,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"Invalid parameter : %s\n\0" as *const u8 as *const i8,
            extra,
        )
    });
}
extern "C" fn xmlC14NErrInternal(mut extra: *const i8) {
    (unsafe {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_C14N as i32,
            XML_ERR_INTERNAL_ERROR as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            extra,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"Internal error : %s\n\0" as *const u8 as *const i8,
            extra,
        )
    });
}
extern "C" fn xmlC14NErrInvalidNode(mut node_type: *const i8, mut extra: *const i8) {
    (unsafe {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_C14N as i32,
            XML_C14N_INVALID_NODE as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            extra,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"Node %s is invalid here : %s\n\0" as *const u8 as *const i8,
            node_type,
            extra,
        )
    });
}
extern "C" fn xmlC14NErrUnknownNode(mut node_type: i32, mut extra: *const i8) {
    (unsafe {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_C14N as i32,
            XML_C14N_UNKNOW_NODE as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            extra,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"Unknown node type %d found : %s\n\0" as *const u8 as *const i8,
            node_type,
            extra,
        )
    });
}
extern "C" fn xmlC14NErrRelativeNamespace(mut ns_uri: *const i8) {
    (unsafe {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_C14N as i32,
            XML_C14N_RELATIVE_NAMESPACE as i32,
            XML_ERR_ERROR,
            0 as *const i8,
            0 as i32,
            0 as *const i8,
            0 as *const i8,
            0 as *const i8,
            0 as i32,
            0 as i32,
            b"Relative namespace UR is invalid here : %s\n\0" as *const u8 as *const i8,
            ns_uri,
        )
    });
}
extern "C" fn xmlC14NErr<'a1>(
    mut ctxt: *mut crate::src::c14n::_xmlC14NCtx<'a1>,
    mut node: *mut crate::src::HTMLparser::_xmlNode,
    mut error: i32,
    mut msg: *const i8,
) {
    if !ctxt.is_null() {
        (unsafe { (*ctxt).error = error });
    }
    (unsafe {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            node as *mut libc::c_void,
            XML_FROM_C14N as i32,
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
        )
    });
}
extern "C" fn xmlC14NIsNodeInNodeset(
    mut user_data: *mut core::ffi::c_void,
    mut node: *mut crate::src::HTMLparser::_xmlNode,
    mut parent: *mut crate::src::HTMLparser::_xmlNode,
) -> i32 {
    let mut nodes: *mut crate::src::c14n::_xmlNodeSet = user_data as xmlNodeSetPtr;
    if !nodes.is_null() && !node.is_null() {
        if (unsafe { (*node).type_0 }) as u32 != XML_NAMESPACE_DECL as i32 as u32 {
            return unsafe { xmlXPathNodeSetContains(nodes, node) };
        } else {
            let mut ns: crate::src::HTMLparser::_xmlNs = xmlNs {
                next: 0 as *mut _xmlNs,
                type_0: 0 as xmlNsType,
                href: 0 as *const xmlChar,
                prefix: 0 as *const xmlChar,
                _private: 0 as *mut libc::c_void,
                context: 0 as *mut _xmlDoc,
            };
            (unsafe {
                memcpy(
                    &mut ns as *mut xmlNs as *mut libc::c_void,
                    node as *const libc::c_void,
                    ::std::mem::size_of::<xmlNs>() as u64,
                )
            });
            if !parent.is_null()
                && (unsafe { (*parent).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
            {
                ns.next = (unsafe { (*parent).parent }) as xmlNsPtr;
            } else {
                ns.next = parent as xmlNsPtr;
            }
            return unsafe {
                xmlXPathNodeSetContains(nodes, &mut ns as *mut xmlNs as xmlNodePtr)
            };
        }
    }
    return 1 as i32;
}
extern "C" fn xmlC14NVisibleNsStackCreate() -> *mut crate::src::c14n::_xmlC14NVisibleNsStack {
    let mut ret: *mut crate::src::c14n::_xmlC14NVisibleNsStack = 0 as *mut _xmlC14NVisibleNsStack;
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlC14NVisibleNsStack>() as u64,
        )
    }) as xmlC14NVisibleNsStackPtr;
    if ret.is_null() {
        xmlC14NErrMemory(b"creating namespaces stack\0" as *const u8 as *const i8);
        return 0 as xmlC14NVisibleNsStackPtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlC14NVisibleNsStack>() as u64,
        )
    });
    return ret;
}
extern "C" fn xmlC14NVisibleNsStackDestroy(mut cur: *mut crate::src::c14n::_xmlC14NVisibleNsStack) {
    if cur.is_null() {
        xmlC14NErrParam(b"destroying namespaces stack\0" as *const u8 as *const i8);
        return;
    }
    if !(unsafe { (*cur).nsTab }).is_null() {
        (unsafe {
            memset(
                (*cur).nsTab as *mut libc::c_void,
                0 as i32,
                ((*cur).nsMax as u64).wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
            )
        });
        (unsafe { xmlFree.expect("non-null function pointer")((*cur).nsTab as *mut libc::c_void) });
    }
    if !(unsafe { (*cur).nodeTab }).is_null() {
        (unsafe {
            memset(
                (*cur).nodeTab as *mut libc::c_void,
                0 as i32,
                ((*cur).nsMax as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
            )
        });
        (unsafe {
            xmlFree.expect("non-null function pointer")((*cur).nodeTab as *mut libc::c_void)
        });
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlC14NVisibleNsStack>() as u64,
        )
    });
    (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
}
extern "C" fn xmlC14NVisibleNsStackAdd(
    mut cur: *mut crate::src::c14n::_xmlC14NVisibleNsStack,
    mut ns: *mut crate::src::HTMLparser::_xmlNs,
    mut node: *mut crate::src::HTMLparser::_xmlNode,
) {
    if cur.is_null()
        || (unsafe { (*cur).nsTab }).is_null() && !(unsafe { (*cur).nodeTab }).is_null()
        || !(unsafe { (*cur).nsTab }).is_null() && (unsafe { (*cur).nodeTab }).is_null()
    {
        xmlC14NErrParam(b"adding namespace to stack\0" as *const u8 as *const i8);
        return;
    }
    if (unsafe { (*cur).nsTab }).is_null() && (unsafe { (*cur).nodeTab }).is_null() {
        let fresh0 = unsafe { &mut ((*cur).nsTab) };
        *fresh0 = (unsafe {
            xmlMalloc.expect("non-null function pointer")(
                (16 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
            )
        }) as *mut xmlNsPtr;
        let fresh1 = unsafe { &mut ((*cur).nodeTab) };
        *fresh1 = (unsafe {
            xmlMalloc.expect("non-null function pointer")(
                (16 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
            )
        }) as *mut xmlNodePtr;
        if (unsafe { (*cur).nsTab }).is_null() || (unsafe { (*cur).nodeTab }).is_null() {
            xmlC14NErrMemory(b"adding node to stack\0" as *const u8 as *const i8);
            return;
        }
        (unsafe {
            memset(
                (*cur).nsTab as *mut libc::c_void,
                0 as i32,
                (16 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
            )
        });
        (unsafe {
            memset(
                (*cur).nodeTab as *mut libc::c_void,
                0 as i32,
                (16 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
            )
        });
        (unsafe { (*cur).nsMax = 16 as i32 });
    } else if (unsafe { (*cur).nsMax }) == (unsafe { (*cur).nsCurEnd }) {
        let mut tmp: *mut core::ffi::c_void = 0 as *mut libc::c_void;
        let mut tmpSize: i32 = 0;
        tmpSize = 2 as i32 * (unsafe { (*cur).nsMax });
        tmp = unsafe {
            xmlRealloc.expect("non-null function pointer")(
                (*cur).nsTab as *mut libc::c_void,
                (tmpSize as u64).wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
            )
        };
        if tmp.is_null() {
            xmlC14NErrMemory(b"adding node to stack\0" as *const u8 as *const i8);
            return;
        }
        let fresh2 = unsafe { &mut ((*cur).nsTab) };
        *fresh2 = tmp as *mut xmlNsPtr;
        tmp = unsafe {
            xmlRealloc.expect("non-null function pointer")(
                (*cur).nodeTab as *mut libc::c_void,
                (tmpSize as u64).wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as u64),
            )
        };
        if tmp.is_null() {
            xmlC14NErrMemory(b"adding node to stack\0" as *const u8 as *const i8);
            return;
        }
        let fresh3 = unsafe { &mut ((*cur).nodeTab) };
        *fresh3 = tmp as *mut xmlNodePtr;
        (unsafe { (*cur).nsMax = tmpSize });
    }
    let fresh4 = unsafe { &mut (*((*cur).nsTab).offset((*cur).nsCurEnd as isize)) };
    *fresh4 = ns;
    let fresh5 = unsafe { &mut (*((*cur).nodeTab).offset((*cur).nsCurEnd as isize)) };
    *fresh5 = node;
    let fresh6 = unsafe { &mut ((*cur).nsCurEnd) };
    *fresh6 += 1;
}
extern "C" fn xmlC14NVisibleNsStackSave<'a1>(
    mut cur: *mut crate::src::c14n::_xmlC14NVisibleNsStack,
    mut state: Option<&'a1 mut crate::src::c14n::_xmlC14NVisibleNsStack>,
) {
    if cur.is_null() || borrow(&state).is_none() {
        xmlC14NErrParam(b"saving namespaces stack\0" as *const u8 as *const i8);
        return;
    }
    (*(borrow_mut(&mut state)).unwrap()).nsCurEnd = unsafe { (*cur).nsCurEnd };
    (*(borrow_mut(&mut state)).unwrap()).nsPrevStart = unsafe { (*cur).nsPrevStart };
    (*(borrow_mut(&mut state)).unwrap()).nsPrevEnd = unsafe { (*cur).nsPrevEnd };
}
extern "C" fn xmlC14NVisibleNsStackRestore<'a1>(
    mut cur: *mut crate::src::c14n::_xmlC14NVisibleNsStack,
    mut state: Option<&'a1 mut crate::src::c14n::_xmlC14NVisibleNsStack>,
) {
    if cur.is_null() || borrow(&state).is_none() {
        xmlC14NErrParam(b"restoring namespaces stack\0" as *const u8 as *const i8);
        return;
    }
    (unsafe { (*cur).nsCurEnd = (*(borrow_mut(&mut state)).unwrap()).nsCurEnd });
    (unsafe { (*cur).nsPrevStart = (*(borrow_mut(&mut state)).unwrap()).nsPrevStart });
    (unsafe { (*cur).nsPrevEnd = (*(borrow_mut(&mut state)).unwrap()).nsPrevEnd });
}
extern "C" fn xmlC14NVisibleNsStackShift(mut cur: *mut crate::src::c14n::_xmlC14NVisibleNsStack) {
    if cur.is_null() {
        xmlC14NErrParam(b"shifting namespaces stack\0" as *const u8 as *const i8);
        return;
    }
    (unsafe { (*cur).nsPrevStart = (*cur).nsPrevEnd });
    (unsafe { (*cur).nsPrevEnd = (*cur).nsCurEnd });
}
extern "C" fn xmlC14NStrEqual(mut str1: *const u8, mut str2: *const u8) -> i32 {
    if str1 == str2 {
        return 1 as i32;
    }
    if str1.is_null() {
        return ((unsafe { *str2 }) as i32 == '\u{0}' as i32) as i32;
    }
    if str2.is_null() {
        return ((unsafe { *str1 }) as i32 == '\u{0}' as i32) as i32;
    }
    loop {
        let mut fresh7 = str1;
        str1 = unsafe { str1.offset(1) };
        if (unsafe { *fresh7 }) as i32 != (unsafe { *str2 }) as i32 {
            return 0 as i32;
        }
        let mut fresh8 = str2;
        str2 = unsafe { str2.offset(1) };
        if !((unsafe { *fresh8 }) != 0) {
            break;
        }
    }
    return 1 as i32;
}
extern "C" fn xmlC14NVisibleNsStackFind(
    mut cur: *mut crate::src::c14n::_xmlC14NVisibleNsStack,
    mut ns: *mut crate::src::HTMLparser::_xmlNs,
) -> i32 {
    let mut i: i32 = 0;
    let mut prefix: *const u8 = 0 as *const xmlChar;
    let mut href: *const u8 = 0 as *const xmlChar;
    let mut has_empty_ns: i32 = 0;
    if cur.is_null() {
        xmlC14NErrParam(b"searching namespaces stack (c14n)\0" as *const u8 as *const i8);
        return 0 as i32;
    }
    prefix = if ns.is_null() || (unsafe { (*ns).prefix }).is_null() {
        b"\0" as *const u8 as *const i8 as *mut xmlChar as *const xmlChar
    } else {
        unsafe { (*ns).prefix }
    };
    href = if ns.is_null() || (unsafe { (*ns).href }).is_null() {
        b"\0" as *const u8 as *const i8 as *mut xmlChar as *const xmlChar
    } else {
        unsafe { (*ns).href }
    };
    has_empty_ns = (xmlC14NStrEqual(prefix, 0 as *const xmlChar) != 0
        && xmlC14NStrEqual(href, 0 as *const xmlChar) != 0) as i32;
    if !(unsafe { (*cur).nsTab }).is_null() {
        let mut start: i32 = if has_empty_ns != 0 {
            0 as i32
        } else {
            unsafe { (*cur).nsPrevStart }
        };
        i = (unsafe { (*cur).nsCurEnd }) - 1 as i32;
        while i >= start {
            let mut ns1: *mut crate::src::HTMLparser::_xmlNs =
                unsafe { *((*cur).nsTab).offset(i as isize) };
            if xmlC14NStrEqual(
                prefix,
                if !ns1.is_null() {
                    unsafe { (*ns1).prefix }
                } else {
                    0 as *const xmlChar
                },
            ) != 0
            {
                return xmlC14NStrEqual(
                    href,
                    if !ns1.is_null() {
                        unsafe { (*ns1).href }
                    } else {
                        0 as *const xmlChar
                    },
                );
            }
            i -= 1;
        }
    }
    return has_empty_ns;
}
extern "C" fn xmlExcC14NVisibleNsStackFind<'a1>(
    mut cur: *mut crate::src::c14n::_xmlC14NVisibleNsStack,
    mut ns: *mut crate::src::HTMLparser::_xmlNs,
    mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'a1>,
) -> i32 {
    let mut i: i32 = 0;
    let mut prefix: *const u8 = 0 as *const xmlChar;
    let mut href: *const u8 = 0 as *const xmlChar;
    let mut has_empty_ns: i32 = 0;
    if cur.is_null() {
        xmlC14NErrParam(b"searching namespaces stack (exc c14n)\0" as *const u8 as *const i8);
        return 0 as i32;
    }
    prefix = if ns.is_null() || (unsafe { (*ns).prefix }).is_null() {
        b"\0" as *const u8 as *const i8 as *mut xmlChar as *const xmlChar
    } else {
        unsafe { (*ns).prefix }
    };
    href = if ns.is_null() || (unsafe { (*ns).href }).is_null() {
        b"\0" as *const u8 as *const i8 as *mut xmlChar as *const xmlChar
    } else {
        unsafe { (*ns).href }
    };
    has_empty_ns = (xmlC14NStrEqual(prefix, 0 as *const xmlChar) != 0
        && xmlC14NStrEqual(href, 0 as *const xmlChar) != 0) as i32;
    if !(unsafe { (*cur).nsTab }).is_null() {
        let mut start: i32 = 0 as i32;
        i = (unsafe { (*cur).nsCurEnd }) - 1 as i32;
        while i >= start {
            let mut ns1: *mut crate::src::HTMLparser::_xmlNs =
                unsafe { *((*cur).nsTab).offset(i as isize) };
            if xmlC14NStrEqual(
                prefix,
                if !ns1.is_null() {
                    unsafe { (*ns1).prefix }
                } else {
                    0 as *const xmlChar
                },
            ) != 0
            {
                if xmlC14NStrEqual(
                    href,
                    if !ns1.is_null() {
                        unsafe { (*ns1).href }
                    } else {
                        0 as *const xmlChar
                    },
                ) != 0
                {
                    return if unsafe { ((*ctx).is_visible_callback).is_some() } {
                        unsafe {
                            ((*ctx).is_visible_callback).expect("non-null function pointer")(
                                (*ctx).user_data,
                                ns1 as xmlNodePtr,
                                *((*cur).nodeTab).offset(i as isize),
                            )
                        }
                    } else {
                        1 as i32
                    };
                } else {
                    return 0 as i32;
                }
            }
            i -= 1;
        }
    }
    return has_empty_ns;
}
extern "C" fn xmlC14NIsXmlNs(mut ns: *mut crate::src::HTMLparser::_xmlNs) -> i32 {
    return (!ns.is_null()
        && (unsafe {
            xmlStrEqual(
                (*ns).prefix,
                b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
            )
        }) != 0
        && (unsafe {
            xmlStrEqual(
                (*ns).href,
                b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                    as *const xmlChar,
            )
        }) != 0) as i32;
}
extern "C" fn xmlC14NNsCompare(
    mut data1: *const core::ffi::c_void,
    mut data2: *const core::ffi::c_void,
) -> i32 {
    let ns1: *mut crate::src::HTMLparser::_xmlNs = data1 as xmlNsPtr;
    let ns2: *mut crate::src::HTMLparser::_xmlNs = data2 as xmlNsPtr;
    if ns1 == ns2 {
        return 0 as i32;
    }
    if ns1.is_null() {
        return -(1 as i32);
    }
    if ns2.is_null() {
        return 1 as i32;
    }
    return unsafe { xmlStrcmp((*ns1).prefix, (*ns2).prefix) };
}
extern "C" fn xmlC14NPrintNamespaces<'a1>(
    ns: *mut crate::src::HTMLparser::_xmlNs,
    mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'a1>,
) -> i32 {
    if ns.is_null() || ctx.is_null() {
        xmlC14NErrParam(b"writing namespaces\0" as *const u8 as *const i8);
        return 0 as i32;
    }
    if !(unsafe { (*ns).prefix }).is_null() {
        (unsafe { xmlOutputBufferWriteString((*ctx).buf, b" xmlns:\0" as *const u8 as *const i8) });
        (unsafe { xmlOutputBufferWriteString((*ctx).buf, (*ns).prefix as *const i8) });
        (unsafe { xmlOutputBufferWriteString((*ctx).buf, b"=\0" as *const u8 as *const i8) });
    } else {
        (unsafe { xmlOutputBufferWriteString((*ctx).buf, b" xmlns=\0" as *const u8 as *const i8) });
    }
    if !(unsafe { (*ns).href }).is_null() {
        xmlBufWriteQuotedString(unsafe { (*(*ctx).buf).buffer }, unsafe { (*ns).href });
    } else {
        (unsafe { xmlOutputBufferWriteString((*ctx).buf, b"\"\"\0" as *const u8 as *const i8) });
    }
    return 1 as i32;
}
extern "C" fn xmlC14NPrintNamespacesWalker(
    mut ns: *const core::ffi::c_void,
    mut ctx: *mut core::ffi::c_void,
) -> i32 {
    return xmlC14NPrintNamespaces(ns as xmlNsPtr, ctx as xmlC14NCtxPtr);
}
extern "C" fn xmlC14NProcessNamespacesAxis<'a1>(
    mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'a1>,
    mut cur: *mut crate::src::HTMLparser::_xmlNode,
    mut visible: i32,
) -> i32 {
    let mut n: *mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    let mut ns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
    let mut tmp: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
    let mut list: *mut crate::src::list::_xmlList = 0 as *mut xmlList;
    let mut already_rendered: i32 = 0;
    let mut has_empty_ns: i32 = 0 as i32;
    if ctx.is_null()
        || cur.is_null()
        || (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
    {
        xmlC14NErrParam(b"processing namespaces axis (c14n)\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    list = xmlListCreate(None, Some(xmlC14NNsCompare));
    if list.is_null() {
        xmlC14NErrInternal(b"creating namespaces list (c14n)\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    n = cur;
    while !n.is_null() {
        ns = unsafe { (*n).nsDef };
        while !ns.is_null() {
            tmp = unsafe { xmlSearchNs((*cur).doc, cur, (*ns).prefix) };
            if tmp == ns
                && xmlC14NIsXmlNs(ns) == 0
                && (if unsafe { ((*ctx).is_visible_callback).is_some() } {
                    unsafe {
                        ((*ctx).is_visible_callback).expect("non-null function pointer")(
                            (*ctx).user_data,
                            ns as xmlNodePtr,
                            cur,
                        )
                    }
                } else {
                    1 as i32
                }) != 0
            {
                already_rendered = xmlC14NVisibleNsStackFind(unsafe { (*ctx).ns_rendered }, ns);
                if visible != 0 {
                    xmlC14NVisibleNsStackAdd(unsafe { (*ctx).ns_rendered }, ns, cur);
                }
                if already_rendered == 0 {
                    xmlListInsert(list, ns as *mut libc::c_void);
                }
                if (unsafe { xmlStrlen((*ns).prefix) }) == 0 as i32 {
                    has_empty_ns = 1 as i32;
                }
            }
            ns = unsafe { (*ns).next };
        }
        n = unsafe { (*n).parent };
    }
    if visible != 0 && has_empty_ns == 0 {
        static mut ns_default: crate::src::HTMLparser::_xmlNs = xmlNs {
            next: 0 as *mut _xmlNs,
            type_0: 0 as xmlNsType,
            href: 0 as *const xmlChar,
            prefix: 0 as *const xmlChar,
            _private: 0 as *mut libc::c_void,
            context: 0 as *mut _xmlDoc,
        };
        (unsafe {
            memset(
                &mut ns_default as *mut xmlNs as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<xmlNs>() as u64,
            )
        });
        if xmlC14NVisibleNsStackFind(
            unsafe { (*ctx).ns_rendered },
            unsafe { &mut ns_default },
        ) == 0
        {
            xmlC14NPrintNamespaces(unsafe { &mut ns_default }, ctx);
        }
    }
    xmlListWalk(
        list,
        Some(xmlC14NPrintNamespacesWalker),
        ctx as *mut libc::c_void,
    );
    xmlListDelete(list);
    return 0 as i32;
}
extern "C" fn xmlExcC14NProcessNamespacesAxis<'a1>(
    mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'a1>,
    mut cur: *mut crate::src::HTMLparser::_xmlNode,
    mut visible: i32,
) -> i32 {
    let mut ns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
    let mut list: *mut crate::src::list::_xmlList = 0 as *mut xmlList;
    let mut attr: *mut crate::src::HTMLparser::_xmlAttr = 0 as *mut xmlAttr;
    let mut already_rendered: i32 = 0;
    let mut has_empty_ns: i32 = 0 as i32;
    let mut has_visibly_utilized_empty_ns: i32 = 0 as i32;
    let mut has_empty_ns_in_inclusive_list: i32 = 0 as i32;
    if ctx.is_null()
        || cur.is_null()
        || (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
    {
        xmlC14NErrParam(b"processing namespaces axis (exc c14n)\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    if !((unsafe { (*ctx).mode }) as u32 == XML_C14N_EXCLUSIVE_1_0 as i32 as u32) {
        xmlC14NErrParam(b"processing namespaces axis (exc c14n)\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    list = xmlListCreate(None, Some(xmlC14NNsCompare));
    if list.is_null() {
        xmlC14NErrInternal(b"creating namespaces list (exc c14n)\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    if !crate::__laertes_array::borrow(unsafe { &((*ctx).inclusive_ns_prefixes) }).is_none() {
        let mut prefix: *mut u8 = 0 as *mut xmlChar;
        let mut i: i32 = 0;
        i = 0 as i32;
        while !(*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
            crate::__laertes_array::borrow_mut(unsafe { &mut ((*ctx).inclusive_ns_prefixes) })
                .as_mut()
                .unwrap(),
            i as isize,
        ))
        .is_null()
        {
            prefix = *crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                crate::__laertes_array::borrow_mut(
                    unsafe { &mut ((*ctx).inclusive_ns_prefixes) },
                )
                .as_mut()
                .unwrap(),
                i as isize,
            );
            if (unsafe {
                xmlStrEqual(
                    prefix,
                    b"#default\0" as *const u8 as *const i8 as *mut xmlChar,
                )
            }) != 0
                || (unsafe { xmlStrEqual(prefix, b"\0" as *const u8 as *const i8 as *mut xmlChar) })
                    != 0
            {
                prefix = 0 as *mut xmlChar;
                has_empty_ns_in_inclusive_list = 1 as i32;
            }
            ns = unsafe { xmlSearchNs((*cur).doc, cur, prefix) };
            if !ns.is_null()
                && xmlC14NIsXmlNs(ns) == 0
                && (if unsafe { ((*ctx).is_visible_callback).is_some() } {
                    unsafe {
                        ((*ctx).is_visible_callback).expect("non-null function pointer")(
                            (*ctx).user_data,
                            ns as xmlNodePtr,
                            cur,
                        )
                    }
                } else {
                    1 as i32
                }) != 0
            {
                already_rendered = xmlC14NVisibleNsStackFind(unsafe { (*ctx).ns_rendered }, ns);
                if visible != 0 {
                    xmlC14NVisibleNsStackAdd(unsafe { (*ctx).ns_rendered }, ns, cur);
                }
                if already_rendered == 0 {
                    xmlListInsert(list, ns as *mut libc::c_void);
                }
                if (unsafe { xmlStrlen((*ns).prefix) }) == 0 as i32 {
                    has_empty_ns = 1 as i32;
                }
            }
            i += 1;
        }
    }
    if !(unsafe { (*cur).ns }).is_null() {
        ns = unsafe { (*cur).ns };
    } else {
        ns = unsafe { xmlSearchNs((*cur).doc, cur, 0 as *const xmlChar) };
        has_visibly_utilized_empty_ns = 1 as i32;
    }
    if !ns.is_null() && xmlC14NIsXmlNs(ns) == 0 {
        if visible != 0
            && (if unsafe { ((*ctx).is_visible_callback).is_some() } {
                unsafe {
                    ((*ctx).is_visible_callback).expect("non-null function pointer")(
                        (*ctx).user_data,
                        ns as xmlNodePtr,
                        cur,
                    )
                }
            } else {
                1 as i32
            }) != 0
        {
            if xmlExcC14NVisibleNsStackFind(unsafe { (*ctx).ns_rendered }, ns, ctx) == 0 {
                xmlListInsert(list, ns as *mut libc::c_void);
            }
        }
        if visible != 0 {
            xmlC14NVisibleNsStackAdd(unsafe { (*ctx).ns_rendered }, ns, cur);
        }
        if (unsafe { xmlStrlen((*ns).prefix) }) == 0 as i32 {
            has_empty_ns = 1 as i32;
        }
    }
    attr = unsafe { (*cur).properties };
    while !attr.is_null() {
        if !(unsafe { (*attr).ns }).is_null()
            && xmlC14NIsXmlNs(unsafe { (*attr).ns }) == 0
            && (if unsafe { ((*ctx).is_visible_callback).is_some() } {
                unsafe {
                    ((*ctx).is_visible_callback).expect("non-null function pointer")(
                        (*ctx).user_data,
                        attr as xmlNodePtr,
                        cur,
                    )
                }
            } else {
                1 as i32
            }) != 0
        {
            already_rendered = xmlExcC14NVisibleNsStackFind(
                unsafe { (*ctx).ns_rendered },
                unsafe { (*attr).ns },
                ctx,
            );
            xmlC14NVisibleNsStackAdd(
                unsafe { (*ctx).ns_rendered },
                unsafe { (*attr).ns },
                cur,
            );
            if already_rendered == 0 && visible != 0 {
                xmlListInsert(list, (unsafe { (*attr).ns }) as *mut libc::c_void);
            }
            if (unsafe { xmlStrlen((*(*attr).ns).prefix) }) == 0 as i32 {
                has_empty_ns = 1 as i32;
            }
        } else if !(unsafe { (*attr).ns }).is_null()
            && (unsafe { xmlStrlen((*(*attr).ns).prefix) }) == 0 as i32
            && (unsafe { xmlStrlen((*(*attr).ns).href) }) == 0 as i32
        {
            has_visibly_utilized_empty_ns = 1 as i32;
        }
        attr = unsafe { (*attr).next };
    }
    if visible != 0
        && has_visibly_utilized_empty_ns != 0
        && has_empty_ns == 0
        && has_empty_ns_in_inclusive_list == 0
    {
        static mut ns_default: crate::src::HTMLparser::_xmlNs = xmlNs {
            next: 0 as *mut _xmlNs,
            type_0: 0 as xmlNsType,
            href: 0 as *const xmlChar,
            prefix: 0 as *const xmlChar,
            _private: 0 as *mut libc::c_void,
            context: 0 as *mut _xmlDoc,
        };
        (unsafe {
            memset(
                &mut ns_default as *mut xmlNs as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<xmlNs>() as u64,
            )
        });
        already_rendered = xmlExcC14NVisibleNsStackFind(
            unsafe { (*ctx).ns_rendered },
            unsafe { &mut ns_default },
            ctx,
        );
        if already_rendered == 0 {
            xmlC14NPrintNamespaces(unsafe { &mut ns_default }, ctx);
        }
    } else if visible != 0 && has_empty_ns == 0 && has_empty_ns_in_inclusive_list != 0 {
        static mut ns_default_0: crate::src::HTMLparser::_xmlNs = xmlNs {
            next: 0 as *mut _xmlNs,
            type_0: 0 as xmlNsType,
            href: 0 as *const xmlChar,
            prefix: 0 as *const xmlChar,
            _private: 0 as *mut libc::c_void,
            context: 0 as *mut _xmlDoc,
        };
        (unsafe {
            memset(
                &mut ns_default_0 as *mut xmlNs as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<xmlNs>() as u64,
            )
        });
        if xmlC14NVisibleNsStackFind(
            unsafe { (*ctx).ns_rendered },
            unsafe { &mut ns_default_0 },
        ) == 0
        {
            xmlC14NPrintNamespaces(unsafe { &mut ns_default_0 }, ctx);
        }
    }
    xmlListWalk(
        list,
        Some(xmlC14NPrintNamespacesWalker),
        ctx as *mut libc::c_void,
    );
    xmlListDelete(list);
    return 0 as i32;
}
extern "C" fn xmlC14NIsXmlAttr(mut attr: *mut crate::src::HTMLparser::_xmlAttr) -> i32 {
    return (!(unsafe { (*attr).ns }).is_null()
        && xmlC14NIsXmlNs(unsafe { (*attr).ns }) != 0 as i32) as i32;
}
extern "C" fn xmlC14NAttrsCompare(
    mut data1: *const core::ffi::c_void,
    mut data2: *const core::ffi::c_void,
) -> i32 {
    let attr1: *mut crate::src::HTMLparser::_xmlAttr = data1 as xmlAttrPtr;
    let attr2: *mut crate::src::HTMLparser::_xmlAttr = data2 as xmlAttrPtr;
    let mut ret: i32 = 0 as i32;
    if attr1 == attr2 {
        return 0 as i32;
    }
    if attr1.is_null() {
        return -(1 as i32);
    }
    if attr2.is_null() {
        return 1 as i32;
    }
    if (unsafe { (*attr1).ns }) == (unsafe { (*attr2).ns }) {
        return unsafe { xmlStrcmp((*attr1).name, (*attr2).name) };
    }
    if (unsafe { (*attr1).ns }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*attr2).ns }).is_null() {
        return 1 as i32;
    }
    if (unsafe { (*(*attr1).ns).prefix }).is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*(*attr2).ns).prefix }).is_null() {
        return 1 as i32;
    }
    ret = unsafe { xmlStrcmp((*(*attr1).ns).href, (*(*attr2).ns).href) };
    if ret == 0 as i32 {
        ret = unsafe { xmlStrcmp((*attr1).name, (*attr2).name) };
    }
    return ret;
}
extern "C" fn xmlC14NPrintAttrs(
    mut data: *const core::ffi::c_void,
    mut user: *mut core::ffi::c_void,
) -> i32 {
    let attr: *mut crate::src::HTMLparser::_xmlAttr = data as xmlAttrPtr;
    let mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'_> = user as xmlC14NCtxPtr;
    let mut value: *mut u8 = 0 as *mut xmlChar;
    let mut buffer: *mut u8 = 0 as *mut xmlChar;
    if attr.is_null() || ctx.is_null() {
        xmlC14NErrParam(b"writing attributes\0" as *const u8 as *const i8);
        return 0 as i32;
    }
    (unsafe { xmlOutputBufferWriteString((*ctx).buf, b" \0" as *const u8 as *const i8) });
    if !(unsafe { (*attr).ns }).is_null()
        && (unsafe { xmlStrlen((*(*attr).ns).prefix) }) > 0 as i32
    {
        (unsafe { xmlOutputBufferWriteString((*ctx).buf, (*(*attr).ns).prefix as *const i8) });
        (unsafe { xmlOutputBufferWriteString((*ctx).buf, b":\0" as *const u8 as *const i8) });
    }
    (unsafe { xmlOutputBufferWriteString((*ctx).buf, (*attr).name as *const i8) });
    (unsafe { xmlOutputBufferWriteString((*ctx).buf, b"=\"\0" as *const u8 as *const i8) });
    value = unsafe { xmlNodeListGetString((*ctx).doc, (*attr).children, 1 as i32) };
    if !value.is_null() {
        buffer = xmlC11NNormalizeString(value, XMLC14N_NORMALIZE_ATTR);
        (unsafe { xmlFree.expect("non-null function pointer")(value as *mut libc::c_void) });
        if !buffer.is_null() {
            (unsafe { xmlOutputBufferWriteString((*ctx).buf, buffer as *const i8) });
            (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
        } else {
            xmlC14NErrInternal(b"normalizing attributes axis\0" as *const u8 as *const i8);
            return 0 as i32;
        }
    }
    (unsafe { xmlOutputBufferWriteString((*ctx).buf, b"\"\0" as *const u8 as *const i8) });
    return 1 as i32;
}
extern "C" fn xmlC14NFindHiddenParentAttr<'a1>(
    mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'a1>,
    mut cur: *mut crate::src::HTMLparser::_xmlNode,
    mut name: *const u8,
    mut ns: *const u8,
) -> *mut crate::src::HTMLparser::_xmlAttr {
    let mut res: *mut crate::src::HTMLparser::_xmlAttr = 0 as *mut xmlAttr;
    while !cur.is_null()
        && (if unsafe { ((*ctx).is_visible_callback).is_some() } {
            unsafe {
                ((*ctx).is_visible_callback).expect("non-null function pointer")(
                    (*ctx).user_data,
                    cur,
                    (*cur).parent as xmlNodePtr,
                )
            }
        } else {
            1 as i32
        }) == 0
    {
        res = unsafe { xmlHasNsProp(cur as *const xmlNode, name, ns) };
        if !res.is_null() {
            return res;
        }
        cur = unsafe { (*cur).parent };
    }
    return 0 as xmlAttrPtr;
}
extern "C" fn xmlC14NFixupBaseAttr<'a1>(
    mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'a1>,
    mut xml_base_attr: *mut crate::src::HTMLparser::_xmlAttr,
) -> *mut crate::src::HTMLparser::_xmlAttr {
    let mut res: *mut u8 = 0 as *mut xmlChar;
    let mut cur: *mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
    let mut attr: *mut crate::src::HTMLparser::_xmlAttr = 0 as *mut xmlAttr;
    let mut tmp_str: *mut u8 = 0 as *mut xmlChar;
    let mut tmp_str2: *mut u8 = 0 as *mut xmlChar;
    let mut tmp_str_len: i32 = 0;
    if ctx.is_null() || xml_base_attr.is_null() || (unsafe { (*xml_base_attr).parent }).is_null()
    {
        xmlC14NErrParam(b"processing xml:base attribute\0" as *const u8 as *const i8);
        return 0 as xmlAttrPtr;
    }
    res = unsafe { xmlNodeListGetString((*ctx).doc, (*xml_base_attr).children, 1 as i32) };
    if res.is_null() {
        xmlC14NErrInternal(
            b"processing xml:base attribute - can't get attr value\0" as *const u8 as *const i8,
        );
        return 0 as xmlAttrPtr;
    }
    cur = unsafe { (*(*xml_base_attr).parent).parent };
    while !cur.is_null()
        && (if unsafe { ((*ctx).is_visible_callback).is_some() } {
            unsafe {
                ((*ctx).is_visible_callback).expect("non-null function pointer")(
                    (*ctx).user_data,
                    cur,
                    (*cur).parent as xmlNodePtr,
                )
            }
        } else {
            1 as i32
        }) == 0
    {
        attr = unsafe {
            xmlHasNsProp(
                cur as *const xmlNode,
                b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                    as *const xmlChar,
            )
        };
        if !attr.is_null() {
            tmp_str = unsafe { xmlNodeListGetString((*ctx).doc, (*attr).children, 1 as i32) };
            if tmp_str.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(res as *mut libc::c_void) });
                xmlC14NErrInternal(
                    b"processing xml:base attribute - can't get attr value\0" as *const u8
                        as *const i8,
                );
                return 0 as xmlAttrPtr;
            }
            tmp_str_len = unsafe { xmlStrlen(tmp_str) };
            if tmp_str_len > 1 as i32
                && (unsafe { *tmp_str.offset((tmp_str_len - 2 as i32) as isize) }) as i32
                    == '.' as i32
            {
                tmp_str2 = unsafe {
                    xmlStrcat(tmp_str, b"/\0" as *const u8 as *const i8 as *mut xmlChar)
                };
                if tmp_str2.is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(tmp_str as *mut libc::c_void)
                    });
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(res as *mut libc::c_void)
                    });
                    xmlC14NErrInternal(
                        b"processing xml:base attribute - can't modify uri\0" as *const u8
                            as *const i8,
                    );
                    return 0 as xmlAttrPtr;
                }
                tmp_str = tmp_str2;
            }
            tmp_str2 = unsafe { xmlBuildURI(res, tmp_str) };
            if tmp_str2.is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(tmp_str as *mut libc::c_void)
                });
                (unsafe { xmlFree.expect("non-null function pointer")(res as *mut libc::c_void) });
                xmlC14NErrInternal(
                    b"processing xml:base attribute - can't construct uri\0" as *const u8
                        as *const i8,
                );
                return 0 as xmlAttrPtr;
            }
            (unsafe { xmlFree.expect("non-null function pointer")(tmp_str as *mut libc::c_void) });
            (unsafe { xmlFree.expect("non-null function pointer")(res as *mut libc::c_void) });
            res = tmp_str2;
        }
        cur = unsafe { (*cur).parent };
    }
    if res.is_null()
        || (unsafe { xmlStrEqual(res, b"\0" as *const u8 as *const i8 as *mut xmlChar) }) != 0
    {
        (unsafe { xmlFree.expect("non-null function pointer")(res as *mut libc::c_void) });
        return 0 as xmlAttrPtr;
    }
    attr = unsafe {
        xmlNewNsProp(
            0 as xmlNodePtr,
            (*xml_base_attr).ns,
            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
            res,
        )
    };
    if attr.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(res as *mut libc::c_void) });
        xmlC14NErrInternal(
            b"processing xml:base attribute - can't construct attribute\0" as *const u8
                as *const i8,
        );
        return 0 as xmlAttrPtr;
    }
    (unsafe { xmlFree.expect("non-null function pointer")(res as *mut libc::c_void) });
    return attr;
}
extern "C" fn xmlC14NProcessAttrsAxis<'a1>(
    mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'a1>,
    mut cur: *mut crate::src::HTMLparser::_xmlNode,
    mut parent_visible: i32,
) -> i32 {
    let mut attr: *mut crate::src::HTMLparser::_xmlAttr = 0 as *mut xmlAttr;
    let mut list: *mut crate::src::list::_xmlList = 0 as *mut xmlList;
    let mut attrs_to_delete: *mut crate::src::HTMLparser::_xmlAttr = 0 as xmlAttrPtr;
    let mut xml_base_attr: *mut crate::src::HTMLparser::_xmlAttr = 0 as xmlAttrPtr;
    let mut xml_lang_attr: *mut crate::src::HTMLparser::_xmlAttr = 0 as xmlAttrPtr;
    let mut xml_space_attr: *mut crate::src::HTMLparser::_xmlAttr = 0 as xmlAttrPtr;
    if ctx.is_null()
        || cur.is_null()
        || (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
    {
        xmlC14NErrParam(b"processing attributes axis\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    list = xmlListCreate(None, Some(xmlC14NAttrsCompare));
    if list.is_null() {
        xmlC14NErrInternal(b"creating attributes list\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    match (unsafe { (*ctx).mode }) as u32 {
        0 => {
            attr = unsafe { (*cur).properties };
            while !attr.is_null() {
                if if unsafe { ((*ctx).is_visible_callback).is_some() } {
                    unsafe {
                        ((*ctx).is_visible_callback).expect("non-null function pointer")(
                            (*ctx).user_data,
                            attr as xmlNodePtr,
                            cur,
                        )
                    }
                } else {
                    1 as i32
                } != 0
                {
                    xmlListInsert(list, attr as *mut libc::c_void);
                }
                attr = unsafe { (*attr).next };
            }
            if parent_visible != 0
                && !(unsafe { (*cur).parent }).is_null()
                && (if unsafe { ((*ctx).is_visible_callback).is_some() } {
                    unsafe {
                        ((*ctx).is_visible_callback).expect("non-null function pointer")(
                            (*ctx).user_data,
                            (*cur).parent as xmlNodePtr,
                            (*(*cur).parent).parent as xmlNodePtr,
                        )
                    }
                } else {
                    1 as i32
                }) == 0
            {
                let mut tmp: *mut crate::src::HTMLparser::_xmlNode = 0 as *mut xmlNode;
                tmp = unsafe { (*cur).parent };
                while !tmp.is_null() {
                    attr = unsafe { (*tmp).properties };
                    while !attr.is_null() {
                        if xmlC14NIsXmlAttr(attr) != 0 as i32 {
                            if (xmlListSearch(list, attr as *mut libc::c_void)).is_null() {
                                xmlListInsert(list, attr as *mut libc::c_void);
                            }
                        }
                        attr = unsafe { (*attr).next };
                    }
                    tmp = unsafe { (*tmp).parent };
                }
            }
        }
        1 => {
            attr = unsafe { (*cur).properties };
            while !attr.is_null() {
                if if unsafe { ((*ctx).is_visible_callback).is_some() } {
                    unsafe {
                        ((*ctx).is_visible_callback).expect("non-null function pointer")(
                            (*ctx).user_data,
                            attr as xmlNodePtr,
                            cur,
                        )
                    }
                } else {
                    1 as i32
                } != 0
                {
                    xmlListInsert(list, attr as *mut libc::c_void);
                }
                attr = unsafe { (*attr).next };
            }
        }
        2 => {
            attr = unsafe { (*cur).properties };
            while !attr.is_null() {
                if parent_visible == 0 || xmlC14NIsXmlAttr(attr) == 0 as i32 {
                    if if unsafe { ((*ctx).is_visible_callback).is_some() } {
                        unsafe {
                            ((*ctx).is_visible_callback).expect("non-null function pointer")(
                                (*ctx).user_data,
                                attr as xmlNodePtr,
                                cur,
                            )
                        }
                    } else {
                        1 as i32
                    } != 0
                    {
                        xmlListInsert(list, attr as *mut libc::c_void);
                    }
                } else {
                    let mut matched: i32 = 0 as i32;
                    if matched == 0
                        && xml_lang_attr.is_null()
                        && (unsafe {
                            xmlStrEqual(
                                (*attr).name,
                                b"lang\0" as *const u8 as *const i8 as *mut xmlChar,
                            )
                        }) != 0
                    {
                        xml_lang_attr = attr;
                        matched = 1 as i32;
                    }
                    if matched == 0
                        && xml_space_attr.is_null()
                        && (unsafe {
                            xmlStrEqual(
                                (*attr).name,
                                b"space\0" as *const u8 as *const i8 as *mut xmlChar,
                            )
                        }) != 0
                    {
                        xml_space_attr = attr;
                        matched = 1 as i32;
                    }
                    if matched == 0
                        && xml_base_attr.is_null()
                        && (unsafe {
                            xmlStrEqual(
                                (*attr).name,
                                b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                            )
                        }) != 0
                    {
                        xml_base_attr = attr;
                        matched = 1 as i32;
                    }
                    if matched == 0
                        && (if unsafe { ((*ctx).is_visible_callback).is_some() } {
                            unsafe {
                                ((*ctx).is_visible_callback).expect("non-null function pointer")(
                                    (*ctx).user_data,
                                    attr as xmlNodePtr,
                                    cur,
                                )
                            }
                        } else {
                            1 as i32
                        }) != 0
                    {
                        xmlListInsert(list, attr as *mut libc::c_void);
                    }
                }
                attr = unsafe { (*attr).next };
            }
            if parent_visible != 0 {
                if xml_lang_attr.is_null() {
                    xml_lang_attr = xmlC14NFindHiddenParentAttr(
                        ctx,
                        unsafe { (*cur).parent },
                        b"lang\0" as *const u8 as *const i8 as *mut xmlChar,
                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                            as *const xmlChar,
                    );
                }
                if !xml_lang_attr.is_null() {
                    xmlListInsert(list, xml_lang_attr as *mut libc::c_void);
                }
                if xml_space_attr.is_null() {
                    xml_space_attr = xmlC14NFindHiddenParentAttr(
                        ctx,
                        unsafe { (*cur).parent },
                        b"space\0" as *const u8 as *const i8 as *mut xmlChar,
                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                            as *const xmlChar,
                    );
                }
                if !xml_space_attr.is_null() {
                    xmlListInsert(list, xml_space_attr as *mut libc::c_void);
                }
                if xml_base_attr.is_null() {
                    xml_base_attr = xmlC14NFindHiddenParentAttr(
                        ctx,
                        unsafe { (*cur).parent },
                        b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                            as *const xmlChar,
                    );
                }
                if !xml_base_attr.is_null() {
                    xml_base_attr = xmlC14NFixupBaseAttr(ctx, xml_base_attr);
                    if !xml_base_attr.is_null() {
                        xmlListInsert(list, xml_base_attr as *mut libc::c_void);
                        let fresh9 = unsafe { &mut ((*xml_base_attr).next) };
                        *fresh9 = attrs_to_delete;
                        attrs_to_delete = xml_base_attr;
                    }
                }
            }
        }
        _ => {}
    }
    xmlListWalk(list, Some(xmlC14NPrintAttrs), ctx as *mut libc::c_void);
    (unsafe { xmlFreePropList(attrs_to_delete) });
    xmlListDelete(list);
    return 0 as i32;
}
extern "C" fn xmlC14NCheckForRelativeNamespaces<'a1>(
    mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'a1>,
    mut cur: *mut crate::src::HTMLparser::_xmlNode,
) -> i32 {
    let mut ns: *mut crate::src::HTMLparser::_xmlNs = 0 as *mut xmlNs;
    if ctx.is_null()
        || cur.is_null()
        || (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
    {
        xmlC14NErrParam(b"checking for relative namespaces\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    ns = unsafe { (*cur).nsDef };
    while !ns.is_null() {
        if (unsafe { xmlStrlen((*ns).href) }) > 0 as i32 {
            let mut uri: *mut crate::src::SAX2::_xmlURI = 0 as *mut xmlURI;
            uri = unsafe { xmlParseURI((*ns).href as *const i8) };
            if uri.is_null() {
                xmlC14NErrInternal(b"parsing namespace uri\0" as *const u8 as *const i8);
                return -(1 as i32);
            }
            if (unsafe { xmlStrlen((*uri).scheme as *const xmlChar) }) == 0 as i32 {
                xmlC14NErrRelativeNamespace(unsafe { (*uri).scheme });
                (unsafe { xmlFreeURI(uri) });
                return -(1 as i32);
            }
            (unsafe { xmlFreeURI(uri) });
        }
        ns = unsafe { (*ns).next };
    }
    return 0 as i32;
}
extern "C" fn xmlC14NProcessElementNode<'a1>(
    mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'a1>,
    mut cur: *mut crate::src::HTMLparser::_xmlNode,
    mut visible: i32,
) -> i32 {
    let mut ret: i32 = 0;
    let mut state: crate::src::c14n::_xmlC14NVisibleNsStack = xmlC14NVisibleNsStack {
        nsCurEnd: 0,
        nsPrevStart: 0,
        nsPrevEnd: 0,
        nsMax: 0,
        nsTab: 0 as *mut xmlNsPtr,
        nodeTab: 0 as *mut xmlNodePtr,
    };
    let mut parent_is_doc: i32 = 0 as i32;
    if ctx.is_null()
        || cur.is_null()
        || (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
    {
        xmlC14NErrParam(b"processing element node\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    if xmlC14NCheckForRelativeNamespaces(ctx, cur) < 0 as i32 {
        xmlC14NErrInternal(b"checking for relative namespaces\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    (unsafe {
        memset(
            &mut state as *mut xmlC14NVisibleNsStack as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlC14NVisibleNsStack>() as u64,
        )
    });
    xmlC14NVisibleNsStackSave(unsafe { (*ctx).ns_rendered }, Some(&mut state));
    if visible != 0 {
        if (unsafe { (*ctx).parent_is_doc }) != 0 {
            parent_is_doc = unsafe { (*ctx).parent_is_doc };
            (unsafe { (*ctx).parent_is_doc = 0 as i32 });
            (unsafe { (*ctx).pos = XMLC14N_INSIDE_DOCUMENT_ELEMENT });
        }
        (unsafe { xmlOutputBufferWriteString((*ctx).buf, b"<\0" as *const u8 as *const i8) });
        if !(unsafe { (*cur).ns }).is_null()
            && (unsafe { xmlStrlen((*(*cur).ns).prefix) }) > 0 as i32
        {
            (unsafe { xmlOutputBufferWriteString((*ctx).buf, (*(*cur).ns).prefix as *const i8) });
            (unsafe { xmlOutputBufferWriteString((*ctx).buf, b":\0" as *const u8 as *const i8) });
        }
        (unsafe { xmlOutputBufferWriteString((*ctx).buf, (*cur).name as *const i8) });
    }
    if !((unsafe { (*ctx).mode }) as u32 == XML_C14N_EXCLUSIVE_1_0 as i32 as u32) {
        ret = xmlC14NProcessNamespacesAxis(ctx, cur, visible);
    } else {
        ret = xmlExcC14NProcessNamespacesAxis(ctx, cur, visible);
    }
    if ret < 0 as i32 {
        xmlC14NErrInternal(b"processing namespaces axis\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    if visible != 0 {
        xmlC14NVisibleNsStackShift(unsafe { (*ctx).ns_rendered });
    }
    ret = xmlC14NProcessAttrsAxis(ctx, cur, visible);
    if ret < 0 as i32 {
        xmlC14NErrInternal(b"processing attributes axis\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    if visible != 0 {
        (unsafe { xmlOutputBufferWriteString((*ctx).buf, b">\0" as *const u8 as *const i8) });
    }
    if !(unsafe { (*cur).children }).is_null() {
        ret = xmlC14NProcessNodeList(ctx, unsafe { (*cur).children });
        if ret < 0 as i32 {
            xmlC14NErrInternal(b"processing childrens list\0" as *const u8 as *const i8);
            return -(1 as i32);
        }
    }
    if visible != 0 {
        (unsafe { xmlOutputBufferWriteString((*ctx).buf, b"</\0" as *const u8 as *const i8) });
        if !(unsafe { (*cur).ns }).is_null()
            && (unsafe { xmlStrlen((*(*cur).ns).prefix) }) > 0 as i32
        {
            (unsafe { xmlOutputBufferWriteString((*ctx).buf, (*(*cur).ns).prefix as *const i8) });
            (unsafe { xmlOutputBufferWriteString((*ctx).buf, b":\0" as *const u8 as *const i8) });
        }
        (unsafe { xmlOutputBufferWriteString((*ctx).buf, (*cur).name as *const i8) });
        (unsafe { xmlOutputBufferWriteString((*ctx).buf, b">\0" as *const u8 as *const i8) });
        if parent_is_doc != 0 {
            (unsafe { (*ctx).parent_is_doc = parent_is_doc });
            (unsafe { (*ctx).pos = XMLC14N_AFTER_DOCUMENT_ELEMENT });
        }
    }
    xmlC14NVisibleNsStackRestore(unsafe { (*ctx).ns_rendered }, Some(&mut state));
    return 0 as i32;
}
extern "C" fn xmlC14NProcessNode<'a1>(
    mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'a1>,
    mut cur: *mut crate::src::HTMLparser::_xmlNode,
) -> i32 {
    let mut ret: i32 = 0 as i32;
    let mut visible: i32 = 0;
    if ctx.is_null() || cur.is_null() {
        xmlC14NErrParam(b"processing node\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    visible = if unsafe { ((*ctx).is_visible_callback).is_some() } {
        unsafe {
            ((*ctx).is_visible_callback).expect("non-null function pointer")(
                (*ctx).user_data,
                cur,
                (*cur).parent as xmlNodePtr,
            )
        }
    } else {
        1 as i32
    };
    match (unsafe { (*cur).type_0 }) as u32 {
        1 => {
            ret = xmlC14NProcessElementNode(ctx, cur, visible);
        }
        4 | 3 => {
            if visible != 0 && !(unsafe { (*cur).content }).is_null() {
                let mut buffer: *mut u8 = 0 as *mut xmlChar;
                buffer =
                    xmlC11NNormalizeString(unsafe { (*cur).content }, XMLC14N_NORMALIZE_TEXT);
                if !buffer.is_null() {
                    (unsafe { xmlOutputBufferWriteString((*ctx).buf, buffer as *const i8) });
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void)
                    });
                } else {
                    xmlC14NErrInternal(b"normalizing text node\0" as *const u8 as *const i8);
                    return -(1 as i32);
                }
            }
        }
        7 => {
            if visible != 0 {
                if (unsafe { (*ctx).pos }) as u32 == XMLC14N_AFTER_DOCUMENT_ELEMENT as i32 as u32 {
                    (unsafe {
                        xmlOutputBufferWriteString((*ctx).buf, b"\n<?\0" as *const u8 as *const i8)
                    });
                } else {
                    (unsafe {
                        xmlOutputBufferWriteString((*ctx).buf, b"<?\0" as *const u8 as *const i8)
                    });
                }
                (unsafe { xmlOutputBufferWriteString((*ctx).buf, (*cur).name as *const i8) });
                if !(unsafe { (*cur).content }).is_null()
                    && (unsafe { *(*cur).content }) as i32 != '\u{0}' as i32
                {
                    let mut buffer_0: *mut u8 = 0 as *mut xmlChar;
                    (unsafe {
                        xmlOutputBufferWriteString((*ctx).buf, b" \0" as *const u8 as *const i8)
                    });
                    buffer_0 =
                        xmlC11NNormalizeString(unsafe { (*cur).content }, XMLC14N_NORMALIZE_PI);
                    if !buffer_0.is_null() {
                        (unsafe { xmlOutputBufferWriteString((*ctx).buf, buffer_0 as *const i8) });
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(
                                buffer_0 as *mut libc::c_void,
                            )
                        });
                    } else {
                        xmlC14NErrInternal(b"normalizing pi node\0" as *const u8 as *const i8);
                        return -(1 as i32);
                    }
                }
                if (unsafe { (*ctx).pos }) as u32 == XMLC14N_BEFORE_DOCUMENT_ELEMENT as i32 as u32 {
                    (unsafe {
                        xmlOutputBufferWriteString((*ctx).buf, b"?>\n\0" as *const u8 as *const i8)
                    });
                } else {
                    (unsafe {
                        xmlOutputBufferWriteString((*ctx).buf, b"?>\0" as *const u8 as *const i8)
                    });
                }
            }
        }
        8 => {
            if visible != 0 && (unsafe { (*ctx).with_comments }) != 0 {
                if (unsafe { (*ctx).pos }) as u32 == XMLC14N_AFTER_DOCUMENT_ELEMENT as i32 as u32 {
                    (unsafe {
                        xmlOutputBufferWriteString(
                            (*ctx).buf,
                            b"\n<!--\0" as *const u8 as *const i8,
                        )
                    });
                } else {
                    (unsafe {
                        xmlOutputBufferWriteString((*ctx).buf, b"<!--\0" as *const u8 as *const i8)
                    });
                }
                if !(unsafe { (*cur).content }).is_null() {
                    let mut buffer_1: *mut u8 = 0 as *mut xmlChar;
                    buffer_1 = xmlC11NNormalizeString(
                        unsafe { (*cur).content },
                        XMLC14N_NORMALIZE_COMMENT,
                    );
                    if !buffer_1.is_null() {
                        (unsafe { xmlOutputBufferWriteString((*ctx).buf, buffer_1 as *const i8) });
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(
                                buffer_1 as *mut libc::c_void,
                            )
                        });
                    } else {
                        xmlC14NErrInternal(b"normalizing comment node\0" as *const u8 as *const i8);
                        return -(1 as i32);
                    }
                }
                if (unsafe { (*ctx).pos }) as u32 == XMLC14N_BEFORE_DOCUMENT_ELEMENT as i32 as u32 {
                    (unsafe {
                        xmlOutputBufferWriteString((*ctx).buf, b"-->\n\0" as *const u8 as *const i8)
                    });
                } else {
                    (unsafe {
                        xmlOutputBufferWriteString((*ctx).buf, b"-->\0" as *const u8 as *const i8)
                    });
                }
            }
        }
        9 | 11 | 13 => {
            if !(unsafe { (*cur).children }).is_null() {
                (unsafe { (*ctx).pos = XMLC14N_BEFORE_DOCUMENT_ELEMENT });
                (unsafe { (*ctx).parent_is_doc = 1 as i32 });
                ret = xmlC14NProcessNodeList(ctx, unsafe { (*cur).children });
            }
        }
        2 => {
            xmlC14NErrInvalidNode(
                b"XML_ATTRIBUTE_NODE\0" as *const u8 as *const i8,
                b"processing node\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        18 => {
            xmlC14NErrInvalidNode(
                b"XML_NAMESPACE_DECL\0" as *const u8 as *const i8,
                b"processing node\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        5 => {
            xmlC14NErrInvalidNode(
                b"XML_ENTITY_REF_NODE\0" as *const u8 as *const i8,
                b"processing node\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        6 => {
            xmlC14NErrInvalidNode(
                b"XML_ENTITY_NODE\0" as *const u8 as *const i8,
                b"processing node\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        10 | 12 | 14 | 15 | 16 | 17 | 19 | 20 => {}
        _ => {
            xmlC14NErrUnknownNode(
                (unsafe { (*cur).type_0 }) as i32,
                b"processing node\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
    }
    return ret;
}
extern "C" fn xmlC14NProcessNodeList<'a1>(
    mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'a1>,
    mut cur: *mut crate::src::HTMLparser::_xmlNode,
) -> i32 {
    let mut ret: i32 = 0;
    if ctx.is_null() {
        xmlC14NErrParam(b"processing node list\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    ret = 0 as i32;
    while !cur.is_null() && ret >= 0 as i32 {
        ret = xmlC14NProcessNode(ctx, cur);
        cur = unsafe { (*cur).next };
    }
    return ret;
}
extern "C" fn xmlC14NFreeCtx<'a1>(mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'a1>) {
    if ctx.is_null() {
        xmlC14NErrParam(b"freeing context\0" as *const u8 as *const i8);
        return;
    }
    if !(unsafe { (*ctx).ns_rendered }).is_null() {
        xmlC14NVisibleNsStackDestroy(unsafe { (*ctx).ns_rendered });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(ctx as *mut libc::c_void) });
}
extern "C" fn xmlC14NNewCtx<'a1, 'a2>(
    mut doc: *mut crate::src::HTMLparser::_xmlDoc,
    mut is_visible_callback: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *mut crate::src::HTMLparser::_xmlNode,
            _: *mut crate::src::HTMLparser::_xmlNode,
        ) -> i32,
    >,
    mut user_data: *mut core::ffi::c_void,
    mut mode: u32,
    mut inclusive_ns_prefixes: Option<
        crate::__laertes_array::CustomSlice<'a1, *mut u8, &'a1 mut [*mut u8]>,
    >,
    mut with_comments: i32,
    mut buf: *mut crate::src::HTMLtree::_xmlOutputBuffer,
) -> *mut crate::src::c14n::_xmlC14NCtx<'a2> {
    let mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'_> = 0 as xmlC14NCtxPtr;
    if doc.is_null() || buf.is_null() {
        xmlC14NErrParam(b"creating new context\0" as *const u8 as *const i8);
        return 0 as xmlC14NCtxPtr;
    }
    if !(unsafe { (*buf).encoder }).is_null() {
        xmlC14NErr(
            ctx,
            doc as xmlNodePtr,
            XML_C14N_REQUIRES_UTF8 as i32,
            b"xmlC14NNewCtx: output buffer encoder != NULL but C14N requires UTF8 output\n\0"
                as *const u8 as *const i8,
        );
        return 0 as xmlC14NCtxPtr;
    }
    ctx = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlC14NCtx>() as u64)
    }) as xmlC14NCtxPtr;
    if ctx.is_null() {
        xmlC14NErrMemory(b"creating context\0" as *const u8 as *const i8);
        return 0 as xmlC14NCtxPtr;
    }
    (unsafe {
        memset(
            ctx as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlC14NCtx>() as u64,
        )
    });
    let fresh10 = unsafe { &mut ((*ctx).doc) };
    *fresh10 = doc;
    (unsafe { (*ctx).with_comments = with_comments });
    let fresh11 = unsafe { &mut ((*ctx).is_visible_callback) };
    *fresh11 = is_visible_callback;
    let fresh12 = unsafe { &mut ((*ctx).user_data) };
    *fresh12 = user_data;
    let fresh13 = unsafe { &mut ((*ctx).buf) };
    *fresh13 = buf;
    (unsafe { (*ctx).parent_is_doc = 1 as i32 });
    (unsafe { (*ctx).pos = XMLC14N_BEFORE_DOCUMENT_ELEMENT });
    let fresh14 = unsafe { &mut ((*ctx).ns_rendered) };
    *fresh14 = xmlC14NVisibleNsStackCreate();
    if (unsafe { (*ctx).ns_rendered }).is_null() {
        xmlC14NErr(
            ctx,
            doc as xmlNodePtr,
            XML_C14N_CREATE_STACK as i32,
            b"xmlC14NNewCtx: xmlC14NVisibleNsStackCreate failed\n\0" as *const u8 as *const i8,
        );
        xmlC14NFreeCtx(ctx);
        return 0 as xmlC14NCtxPtr;
    }
    (unsafe { (*ctx).mode = mode });
    if (unsafe { (*ctx).mode }) as u32 == XML_C14N_EXCLUSIVE_1_0 as i32 as u32 {
        let fresh15 = &mut (crate::__laertes_array::borrow_mut(
            unsafe { &mut (*ctx).inclusive_ns_prefixes },
        ));
        *fresh15 = crate::__laertes_array::borrow_mut(&mut inclusive_ns_prefixes);
    }
    return ctx;
}
#[no_mangle]
pub extern "C" fn xmlC14NExecute<'a1>(
    mut doc: *mut crate::src::HTMLparser::_xmlDoc,
    mut is_visible_callback: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *mut crate::src::HTMLparser::_xmlNode,
            _: *mut crate::src::HTMLparser::_xmlNode,
        ) -> i32,
    >,
    mut user_data: *mut core::ffi::c_void,
    mut mode: i32,
    mut inclusive_ns_prefixes: Option<
        crate::__laertes_array::CustomSlice<'a1, *mut u8, &'a1 mut [*mut u8]>,
    >,
    mut with_comments: i32,
    mut buf: *mut crate::src::HTMLtree::_xmlOutputBuffer,
) -> i32 {
    let mut ctx: *mut crate::src::c14n::_xmlC14NCtx<'_> = 0 as *mut _xmlC14NCtx;
    let mut c14n_mode: u32 = XML_C14N_1_0;
    let mut ret: i32 = 0;
    if buf.is_null() || doc.is_null() {
        xmlC14NErrParam(b"executing c14n\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    match mode {
        0 | 1 | 2 => {
            c14n_mode = mode as xmlC14NMode;
        }
        _ => {
            xmlC14NErrParam(b"invalid mode for executing c14n\0" as *const u8 as *const i8);
            return -(1 as i32);
        }
    }
    if !(unsafe { (*buf).encoder }).is_null() {
        xmlC14NErr(
            0 as xmlC14NCtxPtr,
            doc as xmlNodePtr,
            XML_C14N_REQUIRES_UTF8 as i32,
            b"xmlC14NExecute: output buffer encoder != NULL but C14N requires UTF8 output\n\0"
                as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    ctx = xmlC14NNewCtx(
        doc,
        is_visible_callback,
        user_data,
        c14n_mode,
        crate::__laertes_array::borrow_mut(&mut inclusive_ns_prefixes),
        with_comments,
        buf,
    );
    if ctx.is_null() {
        xmlC14NErr(
            0 as xmlC14NCtxPtr,
            doc as xmlNodePtr,
            XML_C14N_CREATE_CTXT as i32,
            b"xmlC14NExecute: unable to create C14N context\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    if !(unsafe { (*doc).children }).is_null() {
        ret = xmlC14NProcessNodeList(ctx, unsafe { (*doc).children });
        if ret < 0 as i32 {
            xmlC14NErrInternal(b"processing docs children list\0" as *const u8 as *const i8);
            xmlC14NFreeCtx(ctx);
            return -(1 as i32);
        }
    }
    ret = unsafe { xmlOutputBufferFlush(buf) };
    if ret < 0 as i32 {
        xmlC14NErrInternal(b"flushing output buffer\0" as *const u8 as *const i8);
        xmlC14NFreeCtx(ctx);
        return -(1 as i32);
    }
    xmlC14NFreeCtx(ctx);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlC14NDocSaveTo<'a1>(
    mut doc: *mut crate::src::HTMLparser::_xmlDoc,
    mut nodes: *mut crate::src::c14n::_xmlNodeSet,
    mut mode: i32,
    mut inclusive_ns_prefixes: Option<
        crate::__laertes_array::CustomSlice<'a1, *mut u8, &'a1 mut [*mut u8]>,
    >,
    mut with_comments: i32,
    mut buf: *mut crate::src::HTMLtree::_xmlOutputBuffer,
) -> i32 {
    return xmlC14NExecute(
        doc,
        Some(xmlC14NIsNodeInNodeset),
        nodes as *mut libc::c_void,
        mode,
        crate::__laertes_array::borrow_mut(&mut inclusive_ns_prefixes),
        with_comments,
        buf,
    );
}
#[no_mangle]
pub extern "C" fn xmlC14NDocDumpMemory<'a1, 'a2>(
    mut doc: *mut crate::src::HTMLparser::_xmlDoc,
    mut nodes: *mut crate::src::c14n::_xmlNodeSet,
    mut mode: i32,
    mut inclusive_ns_prefixes: Option<
        crate::__laertes_array::CustomSlice<'a1, *mut u8, &'a1 mut [*mut u8]>,
    >,
    mut with_comments: i32,
    mut doc_txt_ptr: Option<&'a2 mut *mut u8>,
) -> i32 {
    let mut ret: i32 = 0;
    let mut buf: *mut crate::src::HTMLtree::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    if borrow(&doc_txt_ptr).is_none() {
        xmlC14NErrParam(b"dumping doc to memory\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    *(borrow_mut(&mut doc_txt_ptr)).unwrap() = 0 as *mut u8;
    buf = unsafe { xmlAllocOutputBuffer(0 as xmlCharEncodingHandlerPtr) };
    if buf.is_null() {
        xmlC14NErrMemory(b"creating output buffer\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    ret = xmlC14NDocSaveTo(
        doc,
        nodes,
        mode,
        crate::__laertes_array::borrow_mut(&mut inclusive_ns_prefixes),
        with_comments,
        buf,
    );
    if ret < 0 as i32 {
        xmlC14NErrInternal(b"saving doc to output buffer\0" as *const u8 as *const i8);
        (unsafe { xmlOutputBufferClose(buf) });
        return -(1 as i32);
    }
    ret = xmlBufUse(unsafe { (*buf).buffer }) as i32;
    if ret >= 0 as i32 {
        *(borrow_mut(&mut doc_txt_ptr)).unwrap() =
            unsafe { xmlStrndup(xmlBufContent((*buf).buffer as *const xmlBuf), ret) };
    }
    (unsafe { xmlOutputBufferClose(buf) });
    if (*(borrow(&doc_txt_ptr)).unwrap()).is_null() && ret >= 0 as i32 {
        xmlC14NErrMemory(b"copying canonicalized document\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlC14NDocSave<'a1>(
    mut doc: *mut crate::src::HTMLparser::_xmlDoc,
    mut nodes: *mut crate::src::c14n::_xmlNodeSet,
    mut mode: i32,
    mut inclusive_ns_prefixes: Option<
        crate::__laertes_array::CustomSlice<'a1, *mut u8, &'a1 mut [*mut u8]>,
    >,
    mut with_comments: i32,
    mut filename: *const i8,
    mut compression: i32,
) -> i32 {
    let mut buf: *mut crate::src::HTMLtree::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
    let mut ret: i32 = 0;
    if filename.is_null() {
        xmlC14NErrParam(b"saving doc\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    if compression < 0 as i32 {
        compression = unsafe { xmlGetCompressMode() };
    }
    buf = unsafe {
        xmlOutputBufferCreateFilename(filename, 0 as xmlCharEncodingHandlerPtr, compression)
    };
    if buf.is_null() {
        xmlC14NErrInternal(b"creating temporary filename\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    ret = xmlC14NDocSaveTo(
        doc,
        nodes,
        mode,
        crate::__laertes_array::borrow_mut(&mut inclusive_ns_prefixes),
        with_comments,
        buf,
    );
    if ret < 0 as i32 {
        xmlC14NErrInternal(b"canonize document to buffer\0" as *const u8 as *const i8);
        (unsafe { xmlOutputBufferClose(buf) });
        return -(1 as i32);
    }
    ret = unsafe { xmlOutputBufferClose(buf) };
    return ret;
}
extern "C" fn xmlC11NNormalizeString(mut input: *const u8, mut mode: u32) -> *mut u8 {
    let mut cur: *const u8 = input;
    let mut buffer: *mut u8 = 0 as *mut xmlChar;
    let mut out: *mut u8 = 0 as *mut xmlChar;
    let mut buffer_size: i32 = 0 as i32;
    if input.is_null() {
        return 0 as *mut xmlChar;
    }
    buffer_size = 1000 as i32;
    buffer = (unsafe {
        xmlMallocAtomic.expect("non-null function pointer")(
            (buffer_size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    }) as *mut xmlChar;
    if buffer.is_null() {
        xmlC14NErrMemory(b"allocating buffer\0" as *const u8 as *const i8);
        return 0 as *mut xmlChar;
    }
    out = buffer;
    while (unsafe { *cur }) as i32 != '\u{0}' as i32 {
        if (unsafe { out.offset_from(buffer) }) as i64 > (buffer_size - 10 as i32) as i64 {
            let mut indx: i32 = (unsafe { out.offset_from(buffer) }) as i64 as i32;
            buffer_size *= 2 as i32;
            buffer = (unsafe {
                xmlRealloc.expect("non-null function pointer")(
                    buffer as *mut libc::c_void,
                    (buffer_size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
                )
            }) as *mut xmlChar;
            if buffer.is_null() {
                xmlC14NErrMemory(b"growing buffer\0" as *const u8 as *const i8);
                return 0 as *mut xmlChar;
            }
            out = (unsafe { &mut *buffer.offset(indx as isize) }) as *mut xmlChar;
        }
        if (unsafe { *cur }) as i32 == '<' as i32
            && (mode as u32 == XMLC14N_NORMALIZE_ATTR as i32 as u32
                || mode as u32 == XMLC14N_NORMALIZE_TEXT as i32 as u32)
        {
            let mut fresh16 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh16 = '&' as i32 as xmlChar });
            let mut fresh17 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh17 = 'l' as i32 as xmlChar });
            let mut fresh18 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh18 = 't' as i32 as xmlChar });
            let mut fresh19 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh19 = ';' as i32 as xmlChar });
        } else if (unsafe { *cur }) as i32 == '>' as i32
            && mode as u32 == XMLC14N_NORMALIZE_TEXT as i32 as u32
        {
            let mut fresh20 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh20 = '&' as i32 as xmlChar });
            let mut fresh21 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh21 = 'g' as i32 as xmlChar });
            let mut fresh22 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh22 = 't' as i32 as xmlChar });
            let mut fresh23 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh23 = ';' as i32 as xmlChar });
        } else if (unsafe { *cur }) as i32 == '&' as i32
            && (mode as u32 == XMLC14N_NORMALIZE_ATTR as i32 as u32
                || mode as u32 == XMLC14N_NORMALIZE_TEXT as i32 as u32)
        {
            let mut fresh24 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh24 = '&' as i32 as xmlChar });
            let mut fresh25 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh25 = 'a' as i32 as xmlChar });
            let mut fresh26 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh26 = 'm' as i32 as xmlChar });
            let mut fresh27 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh27 = 'p' as i32 as xmlChar });
            let mut fresh28 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh28 = ';' as i32 as xmlChar });
        } else if (unsafe { *cur }) as i32 == '"' as i32
            && mode as u32 == XMLC14N_NORMALIZE_ATTR as i32 as u32
        {
            let mut fresh29 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh29 = '&' as i32 as xmlChar });
            let mut fresh30 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh30 = 'q' as i32 as xmlChar });
            let mut fresh31 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh31 = 'u' as i32 as xmlChar });
            let mut fresh32 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh32 = 'o' as i32 as xmlChar });
            let mut fresh33 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh33 = 't' as i32 as xmlChar });
            let mut fresh34 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh34 = ';' as i32 as xmlChar });
        } else if (unsafe { *cur }) as i32 == '\t' as i32
            && mode as u32 == XMLC14N_NORMALIZE_ATTR as i32 as u32
        {
            let mut fresh35 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh35 = '&' as i32 as xmlChar });
            let mut fresh36 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh36 = '#' as i32 as xmlChar });
            let mut fresh37 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh37 = 'x' as i32 as xmlChar });
            let mut fresh38 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh38 = '9' as i32 as xmlChar });
            let mut fresh39 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh39 = ';' as i32 as xmlChar });
        } else if (unsafe { *cur }) as i32 == '\n' as i32
            && mode as u32 == XMLC14N_NORMALIZE_ATTR as i32 as u32
        {
            let mut fresh40 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh40 = '&' as i32 as xmlChar });
            let mut fresh41 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh41 = '#' as i32 as xmlChar });
            let mut fresh42 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh42 = 'x' as i32 as xmlChar });
            let mut fresh43 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh43 = 'A' as i32 as xmlChar });
            let mut fresh44 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh44 = ';' as i32 as xmlChar });
        } else if (unsafe { *cur }) as i32 == '\r' as i32
            && (mode as u32 == XMLC14N_NORMALIZE_ATTR as i32 as u32
                || mode as u32 == XMLC14N_NORMALIZE_TEXT as i32 as u32
                || mode as u32 == XMLC14N_NORMALIZE_COMMENT as i32 as u32
                || mode as u32 == XMLC14N_NORMALIZE_PI as i32 as u32)
        {
            let mut fresh45 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh45 = '&' as i32 as xmlChar });
            let mut fresh46 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh46 = '#' as i32 as xmlChar });
            let mut fresh47 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh47 = 'x' as i32 as xmlChar });
            let mut fresh48 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh48 = 'D' as i32 as xmlChar });
            let mut fresh49 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh49 = ';' as i32 as xmlChar });
        } else {
            let mut fresh50 = out;
            out = unsafe { out.offset(1) };
            (unsafe { *fresh50 = *cur });
        }
        cur = unsafe { cur.offset(1) };
    }
    (unsafe { *out = 0 as i32 as xmlChar });
    return buffer;
}
use crate::laertes_rt::*;
